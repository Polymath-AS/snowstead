#!/usr/bin/env python3
"""Load-test a built service bundle's real TLS proxy without deployment secrets.

Usage: python3 infra/tests/proxy-load.py --bundle /nix/store/...-bundle \
    --output /tmp/proxy-results.json [--expect-success]

A hash-checking HTTP backend isolates proxy behavior from storage capacity.
Only listener addresses/ports change from the generated production config.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import statistics
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-success", action="store_true")
    parser.add_argument("--sustain-seconds", type=float, default=30)
    args = parser.parse_args()
    payload = bytes(range(256)) * 8192
    expected = hashlib.sha256(payload).hexdigest().encode()

    class Backend(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            self.reply(b"healthy")

        def do_POST(self):
            digest = hashlib.sha256()
            remaining = int(self.headers["Content-Length"])
            while remaining:
                chunk = self.rfile.read(min(32768, remaining))
                if not chunk:
                    return
                digest.update(chunk)
                remaining -= len(chunk)
                time.sleep(0.005)
            self.reply(digest.hexdigest().encode())

        def reply(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class BackendServer(ThreadingHTTPServer):
        # Do not let the fixture's default five-connection accept queue become
        # a different bottleneck during the synchronized TLS request bursts.
        request_queue_size = 256
        daemon_threads = True

    backend = BackendServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    proxy = None
    try:
        with tempfile.TemporaryDirectory(prefix="snowstead-proxy-load-") as directory:
            root = Path(directory)
            unit = (args.bundle / "lib/systemd/system/snowstead-proxy.service").read_text()
            start = Path(re.search(r"^ExecStart=(.+)$", unit, re.M)[1])
            source = start.read_text()
            hostname = re.search(r"^\s*server_name (\S+)", source, re.M)[1]
            for name in ["origin", "untrusted"]:
                subprocess.run([
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", f"/CN={name}.test", "-addext", f"subjectAltName=DNS:{hostname}",
                    "-keyout", str(root / f"{name}-key"), "-out", str(root / f"{name}-certificate"),
                ], check=True, capture_output=True)
            (root / "origin-client-ca").write_bytes((root / "origin-certificate").read_bytes())
            render, command = source.rsplit("\nexec ", 1)
            nginx = shlex.split(command)[0]
            subprocess.run(["sh", "-c", render], check=True, env={
                **os.environ, "RUNTIME_DIRECTORY": directory, "CREDENTIALS_DIRECTORY": directory,
            })
            config = root / "nginx.conf"
            original = config.read_text()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            local = original.replace("listen 443 ssl", f"listen 127.0.0.1:{port} ssl")
            local = re.sub(r"^\s*listen \[::\]:443 ssl.*;\n", "", local, flags=re.M)
            local = local.replace("127.0.0.1:8080", f"127.0.0.1:{backend.server_port}")
            config.write_text(local)
            command = [nginx, "-e", str(root / "errors.log"), "-p", directory + "/", "-c", str(config)]
            subprocess.run([*command, "-t"], check=True, capture_output=True)
            with (root / "process.log").open("w") as log:
                proxy = subprocess.Popen([*command, "-g", "daemon off;"], stdout=log, stderr=log)
            context = ssl.create_default_context(cafile=str(root / "origin-certificate"))
            context.load_cert_chain(root / "origin-certificate", root / "origin-key")

            def request(upload=False, tls=context):
                connection = http.client.HTTPSConnection(hostname, port, context=tls, timeout=10)
                # Keep real Host/SNI routing, but never resolve a public address.
                connection._create_connection = lambda *_: socket.create_connection(("127.0.0.1", port), timeout=10)
                started = time.monotonic()
                try:
                    connection.connect()
                    connection.putrequest("POST" if upload else "GET", "/upload" if upload else "/healthz", skip_host=True)
                    connection.putheader("Host", hostname)
                    connection.putheader("Content-Length", str(len(payload) if upload else 0))
                    connection.endheaders()
                    if upload:
                        try:
                            for offset in range(0, len(payload), 32768):
                                connection.send(payload[offset:offset + 32768])
                                time.sleep(0.003)
                        except OSError:
                            # nginx can reject before accepting the request body.
                            pass
                    response = connection.getresponse()
                    body = response.read()
                    if response.status == 200:
                        assert body == (expected if upload else b"healthy"), "response digest differs"
                    return str(response.status), time.monotonic() - started
                except (OSError, http.client.HTTPException) as error:
                    return type(error).__name__, time.monotonic() - started
                finally:
                    connection.close()

            for _ in range(100):
                if request()[0] == "200":
                    break
                assert proxy.poll() is None, (root / "process.log").read_text()
                time.sleep(0.05)
            else:
                raise AssertionError("proxy did not become ready")

            samples = []
            stop = threading.Event()

            def sample():
                while not stop.wait(0.01):
                    try:
                        children = Path(f"/proc/{proxy.pid}/task/{proxy.pid}/children").read_text().split()
                        rss = fds = 0
                        for pid in [str(proxy.pid), *children]:
                            status = Path(f"/proc/{pid}/status").read_text()
                            rss += int(re.search(r"VmRSS:\s+(\d+)", status)[1])
                            fds += len(list(Path(f"/proc/{pid}/fd").iterdir()))
                        samples.append((rss, fds))
                    except FileNotFoundError:
                        pass

            monitor = threading.Thread(target=sample)
            monitor.start()
            def cases():
                for concurrency in [8, 32, 64, 128]:
                    for repetition in range(3):
                        yield concurrency, repetition + 1, "burst"
                deadline = time.monotonic() + args.sustain_seconds
                repetition = 0
                while time.monotonic() < deadline:
                    repetition += 1
                    yield 128, repetition, "sustained"

            runs = []
            try:
                for concurrency, repetition, phase in cases():
                    barrier = threading.Barrier(concurrency + 1)

                    def upload():
                        barrier.wait()
                        return request(upload=True)

                    started = time.monotonic()
                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        uploads = [pool.submit(upload) for _ in range(concurrency)]
                        barrier.wait()
                        time.sleep(0.1)
                        controls = [request() for _ in range(12)]
                        results = [future.result() for future in uploads]
                    durations = sorted(duration for _, duration in results)
                    run = dict(concurrency=concurrency, repetition=repetition, phase=phase,
                               statuses=dict(Counter(status for status, _ in results)),
                               control_statuses=dict(Counter(status for status, _ in controls)),
                               upload_median_ms=round(statistics.median(durations) * 1000, 2),
                               upload_p95_ms=round(durations[int((len(durations) - 1) * .95)] * 1000, 2),
                               control_max_ms=round(max(duration for _, duration in controls) * 1000, 2),
                               elapsed_s=round(time.monotonic() - started, 3))
                    runs.append(run)
                    print(json.dumps(run), flush=True)
                    time.sleep(0.1)
            finally:
                stop.set()
                monitor.join()
            no_certificate = ssl.create_default_context(cafile=str(root / "origin-certificate"))
            untrusted = ssl.create_default_context(cafile=str(root / "origin-certificate"))
            untrusted.load_cert_chain(root / "untrusted-certificate", root / "untrusted-key")
            denied = {"no_certificate": request(tls=no_certificate)[0],
                      "untrusted_certificate": request(tls=untrusted)[0]}
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname="unknown.invalid"):
                        raise AssertionError("unknown SNI accepted")
            except ssl.SSLError:
                denied["unknown_sni"] = "TLS rejected"
            assert all(status != "200" for status in denied.values()), denied
            time.sleep(0.5)
            assert request()[0] == "200", "proxy did not recover after load"
            summary = dict(bundle=str(args.bundle), start_script=str(start), nginx=nginx,
                           configuration=original, runs=runs, rejected_clients=denied,
                           peak_proxy_rss_kib=max(rss for rss, _ in samples),
                           peak_proxy_fds=max(fds for _, fds in samples),
                           final_proxy_rss_kib=samples[-1][0], final_proxy_fds=samples[-1][1])
            args.output.write_text(json.dumps(summary, indent=2) + "\n")
            args.output.with_suffix(".nginx.log").write_text((root / "process.log").read_text() +
                                                           (root / "errors.log").read_text())
            if args.expect_success:
                assert all(run["statuses"] == {"200": run["concurrency"]} and
                           run["control_statuses"] == {"200": 12} for run in runs), runs
                assert summary["peak_proxy_rss_kib"] < 96 * 1024, summary
            print(json.dumps({key: value for key, value in summary.items() if key not in ["configuration", "runs"]}), flush=True)
    finally:
        if proxy is not None:
            proxy.terminate()
            proxy.wait(timeout=15)
        backend.shutdown()
        backend.server_close()


if __name__ == "__main__":
    main()
