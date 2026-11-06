{ pkgs, serverPackage }:
let
  bundle = import ../bundle.nix {
    inherit pkgs serverPackage;
    inventory = (import ../hosts.nix).staging // {
      deploymentReady = true;
      hostname = "origin.test";
      publicHostname = "cache.test";
      cacheHostSuffix = "example.test";
    };
  };
  gatedBundle = import ../bundle.nix {
    inherit pkgs serverPackage;
    inventory = (import ../hosts.nix).staging // {
      deploymentReady = false;
    };
  };
  uploadBackend = pkgs.writeText "proxy-upload-test.py" ''
    import hashlib
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (self.headers["Host"] + self.path).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            remaining = int(self.headers["Content-Length"])
            digest = hashlib.sha256()
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    raise EOFError("incomplete request")
                digest.update(chunk)
                remaining -= len(chunk)
            body = digest.hexdigest().encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
  '';
in
# Exercise the shared units independently of the host's disabled activation gate.
pkgs.testers.runNixOSTest {
  name = "snowstead-service";
  nodes.machine = {
    virtualisation = {
      memorySize = 512;
      cores = 1;
      diskSize = 10 * 1024;
    };
    users.groups.snowstead = { };
    users.groups.snowstead-proxy = { };
    users.users.snowstead = {
      isSystemUser = true;
      group = "snowstead";
    };
    users.users.snowstead-proxy = {
      isSystemUser = true;
      group = "snowstead-proxy";
    };
    environment.systemPackages = [
      pkgs.curl
      pkgs.openssl
      bundle
    ];
    # Allow 8080 to prove loopback binding, not just a firewall rule.
    networking.firewall.allowedTCPPorts = [
      443
      8080
    ];
  };
  nodes.database = {
    services.postgresql = {
      enable = true;
      enableTCPIP = true;
      ensureDatabases = [ "snowstead" ];
      ensureUsers = [
        {
          name = "snowstead";
          ensureDBOwnership = true;
        }
      ];
      # Test-only trust on an isolated VM network, never a production policy.
      authentication = pkgs.lib.mkForce ''
        local all all peer
        host snowstead snowstead all trust
      '';
    };
    networking.firewall.allowedTCPPorts = [ 5432 ];
  };
  nodes.client = { };
  testScript = ''
    start_all()
    database.wait_for_unit("postgresql.service")
    machine.wait_for_unit("multi-user.target")
    # Replace the harness's immutable unit directory with a writable copy,
    # matching stock Linux. Install the actual generic bundle, not a module.
    machine.succeed("mkdir /run/test-units; cp -a /etc/systemd/system/. /run/test-units/; chmod -R u+w /run/test-units; rm /etc/systemd/system; ln -s /run/test-units /etc/systemd/system")
    # Object storage is not exercised here; all values are dummy test inputs.
    machine.succeed("install -d -m 0700 /etc/snowstead; printf '%s\\n' 'DATABASE_URL=postgres://snowstead@database/snowstead?sslmode=disable' 'R2_ENDPOINT=http://127.0.0.1:9999' 'R2_ACCESS_KEY_ID=test' 'R2_SECRET_ACCESS_KEY=test' > /etc/snowstead/environment; chmod 0600 /etc/snowstead/environment")
    # Startup never migrates. Prepare the disposable application schema explicitly.
    machine.succeed("set -a; . /etc/snowstead/environment; ${serverPackage}/bin/snowstead-server migrate")
    machine.succeed("openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=origin.test -addext 'subjectAltName=DNS:origin.test,DNS:cache.test,DNS:*.example.test' -keyout /etc/snowstead/origin-key -out /etc/snowstead/origin-certificate; cp /etc/snowstead/origin-certificate /etc/snowstead/origin-client-ca; chmod 0600 /etc/snowstead/*")
    machine.succeed("openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=untrusted -keyout /run/untrusted-key -out /run/untrusted-certificate")
    # Even with valid runtime files, direct activation cannot bypass readiness.
    machine.fail("${gatedBundle}/bin/snowstead-activate")
    machine.succeed("test ! -e /etc/systemd/system/snowstead.service")
    machine.succeed("snowstead-activate")
    machine.wait_for_unit("snowstead.service")
    machine.wait_for_unit("snowstead-proxy.service")
    machine.succeed("test $(stat -c %a /run/snowstead) = 700")
    machine.fail("su -s /bin/sh snowstead-proxy -c 'cat /etc/snowstead/origin-key'")
    tls = "curl --fail --silent --show-error --resolve origin.test:443:127.0.0.1 --cacert /etc/snowstead/origin-certificate"
    machine.fail(tls + " https://origin.test/healthz")
    machine.fail(tls + " --cert /run/untrusted-certificate --key /run/untrusted-key https://origin.test/healthz")
    machine.succeed(tls + " --cert /etc/snowstead/origin-certificate --key /etc/snowstead/origin-key https://origin.test/healthz")
    machine.succeed(tls.replace("origin.test", "cache.test") + " --cert /etc/snowstead/origin-certificate --key /etc/snowstead/origin-key https://cache.test/healthz")
    machine.fail("curl --fail --silent --show-error --insecure --resolve unknown.invalid:443:127.0.0.1 --cert /etc/snowstead/origin-certificate --key /etc/snowstead/origin-key https://unknown.invalid/healthz")
    # Isolate proxy transfer behavior from application authorization/R2 policy.
    # nginx's default 1 MiB cap would reject this complete, hash-checked upload.
    machine.succeed("systemctl stop snowstead; systemd-run --unit=proxy-upload-test ${pkgs.python3}/bin/python3 ${uploadBackend}")
    machine.wait_for_open_port(8080)
    # Direct org ingress preserves both Host and cache-scoped path. The API,
    # not nginx rewrite rules or a Worker, resolves current org/cache policy.
    for org in ["hackr", "uzair"]:
        org_tls = tls.replace("origin.test", org + ".example.test")
        address = "https://" + org + ".example.test/main/nix-cache-info"
        machine.fail(org_tls + " " + address)
        body = machine.succeed(org_tls + " --cert /etc/snowstead/origin-certificate --key /etc/snowstead/origin-key " + address).strip()
        assert body == org + ".example.test/main/nix-cache-info", body
    machine.succeed("head -c 2097152 /dev/zero > /run/proxy-request")
    digest = machine.succeed(tls + " --cert /etc/snowstead/origin-certificate --key /etc/snowstead/origin-key --data-binary @/run/proxy-request https://origin.test/upload").strip()
    assert digest == machine.succeed("sha256sum /run/proxy-request").split()[0]
    machine.succeed("systemctl stop proxy-upload-test; systemctl start snowstead")
    machine.wait_for_open_port(8080)
    client.wait_for_unit("multi-user.target")
    client.fail("curl --fail --connect-timeout 2 http://machine:8080/healthz")
    # Re-activation is idempotent; object durability belongs to R2, not this VM.
    machine.succeed("snowstead-activate")
    # Preflight failure must leave the currently running generation untouched.
    machine.succeed("chmod 0644 /etc/snowstead/environment")
    machine.fail("snowstead-activate")
    machine.succeed("curl --fail http://127.0.0.1:8080/healthz; chmod 0600 /etc/snowstead/environment")
    database.succeed("systemctl stop postgresql")
    machine.wait_until_succeeds("test $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/healthz) = 503")
    database.succeed("systemctl start postgresql")
    machine.wait_until_succeeds("curl --fail http://127.0.0.1:8080/healthz")
    machine.succeed("free -m; df -h /; systemctl show snowstead snowstead-proxy -p MemoryCurrent -p MemoryPeak -p MemorySwapCurrent")
    machine.fail("dmesg | grep -E 'Out of memory|Killed process'")
    machine.succeed("systemctl stop snowstead")
    machine.succeed("test $(systemctl show snowstead -p Result --value) = success")
    machine.succeed("systemctl stop snowstead-proxy; test $(systemctl show snowstead-proxy -p Result --value) = success")
  '';
}
