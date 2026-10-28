// A conservative stock-Zig snapshot client, not a build runner or action cache.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const maxArchive = 96 << 20
const maxExpanded = 1 << 30
const maxFiles = 100000

type compatibility struct {
	Format, Trust, ToolchainHash, OS, Arch, SourceHash, Context string
	NativeTarget                                                string
	CPU, BuildArgs                                              []string
	ProjectRoot, ToolchainRoot, SessionRoot                     string
}

func (c compatibility) key() string {
	encoded, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func hashTree(root string, project bool) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if project && d.IsDir() && (rel == ".git" || rel == ".zig-cache" || rel == "zig-out") {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			fmt.Fprintf(h, "directory\x00%s\x00%d\x00", rel, info.Mode().Perm())
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular input: %s", p)
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00", rel, info.Mode().Perm(), info.Size())
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(h, f)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	return hex.EncodeToString(h.Sum(nil)), err
}

// Include completed outputs, manifests, serialized configurations, and builtins.
// z contains mutable ZIR; tmp, locks, package downloads and maker state stay out.
// The reviewed build must honor -fno-incremental: incremental outputs also use o.
func eligible(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) < 3 || (parts[0] != "local" && parts[0] != "global") || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") || strings.Contains(name, "../") {
		return false
	}
	if parts[1] == "h" || parts[1] == "b" || parts[1] == "c" {
		// Cache.Manifest.check opens a 32-character hex digest filename.
		// In particular, h/timestamp is mutable filesystem-clock state, not a manifest.
		// Module.createBuiltin uses b/<Builtin.hash()>/builtin.zig; it is generated
		// from compiler options, not mutable incremental state (Builtin.updateFileOnDisk).
		// Maker.configure atomically publishes immutable local/c/<digest>.
		decoded, err := hex.DecodeString(parts[2])
		valid := err == nil && len(decoded) == 16 && strings.ToLower(parts[2]) == parts[2]
		return valid && (parts[1] == "h" && len(parts) == 3 || parts[0] == "global" && parts[1] == "b" && len(parts) == 4 && parts[3] == "builtin.zig" || parts[0] == "local" && parts[1] == "c" && len(parts) == 3)
	}
	return parts[1] == "o"
}

func pack(root, dest string) (string, int64, error) {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(f, h))
	tw := tar.NewWriter(gz)
	var expanded int64
	count := 0
	for _, which := range []string{"local", "global"} {
		for _, sub := range []string{"o", "h", "b", "c"} {
			base := filepath.Join(root, which, sub)
			err = filepath.WalkDir(base, func(p string, d fs.DirEntry, walkErr error) error {
				if errors.Is(walkErr, fs.ErrNotExist) && p == base {
					return nil
				}
				if walkErr != nil {
					return walkErr
				}
				if d.IsDir() {
					return nil
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("non-regular cache output: %s", p)
				}
				expanded += info.Size()
				count++
				if expanded > maxExpanded || count > maxFiles {
					return errors.New("snapshot expansion limit")
				}
				name, _ := filepath.Rel(root, p)
				if !eligible(name) {
					return nil
				}
				if err = tw.WriteHeader(&tar.Header{Name: name, Mode: int64(info.Mode().Perm() & 0755), Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
					return err
				}
				in, err := os.Open(p)
				if err != nil {
					return err
				}
				_, err = io.CopyN(tw, in, info.Size())
				closeErr := in.Close()
				if err != nil {
					return err
				}
				return closeErr
			})
			if err != nil {
				return "", 0, err
			}
		}
	}
	if err = tw.Close(); err != nil {
		return "", 0, err
	}
	if err = gz.Close(); err != nil {
		return "", 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	if info.Size() > maxArchive {
		return "", 0, errors.New("compressed snapshot exceeds 96 MiB")
	}
	return hex.EncodeToString(h.Sum(nil)), info.Size(), nil
}

// Caller supplies a fresh private staging directory, never a shared cache root.
// No tar extraction API, symlinks, hard links, devices, duplicates, or metadata replay.
func unpack(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	// Bound the entire decompressed stream, including hidden tar/PAX headers,
	// not just payload sizes reported by tar.Next.
	expanded := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	tr := tar.NewReader(expanded)
	var total int64
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= maxFiles || h.Typeflag != tar.TypeReg || !eligible(h.Name) || h.Size < 0 || h.Size > maxExpanded-total {
			return errors.New("invalid snapshot entry or expansion limit")
		}
		total += h.Size
		p := filepath.Join(dest, h.Name)
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(h.Mode)&0755)
		if err != nil {
			return err
		}
		_, err = io.CopyN(out, tr, h.Size)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if expanded.N <= 1 {
		return errors.New("decompressed archive exceeds limit")
	}
	// Consume gzip trailer too: tar EOF alone does not validate its checksum.
	n, err := io.Copy(io.Discard, io.LimitReader(gz, 1))
	if n != 0 {
		return errors.New("unexpected data after tar end")
	}
	return err
}

var client = &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}

func transfer(method, endpoint, token, file, digest string, size int64) (*http.Response, error) {
	var body io.Reader
	if method == "PUT" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		body = f
	}
	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == "PUT" {
		req.ContentLength = size
		req.Header.Set("X-Snapshot-SHA256", digest)
	}
	return client.Do(req)
}

func restore(endpoint, token, session string) error {
	res, err := transfer("GET", endpoint, token, "", "", 0)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("restore HTTP %d", res.StatusCode)
	}
	digest := res.Header.Get("X-Snapshot-SHA256")
	if len(digest) != 64 {
		return errors.New("missing snapshot digest")
	}
	archive := filepath.Join(session, "download")
	f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, maxArchive+1))
	closeErr := f.Close()
	defer os.Remove(archive)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxArchive || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("snapshot checksum or length mismatch")
	}
	stage := filepath.Join(session, "stage")
	if err = os.Mkdir(stage, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err = unpack(archive, stage); err != nil {
		return err
	}
	// Publish all outputs AND manifests with one rename, after full verification.
	if err = os.Rename(stage, filepath.Join(session, "cache")); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "snapshot restored: %d bytes\n", n)
	return nil
}

func run() error {
	project := flag.String("project", ".", "reviewed source tree; .git, .zig-cache and zig-out excluded")
	zigRoot := flag.String("toolchain", "", "unmodified stock Zig 0.17.0 distribution directory")
	remote := flag.String("url", "", "dedicated snapshot Worker URL (HTTPS; loopback HTTP for tests)")
	namespace := flag.String("trust", "", "project/trust identity, rotated after writer compromise")
	context := flag.String("context", "", "file hashing ALL external tools, environment, SDK and dependency identities")
	scratch := flag.String("scratch", "", "controlled CI scratch path; MUST NOT exist; exclusively created and removed")
	write := flag.Bool("save", false, "save after success; trusted CI only; token from SNOWSTEAD_ZIG_WRITE_TOKEN")
	flag.Parse()
	if *zigRoot == "" || *namespace == "" || *context == "" || *scratch == "" {
		return errors.New("toolchain, trust, context and scratch are required; see README for supported scope")
	}
	u, err := url.Parse(*remote)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return errors.New("expected HTTPS origin or loopback HTTP")
	}
	*project, err = filepath.Abs(*project)
	if err != nil {
		return err
	}
	*zigRoot, err = filepath.Abs(*zigRoot)
	if err != nil {
		return err
	}
	*project, err = filepath.EvalSymlinks(*project)
	if err != nil {
		return err
	}
	*zigRoot, err = filepath.EvalSymlinks(*zigRoot)
	if err != nil {
		return err
	}
	zig := filepath.Join(*zigRoot, "zig")
	// Probe and build under the same environment. Transfer credentials and Zig
	// cache overrides must never intentionally reach compiler/build children.
	var compilerEnv []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SNOWSTEAD_ZIG_") && !strings.HasPrefix(e, "ZIG_") {
			compilerEnv = append(compilerEnv, e)
		}
	}
	versionCommand := exec.Command(zig, "version")
	versionCommand.Env = compilerEnv
	version, err := versionCommand.Output()
	if err != nil {
		return err
	}
	if string(version) != "0.17.0\n" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("spike supports stock Zig 0.17.0 on x86_64 Linux only")
	}
	envCommand := exec.Command(zig, "env")
	envCommand.Env = compilerEnv
	envOutput, err := envCommand.Output()
	if err != nil {
		return err
	}
	var nativeTarget string
	for _, line := range strings.Split(string(envOutput), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ".target = ") {
			nativeTarget = strings.TrimSpace(line)
		}
	}
	if nativeTarget == "" {
		return errors.New("missing stock Zig native target (kernel/libc versions)")
	}
	args := flag.Args()
	for _, a := range args {
		if strings.Contains(a, "incremental") || strings.Contains(a, "cache-dir") || strings.HasPrefix(a, "--prefix") || a == "-p" {
			return fmt.Errorf("reserved build argument: %s", a)
		}
	}
	sourceHash, err := hashTree(*project, true)
	if err != nil {
		return err
	}
	toolHash, err := hashTree(*zigRoot, false)
	if err != nil {
		return err
	}
	ctxBytes, err := os.ReadFile(*context)
	if err != nil {
		return err
	}
	cpu, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return err
	}
	// Per-core clock/load values are volatile. CPU model and ISA flags are not.
	var host []string
	for _, line := range strings.Split(string(cpu), "\n") {
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "flags") {
			host = append(host, line)
		}
	}
	session, err := filepath.Abs(*scratch)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(session))
	if err != nil {
		return err
	}
	session = filepath.Join(parent, filepath.Base(session))
	for _, input := range []string{*project, *zigRoot} {
		rel, relErr := filepath.Rel(input, session)
		if relErr != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, "../") {
			return errors.New("scratch must be outside the source and toolchain trees")
		}
	}
	if err = os.Mkdir(session, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(session)
	// Stock 0.17 configurations and generated inputs contain absolute paths.
	// Conservatively fence layout compatibility instead of rewriting manifests.
	key := (compatibility{
		Format: "zig-snapshot-v1", Trust: *namespace, ToolchainHash: toolHash,
		OS: runtime.GOOS, Arch: runtime.GOARCH, CPU: host, NativeTarget: nativeTarget,
		SourceHash: sourceHash, Context: string(ctxBytes), BuildArgs: args,
		ProjectRoot: *project, ToolchainRoot: *zigRoot, SessionRoot: session,
	}).key()
	endpoint := strings.TrimRight(*remote, "/") + "/v1/snapshots/" + key
	fmt.Fprintln(os.Stderr, "snapshot key:", key)
	restored := false
	if err = restore(endpoint, os.Getenv("SNOWSTEAD_ZIG_READ_TOKEN"), session); err != nil {
		fmt.Fprintln(os.Stderr, "snapshot miss (building normally):", err)
	} else {
		restored = true
	}
	root := filepath.Join(session, "cache")
	for _, which := range []string{"local", "global"} {
		// Maker.configure may reuse its executable after source metadata changes
		// and create tmp/<random> without creating tmp itself. Restore no temp
		// contents, but provide empty working directories for stock Zig.
		if err = os.MkdirAll(filepath.Join(root, which, "tmp"), 0700); err != nil {
			return err
		}
	}
	buildArgs := append([]string{"build", "-fno-incremental", "--cache-dir", filepath.Join(root, "local")}, args...)
	cmd := exec.Command(zig, buildArgs...)
	cmd.Dir = *project
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(compilerEnv, "ZIG_GLOBAL_CACHE_DIR="+filepath.Join(root, "global"))
	started := time.Now()
	if err = cmd.Run(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "zig build seconds: %.3f\n", time.Since(started).Seconds())
	// An existing verified immutable snapshot needs no second publication. Native
	// manifest metadata can change on rebuild without changing source contents.
	if !*write || restored {
		return nil
	}
	token := os.Getenv("SNOWSTEAD_ZIG_WRITE_TOKEN")
	if token == "" {
		return errors.New("save requires SNOWSTEAD_ZIG_WRITE_TOKEN")
	}
	after, err := hashTree(*project, true)
	if err != nil {
		return err
	}
	if after != sourceHash {
		return errors.New("source tree changed during build; refusing save")
	}
	archive := filepath.Join(session, "upload")
	digest, n, err := pack(root, archive)
	if err != nil {
		return err
	}
	res, err := transfer("PUT", endpoint, token, archive, digest, n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snapshot save unavailable:", err)
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != 201 && res.StatusCode != 204 {
		return fmt.Errorf("save HTTP %d (409 means immutable snapshot conflict)", res.StatusCode)
	}
	fmt.Fprintf(os.Stderr, "snapshot saved: %d bytes, HTTP %d\n", n, res.StatusCode)
	return nil
}

func main() {
	err := run()
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		fmt.Fprintf(os.Stderr, "client peak RSS KiB: %d\n", usage.Maxrss)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
