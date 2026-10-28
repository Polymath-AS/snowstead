package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCompatibilityFencesInputsTrustAndAbsoluteLayout(t *testing.T) {
	base := compatibility{Format: "zig-snapshot-v1", Trust: "project-reviewed", ToolchainHash: "stock-distribution", OS: "linux", Arch: "amd64", CPU: []string{"baseline"}, SourceHash: "source-and-dependencies", Context: "external-inputs", BuildArgs: []string{"-Doptimize=ReleaseFast"}, ProjectRoot: "/ci/source", ToolchainRoot: "/opt/zig", SessionRoot: "/ci/session"}
	for name, mutate := range map[string]func(*compatibility){
		"trust":          func(c *compatibility) { c.Trust = "other-project" },
		"compiler":       func(c *compatibility) { c.ToolchainHash = "other-distribution" },
		"host":           func(c *compatibility) { c.OS = "other-host" },
		"arch":           func(c *compatibility) { c.Arch = "arm64" },
		"cpu":            func(c *compatibility) { c.CPU = []string{"other-ISA"} },
		"kernel-libc":    func(c *compatibility) { c.NativeTarget = "linux.7.2.6-gnu.2.42" },
		"source":         func(c *compatibility) { c.SourceHash = "changed-source-import-or-embed" },
		"external":       func(c *compatibility) { c.Context = "changed-SDK" },
		"options":        func(c *compatibility) { c.BuildArgs = []string{"-Doptimize=ReleaseSmall"} },
		"target":         func(c *compatibility) { c.BuildArgs = []string{"-Dtarget=aarch64-linux"} },
		"checkout":       func(c *compatibility) { c.ProjectRoot = "/other/source" },
		"toolchain-path": func(c *compatibility) { c.ToolchainRoot = "/other/zig" },
		"scratch-path":   func(c *compatibility) { c.SessionRoot = "/other/session" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if changed.key() == base.key() {
				t.Fatal("incompatible snapshot selected")
			}
		})
	}
	if base.key() != base.key() {
		t.Fatal("unstable compatibility key")
	}
}

func TestRoundtripAndExcludedMutableState(t *testing.T) {
	root := t.TempDir()
	manifest := "local/h/0123456789abcdef0123456789abcdef"
	builtin := "global/b/0123456789abcdef0123456789abcdef/builtin.zig"
	configuration := "local/c/0123456789abcdef0123456789abcdef"
	for _, name := range []string{"local/o/hash/bin", manifest, builtin, configuration, "local/h/timestamp", "global/o/hash/build", "local/z/zir", "local/tmp/partial", "global/p/package"} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "snapshot")
	_, _, err := pack(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err = unpack(archive, out); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(out, "local/o/hash/bin")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{manifest, builtin, configuration} {
		if _, err = os.Stat(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"local/z", "local/tmp", "global/p", "local/h/timestamp"} {
		if _, err = os.Stat(filepath.Join(out, p)); !os.IsNotExist(err) {
			t.Fatalf("mutable path restored: %s", p)
		}
	}
}

func TestRejectUnsafeArchives(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      byte
		duplicate bool
		size      int64
	}{
		{"../outside", tar.TypeReg, false, 0}, {"local/o/../../outside", tar.TypeReg, false, 0},
		{"/local/o/x", tar.TypeReg, false, 0}, {"local/o/link", tar.TypeSymlink, false, 0},
		{"local/o/link", tar.TypeLink, false, 0}, {"local/o/file", tar.TypeReg, true, 0},
		{"local/z/file", tar.TypeReg, false, 0}, {"local/o/large", tar.TypeReg, false, maxExpanded + 1},
	} {
		t.Run(fmt.Sprintf("%s-%d-%t", tc.name, tc.kind, tc.duplicate), func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "bad")
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(f)
			tw := tar.NewWriter(gz)
			h := &tar.Header{Name: tc.name, Mode: 0600, Typeflag: tc.kind, Linkname: "outside", Size: tc.size}
			if tc.kind == tar.TypeReg {
				h.Linkname = ""
			}
			if err = tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if tc.duplicate {
				if err = tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
			}
			// An oversized header is rejected before attempting its missing body.
			tw.Close()
			gz.Close()
			f.Close()
			if err = unpack(f.Name(), t.TempDir()); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestCorruptRestoreNeverPublishesAndConcurrentRestoreIsIsolated(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "local/o/id"), 0700)
	os.WriteFile(filepath.Join(root, "local/o/id/file"), []byte("valid"), 0600)
	archive := filepath.Join(t.TempDir(), "snapshot")
	digest, _, err := pack(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Snapshot-SHA256", digest)
		if r.URL.Path == "/corrupt" {
			w.Write([]byte("corrupt"))
			return
		}
		w.Write(body)
	}))
	defer server.Close()
	session := t.TempDir()
	if restore(server.URL+"/corrupt", "", session) == nil {
		t.Fatal("corruption accepted")
	}
	if _, err = os.Stat(filepath.Join(session, "cache")); !os.IsNotExist(err) {
		t.Fatal("failed restore published")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := restore(server.URL, "", t.TempDir()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestSourceHashIgnoresMetadataNotContents(t *testing.T) {
	for _, name := range []string{"main.zig", "import.zig", "embedded.txt", "lib/std.zig"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("one"), 0600); err != nil {
				t.Fatal(err)
			}
			a, err := hashTree(root, true)
			if err != nil {
				t.Fatal(err)
			}
			stat, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(p, []byte("two"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(p, stat.ModTime(), stat.ModTime()); err != nil {
				t.Fatal(err)
			}
			b, err := hashTree(root, true)
			if err != nil {
				t.Fatal(err)
			}
			if a == b {
				t.Fatal("same-size same-mtime content change missed")
			}
		})
	}
}

func TestVerifiedButInvalidArchiveDoesNotPublishPartialOutputs(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, header := range []*tar.Header{
		{Name: "local/o/id/output", Mode: 0600, Typeflag: tar.TypeReg},
		{Name: "local/o/link", Typeflag: tar.TypeSymlink, Linkname: "outside"},
	} {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Snapshot-SHA256", digest)
		w.Write(archive.Bytes())
	}))
	defer server.Close()
	session := t.TempDir()
	if restore(server.URL, "", session) == nil {
		t.Fatal("unsafe archive accepted")
	}
	for _, name := range []string{"cache", "stage", "download"} {
		if _, err := os.Stat(filepath.Join(session, name)); !os.IsNotExist(err) {
			t.Fatalf("partial restore remains: %s", name)
		}
	}
}
