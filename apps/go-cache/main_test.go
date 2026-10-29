package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T, endpoint string) *cache {
	t.Helper()
	t.Setenv("SNOWSTEAD_GO_CACHE_URL", endpoint)
	t.Setenv("SNOWSTEAD_GO_CACHE_TOKEN", "test-secret")
	t.Setenv("SNOWSTEAD_GO_CACHE_DIR", t.TempDir())
	t.Setenv("SNOWSTEAD_GO_CACHE_READ_ONLY", "false")
	c, err := newCache()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Exercise only the public wire protocol: bodies are separate base64 JSON
// strings, and IDs are byte slices (also base64), not hexadecimal strings.
func exchange(t *testing.T, c *cache, reqs []request, bodies map[int64][]byte) ([]response, string) {
	t.Helper()
	var input, output, stderr bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, req := range reqs {
		if err := enc.Encode(req); err != nil {
			t.Fatal(err)
		}
		// Match cmd/go's extra newline between its metadata and body values.
		input.WriteByte('\n')
		if req.BodySize > 0 {
			if err := enc.Encode(bodies[req.ID]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := c.serve(&input, &output, &stderr); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&output)
	var hello response
	if err := dec.Decode(&hello); err != nil {
		t.Fatal(err)
	}
	if hello.ID != 0 || strings.Join(hello.KnownCommands, ",") != "get,put,close" {
		t.Fatalf("capabilities: %+v", hello)
	}
	byID := make(map[int64]response)
	for {
		var r response
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if _, exists := byID[r.ID]; exists {
			t.Fatalf("duplicate response: %+v", r)
		}
		byID[r.ID] = r
	}
	if len(byID) != len(reqs) {
		t.Fatalf("responses: %+v", byID)
	}
	var results []response
	for _, req := range reqs {
		r, ok := byID[req.ID]
		if !ok {
			t.Fatalf("missing response ID %d", req.ID)
		}
		results = append(results, r)
	}
	return results, stderr.String()
}

func artifact() ([]byte, []byte, []byte) {
	body := []byte("compiler artifact\x00\xff\n")
	action, output := sha256.Sum256([]byte("action")), sha256.Sum256(body)
	return action[:], output[:], body
}

func assertFile(t *testing.T, r response, body []byte) {
	t.Helper()
	if r.Err != "" || r.Miss || !filepath.IsAbs(r.DiskPath) {
		t.Fatalf("response: %+v", r)
	}
	got, err := os.ReadFile(r.DiskPath)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("disk artifact %q: %v", got, err)
	}
}

func TestProtocolLocalAndEmpty(t *testing.T) {
	for _, size := range []int{0, 29, 65535, 65536, 65537} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			c := setup(t, "")
			a, _, _ := artifact()
			body := bytes.Repeat([]byte{0, 255, 37, 8, 91}, (size+4)/5)[:size]
			sum := sha256.Sum256(body)
			o := sum[:]
			r, _ := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}}, nil)
			if !r[0].Miss {
				t.Fatal("initial get must miss")
			}
			r, _ = exchange(t, c, []request{{ID: 2, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{2: body})
			assertFile(t, r[0], body)
			r, summary := exchange(t, c, []request{{ID: 3, Command: "get", ActionID: a}, {ID: 4, Command: "close"}}, nil)
			assertFile(t, r[0], body)
			if !bytes.Equal(r[0].OutputID, o) || r[0].Size != int64(len(body)) {
				t.Fatalf("get metadata: %+v", r[0])
			}
			if !strings.Contains(summary, "local_hits=1 remote_hits=0 misses=1") {
				t.Fatal(summary)
			}
			// A fresh helper retains the persistent cache.
			next, err := newCache()
			if err != nil {
				t.Fatal(err)
			}
			r, _ = exchange(t, next, []request{{ID: 5, Command: "get", ActionID: a}}, nil)
			assertFile(t, r[0], body)
		})
	}
}

func TestInvalidStreamDoesNotPublishOrDesynchronize(t *testing.T) {
	for _, delta := range []int{-1, 1} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			c := setup(t, "")
			a, o, body := artifact()
			r, _ := exchange(t, c, []request{
				{ID: 1, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body) + delta)},
				{ID: 2, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))},
				{ID: 3, Command: "close"},
			}, map[int64][]byte{1: body, 2: body})
			if r[0].Err == "" {
				t.Fatal("mismatched put size accepted")
			}
			assertFile(t, r[1], body)
			pending, err := filepath.Glob(filepath.Join(c.dir, ".pending-*"))
			if err != nil || len(pending) != 0 {
				t.Fatalf("partial files retained: %v, %v", pending, err)
			}
		})
	}
}

func TestTruncatedPutNeverPublishes(t *testing.T) {
	c := setup(t, "")
	a, _, _ := artifact()
	body := bytes.Repeat([]byte{7}, 49152)
	o := sha256.Sum256(body)
	var wire, output, summary bytes.Buffer
	if err := json.NewEncoder(&wire).Encode(request{ID: 1, Command: "put", ActionID: a, OutputID: o[:], BodySize: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	// All encoded bytes arrived, but the writer died before closing the JSON
	// string. A complete digest is not sufficient to publish an incomplete put.
	wire.Write(encoded[:len(encoded)-1])
	if err := c.serve(&wire, &output, &summary); err == nil {
		t.Fatal("incomplete body accepted")
	}
	r, _ := exchange(t, c, []request{{ID: 2, Command: "get", ActionID: a}}, nil)
	if !r[0].Miss {
		t.Fatal("incomplete put was published")
	}
}

func TestRemoteReads(t *testing.T) {
	a, o, body := artifact()
	for _, mode := range []string{"hit", "hash", "header", "oversize", "truncated", "missing", "unauthorized", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			redirects := 0
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects++; t.Error("redirect followed") }))
			defer target.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-secret" || r.URL.Path != "/v1/actions/"+hex.EncodeToString(a) || r.Method != "GET" {
					t.Errorf("bad request: %+v", r)
				}
				w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(o))
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				switch mode {
				case "hash":
					bodyCopy := bytes.Clone(body)
					bodyCopy[0]++
					w.Write(bodyCopy)
					return
				case "header":
					w.Header().Set("X-Snowstead-Output-ID", strings.ToUpper(hex.EncodeToString(o)))
				case "oversize":
					w.Header().Set("Content-Length", fmt.Sprint(maxArtifact+1))
					w.WriteHeader(200)
					return
				case "truncated":
					w.Write(body[:2])
					return
				case "missing":
					w.WriteHeader(404)
					return
				case "unauthorized":
					w.WriteHeader(401)
					return
				case "redirect":
					w.Header().Set("Location", target.URL)
					w.WriteHeader(302)
					return
				}
				w.Write(body)
			}))
			defer s.Close()
			c := setup(t, s.URL)
			r, summary := exchange(t, c, []request{{ID: 7, Command: "get", ActionID: a}, {ID: 8, Command: "close"}}, nil)
			if mode == "hit" {
				assertFile(t, r[0], body)
				if !strings.Contains(summary, fmt.Sprintf("downloaded_bytes=%d", len(body))) {
					t.Fatal(summary)
				}
			} else if !r[0].Miss || r[0].Err != "" {
				t.Fatalf("must safely miss: %+v", r[0])
			}
			if redirects != 0 {
				t.Fatal("redirect followed")
			}
			wantErrors := int64(1)
			if mode == "hit" || mode == "missing" {
				wantErrors = 0
			}
			if c.stats.readErrors.Load() != wantErrors || c.stats.readTimeouts.Load() != 0 {
				t.Fatalf("read errors=%d timeouts=%d: %s", c.stats.readErrors.Load(), c.stats.readTimeouts.Load(), summary)
			}
		})
	}
}

func TestRemoteLargeArtifactMakesProgress(t *testing.T) {
	// The hosted Kubernetes benchmark timed out twice on this exact size,
	// despite receiving 17,039,360 and 23,117,824 bytes before the 5s cutoff.
	// Reproduce the size and sustained progress, not the old premature cutoff.
	body := bytes.Repeat([]byte{'k'}, 23_345_386)
	a, output := sha256.Sum256([]byte("large-progress")), sha256.Sum256(body)
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(output[:]))
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for offset := 0; offset < len(body); offset += 1 << 20 {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
			end := min(offset+1<<20, len(body))
			if _, err := w.Write(body[offset:end]); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer s.Close()
	c := setup(t, s.URL)
	start := time.Now()
	r, summary := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a[:]}, {ID: 2, Command: "close"}}, nil)
	assertFile(t, r[0], body)
	if elapsed := time.Since(start); elapsed < 5*time.Second {
		t.Fatalf("regression did not cross the old total timeout: %s", elapsed)
	}
	if calls.Load() != 1 || c.remoteDisabled.Load() || !strings.Contains(summary, "remote_hits=1") || !strings.Contains(summary, "read_errors=0 read_timeouts=0 remote_disabled=false") {
		t.Fatal(summary)
	}
	t.Logf("23,345,386-byte verified download completed in %s: %s", time.Since(start), summary)
}

func TestRemoteLargeUploadMakesProgress(t *testing.T) {
	body := bytes.Repeat([]byte{'u'}, 23_345_386)
	a, output := sha256.Sum256([]byte("large-upload")), sha256.Sum256(body)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hash := sha256.New()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for remaining := len(body); remaining > 0; remaining -= min(1<<20, remaining) {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
			if _, err := io.CopyN(hash, r.Body, int64(min(1<<20, remaining))); err != nil {
				return
			}
		}
		if r.Method != http.MethodPut || r.ContentLength != int64(len(body)) || r.Header.Get("Authorization") != "Bearer test-secret" || r.Header.Get("X-Snowstead-Output-ID") != hex.EncodeToString(hash.Sum(nil)) {
			t.Error("upload headers or digest differ")
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer s.Close()
	c := setup(t, s.URL)
	path, err := c.store(hex.EncodeToString(a[:]), hex.EncodeToString(output[:]), bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := c.put(request{ID: 1, ActionID: a[:], OutputID: output[:], BodySize: int64(len(body))}, path)
	assertFile(t, r, body)
	if elapsed := time.Since(start); elapsed < 5*time.Second {
		t.Fatalf("regression did not cross the old total timeout: %s", elapsed)
	}
	if c.stats.uploads.Load() != 1 || c.stats.uploadedBytes.Load() != int64(len(body)) || c.stats.uploadErrors.Load() != 0 || c.remoteDisabled.Load() {
		t.Fatalf("uploads=%d errors=%d disabled=%t", c.stats.uploads.Load(), c.stats.uploadErrors.Load(), c.remoteDisabled.Load())
	}
}

func TestRemoteProgressDeadline(t *testing.T) {
	for _, stage := range []string{"headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if stage == "body" {
					_, output, body := artifact()
					w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(output))
					w.Write(body[:1])
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer s.Close()
			c := setup(t, s.URL)
			a, _, _ := artifact()
			start := time.Now()
			r, summary := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}}, nil)
			if !r[0].Miss || r[0].Err != "" || time.Since(start) > remoteIdleTimeout+3*time.Second {
				t.Fatalf("stalled remote did not fall back promptly: %+v in %s", r[0], time.Since(start))
			}
			// A disabled remote is a local miss, not another failed HTTP attempt.
			r, summary = exchange(t, c, []request{{ID: 2, Command: "get", ActionID: a}, {ID: 3, Command: "close"}}, nil)
			if !r[0].Miss || calls.Load() != 1 || !strings.Contains(summary, "read_errors=1 read_timeouts=1 remote_disabled=true") {
				t.Fatal(summary)
			}
			entries, err := os.ReadDir(c.dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("partial artifact published or retained: %v, %v", entries, err)
			}
		})
	}
}

func TestRemoteTrickleHasAbsoluteDeadline(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, output, _ := artifact()
		w.Header().Set("Content-Length", "100")
		w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(output))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := w.Write([]byte{'x'}); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}))
	defer s.Close()
	c := setup(t, s.URL)
	if c.client.Timeout != 69*time.Second {
		t.Fatalf("absolute production transfer budget=%s", c.client.Timeout)
	}
	// Exercise the same absolute deadline without making the unit suite wait 69s.
	c.client.Timeout = 120 * time.Millisecond
	a, _, _ := artifact()
	start := time.Now()
	r, summary := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}, {ID: 2, Command: "close"}}, nil)
	if !r[0].Miss || r[0].Err != "" || time.Since(start) > time.Second || !strings.Contains(summary, "read_errors=1 read_timeouts=1 remote_disabled=true") {
		t.Fatalf("trickling remote was not bounded: %+v, %s", r[0], summary)
	}
}

func TestRemoteWritesAndReadOnly(t *testing.T) {
	a, o, body := artifact()
	for _, status := range []int{201, 204, 409, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				got, _ := io.ReadAll(r.Body)
				if r.Method != "PUT" || r.URL.Path != "/v1/actions/"+hex.EncodeToString(a) || r.Header.Get("Authorization") != "Bearer test-secret" || r.Header.Get("X-Snowstead-Output-ID") != hex.EncodeToString(o) || r.ContentLength != int64(len(body)) || !bytes.Equal(got, body) {
					t.Error("incorrect upload")
				}
				w.WriteHeader(status)
			}))
			defer s.Close()
			c := setup(t, s.URL)
			for _, ro := range []bool{false, true} {
				c.readOnly = ro
				r, _ := exchange(t, c, []request{{ID: 1, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{1: body})
				assertFile(t, r[0], body)
				r, _ = exchange(t, c, []request{{ID: 2, Command: "get", ActionID: a}, {ID: 3, Command: "close"}}, nil)
				assertFile(t, r[0], body)
			}
			if calls != 1 {
				t.Fatalf("writes=%d", calls)
			}
			if status == 409 && c.stats.conflicts.Load() != 1 || status >= 400 && status != 409 && c.stats.uploadErrors.Load() != 1 || status < 300 && c.stats.uploads.Load() != 1 {
				t.Fatal("unexpected upload counters")
			}
		})
	}
}

func TestCorruptionAndNetworkFallback(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s.Close()
	c := setup(t, s.URL)
	a, o, body := artifact()
	r, _ := exchange(t, c, []request{{ID: 1, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{1: body})
	assertFile(t, r[0], body)
	if c.stats.uploadErrors.Load() != 1 {
		t.Fatal("network error not recorded")
	}
	if err := os.WriteFile(r[0].DiskPath, []byte("corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	r, _ = exchange(t, c, []request{{ID: 2, Command: "get", ActionID: a}}, nil)
	if !r[0].Miss || r[0].Err != "" {
		t.Fatalf("corruption served: %+v", r[0])
	}
	if err := os.WriteFile(filepath.Join(c.dir, hex.EncodeToString(a)+".action"), []byte("../../outside"), 0600); err != nil {
		t.Fatal(err)
	}
	r, _ = exchange(t, c, []request{{ID: 3, Command: "get", ActionID: a}}, nil)
	if !r[0].Miss {
		t.Fatal("invalid metadata served")
	}
}

func TestScopesAndCredentials(t *testing.T) {
	c := setup(t, "https://cache.example")
	a, o, body := artifact()
	c.readOnly = true // Avoid real networking while seeding local data.
	exchange(t, c, []request{{ID: 1, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{1: body})
	for _, change := range []struct{ key, value string }{{"SNOWSTEAD_GO_CACHE_URL", "https://other.example"}, {"SNOWSTEAD_GO_CACHE_TOKEN", "another"}, {"SNOWSTEAD_GO_CACHE_READ_ONLY", "true"}} {
		t.Run(change.key, func(t *testing.T) {
			t.Setenv(change.key, change.value)
			next, err := newCache()
			if err != nil {
				t.Fatal(err)
			}
			if next.dir == c.dir {
				t.Fatal("trust scopes overlap")
			}
			if _, err := os.Stat(filepath.Join(next.dir, hex.EncodeToString(a)+".action")); !os.IsNotExist(err) {
				t.Fatal("scope contains existing action")
			}
		})
	}
	t.Setenv("SNOWSTEAD_GO_CACHE_TOKEN", "")
	next, err := newCache()
	if err != nil {
		t.Fatal(err)
	}
	if next.endpoint != "" {
		t.Fatal("anonymous remote enabled")
	}
}

func TestAnonymousReadOnly(t *testing.T) {
	a, o, body := artifact()
	var requests atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
			t.Errorf("anonymous request must only read without an authorization header: %s", r.Method)
		}
		w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(o))
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
	}))
	defer s.Close()
	setup(t, s.URL)
	t.Setenv("SNOWSTEAD_GO_CACHE_TOKEN", "")
	t.Setenv("SNOWSTEAD_GO_CACHE_READ_ONLY", "true")
	c, err := newCache()
	if err != nil {
		t.Fatal(err)
	}
	r, _ := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}}, nil)
	assertFile(t, r[0], body)
	r, _ = exchange(t, c, []request{{ID: 2, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{2: body})
	assertFile(t, r[0], body)
	if requests.Load() != 1 {
		t.Fatal("read-only helper attempted an anonymous upload")
	}
}

func TestEndpointPolicy(t *testing.T) {
	for _, raw := range []string{"https://cache.example", "https://cache.example/base", "http://127.0.0.1:1234", "http://[::1]:1234", "http://localhost:1234"} {
		if !validEndpoint(raw) {
			t.Errorf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"", "/relative", "http://cache.example", "http://192.168.1.1", "https://user:pass@cache.example", "https://cache.example?a=b", "https://cache.example#frag", "ftp://cache.example"} {
		if validEndpoint(raw) {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestTimeoutAndInvalidPut(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	c := setup(t, s.URL)
	c.client.Timeout = 20 * time.Millisecond
	a, o, body := artifact()
	r, _ := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}, {ID: 2, Command: "put", ActionID: a, OutputID: o, BodySize: 1}}, map[int64][]byte{2: body})
	if !r[0].Miss || r[0].Err != "" || r[1].Err == "" {
		t.Fatalf("responses: %+v", r)
	}
}

func TestConcurrentRequestsAndClose(t *testing.T) {
	_, o, body := artifact()
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	releaseFirst := make(chan struct{})
	first := sha256.Sum256([]byte("request-1"))
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		if strings.HasSuffix(r.URL.Path, hex.EncodeToString(first[:])) {
			<-releaseFirst
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(o))
		w.Write(body)
	}))
	defer s.Close()
	defer func() { // unblock handlers before closing the server if the test fails
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-releaseFirst:
		default:
			close(releaseFirst)
		}
	}()
	c := setup(t, s.URL)
	var input, summary bytes.Buffer
	enc := json.NewEncoder(&input)
	for id := int64(1); id <= 64; id++ {
		a := sha256.Sum256([]byte(fmt.Sprintf("request-%d", id)))
		enc.Encode(request{ID: id, Command: "get", ActionID: a[:]})
	}
	enc.Encode(request{ID: 65, Command: "close"})
	out, writer := io.Pipe()
	defer out.Close()
	done := make(chan error, 1)
	go func() { err := c.serve(&input, writer, &summary); writer.Close(); done <- err }()
	dec := json.NewDecoder(out)
	var r response
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxConcurrent; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("requests were serialized")
		}
	}
	select {
	case <-entered:
		t.Fatal("more than 16 requests in flight")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.ID == 1 || r.ID == 65 {
		t.Fatalf("slow request or close blocked independent responses: %+v", r)
	}
	assertFile(t, r, body)
	seen := map[int64]bool{r.ID: true}
	close(releaseFirst)
	for i := 1; i < 65; i++ {
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if seen[r.ID] || r.ID < 1 || r.ID > 65 {
			t.Fatalf("unexpected response: %+v", r)
		}
		seen[r.ID] = true
		if r.ID == 65 {
			if i != 64 {
				t.Fatal("close did not drain pending requests")
			}
		} else {
			assertFile(t, r, body)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "remote_hits=64") {
		t.Fatal(summary.String())
	}
}

func TestRemoteCircuitBreaker(t *testing.T) {
	for _, failure := range []string{"401", "403", "429", "500", "503", "timeout", "disconnect", "body-timeout", "404", "409"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch failure {
				case "timeout":
					<-r.Context().Done()
				case "body-timeout":
					_, o, _ := artifact()
					w.Header().Set("Content-Length", "100")
					w.Header().Set("X-Snowstead-Output-ID", hex.EncodeToString(o))
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				case "disconnect":
					conn, _, _ := w.(http.Hijacker).Hijack()
					conn.Close()
				default:
					var status int
					fmt.Sscan(failure, &status)
					w.WriteHeader(status)
				}
			}))
			defer s.Close()
			c := setup(t, s.URL)
			c.client.Timeout = 40 * time.Millisecond
			a, o, body := artifact()
			// First failure completes before subsequent requests are submitted.
			r, _ := exchange(t, c, []request{{ID: 1, Command: "get", ActionID: a}}, nil)
			if !r[0].Miss || r[0].Err != "" {
				t.Fatalf("outage must miss: %+v", r)
			}
			r, _ = exchange(t, c, []request{{ID: 2, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body))}}, map[int64][]byte{2: body})
			assertFile(t, r[0], body)
			var reqs []request
			for i := int64(3); i <= 100; i++ {
				other := sha256.Sum256([]byte(fmt.Sprint(i)))
				reqs = append(reqs, request{ID: i, Command: "get", ActionID: other[:]})
			}
			reqs = append(reqs, request{ID: 101, Command: "get", ActionID: a}, request{ID: 102, Command: "close"})
			r, _ = exchange(t, c, reqs, nil)
			for _, miss := range r[:98] {
				if !miss.Miss || miss.Err != "" {
					t.Fatalf("expected miss: %+v", miss)
				}
			}
			assertFile(t, r[98], body)
			want := int64(1)
			if failure == "404" || failure == "409" {
				want = 100
			}
			if got := calls.Load(); got != want {
				t.Fatalf("remote calls=%d, want %d", got, want)
			}
		})
	}
}

func TestConcurrentPutBodies(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		if err != nil || r.Header.Get("X-Snowstead-Output-ID") != hex.EncodeToString(sum[:]) || r.Header.Get("Authorization") != "Bearer test-secret" || r.ContentLength != int64(len(body)) {
			t.Error("put body/header mismatch")
		}
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(201)
	}))
	defer s.Close()
	c := setup(t, s.URL)
	var puts, gets []request
	bodies := make(map[int64][]byte)
	for id := int64(1); id <= 40; id++ {
		body := bytes.Repeat([]byte(fmt.Sprintf("body-%d\x00", id)), 100)
		if id == 1 {
			body = nil
		}
		a, o := sha256.Sum256([]byte(fmt.Sprint(id))), sha256.Sum256(body)
		puts = append(puts, request{ID: id, Command: "put", ActionID: a[:], OutputID: o[:], BodySize: int64(len(body))})
		gets = append(gets, request{ID: id, Command: "get", ActionID: a[:]})
		bodies[id] = body
	}
	puts = append(puts, request{ID: 41, Command: "close"})
	r, summary := exchange(t, c, puts, bodies)
	for i := 0; i < 40; i++ {
		assertFile(t, r[i], bodies[r[i].ID])
	}
	if !strings.Contains(summary, "uploads=40 upload_errors=0") {
		t.Fatal(summary)
	}
	r, _ = exchange(t, c, gets, nil)
	for _, result := range r {
		assertFile(t, result, bodies[result.ID])
	}
}

func TestPutBackpressureBeforeBodyDecode(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == maxConcurrent {
			close(entered)
		}
		<-release
		w.WriteHeader(404)
	}))
	defer s.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	c := setup(t, s.URL)
	in, writer := io.Pipe()
	defer writer.Close()
	var output, summary bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- c.serve(in, &output, &summary) }()
	enc := json.NewEncoder(writer)
	a, o, body := artifact()
	for id := int64(1); id <= maxConcurrent; id++ {
		if err := enc.Encode(request{ID: id, Command: "get", ActionID: a}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("get did not start")
	}
	// A full wave of pending requests must apply backpressure before the next
	// body is consumed. Its deliberately wrong size is still rejected afterward.
	if err := enc.Encode(request{ID: maxConcurrent + 1, Command: "put", ActionID: a, OutputID: o, BodySize: int64(len(body) + 1)}); err != nil {
		t.Fatal(err)
	}
	bodyWritten := make(chan error, 1)
	go func() { bodyWritten <- enc.Encode(body) }()
	select {
	case err := <-bodyWritten:
		t.Fatalf("body decoded without backpressure: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-bodyWritten; err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(request{ID: maxConcurrent + 2, Command: "close"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&output)
	var r response
	for i := 0; i < maxConcurrent+3; i++ {
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if r.ID == maxConcurrent+1 && r.Err == "" {
			t.Fatal("size mismatch was accepted")
		}
	}
	if r.ID != maxConcurrent+2 {
		t.Fatal("close was not last")
	}
}
