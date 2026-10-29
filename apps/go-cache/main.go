// Command go-cache implements the Go GOCACHEPROG JSON protocol.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxArtifact = 64 << 20
const maxConcurrent = 16
const remoteIdleTimeout = 5 * time.Second

// Allow a maximum-size artifact at 1 MiB/s plus connection/header time.
// The progress deadline still stops a stalled remote in five seconds;
// this absolute ceiling also bounds peers that keep trickling bytes.
const remoteRequestTimeout = remoteIdleTimeout + maxArtifact/(1<<20)*time.Second

var errRemoteDisabled = errors.New("remote cache disabled")

type request struct {
	ID                 int64
	Command            string
	ActionID, OutputID []byte
	BodySize           int64
}

type response struct {
	ID            int64
	Err           string   `json:",omitempty"`
	KnownCommands []string `json:",omitempty"`
	Miss          bool     `json:",omitempty"`
	OutputID      []byte   `json:",omitempty"`
	Size          int64    `json:",omitempty"`
	DiskPath      string   `json:",omitempty"`
}

type stats struct {
	localHits, remoteHits, misses, uploads, uploadErrors, conflicts, downloadedBytes, uploadedBytes atomic.Int64
	readErrors, readTimeouts                                                                        atomic.Int64
}

type cache struct {
	dir, endpoint, token string
	readOnly             bool
	client               *http.Client
	stats                stats
	remoteDisabled       atomic.Bool
}

func newCache() (*cache, error) {
	endpoint := os.Getenv("SNOWSTEAD_GO_CACHE_URL")
	token := os.Getenv("SNOWSTEAD_GO_CACHE_TOKEN")
	readOnly := os.Getenv("SNOWSTEAD_GO_CACHE_READ_ONLY") == "true"
	// Include the credential and write policy even with a caller-selected directory:
	// a locally compiled result from a writer must not seed a read-only trust scope.
	scope, _ := json.Marshal([]any{endpoint, token, readOnly})
	sum := sha256.Sum256(scope)
	root := os.Getenv("SNOWSTEAD_GO_CACHE_DIR")
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(base, "snowstead-go-cache")
	}
	dir, err := filepath.Abs(filepath.Join(root, hex.EncodeToString(sum[:])))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = maxConcurrent
	transport.MaxConnsPerHost = maxConcurrent
	transport.ResponseHeaderTimeout = remoteIdleTimeout
	c := &cache{dir: dir, token: token, readOnly: readOnly, client: &http.Client{
		Transport:     transport,
		Timeout:       remoteRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if validEndpoint(endpoint) && (token != "" || readOnly) {
		c.endpoint = strings.TrimRight(endpoint, "/")
	}
	return c, nil
}

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback()))
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func atomicWrite(path string, body []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Publish only after all bytes, the size, and the output digest are verified.
// The same bounded-memory path handles remote downloads and Go's put stream.
func (c *cache) store(action, output string, body io.Reader, size int64) (string, error) {
	f, err := os.CreateTemp(c.dir, ".pending-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, size+1))
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n != size || !validID(action) || !validID(output) || hex.EncodeToString(h.Sum(nil)) != output {
		return "", errors.New("invalid put IDs, size, or body digest")
	}
	path := filepath.Join(c.dir, output)
	if err := os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(c.dir, action+".action"), []byte(output)); err != nil {
		return "", err
	}
	return path, nil
}

// Watch each request, not the shared connection: another HTTP/2 stream must
// not keep a stalled transfer alive. Upload pulls and download reads refresh
// the deadline without buffering artifacts or starting a polling goroutine.
type requestProgress struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	timer  *time.Timer
	mu     sync.Mutex
	closed bool
}

func (p *requestProgress) touch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.timer.Reset(remoteIdleTimeout)
	}
}

func (p *requestProgress) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.timer.Stop()
	p.cancel(nil)
}

func (p *requestProgress) read(reader io.Reader, body []byte) (int, error) {
	n, err := reader.Read(body)
	if n > 0 {
		p.touch()
	}
	if err != nil && errors.Is(context.Cause(p.ctx), context.DeadlineExceeded) {
		err = context.DeadlineExceeded
	}
	return n, err
}

type progressReader struct {
	io.Reader
	progress *requestProgress
}

func (r progressReader) Read(body []byte) (int, error) {
	return r.progress.read(r.Reader, body)
}

type progressBody struct {
	io.ReadCloser
	progress *requestProgress
}

func (b progressBody) Read(body []byte) (int, error) {
	return b.progress.read(b.ReadCloser, body)
}

func (b progressBody) Close() error {
	b.progress.close()
	return b.ReadCloser.Close()
}

func (c *cache) remote(method, action, output string, body io.Reader, size int64) (*http.Response, error) {
	// Anonymous reads require explicit read-only mode. Writes always need a
	// credential, even if a public endpoint were to accept anonymous uploads.
	if c.endpoint == "" || (c.token == "" && (!c.readOnly || method != http.MethodGet)) || c.remoteDisabled.Load() {
		return nil, errRemoteDisabled
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	progress := &requestProgress{ctx: ctx, cancel: cancel}
	progress.timer = time.AfterFunc(remoteIdleTimeout, func() { cancel(context.DeadlineExceeded) })
	if body != nil {
		body = progressReader{Reader: body, progress: progress}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/v1/actions/"+action, body)
	if err != nil {
		progress.close()
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if method == http.MethodPut {
		req.Header.Set("X-Snowstead-Output-ID", output)
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
	}
	res, err := c.client.Do(req)
	if err != nil {
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			err = context.DeadlineExceeded
		}
		progress.close()
		c.remoteDisabled.Store(true)
	} else {
		progress.touch()
		res.Body = progressBody{ReadCloser: res.Body, progress: progress}
		if res.StatusCode == 401 || res.StatusCode == 403 || res.StatusCode == 429 || res.StatusCode >= 500 {
			c.remoteDisabled.Store(true)
		}
	}
	return res, err
}

func (c *cache) recordReadError(err error) {
	c.stats.readErrors.Add(1)
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		c.stats.readTimeouts.Add(1)
	}
}

func (c *cache) get(req request) response {
	r := response{ID: req.ID, Miss: true}
	if len(req.ActionID) != sha256.Size {
		c.stats.misses.Add(1)
		return r
	}
	action := hex.EncodeToString(req.ActionID)
	if meta, err := os.ReadFile(filepath.Join(c.dir, action+".action")); err == nil && validID(string(meta)) {
		path := filepath.Join(c.dir, string(meta))
		if f, err := os.Open(path); err == nil {
			h := sha256.New()
			size, err := io.Copy(h, f)
			f.Close()
			if err == nil && hex.EncodeToString(h.Sum(nil)) == string(meta) {
				c.stats.localHits.Add(1)
				return response{ID: req.ID, OutputID: h.Sum(nil), Size: size, DiskPath: path}
			}
		}
	}
	res, err := c.remote(http.MethodGet, action, "", nil, 0)
	if err == nil {
		defer res.Body.Close()
		output := res.Header.Get("X-Snowstead-Output-ID")
		if res.StatusCode == http.StatusOK && validID(output) && res.ContentLength >= 0 && res.ContentLength <= maxArtifact {
			if path, err := c.store(action, output, res.Body, res.ContentLength); err == nil {
				c.stats.remoteHits.Add(1)
				c.stats.downloadedBytes.Add(res.ContentLength)
				id, _ := hex.DecodeString(output)
				return response{ID: req.ID, OutputID: id, Size: res.ContentLength, DiskPath: path}
			} else {
				c.recordReadError(err)
				c.remoteDisabled.Store(true)
			}
		} else if res.StatusCode != http.StatusNotFound {
			c.recordReadError(nil)
		}
	} else if !errors.Is(err, errRemoteDisabled) {
		c.recordReadError(err)
	}
	c.stats.misses.Add(1)
	return r
}

func (c *cache) put(req request, path string) response {
	r := response{ID: req.ID, DiskPath: path}
	action, output := hex.EncodeToString(req.ActionID), hex.EncodeToString(req.OutputID)
	if c.readOnly || c.endpoint == "" || c.remoteDisabled.Load() || req.BodySize > maxArtifact {
		return r
	}
	f, err := os.Open(path)
	if err != nil {
		c.stats.uploadErrors.Add(1)
		return r
	}
	defer f.Close()
	res, err := c.remote(http.MethodPut, action, output, f, req.BodySize)
	if err != nil {
		c.stats.uploadErrors.Add(1)
		return r
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusCreated, http.StatusNoContent:
		c.stats.uploads.Add(1)
		c.stats.uploadedBytes.Add(req.BodySize)
	case http.StatusConflict:
		c.stats.conflicts.Add(1)
	default:
		c.stats.uploadErrors.Add(1)
	}
	return r
}

// Go emits a base64 JSON string with no escapes. Read to its closing quote in
// fixed-size chunks instead of asking encoding/json to allocate the whole body.
type bodyReader struct {
	in      *bufio.Reader
	pending []byte
	done    bool
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if len(b.pending) == 0 {
		if b.done {
			return 0, io.EOF
		}
		chunk, err := b.in.ReadSlice('"')
		if err == nil {
			chunk, b.done = chunk[:len(chunk)-1], true
		} else if err != bufio.ErrBufferFull {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if bytes.IndexAny(chunk, "\\\r\n") >= 0 {
			return 0, errors.New("invalid Go base64 body")
		}
		b.pending = chunk
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (c *cache) serve(in io.Reader, out, stderr io.Writer) (result error) {
	defer func() {
		s := &c.stats
		fmt.Fprintf(stderr, "snowstead-go-cache: local_hits=%d remote_hits=%d misses=%d uploads=%d upload_errors=%d conflicts=%d downloaded_bytes=%d uploaded_bytes=%d read_errors=%d read_timeouts=%d remote_disabled=%t\n", s.localHits.Load(), s.remoteHits.Load(), s.misses.Load(), s.uploads.Load(), s.uploadErrors.Load(), s.conflicts.Load(), s.downloadedBytes.Load(), s.uploadedBytes.Load(), s.readErrors.Load(), s.readTimeouts.Load(), c.remoteDisabled.Load())
	}()
	reader, enc := bufio.NewReaderSize(in, 64<<10), json.NewEncoder(out)
	if err := enc.Encode(response{KnownCommands: []string{"get", "put", "close"}}); err != nil {
		return err
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	ready := sync.NewCond(&mu)
	var active int
	var writeErr error
	defer func() { // drain even on EOF or malformed input, before the summary
		workers.Wait()
		if result == nil {
			result = writeErr
		}
	}()
	for {
		var req request
		line, err := reader.ReadSlice('\n')
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				return nil
			}
			return err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &req); err != nil {
			return err
		}
		if req.Command == "close" {
			workers.Wait()
			if writeErr != nil {
				return writeErr
			}
			return enc.Encode(response{ID: req.ID})
		}
		mu.Lock()
		for active == maxConcurrent {
			ready.Wait()
		}
		if writeErr != nil {
			mu.Unlock()
			return writeErr
		}
		active++
		mu.Unlock()
		var path string
		var putErr error
		if req.Command == "put" {
			var body io.Reader = bytes.NewReader(nil)
			var raw *bodyReader
			if req.BodySize > 0 {
				// Go writes an extra newline after the encoded request. JSON
				// whitespace may precede its separately encoded body string.
				quote, err := reader.ReadByte()
				for err == nil && (quote == ' ' || quote == '\t' || quote == '\r' || quote == '\n') {
					quote, err = reader.ReadByte()
				}
				if err != nil || quote != '"' {
					return errors.New("expected Go base64 body")
				}
				raw = &bodyReader{in: reader}
				body = base64.NewDecoder(base64.StdEncoding, raw)
			}
			path, putErr = c.store(hex.EncodeToString(req.ActionID), hex.EncodeToString(req.OutputID), body, req.BodySize)
			if raw != nil {
				if _, err := io.Copy(io.Discard, raw); err != nil {
					return err
				}
			}
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			var r response
			switch req.Command {
			case "get":
				r = c.get(req)
			case "put":
				if putErr != nil {
					r = response{ID: req.ID, Err: putErr.Error()}
				} else {
					r = c.put(req, path)
				}
			default:
				r = response{ID: req.ID, Err: "unknown command"}
			}
			mu.Lock()
			defer mu.Unlock()
			if writeErr == nil {
				writeErr = enc.Encode(r)
			}
			active--
			ready.Broadcast()
		}()
	}
}

func main() {
	c, err := newCache()
	if err == nil {
		err = c.serve(os.Stdin, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "snowstead-go-cache:", err)
		os.Exit(1)
	}
}
