package main

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"memecdn/internal/keyless"
)

func main() {
	listen := flag.String("listen", ":443", "public HTTPS listen address")
	backendRaw := flag.String("backend", "http://127.0.0.1:8080", "upstream backend URL")
	certPath := flag.String("cert", "", "public certificate chain PEM path")
	keylessURL := flag.String("keyless-url", "", "keyless signer base URL")
	token := flag.String("token", "", "shared auth token for keyless API")
	keylessClientID := flag.String("keyless-client-id", "", "client id for signer audit logs")
	caPath := flag.String("ca", "", "CA file for verifying keyless API server")
	clientCert := flag.String("client-cert", "", "mTLS client certificate for keyless API")
	clientKey := flag.String("client-key", "", "mTLS client key for keyless API")
	cacheTTL := flag.String("cache-ttl", "10m", "static edge cache TTL, or 0 to disable")
	cacheMaxBytes := flag.String("cache-max-bytes", "67108864", "maximum in-memory static cache bytes")
	cacheMaxObjectBytes := flag.String("cache-max-object-bytes", "4194304", "maximum single cached object bytes")
	flag.Parse()

	applyEnv("EDGE_LISTEN", listen)
	applyEnv("EDGE_BACKEND", backendRaw)
	applyEnv("EDGE_CERT", certPath)
	applyEnv("KEYLESS_URL", keylessURL)
	applyEnv("KEYLESS_TOKEN", token)
	applyEnv("KEYLESS_CLIENT_ID", keylessClientID)
	applyEnv("KEYLESS_CA", caPath)
	applyEnv("KEYLESS_CLIENT_CERT", clientCert)
	applyEnv("KEYLESS_CLIENT_KEY", clientKey)
	applyEnv("EDGE_CACHE_TTL", cacheTTL)
	applyEnv("EDGE_CACHE_MAX_BYTES", cacheMaxBytes)
	applyEnv("EDGE_CACHE_MAX_OBJECT_BYTES", cacheMaxObjectBytes)

	if *certPath == "" || *keylessURL == "" {
		log.Fatal("-cert and -keyless-url are required")
	}

	transport, err := keylessTransport(*caPath, *clientCert, *clientKey)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := keyless.NewRemoteSigner(
		context.Background(),
		*keylessURL,
		*token,
		&http.Client{Transport: transport, Timeout: 10 * time.Second},
	)
	if err != nil {
		log.Fatalf("connect keyless signer: %v", err)
	}
	signer.SetClientID(*keylessClientID)

	cert, err := loadCertificateChain(*certPath)
	if err != nil {
		log.Fatalf("parse certificate: %v", err)
	}
	cert.PrivateKey = signer
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])

	backend, err := url.Parse(*backendRaw)
	if err != nil {
		log.Fatalf("parse backend URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	cache := newResponseCache(mustParseBytes(*cacheMaxBytes), mustParseBytes(*cacheMaxObjectBytes), mustParseDuration(*cacheTTL))
	proxy.ModifyResponse = func(resp *http.Response) error {
		if cache.enabled() && isCacheableStatic(resp.Request, resp) {
			if err := cache.store(resp.Request, resp); err != nil {
				return err
			}
			resp.Header.Set("X-Memecdn-Cache", "MISS")
		}
		if shouldGzip(resp.Request, resp) {
			gzipResponse(resp)
			resp.Header.Set("X-Memecdn-Compression", "gzip")
		}
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cached, ok := cache.get(r); ok {
			cached.write(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	listeners := splitListens(*listen)
	errCh := make(chan error, len(listeners))
	for _, addr := range listeners {
		server := &http.Server{
			Addr:              addr,
			Handler:           mux,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("listening on %s", server.Addr)
			errCh <- server.ListenAndServeTLS("", "")
		}()
	}
	log.Fatal(<-errCh)
}

func keylessTransport(caPath, clientCertPath, clientKeyPath string) (*http.Transport, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errNoCAPEM()
		}
		tlsConfig.RootCAs = pool
	}
	if clientCertPath != "" || clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func loadCertificateChain(path string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	var cert tls.Certificate
	remaining := data
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, errors.New("certificate file contains no CERTIFICATE blocks")
	}
	return cert, nil
}

type caPEMError struct{}

func (caPEMError) Error() string { return "CA file has no PEM certificates" }

func errNoCAPEM() error { return caPEMError{} }

func applyEnv(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

func splitListens(value string) []string {
	var listens []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			listens = append(listens, part)
		}
	}
	if len(listens) == 0 {
		return []string{":443"}
	}
	return listens
}

type cacheEntry struct {
	key       string
	status    int
	header    http.Header
	body      []byte
	storedAt  time.Time
	expiresAt time.Time
	size      int64
}

type responseCache struct {
	mu             sync.Mutex
	ttl            time.Duration
	maxBytes       int64
	maxObjectBytes int64
	bytes          int64
	ll             *list.List
	items          map[string]*list.Element
}

func newResponseCache(maxBytes int64, maxObjectBytes int64, ttl time.Duration) *responseCache {
	return &responseCache{
		ttl:            ttl,
		maxBytes:       maxBytes,
		maxObjectBytes: maxObjectBytes,
		ll:             list.New(),
		items:          make(map[string]*list.Element),
	}
}

func (c *responseCache) enabled() bool {
	return c != nil && c.ttl > 0 && c.maxBytes > 0 && c.maxObjectBytes > 0
}

func (c *responseCache) get(r *http.Request) (*cacheEntry, bool) {
	if !c.enabled() || (r.Method != http.MethodGet && r.Method != http.MethodHead) || !isStaticPath(r.URL.Path) {
		return nil, false
	}
	key := cacheKey(r)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	elem := c.items[key]
	if elem == nil {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if now.After(entry.expiresAt) {
		c.removeElement(elem)
		return nil, false
	}
	c.ll.MoveToFront(elem)
	return entry.clone(), true
}

func (c *responseCache) store(r *http.Request, resp *http.Response) error {
	if !c.enabled() || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxObjectBytes+1))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	if err != nil || int64(len(body)) > c.maxObjectBytes {
		return err
	}
	now := time.Now()
	entry := &cacheEntry{
		key:       cacheKey(r),
		status:    resp.StatusCode,
		header:    cloneHeader(resp.Header),
		body:      append([]byte(nil), body...),
		storedAt:  now,
		expiresAt: now.Add(c.ttl),
		size:      int64(len(body)),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem := c.items[entry.key]; elem != nil {
		c.removeElement(elem)
	}
	elem := c.ll.PushFront(entry)
	c.items[entry.key] = elem
	c.bytes += entry.size
	for c.bytes > c.maxBytes {
		c.removeElement(c.ll.Back())
	}
	return nil
}

func (c *responseCache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*cacheEntry)
	delete(c.items, entry.key)
	c.bytes -= entry.size
	c.ll.Remove(elem)
}

func (e *cacheEntry) clone() *cacheEntry {
	return &cacheEntry{
		status:    e.status,
		header:    cloneHeader(e.header),
		body:      append([]byte(nil), e.body...),
		storedAt:  e.storedAt,
		expiresAt: e.expiresAt,
		size:      e.size,
	}
}

func (e *cacheEntry) write(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	for k, values := range e.header {
		header.Del(k)
		for _, value := range values {
			header.Add(k, value)
		}
	}
	header.Set("X-Memecdn-Cache", "HIT")
	header.Set("Age", strconv.FormatInt(maxInt64(0, int64(time.Since(e.storedAt)/time.Second)), 10))
	header.Set("Content-Length", strconv.Itoa(len(e.body)))
	w.WriteHeader(e.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(e.body)
	}
}

func isCacheableStatic(r *http.Request, resp *http.Response) bool {
	if r == nil || resp == nil {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}
	if r.Header.Get("Authorization") != "" {
		return false
	}
	if resp.StatusCode != http.StatusOK || !isStaticPath(r.URL.Path) {
		return false
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "private") || strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Authorization") != "" {
		return false
	}
	return true
}

func isStaticPath(value string) bool {
	switch strings.ToLower(path.Ext(value)) {
	case ".css", ".js", ".mjs", ".json", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".mp4", ".webm", ".mp3", ".ogg", ".txt", ".xml":
		return true
	default:
		return false
	}
}

func cacheKey(r *http.Request) string {
	return r.Host + "\x00" + r.URL.RequestURI() + "\x00" + r.Header.Get("Accept-Encoding")
}

func shouldGzip(r *http.Request, resp *http.Response) bool {
	if r == nil || resp == nil || r.Method == http.MethodHead || isStaticPath(r.URL.Path) {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") {
		return false
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Upgrade") != "" {
		return false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "xml")
}

func gzipResponse(resp *http.Response) {
	pr, pw := io.Pipe()
	body := resp.Body
	go func() {
		gz, err := gzip.NewWriterLevel(pw, gzip.BestSpeed)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_, copyErr := io.Copy(gz, body)
		closeErr := gz.Close()
		_ = body.Close()
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
			return
		}
		_ = pw.CloseWithError(closeErr)
	}()
	resp.Body = pr
	resp.Header.Del("Content-Length")
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Add("Vary", "Accept-Encoding")
	resp.ContentLength = -1
}

func cloneHeader(header http.Header) http.Header {
	next := make(http.Header, len(header))
	for k, values := range header {
		next[k] = append([]string(nil), values...)
	}
	return next
}

func mustParseDuration(value string) time.Duration {
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		log.Fatalf("parse duration %q: %v", value, err)
	}
	return duration
}

func mustParseBytes(value string) int64 {
	if value == "" {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		log.Fatalf("parse byte size %q: %v", value, err)
	}
	return n
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
