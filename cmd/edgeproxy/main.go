package main

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"memecdn/internal/keyless"

	"golang.org/x/net/http2"
)

func main() {
	listen := flag.String("listen", ":443", "public HTTPS listen address")
	backendRaw := flag.String("backend", "http://127.0.0.1:8080", "upstream backend URL")
	certPath := flag.String("cert", "", "public certificate chain PEM path")
	certPaths := flag.String("certs", "", "comma-separated certificate chain entries, optionally key_id=path")
	keylessURL := flag.String("keyless-url", "", "keyless signer base URL")
	token := flag.String("token", "", "shared auth token for keyless API")
	keylessClientID := flag.String("keyless-client-id", "", "client id for signer audit logs")
	caPath := flag.String("ca", "", "CA file for verifying keyless API server")
	clientCert := flag.String("client-cert", "", "mTLS client certificate for keyless API")
	clientKey := flag.String("client-key", "", "mTLS client key for keyless API")
	tokenFile := flag.String("token-file", "", "file for a persisted signer token")
	registerURL := flag.String("register-url", "", "signer console URL for edge self-enrollment")
	registerID := flag.String("register-id", "", "edge client id for self-enrollment")
	registerLabel := flag.String("register-label", "", "edge label for self-enrollment")
	registerToken := flag.String("register-token", "", "one-time install token for self-enrollment")
	registerPoll := flag.String("register-poll", "10s", "self-enrollment polling interval")
	cacheTTL := flag.String("cache-ttl", "10m", "static edge cache TTL, or 0 to disable")
	cacheMaxBytes := flag.String("cache-max-bytes", "67108864", "maximum in-memory static cache bytes")
	cacheMaxObjectBytes := flag.String("cache-max-object-bytes", "4194304", "maximum single cached object bytes")
	pluginRoutesPath := flag.String("plugin-routes", "", "optional local plugin route JSON path")
	flag.Parse()

	applyEnv("EDGE_LISTEN", listen)
	applyEnv("EDGE_BACKEND", backendRaw)
	applyEnv("EDGE_CERT", certPath)
	applyEnv("EDGE_CERTS", certPaths)
	applyEnv("KEYLESS_URL", keylessURL)
	applyEnv("KEYLESS_TOKEN", token)
	applyEnv("KEYLESS_CLIENT_ID", keylessClientID)
	applyEnv("KEYLESS_CA", caPath)
	applyEnv("KEYLESS_CLIENT_CERT", clientCert)
	applyEnv("KEYLESS_CLIENT_KEY", clientKey)
	applyEnv("KEYLESS_TOKEN_FILE", tokenFile)
	applyEnv("EDGE_REGISTER_URL", registerURL)
	applyEnv("EDGE_REGISTER_ID", registerID)
	applyEnv("EDGE_REGISTER_LABEL", registerLabel)
	applyEnv("EDGE_REGISTER_TOKEN", registerToken)
	applyEnv("EDGE_REGISTER_POLL", registerPoll)
	applyEnv("EDGE_CACHE_TTL", cacheTTL)
	applyEnv("EDGE_CACHE_MAX_BYTES", cacheMaxBytes)
	applyEnv("EDGE_CACHE_MAX_OBJECT_BYTES", cacheMaxObjectBytes)
	applyEnv("EDGE_PLUGIN_ROUTES", pluginRoutesPath)

	if *token == "" && *tokenFile != "" {
		loadedToken, err := readTokenFile(*tokenFile)
		if err != nil {
			log.Fatalf("read token file: %v", err)
		}
		*token = loadedToken
	}
	enrolledInstallToken := ""
	var enrolledConfig map[string]string
	if *token == "" && *registerURL != "" && *registerID != "" {
		enrolledToken, installToken, config, err := enrollEdge(context.Background(), *registerURL, *registerID, *registerLabel, *registerToken, mustParseDuration(*registerPoll))
		if err != nil {
			log.Fatalf("edge enrollment failed: %v", err)
		}
		*token = enrolledToken
		enrolledInstallToken = installToken
		enrolledConfig = config
		if *tokenFile != "" {
			if err := writeTokenFile(*tokenFile, enrolledToken); err != nil {
				log.Fatalf("write token file: %v", err)
			}
		}
	}
	applyRemoteDefault("KEYLESS_URL", keylessURL, enrolledConfig)
	if (*certPath == "" && *certPaths == "") || *keylessURL == "" {
		log.Fatal("-cert or -certs and -keyless-url are required")
	}

	transport, err := keylessTransport(*caPath, *clientCert, *clientKey)
	if err != nil {
		log.Fatal(err)
	}
	keylessClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	if enrolledInstallToken != "" {
		if err := reportInstallVerified(context.Background(), *registerURL, enrolledInstallToken); err != nil {
			log.Printf("warning: report edge install verification: %v", err)
		}
	}

	certificates, err := loadKeylessCertificates(context.Background(), certificateSpecs(*certPath, *certPaths), *keylessURL, *token, *keylessClientID, keylessClient)
	if err != nil {
		log.Fatalf("load certificates: %v", err)
	}

	backend, err := url.Parse(*backendRaw)
	if err != nil {
		log.Fatalf("parse backend URL: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backend)
	pluginRoutes, err := loadPluginRoutes(*pluginRoutesPath)
	if err != nil {
		log.Fatalf("load plugin routes: %v", err)
	}
	cache := newResponseCache(mustParseBytes(*cacheMaxBytes), mustParseBytes(*cacheMaxObjectBytes), mustParseDuration(*cacheTTL))
	proxy.ModifyResponse = func(resp *http.Response) error {
		if cache.enabled() && isCacheableResponse(resp.Request, resp) {
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
		if route := pluginRoutes.match(r); route != nil {
			route.proxy.ServeHTTP(w, r)
			return
		}
		if cached, ok := cache.get(r); ok {
			cached.write(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certificates,
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

type certificateSpec struct {
	KeyID string
	Path  string
}

func certificateSpecs(singlePath string, multiValue string) []certificateSpec {
	var specs []certificateSpec
	if strings.TrimSpace(multiValue) != "" {
		for _, raw := range strings.Split(multiValue, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			keyID, path, ok := strings.Cut(raw, "=")
			if !ok {
				keyID, path = "", keyID
			}
			specs = append(specs, certificateSpec{
				KeyID: strings.TrimSpace(keyID),
				Path:  strings.TrimSpace(path),
			})
		}
		return specs
	}
	if strings.TrimSpace(singlePath) != "" {
		specs = append(specs, certificateSpec{Path: strings.TrimSpace(singlePath)})
	}
	return specs
}

func loadKeylessCertificates(ctx context.Context, specs []certificateSpec, keylessURL string, token string, clientID string, client *http.Client) ([]tls.Certificate, error) {
	if len(specs) == 0 {
		return nil, errors.New("no certificate paths configured")
	}
	certificates := make([]tls.Certificate, 0, len(specs))
	for _, spec := range specs {
		if spec.Path == "" {
			return nil, errors.New("empty certificate path")
		}
		signer, err := keyless.NewRemoteSignerForKey(ctx, keylessURL, token, spec.KeyID, client)
		if err != nil {
			if spec.KeyID != "" {
				return nil, fmt.Errorf("connect keyless signer for key %q: %w", spec.KeyID, err)
			}
			return nil, fmt.Errorf("connect keyless signer: %w", err)
		}
		signer.SetClientID(clientID)
		cert, err := loadCertificateChain(spec.Path)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %s: %w", spec.Path, err)
		}
		cert.PrivateKey = signer
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		certificates = append(certificates, cert)
	}
	return certificates, nil
}

type caPEMError struct{}

func (caPEMError) Error() string { return "CA file has no PEM certificates" }

func errNoCAPEM() error { return caPEMError{} }

func applyEnv(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

func applyRemoteDefault(name string, target *string, config map[string]string) {
	if *target != "" || config == nil {
		return
	}
	if value := strings.TrimSpace(config[name]); value != "" {
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

type pluginRouteConfig struct {
	Routes []pluginRouteSpec `json:"routes"`
}

type pluginRouteSpec struct {
	Name         string   `json:"name"`
	Hosts        []string `json:"hosts,omitempty"`
	ExactPaths   []string `json:"exact_paths,omitempty"`
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	Backend      string   `json:"backend"`
	Protocol     string   `json:"protocol,omitempty"`
}

type pluginRoutes []*pluginRoute

type pluginRoute struct {
	name         string
	hosts        map[string]struct{}
	exactPaths   map[string]struct{}
	pathPrefixes []string
	proxy        *httputil.ReverseProxy
}

func loadPluginRoutes(path string) (pluginRoutes, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config pluginRouteConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	routes := make(pluginRoutes, 0, len(config.Routes))
	for _, spec := range config.Routes {
		route, err := newPluginRoute(spec)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	if len(routes) > 0 {
		log.Printf("loaded %d plugin route(s) from %s", len(routes), path)
	}
	return routes, nil
}

func newPluginRoute(spec pluginRouteSpec) (*pluginRoute, error) {
	if spec.Backend == "" {
		return nil, errors.New("plugin route backend is required")
	}
	backend, err := url.Parse(spec.Backend)
	if err != nil {
		return nil, err
	}
	if backend.Scheme == "" || backend.Host == "" {
		return nil, errors.New("plugin route backend must include scheme and host")
	}
	protocol := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if protocol == "" {
		protocol = "http"
	}
	proxyBackend := *backend
	if protocol == "h2c" {
		proxyBackend.Scheme = "http"
	}
	proxy := httputil.NewSingleHostReverseProxy(&proxyBackend)
	switch protocol {
	case "http", "http1", "ws", "websocket":
	case "h2c", "grpc-h2c":
		proxy.Transport = h2cTransport()
	default:
		return nil, errors.New("unsupported plugin route protocol: " + spec.Protocol)
	}
	route := &pluginRoute{
		name:         spec.Name,
		hosts:        makeHostSet(spec.Hosts),
		exactPaths:   makePathSet(spec.ExactPaths),
		pathPrefixes: cleanPathList(spec.PathPrefixes),
		proxy:        proxy,
	}
	if len(route.exactPaths) == 0 && len(route.pathPrefixes) == 0 {
		return nil, errors.New("plugin route requires exact_paths or path_prefixes")
	}
	return route, nil
}

func (routes pluginRoutes) match(r *http.Request) *pluginRoute {
	for _, route := range routes {
		if route.matches(r) {
			return route
		}
	}
	return nil
}

func (r *pluginRoute) matches(req *http.Request) bool {
	if len(r.hosts) > 0 {
		host := strings.ToLower(req.Host)
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		if _, ok := r.hosts[host]; !ok {
			return false
		}
	}
	path := req.URL.Path
	if _, ok := r.exactPaths[path]; ok {
		return true
	}
	for _, prefix := range r.pathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func h2cTransport() *http2.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
}

func makeHostSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func makePathSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range cleanPathList(values) {
		out[value] = struct{}{}
	}
	return out
}

func cleanPathList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

type registerRequest struct {
	ID           string `json:"id"`
	Label        string `json:"label,omitempty"`
	InstallToken string `json:"install_token,omitempty"`
}

type installResponse struct {
	KeylessToken string            `json:"keyless_token"`
	EdgeConfig   map[string]string `json:"edge_config,omitempty"`
}

func enrollEdge(ctx context.Context, consoleURL, id, label, installToken string, pollInterval time.Duration) (string, string, map[string]string, error) {
	consoleURL = strings.TrimRight(consoleURL, "/")
	if installToken == "" {
		installToken = randomToken()
	}
	if label == "" {
		label = id
	}
	payload, err := json.Marshal(registerRequest{ID: id, Label: label, InstallToken: installToken})
	if err != nil {
		return "", "", nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, consoleURL+"/api/register", bytes.NewReader(payload))
	if err != nil {
		return "", "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusConflict {
		return "", "", nil, errors.New("edge registration failed: " + resp.Status)
	}
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", "", nil, ctx.Err()
		case <-ticker.C:
			install, err := fetchInstallToken(ctx, client, consoleURL, installToken)
			if err == nil && install.KeylessToken != "" {
				return install.KeylessToken, installToken, install.EdgeConfig, nil
			}
			if err != nil && !errors.Is(err, errInstallPending) {
				return "", "", nil, err
			}
			log.Printf("edge registration %s pending approval", id)
		}
	}
}

var errInstallPending = errors.New("install pending")

func fetchInstallToken(ctx context.Context, client *http.Client, consoleURL, installToken string) (installResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, consoleURL+"/api/install/"+installToken+"?format=json", nil)
	if err != nil {
		return installResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return installResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return installResponse{}, errInstallPending
	}
	if resp.StatusCode != http.StatusOK {
		return installResponse{}, errors.New("install token fetch failed: " + resp.Status)
	}
	var install installResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&install); err != nil {
		return installResponse{}, err
	}
	if install.KeylessToken == "" {
		return installResponse{}, errors.New("install response missing keyless token")
	}
	return install, nil
}

func reportInstallVerified(ctx context.Context, consoleURL, installToken string) error {
	consoleURL = strings.TrimRight(consoleURL, "/")
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, consoleURL+"/api/install/"+installToken+"/verified", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("install verification report failed: " + resp.Status)
	}
	return nil
}

func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeTokenFile(path string, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token+"\n"), 0600)
}

func randomToken() string {
	var raw [48]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
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
	if !c.enabled() || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
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
	ttl := cacheTTLFromResponse(resp, c.ttl)
	entry := &cacheEntry{
		key:       cacheKey(r),
		status:    resp.StatusCode,
		header:    cloneHeader(resp.Header),
		body:      append([]byte(nil), body...),
		storedAt:  now,
		expiresAt: now.Add(ttl),
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

func isCacheableResponse(r *http.Request, resp *http.Response) bool {
	if r == nil || resp == nil {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}
	if r.Header.Get("Authorization") != "" {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "private") || strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Authorization") != "" {
		return false
	}
	return strings.Contains(cacheControl, "public") ||
		cacheDirectiveSeconds(cacheControl, "s-maxage") > 0 ||
		cacheDirectiveSeconds(cacheControl, "max-age") > 0
}

func cacheTTLFromResponse(resp *http.Response, fallback time.Duration) time.Duration {
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if seconds := cacheDirectiveSeconds(cacheControl, "s-maxage"); seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if seconds := cacheDirectiveSeconds(cacheControl, "max-age"); seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func cacheDirectiveSeconds(cacheControl string, name string) int64 {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		key, value, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(key) != name {
			continue
		}
		seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err == nil && seconds > 0 {
			return seconds
		}
	}
	return 0
}

func cacheKey(r *http.Request) string {
	return r.Host + "\x00" + r.URL.RequestURI() + "\x00" + r.Header.Get("Accept-Encoding")
}

func shouldGzip(r *http.Request, resp *http.Response) bool {
	if r == nil || resp == nil || r.Method == http.MethodHead {
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
