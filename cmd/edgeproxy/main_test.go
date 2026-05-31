package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"
)

func TestCacheObeysOriginHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    req,
	}
	if isCacheableResponse(req, resp) {
		t.Fatal("response without cache policy must not be cached")
	}
	resp.Header.Set("Cache-Control", "public, max-age=60")
	if !isCacheableResponse(req, resp) {
		t.Fatal("origin-cacheable response should be cacheable")
	}

	req.Header.Set("Authorization", "Bearer secret")
	if isCacheableResponse(req, resp) {
		t.Fatal("authorized request must not be cached")
	}
	req.Header.Del("Authorization")

	req.Method = http.MethodHead
	if isCacheableResponse(req, resp) {
		t.Fatal("HEAD response must not fill cache")
	}
	req.Method = http.MethodGet

	resp.Header.Set("Set-Cookie", "sid=secret")
	if isCacheableResponse(req, resp) {
		t.Fatal("cookie response must not be cached")
	}
	resp.Header.Del("Set-Cookie")

	resp.Header.Set("Cache-Control", "private, max-age=60")
	if isCacheableResponse(req, resp) {
		t.Fatal("private response must not be cached")
	}
}

func TestResponseCacheHit(t *testing.T) {
	cache := newResponseCache(1024, 512, time.Minute)
	req, err := http.NewRequest(http.MethodGet, "https://example.test/app.css", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("body")),
		Request:    req,
	}
	resp.Header.Set("Cache-Control", "public, max-age=60")
	if err := cache.store(req, resp); err != nil {
		t.Fatal(err)
	}
	entry, ok := cache.get(req)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(entry.body) != "body" {
		t.Fatalf("cached body = %q", string(entry.body))
	}
}

func TestShouldGzipDynamicJSON(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/api/data", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip, br")
	resp := &http.Response{Header: make(http.Header), Request: req}
	resp.Header.Set("Content-Type", "application/json")
	if !shouldGzip(req, resp) {
		t.Fatal("dynamic JSON should be gzip-compressed")
	}

	resp.Header.Set("Content-Encoding", "br")
	if shouldGzip(req, resp) {
		t.Fatal("already encoded response should not be gzip-compressed")
	}
}

func TestPluginRouteMatchesHostAndPath(t *testing.T) {
	route := &pluginRoute{
		hosts:        makeHostSet([]string{"plugin.example.test"}),
		exactPaths:   makePathSet([]string{"/plugin/ws"}),
		pathPrefixes: cleanPathList([]string{"/plugin/api/", "/plugin/grpc/"}),
		proxy:        &httputil.ReverseProxy{},
	}
	req, err := http.NewRequest(http.MethodGet, "https://plugin.example.test/plugin/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !route.matches(req) {
		t.Fatal("expected exact path to match configured host")
	}

	req.URL.Path = "/plugin/grpc/service"
	if !route.matches(req) {
		t.Fatal("expected prefix path to match configured host")
	}

	req.Host = "other.example.test"
	if route.matches(req) {
		t.Fatal("route must not match a different host")
	}
}

func TestPluginRouteMatchesWildcardHost(t *testing.T) {
	route := &pluginRoute{
		hosts:        makeHostSet([]string{"js.gripe", "*.js.gripe"}),
		pathPrefixes: cleanPathList([]string{"/"}),
		proxy:        &httputil.ReverseProxy{},
	}
	for _, rawURL := range []string{
		"https://js.gripe/",
		"https://files.js.gripe/",
		"https://deep.files.js.gripe/",
	} {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !route.matches(req) {
			t.Fatalf("expected %s to match wildcard host route", rawURL)
		}
	}
	req, err := http.NewRequest(http.MethodGet, "https://js.gripe.evil.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if route.matches(req) {
		t.Fatal("wildcard host route must not match suffix-like unrelated domains")
	}
}

func TestPluginRouteHostHeaderOverride(t *testing.T) {
	route, err := newPluginRoute(pluginRouteSpec{
		Name:         "files-origin",
		Hosts:        []string{"files.js.gripe"},
		PathPrefixes: []string{"/"},
		Backend:      "https://files-origin.js.gripe",
		HostHeader:   "files-origin.js.gripe",
		ForwardHost:  "X-Origin-Host",
		Protocol:     "http",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://files.js.gripe/", nil)
	route.proxy.Director(req)

	if req.Host != "files-origin.js.gripe" {
		t.Fatalf("outbound Host = %q, want files-origin.js.gripe", req.Host)
	}
	if req.URL.Host != "files-origin.js.gripe" {
		t.Fatalf("outbound URL host = %q, want files-origin.js.gripe", req.URL.Host)
	}
	if got := req.Header.Get("X-Origin-Host"); got != "files.js.gripe" {
		t.Fatalf("X-Origin-Host = %q, want files.js.gripe", got)
	}
}

func TestCertificateSelectorRequiresKnownSNI(t *testing.T) {
	certs := []tls.Certificate{
		{
			Leaf: &x509.Certificate{
				DNSNames: []string{"js.gripe", "*.js.gripe", "*.sos.js.gripe"},
			},
		},
	}
	selectCert := buildCertificateSelector(certs)
	for _, name := range []string{"js.gripe", "files.js.gripe", "hk.sos.js.gripe"} {
		if _, err := selectCert(&tls.ClientHelloInfo{ServerName: name}); err != nil {
			t.Fatalf("expected %s to be accepted: %v", name, err)
		}
	}
	for _, name := range []string{"", "evil.test", "js.gripe.evil.test"} {
		if _, err := selectCert(&tls.ClientHelloInfo{ServerName: name}); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}
