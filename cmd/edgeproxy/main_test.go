package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStaticCacheSkipsPrivateState(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Request:    req,
	}
	if !isCacheableStatic(req, resp) {
		t.Fatal("plain static response should be cacheable")
	}

	req.Header.Set("Authorization", "Bearer secret")
	if isCacheableStatic(req, resp) {
		t.Fatal("authorized request must not be cached")
	}
	req.Header.Del("Authorization")

	req.Method = http.MethodHead
	if isCacheableStatic(req, resp) {
		t.Fatal("HEAD response must not fill cache")
	}
	req.Method = http.MethodGet

	resp.Header.Set("Set-Cookie", "sid=secret")
	if isCacheableStatic(req, resp) {
		t.Fatal("cookie response must not be cached")
	}
	resp.Header.Del("Set-Cookie")

	resp.Header.Set("Cache-Control", "private, max-age=60")
	if isCacheableStatic(req, resp) {
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

	req.URL.Path = "/asset.js"
	if shouldGzip(req, resp) {
		t.Fatal("static asset should not be compressed by dynamic gzip path")
	}
}
