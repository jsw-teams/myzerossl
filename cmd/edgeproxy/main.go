package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"myzerossl/internal/keyless"
)

func main() {
	listen := flag.String("listen", ":443", "public HTTPS listen address")
	backendRaw := flag.String("backend", "http://127.0.0.1:8080", "upstream backend URL")
	certPath := flag.String("cert", "", "public certificate chain PEM path")
	keylessURL := flag.String("keyless-url", "", "keyless signer base URL")
	token := flag.String("token", "", "shared auth token for keyless API")
	caPath := flag.String("ca", "", "CA file for verifying keyless API server")
	clientCert := flag.String("client-cert", "", "mTLS client certificate for keyless API")
	clientKey := flag.String("client-key", "", "mTLS client key for keyless API")
	flag.Parse()

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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/", proxy)

	server := &http.Server{
		Addr:    *listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
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
