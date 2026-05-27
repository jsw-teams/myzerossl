package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"memecdn/internal/keyless"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "address for keyless signing API")
	keyPath := flag.String("key", "", "private key PEM path kept only on this signer")
	tlsCert := flag.String("tls-cert", "", "server TLS certificate for the keyless API")
	tlsKey := flag.String("tls-key", "", "server TLS private key for the keyless API")
	clientCA := flag.String("client-ca", "", "CA file for mTLS client certificates")
	token := flag.String("token", "", "shared auth token; prefer mTLS for production")
	clients := flag.String("clients", "", "JSON file with per-edge client tokens and abuse thresholds")
	revoked := flag.String("revoked", "", "file containing revoked client ids, one per line")
	audit := flag.String("audit", "", "JSONL audit log path")
	flag.Parse()

	applyEnv("KEYLESS_LISTEN", listen)
	applyEnv("KEYLESS_PRIVATE_KEY", keyPath)
	applyEnv("KEYLESS_TLS_CERT", tlsCert)
	applyEnv("KEYLESS_TLS_KEY", tlsKey)
	applyEnv("KEYLESS_CLIENT_CA", clientCA)
	applyEnv("KEYLESS_TOKEN", token)
	applyEnv("KEYLESS_CLIENTS", clients)
	applyEnv("KEYLESS_REVOKED", revoked)
	applyEnv("KEYLESS_AUDIT", audit)

	if *keyPath == "" {
		log.Fatal("-key is required")
	}
	key, err := keyless.LoadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}

	server := &http.Server{
		Addr:              *listen,
		ReadHeaderTimeout: 5 * time.Second,
	}
	signServer, err := keyless.NewSignServerWithOptions(key, keyless.SignServerOptions{
		Token:       *token,
		ClientsPath: *clients,
		RevokedPath: *revoked,
		AuditPath:   *audit,
	})
	if err != nil {
		log.Fatalf("load signer auth config: %v", err)
	}
	server.Handler = signServer.Routes()

	if *tlsCert == "" || *tlsKey == "" {
		log.Printf("warning: serving keyless API without TLS; use only on a private localhost link")
		log.Fatal(server.ListenAndServe())
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *clientCA != "" {
		caPEM, err := os.ReadFile(*clientCA)
		if err != nil {
			log.Fatalf("read client CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			log.Fatal("client CA has no PEM certificates")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	server.TLSConfig = tlsConfig
	log.Fatal(server.ListenAndServeTLS(*tlsCert, *tlsKey))
}

func applyEnv(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}
