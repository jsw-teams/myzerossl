package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"myzerossl/internal/keyless"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "address for keyless signing API")
	keyPath := flag.String("key", "", "private key PEM path kept only on this signer")
	tlsCert := flag.String("tls-cert", "", "server TLS certificate for the keyless API")
	tlsKey := flag.String("tls-key", "", "server TLS private key for the keyless API")
	clientCA := flag.String("client-ca", "", "CA file for mTLS client certificates")
	token := flag.String("token", "", "shared auth token; prefer mTLS for production")
	flag.Parse()

	if *keyPath == "" {
		log.Fatal("-key is required")
	}
	key, err := keyless.LoadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           keyless.NewSignServer(key, *token).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

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
