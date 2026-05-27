package keyless

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	var key any
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = parsed
	} else if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = parsed
	} else {
		return nil, errors.New("unsupported private key; use PKCS#8, PKCS#1 RSA, or EC PEM")
	}

	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return typed, nil
	case *ecdsa.PrivateKey:
		return typed, nil
	case ed25519.PrivateKey:
		return typed, nil
	default:
		return nil, errors.New("private key does not implement crypto.Signer")
	}
}
