package keyless

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderToken    = "X-Keyless-Token"
	HeaderClientID = "X-Keyless-Client-ID"
	HeaderKeyID    = "X-Keyless-Key-ID"

	SchemeDefault = "default"
	SchemeRSAPSS  = "rsa-pss"
)

type PublicKeyResponse struct {
	DER string `json:"der"`
}

type SignRequest struct {
	Payload    string `json:"payload"`
	Hash       string `json:"hash"`
	Scheme     string `json:"scheme"`
	SaltLength int    `json:"salt_length,omitempty"`
}

type SignResponse struct {
	Signature string `json:"signature"`
}

func HashName(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA224:
		return "SHA224"
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	case crypto.Hash(0):
		return "NONE"
	default:
		return fmt.Sprintf("UNKNOWN-%d", hash)
	}
}

func ParseHash(name string) (crypto.Hash, error) {
	switch strings.ToUpper(name) {
	case "", "NONE":
		return crypto.Hash(0), nil
	case "SHA1":
		return crypto.SHA1, nil
	case "SHA224":
		return crypto.SHA224, nil
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported hash %q", name)
	}
}

func RequestFromSignerInput(payload []byte, opts crypto.SignerOpts) SignRequest {
	req := SignRequest{
		Payload: base64.StdEncoding.EncodeToString(payload),
		Hash:    HashName(opts.HashFunc()),
		Scheme:  SchemeDefault,
	}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		req.Scheme = SchemeRSAPSS
		req.SaltLength = pss.SaltLength
	}
	return req
}

func SignerOptsFromRequest(req SignRequest) (crypto.SignerOpts, error) {
	hash, err := ParseHash(req.Hash)
	if err != nil {
		return nil, err
	}
	switch req.Scheme {
	case "", SchemeDefault:
		return hash, nil
	case SchemeRSAPSS:
		return &rsa.PSSOptions{SaltLength: req.SaltLength, Hash: hash}, nil
	default:
		return nil, fmt.Errorf("unsupported signing scheme %q", req.Scheme)
	}
}

func EncodePublicKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func DecodePublicKey(encoded string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKIXPublicKey(der)
}

func DecodePayload(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("empty payload")
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func ReadJSON(r *http.Request, maxBytes int64, value any) error {
	defer r.Body.Close()
	limited := io.LimitReader(r.Body, maxBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	return dec.Decode(value)
}

func IsEd25519Key(key crypto.PrivateKey) bool {
	_, ok := key.(ed25519.PrivateKey)
	return ok
}

func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}
