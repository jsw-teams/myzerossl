package keyless

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSignServerSelectsClientPrivateKey(t *testing.T) {
	defaultKey := mustTestKey(t)
	clientKey := mustTestKey(t)

	dir := t.TempDir()
	clientKeyPath := filepath.Join(dir, "client.key")
	writeTestKey(t, clientKeyPath, clientKey)
	clientsPath := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(clientsPath, []byte(`{
  "clients": [
    {"id": "default-edge", "token": "default-token", "private_keys": {"alt": "`+clientKeyPath+`"}},
    {"id": "alt-edge", "token": "alt-token", "private_key": "`+clientKeyPath+`"}
  ]
}
`), 0600); err != nil {
		t.Fatal(err)
	}

	server, err := NewSignServerWithOptions(defaultKey, SignServerOptions{ClientsPath: clientsPath})
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Routes()

	defaultDER, err := EncodePublicKey(defaultKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	altDER, err := EncodePublicKey(clientKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	gotDefault := fetchTestPublicKey(t, handler, "default-token", "")
	gotAlt := fetchTestPublicKey(t, handler, "alt-token", "")
	gotSameClientAlt := fetchTestPublicKey(t, handler, "default-token", "alt")
	if gotDefault != defaultDER {
		t.Fatalf("default token got wrong public key")
	}
	if gotAlt != altDER {
		t.Fatalf("client token got wrong public key")
	}
	if gotSameClientAlt != altDER {
		t.Fatalf("client key id got wrong public key")
	}
}

func fetchTestPublicKey(t *testing.T, handler http.Handler, token string, keyID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/public-key", nil)
	req.Header.Set(HeaderToken, token)
	if keyID != "" {
		req.Header.Set(HeaderKeyID, keyID)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("public key status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp PublicKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.DER
}

func mustTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeTestKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
