package keyless

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type RemoteSigner struct {
	baseURL   string
	token     string
	client    *http.Client
	publicKey crypto.PublicKey
	clientID  string
}

func NewRemoteSigner(ctx context.Context, baseURL string, token string, client *http.Client) (*RemoteSigner, error) {
	if client == nil {
		client = http.DefaultClient
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("keyless URL must use http or https")
	}
	signer := &RemoteSigner{
		baseURL: stringsTrimRightSlash(parsed.String()),
		token:   token,
		client:  client,
	}
	pub, err := signer.fetchPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	signer.publicKey = pub
	return signer, nil
}

func (s *RemoteSigner) SetClientID(clientID string) {
	s.clientID = clientID
}

func (s *RemoteSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *RemoteSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	reqBody := RequestFromSignerInput(digest, opts)
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, s.baseURL+"/v1/sign", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set(HeaderToken, s.token)
	}
	if s.clientID != "" {
		req.Header.Set(HeaderClientID, s.clientID)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("keyless sign failed: %s: %s", resp.Status, string(body))
	}

	var signResp SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(signResp.Signature)
}

func (s *RemoteSigner) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/v1/public-key", nil)
	if err != nil {
		return nil, err
	}
	if s.token != "" {
		req.Header.Set(HeaderToken, s.token)
	}
	if s.clientID != "" {
		req.Header.Set(HeaderClientID, s.clientID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("keyless public key failed: %s: %s", resp.Status, string(body))
	}
	var keyResp PublicKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, err
	}
	return DecodePublicKey(keyResp.DER)
}

func stringsTrimRightSlash(value string) string {
	for len(value) > 0 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	return value
}
