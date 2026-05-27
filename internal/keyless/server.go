package keyless

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type SignServer struct {
	key        crypto.Signer
	clientKeys map[string]map[string]crypto.Signer
	auth       *authManager
}

func NewSignServer(key crypto.Signer, token string) *SignServer {
	server, err := NewSignServerWithOptions(key, SignServerOptions{Token: token})
	if err != nil {
		panic(err)
	}
	return server
}

func NewSignServerWithOptions(key crypto.Signer, opts SignServerOptions) (*SignServer, error) {
	auth, err := newAuthManager(opts)
	if err != nil {
		return nil, err
	}
	clientKeys, err := loadClientKeys(auth)
	if err != nil {
		return nil, err
	}
	return &SignServer{key: key, clientKeys: clientKeys, auth: auth}, nil
}

func (s *SignServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/public-key", s.requireAuth(s.publicKey))
	mux.HandleFunc("POST /v1/sign", s.requireAuth(s.sign))
	return mux
}

func (s *SignServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID, ok, reason := s.auth.authenticate(r.Header.Get(HeaderToken))
		if !ok {
			s.auth.record(clientID, "auth", false, reason, r.RemoteAddr)
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), clientIDContextKey{}, clientID))
		next(w, r)
	}
}

func (s *SignServer) publicKey(w http.ResponseWriter, r *http.Request) {
	key, ok := s.keyForRequest(r)
	if !ok {
		WriteJSON(w, http.StatusForbidden, map[string]string{"error": "key not allowed"})
		return
	}
	encoded, err := EncodePublicKey(key.Public())
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, PublicKeyResponse{DER: encoded})
}

func (s *SignServer) sign(w http.ResponseWriter, r *http.Request) {
	clientID := clientIDFromContext(r.Context())
	if ok, reason := s.auth.allowed(clientID, "sign"); !ok {
		s.auth.record(clientID, "sign", false, reason, r.RemoteAddr)
		WriteJSON(w, http.StatusTooManyRequests, map[string]string{"error": reason})
		return
	}

	var signReq SignRequest
	if err := ReadJSON(r, 64*1024, &signReq); err != nil {
		s.auth.record(clientID, "sign", false, err.Error(), r.RemoteAddr)
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	payload, err := DecodePayload(signReq.Payload)
	if err != nil {
		s.auth.record(clientID, "sign", false, err.Error(), r.RemoteAddr)
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	opts, err := SignerOptsFromRequest(signReq)
	if err != nil {
		s.auth.record(clientID, "sign", false, err.Error(), r.RemoteAddr)
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validatePayload(payload, opts); err != nil {
		s.auth.record(clientID, "sign", false, err.Error(), r.RemoteAddr)
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	key, ok := s.keyForRequest(r)
	if !ok {
		s.auth.record(clientID, "sign", false, "key not allowed", r.RemoteAddr)
		WriteJSON(w, http.StatusForbidden, map[string]string{"error": "key not allowed"})
		return
	}
	signature, err := key.Sign(rand.Reader, payload, opts)
	if err != nil {
		s.auth.record(clientID, "sign", false, err.Error(), r.RemoteAddr)
		WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.auth.record(clientID, "sign", true, "", r.RemoteAddr)
	WriteJSON(w, http.StatusOK, SignResponse{Signature: base64.StdEncoding.EncodeToString(signature)})
}

func loadClientKeys(auth *authManager) (map[string]map[string]crypto.Signer, error) {
	keys := make(map[string]map[string]crypto.Signer)
	if auth == nil {
		return keys, nil
	}
	for clientID, state := range auth.clients {
		if state == nil {
			continue
		}
		for keyID, path := range state.cfg.PrivateKeys {
			keyID = strings.TrimSpace(keyID)
			path = strings.TrimSpace(path)
			if keyID == "" || path == "" {
				continue
			}
			key, err := LoadPrivateKey(path)
			if err != nil {
				return nil, err
			}
			if keys[clientID] == nil {
				keys[clientID] = make(map[string]crypto.Signer)
			}
			keys[clientID][keyID] = key
		}
		if path := strings.TrimSpace(state.cfg.PrivateKey); path != "" {
			key, err := LoadPrivateKey(path)
			if err != nil {
				return nil, err
			}
			if keys[clientID] == nil {
				keys[clientID] = make(map[string]crypto.Signer)
			}
			keys[clientID][""] = key
		}
	}
	return keys, nil
}

func (s *SignServer) keyForRequest(r *http.Request) (crypto.Signer, bool) {
	clientID := clientIDFromContext(r.Context())
	keyID := strings.TrimSpace(r.Header.Get(HeaderKeyID))
	if keys := s.clientKeys[clientID]; keys != nil {
		if key, ok := keys[keyID]; ok {
			return key, true
		}
		if keyID == "" {
			return s.key, true
		}
		return nil, false
	}
	if keyID != "" {
		return nil, false
	}
	return s.key, true
}

func validatePayload(payload []byte, opts crypto.SignerOpts) error {
	hash := opts.HashFunc()
	if hash == 0 {
		return nil
	}
	if !hash.Available() {
		return errors.New("requested hash is unavailable")
	}
	if len(payload) != hash.Size() {
		return errors.New("payload length does not match requested hash")
	}
	return nil
}

type clientIDContextKey struct{}

func clientIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(clientIDContextKey{}).(string)
	return id
}
