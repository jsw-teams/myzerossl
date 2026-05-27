package keyless

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
)

type SignServer struct {
	key   crypto.Signer
	token string
}

func NewSignServer(key crypto.Signer, token string) *SignServer {
	return &SignServer{key: key, token: token}
}

func (s *SignServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/public-key", s.requireAuth(s.publicKey))
	mux.HandleFunc("POST /v1/sign", s.requireAuth(s.sign))
	return mux
}

func (s *SignServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && r.Header.Get(HeaderToken) != s.token {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *SignServer) publicKey(w http.ResponseWriter, _ *http.Request) {
	encoded, err := EncodePublicKey(s.key.Public())
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, PublicKeyResponse{DER: encoded})
}

func (s *SignServer) sign(w http.ResponseWriter, r *http.Request) {
	var signReq SignRequest
	if err := ReadJSON(r, 64*1024, &signReq); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	payload, err := DecodePayload(signReq.Payload)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	opts, err := SignerOptsFromRequest(signReq)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validatePayload(payload, opts); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	signature, err := s.key.Sign(rand.Reader, payload, opts)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, SignResponse{Signature: base64.StdEncoding.EncodeToString(signature)})
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
