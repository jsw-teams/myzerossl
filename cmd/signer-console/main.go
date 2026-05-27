package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"memecdn/internal/keyless"
)

type app struct {
	accountAPI   string
	accountLogin string
	publicURL    string
	clientID     string
	sessionKey   []byte
	clientsPath  string
	revokedPath  string
	auditPath    string
	registerPath string
	mu           sync.Mutex
}

type accountMe struct {
	User struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
	} `json:"user"`
}

type registrationFile struct {
	Registrations []edgeRegistration `json:"registrations"`
}

type edgeRegistration struct {
	ID                string `json:"id"`
	Label             string `json:"label,omitempty"`
	Status            string `json:"status"`
	RemoteAddr        string `json:"remote_addr,omitempty"`
	RequestedAt       string `json:"requested_at"`
	ApprovedAt        string `json:"approved_at,omitempty"`
	RejectedAt        string `json:"rejected_at,omitempty"`
	InstallToken      string `json:"install_token,omitempty"`
	InstallIssuedAt   string `json:"install_issued_at,omitempty"`
	InstallUsedAt     string `json:"install_used_at,omitempty"`
	InstallVerifiedAt string `json:"install_verified_at,omitempty"`
	InstallStatus     string `json:"install_status,omitempty"`
	InstallError      string `json:"install_error,omitempty"`
}

type registerRequest struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	InstallToken string `json:"install_token,omitempty"`
}

type clientLimitsRequest struct {
	RatePerMinute              int  `json:"rate_per_minute"`
	AutoDisableSignsPerMinute  int  `json:"auto_disable_signs_per_minute"`
	AutoDisableErrorsPerMinute int  `json:"auto_disable_errors_per_minute"`
	AutoRevoke                 bool `json:"auto_revoke"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19444", "console listen address")
	accountAPI := flag.String("account-api", "https://gateway.js.gripe/api/v1/myaccount", "account-system API base")
	accountLogin := flag.String("account-login", "https://account.js.gripe/login", "account-system login URL")
	publicURL := flag.String("public-url", "https://ssl-signer.js.gripe", "public console base URL")
	clientID := flag.String("client-id", "", "account-system third-party client_id")
	sessionSecret := flag.String("session-secret", "", "HMAC secret for console sessions")
	clientsPath := flag.String("clients", "/etc/myzerossl/clients.json", "signer clients JSON path")
	revokedPath := flag.String("revoked", "/etc/myzerossl/revoked-clients.txt", "revoked client ids path")
	auditPath := flag.String("audit", "/var/log/myzerossl/signer-audit.jsonl", "audit JSONL path")
	registerPath := flag.String("registrations", "/etc/myzerossl/edge-registrations.json", "pending edge registration path")
	flag.Parse()

	applyEnv("CONSOLE_LISTEN", listen)
	applyEnv("CONSOLE_ACCOUNT_API", accountAPI)
	applyEnv("CONSOLE_ACCOUNT_LOGIN", accountLogin)
	applyEnv("CONSOLE_PUBLIC_URL", publicURL)
	applyEnv("CONSOLE_CLIENT_ID", clientID)
	applyEnv("CONSOLE_SESSION_SECRET", sessionSecret)
	applyEnv("KEYLESS_CLIENTS", clientsPath)
	applyEnv("KEYLESS_REVOKED", revokedPath)
	applyEnv("KEYLESS_AUDIT", auditPath)
	applyEnv("CONSOLE_REGISTRATIONS", registerPath)

	if *clientID == "" {
		log.Fatal("-client-id is required")
	}
	if *sessionSecret == "" {
		log.Fatal("-session-secret is required")
	}
	a := &app{
		accountAPI:   strings.TrimRight(*accountAPI, "/"),
		accountLogin: *accountLogin,
		publicURL:    strings.TrimRight(*publicURL, "/"),
		clientID:     *clientID,
		sessionKey:   []byte(*sessionSecret),
		clientsPath:  *clientsPath,
		revokedPath:  *revokedPath,
		auditPath:    *auditPath,
		registerPath: *registerPath,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.index)
	mux.HandleFunc("GET /login", a.login)
	mux.HandleFunc("GET /auth/start", a.authStart)
	mux.HandleFunc("GET /auth/account/callback", a.callback)
	mux.HandleFunc("GET /console", a.console)
	mux.HandleFunc("GET /favicon.png", a.icon)
	mux.HandleFunc("GET /og.png", a.icon)
	mux.HandleFunc("GET /llms.txt", a.llms)
	mux.HandleFunc("GET /robots.txt", a.robots)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("POST /api/register", a.registerEdge)
	mux.HandleFunc("POST /api/install/", a.verifyInstall)
	mux.HandleFunc("GET /api/install/", a.installEdge)
	mux.HandleFunc("GET /api/summary", a.requireAdmin(a.summary))
	mux.HandleFunc("POST /api/clients/", a.requireAdmin(a.clientAction))
	mux.HandleFunc("POST /api/registrations/", a.requireAdmin(a.registrationAction))

	server := &http.Server{
		Addr:              *listen,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("signer-console listening on http://%s", *listen)
	log.Fatal(server.ListenAndServe())
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.currentUser(r); ok {
		http.Redirect(w, r, "/console", http.StatusFound)
		return
	}
	renderTemplate(w, landingPage, nil)
}

func (a *app) console(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consolePage.Execute(w, map[string]string{
		"Email": user.User.Email,
		"Name":  user.User.DisplayName,
	})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.currentUser(r); ok {
		http.Redirect(w, r, "/console", http.StatusFound)
		return
	}
	renderTemplate(w, loginPage, nil)
}

func (a *app) authStart(w http.ResponseWriter, r *http.Request) {
	state := randomString(32)
	setCookie(w, "ssl_signer_state", a.signValue(state), 10*time.Minute)

	loginURL, err := url.Parse(a.accountLogin)
	if err != nil {
		http.Error(w, "bad account login URL", http.StatusInternalServerError)
		return
	}
	q := loginURL.Query()
	q.Set("client_id", a.clientID)
	q.Set("redirect_uri", a.publicURL+"/auth/account/callback")
	q.Set("scope", "accounts:read identities:resolve")
	q.Set("state", state)
	q.Set("prompt", "consent")
	loginURL.RawQuery = q.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
}

func (a *app) icon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(bearIcon)
}

func (a *app) llms(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(`# SSL Signer Console

SSL Signer Console is the administrator interface for memecdn keyless TLS signing.

Canonical URL: https://ssl-signer.js.gripe
Repository: https://github.com/jsw-teams/memecdn

Purpose:
- Review pending low-trust edge VPS registration requests.
- Approve a pending edge and generate a one-time install command.
- Revoke or restore edge signing clients.
- Review signer audit logs and automatic abuse revocation state.

Access policy:
- Human access requires account-system login at https://account.js.gripe.
- Only users with role system_admin may access the console.
- Edge VPS nodes must not receive the certificate private key.

Automation:
- New edge nodes submit POST /api/register with a proposed id and label.
- Registration stays pending until approved by a system administrator.
- Approval returns a one-time install command instead of displaying the real signer token.
- Signing API traffic uses https://gateway.js.gripe/api/v1/ssl-signer.
`))
}

func (a *app) robots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\nAllow: /llms.txt\n"))
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("ssl_signer_state")
	if err != nil || !a.verifySignedValue(stateCookie.Value, r.URL.Query().Get("state")) {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	accountSession := r.URL.Query().Get("account_session")
	if accountSession == "" {
		http.Error(w, "missing account session", http.StatusBadRequest)
		return
	}
	user, err := a.fetchMe(accountSession)
	if err != nil {
		http.Error(w, "account verification failed", http.StatusUnauthorized)
		return
	}
	if user.User.Role != "system_admin" {
		http.Error(w, "system_admin required", http.StatusForbidden)
		return
	}

	sessionPayload, _ := json.Marshal(map[string]string{
		"account_session": accountSession,
		"email":           user.User.Email,
		"role":            user.User.Role,
	})
	setCookie(w, "ssl_signer_session", a.signValue(base64.RawURLEncoding.EncodeToString(sessionPayload)), 8*time.Hour)
	clearCookie(w, "ssl_signer_state")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, "ssl_signer_session")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (a *app) summary(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	clients, err := readClientFile(a.clientsPath)
	if err != nil {
		writeError(w, err)
		return
	}
	revoked, err := readRevoked(a.revokedPath)
	if err != nil {
		writeError(w, err)
		return
	}
	audit, err := tailLines(a.auditPath, 200)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, err)
		return
	}
	registrations, err := readRegistrations(a.registerPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clients":       clients.Clients,
		"revoked":       revoked,
		"audit":         audit,
		"registrations": registrations.Registrations,
	})
}

func (a *app) registerEdge(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Label = strings.TrimSpace(req.Label)
	req.InstallToken = strings.TrimSpace(req.InstallToken)
	if !validClientID(req.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if req.InstallToken == "" {
		req.InstallToken = randomString(48)
	}
	if !validInstallToken(req.InstallToken) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid install token"})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	clients, err := readClientFile(a.clientsPath)
	if err != nil {
		writeError(w, err)
		return
	}
	for _, client := range clients.Clients {
		if client.ID == req.ID {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "client already exists"})
			return
		}
	}
	file, err := readRegistrations(a.registerPath)
	if err != nil {
		writeError(w, err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range file.Registrations {
		if file.Registrations[i].ID == req.ID && file.Registrations[i].Status == "pending" {
			file.Registrations[i].Label = req.Label
			file.Registrations[i].RemoteAddr = clientAddress(r)
			file.Registrations[i].RequestedAt = now
			file.Registrations[i].InstallToken = req.InstallToken
			file.Registrations[i].InstallIssuedAt = now
			if err := writeRegistrations(a.registerPath, file); err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "pending"})
			return
		}
	}
	file.Registrations = append(file.Registrations, edgeRegistration{
		ID:              req.ID,
		Label:           req.Label,
		Status:          "pending",
		RemoteAddr:      clientAddress(r),
		RequestedAt:     now,
		InstallToken:    req.InstallToken,
		InstallIssuedAt: now,
	})
	if err := writeRegistrations(a.registerPath, file); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "pending"})
}

func (a *app) clientAction(w http.ResponseWriter, r *http.Request) {
	id, action, ok := parseClientAction(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	clients, err := readClientFile(a.clientsPath)
	if err != nil {
		writeError(w, err)
		return
	}
	found := false
	for i := range clients.Clients {
		if clients.Clients[i].ID == id {
			found = true
			switch action {
			case "disable":
				clients.Clients[i].Disabled = true
			case "enable":
				clients.Clients[i].Disabled = false
			case "limits":
				var req clientLimitsRequest
				if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
					return
				}
				if req.RatePerMinute < 0 || req.RatePerMinute > 1000000 ||
					req.AutoDisableSignsPerMinute < 0 || req.AutoDisableSignsPerMinute > 1000000 ||
					req.AutoDisableErrorsPerMinute < 0 || req.AutoDisableErrorsPerMinute > 1000000 {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limits must be between 0 and 1000000"})
					return
				}
				clients.Clients[i].RatePerMinute = req.RatePerMinute
				clients.Clients[i].AutoDisableSignsPerMinute = req.AutoDisableSignsPerMinute
				clients.Clients[i].AutoDisableErrorsPerMinute = req.AutoDisableErrorsPerMinute
				clients.Clients[i].AutoRevoke = req.AutoRevoke
			}
		}
	}
	if !found && (action == "disable" || action == "enable" || action == "limits") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	switch action {
	case "disable", "enable", "limits":
		if err := writeClientFile(a.clientsPath, clients); err != nil {
			writeError(w, err)
			return
		}
	case "revoke":
		if err := appendRevoked(a.revokedPath, id); err != nil {
			writeError(w, err)
			return
		}
	case "unrevoke":
		if err := removeRevoked(a.revokedPath, id); err != nil {
			writeError(w, err)
			return
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) registrationAction(w http.ResponseWriter, r *http.Request) {
	id, action, ok := parseRegistrationAction(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	registrations, err := readRegistrations(a.registerPath)
	if err != nil {
		writeError(w, err)
		return
	}
	clients, err := readClientFile(a.clientsPath)
	if err != nil {
		writeError(w, err)
		return
	}

	index := -1
	for i := range registrations.Registrations {
		if registrations.Registrations[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "registration not found"})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	switch action {
	case "approve":
		for _, client := range clients.Clients {
			if client.ID == id {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "client already exists"})
				return
			}
		}
		token := randomString(48)
		clients.Clients = append(clients.Clients, keyless.ClientConfig{
			ID:                         id,
			Token:                      token,
			RatePerMinute:              20000,
			AutoDisableSignsPerMinute:  0,
			AutoDisableErrorsPerMinute: 0,
			AutoRevoke:                 false,
		})
		registrations.Registrations[index].Status = "approved"
		registrations.Registrations[index].ApprovedAt = now
		if registrations.Registrations[index].InstallToken == "" {
			registrations.Registrations[index].InstallToken = randomString(48)
			registrations.Registrations[index].InstallIssuedAt = now
		}
		registrations.Registrations[index].InstallUsedAt = ""
		registrations.Registrations[index].InstallStatus = "approved"
		registrations.Registrations[index].InstallError = ""
		if err := writeClientFile(a.clientsPath, clients); err != nil {
			writeError(w, err)
			return
		}
		if err := writeRegistrations(a.registerPath, registrations); err != nil {
			writeError(w, err)
			return
		}
		installURL := a.publicURL + "/api/install/" + registrations.Registrations[index].InstallToken
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"install_url": installURL,
			"message":     "approved; edge will fetch signer token over HTTPS",
		})
	case "reject":
		registrations.Registrations[index].Status = "rejected"
		registrations.Registrations[index].RejectedAt = now
		if err := writeRegistrations(a.registerPath, registrations); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (a *app) installEdge(w http.ResponseWriter, r *http.Request) {
	installToken := strings.TrimPrefix(r.URL.Path, "/api/install/")
	if installToken == "" || strings.Contains(installToken, "/") {
		http.NotFound(w, r)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	registrations, err := readRegistrations(a.registerPath)
	if err != nil {
		http.Error(w, "registration file unavailable", http.StatusInternalServerError)
		return
	}
	clients, err := readClientFile(a.clientsPath)
	if err != nil {
		http.Error(w, "client file unavailable", http.StatusInternalServerError)
		return
	}

	regIndex := -1
	for i := range registrations.Registrations {
		reg := registrations.Registrations[i]
		if reg.InstallToken == installToken && reg.Status == "approved" {
			regIndex = i
			break
		}
	}
	if regIndex < 0 {
		http.NotFound(w, r)
		return
	}
	reg := registrations.Registrations[regIndex]
	if reg.InstallUsedAt != "" {
		http.Error(w, "install token already used", http.StatusGone)
		return
	}

	keylessToken := ""
	for _, client := range clients.Clients {
		if client.ID == reg.ID {
			keylessToken = client.Token
			break
		}
	}
	if keylessToken == "" {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	if wantsJSON(r) {
		registrations.Registrations[regIndex].InstallStatus = "delivered"
		if err := writeRegistrations(a.registerPath, registrations); err != nil {
			http.Error(w, "registration file unavailable", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"client_id":     reg.ID,
			"keyless_token": keylessToken,
		})
		return
	}

	registrations.Registrations[regIndex].InstallUsedAt = time.Now().UTC().Format(time.RFC3339)
	registrations.Registrations[regIndex].InstallStatus = "delivered"
	if err := writeRegistrations(a.registerPath, registrations); err != nil {
		http.Error(w, "registration file unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = fmt.Fprintf(w, `#!/bin/sh
set -eu

ENV_FILE="${EDGE_ENV_FILE:-/etc/myzerossl/edgeproxy.env}"
ENV_DIR="$(dirname "$ENV_FILE")"
install -d -m 0750 "$ENV_DIR"

tmp="$(mktemp)"
if [ -f "$ENV_FILE" ]; then
  awk -F= '$1 != "KEYLESS_TOKEN" { print }' "$ENV_FILE" > "$tmp"
  chmod --reference="$ENV_FILE" "$tmp" 2>/dev/null || chmod 0640 "$tmp"
  chown --reference="$ENV_FILE" "$tmp" 2>/dev/null || true
else
  chmod 0640 "$tmp"
fi
printf 'KEYLESS_TOKEN=%%s\n' %s >> "$tmp"
mv "$tmp" "$ENV_FILE"

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart edgeproxy
fi
echo "memecdn edge token installed for %s"
`, shellQuote(keylessToken), reg.ID)
}

func (a *app) verifyInstall(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/verified") {
		http.NotFound(w, r)
		return
	}
	installToken := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/install/"), "/verified")
	if installToken == "" || strings.Contains(installToken, "/") {
		http.NotFound(w, r)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	registrations, err := readRegistrations(a.registerPath)
	if err != nil {
		writeError(w, err)
		return
	}
	for i := range registrations.Registrations {
		reg := registrations.Registrations[i]
		if reg.InstallToken == installToken && reg.Status == "approved" {
			now := time.Now().UTC().Format(time.RFC3339)
			registrations.Registrations[i].InstallUsedAt = now
			registrations.Registrations[i].InstallVerifiedAt = now
			registrations.Registrations[i].InstallStatus = "verified"
			registrations.Registrations[i].InstallError = ""
			if err := writeRegistrations(a.registerPath, registrations); err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	http.NotFound(w, r)
}

func (a *app) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.currentUser(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *app) currentUser(r *http.Request) (accountMe, bool) {
	var empty accountMe
	cookie, err := r.Cookie("ssl_signer_session")
	if err != nil {
		return empty, false
	}
	value, ok := a.verifiedPayload(cookie.Value)
	if !ok {
		return empty, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return empty, false
	}
	var session map[string]string
	if err := json.Unmarshal(payload, &session); err != nil {
		return empty, false
	}
	user, err := a.fetchMe(session["account_session"])
	if err != nil || user.User.Role != "system_admin" {
		return empty, false
	}
	return user, true
}

func (a *app) fetchMe(accountSession string) (accountMe, error) {
	var out accountMe
	req, err := http.NewRequest(http.MethodGet, a.accountAPI+"/me", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+accountSession)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("account-system /me returned %s", resp.Status)
	}
	return out, json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out)
}

func (a *app) signValue(value string) string {
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(value))
	return value + "." + hex.EncodeToString(mac.Sum(nil))
}

func (a *app) verifySignedValue(signed string, expected string) bool {
	value, ok := a.verifiedPayload(signed)
	return ok && value == expected
}

func (a *app) verifiedPayload(signed string) (string, bool) {
	value, sig, ok := strings.Cut(signed, ".")
	if !ok {
		return "", false
	}
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(value))
	expected := mac.Sum(nil)
	got, err := hex.DecodeString(sig)
	if err != nil {
		return "", false
	}
	return value, hmac.Equal(got, expected)
}

func readClientFile(path string) (keyless.ClientFile, error) {
	var clients keyless.ClientFile
	data, err := os.ReadFile(path)
	if err != nil {
		return clients, err
	}
	return clients, json.Unmarshal(data, &clients)
}

func writeClientFile(path string, clients keyless.ClientFile) error {
	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

func readRevoked(path string) ([]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var out []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, scanner.Err()
}

func readRegistrations(path string) (registrationFile, error) {
	var file registrationFile
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return file, nil
	}
	if err != nil {
		return file, err
	}
	return file, json.Unmarshal(data, &file)
}

func writeRegistrations(path string, file registrationFile) error {
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

func appendRevoked(path string, id string) error {
	current, err := readRevoked(path)
	if err != nil {
		return err
	}
	for _, item := range current {
		if item == id {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(id + "\n")
	return err
}

func removeRevoked(path string, id string) error {
	current, err := readRevoked(path)
	if err != nil {
		return err
	}
	var next []string
	for _, item := range current {
		if item != id {
			next = append(next, item)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(next, "\n")+"\n"), 0640)
}

func tailLines(path string, limit int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > limit {
			lines = lines[1:]
		}
	}
	return lines, scanner.Err()
}

func parseClientAction(path string) (string, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "clients" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func parseRegistrationAction(path string) (string, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "registrations" {
		return "", "", false
	}
	return parts[2], parts[3], true
}

func wantsJSON(r *http.Request) bool {
	return r.URL.Query().Get("format") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func validClientID(id string) bool {
	if len(id) < 3 || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func validInstallToken(token string) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, ch := range token {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

func clientAddress(r *http.Request) string {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			return value
		}
	}
	return r.RemoteAddr
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func randomString(n int) string {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func setCookie(w http.ResponseWriter, name string, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func applyEnv(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

//go:embed black-bear-wrench.png
var bearIcon []byte

const head = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="SSL Signer Console manages keyless TLS signer access for low-trust edge VPS nodes without placing certificate private keys on those nodes.">
<meta property="og:title" content="SSL Signer Console">
<meta property="og:description" content="Approve edge registrations, revoke signer clients, and review keyless SSL audit logs.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://ssl-signer.js.gripe">
<meta property="og:image" content="https://ssl-signer.js.gripe/og.png">
<link rel="icon" type="image/png" href="/favicon.png">
<style>
:root{--ink:#12151a;--muted:#5c6572;--line:#1f2937;--paper:#fffdf7;--soft:#f7f4ea;--soft-2:#ede8da;--mint:#b8f3d4;--blue:#b8d8ff;--red:#ffe0e0;--red-ink:#8a1111}
*{box-sizing:border-box}html{overflow-x:hidden;background:var(--soft)}body{margin:0;min-width:320px;min-height:100vh;background:var(--soft);color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;image-rendering:pixelated;overflow-x:hidden}
body{display:flex;flex-direction:column}.page{min-height:100vh;display:flex;flex-direction:column}.fill{flex:1}a{color:inherit}.wrap{width:min(1120px,100%);margin:0 auto;padding:20px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 0}
.brand{display:flex;align-items:center;gap:12px;min-width:0;text-decoration:none}.brand>div,.brand span{min-width:0}.logo{flex:0 0 auto;width:54px;height:54px;border:3px solid var(--line);border-radius:8px;background:#fff;box-shadow:4px 4px 0 var(--line);object-fit:cover}
.title{font-size:24px;font-weight:900;line-height:1.08;overflow-wrap:anywhere}.muted{color:var(--muted);overflow-wrap:anywhere}.pixel{border:3px solid var(--line);box-shadow:5px 5px 0 var(--line);background:var(--paper);border-radius:6px}
.hero{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(170px,.9fr);gap:22px;align-items:center;padding:26px;margin-top:14px}.hero h1{font-size:34px;line-height:1.08;margin:0 0 12px;overflow-wrap:anywhere}
.hero p{font-size:16px;line-height:1.7}.mascot{width:220px;max-width:100%;display:block;margin:auto;border:3px solid var(--line);border-radius:10px;background:#fff;box-shadow:5px 5px 0 var(--line)}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin-top:18px}.card{padding:16px}.card h2,.card h3{margin:0 0 10px;font-size:18px}.card p{line-height:1.6}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:42px;padding:10px 14px;border:3px solid var(--line);background:var(--mint);box-shadow:3px 3px 0 var(--line);border-radius:6px;font-weight:900;text-decoration:none;cursor:pointer;white-space:normal;text-align:center;color:var(--ink)}
.btn.secondary{background:var(--blue)}.btn.danger{background:var(--red);color:var(--red-ink)}.btn:disabled{opacity:.55;cursor:wait;transform:translate(2px,2px);box-shadow:1px 1px 0 var(--line)}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
header.app{background:var(--paper);border-bottom:3px solid var(--line)}main.console{display:grid;gap:18px}.panel{padding:16px;overflow:hidden}.panel h2{margin:0 0 12px;font-size:18px}.table-scroll{overflow-x:auto;padding-bottom:4px}
table{width:100%;min-width:760px;border-collapse:collapse;font-size:14px}th,td{text-align:left;border-bottom:2px solid #e5dfcf;padding:10px;vertical-align:middle;overflow-wrap:anywhere}td.actions{min-width:300px}code,pre{background:var(--soft-2);border:2px solid #d8cfba;border-radius:4px}code{padding:1px 4px;white-space:normal;overflow-wrap:anywhere}pre{padding:12px;white-space:pre-wrap;max-height:360px;overflow:auto}
input[type=number]{width:110px;min-height:34px;padding:6px 8px;border:2px solid var(--line);border-radius:5px;background:#fff;color:var(--ink);font:inherit}.limit-form{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.limit-form label{display:inline-flex;align-items:center;gap:6px;color:var(--muted);font-size:13px}.limit-form .check{color:var(--ink)}.limit-form .btn{min-height:34px;padding:6px 10px}
.empty{padding:14px;background:var(--soft-2);border:2px dashed #b9ae99;border-radius:6px;overflow-wrap:anywhere}.pill{display:inline-block;padding:4px 8px;border:2px solid var(--line);background:#fff;border-radius:999px}.actions{display:flex;gap:8px;flex-wrap:wrap}.actions .btn{min-height:38px;padding:8px 10px}
.site-footer{margin-top:auto;border-top:3px solid var(--line);background:var(--soft)}.site-footer .wrap{padding-top:14px;padding-bottom:14px;color:var(--muted);font-size:13px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.toast{position:fixed;right:18px;bottom:18px;z-index:20;max-width:min(420px,calc(100vw - 36px));padding:12px 14px;opacity:0;transform:translateY(8px);pointer-events:none;transition:opacity .15s,transform .15s}.toast.show{opacity:1;transform:translateY(0)}
dialog{border:0;background:transparent;padding:0;max-width:min(680px,calc(100vw - 28px))}dialog::backdrop{background:rgba(18,21,26,.58)}.token-box{padding:18px}.token-box h2{font-size:20px;margin:0 0 8px}.token-box p{line-height:1.6}.token-value{display:block;width:100%;max-height:180px;overflow:auto;word-break:break-all}
@media(max-width:900px){.grid{grid-template-columns:1fr 1fr}.hero{grid-template-columns:1fr}.mascot{width:180px}.hero h1{font-size:30px}}
@media(max-width:620px){.wrap{padding:14px}.grid{grid-template-columns:1fr}.hero{padding:18px}.hero h1{font-size:26px}.top{align-items:stretch;flex-direction:column}.toolbar{align-items:stretch;flex-direction:column}.btn{width:100%}.logo{width:48px;height:48px}.title{font-size:20px}.panel{padding:12px}.pixel{box-shadow:3px 3px 0 var(--line)}.site-footer .wrap{display:block}.actions .btn{width:auto;flex:1 1 180px}td.actions{min-width:240px}table{min-width:680px}}
</style>`

const i18nScript = `<script>
const dict={
  "zh-CN":{
    lang:"zh-CN",login:"管理员登录",subtitle:"Keyless 边缘控制",heroTitle:"让低信任边缘 VPS 不再持有证书私钥。",heroCopy:"SSL Signer Console 用 account-system 验证系统管理员，审批 edge 注册、吊销 signer client，并查看 keyless TLS 签名审计日志。",enterLogin:"进入登录页",noKey:"无私钥驻留",noKeyCopy:"边缘节点只保存证书链，TLS 握手签名由可信 signer 完成。",approval:"人工审批",approvalCopy:"新 edge 设备只能提交 pending 申请，管理员批准后才生成 token。",auto:"自动处置",autoCopy:"异常签名频率和错误阈值会触发自动吊销，降低滥用窗口。",loginTitle:"系统管理员登录",loginCopy:"登录将跳转到 account.js.gripe。只有 account-system 的 system_admin 可以访问控制台。",loginButton:"使用 account-system 登录",logout:"退出",pending:"待审批 Edge 注册",clients:"Edge 客户端",revoked:"已吊销客户端",audit:"Signer 审计",id:"ID",label:"标签",remote:"来源",requested:"申请时间",status:"状态",rate:"频率",autoDisable:"自动停用",approve:"批准并生成 token",reject:"拒绝",disable:"撤销注册权限",enable:"允许注册/启用",revoke:"吊销",unrevoke:"允许再次注册",noPending:"暂无待审批 edge 注册申请",noClients:"暂无已批准 edge client",none:"无",noAudit:"暂无审计记录",tokenTitle:"Edge 安装命令已生成",tokenCopy:"复制后在对应 edge VPS 上以 root 执行。真实 signer token 会由一次性链接写入设备，不在控制台明文展示。",copyToken:"复制安装命令",copied:"已复制",close:"我已保存，关闭",updated:"已更新",loadFailed:"加载失败",footer:"Keyless SSL signer control for js.gripe"},
  "zh-TW":{
    lang:"zh-TW",login:"管理員登入",subtitle:"Keyless 邊緣控制",heroTitle:"讓低信任邊緣 VPS 不再持有憑證私鑰。",heroCopy:"SSL Signer Console 使用 account-system 驗證系統管理員，審核 edge 註冊、撤銷 signer client，並查看 keyless TLS 簽章稽核記錄。",enterLogin:"進入登入頁",noKey:"無私鑰駐留",noKeyCopy:"邊緣節點只保存憑證鏈，TLS 握手簽章由可信 signer 完成。",approval:"人工審核",approvalCopy:"新 edge 裝置只能提交 pending 申請，管理員核准後才會產生 token。",auto:"自動處置",autoCopy:"異常簽章頻率與錯誤閾值會觸發自動吊銷，降低濫用窗口。",loginTitle:"系統管理員登入",loginCopy:"登入將跳轉到 account.js.gripe。只有 account-system 的 system_admin 可以存取控制台。",loginButton:"使用 account-system 登入",logout:"登出",pending:"待審核 Edge 註冊",clients:"Edge 用戶端",revoked:"已吊銷用戶端",audit:"Signer 稽核",id:"ID",label:"標籤",remote:"來源",requested:"申請時間",status:"狀態",rate:"頻率",autoDisable:"自動停用",approve:"核准並產生 token",reject:"拒絕",disable:"撤銷註冊權限",enable:"允許註冊/啟用",revoke:"吊銷",unrevoke:"允許再次註冊",noPending:"暫無待審核 edge 註冊申請",noClients:"暫無已核准 edge client",none:"無",noAudit:"暫無稽核記錄",tokenTitle:"Edge 安裝命令已產生",tokenCopy:"複製後在對應 edge VPS 上以 root 執行。真實 signer token 會由一次性連結寫入設備，不在控制台明文顯示。",copyToken:"複製安裝命令",copied:"已複製",close:"我已保存，關閉",updated:"已更新",loadFailed:"載入失敗",footer:"Keyless SSL signer control for js.gripe"},
  "en":{
    lang:"en",login:"Admin Login",subtitle:"Keyless edge control",heroTitle:"Keep certificate private keys off low-trust edge VPS nodes.",heroCopy:"SSL Signer Console uses account-system to verify system administrators, approve edge registrations, revoke signer clients, and review keyless TLS signing audit logs.",enterLogin:"Open Login",noKey:"No key residency",noKeyCopy:"Edge nodes keep only certificate chains; trusted signers produce TLS handshake signatures.",approval:"Manual approval",approvalCopy:"New edge devices can only submit pending requests. Tokens are generated after admin approval.",auto:"Automatic response",autoCopy:"Abnormal signing volume and error thresholds trigger automatic revocation to limit abuse.",loginTitle:"System Admin Login",loginCopy:"Login redirects to account.js.gripe. Only account-system system_admin users can access the console.",loginButton:"Login with account-system",logout:"Sign Out",pending:"Pending Edge Registrations",clients:"Edge Clients",revoked:"Revoked Clients",audit:"Signer Audit",id:"ID",label:"Label",remote:"Remote",requested:"Requested",status:"Status",rate:"Rate",autoDisable:"Auto disable",approve:"Approve and generate token",reject:"Reject",disable:"Disable registration",enable:"Allow registration",revoke:"Revoke",unrevoke:"Allow again",noPending:"No pending edge registrations",noClients:"No approved edge clients",none:"none",noAudit:"No audit entries",tokenTitle:"Edge install command generated",tokenCopy:"Run this command as root on the matching edge VPS. The real signer token is installed through a one-time link and is not shown in the console.",copyToken:"Copy install command",copied:"Copied",close:"Saved, close",updated:"Updated",loadFailed:"Load failed",footer:"Keyless SSL signer control for js.gripe"}
};
const locale = (navigator.language || "en").toLowerCase();
const t = locale.startsWith("zh-tw") || locale.startsWith("zh-hk") || locale.startsWith("zh-mo") ? dict["zh-TW"] : (locale.startsWith("zh") ? dict["zh-CN"] : dict.en);
document.documentElement.lang=t.lang;
function applyText(){document.querySelectorAll("[data-i18n]").forEach(el=>{el.textContent=t[el.dataset.i18n]||el.dataset.i18n});document.querySelectorAll("[data-i18n-title]").forEach(el=>{el.title=t[el.dataset.i18nTitle]||el.dataset.i18nTitle})}
document.addEventListener("DOMContentLoaded",applyText);
</script>`

var landingPage = template.Must(template.New("landing").Parse(`<!doctype html>
	<html lang="zh-CN">
	<head>
	  <title>SSL Signer Console - Keyless SSL Edge Control</title>` + head + `
	</head>
	<body>
	  <div class="page"><main class="wrap fill">
	    <nav class="top"><div class="brand"><img class="logo" src="/favicon.png" alt=""><div><div class="title">SSL Signer</div><div class="muted" data-i18n="subtitle">Keyless edge control</div></div></div><a class="btn" href="/login" data-i18n="login">管理员登录</a></nav>
	    <section class="hero pixel">
	      <div><h1 data-i18n="heroTitle">让低信任边缘 VPS 不再持有证书私钥。</h1><p data-i18n="heroCopy">SSL Signer Console 用 account-system 验证系统管理员，审批 edge 注册、吊销 signer client，并查看 keyless TLS 签名审计日志。</p><div class="toolbar"><a class="btn" href="/login" data-i18n="enterLogin">进入登录页</a><a class="btn secondary" href="/llms.txt">llms.txt</a></div></div>
	      <img class="mascot" src="/favicon.png" alt="黑熊拿着扳手的像素风图标">
	    </section>
	    <section class="grid">
	      <article class="card pixel"><h2 data-i18n="noKey">无私钥驻留</h2><p data-i18n="noKeyCopy">边缘节点只保存证书链，TLS 握手签名由可信 signer 完成。</p></article>
	      <article class="card pixel"><h2 data-i18n="approval">人工审批</h2><p data-i18n="approvalCopy">新 edge 设备只能提交 pending 申请，管理员批准后才生成 token。</p></article>
	      <article class="card pixel"><h2 data-i18n="auto">自动处置</h2><p data-i18n="autoCopy">异常签名频率和错误阈值会触发自动吊销，降低滥用窗口。</p></article>
	    </section>
	  </main><footer class="site-footer"><div class="wrap"><span data-i18n="footer">Keyless SSL signer control for js.gripe</span><a href="/llms.txt">llms.txt</a></div></footer></div>` + i18nScript + `
	</body></html>`))

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="zh-CN"><head><title>登录 - SSL Signer Console</title>` + head + `</head>
	<body><div class="page"><main class="wrap fill"><nav class="top"><a class="brand" href="/"><img class="logo" src="/favicon.png" alt=""><span class="title">SSL Signer</span></a></nav>
	<section class="hero pixel"><div><h1 data-i18n="loginTitle">系统管理员登录</h1><p data-i18n="loginCopy">登录将跳转到 account.js.gripe。只有 account-system 的 system_admin 可以访问控制台。</p><a class="btn" href="/auth/start" data-i18n="loginButton">使用 account-system 登录</a></div><img class="mascot" src="/favicon.png" alt=""></section>
	</main><footer class="site-footer"><div class="wrap"><span data-i18n="footer">Keyless SSL signer control for js.gripe</span><a href="/llms.txt">llms.txt</a></div></footer></div>` + i18nScript + `</body></html>`))

var consolePage = template.Must(template.New("console").Parse(`<!doctype html>
<html lang="zh-CN"><head><title>控制台 - SSL Signer Console</title>` + head + `</head>
<body><div class="page">
  <header class="app"><div class="wrap top"><div class="brand"><img class="logo" src="/favicon.png" alt=""><div><div class="title">SSL Signer Console</div><div class="muted">{{.Email}}</div></div></div><form method="post" action="/logout"><button class="btn secondary" data-i18n="logout">退出</button></form></div></header>
  <main class="wrap console fill">
    <section class="panel pixel"><h2 data-i18n="pending">Pending Edge Registrations</h2><div id="registrations"></div></section>
    <section class="panel pixel"><h2 data-i18n="clients">Edge Clients</h2><div id="clients"></div></section>
    <section class="panel pixel"><h2 data-i18n="revoked">Revoked Clients</h2><pre id="revoked"></pre></section>
    <section class="panel pixel"><h2 data-i18n="audit">Signer Audit</h2><pre id="audit"></pre></section>
  </main>
  <footer class="site-footer"><div class="wrap"><span data-i18n="footer">Keyless SSL signer control for js.gripe</span><a href="/llms.txt">llms.txt</a></div></footer>
  <dialog id="token-dialog">
    <form method="dialog" class="pixel token-box">
      <h2 data-i18n="tokenTitle">Edge 安装命令已生成</h2>
      <p data-i18n="tokenCopy">复制后在对应 edge VPS 上以 root 执行。真实 signer token 会由一次性链接写入设备，不在控制台明文展示。</p>
      <pre id="issued-token" class="token-value"></pre>
      <div class="toolbar"><button type="button" class="btn" id="copy-token" data-i18n="copyToken">复制安装命令</button><button class="btn secondary" data-i18n="close">我已保存，关闭</button></div>
    </form>
  </dialog>
  <div id="toast" class="toast pixel" role="status" aria-live="polite"></div>
</div>
` + i18nScript + `<script>
let issuedCommand = "";
let toastTimer = 0;
async function api(path, options = {}) {
  const init = { method: options.method || "GET", cache: "no-store" };
  if (options.body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch(path, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}
function toast(message) {
  const el = document.querySelector("#toast");
  clearTimeout(toastTimer);
  el.textContent = message;
  el.classList.add("show");
  toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}
async function withButton(button, fn) {
  const old = button ? button.disabled : false;
  if (button) button.disabled = true;
  try { await fn(); toast(t.updated); }
  catch (err) { toast(err.message || t.loadFailed); }
  finally { if (button) button.disabled = old; }
}
async function action(id, name) {
  await api("/api/clients/" + encodeURIComponent(id) + "/" + name, { method: "POST" });
  await load();
}
async function updateLimits(id) {
  const form = document.querySelector("[data-client-limits='" + cssEscape(id) + "']");
  const payload = {
    rate_per_minute: intValue(form.querySelector("[name='rate_per_minute']").value),
    auto_disable_signs_per_minute: intValue(form.querySelector("[name='auto_disable_signs_per_minute']").value),
    auto_disable_errors_per_minute: intValue(form.querySelector("[name='auto_disable_errors_per_minute']").value),
    auto_revoke: form.querySelector("[name='auto_revoke']").checked
  };
  await api("/api/clients/" + encodeURIComponent(id) + "/limits", { method: "POST", body: payload });
  await load();
}
async function registrationAction(id, name) {
  const data = await api("/api/registrations/" + encodeURIComponent(id) + "/" + name, { method: "POST" });
  if (data.install_command) showInstallCommand(data.install_command);
  await load();
}
function intValue(value) {
  const n = Number.parseInt(value || "0", 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function cssEscape(value) {
  if (window.CSS && CSS.escape) return CSS.escape(value);
  return String(value).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}
function showInstallCommand(command) {
  issuedCommand = command;
  document.querySelector("#issued-token").textContent = command;
  document.querySelector("#token-dialog").showModal();
}
function esc(s){return String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}
async function load() {
  const data = await api("/api/summary");
  const revoked = new Set(data.revoked || []);
  const pendingRows = (data.registrations || []).filter(r => r.status === "pending").map(r => {
    const id = esc(r.id);
    return "<tr><td><code>" + id + "</code></td><td>" + esc(r.label || "") + "</td><td>" +
      esc(r.remote_addr || "") + "</td><td>" + esc(r.requested_at || "") + "</td><td class=\"actions\">" +
      "<button class=\"btn\" onclick=\"withButton(this,()=>registrationAction('" + id + "','approve'))\">" + t.approve + "</button>" +
      "<button class=\"btn danger\" onclick=\"withButton(this,()=>registrationAction('" + id + "','reject'))\">" + t.reject + "</button>" +
      "</td></tr>";
  }).join("");
  document.querySelector("#registrations").innerHTML = pendingRows ? "<div class=\"table-scroll\"><table><thead><tr><th>" + t.id + "</th><th>" + t.label + "</th><th>" + t.remote + "</th><th>" + t.requested + "</th><th></th></tr></thead><tbody>" + pendingRows + "</tbody></table></div>" : "<div class=\"empty\">" + t.noPending + "</div>";
  const rows = (data.clients || []).map(c => {
    const id = esc(c.id);
    const next = c.disabled ? "enable" : "disable";
    const label = c.disabled ? "允许注册/启用" : "撤销注册权限";
    const status = (c.disabled ? "disabled" : "active") + (revoked.has(c.id) ? " / revoked" : "");
    const limits = "<form class=\"limit-form\" data-client-limits=\"" + id + "\" onsubmit=\"event.preventDefault();withButton(this.querySelector('button'),()=>updateLimits('" + id + "'))\">" +
      "<label>软限流/min <input name=\"rate_per_minute\" type=\"number\" min=\"0\" max=\"1000000\" step=\"1\" value=\"" + Number(c.rate_per_minute || 0) + "\"></label>" +
      "<label>签名阈值 <input name=\"auto_disable_signs_per_minute\" type=\"number\" min=\"0\" max=\"1000000\" step=\"1\" value=\"" + Number(c.auto_disable_signs_per_minute || 0) + "\"></label>" +
      "<label>错误阈值 <input name=\"auto_disable_errors_per_minute\" type=\"number\" min=\"0\" max=\"1000000\" step=\"1\" value=\"" + Number(c.auto_disable_errors_per_minute || 0) + "\"></label>" +
      "<label class=\"check\"><input name=\"auto_revoke\" type=\"checkbox\" " + (c.auto_revoke ? "checked" : "") + ">自动永久吊销</label>" +
      "<button class=\"btn secondary\" type=\"submit\">保存阈值</button></form>";
    return "<tr><td><code>" + id + "</code></td><td>" + status + "</td><td>" +
      (c.rate_per_minute || "-") + "/min</td><td>" +
      (c.auto_disable_signs_per_minute || "-") + " signs, " +
      (c.auto_disable_errors_per_minute || "-") + " errors</td><td class=\"actions\">" +
      "<button class=\"btn secondary\" onclick=\"withButton(this,()=>action('" + id + "','" + next + "'))\">" + (c.disabled ? t.enable : t.disable) + "</button>" +
      "<button class=\"btn danger\" onclick=\"withButton(this,()=>action('" + id + "','revoke'))\">" + t.revoke + "</button>" +
      "<button class=\"btn\" onclick=\"withButton(this,()=>action('" + id + "','unrevoke'))\">" + t.unrevoke + "</button>" +
      "</td></tr><tr><td></td><td colspan=\"4\">" + limits + "</td></tr>";
  }).join("");
  document.querySelector("#clients").innerHTML = rows ? "<div class=\"table-scroll\"><table><thead><tr><th>" + t.id + "</th><th>" + t.status + "</th><th>" + t.rate + "</th><th>" + t.autoDisable + "</th><th></th></tr></thead><tbody>" + rows + "</tbody></table></div>" : "<div class=\"empty\">" + t.noClients + "</div>";
  document.querySelector("#revoked").textContent = (data.revoked || []).join("\n") || t.none;
  document.querySelector("#audit").textContent = (data.audit || []).join("\n") || t.noAudit;
}
document.addEventListener("DOMContentLoaded",()=>{
  applyText();
  const dialog = document.querySelector("#token-dialog");
  dialog.addEventListener("close",()=>{issuedCommand="";document.querySelector("#issued-token").textContent="";});
  document.querySelector("#copy-token").addEventListener("click",async()=>{
    try {
      await navigator.clipboard.writeText(issuedCommand);
      toast(t.copied);
    } catch (err) {
      toast(err.message || t.loadFailed);
    }
  });
  load().catch(err => toast((t.loadFailed || "Load failed") + ": " + err.message));
});
</script>
</body>
</html>`))
