package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	"myzerossl/internal/keyless"
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
	ID          string `json:"id"`
	Label       string `json:"label,omitempty"`
	Status      string `json:"status"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	RequestedAt string `json:"requested_at"`
	ApprovedAt  string `json:"approved_at,omitempty"`
	RejectedAt  string `json:"rejected_at,omitempty"`
}

type registerRequest struct {
	ID    string `json:"id"`
	Label string `json:"label"`
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
	mux.HandleFunc("GET /auth/account/callback", a.callback)
	mux.HandleFunc("POST /logout", a.logout)
	mux.HandleFunc("POST /api/register", a.registerEdge)
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
	user, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]string{
		"Email": user.User.Email,
		"Name":  user.User.DisplayName,
	})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
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
	if !validClientID(req.ID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
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
			if err := writeRegistrations(a.registerPath, file); err != nil {
				writeError(w, err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "pending"})
			return
		}
	}
	file.Registrations = append(file.Registrations, edgeRegistration{
		ID:          req.ID,
		Label:       req.Label,
		Status:      "pending",
		RemoteAddr:  clientAddress(r),
		RequestedAt: now,
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
			}
		}
	}
	if !found && (action == "disable" || action == "enable") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
		return
	}

	switch action {
	case "disable", "enable":
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
			RatePerMinute:              300,
			AutoDisableSignsPerMinute:  1000,
			AutoDisableErrorsPerMinute: 30,
		})
		registrations.Registrations[index].Status = "approved"
		registrations.Registrations[index].ApprovedAt = now
		if err := writeClientFile(a.clientsPath, clients); err != nil {
			writeError(w, err)
			return
		}
		if err := writeRegistrations(a.registerPath, registrations); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": token})
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

func clientAddress(r *http.Request) string {
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if value := strings.TrimSpace(r.Header.Get(header)); value != "" {
			return value
		}
	}
	return r.RemoteAddr
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func applyEnv(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSL Signer Console</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f7f8fa;color:#101418}
    header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid #dde1e6;background:#fff}
    main{max-width:1100px;margin:0 auto;padding:20px;display:grid;gap:18px}
    section{background:#fff;border:1px solid #dde1e6;border-radius:8px;padding:16px}
    h1{font-size:20px;margin:0} h2{font-size:16px;margin:0 0 12px}
    table{width:100%;border-collapse:collapse;font-size:14px} th,td{text-align:left;border-bottom:1px solid #edf0f2;padding:8px}
    button{border:1px solid #bac2cc;background:#fff;border-radius:6px;padding:6px 10px;cursor:pointer}
    button.danger{border-color:#c73b3b;color:#a81818} code,pre{background:#f0f2f4;border-radius:6px}
    pre{padding:12px;overflow:auto;max-height:360px}.muted{color:#5d6875}.actions{display:flex;gap:8px;flex-wrap:wrap}
  </style>
</head>
<body>
  <header>
    <div><h1>SSL Signer Console</h1><div class="muted">{{.Email}}</div></div>
    <form method="post" action="/logout"><button>退出</button></form>
  </header>
  <main>
    <section><h2>Pending Edge Registrations</h2><div id="registrations"></div></section>
    <section><h2>Edge Clients</h2><div id="clients"></div></section>
    <section><h2>Revoked Clients</h2><pre id="revoked"></pre></section>
    <section><h2>Signer Audit</h2><pre id="audit"></pre></section>
  </main>
<script>
async function api(path, options = {}) {
  const res = await fetch(path, { method: options.method || "GET", cache: "no-store" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}
async function action(id, name) {
  await api("/api/clients/" + encodeURIComponent(id) + "/" + name, { method: "POST" });
  await load();
}
async function registrationAction(id, name) {
  const data = await api("/api/registrations/" + encodeURIComponent(id) + "/" + name, { method: "POST" });
  if (data.token) alert("请立即保存该 edge token：\n\n" + data.token);
  await load();
}
function esc(s){return String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]))}
async function load() {
  const data = await api("/api/summary");
  const revoked = new Set(data.revoked || []);
  const pendingRows = (data.registrations || []).filter(r => r.status === "pending").map(r => {
    const id = esc(r.id);
    return "<tr><td><code>" + id + "</code></td><td>" + esc(r.label || "") + "</td><td>" +
      esc(r.remote_addr || "") + "</td><td>" + esc(r.requested_at || "") + "</td><td class=\"actions\">" +
      "<button onclick=\"registrationAction('" + id + "','approve')\">批准并生成 token</button>" +
      "<button class=\"danger\" onclick=\"registrationAction('" + id + "','reject')\">拒绝</button>" +
      "</td></tr>";
  }).join("");
  document.querySelector("#registrations").innerHTML = "<table><thead><tr><th>ID</th><th>Label</th><th>Remote</th><th>Requested</th><th></th></tr></thead><tbody>" + pendingRows + "</tbody></table>";
  const rows = (data.clients || []).map(c => {
    const id = esc(c.id);
    const next = c.disabled ? "enable" : "disable";
    const label = c.disabled ? "允许注册/启用" : "撤销注册权限";
    const status = (c.disabled ? "disabled" : "active") + (revoked.has(c.id) ? " / revoked" : "");
    return "<tr><td><code>" + id + "</code></td><td>" + status + "</td><td>" +
      (c.rate_per_minute || "-") + "/min</td><td>" +
      (c.auto_disable_signs_per_minute || "-") + " signs, " +
      (c.auto_disable_errors_per_minute || "-") + " errors</td><td class=\"actions\">" +
      "<button onclick=\"action('" + id + "','" + next + "')\">" + label + "</button>" +
      "<button class=\"danger\" onclick=\"action('" + id + "','revoke')\">吊销</button>" +
      "<button onclick=\"action('" + id + "','unrevoke')\">允许再次注册</button>" +
      "</td></tr>";
  }).join("");
  document.querySelector("#clients").innerHTML = "<table><thead><tr><th>ID</th><th>Status</th><th>Rate</th><th>Auto disable</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>";
  document.querySelector("#revoked").textContent = (data.revoked || []).join("\n") || "none";
  document.querySelector("#audit").textContent = (data.audit || []).join("\n") || "no audit entries";
}
load().catch(err => alert(err.message));
</script>
</body>
</html>`))
