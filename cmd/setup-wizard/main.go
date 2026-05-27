package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type app struct {
	repo string
}

type result struct {
	Title string
	Lines []string
}

func main() {
	listen := flag.String("listen", "127.0.0.1:19500", "local setup wizard listen address")
	repo := flag.String("repo", "/opt/myzerossl", "repository path containing dist and deploy files")
	flag.Parse()
	if os.Geteuid() != 0 {
		log.Fatal("setup-wizard must run as root because it writes /etc and systemd units")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		log.Fatal("setup-wizard refuses non-local listen addresses")
	}
	a := &app{repo: *repo}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.index)
	mux.HandleFunc("POST /apply", a.apply)
	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("memecdn setup wizard listening on http://%s", *listen)
	log.Fatal(server.ListenAndServe())
}

func (a *app) index(w http.ResponseWriter, _ *http.Request) {
	render(w, pageData{})
}

func (a *app) apply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		render(w, pageData{Error: err.Error()})
		return
	}
	role := r.FormValue("role")
	var res result
	var err error
	switch role {
	case "edge":
		res, err = a.installEdge(r)
	case "trusted":
		res, err = a.installTrusted(r)
	default:
		err = fmt.Errorf("unknown role %q", role)
	}
	if err != nil {
		render(w, pageData{Error: err.Error()})
		return
	}
	render(w, pageData{Result: &res})
}

func (a *app) installEdge(r *http.Request) (result, error) {
	edgeID := value(r, "edge_id", hostname()+"-edge")
	installToken := secret()
	if err := ensureUser(); err != nil {
		return result{}, err
	}
	if err := mkdirs(0755, "/etc/myzerossl", "/etc/myzerossl/certs", "/etc/myzerossl/keyless", "/var/log/myzerossl", "/var/lib/memecdn"); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "dist/linux-amd64/edgeproxy"), "/usr/local/bin/edgeproxy", 0755); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "deploy/systemd/edgeproxy.service"), "/etc/systemd/system/edgeproxy.service", 0644); err != nil {
		return result{}, err
	}
	env := map[string]string{
		"EDGE_LISTEN":                 value(r, "edge_listen", ":443,:2053,:2083,:2087,:2096,:8443"),
		"EDGE_BACKEND":                value(r, "edge_backend", "http://127.0.0.1:8080"),
		"EDGE_CERT":                   value(r, "edge_cert", "/etc/myzerossl/certs/example.com.fullchain.crt"),
		"KEYLESS_TOKEN_FILE":          "/var/lib/memecdn/keyless.token",
		"EDGE_CACHE_TTL":              "10m",
		"EDGE_CACHE_MAX_BYTES":        "67108864",
		"EDGE_CACHE_MAX_OBJECT_BYTES": "4194304",
		"EDGE_REGISTER_URL":           value(r, "edge_register_url", "https://ssl-signer.example.com"),
		"EDGE_REGISTER_ID":            edgeID,
		"EDGE_REGISTER_LABEL":         value(r, "edge_label", edgeID),
		"EDGE_REGISTER_TOKEN":         installToken,
		"EDGE_REGISTER_POLL":          "10s",
		"KEYLESS_URL":                 value(r, "edge_keyless_url", "https://gateway.example.com:9443/api/v1/ssl-signer"),
		"KEYLESS_CLIENT_ID":           edgeID,
		"KEYLESS_CA":                  value(r, "edge_ca", "/etc/ssl/certs/ca-certificates.crt"),
		"KEYLESS_CLIENT_CERT":         value(r, "edge_client_cert", "/etc/myzerossl/keyless/edge-client.crt"),
		"KEYLESS_CLIENT_KEY":          value(r, "edge_client_key", "/etc/myzerossl/keyless/edge-client.key"),
		"KEYLESS_TOKEN":               "",
	}
	if err := writeEnv("/etc/myzerossl/edgeproxy.env", env); err != nil {
		return result{}, err
	}
	_ = run("chown", "-R", "root:myzerossl", "/etc/myzerossl")
	_ = run("chmod", "0750", "/etc/myzerossl", "/etc/myzerossl/certs", "/etc/myzerossl/keyless")
	_ = run("chmod", "0640", "/etc/myzerossl/edgeproxy.env")
	_ = run("chown", "-R", "myzerossl:myzerossl", "/var/log/myzerossl", "/var/lib/memecdn")
	if err := run("systemctl", "daemon-reload"); err != nil {
		return result{}, err
	}
	if err := run("systemctl", "enable", "edgeproxy.service"); err != nil {
		return result{}, err
	}
	return result{
		Title: "Edge configured",
		Lines: []string{
			"Place certificate and mTLS files on this edge, then run: systemctl restart edgeproxy",
			"Approve edge id " + edgeID + " in the trusted console.",
			"After approval, edgeproxy will fetch its signer token over HTTPS, store it in /var/lib/memecdn/keyless.token, verify with the signer, and start serving.",
		},
	}, nil
}

func (a *app) installTrusted(r *http.Request) (result, error) {
	if err := ensureUser(); err != nil {
		return result{}, err
	}
	if err := mkdirs(0755, "/etc/myzerossl", "/etc/myzerossl/private", "/etc/myzerossl/keyless", "/var/log/myzerossl"); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "dist/linux-amd64/keylessd"), "/usr/local/bin/keylessd", 0755); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "dist/linux-amd64/signer-console"), "/usr/local/bin/signer-console", 0755); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "deploy/systemd/keylessd-local.service"), "/etc/systemd/system/keylessd-local.service", 0644); err != nil {
		return result{}, err
	}
	if err := copyFile(filepath.Join(a.repo, "deploy/systemd/signer-console.service"), "/etc/systemd/system/signer-console.service", 0644); err != nil {
		return result{}, err
	}
	consoleURL := value(r, "trusted_console_url", "https://ssl-signer.example.com")
	keylessURL := value(r, "trusted_keyless_url", "https://gateway.example.com:9443/api/v1/ssl-signer")
	keylessListen := value(r, "trusted_keyless_listen", "127.0.0.1:19443")
	if err := writeEnv("/etc/myzerossl/keylessd-local.env", map[string]string{
		"KEYLESS_LISTEN":      keylessListen,
		"KEYLESS_PRIVATE_KEY": value(r, "trusted_private_key", "/etc/openresty/ssl/js.gripe.key.pem"),
		"KEYLESS_TOKEN":       "",
		"KEYLESS_CLIENTS":     "/etc/myzerossl/clients.json",
		"KEYLESS_REVOKED":     "/etc/myzerossl/revoked-clients.txt",
		"KEYLESS_AUDIT":       "/var/log/myzerossl/signer-audit.jsonl",
	}); err != nil {
		return result{}, err
	}
	if err := writeEnv("/etc/myzerossl/signer-console.env", map[string]string{
		"CONSOLE_LISTEN":         "127.0.0.1:19444",
		"CONSOLE_ACCOUNT_API":    value(r, "trusted_account_api", "https://gateway.example.com/api/v1/myaccount"),
		"CONSOLE_ACCOUNT_LOGIN":  value(r, "trusted_account_login", "https://account.example.com/login"),
		"CONSOLE_PUBLIC_URL":     consoleURL,
		"CONSOLE_CLIENT_ID":      value(r, "trusted_client_id", ""),
		"CONSOLE_SESSION_SECRET": value(r, "trusted_session_secret", secret()),
		"KEYLESS_CLIENTS":        "/etc/myzerossl/clients.json",
		"KEYLESS_REVOKED":        "/etc/myzerossl/revoked-clients.txt",
		"KEYLESS_AUDIT":          "/var/log/myzerossl/signer-audit.jsonl",
		"CONSOLE_REGISTRATIONS":  "/etc/myzerossl/edge-registrations.json",
	}); err != nil {
		return result{}, err
	}
	ensureFile("/etc/myzerossl/clients.json", "{\n  \"clients\": []\n}\n")
	ensureFile("/etc/myzerossl/revoked-clients.txt", "")
	ensureFile("/etc/myzerossl/edge-registrations.json", "{\n  \"registrations\": []\n}\n")
	_ = run("chown", "-R", "root:myzerossl", "/etc/myzerossl")
	_ = run("chmod", "0750", "/etc/myzerossl", "/etc/myzerossl/private", "/etc/myzerossl/keyless")
	_ = run("chmod", "0640", "/etc/myzerossl/keylessd-local.env", "/etc/myzerossl/signer-console.env", "/etc/myzerossl/clients.json", "/etc/myzerossl/revoked-clients.txt", "/etc/myzerossl/edge-registrations.json")
	_ = run("chown", "-R", "myzerossl:myzerossl", "/var/log/myzerossl")
	if err := run("systemctl", "daemon-reload"); err != nil {
		return result{}, err
	}
	if err := run("systemctl", "enable", "keylessd-local.service", "signer-console.service"); err != nil {
		return result{}, err
	}
	if err := run("systemctl", "restart", "keylessd-local.service", "signer-console.service"); err != nil {
		return result{}, err
	}
	return result{
		Title: "Trusted center deployed",
		Lines: []string{
			"Expose http://127.0.0.1:19444 as " + consoleURL,
			"Expose http://" + keylessListen + " as " + keylessURL,
			"Configure edges with EDGE_REGISTER_URL=" + consoleURL,
			"Configure edges with KEYLESS_URL=" + keylessURL,
		},
	}, nil
}

func value(r *http.Request, key, fallback string) string {
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return fallback
	}
	return value
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "memecdn"
	}
	return name
}

func secret() string {
	var raw [48]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func ensureUser() error {
	if err := run("id", "myzerossl"); err == nil {
		return nil
	}
	return run("useradd", "--system", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "myzerossl")
}

func mkdirs(mode os.FileMode, paths ...string) error {
	for _, path := range paths {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func writeEnv(path string, values map[string]string) error {
	var b strings.Builder
	for _, key := range sortedKeys(values) {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(envQuote(values[key]))
		b.WriteString("\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0640)
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	// Small stable insertion sort keeps dependencies at zero.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func envQuote(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}

func ensureFile(path, content string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	_ = os.WriteFile(path, []byte(content), 0640)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type pageData struct {
	Error  string
	Result *result
}

func render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setupPage.Execute(w, data)
}

var setupPage = template.Must(template.New("setup").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>memecdn setup</title>
<style>
body{margin:0;background:#f7f4ea;color:#12151a;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main{max-width:980px;margin:0 auto;padding:24px}h1{font-size:28px}.panel{border:3px solid #1f2937;border-radius:6px;box-shadow:5px 5px 0 #1f2937;background:#fffdf7;padding:18px;margin:18px 0}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}label{display:grid;gap:6px;font-weight:700}input,select{min-height:38px;border:2px solid #1f2937;border-radius:5px;padding:7px;font:inherit}
button{min-height:42px;border:3px solid #1f2937;border-radius:6px;background:#b8f3d4;box-shadow:3px 3px 0 #1f2937;font-weight:900;padding:8px 14px;cursor:pointer}.muted{color:#5c6572}.error{background:#ffe0e0}.ok{background:#e8fff1}pre{white-space:pre-wrap}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
</style>
<script>
function syncRole(){
 const role=document.querySelector("[name=role]").value;
 document.querySelector("#edge").hidden=role!="edge";
 document.querySelector("#trusted").hidden=role!="trusted";
}
addEventListener("DOMContentLoaded",syncRole);
</script>
</head>
<body><main>
<h1>memecdn setup</h1>
<p class="muted">本向导只监听本机地址，用于初始化 edge 设备或高信任中心。</p>
{{if .Error}}<section class="panel error"><strong>失败</strong><pre>{{.Error}}</pre></section>{{end}}
{{if .Result}}<section class="panel ok"><h2>{{.Result.Title}}</h2>{{range .Result.Lines}}<p>{{.}}</p>{{end}}</section>{{end}}
<form method="post" action="/apply" class="panel">
<label>注册类型<select name="role" onchange="syncRole()"><option value="edge">edge 设备</option><option value="trusted">高信任中心</option></select></label>
<section id="edge">
<h2>Edge 设备</h2><div class="grid">
<label>高信任控制台地址<input name="edge_register_url" value="https://ssl-signer.example.com"></label>
<label>高信任 signer 验证地址<input name="edge_keyless_url" value="https://gateway.example.com:9443/api/v1/ssl-signer"></label>
<label>Edge ID<input name="edge_id" value=""></label>
<label>Edge 标签<input name="edge_label" value=""></label>
<label>监听地址<input name="edge_listen" value=":443,:2053,:2083,:2087,:2096,:8443"></label>
<label>后端源站<input name="edge_backend" value="http://127.0.0.1:8080"></label>
<label>证书链路径<input name="edge_cert" value="/etc/myzerossl/certs/example.com.fullchain.crt"></label>
<label>CA 路径<input name="edge_ca" value="/etc/ssl/certs/ca-certificates.crt"></label>
<label>mTLS 客户端证书<input name="edge_client_cert" value="/etc/myzerossl/keyless/edge-client.crt"></label>
<label>mTLS 客户端私钥<input name="edge_client_key" value="/etc/myzerossl/keyless/edge-client.key"></label>
</div></section>
<section id="trusted" hidden>
<h2>高信任中心</h2><div class="grid">
<label>控制台公网地址<input name="trusted_console_url" value="https://ssl-signer.example.com"></label>
<label>Signer 公网验证地址<input name="trusted_keyless_url" value="https://gateway.example.com:9443/api/v1/ssl-signer"></label>
<label>私钥路径<input name="trusted_private_key" value="/etc/openresty/ssl/js.gripe.key.pem"></label>
<label>本地 signer 监听<input name="trusted_keyless_listen" value="127.0.0.1:19443"></label>
<label>account API<input name="trusted_account_api" value="https://gateway.example.com/api/v1/myaccount"></label>
<label>account 登录地址<input name="trusted_account_login" value="https://account.example.com/login"></label>
<label>account client_id<input name="trusted_client_id" value=""></label>
<label>控制台 session secret<input name="trusted_session_secret" value=""></label>
</div></section>
<p><button type="submit">部署配置</button></p>
</form>
</main></body></html>`))
