package keyless

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

type SignServerOptions struct {
	Token       string
	ClientsPath string
	RevokedPath string
	AuditPath   string
}

type ClientFile struct {
	Clients []ClientConfig `json:"clients"`
}

type ClientConfig struct {
	ID                         string            `json:"id"`
	Token                      string            `json:"token"`
	PrivateKey                 string            `json:"private_key,omitempty"`
	PrivateKeys                map[string]string `json:"private_keys,omitempty"`
	Disabled                   bool              `json:"disabled,omitempty"`
	RatePerMinute              int               `json:"rate_per_minute,omitempty"`
	AutoDisableSignsPerMinute  int               `json:"auto_disable_signs_per_minute,omitempty"`
	AutoDisableErrorsPerMinute int               `json:"auto_disable_errors_per_minute,omitempty"`
	AutoRevoke                 bool              `json:"auto_revoke,omitempty"`
}

type clientState struct {
	cfg          ClientConfig
	windowStart  time.Time
	signs        int
	errors       int
	autoDisabled bool
}

type authManager struct {
	mu          sync.Mutex
	sharedToken string
	clientsMode bool
	clients     map[string]*clientState
	revoked     map[string]struct{}
	revokedPath string
	auditPath   string
}

type auditRecord struct {
	Time       string `json:"time"`
	ClientID   string `json:"client_id,omitempty"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	Action     string `json:"action"`
	Result     string `json:"result"`
	Reason     string `json:"reason,omitempty"`
}

func newAuthManager(opts SignServerOptions) (*authManager, error) {
	manager := &authManager{
		sharedToken: opts.Token,
		clients:     make(map[string]*clientState),
		revoked:     make(map[string]struct{}),
		revokedPath: opts.RevokedPath,
		auditPath:   opts.AuditPath,
	}
	if opts.ClientsPath != "" {
		manager.clientsMode = true
		if err := manager.loadClients(opts.ClientsPath); err != nil {
			return nil, err
		}
	}
	if opts.RevokedPath != "" {
		if err := manager.loadRevoked(opts.RevokedPath); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (a *authManager) loadClients(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var file ClientFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	for _, client := range file.Clients {
		client.ID = strings.TrimSpace(client.ID)
		if client.ID == "" || client.Token == "" {
			return errors.New("client id and token are required")
		}
		a.clients[client.ID] = &clientState{cfg: client}
	}
	return nil
}

func (a *authManager) loadRevoked(path string) error {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		if id != "" && !strings.HasPrefix(id, "#") {
			a.revoked[id] = struct{}{}
		}
	}
	return scanner.Err()
}

func (a *authManager) authenticate(token string) (string, bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.clientsMode && len(a.clients) == 0 {
		if a.sharedToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(a.sharedToken)) == 1 {
			return "shared", true, ""
		}
		return "", false, "bad token"
	}

	for id, state := range a.clients {
		if subtle.ConstantTimeCompare([]byte(token), []byte(state.cfg.Token)) != 1 {
			continue
		}
		if state.cfg.Disabled {
			return id, false, "client disabled"
		}
		if state.autoDisabled {
			return id, false, "client auto-disabled"
		}
		if _, ok := a.revoked[id]; ok {
			return id, false, "client revoked"
		}
		return id, true, ""
	}
	return "", false, "bad token"
}

func (a *authManager) record(clientID string, action string, ok bool, reason string, remoteAddr string) {
	if clientID == "" {
		a.audit(clientID, action, resultName(ok), reason, remoteAddr)
		return
	}

	a.mu.Lock()
	state := a.clients[clientID]
	if state != nil {
		now := time.Now().UTC()
		minute := now.Truncate(time.Minute)
		if state.windowStart.IsZero() || !state.windowStart.Equal(minute) {
			state.windowStart = minute
			state.signs = 0
			state.errors = 0
		}
		if ok && action == "sign" {
			state.signs++
		}
		if !ok {
			state.errors++
		}
		if limit := state.cfg.RatePerMinute; limit > 0 && action == "sign" && state.signs > limit {
			reason = "rate limit exceeded"
			ok = false
		}
		if limit := state.cfg.AutoDisableSignsPerMinute; limit > 0 && action == "sign" && state.signs > limit {
			reason = "auto limit exceeded: sign threshold"
			ok = false
			if state.cfg.AutoRevoke {
				state.autoDisabled = true
				reason = "auto-revoked: sign threshold exceeded"
				a.appendRevokedLocked(clientID)
			}
		}
		if limit := state.cfg.AutoDisableErrorsPerMinute; limit > 0 && state.errors > limit {
			reason = "auto limit exceeded: error threshold"
			ok = false
			if state.cfg.AutoRevoke {
				state.autoDisabled = true
				reason = "auto-revoked: error threshold exceeded"
				a.appendRevokedLocked(clientID)
			}
		}
	}
	a.mu.Unlock()

	a.audit(clientID, action, resultName(ok), reason, remoteAddr)
}

func (a *authManager) allowed(clientID string, action string) (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.clients[clientID]
	if state == nil {
		return true, ""
	}
	if state.cfg.RatePerMinute > 0 && action == "sign" && state.signs >= state.cfg.RatePerMinute {
		return false, "rate limit exceeded"
	}
	if state.cfg.AutoDisableSignsPerMinute > 0 && action == "sign" && state.signs >= state.cfg.AutoDisableSignsPerMinute {
		if state.cfg.AutoRevoke {
			state.autoDisabled = true
			a.appendRevokedLocked(clientID)
			return false, "auto-revoked: sign threshold exceeded"
		}
		return false, "auto limit exceeded: sign threshold"
	}
	return true, ""
}

func (a *authManager) appendRevokedLocked(clientID string) {
	if _, ok := a.revoked[clientID]; ok {
		return
	}
	a.revoked[clientID] = struct{}{}
	if a.revokedPath == "" {
		return
	}
	file, err := os.OpenFile(a.revokedPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(clientID + "\n")
}

func (a *authManager) audit(clientID string, action string, result string, reason string, remoteAddr string) {
	if a.auditPath == "" {
		return
	}
	record := auditRecord{
		Time:       time.Now().UTC().Format(time.RFC3339),
		ClientID:   clientID,
		RemoteAddr: remoteAddr,
		Action:     action,
		Result:     result,
		Reason:     reason,
	}
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	file, err := os.OpenFile(a.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write(append(line, '\n'))
}

func resultName(ok bool) string {
	if ok {
		return "ok"
	}
	return "denied"
}
