// Command aegis-responder is a Falcosidekick webhook responder that turns Falco
// detections into AegisBPF kernel enforcement via the node-local control socket.
//
// Flow:  Falco (detect) -> Falcosidekick (webhook output) -> aegis-responder
//
//	-> POST /block/add|/network/deny/... on the AegisBPF control socket
//	-> race-free in-kernel -EPERM on this node.
//
// Safe by default: only rules named in the config act, and it can run in
// dry-run mode. Deploy as a DaemonSet next to the AegisBPF agent so alerts are
// enforced on the node where they fired.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// maxBody caps the webhook request body to prevent memory exhaustion.
const maxBody = 64 * 1024

// FalcoAlert is the subset of the Falcosidekick/Falco payload we consume.
type FalcoAlert struct {
	Rule         string                 `json:"rule"`
	Priority     string                 `json:"priority"`
	Output       string                 `json:"output"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

// RuleAction maps a Falco rule name to an AegisBPF enforcement action.
type RuleAction struct {
	Rule   string `json:"rule"`                  // exact Falco rule name to act on
	Action string `json:"action"`                // block-file | deny-ip | deny-cidr
	Field  string `json:"field"`                 // output_fields key holding the target (path/ip/cidr)
	TTL    int    `json:"ttl_seconds,omitempty"` // if >0, the deny auto-expires after this many seconds
}

// Config is the responder configuration (JSON; stdlib-only, no YAML dep).
type Config struct {
	Socket      string       `json:"socket"`       // AegisBPF control socket path
	DryRun      bool         `json:"dry_run"`      // log intended actions, do not enforce
	MinPriority string       `json:"min_priority"` // ignore alerts below this Falco priority
	AuthToken   string       `json:"auth_token"`   // if set, require X-Aegis-Token header match
	Rules       []RuleAction `json:"rules"`
}

// Falco priority ordering (higher = more severe).
var priorityRank = map[string]int{
	"debug": 0, "informational": 1, "notice": 2, "warning": 3,
	"error": 4, "critical": 5, "alert": 6, "emergency": 7,
}

func rank(p string) int { return priorityRank[strings.ToLower(strings.TrimSpace(p))] }

// verbFor maps an action to the control-socket verb.
func verbFor(action string) (string, bool) {
	switch action {
	case "block-file":
		return "/block/add", true
	case "deny-ip":
		return "/network/deny/ip", true
	case "deny-cidr":
		return "/network/deny/cidr", true
	default:
		return "", false
	}
}

// validTarget rejects arguments that are malformed or unsafe to forward over the
// newline-delimited control protocol. It is the trust boundary between untrusted
// Falco output_fields and the kernel-enforcement socket: an embedded newline
// could smuggle a second command, and a malformed path/IP would be a no-op at
// best. Verb-specific shape checks keep enforcement targeted.
func validTarget(verb, arg string) bool {
	// No control characters may cross into the line-oriented control protocol.
	if strings.ContainsAny(arg, "\n\r\x00") {
		return false
	}
	switch verb {
	case "/block/add":
		// Absolute filesystem path only.
		return strings.HasPrefix(arg, "/") && !strings.Contains(arg, "..")
	case "/network/deny/ip":
		ip := net.ParseIP(arg)
		return ip != nil
	case "/network/deny/cidr":
		_, _, err := net.ParseCIDR(arg)
		return err == nil
	default:
		return false
	}
}

// decide is the pure mapping: given an alert and config, return the control
// (verb, arg, ttl) to issue, or ok=false to take no action. ttl is the matched
// rule's auto-expiry in seconds (0 = permanent). Kept side-effect-free so it is
// fully unit-testable.
func decide(a FalcoAlert, cfg *Config) (verb, arg string, ttl int, ok bool) {
	if cfg.MinPriority != "" && rank(a.Priority) < rank(cfg.MinPriority) {
		return "", "", 0, false
	}
	for _, r := range cfg.Rules {
		if r.Rule != a.Rule {
			continue
		}
		v, vok := verbFor(r.Action)
		if !vok {
			return "", "", 0, false
		}
		raw, present := a.OutputFields[r.Field]
		if !present {
			return "", "", 0, false
		}
		s, _ := raw.(string)
		s = strings.TrimSpace(s)
		if s == "" {
			return "", "", 0, false
		}
		if !validTarget(v, s) {
			return "", "", 0, false
		}
		ttl := r.TTL
		if ttl < 0 {
			ttl = 0
		}
		return v, s, ttl, true
	}
	return "", "", 0, false
}

// sendControl issues one control request to the AegisBPF socket and returns the
// agent's JSON reply (read up to the blank-line terminator). When ttl > 0 the
// deny is installed with an auto-expiry, appended as a trailing "ttl=<sec>" token
// (the agent strips it before treating the rest as the target).
func sendControl(socket, verb, arg string, ttl int) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(context.Background(), "unix", socket)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	line := fmt.Sprintf("POST %s %s", verb, arg)
	if ttl > 0 {
		line += fmt.Sprintf(" ttl=%d", ttl)
	}
	if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
		return "", err
	}
	buf := make([]byte, 512)
	var reply strings.Builder
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			reply.Write(buf[:n])
			if strings.Contains(reply.String(), "\n\n") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(reply.String()), nil
}

type responder struct {
	cfg *Config
}

func (h *responder) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Optional shared-secret auth. Constant-time compare avoids leaking the
	// token via response timing.
	if h.cfg.AuthToken != "" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Aegis-Token")), []byte(h.cfg.AuthToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var a FalcoAlert
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	verb, arg, ttl, ok := decide(a, h.cfg)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{"result": "no-action", "rule": a.Rule})
		return
	}
	if h.cfg.DryRun {
		log.Printf("DRY-RUN rule=%q -> POST %s %s ttl=%d", a.Rule, verb, arg, ttl)
		writeJSON(w, http.StatusOK, map[string]string{"result": "dry-run", "verb": verb, "arg": arg})
		return
	}
	reply, err := sendControl(h.cfg.Socket, verb, arg, ttl)
	if err != nil {
		log.Printf("ERROR rule=%q POST %s %s: %v", a.Rule, verb, arg, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"result": "error", "error": err.Error()})
		return
	}
	log.Printf("ENFORCED rule=%q -> POST %s %s ttl=%d -> %s", a.Rule, verb, arg, ttl, reply)
	writeJSON(w, http.StatusOK, map[string]string{"result": "enforced", "verb": verb, "arg": arg, "agent": reply})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Socket == "" {
		c.Socket = "/var/run/aegisbpf/aegisbpf.sock"
	}
	return &c, nil
}

func main() {
	cfgPath := getenv("AEGIS_RESPONDER_CONFIG", "/etc/aegis-responder/config.json")
	addr := getenv("AEGIS_RESPONDER_ADDR", ":8080")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config %s: %v", cfgPath, err)
	}
	if v := os.Getenv("AEGIS_API_SOCKET"); v != "" {
		cfg.Socket = v
	}
	if os.Getenv("AEGIS_RESPONDER_DRYRUN") == "1" {
		cfg.DryRun = true
	}
	if v := os.Getenv("AEGIS_RESPONDER_TOKEN"); v != "" {
		cfg.AuthToken = v
	}
	if cfg.AuthToken == "" {
		log.Printf("WARNING: no auth_token set — webhook accepts unauthenticated requests; "+
			"restrict network exposure or set AEGIS_RESPONDER_TOKEN (dry_run=%v)", cfg.DryRun)
	}
	log.Printf("aegis-responder: addr=%s socket=%s dry_run=%v rules=%d min_priority=%q auth=%v",
		addr, cfg.Socket, cfg.DryRun, len(cfg.Rules), cfg.MinPriority, cfg.AuthToken != "")

	h := &responder{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/", h.handle)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
