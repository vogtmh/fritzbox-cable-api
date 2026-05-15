package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
)

// ==================== Configuration ====================

type Config struct {
	FritzboxURL string `json:"fritzbox_url"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	ServerPort  int    `json:"server_port"`
}

func loadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	cfg.FritzboxURL = strings.TrimRight(cfg.FritzboxURL, "/")
	if cfg.FritzboxURL == "" {
		cfg.FritzboxURL = "http://192.168.178.1"
	}
	if cfg.ServerPort == 0 {
		cfg.ServerPort = 8080
	}
	return cfg, nil
}

// ==================== Fritz!Box Authentication ====================

type sessionInfo struct {
	XMLName   xml.Name `xml:"SessionInfo"`
	SID       string   `xml:"SID"`
	Challenge string   `xml:"Challenge"`
	BlockTime int      `xml:"BlockTime"`
}

// computeMD5Response computes the challenge response using MD5 with UTF-16LE encoding.
// This is used by Fritz!OS versions before 7.24.
func computeMD5Response(challenge, password string) string {
	combined := challenge + "-" + password
	runes := []rune(combined)
	encoded := utf16.Encode(runes)
	buf := make([]byte, len(encoded)*2)
	for i, r := range encoded {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	hash := md5.Sum(buf)
	return challenge + "-" + hex.EncodeToString(hash[:])
}

// computePBKDF2Response computes the challenge response for Fritz!OS 7.24+.
// The challenge format is: 2$<iter1>$<salt1>$<iter2>$<salt2>
func computePBKDF2Response(challenge, password string) (string, error) {
	parts := strings.Split(challenge, "$")
	if len(parts) != 5 || parts[0] != "2" {
		return "", fmt.Errorf("unexpected PBKDF2 challenge format: %q", challenge)
	}
	iter1, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("parse iter1: %w", err)
	}
	salt1, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("parse salt1: %w", err)
	}
	iter2, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", fmt.Errorf("parse iter2: %w", err)
	}
	salt2, err := hex.DecodeString(parts[4])
	if err != nil {
		return "", fmt.Errorf("parse salt2: %w", err)
	}
	hash1 := pbkdf2.Key([]byte(password), salt1, iter1, 32, sha256.New)
	hash2 := pbkdf2.Key(hash1, salt2, iter2, 32, sha256.New)
	return challenge + "$" + hex.EncodeToString(hash2), nil
}

// ==================== Fritz!Box Client ====================

type FritzClient struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	sid        string
	sidExpiry  time.Time
}

func NewFritzClient(cfg Config) *FritzClient {
	return &FritzClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (f *FritzClient) getSessionInfo() (*sessionInfo, error) {
	loginURL := f.cfg.FritzboxURL + "/login_sid.lua"
	if f.cfg.Username != "" {
		loginURL += "?username=" + url.QueryEscape(f.cfg.Username)
	}
	resp, err := f.httpClient.Get(loginURL)
	if err != nil {
		return nil, fmt.Errorf("get session info: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read session info body: %w", err)
	}
	var si sessionInfo
	if err := xml.Unmarshal(body, &si); err != nil {
		return nil, fmt.Errorf("parse session info XML: %w", err)
	}
	return &si, nil
}

// login performs the Fritz!Box challenge-response login and stores the SID.
// Must be called with f.mu held.
func (f *FritzClient) login() error {
	si, err := f.getSessionInfo()
	if err != nil {
		return err
	}

	if si.SID != "" && si.SID != "0000000000000000" {
		f.sid = si.SID
		f.sidExpiry = time.Now().Add(18 * time.Minute)
		return nil
	}

	if si.BlockTime > 0 {
		return fmt.Errorf("login blocked for %d seconds (too many failed attempts)", si.BlockTime)
	}

	var response string
	if strings.HasPrefix(si.Challenge, "2$") {
		response, err = computePBKDF2Response(si.Challenge, f.cfg.Password)
		if err != nil {
			return fmt.Errorf("compute PBKDF2 response: %w", err)
		}
	} else {
		response = computeMD5Response(si.Challenge, f.cfg.Password)
	}

	params := url.Values{
		"username": {f.cfg.Username},
		"response": {response},
	}
	resp, err := f.httpClient.PostForm(f.cfg.FritzboxURL+"/login_sid.lua", params)
	if err != nil {
		return fmt.Errorf("login POST: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	var newSI sessionInfo
	if err := xml.Unmarshal(body, &newSI); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}
	if newSI.SID == "" || newSI.SID == "0000000000000000" {
		return fmt.Errorf("login failed: wrong password or username")
	}

	f.sid = newSI.SID
	f.sidExpiry = time.Now().Add(18 * time.Minute)
	log.Printf("Fritz!Box login successful, SID obtained")
	return nil
}

// ensureSID guarantees a valid SID exists, logging in if necessary.
func (f *FritzClient) ensureSID() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.sid != "" && time.Now().Before(f.sidExpiry) {
		return f.sid, nil
	}
	if err := f.login(); err != nil {
		return "", err
	}
	return f.sid, nil
}

// invalidateSID forces a re-login on the next request.
func (f *FritzClient) invalidateSID() {
	f.mu.Lock()
	f.sid = ""
	f.mu.Unlock()
}

// ==================== DOCSIS Data Structures ====================

// fritzDocInfoResponse is the raw JSON response from data.lua?page=docInfo.
// Field names and types are as returned by Fritz!OS on the 6660 Cable.
type fritzDocInfoResponse struct {
	PID  string           `json:"pid"`
	Data fritzDocInfoData `json:"data"`
}

type fritzDocInfoData struct {
	ChannelDs  fritzChannelGroup `json:"channelDs"`
	ChannelUs  fritzChannelGroup `json:"channelUs"`
	ReadyState string            `json:"readyState"`
}

type fritzChannelGroup struct {
	DOCSIS31 []fritzChannel `json:"docsis31"`
	DOCSIS30 []fritzChannel `json:"docsis30"`
}

// fritzChannel covers both downstream and upstream channel fields.
// Fritz!OS returns some numbers as JSON strings and some as actual numbers.
type fritzChannel struct {
	ChannelID     int     `json:"channelID"`    // actual int
	Modulation    string  `json:"modulation"`
	Frequency     string  `json:"frequency"`    // MHz string, may be range e.g. "134.975 - 324.975"
	PowerLevel    string  `json:"powerLevel"`   // dBmV as string e.g. "-0.5"
	// Downstream-only quality fields (strings)
	MER           string  `json:"mer"`          // DOCSIS 3.1 downstream MER (dB)
	MSE           string  `json:"mse"`          // DOCSIS 3.0 downstream MSE (dB)
	CorrErrors    int64   `json:"corrErrors"`   // actual int
	NonCorrErrors int64   `json:"nonCorrErrors"` // actual int
	Latency       float64 `json:"latency"`      // actual float
	// DOCSIS 3.1 extra fields
	FFT           string  `json:"fft"`
	PLC           string  `json:"plc"`          // string
	// Upstream-only fields
	Multiplex     string  `json:"multiplex"`
	ActiveSub     string  `json:"activesub"`    // string
}

// Channel is the public representation of a single DOCSIS channel.
type Channel struct {
	ChannelID     int     `json:"channel_id"`
	Standard      string  `json:"standard"`
	Modulation    string  `json:"modulation"`
	Frequency     string  `json:"frequency_mhz"` // MHz string, may be range for DOCSIS 3.1
	PowerDBmV     float64 `json:"power_dbmv"`
	MER_dB        float64 `json:"mer_db,omitempty"`  // DOCSIS 3.1 DS
	MSE_dB        float64 `json:"mse_db,omitempty"`  // DOCSIS 3.0 DS
	CorrErrors    int64   `json:"corrected_errors,omitempty"`
	NonCorrErrors int64   `json:"uncorrected_errors,omitempty"`
	Latency       float64 `json:"latency_ms,omitempty"`
	// DOCSIS 3.1 extras
	FFT           string  `json:"fft,omitempty"`
}

// DOCSISStatus is the public JSON API response.
type DOCSISStatus struct {
	Timestamp  time.Time `json:"timestamp"`
	ReadyState string    `json:"ready_state"`
	Downstream []Channel `json:"downstream"`
	Upstream   []Channel `json:"upstream"`
}

func parseFloatStr(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}

func convertChannel(fc fritzChannel, standard string) Channel {
	return Channel{
		ChannelID:     fc.ChannelID,
		Standard:      standard,
		Modulation:    fc.Modulation,
		Frequency:     fc.Frequency,
		PowerDBmV:     parseFloatStr(fc.PowerLevel),
		MER_dB:        parseFloatStr(fc.MER),
		MSE_dB:        parseFloatStr(fc.MSE),
		CorrErrors:    fc.CorrErrors,
		NonCorrErrors: fc.NonCorrErrors,
		Latency:       fc.Latency,
		FFT:           fc.FFT,
	}
}

// FetchDOCSISData fetches fresh DOCSIS data from the Fritz!Box.
func (f *FritzClient) FetchDOCSISData() (*DOCSISStatus, error) {
	sid, err := f.ensureSID()
	if err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	data, err := f.fetchDocInfo(sid)
	if err != nil {
		// Session may have expired server-side; try re-logging in once.
		log.Printf("Data fetch failed (%v), re-authenticating...", err)
		f.invalidateSID()
		sid, err = f.ensureSID()
		if err != nil {
			return nil, fmt.Errorf("re-authenticate: %w", err)
		}
		data, err = f.fetchDocInfo(sid)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (f *FritzClient) fetchDocInfo(sid string) (*DOCSISStatus, error) {
	params := url.Values{
		"sid":   {sid},
		"page":  {"docInfo"},
		"xhrId": {"all"},
		"xhr":   {"1"},
	}
	resp, err := f.httpClient.PostForm(f.cfg.FritzboxURL+"/data.lua", params)
	if err != nil {
		return nil, fmt.Errorf("POST data.lua: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	// If the response starts with '<', the Fritz!Box returned HTML (e.g. login page),
	// meaning the SID was invalid.
	if len(body) > 0 && body[0] == '<' {
		return nil, fmt.Errorf("fritz!box returned HTML instead of JSON (SID invalid or no permission)")
	}

	var raw fritzDocInfoResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse JSON response: %w (body: %.200s)", err, string(body))
	}

	status := &DOCSISStatus{
		Timestamp:  time.Now(),
		ReadyState: raw.Data.ReadyState,
		Downstream: []Channel{},
		Upstream:   []Channel{},
	}

	for _, ch := range raw.Data.ChannelDs.DOCSIS31 {
		status.Downstream = append(status.Downstream, convertChannel(ch, "DOCSIS 3.1"))
	}
	for _, ch := range raw.Data.ChannelDs.DOCSIS30 {
		status.Downstream = append(status.Downstream, convertChannel(ch, "DOCSIS 3.0"))
	}
	for _, ch := range raw.Data.ChannelUs.DOCSIS31 {
		status.Upstream = append(status.Upstream, convertChannel(ch, "DOCSIS 3.1"))
	}
	for _, ch := range raw.Data.ChannelUs.DOCSIS30 {
		status.Upstream = append(status.Upstream, convertChannel(ch, "DOCSIS 3.0"))
	}

	return status, nil
}

// ==================== Cache ====================

type Cache struct {
	mu        sync.Mutex
	data      *DOCSISStatus
	lastFetch time.Time
	ttl       time.Duration
	client    *FritzClient
}

func NewCache(client *FritzClient, ttl time.Duration) *Cache {
	return &Cache{client: client, ttl: ttl}
}

// Get returns cached data if fresh, otherwise fetches new data from the Fritz!Box.
func (c *Cache) Get() (*DOCSISStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data != nil && time.Since(c.lastFetch) < c.ttl {
		return c.data, nil
	}

	fresh, err := c.client.FetchDOCSISData()
	if err != nil {
		if c.data != nil {
			log.Printf("Fetch error, serving stale cache: %v", err)
			return c.data, nil
		}
		return nil, err
	}

	c.data = fresh
	c.lastFetch = time.Now()
	log.Printf("Cache refreshed: %d downstream, %d upstream channels",
		len(fresh.Downstream), len(fresh.Upstream))
	return c.data, nil
}

// ==================== HTTP Server ====================

type Server struct {
	cache *Cache
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	data, err := s.cache.Get()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) handleHAConfig(w http.ResponseWriter, r *http.Request) {
	data, err := s.cache.Get()
	if err != nil {
		http.Error(w, "Failed to fetch data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Determine the base URL from the request so the generated config points back here.
	scheme := "http"
	host := r.Host
	baseURL := scheme + "://" + host

	var b strings.Builder

	b.WriteString("# Fritz!Box DOCSIS — Home Assistant Configuration\n")
	b.WriteString("# Generated: " + data.Timestamp.Format("2006-01-02T15:04:05Z07:00") + "\n")
	b.WriteString("# Paste into configuration.yaml (or a file included from it).\n\n")

	// --- rest sensor (loads full JSON as attributes) ---
	b.WriteString("rest:\n")
	b.WriteString("  - resource: " + baseURL + "/api/status\n")
	b.WriteString("    scan_interval: 60\n")
	b.WriteString("    sensor:\n")
	b.WriteString("      - name: \"Fritz!Box DOCSIS\"\n")
	b.WriteString("        unique_id: fritzbox_docsis\n")
	b.WriteString("        value_template: \"{{ value_json.ready_state }}\"\n")
	b.WriteString("        json_attributes:\n")
	b.WriteString("          - downstream\n")
	b.WriteString("          - upstream\n")
	b.WriteString("          - timestamp\n\n")

	// --- template sensors ---
	b.WriteString("template:\n")
	b.WriteString("  - sensor:\n")

	writeSensor := func(name, uid, unit, attr, direction string, chID int) {
		selectExpr := fmt.Sprintf(
			"{{ state_attr('sensor.fritz_box_docsis', '%s')\n"+
				"             | selectattr('channel_id', 'eq', %d)\n"+
				"             | map(attribute='%s') | first | default('unknown') }}",
			direction, chID, attr,
		)
		b.WriteString("      - name: \"" + name + "\"\n")
		b.WriteString("        unique_id: " + uid + "\n")
		if unit != "" {
			b.WriteString("        unit_of_measurement: \"" + unit + "\"\n")
		}
		b.WriteString("        state: >\n")
		b.WriteString("          " + selectExpr + "\n")
	}

	for _, ch := range data.Downstream {
		pfx := fmt.Sprintf("docsis_downstream_ch%d", ch.ChannelID)
		lbl := fmt.Sprintf("DOCSIS DS Ch%d", ch.ChannelID)
		b.WriteString(fmt.Sprintf("      # %s (%s)\n", lbl, ch.Standard))
		writeSensor(lbl+" Power", pfx+"_power", "dBmV", "power_dbmv", "downstream", ch.ChannelID)
		if ch.MER_dB != 0 {
			writeSensor(lbl+" MER", pfx+"_mer", "dB", "mer_db", "downstream", ch.ChannelID)
		}
		if ch.MSE_dB != 0 {
			writeSensor(lbl+" MSE", pfx+"_mse", "dB", "mse_db", "downstream", ch.ChannelID)
		}
		writeSensor(lbl+" Corrected Errors", pfx+"_corr_err", "", "corrected_errors", "downstream", ch.ChannelID)
		writeSensor(lbl+" Uncorrected Errors", pfx+"_uncorr_err", "", "uncorrected_errors", "downstream", ch.ChannelID)
	}

	for _, ch := range data.Upstream {
		pfx := fmt.Sprintf("docsis_upstream_ch%d", ch.ChannelID)
		lbl := fmt.Sprintf("DOCSIS US Ch%d", ch.ChannelID)
		b.WriteString(fmt.Sprintf("      # %s (%s)\n", lbl, ch.Standard))
		writeSensor(lbl+" Power", pfx+"_power", "dBmV", "power_dbmv", "upstream", ch.ChannelID)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, b.String())
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl, err := template.New("ui").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

// ==================== HTML Template ====================

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Fritz!Box Cable Status</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
  header{background:#1e293b;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #334155;gap:1rem}
  h1{font-size:1.2rem;font-weight:600;color:#f1f5f9;white-space:nowrap}
  .meta{font-size:.8rem;color:#94a3b8}
  main{padding:1.5rem 2rem;max-width:1500px;margin:0 auto}
  .stat-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:1rem;margin-bottom:1.5rem}
  .stat{background:#1e293b;border:1px solid #334155;border-radius:.5rem;padding:1rem}
  .stat-label{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.25rem}
  .stat-value{font-size:1.4rem;font-weight:600;color:#f1f5f9}
  .section{margin-bottom:1.5rem}
  .section h2{font-size:.75rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.75rem}
  .card{background:#1e293b;border-radius:.5rem;overflow:auto;border:1px solid #334155}
  table{width:100%;border-collapse:collapse;font-size:.825rem;min-width:600px}
  th{background:#0f172a;color:#64748b;text-align:left;padding:.6rem 1rem;font-weight:500;font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
  td{padding:.6rem 1rem;border-top:1px solid #0f172a;white-space:nowrap}
  tr:hover td{background:#243044}
  .badge{display:inline-block;padding:.1rem .45rem;border-radius:9999px;font-size:.7rem;font-weight:600}
  .g{background:#14532d;color:#4ade80}
  .r{background:#450a0a;color:#f87171}
  .b{background:#1e3a5f;color:#60a5fa}
  .p{background:#3b0764;color:#c084fc}
  .y{background:#422006;color:#fbbf24}
  .mono{font-family:'SF Mono',Menlo,Monaco,Consolas,monospace}
  .btn{background:#3b82f6;color:#fff;border:none;padding:.45rem .9rem;border-radius:.375rem;cursor:pointer;font-size:.825rem;font-family:inherit;text-decoration:none}
  .btn:hover{background:#2563eb}
  .err{background:#450a0a;border:1px solid #991b1b;color:#f87171;padding:.75rem 1rem;border-radius:.5rem;margin-bottom:1rem;display:none}
  .loading{text-align:center;padding:2rem;color:#64748b}
  .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
  .overlay.open{display:flex}
  .modal{background:#1e293b;border:1px solid #334155;border-radius:.75rem;width:90%;max-width:860px;max-height:85vh;display:flex;flex-direction:column}
  .modal-header{display:flex;justify-content:space-between;align-items:center;padding:1rem 1.25rem;border-bottom:1px solid #334155}
  .modal-header h3{font-size:.95rem;font-weight:600}
  .modal-actions{display:flex;gap:.5rem}
  .modal-body{overflow:auto;padding:1.25rem}
  .modal-body pre{font-family:'SF Mono',Menlo,Monaco,Consolas,monospace;font-size:.78rem;color:#cbd5e1;white-space:pre;line-height:1.6}
  .sec-btn{background:transparent;border:1px solid #475569;color:#94a3b8;padding:.3rem .7rem;border-radius:.375rem;cursor:pointer;font-size:.8rem}
  .sec-btn:hover{background:#334155}
</style>
</head>
<body>
<header>
  <h1>Fritz!Box Cable Status</h1>
  <div style="display:flex;align-items:center;gap:1rem">
    <span class="meta" id="ts">–</span>
    <button class="btn" onclick="refresh()">Refresh</button>
    <a class="btn" href="/api/status" target="_blank">JSON API</a>
    <button class="btn" style="background:#7c3aed" onclick="showHA()">HA Config</button>
  </div>
</header>
<div class="overlay" id="overlay">
  <div class="modal">
    <div class="modal-header">
      <h3>Home Assistant configuration.yaml</h3>
      <div class="modal-actions">
        <button class="sec-btn" onclick="copyHA()">Copy</button>
        <button class="sec-btn" onclick="closeHA()">Close</button>
      </div>
    </div>
    <div class="modal-body"><pre id="ha-yaml">Loading…</pre></div>
  </div>
</div>
<main>
  <div class="err" id="err"></div>
  <div class="stat-row" id="stats"></div>

  <div class="section">
    <h2>Downstream Channels</h2>
    <div class="card">
      <table>
        <thead><tr>
          <th>Ch ID</th><th>Standard</th><th>Modulation</th>
          <th>Frequency (MHz)</th><th>Power (dBmV)</th><th>MER / MSE (dB)</th>
          <th>Corr. Err</th><th>Uncorr. Err</th>
        </tr></thead>
        <tbody id="ds"><tr><td colspan="8" class="loading">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>Upstream Channels</h2>
    <div class="card">
      <table>
        <thead><tr>
          <th>Ch ID</th><th>Standard</th><th>Modulation</th>
          <th>Frequency (MHz)</th><th>Power (dBmV)</th>
        </tr></thead>
        <tbody id="us"><tr><td colspan="5" class="loading">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>
</main>
<script>
let timer;

function fmtF(v){return(v===undefined||v===null||v===0)?'–':v.toFixed(1)}
function fmtN(v){return(!v)?'<span style="color:#475569">0</span>':String(v)}

function stdBadge(s){
  if(!s)return'';
  return s.includes('3.1')?badge(s,'p'):badge(s,'b');
}
function badge(t,cls){return'<span class="badge '+cls+'">'+t+'</span>'}

function qualCell(ch){
  if(ch.mer_db)return fmtF(ch.mer_db)+' <span style="color:#64748b;font-size:.7rem">MER</span>';
  if(ch.mse_db)return fmtF(ch.mse_db)+' <span style="color:#64748b;font-size:.7rem">MSE</span>';
  return'–';
}

function renderDS(chs){
  const el=document.getElementById('ds');
  if(!chs||!chs.length){el.innerHTML='<tr><td colspan="8" class="loading">No data</td></tr>';return}
  el.innerHTML=chs.map(c=>'<tr>'+
    '<td class="mono">'+c.channel_id+'</td>'+
    '<td>'+stdBadge(c.standard)+'</td>'+
    '<td class="mono">'+c.modulation+'</td>'+
    '<td class="mono">'+(c.frequency_mhz||'–')+' MHz</td>'+
    '<td class="mono">'+fmtF(c.power_dbmv)+'</td>'+
    '<td class="mono">'+qualCell(c)+'</td>'+
    '<td class="mono">'+fmtN(c.corrected_errors)+'</td>'+
    '<td class="mono">'+fmtN(c.uncorrected_errors)+'</td>'+
  '</tr>').join('');
}

function renderUS(chs){
  const el=document.getElementById('us');
  if(!chs||!chs.length){el.innerHTML='<tr><td colspan="5" class="loading">No data</td></tr>';return}
  el.innerHTML=chs.map(c=>'<tr>'+
    '<td class="mono">'+c.channel_id+'</td>'+
    '<td>'+stdBadge(c.standard)+'</td>'+
    '<td class="mono">'+c.modulation+'</td>'+
    '<td class="mono">'+(c.frequency_mhz||'–')+' MHz</td>'+
    '<td class="mono">'+fmtF(c.power_dbmv)+'</td>'+
  '</tr>').join('');
}

function renderStats(d){
  const ds=d.downstream||[],us=d.upstream||[];
  const mers=ds.filter(c=>c.mer_db);
  const mses=ds.filter(c=>c.mse_db);
  const qualArr=[...mers.map(c=>c.mer_db),...mses.map(c=>Math.abs(c.mse_db))];
  const avgQual=qualArr.length?qualArr.reduce((a,b)=>a+b,0)/qualArr.length:null;
  const avgPow=ds.length?ds.reduce((a,b)=>a+(b.power_dbmv||0),0)/ds.length:null;
  const rs=d.ready_state||'–';
  document.getElementById('stats').innerHTML=
    stat('DS Channels',ds.length)+
    stat('US Channels',us.length)+
    stat('Status',rs)+
    (avgQual!==null?stat('Avg DS Quality',avgQual.toFixed(1)+' dB'):'')+
    (avgPow!==null?stat('Avg DS Power',avgPow.toFixed(1)+' dBmV'):'');
}
function stat(label,val){
  return'<div class="stat"><div class="stat-label">'+label+'</div><div class="stat-value">'+val+'</div></div>';
}

async function refresh(){
  try{
    const r=await fetch('/api/status');
    if(!r.ok)throw new Error('HTTP '+r.status);
    const d=await r.json();
    if(d.error){showErr(d.error);return}
    hideErr();
    document.getElementById('ts').textContent='Updated: '+new Date(d.timestamp).toLocaleTimeString();
    renderStats(d);
    renderDS(d.downstream);
    renderUS(d.upstream);
  }catch(e){
    showErr('Failed to fetch data: '+e.message);
  }
  clearTimeout(timer);
  timer=setTimeout(refresh,60000);
}
function showErr(msg){const el=document.getElementById('err');el.textContent=msg;el.style.display='block'}
function hideErr(){document.getElementById('err').style.display='none'}

async function showHA(){
  const el=document.getElementById('ha-yaml');
  el.textContent='Loading…';
  document.getElementById('overlay').classList.add('open');
  try{
    const r=await fetch('/api/ha-config');
    el.textContent=await r.text();
  }catch(e){
    el.textContent='Error: '+e.message;
  }
}
function closeHA(){document.getElementById('overlay').classList.remove('open')}
function copyHA(){
  navigator.clipboard.writeText(document.getElementById('ha-yaml').textContent)
    .then(()=>alert('Copied to clipboard!'))
    .catch(()=>alert('Copy failed — select the text and copy manually.'));
}
document.getElementById('overlay').addEventListener('click',function(e){
  if(e.target===this)closeHA();
});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeHA();});

refresh();
</script>
</body>
</html>`

// ==================== Main ====================

func main() {
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config.json: %v", err)
	}

	client := NewFritzClient(cfg)
	cache := NewCache(client, time.Minute)

	// Attempt initial connection to surface configuration errors early.
	log.Printf("Connecting to Fritz!Box at %s ...", cfg.FritzboxURL)
	if _, err := cache.Get(); err != nil {
		log.Printf("Warning: initial data fetch failed: %v", err)
		log.Printf("The server will still start; retries happen on each request.")
	}

	srv := &Server{cache: cache}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", srv.handleAPI)
	mux.HandleFunc("/api/ha-config", srv.handleHAConfig)
	mux.HandleFunc("/", srv.handleUI)

	addr := fmt.Sprintf(":%d", cfg.ServerPort)
	log.Printf("Server listening on http://localhost%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
