package proxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/overkazaf/cap/internal/types"
)

const (
	companionTokenFile             = "companion.token"
	companionTokenHeader           = "X-Cap-Token"
	companionAPIPrefix             = "/_cap/companion/"
	companionMinTokenHexChars      = 32
	companionTokenRandomBytes      = 32
	defaultCompanionBufferSize     = 200
	minCompanionBufferSize         = 10
	maxCompanionBufferSize         = 1000
	defaultCompanionFlowsLimit     = 80
	minCompanionFlowsLimit         = 1
	maxCompanionFlowsLimit         = 200
	companionMaxPreviewBytes       = 32 * 1024
	companionBinaryHexPreviewBytes = 512
	companionRPSWindowSec          = 10
	companionRPSBucketMs           = 100
	companionRPSBuckets            = (companionRPSWindowSec * 1000) / companionRPSBucketMs
)

var companionTokenMu sync.Mutex

// CompanionFlowSummary is the compact traffic row returned by
// GET /_cap/companion/flows.
type CompanionFlowSummary struct {
	Seq         int64  `json:"seq"`
	ID          string `json:"id"`
	Method      string `json:"method"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqBytes    int64  `json:"req_bytes"`
	RespBytes   int64  `json:"resp_bytes"`
	LatencyMs   int64  `json:"latency_ms"`
	TimestampMs int64  `json:"timestamp_ms"`
	Error       string `json:"error"`
}

// CompanionFlowDetail is the full flow snapshot returned by
// GET /_cap/companion/flows/{id}.
type CompanionFlowDetail struct {
	CompanionFlowSummary
	ReqHeaders        map[string]string `json:"req_headers"`
	RespHeaders       map[string]string `json:"resp_headers"`
	ReqBody           string            `json:"req_body"`
	RespBody          string            `json:"resp_body"`
	ReqBodyTruncated  bool              `json:"req_body_truncated"`
	RespBodyTruncated bool              `json:"resp_body_truncated"`
	ReqBodyBinary     bool              `json:"req_body_binary"`
	RespBodyBinary    bool              `json:"resp_body_binary"`
}

type companionStatsResponse struct {
	OK            bool    `json:"ok"`
	ProxyAddr     string  `json:"proxy_addr"`
	TotalFlows    int64   `json:"total_flows"`
	BufferedFlows int     `json:"buffered_flows"`
	LatestSeq     int64   `json:"latest_seq"`
	TotalBytes    int64   `json:"total_bytes"`
	ReqPerSec     float64 `json:"req_per_sec"`
	UptimeSec     int64   `json:"uptime_sec"`
}

type companionFlowsResponse struct {
	OK            bool                   `json:"ok"`
	LatestSeq     int64                  `json:"latest_seq"`
	TotalFlows    int64                  `json:"total_flows"`
	BufferedFlows int                    `json:"buffered_flows"`
	TotalBytes    int64                  `json:"total_bytes"`
	ReqPerSec     float64                `json:"req_per_sec"`
	Flows         []CompanionFlowSummary `json:"flows"`
}

type companionFlowDetailResponse struct {
	OK   bool                `json:"ok"`
	Flow CompanionFlowDetail `json:"flow"`
}

type companionClearResponse struct {
	OK        bool  `json:"ok"`
	LatestSeq int64 `json:"latest_seq"`
}

type companionErrorResponse struct {
	Error string `json:"error"`
}

type companionFlowQuery struct {
	Limit       int
	After       int64
	Method      string
	Search      string
	StatusGroup string
	Scheme      string
}

type rpsBucket struct {
	slot  int64
	count int
}

// companionFeed is a thread-safe bounded ring buffer holding recent captured
// flows and aggregate metrics for the Companion Live Traffic API.
type companionFeed struct {
	mu         sync.RWMutex
	proxyAddr  string
	startTime  time.Time
	maxSize    int
	ring       []*CompanionFlowDetail
	head       int
	count      int
	byID       map[string]*CompanionFlowDetail
	latestSeq  int64
	totalFlows int64
	totalBytes int64
	rpsBuckets [companionRPSBuckets]rpsBucket
}

// EnsureCompanionToken reads the per-host companion API token from
// <certDir>/companion.token if present and valid (>=32 hex chars), or
// generates a fresh 32-byte (64 lowercase hex char) token and atomically
// writes it with mode 0600. When certDir is empty, defaultCertDir() (~/.cap)
// is used.
func EnsureCompanionToken(certDir string) (string, error) {
	companionTokenMu.Lock()
	defer companionTokenMu.Unlock()

	if strings.TrimSpace(certDir) == "" {
		certDir = defaultCertDir()
	}
	tokenPath := filepath.Join(certDir, companionTokenFile)

	if raw, err := os.ReadFile(tokenPath); err == nil {
		if tok := strings.TrimSpace(string(raw)); isValidCompanionToken(tok) {
			return tok, nil
		}
	}

	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", fmt.Errorf("proxy: create companion token dir %s: %w", certDir, err)
	}

	var buf [companionTokenRandomBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("proxy: generate companion token: %w", err)
	}
	tok := hex.EncodeToString(buf[:])

	tmpFile, err := os.CreateTemp(certDir, ".companion.token.*")
	if err != nil {
		return "", fmt.Errorf("proxy: create temp companion token: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("proxy: chmod companion token: %w", err)
	}
	if _, err := tmpFile.WriteString(tok + "\n"); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("proxy: write companion token: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("proxy: sync companion token: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("proxy: close companion token: %w", err)
	}
	if err := os.Rename(tmpPath, tokenPath); err != nil {
		return "", fmt.Errorf("proxy: install companion token: %w", err)
	}
	cleanupTmp = false
	return tok, nil
}

func isValidCompanionToken(tok string) bool {
	if len(tok) < companionMinTokenHexChars {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func clampCompanionBufferSize(size int) int {
	if size <= 0 {
		return defaultCompanionBufferSize
	}
	if size < minCompanionBufferSize {
		return minCompanionBufferSize
	}
	if size > maxCompanionBufferSize {
		return maxCompanionBufferSize
	}
	return size
}

func newCompanionFeed(proxyAddr string, maxSize int) *companionFeed {
	capSize := clampCompanionBufferSize(maxSize)
	return &companionFeed{
		proxyAddr: proxyAddr,
		startTime: time.Now(),
		maxSize:   capSize,
		ring:      make([]*CompanionFlowDetail, capSize),
		byID:      make(map[string]*CompanionFlowDetail, capSize),
	}
}

func (f *companionFeed) recordFlow(flow *types.Flow, req *http.Request, resp *http.Response) {
	if f == nil || flow == nil {
		return
	}

	reqHeaders := map[string]string{}
	if req != nil {
		reqHeaders = flattenCompanionHeaders(req.Header)
	} else if flow.ReqHeaders != nil {
		reqHeaders = copyStringMap(flow.ReqHeaders)
	}

	respHeaders := map[string]string{}
	status := flow.Status
	contentType := flow.RespBodyType
	var respContentLen int64 = -1
	if resp != nil {
		status = resp.StatusCode
		respHeaders = flattenCompanionHeaders(resp.Header)
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			contentType = ct
		}
		respContentLen = resp.ContentLength
	} else if flow.RespHeaders != nil {
		respHeaders = copyStringMap(flow.RespHeaders)
	}

	reqContentType := flow.ReqBodyType
	var reqContentLen int64 = -1
	if req != nil {
		if ct := req.Header.Get("Content-Type"); ct != "" {
			reqContentType = ct
		}
		reqContentLen = req.ContentLength
	}

	reqBytes := int64(len(flow.ReqBody))
	if reqContentLen > reqBytes {
		reqBytes = reqContentLen
	}
	respBytes := int64(len(flow.RespBody))
	if respContentLen > respBytes {
		respBytes = respContentLen
	}

	reqPreview, reqTrunc, reqBin := formatCompanionBodyPreview(flow.ReqBody, reqContentType, reqBytes)
	respPreview, respTrunc, respBin := formatCompanionBodyPreview(flow.RespBody, contentType, respBytes)

	scheme := resolveFlowScheme(req, flow.URL)
	host := resolveFlowHost(req, flow.Host)
	path := resolveFlowPath(req, flow.Path)
	rawURL := resolveFlowURL(req, flow.URL, scheme, host, path)
	method := strings.ToUpper(flow.Method)
	if method == "" && req != nil {
		method = strings.ToUpper(req.Method)
	}
	latency := flow.LatencyMs
	if latency < 0 {
		latency = 0
	}
	tsMs := flow.Timestamp.UnixMilli()
	if flow.Timestamp.IsZero() {
		tsMs = time.Now().UnixMilli()
	}

	rec := &CompanionFlowDetail{
		CompanionFlowSummary: CompanionFlowSummary{
			ID:          flow.ID,
			Method:      method,
			Scheme:      scheme,
			Host:        host,
			Path:        path,
			URL:         rawURL,
			Status:      status,
			ContentType: contentType,
			ReqBytes:    reqBytes,
			RespBytes:   respBytes,
			LatencyMs:   latency,
			TimestampMs: tsMs,
			Error:       "",
		},
		ReqHeaders:        reqHeaders,
		RespHeaders:       respHeaders,
		ReqBody:           reqPreview,
		RespBody:          respPreview,
		ReqBodyTruncated:  reqTrunc,
		RespBodyTruncated: respTrunc,
		ReqBodyBinary:     reqBin,
		RespBodyBinary:    respBin,
	}

	f.appendRecord(rec)
}

func (f *companionFeed) recordError(id string, req *http.Request, start time.Time, reqBody []byte, errMsg string) {
	if f == nil || req == nil {
		return
	}
	reqBytes := int64(len(reqBody))
	if req.ContentLength > reqBytes {
		reqBytes = req.ContentLength
	}
	reqPreview, reqTrunc, reqBin := formatCompanionBodyPreview(reqBody, req.Header.Get("Content-Type"), reqBytes)
	scheme := resolveFlowScheme(req, "")
	host := resolveFlowHost(req, "")
	path := resolveFlowPath(req, "")
	rawURL := resolveFlowURL(req, "", scheme, host, path)
	latency := time.Since(start).Milliseconds()
	if latency < 0 {
		latency = 0
	}

	rec := &CompanionFlowDetail{
		CompanionFlowSummary: CompanionFlowSummary{
			ID:          id,
			Method:      strings.ToUpper(req.Method),
			Scheme:      scheme,
			Host:        host,
			Path:        path,
			URL:         rawURL,
			Status:      0,
			ContentType: "",
			ReqBytes:    reqBytes,
			RespBytes:   0,
			LatencyMs:   latency,
			TimestampMs: start.UnixMilli(),
			Error:       errMsg,
		},
		ReqHeaders:        flattenCompanionHeaders(req.Header),
		RespHeaders:       map[string]string{},
		ReqBody:           reqPreview,
		RespBody:          "",
		ReqBodyTruncated:  reqTrunc,
		RespBodyTruncated: false,
		ReqBodyBinary:     reqBin,
		RespBodyBinary:    false,
	}

	f.appendRecord(rec)
}

func (f *companionFeed) appendRecord(rec *CompanionFlowDetail) {
	now := time.Now()
	slot := now.UnixMilli() / companionRPSBucketMs

	f.mu.Lock()
	defer f.mu.Unlock()

	f.latestSeq++
	rec.Seq = f.latestSeq
	f.totalFlows++
	f.totalBytes += rec.ReqBytes + rec.RespBytes

	idx := int(slot % companionRPSBuckets)
	if idx < 0 {
		idx += companionRPSBuckets
	}
	if f.rpsBuckets[idx].slot != slot {
		f.rpsBuckets[idx] = rpsBucket{slot: slot, count: 1}
	} else {
		f.rpsBuckets[idx].count++
	}

	if f.count < f.maxSize {
		pos := (f.head + f.count) % f.maxSize
		f.ring[pos] = rec
		f.count++
	} else {
		if evicted := f.ring[f.head]; evicted != nil {
			delete(f.byID, evicted.ID)
		}
		f.ring[f.head] = rec
		f.head = (f.head + 1) % f.maxSize
	}
	f.byID[rec.ID] = rec
}

func (f *companionFeed) reqPerSecLocked(now time.Time) float64 {
	curSlot := now.UnixMilli() / companionRPSBucketMs
	minSlot := curSlot - companionRPSBuckets
	sum := 0
	for i := range f.rpsBuckets {
		b := f.rpsBuckets[i]
		if b.slot > minSlot && b.slot <= curSlot {
			sum += b.count
		}
	}
	if sum == 0 {
		return 0
	}
	window := now.Sub(f.startTime).Seconds()
	if window < 1.0 {
		window = 1.0
	}
	if window > float64(companionRPSWindowSec) {
		window = float64(companionRPSWindowSec)
	}
	return math.Round((float64(sum)/window)*100) / 100
}

func (f *companionFeed) stats() companionStatsResponse {
	now := time.Now()
	f.mu.RLock()
	defer f.mu.RUnlock()

	uptime := int64(now.Sub(f.startTime).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	return companionStatsResponse{
		OK:            true,
		ProxyAddr:     f.proxyAddr,
		TotalFlows:    f.totalFlows,
		BufferedFlows: f.count,
		LatestSeq:     f.latestSeq,
		TotalBytes:    f.totalBytes,
		ReqPerSec:     f.reqPerSecLocked(now),
		UptimeSec:     uptime,
	}
}

func (f *companionFeed) list(q companionFlowQuery) companionFlowsResponse {
	now := time.Now()
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]CompanionFlowSummary, 0, min(q.Limit, f.count))
	for i := f.count - 1; i >= 0 && len(out) < q.Limit; i-- {
		rec := f.ring[(f.head+i)%f.maxSize]
		if rec == nil {
			continue
		}
		if q.After > 0 && rec.Seq <= q.After {
			// Ring is strictly ordered by increasing seq, so once seq <= after
			// no older entry can match.
			break
		}
		if !matchesCompanionQuery(rec, q) {
			continue
		}
		out = append(out, rec.CompanionFlowSummary)
	}

	return companionFlowsResponse{
		OK:            true,
		LatestSeq:     f.latestSeq,
		TotalFlows:    f.totalFlows,
		BufferedFlows: f.count,
		TotalBytes:    f.totalBytes,
		ReqPerSec:     f.reqPerSecLocked(now),
		Flows:         out,
	}
}

func (f *companionFeed) get(id string) (CompanionFlowDetail, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	rec, ok := f.byID[id]
	if !ok || rec == nil {
		return CompanionFlowDetail{}, false
	}
	cp := *rec
	cp.ReqHeaders = copyStringMap(rec.ReqHeaders)
	cp.RespHeaders = copyStringMap(rec.RespHeaders)
	return cp, true
}

func (f *companionFeed) clear() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i := range f.ring {
		f.ring[i] = nil
	}
	f.head = 0
	f.count = 0
	clear(f.byID)
	return f.latestSeq
}

func matchesCompanionQuery(rec *CompanionFlowDetail, q companionFlowQuery) bool {
	if q.Method != "" && rec.Method != q.Method {
		return false
	}
	if q.Scheme != "" && rec.Scheme != q.Scheme {
		return false
	}
	if q.StatusGroup != "" && !matchesStatusGroup(rec.Status, rec.Error, q.StatusGroup) {
		return false
	}
	if q.Search != "" {
		if !strings.Contains(strings.ToLower(rec.Host), q.Search) &&
			!strings.Contains(strings.ToLower(rec.Path), q.Search) &&
			!strings.Contains(strings.ToLower(rec.URL), q.Search) &&
			!strings.Contains(strings.ToLower(rec.Method), q.Search) &&
			!strings.Contains(strings.ToLower(rec.ContentType), q.Search) {
			return false
		}
	}
	return true
}

func matchesStatusGroup(status int, errMsg, group string) bool {
	switch group {
	case "2xx":
		return status >= 200 && status < 300
	case "3xx":
		return status >= 300 && status < 400
	case "4xx":
		return status >= 400 && status < 500
	case "5xx":
		return status >= 500 && status < 600
	case "err", "error", "4xx/5xx", "4xx,5xx":
		return status >= 400 || status == 0 || errMsg != ""
	default:
		return false
	}
}

func isCompanionAPIRequest(r *http.Request) bool {
	return r != nil &&
		r.Method != http.MethodConnect &&
		r.URL != nil &&
		r.URL.Host == "" &&
		strings.HasPrefix(r.URL.Path, companionAPIPrefix)
}

func (p *Proxy) authorizeCompanionRequest(r *http.Request) bool {
	if p.companionToken == "" {
		return false
	}
	got := r.Header.Get(companionTokenHeader)
	if len(got) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(p.companionToken)) == 1
}

func (p *Proxy) serveCompanionAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if !p.authorizeCompanionRequest(r) {
		writeCompanionJSON(w, http.StatusUnauthorized, companionErrorResponse{Error: "unauthorized"})
		return
	}

	if p.companion == nil {
		writeCompanionJSON(w, http.StatusNotFound, companionErrorResponse{Error: "not found"})
		return
	}

	subpath := strings.TrimPrefix(r.URL.Path, companionAPIPrefix)
	switch {
	case subpath == "stats":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeCompanionJSON(w, http.StatusMethodNotAllowed, companionErrorResponse{Error: "method not allowed"})
			return
		}
		writeCompanionJSON(w, http.StatusOK, p.companion.stats())

	case subpath == "flows":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeCompanionJSON(w, http.StatusMethodNotAllowed, companionErrorResponse{Error: "method not allowed"})
			return
		}
		q := parseCompanionFlowQuery(r)
		writeCompanionJSON(w, http.StatusOK, p.companion.list(q))

	case strings.HasPrefix(subpath, "flows/"):
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeCompanionJSON(w, http.StatusMethodNotAllowed, companionErrorResponse{Error: "method not allowed"})
			return
		}
		id := strings.TrimPrefix(subpath, "flows/")
		if id == "" || strings.Contains(id, "/") {
			writeCompanionJSON(w, http.StatusNotFound, companionErrorResponse{Error: "flow not found"})
			return
		}
		detail, ok := p.companion.get(id)
		if !ok {
			writeCompanionJSON(w, http.StatusNotFound, companionErrorResponse{Error: "flow not found"})
			return
		}
		writeCompanionJSON(w, http.StatusOK, companionFlowDetailResponse{
			OK:   true,
			Flow: detail,
		})

	case subpath == "clear":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeCompanionJSON(w, http.StatusMethodNotAllowed, companionErrorResponse{Error: "method not allowed"})
			return
		}
		latestSeq := p.companion.clear()
		writeCompanionJSON(w, http.StatusOK, companionClearResponse{
			OK:        true,
			LatestSeq: latestSeq,
		})

	default:
		writeCompanionJSON(w, http.StatusNotFound, companionErrorResponse{Error: "not found"})
	}
}

func parseCompanionFlowQuery(r *http.Request) companionFlowQuery {
	vals := r.URL.Query()
	limit := defaultCompanionFlowsLimit
	if raw := strings.TrimSpace(vals.Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	if limit < minCompanionFlowsLimit {
		limit = minCompanionFlowsLimit
	}
	if limit > maxCompanionFlowsLimit {
		limit = maxCompanionFlowsLimit
	}

	var after int64
	if raw := strings.TrimSpace(vals.Get("after")); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			after = n
		}
	}

	return companionFlowQuery{
		Limit:       limit,
		After:       after,
		Method:      strings.ToUpper(strings.TrimSpace(vals.Get("method"))),
		Search:      strings.ToLower(strings.TrimSpace(vals.Get("search"))),
		StatusGroup: strings.ToLower(strings.TrimSpace(vals.Get("status_group"))),
		Scheme:      strings.ToLower(strings.TrimSpace(vals.Get("scheme"))),
	}
}

func writeCompanionJSON(w http.ResponseWriter, status int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal marshal error"}`))
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func flattenCompanionHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vals := range h {
		m[k] = strings.Join(vals, ", ")
	}
	return m
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func formatCompanionBodyPreview(body []byte, contentType string, totalBytes int64) (preview string, truncated bool, binary bool) {
	if len(body) == 0 {
		return "", totalBytes > 0, false
	}

	truncated = len(body) > companionMaxPreviewBytes || totalBytes > int64(len(body))
	sample := body
	if len(sample) > companionMaxPreviewBytes {
		sample = sample[:companionMaxPreviewBytes]
	}

	if isLikelyBinaryContentType(contentType) {
		return formatBinaryPreview(body, contentType, totalBytes)
	}

	candidate := sample
	if len(body) > companionMaxPreviewBytes {
		candidate = trimIncompleteUTF8Tail(sample)
	}
	if !utf8.Valid(candidate) || hasBinaryControlBytes(candidate) {
		return formatBinaryPreview(body, contentType, totalBytes)
	}

	return string(candidate), truncated, false
}

func formatBinaryPreview(body []byte, contentType string, totalBytes int64) (string, bool, bool) {
	actualTotal := int64(len(body))
	if totalBytes > actualTotal {
		actualTotal = totalBytes
	}
	shown := body
	truncated := actualTotal > int64(len(body))
	if len(shown) > companionBinaryHexPreviewBytes {
		shown = shown[:companionBinaryHexPreviewBytes]
		truncated = true
	}

	ct := strings.TrimSpace(contentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[binary body: %d bytes, content-type: %s]\n", actualTotal, ct)
	b.WriteString(hex.Dump(shown))
	if truncated {
		fmt.Fprintf(&b, "... (truncated, showing first %d of %d bytes)", len(shown), actualTotal)
	}
	return b.String(), truncated, true
}

func isLikelyBinaryContentType(contentType string) bool {
	if strings.TrimSpace(contentType) == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	} else {
		mediaType = strings.ToLower(mediaType)
	}
	for _, prefix := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(mediaType, prefix) {
			return true
		}
	}
	switch mediaType {
	case "application/octet-stream",
		"application/pdf",
		"application/zip",
		"application/gzip",
		"application/x-gzip",
		"application/x-bzip2",
		"application/x-xz",
		"application/zstd",
		"application/protobuf",
		"application/x-protobuf",
		"application/grpc",
		"application/wasm",
		"application/vnd.android.package-archive":
		return true
	}
	return false
}

func trimIncompleteUTF8Tail(b []byte) []byte {
	if len(b) == 0 || utf8.Valid(b) {
		return b
	}
	for cut := 1; cut <= 3 && cut <= len(b); cut++ {
		if utf8.Valid(b[:len(b)-cut]) {
			return b[:len(b)-cut]
		}
	}
	return b
}

func hasBinaryControlBytes(b []byte) bool {
	checkLen := len(b)
	if checkLen > 512 {
		checkLen = 512
	}
	if checkLen == 0 {
		return false
	}
	ctrl := 0
	for i := 0; i < checkLen; i++ {
		c := b[i]
		if c == 0 {
			return true
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			ctrl++
		}
	}
	return ctrl*10 > checkLen
}

func resolveFlowScheme(req *http.Request, fallbackURL string) string {
	if req != nil && req.URL != nil && req.URL.Scheme != "" {
		return strings.ToLower(req.URL.Scheme)
	}
	if strings.HasPrefix(strings.ToLower(fallbackURL), "https://") {
		return "https"
	}
	if req != nil && req.TLS != nil {
		return "https"
	}
	return "http"
}

func resolveFlowHost(req *http.Request, fallbackHost string) string {
	if req != nil && req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	if req != nil && req.Host != "" {
		return req.Host
	}
	return fallbackHost
}

func resolveFlowPath(req *http.Request, fallbackPath string) string {
	if req != nil && req.URL != nil && req.URL.Path != "" {
		return req.URL.Path
	}
	if fallbackPath != "" {
		return fallbackPath
	}
	return "/"
}

func resolveFlowURL(req *http.Request, fallbackURL, scheme, host, path string) string {
	if fallbackURL != "" && strings.Contains(fallbackURL, "://") {
		return fallbackURL
	}
	if req != nil && req.URL != nil {
		s := req.URL.String()
		if strings.Contains(s, "://") {
			return s
		}
		reqURI := req.URL.RequestURI()
		if reqURI == "" {
			reqURI = path
		}
		if host != "" {
			return scheme + "://" + host + reqURI
		}
		return reqURI
	}
	if host != "" {
		return scheme + "://" + host + path
	}
	return path
}
