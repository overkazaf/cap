package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	minSignerTimeoutSec = 1
	maxSignerTimeoutSec = 60
	maxSignerOutputSize = 256 * 1024
)

// limitedBuffer caps captured stdout/stderr bytes from external signer processes.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	if l.limit <= 0 {
		return origLen, nil
	}
	rem := l.limit - l.buf.Len()
	if rem <= 0 {
		l.truncated = true
		return origLen, nil
	}
	if len(p) > rem {
		l.buf.Write(p[:rem])
		l.truncated = true
		return origLen, nil
	}
	l.buf.Write(p)
	return origLen, nil
}

func (l *limitedBuffer) String() string {
	return l.buf.String()
}

func clampSignerTimeout(sec int) time.Duration {
	if sec <= 0 {
		return time.Duration(DefaultSignerTimeoutSec) * time.Second
	}
	if sec < minSignerTimeoutSec {
		sec = minSignerTimeoutSec
	}
	if sec > maxSignerTimeoutSec {
		sec = maxSignerTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

// ValidateSigner validates required configuration fields for a SignerProvider.
func ValidateSigner(p *SignerProvider) error {
	if p == nil {
		return errors.New("signer provider is nil")
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("signer name is required")
	}
	switch strings.ToLower(strings.TrimSpace(p.Kind)) {
	case SignerKindBuiltinHMAC:
		algo := strings.ToLower(strings.TrimSpace(p.HMACAlgorithm))
		switch algo {
		case "", "md5", "sha1", "sha256", "sha512", "hmac-md5", "hmac-sha1", "hmac-sha256", "hmac-sha512":
			return nil
		default:
			return fmt.Errorf("unsupported hmac_algorithm %q", p.HMACAlgorithm)
		}
	case SignerKindScript:
		if strings.TrimSpace(p.ScriptCode) == "" {
			return errors.New("script_code is required for script signer")
		}
		if _, _, err := signerRuntimeSpec(p.Runtime); err != nil {
			return err
		}
		return nil
	case SignerKindHTTP, SignerKindUnidbgHTTP:
		raw := strings.TrimSpace(p.EndpointURL)
		poolID := strings.TrimSpace(p.WorkerPoolID)
		if raw == "" && poolID == "" {
			return fmt.Errorf("endpoint_url or worker_pool_id is required for %s signer", p.Kind)
		}
		if raw != "" {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("invalid endpoint_url %q", raw)
			}
		}
		return nil
	case SignerKindFridaRPC:
		if strings.TrimSpace(p.FridaPackage) == "" {
			return errors.New("frida_package is required for frida_rpc signer")
		}
		if strings.TrimSpace(p.FridaExport) == "" {
			return errors.New("frida_export is required for frida_rpc signer")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signer kind %q", p.Kind)
	}
}

// SignerExecutor runs SignerProviders with optional Managed WorkerPool routing
// for HTTP / Unidbg HTTP signers.
type SignerExecutor struct {
	Workers *WorkerPool
}

// NewSignerExecutor constructs a SignerExecutor optionally backed by a WorkerPool.
func NewSignerExecutor(workers *WorkerPool) *SignerExecutor {
	return &SignerExecutor{Workers: workers}
}

// Execute runs a configured SignerProvider against input, dynamically routing
// HTTP/Unidbg HTTP signers across healthy instances when WorkerPoolID is set.
func (e *SignerExecutor) Execute(ctx context.Context, p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	if p == nil {
		return nil, errors.New("signer provider is nil")
	}
	if !p.Enabled {
		return nil, fmt.Errorf("signer %q is disabled", p.Name)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if input.Query == nil {
		input.Query = map[string]string{}
	}
	if input.Headers == nil {
		input.Headers = map[string]string{}
	}
	if input.Timestamp == 0 {
		input.Timestamp = time.Now().Unix()
	}
	if input.Nonce == "" {
		input.Nonce = randomHex(8)
	}

	start := time.Now()
	var (
		out *SignerOutput
		err error
	)

	switch strings.ToLower(strings.TrimSpace(p.Kind)) {
	case SignerKindBuiltinHMAC:
		out, err = runBuiltinHMAC(p, input)
	case SignerKindScript:
		out, err = runScriptSigner(ctx, p, input)
	case SignerKindHTTP, SignerKindUnidbgHTTP:
		endpoint := strings.TrimSpace(p.EndpointURL)
		var release func()
		if poolID := strings.TrimSpace(p.WorkerPoolID); poolID != "" {
			if e == nil || e.Workers == nil {
				return nil, fmt.Errorf("worker pool %q unavailable for signer %q", poolID, p.Name)
			}
			ep, rel, epErr := e.Workers.AcquireHealthyEndpoint(poolID)
			if epErr != nil {
				return nil, fmt.Errorf("resolve worker pool %q for signer %q: %w", poolID, p.Name, epErr)
			}
			endpoint = ep
			release = rel
		}
		if release != nil {
			defer release()
		}
		out, err = runHTTPSignerEndpoint(ctx, p, endpoint, input)
	case SignerKindFridaRPC:
		out, err = runFridaRPCSigner(ctx, p, input)
	default:
		return nil, fmt.Errorf("unsupported signer kind %q", p.Kind)
	}
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = &SignerOutput{}
	}
	out.LatencyMs = time.Since(start).Milliseconds()
	return out, nil
}

// ExecuteSigner runs a configured SignerProvider against input and returns the
// computed SignerOutput (plus measured latency).
func ExecuteSigner(ctx context.Context, p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	return (&SignerExecutor{}).Execute(ctx, p, input)
}

// runBuiltinHMAC computes a deterministic MD5 / SHA1 / SHA256 / HMAC-SHA256
// digest over sorted query + body parameters combined with HMACSecret.
func runBuiltinHMAC(p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	params := make(map[string]string, len(input.Query))
	for k, v := range input.Query {
		params[k] = v
	}

	bodyTrim := strings.TrimSpace(input.Body)
	if bodyTrim != "" {
		if strings.HasPrefix(bodyTrim, "{") {
			var bodyObj map[string]any
			if json.Unmarshal([]byte(bodyTrim), &bodyObj) == nil {
				for k, v := range bodyObj {
					params[k] = stringifyScalar(v)
				}
			} else {
				params["_body"] = bodyTrim
			}
		} else if parsed, err := url.ParseQuery(bodyTrim); err == nil && strings.Contains(bodyTrim, "=") {
			for k, vals := range parsed {
				if len(vals) > 0 {
					params[k] = vals[0]
				}
			}
		} else {
			params["_body"] = bodyTrim
		}
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(params[k])
	}
	canonical := sb.String()
	secret := p.HMACSecret

	algo := strings.ToLower(strings.TrimSpace(p.HMACAlgorithm))
	if algo == "" {
		algo = "hmac-sha256"
	}

	var digest string
	switch algo {
	case "md5":
		sum := md5.Sum([]byte(canonical + secret))
		digest = hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum([]byte(canonical + secret))
		digest = hex.EncodeToString(sum[:])
	case "sha256":
		sum := sha256.Sum256([]byte(canonical + secret))
		digest = hex.EncodeToString(sum[:])
	case "sha512":
		sum := sha512.Sum512([]byte(canonical + secret))
		digest = hex.EncodeToString(sum[:])
	case "hmac-md5":
		digest = computeHMAC(md5.New, []byte(secret), []byte(canonical))
	case "hmac-sha1":
		digest = computeHMAC(sha1.New, []byte(secret), []byte(canonical))
	case "hmac-sha256":
		digest = computeHMAC(sha256.New, []byte(secret), []byte(canonical))
	case "hmac-sha512":
		digest = computeHMAC(sha512.New, []byte(secret), []byte(canonical))
	default:
		return nil, fmt.Errorf("unsupported hmac algorithm %q", p.HMACAlgorithm)
	}

	return &SignerOutput{
		Sign: digest,
		Raw: map[string]any{
			"sign":      digest,
			"algorithm": algo,
			"canonical": canonical,
		},
	}, nil
}

func computeHMAC(newHash func() hash.Hash, key, data []byte) string {
	mac := hmac.New(newHash, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func signerRuntimeSpec(rt string) (interp string, ext string, err error) {
	switch strings.ToLower(strings.TrimSpace(rt)) {
	case "", "python3", "python":
		return "python3", ".py", nil
	case "node", "nodejs", "js", "javascript":
		return "node", ".js", nil
	case "sh", "bash", "shell":
		return "sh", ".sh", nil
	default:
		return "", "", fmt.Errorf("unsupported signer script runtime %q", rt)
	}
}

// runScriptSigner runs an external script (python3/node/sh) passing JSON
// SignerInput on stdin and parsing JSON `{sign, params, headers, body_fields}`
// (or plain text signature fallback) from stdout.
func runScriptSigner(ctx context.Context, p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	interp, ext, err := signerRuntimeSpec(p.Runtime)
	if err != nil {
		return nil, err
	}
	interpPath, err := exec.LookPath(interp)
	if err != nil {
		return nil, fmt.Errorf("signer runtime %q not found on PATH: %w", interp, err)
	}

	tmpFile, err := os.CreateTemp("", "cap-gw-signer-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp signer script: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("chmod temp signer script: %w", err)
	}
	if _, err := tmpFile.WriteString(p.ScriptCode); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp signer script: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("close temp signer script: %w", err)
	}

	return execSubprocessSigner(ctx, interpPath, []string{tmpPath}, p.TimeoutSec, input)
}

func execSubprocessSigner(ctx context.Context, binPath string, args []string, timeoutSec int, input SignerInput) (*SignerOutput, error) {
	stdinBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal signer input: %w", err)
	}

	timeout := clampSignerTimeout(timeoutSec)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binPath, args...)
	configureProcGroup(cmd)
	cmd.Stdin = bytes.NewReader(stdinBytes)

	stdout := &limitedBuffer{limit: maxSignerOutputSize}
	stderr := &limitedBuffer{limit: maxSignerOutputSize}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	outStr := strings.TrimSpace(stdout.String())
	errStr := strings.TrimSpace(stderr.String())

	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			msg := fmt.Sprintf("signer script timed out after %s", timeout)
			if errStr != "" {
				msg += ": " + errStr
			}
			return nil, errors.New(msg)
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("signer script cancelled: %w", ctx.Err())
		}
		if errStr != "" {
			return nil, fmt.Errorf("signer script failed: %s (%w)", errStr, runErr)
		}
		return nil, fmt.Errorf("signer script failed: %w", runErr)
	}

	return parseSignerResponseBytes([]byte(outStr))
}

// runHTTPSigner invokes an HTTP or Unidbg HTTP signing microservice with the
// normalized SignerInput payload and decodes the returned signature fields.
func runHTTPSigner(ctx context.Context, p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	return runHTTPSignerEndpoint(ctx, p, p.EndpointURL, input)
}

func runHTTPSignerEndpoint(ctx context.Context, p *SignerProvider, rawEndpoint string, input SignerInput) (*SignerOutput, error) {
	endpoint := strings.TrimSpace(rawEndpoint)
	if endpoint == "" {
		return nil, errors.New("signer endpoint_url is required")
	}
	method := strings.ToUpper(strings.TrimSpace(p.HTTPMethod))
	if method == "" {
		method = http.MethodPost
	}

	timeout := clampSignerTimeout(p.TimeoutSec)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		reqBody io.Reader
		reqURL  = endpoint
	)
	if method == http.MethodGet || method == http.MethodHead {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid signer endpoint URL: %w", err)
		}
		q := u.Query()
		q.Set("method", input.Method)
		q.Set("url", input.URL)
		q.Set("path", input.Path)
		q.Set("timestamp", strconv.FormatInt(input.Timestamp, 10))
		q.Set("nonce", input.Nonce)
		for k, v := range input.Query {
			if q.Get(k) == "" {
				q.Set(k, v)
			}
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	} else {
		payload, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("marshal signer payload: %w", err)
		}
		reqBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(runCtx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("build signer request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range p.Headers {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call http signer %s: %s", redactURLString(endpoint), redactSecrets(err.Error()))
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSignerOutputSize))
	if err != nil {
		return nil, fmt.Errorf("read http signer response: %s", redactSecrets(err.Error()))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http signer returned status %d: %s", resp.StatusCode, redactSecrets(strings.TrimSpace(string(bodyBytes))))
	}

	return parseSignerResponseBytes(bodyBytes)
}

// runFridaRPCSigner invokes a Frida RPC export (`script.exports_sync.<export>`)
// via a compact Python runner.
func runFridaRPCSigner(ctx context.Context, p *SignerProvider, input SignerInput) (*SignerOutput, error) {
	if strings.TrimSpace(p.FridaPackage) == "" || strings.TrimSpace(p.FridaExport) == "" {
		return nil, errors.New("frida_rpc signer requires frida_package and frida_export")
	}
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		return nil, fmt.Errorf("python3 not found on PATH for frida_rpc signer: %w", err)
	}

	pyCode := buildFridaRPCDriverScript(p)
	tmpFile, err := os.CreateTemp("", "cap-gw-frida-rpc-*.py")
	if err != nil {
		return nil, fmt.Errorf("create temp frida rpc script: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		return nil, err
	}
	if _, err := tmpFile.WriteString(pyCode); err != nil {
		tmpFile.Close()
		return nil, err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, err
	}

	return execSubprocessSigner(ctx, pythonPath, []string{tmpPath}, p.TimeoutSec, input)
}

func buildFridaRPCDriverScript(p *SignerProvider) string {
	jsCode := strings.TrimSpace(p.ScriptCode)
	if jsCode == "" {
		jsCode = fmt.Sprintf("rpc.exports = { %s: function(payload) { throw new Error(%s); } };",
			jsonStringLiteral(p.FridaExport),
			jsonStringLiteral("script_code not configured for export "+p.FridaExport),
		)
	}
	return fmt.Sprintf(`import json, sys
import frida

payload = json.loads(sys.stdin.read() or "{}")
serial = %s
package = %s
export_name = %s
js_code = %s

device = frida.get_device(serial, timeout=5) if serial else frida.get_usb_device(timeout=5)
session = device.attach(package)
script = session.create_script(js_code)
script.load()
try:
    fn = getattr(script.exports_sync, export_name)
    result = fn(payload)
    if isinstance(result, (dict, list)):
        print(json.dumps(result))
    else:
        print(json.dumps({"sign": "" if result is None else str(result)}))
finally:
    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
`,
		jsonStringLiteral(strings.TrimSpace(p.FridaSerial)),
		jsonStringLiteral(strings.TrimSpace(p.FridaPackage)),
		jsonStringLiteral(strings.TrimSpace(p.FridaExport)),
		jsonStringLiteral(jsCode),
	)
}

// parseSignerResponseBytes decodes JSON `{sign, params, headers, body_fields}`
// (including optional Unidbg-style `{"data": {...}}` wrappers) or treats plain
// text output as a raw signature string.
func parseSignerResponseBytes(raw []byte) (*SignerOutput, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("signer returned empty output")
	}

	out := &SignerOutput{
		Params:     map[string]string{},
		Headers:    map[string]string{},
		BodyFields: map[string]any{},
		Raw:        map[string]any{},
	}

	if !strings.HasPrefix(trimmed, "{") {
		out.Sign = trimmed
		out.Raw["sign"] = trimmed
		return out, nil
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		// Fall back to treating raw stdout as signature text.
		out.Sign = trimmed
		out.Raw["sign"] = trimmed
		return out, nil
	}

	// Copy top-level fields into Raw for OutputMapping access.
	for k, v := range obj {
		out.Raw[k] = v
	}

	// Unwrap Unidbg/remote microservice `{"code": 0, "data": {...}}` envelopes if present.
	source := obj
	if inner, ok := obj["data"].(map[string]any); ok {
		for k, v := range inner {
			if _, exists := out.Raw[k]; !exists {
				out.Raw[k] = v
			}
		}
		if _, hasTopSign := obj["sign"]; !hasTopSign {
			if _, hasTopParams := obj["params"]; !hasTopParams {
				if _, hasTopHeaders := obj["headers"]; !hasTopHeaders {
					source = inner
				}
			}
		}
	}

	for _, key := range []string{"sign", "signature", "sig"} {
		if v, ok := source[key]; ok && v != nil {
			if s := stringifyScalar(v); s != "" {
				out.Sign = s
				break
			}
		}
	}

	if pm, ok := source["params"].(map[string]any); ok {
		for k, v := range pm {
			out.Params[k] = stringifyScalar(v)
		}
	}
	if pm, ok := source["query"].(map[string]any); ok {
		for k, v := range pm {
			out.Params[k] = stringifyScalar(v)
		}
	}
	if hm, ok := source["headers"].(map[string]any); ok {
		for k, v := range hm {
			out.Headers[k] = stringifyScalar(v)
		}
	}
	if bm, ok := source["body_fields"].(map[string]any); ok {
		for k, v := range bm {
			out.BodyFields[k] = v
		}
	}
	if bm, ok := source["body"].(map[string]any); ok {
		for k, v := range bm {
			out.BodyFields[k] = v
		}
	}

	if len(out.Params) == 0 {
		out.Params = nil
	}
	if len(out.Headers) == 0 {
		out.Headers = nil
	}
	if len(out.BodyFields) == 0 {
		out.BodyFields = nil
	}
	return out, nil
}

// ApplySignature injects a SignerOutput into the outgoing request URL, headers,
// and/or JSON body according to SignerProvider's InjectTarget, InjectField, and
// OutputMapping rules.
func ApplySignature(p *SignerProvider, out *SignerOutput, targetURL *url.URL, headers map[string]string, body string) (*url.URL, map[string]string, string, error) {
	if targetURL == nil {
		return nil, headers, body, errors.New("target URL is nil")
	}
	if out == nil {
		return targetURL, headers, body, nil
	}

	uCopy := *targetURL
	q := uCopy.Query()
	hdrs := cloneStringMap(headers)
	if hdrs == nil {
		hdrs = make(map[string]string)
	}
	bodyFields := make(map[string]any)

	// 1. Apply explicit Params / Headers / BodyFields returned by signer.
	for k, v := range out.Params {
		q.Set(k, v)
	}
	for k, v := range out.Headers {
		setHeaderFold(hdrs, k, v)
	}
	for k, v := range out.BodyFields {
		bodyFields[k] = v
	}

	defaultTarget := InjectTargetQuery
	defaultField := "sign"
	if p != nil {
		if t := strings.ToLower(strings.TrimSpace(p.InjectTarget)); t != "" {
			defaultTarget = t
		}
		if f := strings.TrimSpace(p.InjectField); f != "" {
			defaultField = f
		} else if defaultTarget == InjectTargetHeader {
			defaultField = "X-Sign"
		}
	}

	// 2. Apply OutputMapping rules (e.g. {"x_gorgon": "header:X-Gorgon", "sig": "query:sign"}).
	mappedSign := false
	if p != nil && len(p.OutputMapping) > 0 {
		for srcKey, destSpec := range p.OutputMapping {
			val, found := lookupSignerRawValue(out, srcKey)
			if !found {
				continue
			}
			if strings.EqualFold(srcKey, "sign") {
				mappedSign = true
			}
			target, field := parseOutputMappingTarget(destSpec, defaultTarget)
			if field == "" {
				continue
			}
			switch target {
			case InjectTargetHeader:
				setHeaderFold(hdrs, field, stringifyScalar(val))
			case InjectTargetBodyJSON:
				bodyFields[field] = val
			default:
				q.Set(field, stringifyScalar(val))
			}
		}
	}

	// 3. Inject primary Sign field unless already explicitly mapped.
	if out.Sign != "" && !mappedSign {
		switch defaultTarget {
		case InjectTargetHeader:
			setHeaderFold(hdrs, defaultField, out.Sign)
		case InjectTargetBodyJSON:
			bodyFields[defaultField] = out.Sign
		default:
			q.Set(defaultField, out.Sign)
		}
	}

	uCopy.RawQuery = q.Encode()

	// 4. Merge any body_json fields into JSON body.
	updatedBody := body
	if len(bodyFields) > 0 {
		bodyMap := make(map[string]any)
		trimmed := strings.TrimSpace(body)
		if trimmed != "" {
			if err := json.Unmarshal([]byte(trimmed), &bodyMap); err != nil {
				return nil, nil, "", fmt.Errorf("inject signature into body_json: existing body is not a JSON object: %w", err)
			}
		}
		for k, v := range bodyFields {
			bodyMap[k] = v
		}
		encoded, err := json.Marshal(bodyMap)
		if err != nil {
			return nil, nil, "", fmt.Errorf("marshal signed JSON body: %w", err)
		}
		updatedBody = string(encoded)
		if lookupMapFold(hdrs, "Content-Type") == "" {
			setHeaderFold(hdrs, "Content-Type", "application/json")
		}
	}

	return &uCopy, hdrs, updatedBody, nil
}

func lookupSignerRawValue(out *SignerOutput, key string) (any, bool) {
	if out == nil {
		return nil, false
	}
	if out.Raw != nil {
		if v, ok := out.Raw[key]; ok {
			return v, true
		}
	}
	if strings.EqualFold(key, "sign") && out.Sign != "" {
		return out.Sign, true
	}
	if out.Params != nil {
		if v, ok := out.Params[key]; ok {
			return v, true
		}
	}
	if out.Headers != nil {
		if v, ok := out.Headers[key]; ok {
			return v, true
		}
	}
	return nil, false
}

func parseOutputMappingTarget(spec, defaultTarget string) (target, field string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return defaultTarget, ""
	}
	if prefix, rest, ok := strings.Cut(spec, ":"); ok {
		switch strings.ToLower(strings.TrimSpace(prefix)) {
		case InjectTargetQuery, "param":
			return InjectTargetQuery, strings.TrimSpace(rest)
		case InjectTargetHeader, "hdr":
			return InjectTargetHeader, strings.TrimSpace(rest)
		case InjectTargetBodyJSON, "body", "json":
			return InjectTargetBodyJSON, strings.TrimSpace(rest)
		}
	}
	return defaultTarget, spec
}

func stringifyScalar(v any) string {
	switch tv := v.(type) {
	case nil:
		return ""
	case string:
		return tv
	case bool:
		return strconv.FormatBool(tv)
	case float64:
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case int:
		return strconv.Itoa(tv)
	case int64:
		return strconv.FormatInt(tv, 10)
	case json.Number:
		return tv.String()
	default:
		b, err := json.Marshal(tv)
		if err != nil {
			return fmt.Sprint(tv)
		}
		return string(b)
	}
}
