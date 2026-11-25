package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxResponseBodyBytes = 4 * 1024 * 1024
	maxErrorExcerptBytes = 512
	anthropicAPIVersion  = "2023-06-01"
)

// CompletionResponse is the normalized output from any supported AI provider.
type CompletionResponse struct {
	Content          string
	PromptTokens     int
	CompletionTokens int
}

// Client invokes OpenAI-compatible, Anthropic, Gemini, and Ollama HTTP APIs
// using pure Go net/http with strict URL validation, bounded reads, and secret
// redaction on all returned error messages.
type Client struct {
	httpClient *http.Client
}

// NewClient constructs a hardened pure-Go HTTP client for AI providers.
func NewClient() *Client {
	var transport http.RoundTripper
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = dt.Clone()
	}
	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			// Never follow redirects on POST API calls to avoid leaking
			// Authorization / API key headers across hosts.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("unexpected HTTP redirect from AI provider")
			},
		},
	}
}

// ValidateBaseURL verifies that raw is a valid http:// or https:// base URL
// with a non-empty host and no embedded credentials or fragment.
func ValidateBaseURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("base_url is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (must be http or https)", u.Scheme)
	}
	if strings.TrimSpace(u.Host) == "" || strings.TrimSpace(u.Hostname()) == "" {
		return nil, errors.New("base_url must include a host")
	}
	if u.User != nil {
		return nil, errors.New("base_url must not contain embedded user credentials")
	}
	if u.Fragment != "" {
		return nil, errors.New("base_url must not contain a fragment")
	}
	return u, nil
}

// Complete executes one non-streaming chat completion request against profile.
func (c *Client) Complete(ctx context.Context, profile ProviderConfig, systemPrompt, userPrompt string) (*CompletionResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := normalizeProfileDefaults(profile)
	secrets := collectProfileSecrets(p)
	if !IsValidProvider(p.Provider) {
		return nil, fmt.Errorf("unsupported AI provider %q", p.Provider)
	}
	if p.Model == "" {
		return nil, errors.New("AI profile model is required")
	}
	baseURL, err := ValidateBaseURL(p.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid AI profile base_url: %w", err)
	}

	timeout := time.Duration(p.TimeoutSec) * time.Second
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		endpoint string
		payload  []byte
		headers  = make(map[string]string)
	)

	switch p.Provider {
	case ProviderOpenAICompat:
		endpoint = joinEndpoint(baseURL, "/chat/completions")
		body := map[string]any{
			"model": p.Model,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"max_tokens":  p.MaxTokens,
			"temperature": p.Temperature,
		}
		payload, err = json.Marshal(body)
		if p.APIKey != "" {
			headers["Authorization"] = "Bearer " + p.APIKey
		}

	case ProviderAnthropic:
		endpoint = joinAnthropicEndpoint(baseURL)
		body := map[string]any{
			"model":       p.Model,
			"max_tokens":  p.MaxTokens,
			"temperature": p.Temperature,
			"messages": []map[string]string{
				{"role": "user", "content": userPrompt},
			},
		}
		if strings.TrimSpace(systemPrompt) != "" {
			body["system"] = systemPrompt
		}
		payload, err = json.Marshal(body)
		headers["anthropic-version"] = anthropicAPIVersion
		if p.APIKey != "" {
			headers["x-api-key"] = p.APIKey
		}

	case ProviderGemini:
		// Ensure no API key is ever transmitted via query parameters and model
		// cannot inject path traversal or query segments.
		endpoint, err = joinGeminiEndpoint(baseURL, p.Model)
		if err != nil {
			return nil, sanitizeProviderError(err, secrets...)
		}
		body := map[string]any{
			"contents": []map[string]any{
				{
					"role":  "user",
					"parts": []map[string]string{{"text": userPrompt}},
				},
			},
			"generationConfig": map[string]any{
				"maxOutputTokens": p.MaxTokens,
				"temperature":     p.Temperature,
			},
		}
		if strings.TrimSpace(systemPrompt) != "" {
			body["systemInstruction"] = map[string]any{
				"parts": []map[string]string{{"text": systemPrompt}},
			}
		}
		payload, err = json.Marshal(body)
		if p.APIKey != "" {
			headers["x-goog-api-key"] = p.APIKey
		}

	case ProviderOllama:
		endpoint = joinEndpoint(baseURL, "/api/chat")
		body := map[string]any{
			"model":  p.Model,
			"stream": false,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"options": map[string]any{
				"temperature": p.Temperature,
				"num_predict": p.MaxTokens,
			},
		}
		payload, err = json.Marshal(body)
		if p.APIKey != "" {
			headers["Authorization"] = "Bearer " + p.APIKey
		}
	}
	if err != nil {
		return nil, sanitizeProviderError(fmt.Errorf("encode %s request: %w", p.Provider, err), secrets...)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, sanitizeProviderError(fmt.Errorf("build HTTP request: %w", err), secrets...)
	}

	// Apply custom extra headers first (ignoring dangerous/reserved headers),
	// then enforce mandatory protocol headers.
	for k, v := range p.ExtraHeaders {
		kt := strings.TrimSpace(k)
		if kt == "" || strings.ContainsAny(kt, "\r\n") || strings.ContainsAny(v, "\r\n") {
			continue
		}
		low := strings.ToLower(kt)
		if low == "host" || low == "content-length" {
			continue
		}
		req.Header.Set(kt, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, sanitizeProviderError(fmt.Errorf("%s request failed: %w", p.Provider, err), secrets...)
	}
	defer resp.Body.Close()

	respBody, err := readBoundedBody(resp.Body, maxResponseBodyBytes)
	if err != nil {
		return nil, sanitizeProviderError(fmt.Errorf("read %s response: %w", p.Provider, err), secrets...)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := extractAPIErrorMessage(respBody)
		if msg == "" {
			msg = strings.TrimSpace(string(respBody))
		}
		if len(msg) > maxErrorExcerptBytes {
			msg = truncatePrefixUTF8(msg, maxErrorExcerptBytes) + "..."
		}
		return nil, sanitizeProviderError(
			fmt.Errorf("%s HTTP %d: %s", p.Provider, resp.StatusCode, msg),
			secrets...,
		)
	}

	parsed, err := parseProviderResponse(p.Provider, respBody)
	if err != nil {
		return nil, sanitizeProviderError(err, secrets...)
	}
	return parsed, nil
}

// TestConnection performs a minimal prompt round-trip against profile to verify
// reachability, authentication, and model availability.
func (c *Client) TestConnection(ctx context.Context, profile ProviderConfig) TestConnectionResult {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	p := normalizeProfileDefaults(profile)
	secrets := collectProfileSecrets(p)
	if p.TimeoutSec > 30 {
		p.TimeoutSec = 30
	}
	p.MaxTokens = 32
	p.Temperature = 0

	res := TestConnectionResult{
		Provider: p.Provider,
		Model:    p.Model,
	}
	out, err := c.Complete(ctx, p, "You are a connectivity probe.", "Reply with exactly: OK")
	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.OK = false
		res.Error = sanitizeProviderError(err, secrets...).Error()
		return res
	}
	res.OK = true
	reply := strings.TrimSpace(out.Content)
	if len(reply) > 120 {
		reply = truncatePrefixUTF8(reply, 120) + "..."
	}
	res.Reply = reply
	return res
}

func joinEndpoint(base *url.URL, suffix string) string {
	cp := *base
	basePath := strings.TrimRight(cp.Path, "/")
	if strings.HasSuffix(basePath, suffix) {
		cp.Path = basePath
	} else {
		cp.Path = basePath + suffix
	}
	return cp.String()
}

func joinAnthropicEndpoint(base *url.URL) string {
	cp := *base
	basePath := strings.TrimRight(cp.Path, "/")
	switch {
	case strings.HasSuffix(basePath, "/v1/messages"):
		cp.Path = basePath
	case strings.HasSuffix(basePath, "/v1"):
		cp.Path = basePath + "/messages"
	default:
		cp.Path = basePath + "/v1/messages"
	}
	return cp.String()
}

func joinGeminiEndpoint(base *url.URL, model string) (string, error) {
	cleanModel := strings.TrimPrefix(strings.TrimSpace(model), "models/")
	if cleanModel == "" || strings.ContainsAny(cleanModel, "/\\?#\r\n") || strings.Contains(cleanModel, "..") {
		return "", fmt.Errorf("invalid Gemini model name %q", model)
	}
	cp := *base
	cp.RawQuery = ""
	cp.Fragment = ""
	basePath := strings.TrimRight(cp.Path, "/")
	suffix := "/models/" + cleanModel + ":generateContent"
	if strings.HasSuffix(basePath, "/v1beta") {
		cp.Path = basePath + suffix
	} else {
		cp.Path = basePath + "/v1beta" + suffix
	}
	return cp.String(), nil
}

func readBoundedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response body exceeded %d bytes limit", maxBytes)
	}
	return data, nil
}

func collectProfileSecrets(p ProviderConfig) []string {
	var secrets []string
	if k := strings.TrimSpace(p.APIKey); k != "" {
		secrets = append(secrets, k)
	}
	secrets = append(secrets, sensitiveExtraHeaderValues(p.ExtraHeaders)...)
	return secrets
}

func sanitizeProviderError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return errors.New(RedactLiteralSecrets(err.Error(), secrets...))
}

func extractAPIErrorMessage(body []byte) string {
	var envelope struct {
		Error any `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error == nil {
		return ""
	}
	switch typed := envelope.Error.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		if msg, ok := typed["message"].(string); ok && strings.TrimSpace(msg) != "" {
			return strings.TrimSpace(msg)
		}
	}
	return ""
}

func parseProviderResponse(provider string, body []byte) (*CompletionResponse, error) {
	switch provider {
	case ProviderOpenAICompat:
		var resp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode openai_compat response: %w", err)
		}
		if len(resp.Choices) == 0 {
			return nil, errors.New("openai_compat response contained no choices")
		}
		if strings.TrimSpace(resp.Choices[0].Message.Content) == "" {
			return nil, errors.New("openai_compat response contained empty message content")
		}
		return &CompletionResponse{
			Content:          resp.Choices[0].Message.Content,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
		}, nil

	case ProviderAnthropic:
		var resp struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode anthropic response: %w", err)
		}
		var b strings.Builder
		for _, blk := range resp.Content {
			if blk.Type == "text" || blk.Type == "" {
				b.WriteString(blk.Text)
			}
		}
		if strings.TrimSpace(b.String()) == "" {
			return nil, errors.New("anthropic response contained no text content")
		}
		return &CompletionResponse{
			Content:          b.String(),
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
		}, nil

	case ProviderGemini:
		var resp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode gemini response: %w", err)
		}
		if len(resp.Candidates) == 0 {
			return nil, errors.New("gemini response contained no candidates")
		}
		var b strings.Builder
		for _, part := range resp.Candidates[0].Content.Parts {
			b.WriteString(part.Text)
		}
		if strings.TrimSpace(b.String()) == "" {
			return nil, errors.New("gemini response contained empty candidate text")
		}
		return &CompletionResponse{
			Content:          b.String(),
			PromptTokens:     resp.UsageMetadata.PromptTokenCount,
			CompletionTokens: resp.UsageMetadata.CandidatesTokenCount,
		}, nil

	case ProviderOllama:
		var resp struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			PromptEvalCount int `json:"prompt_eval_count"`
			EvalCount       int `json:"eval_count"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("decode ollama response: %w", err)
		}
		if strings.TrimSpace(resp.Message.Content) == "" {
			return nil, errors.New("ollama response contained empty message content")
		}
		return &CompletionResponse{
			Content:          resp.Message.Content,
			PromptTokens:     resp.PromptEvalCount,
			CompletionTokens: resp.EvalCount,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported AI provider %q", provider)
	}
}
