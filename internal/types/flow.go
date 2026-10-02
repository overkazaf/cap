package types

import "time"

type Flow struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"ts"`
	Method       string            `json:"method"`
	URL          string            `json:"url"`
	Host         string            `json:"host"`
	Path         string            `json:"path"`
	ReqHeaders   map[string]string `json:"req_headers"`
	ReqBody      []byte            `json:"req_body,omitempty"`
	ReqBodyType  string            `json:"req_body_type,omitempty"`
	Status       int               `json:"status"`
	RespHeaders  map[string]string `json:"resp_headers,omitempty"`
	RespBody     []byte            `json:"resp_body,omitempty"`
	RespBodyType string            `json:"resp_body_type,omitempty"`
	LatencyMs    int64             `json:"latency_ms"`
	Tags         []string          `json:"tags,omitempty"`
	SignParams   []string          `json:"sign_params,omitempty"`
	SourceRef    *SourceRef        `json:"source_ref,omitempty"`
}

type SourceRef struct {
	File      string `json:"file"`
	Class     string `json:"class,omitempty"`
	Method    string `json:"method,omitempty"`
	Line      int    `json:"line,omitempty"`
	SignFunc  string `json:"sign_func,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

type FlowFilter struct {
	Host       string
	Path       string
	Method     string
	StatusFrom int
	StatusTo   int
	Tag        string
	Search     string
	Limit      int
	Offset     int
}
