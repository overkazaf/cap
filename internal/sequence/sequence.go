// Package sequence records a series of captured flows (e.g. login → get
// data → submit) as a replayable Sequence, persists it to disk, and replays
// it end to end with automatic propagation of values — auth tokens, session
// cookies — extracted from one step's response into later steps' requests.
package sequence

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/overkazaf/cap/internal/types"
)

// Sequence is an ordered list of request Steps, plus the variables that
// seed (and, after a replay, reflect) propagation between them.
type Sequence struct {
	Name      string     `json:"name"`
	Steps     []Step     `json:"steps"`
	Variables []Variable `json:"variables"`
	CreatedAt time.Time  `json:"created_at"`
}

// Step is a single request in a Sequence. URL, Headers and Body may contain
// "{{variable_name}}" placeholders that Replay substitutes before sending.
type Step struct {
	FlowID  string            `json:"flow_id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body,omitempty"`
	Extract []Extraction      `json:"extract,omitempty"`
}

// Extraction describes how to pull a value out of a step's response and
// store it as a Variable for use by later steps.
type Extraction struct {
	Name   string `json:"name"`   // variable name, e.g. "token"
	Source string `json:"source"` // "header", "body_json", or "cookie"
	Path   string `json:"path"`   // header name, JSON dot-path (e.g. "data.token"), or cookie name ("" = whole cookie jar)
}

// Variable is a named value propagated between steps during replay, either
// seeded up front (Sequence.Variables) or produced by an Extraction.
type Variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// autoExtractFields lists response JSON field names that FromFlows treats
// as likely auth/session values worth auto-extracting. Checked in this
// order so detection is deterministic when a response matches more than
// one.
var autoExtractFields = []string{"token", "access_token", "session_id"}

// FromFlows builds a Sequence from captured flows, in order, one Step per
// flow. For each flow it also auto-detects likely variable extractions from
// that flow's response: a Set-Cookie response header yields a "cookie"
// extraction, and a JSON response body containing a field named "token",
// "access_token" or "session_id" (at the top level or one level of nesting,
// e.g. {"data":{"token":...}}) yields a "body_json" extraction for that
// field. Nil flows are skipped.
func FromFlows(name string, flows []*types.Flow) *Sequence {
	seq := &Sequence{
		Name:      name,
		Steps:     make([]Step, 0, len(flows)),
		Variables: []Variable{},
		CreatedAt: time.Now(),
	}
	for _, f := range flows {
		if f == nil {
			continue
		}
		seq.Steps = append(seq.Steps, Step{
			FlowID:  f.ID,
			Method:  f.Method,
			URL:     f.URL,
			Headers: copyHeaders(f.ReqHeaders),
			Body:    f.ReqBody,
			Extract: autoExtract(f),
		})
	}
	return seq
}

// autoExtract inspects a single flow's response and returns the
// extractions FromFlows should auto-attach to the corresponding step. See
// FromFlows for the detection rules.
func autoExtract(f *types.Flow) []Extraction {
	var extractions []Extraction

	if _, ok := getHeaderCI(f.RespHeaders, "Set-Cookie"); ok {
		extractions = append(extractions, Extraction{Name: "cookie", Source: "cookie"})
	}

	if len(f.RespBody) > 0 {
		var parsed map[string]interface{}
		if err := json.Unmarshal(f.RespBody, &parsed); err == nil {
			keys := make([]string, 0, len(parsed))
			for k := range parsed {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, field := range autoExtractFields {
				if _, ok := parsed[field]; ok {
					extractions = append(extractions, Extraction{Name: field, Source: "body_json", Path: field})
					continue
				}
				for _, key := range keys {
					nested, ok := parsed[key].(map[string]interface{})
					if !ok {
						continue
					}
					if _, ok := nested[field]; ok {
						extractions = append(extractions, Extraction{Name: field, Source: "body_json", Path: key + "." + field})
						break
					}
				}
			}
		}
	}

	return extractions
}

// copyHeaders returns an independent copy of h so a Step never aliases a
// Flow's (or another Step's) header map.
func copyHeaders(h map[string]string) map[string]string {
	if h == nil {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// getHeaderCI looks up key in headers case-insensitively, since headers
// captured by the proxy or returned by net/http may not agree on casing.
func getHeaderCI(headers map[string]string, key string) (string, bool) {
	if v, ok := headers[key]; ok {
		return v, true
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}
