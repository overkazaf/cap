package tui

import (
	"strconv"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

// FilterQuery represents a parsed live-search expression supporting free-text
// terms and structured predicates:
//   - m:POST / method:GET
//   - s:200 / s:4xx / s:>=400 / status:5xx
//   - h:api.example.com / host:example
//   - t:auth / tag:login
//   - negation with leading '!' or '-' (e.g. !m:OPTIONS, -h:analytics)
type FilterQuery struct {
	Raw   string
	Terms []filterTerm
}

type filterTerm struct {
	Negate bool
	Field  string // "", "m", "s", "h", "t"
	Value  string
}

// ParseFilter parses a filter query string into a FilterQuery.
func ParseFilter(raw string) FilterQuery {
	fq := FilterQuery{Raw: strings.TrimSpace(raw)}
	if fq.Raw == "" {
		return fq
	}
	for _, tok := range strings.Fields(fq.Raw) {
		term := filterTerm{}
		if strings.HasPrefix(tok, "!") || strings.HasPrefix(tok, "-") {
			if len(tok) > 1 {
				term.Negate = true
				tok = tok[1:]
			}
		}
		if k, v, ok := strings.Cut(tok, ":"); ok && v != "" {
			switch strings.ToLower(k) {
			case "m", "method":
				term.Field = "m"
				term.Value = strings.ToUpper(v)
			case "s", "status":
				term.Field = "s"
				term.Value = strings.ToLower(v)
			case "h", "host":
				term.Field = "h"
				term.Value = strings.ToLower(v)
			case "t", "tag":
				term.Field = "t"
				term.Value = strings.ToLower(v)
			default:
				term.Field = ""
				term.Value = strings.ToLower(tok)
			}
		} else {
			term.Value = strings.ToLower(tok)
		}
		fq.Terms = append(fq.Terms, term)
	}
	return fq
}

// Matches reports whether flow satisfies all terms in fq plus optional quick
// methodFilter and errorsOnly constraints.
func (fq FilterQuery) Matches(f *types.Flow, methodFilter string, errorsOnly bool) bool {
	if f == nil {
		return false
	}
	if methodFilter != "" && !strings.EqualFold(f.Method, methodFilter) {
		return false
	}
	if errorsOnly && f.Status < 400 {
		return false
	}
	for _, term := range fq.Terms {
		ok := matchTerm(f, term)
		if term.Negate {
			ok = !ok
		}
		if !ok {
			return false
		}
	}
	return true
}

func matchTerm(f *types.Flow, term filterTerm) bool {
	switch term.Field {
	case "m":
		return strings.EqualFold(f.Method, term.Value)
	case "h":
		return strings.Contains(strings.ToLower(f.Host), term.Value)
	case "s":
		return matchStatus(f.Status, term.Value)
	case "t":
		for _, tag := range f.Tags {
			if strings.Contains(strings.ToLower(tag), term.Value) {
				return true
			}
		}
		return false
	default:
		q := term.Value
		if strings.Contains(strings.ToLower(f.ID), q) ||
			strings.Contains(strings.ToLower(f.Method), q) ||
			strings.Contains(strings.ToLower(f.URL), q) ||
			strings.Contains(strings.ToLower(f.Host), q) ||
			strings.Contains(strings.ToLower(f.Path), q) ||
			strings.Contains(strconv.Itoa(f.Status), q) {
			return true
		}
		for _, tag := range f.Tags {
			if strings.Contains(strings.ToLower(tag), q) {
				return true
			}
		}
		if len(f.ReqBody) > 0 && strings.Contains(strings.ToLower(string(f.ReqBody)), q) {
			return true
		}
		if len(f.RespBody) > 0 && len(f.RespBody) <= 256*1024 && !IsBinary(f.RespBody) {
			if strings.Contains(strings.ToLower(string(f.RespBody)), q) {
				return true
			}
		}
		return false
	}
}

func matchStatus(status int, expr string) bool {
	if expr == "err" || expr == "error" {
		return status >= 400
	}
	if len(expr) == 3 && strings.HasSuffix(expr, "xx") && expr[0] >= '1' && expr[0] <= '5' {
		class := int(expr[0] - '0')
		return status >= class*100 && status < (class+1)*100
	}
	if strings.HasPrefix(expr, ">=") {
		if n, err := strconv.Atoi(expr[2:]); err == nil {
			return status >= n
		}
	}
	if strings.HasPrefix(expr, "<=") {
		if n, err := strconv.Atoi(expr[2:]); err == nil {
			return status <= n
		}
	}
	if strings.HasPrefix(expr, ">") {
		if n, err := strconv.Atoi(expr[1:]); err == nil {
			return status > n
		}
	}
	if strings.HasPrefix(expr, "<") {
		if n, err := strconv.Atoi(expr[1:]); err == nil {
			return status < n
		}
	}
	if n, err := strconv.Atoi(expr); err == nil {
		return status == n
	}
	return strings.HasPrefix(strconv.Itoa(status), expr)
}
