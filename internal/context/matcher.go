package context

import (
	"strings"

	"github.com/nongjiawu/cap/internal/types"
)

// Matcher matches captured flows against a known set of source-code
// mappings (method + path pattern -> SourceRef).
type Matcher struct {
	mappings []Mapping
}

// NewMatcher returns a Matcher that matches flows against mappings. A nil or
// empty mappings slice is valid and causes Match to always return nil.
func NewMatcher(mappings []Mapping) *Matcher {
	return &Matcher{mappings: mappings}
}

// Match returns a copy of the SourceRef for the first mapping whose method
// and path pattern match flow, or nil if no mapping matches.
func (m *Matcher) Match(flow *types.Flow) *types.SourceRef {
	if m == nil || flow == nil {
		return nil
	}
	for _, mapping := range m.mappings {
		method, pattern, ok := splitURLPattern(mapping.URLPattern)
		if !ok {
			continue
		}
		if !strings.EqualFold(flow.Method, method) {
			continue
		}
		if !matchPath(flow.Path, pattern) {
			continue
		}
		ref := mapping.Source
		return &ref
	}
	return nil
}

// splitURLPattern splits a "METHOD /path" pattern into its method and path
// components.
func splitURLPattern(p string) (method, path string, ok bool) {
	parts := strings.SplitN(p, " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// matchPath reports whether actual matches pattern, where pattern may
// contain "{param}" placeholders that each match exactly one path segment.
func matchPath(actual, pattern string) bool {
	if actual == pattern {
		return true
	}
	actualParts := splitPathSegments(actual)
	patternParts := splitPathSegments(pattern)
	if len(actualParts) != len(patternParts) {
		return false
	}
	for i, seg := range patternParts {
		if isPathParam(seg) {
			continue
		}
		if seg != actualParts[i] {
			return false
		}
	}
	return true
}

// splitPathSegments splits a URL path into its non-empty segments, ignoring
// leading/trailing slashes.
func splitPathSegments(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// isPathParam reports whether a path segment is a "{param}" placeholder.
func isPathParam(segment string) bool {
	return strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 1
}
