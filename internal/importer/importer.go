// Package importer converts capture exports from other HTTP debugging tools
// — HAR (the JSON "HTTP Archive" format produced by browser DevTools and
// most proxies) and Charles Proxy's XML session export — into cap's Flow
// type, so traffic recorded elsewhere can be loaded into cap for grouping,
// signature analysis, and replay.
//
// Both Import functions are best-effort: a flow missing optional data (a
// body, a Host header, a session start time) is still returned rather than
// rejected. Only a document that fails to parse as the expected format
// produces an error. Generated Flow IDs are "imp-1", "imp-2", ... in
// document order, since imported traffic has no capture-time ID of its own.
package importer

import (
	"net/url"
	"strings"
)

// header is a single request/response header. Its tags cover both input
// formats: HAR encodes headers as a JSON {"name":...,"value":...} object,
// Charles as a <header name="..." value="..."/> XML element.
type header struct {
	Name  string `json:"name" xml:"name,attr"`
	Value string `json:"value" xml:"value,attr"`
}

// headerMap collapses a header list into the map shape stored on
// types.Flow. When a name repeats, the last occurrence wins. An empty list
// yields a nil map rather than an empty one, matching the zero value of an
// unset field.
func headerMap(hs []header) map[string]string {
	if len(hs) == 0 {
		return nil
	}
	m := make(map[string]string, len(hs))
	for _, h := range hs {
		m[h.Name] = h.Value
	}
	return m
}

// headerValue returns the value of the first header named name
// (case-insensitive), or "" if there isn't one.
func headerValue(hs []header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// hostAndPath extracts the host and path from a request URL. A URL that
// fails to parse yields two empty strings rather than an error, since one
// malformed entry shouldn't fail the whole import.
func hostAndPath(raw string) (host, path string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	return u.Host, u.Path
}
