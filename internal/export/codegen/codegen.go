// Package codegen renders a captured Flow as a runnable HTTP request snippet
// in several target languages (curl, Python, Go, Java, JavaScript), using
// Go's embed and text/template packages.
package codegen

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/nongjiawu/cap/internal/types"
)

//go:embed templates/*.tmpl
var tmplFS embed.FS

// KV is a single header key/value pair, exposed to templates via
// sortedHeaders so generated code lists headers in a deterministic order.
type KV struct {
	K string
	V string
}

// langTemplates maps a language identifier (as returned by Languages) to the
// embedded template file that renders it. The identifier intentionally
// differs from the file name for "go" and "js" (golang.tmpl / javascript.tmpl)
// to keep file names unambiguous while keeping the public identifiers short.
var langTemplates = map[string]string{
	"curl":   "curl.tmpl",
	"python": "python.tmpl",
	"go":     "golang.tmpl",
	"java":   "java.tmpl",
	"js":     "javascript.tmpl",
}

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"jsonPretty":    jsonPretty,
	"escapeShell":   escapeShell,
	"sortedHeaders": sortedHeaders,
	"hasBody":       hasBody,
	"isJSON":        isJSON,
	"lower":         lower,
}).ParseFS(tmplFS, "templates/*.tmpl"))

// Languages returns the supported target language identifiers, in the order
// they should be presented to users.
func Languages() []string {
	return []string{"curl", "python", "go", "java", "js"}
}

// Generate renders flow as a runnable HTTP request snippet for lang. lang
// must be one of the identifiers returned by Languages.
func Generate(flow *types.Flow, lang string) (string, error) {
	name, ok := langTemplates[lang]
	if !ok {
		return "", fmt.Errorf("codegen: unknown language %q", lang)
	}

	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, flow); err != nil {
		return "", fmt.Errorf("codegen: render %s: %w", lang, err)
	}
	return buf.String(), nil
}

// jsonPretty indents raw JSON for readability inside generated snippets. If
// body isn't valid JSON it is returned unmodified, decoded as text.
func jsonPretty(body []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		return string(body)
	}
	return buf.String()
}

// escapeShell escapes single quotes in s so it can be embedded inside a
// single-quoted POSIX shell argument.
func escapeShell(s string) string {
	return strings.ReplaceAll(s, "'", `'\''`)
}

// sortedHeaders returns headers as key/value pairs sorted by key, so
// generated code lists them in a deterministic order across runs.
func sortedHeaders(headers map[string]string) []KV {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	kvs := make([]KV, len(keys))
	for i, k := range keys {
		kvs[i] = KV{K: k, V: headers[k]}
	}
	return kvs
}

// hasBody reports whether flow carries a request body worth emitting.
func hasBody(flow *types.Flow) bool {
	return flow != nil && len(flow.ReqBody) > 0
}

// isJSON reports whether a Content-Type value denotes a JSON payload.
func isJSON(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "json")
}

// lower lowercases s. Used to turn an HTTP method into a library call name,
// e.g. "POST" -> "post" for requests.post(...).
func lower(s string) string {
	return strings.ToLower(s)
}
