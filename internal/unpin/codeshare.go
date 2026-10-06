package unpin

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const codeshareBase = "https://codeshare.frida.re"

// CodeShareEntry represents one script from Frida CodeShare.
type CodeShareEntry struct {
	Slug        string `json:"slug"`        // e.g. "@user/project-name"
	Title       string `json:"title"`
	Author      string `json:"author"`
	Description string `json:"description"`
	Likes       string `json:"likes"`
	Views       string `json:"views"`
	URL         string `json:"url"`
}

// CodeShareScript is a fetched script with its source code.
type CodeShareScript struct {
	CodeShareEntry
	Source string `json:"source"`
}

// CodeShareClient searches and fetches scripts from codeshare.frida.re.
type CodeShareClient struct {
	client *http.Client
}

// NewCodeShareClient creates a client with sensible defaults.
func NewCodeShareClient() *CodeShareClient {
	return &CodeShareClient{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Search queries CodeShare and returns matching entries.
func (c *CodeShareClient) Search(query string) ([]CodeShareEntry, error) {
	u := fmt.Sprintf("%s/search/?query=%s", codeshareBase, url.QueryEscape(query))
	body, err := c.fetch(u)
	if err != nil {
		return nil, fmt.Errorf("codeshare search: %w", err)
	}
	return parseSearchResults(body), nil
}

// Browse returns entries from the popularity-sorted browse page.
func (c *CodeShareClient) Browse(page int) ([]CodeShareEntry, error) {
	if page < 1 {
		page = 1
	}
	u := fmt.Sprintf("%s/browse?page=%d", codeshareBase, page)
	body, err := c.fetch(u)
	if err != nil {
		return nil, fmt.Errorf("codeshare browse: %w", err)
	}
	return parseSearchResults(body), nil
}

// FetchScript downloads the source code for a given slug (e.g. "@user/project").
func (c *CodeShareClient) FetchScript(slug string) (*CodeShareScript, error) {
	if !strings.HasPrefix(slug, "/") && !strings.HasPrefix(slug, "@") {
		slug = "/" + slug
	}
	if !strings.HasPrefix(slug, "/") {
		slug = "/" + slug
	}

	u := codeshareBase + slug
	body, err := c.fetch(u)
	if err != nil {
		return nil, fmt.Errorf("codeshare fetch %s: %w", slug, err)
	}

	source := extractProjectSource(body)
	if source == "" {
		return nil, fmt.Errorf("could not extract script source from %s", slug)
	}

	script := &CodeShareScript{
		CodeShareEntry: CodeShareEntry{
			Slug: slug,
			URL:  u,
		},
		Source: source,
	}

	// Try to extract title from page
	if title := extractBetween(body, "<title>", "</title>"); title != "" {
		title = strings.TrimSuffix(title, " | Frida CodeShare")
		title = strings.TrimSpace(title)
		script.Title = title
	}

	return script, nil
}

func (c *CodeShareClient) fetch(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cap/1.0 (frida-codeshare-client)")
	req.Header.Set("Accept", "text/html")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// parseSearchResults extracts entries from CodeShare search/browse HTML.
// Each result is an <article> containing:
//
//	<h2><a href="https://codeshare.frida.re/@user/project/">Title</a></h2>
//	<h3><i>...</i> N | <i>...</i> NK</h3>
//	<h4>Uploaded by: <a href="/@user/">@user</a></h4>
//	<p>Description</p>
func parseSearchResults(html string) []CodeShareEntry {
	var entries []CodeShareEntry

	// Match full project URLs in <h2> links
	projectRe := regexp.MustCompile(`href="(?:https://codeshare\.frida\.re)?(/@[^/]+/[^/]+/)"`)
	matches := projectRe.FindAllStringSubmatchIndex(html, -1)

	seen := make(map[string]bool)
	for _, loc := range matches {
		slug := html[loc[2]:loc[3]]
		if seen[slug] {
			continue
		}
		seen[slug] = true

		entry := CodeShareEntry{
			Slug: slug,
			URL:  codeshareBase + slug,
		}

		// Find the <article> block containing this link
		// Look backwards for <article> and forwards for </article>
		blockStart := loc[0] - 200
		if blockStart < 0 {
			blockStart = 0
		}
		blockEnd := loc[0] + 2000
		if blockEnd > len(html) {
			blockEnd = len(html)
		}
		block := html[blockStart:blockEnd]

		// Title from <h2><a ...>Title</a></h2>
		h2Re := regexp.MustCompile(`<h2><a[^>]*>([^<]+)</a></h2>`)
		if m := h2Re.FindStringSubmatch(block); len(m) > 1 {
			entry.Title = strings.TrimSpace(m[1])
		}

		// Likes and views from <h3>
		if h3 := extractBetween(block, "<h3", "</h3>"); h3 != "" {
			text := stripTags(h3)
			// Format: "131 | 583K" or "5 | 29K"
			parts := strings.Split(text, "|")
			if len(parts) >= 2 {
				entry.Likes = strings.TrimSpace(parts[0])
				entry.Views = strings.TrimSpace(parts[1])
			}
		}

		// Author from <h4>
		if h4 := extractBetween(block, "<h4", "</h4>"); h4 != "" {
			text := stripTags(h4)
			if idx := strings.Index(text, "@"); idx >= 0 {
				entry.Author = strings.TrimSpace(text[idx:])
			}
		}

		// Description from <p>
		if p := extractBetween(block, "<p", "</p>"); p != "" {
			desc := stripTags(p)
			desc = strings.TrimSpace(desc)
			if len(desc) > 200 {
				desc = desc[:200] + "..."
			}
			entry.Description = desc
		}

		// Fallback title from slug
		if entry.Title == "" {
			parts := strings.Split(strings.Trim(slug, "/"), "/")
			if len(parts) >= 2 {
				entry.Title = parts[1]
				if entry.Author == "" {
					entry.Author = "@" + parts[0]
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries
}

// extractProjectSource finds the script source code embedded in the
// CodeShare project page's Vue.js data.
// It looks for: projectSource: "..." or projectSource: '...'
func extractProjectSource(html string) string {
	marker := "projectSource:"
	idx := strings.Index(html, marker)
	if idx < 0 {
		marker = "projectSource :"
		idx = strings.Index(html, marker)
	}
	if idx < 0 {
		return ""
	}

	rest := html[idx+len(marker):]
	rest = strings.TrimLeft(rest, " \t")

	if len(rest) == 0 {
		return ""
	}

	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return ""
	}

	// Find the closing quote, handling escape sequences
	var sb strings.Builder
	i := 1
	for i < len(rest) {
		ch := rest[i]
		if ch == byte(quote) {
			break
		}
		if ch == '\\' && i+1 < len(rest) {
			next := rest[i+1]
			switch next {
			case 'n':
				sb.WriteByte('\n')
				i += 2
			case 'r':
				sb.WriteByte('\r')
				i += 2
			case 't':
				sb.WriteByte('\t')
				i += 2
			case '\\':
				sb.WriteByte('\\')
				i += 2
			case '\'':
				sb.WriteByte('\'')
				i += 2
			case '"':
				sb.WriteByte('"')
				i += 2
			case 'u':
				// Unicode escape: \uXXXX
				if i+5 < len(rest) {
					hex := rest[i+2 : i+6]
					if r, ok := parseHex4(hex); ok {
						sb.WriteRune(r)
						i += 6
						continue
					}
				}
				sb.WriteByte('\\')
				sb.WriteByte('u')
				i += 2
			default:
				sb.WriteByte('\\')
				sb.WriteByte(next)
				i += 2
			}
		} else {
			sb.WriteByte(ch)
			i++
		}
	}

	return sb.String()
}

func parseHex4(s string) (rune, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var val rune
	for _, c := range s {
		val <<= 4
		switch {
		case c >= '0' && c <= '9':
			val |= c - '0'
		case c >= 'a' && c <= 'f':
			val |= c - 'a' + 10
		case c >= 'A' && c <= 'F':
			val |= c - 'A' + 10
		default:
			return 0, false
		}
	}
	return val, true
}

func extractBetween(s, open, close string) string {
	start := strings.Index(s, open)
	if start < 0 {
		return ""
	}
	// Skip past the opening tag's >
	gt := strings.Index(s[start:], ">")
	if gt < 0 {
		return ""
	}
	start += gt + 1
	end := strings.Index(s[start:], close)
	if end < 0 {
		return ""
	}
	return s[start : start+end]
}

func stripTags(s string) string {
	var sb strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			sb.WriteRune(r)
		}
	}
	result := sb.String()
	// Collapse whitespace
	var collapsed strings.Builder
	prevSpace := false
	for _, r := range result {
		if unicode.IsSpace(r) {
			if !prevSpace {
				collapsed.WriteRune(' ')
			}
			prevSpace = true
		} else {
			collapsed.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(collapsed.String())
}

// SearchForApp searches CodeShare using multiple queries derived from
// the app's fingerprint, deduplicates results, and returns them sorted
// by relevance (number of query matches).
func SearchForApp(fp *AppFingerprint) ([]CodeShareEntry, error) {
	client := NewCodeShareClient()
	queries := fp.TopSearchQueries(5)

	type scored struct {
		entry CodeShareEntry
		hits  int
	}
	scoreMap := make(map[string]*scored)

	for _, q := range queries {
		results, err := client.Search(q)
		if err != nil {
			continue
		}
		for _, entry := range results {
			if s, ok := scoreMap[entry.Slug]; ok {
				s.hits++
			} else {
				scoreMap[entry.Slug] = &scored{entry: entry, hits: 1}
			}
		}
	}

	// Sort by hit count descending
	sorted := make([]scored, 0, len(scoreMap))
	for _, s := range scoreMap {
		sorted = append(sorted, *s)
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].hits > sorted[i].hits {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	entries := make([]CodeShareEntry, len(sorted))
	for i, s := range sorted {
		entries[i] = s.entry
	}
	return entries, nil
}

// DownloadScript fetches a script from CodeShare and saves it to dir.
func DownloadScript(slug, dir string) (string, error) {
	client := NewCodeShareClient()
	script, err := client.FetchScript(slug)
	if err != nil {
		return "", err
	}

	if dir == "" {
		dir = os.TempDir()
	}
	os.MkdirAll(dir, 0755)

	// Sanitize filename from slug
	name := strings.ReplaceAll(strings.Trim(slug, "/"), "/", "_")
	name = strings.ReplaceAll(name, "@", "")
	filename := filepath.Join(dir, name+".js")

	if err := os.WriteFile(filename, []byte(script.Source), 0644); err != nil {
		return "", fmt.Errorf("write script: %w", err)
	}
	return filename, nil
}
