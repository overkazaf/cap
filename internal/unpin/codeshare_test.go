package unpin

import (
	"testing"
)

func TestParseSearchResults(t *testing.T) {
	html := `
<div>
  <a href="/@user1/ssl-bypass/">
    <h3>SSL Pinning Bypass 42 likes 1337 views</h3>
    <h4>Uploaded by: @user1</h4>
    <p>Universal SSL pinning bypass for Android apps</p>
  </a>
  <a href="/@user2/flutter-unpin/">
    <h3>Flutter SSL Bypass 10 likes 200 views</h3>
    <h4>Uploaded by: @user2</h4>
    <p>Bypass SSL in Flutter apps</p>
  </a>
</div>`

	results := parseSearchResults(html)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].Slug != "/@user1/ssl-bypass/" {
		t.Errorf("result[0].Slug = %q", results[0].Slug)
	}
	if results[0].Author != "@user1" {
		t.Errorf("result[0].Author = %q", results[0].Author)
	}
	if results[1].Slug != "/@user2/flutter-unpin/" {
		t.Errorf("result[1].Slug = %q", results[1].Slug)
	}
}

func TestParseSearchResultsDedup(t *testing.T) {
	html := `
<a href="/@user/project/">link1</a>
<a href="/@user/project/">link2</a>
`
	results := parseSearchResults(html)
	if len(results) != 1 {
		t.Errorf("expected 1 deduped result, got %d", len(results))
	}
}

func TestParseSearchResultsEmpty(t *testing.T) {
	results := parseSearchResults("<html><body>No results</body></html>")
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestExtractProjectSource(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "double quoted",
			html: `projectSource: "console.log('hello');"`,
			want: "console.log('hello');",
		},
		{
			name: "single quoted",
			html: `projectSource: 'console.log("hello");'`,
			want: `console.log("hello");`,
		},
		{
			name: "unicode escapes",
			html: `projectSource: "var x = A;"`,
			want: "var x = A;",
		},
		{
			name: "newline escapes",
			html: `projectSource: "line1\nline2"`,
			want: "line1\nline2",
		},
		{
			name: "not found",
			html: `<html>no source here</html>`,
			want: "",
		},
		{
			name: "with space before colon",
			html: `projectSource : "test()"`,
			want: "test()",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractProjectSource(tt.html)
			if got != tt.want {
				t.Errorf("extractProjectSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractBetween(t *testing.T) {
	s := `<h3 class="title">Hello World</h3>`
	got := extractBetween(s, "<h3", "</h3>")
	if got != "Hello World" {
		t.Errorf("extractBetween() = %q, want %q", got, "Hello World")
	}
}

func TestStripTags(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<b>bold</b>", "bold"},
		{"<a href='x'>link</a>", "link"},
		{"no tags", "no tags"},
		{"<p>  spaced  out  </p>", "spaced out"},
		{"", ""},
	}
	for _, tt := range tests {
		got := stripTags(tt.input)
		if got != tt.want {
			t.Errorf("stripTags(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseHex4(t *testing.T) {
	r, ok := parseHex4("0041")
	if !ok || r != 'A' {
		t.Errorf("parseHex4(0041) = %c, %v", r, ok)
	}
	r, ok = parseHex4("4e2d")
	if !ok || r != '中' {
		t.Errorf("parseHex4(4e2d) = %c, %v", r, ok)
	}
	_, ok = parseHex4("ZZZZ")
	if ok {
		t.Error("parseHex4(ZZZZ) should fail")
	}
	_, ok = parseHex4("12")
	if ok {
		t.Error("parseHex4(12) should fail for wrong length")
	}
}
