package context

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nongjiawu/cap/internal/types"
)

// retrofitAnnotation matches a Retrofit HTTP method annotation, e.g.
// @POST("/api/v1/login") or @GET("/api/v1/user/{id}").
var retrofitAnnotation = regexp.MustCompile(`@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"\s*\)`)

// retrofitMethodDecl matches a Java method declaration, used to pull the
// method name off the line immediately following a Retrofit annotation.
var retrofitMethodDecl = regexp.MustCompile(`\s+\w+[\w<>,\s]*\s+(\w+)\s*\(`)

// okHttpBuilderStart matches the start of an OkHttp request builder chain.
var okHttpBuilderStart = regexp.MustCompile(`new\s+Request\.Builder\s*\(\s*\)`)

// okHttpBuildEnd matches the terminating .build() call of a builder chain.
var okHttpBuildEnd = regexp.MustCompile(`\.build\s*\(\s*\)`)

// okHttpURL extracts the argument of a .url("...") call.
var okHttpURL = regexp.MustCompile(`\.url\s*\(\s*"([^"]+)"\s*\)`)

// okHttpExplicitMethod matches a .method("POST", body) style call.
var okHttpExplicitMethod = regexp.MustCompile(`\.method\s*\(\s*"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"`)

// okHttpBodyVerb matches .post(...)/.put(...)/.delete(...)/.patch(...) calls.
var okHttpBodyVerb = regexp.MustCompile(`\.(post|put|delete|patch)\s*\(`)

// okHttpNoBodyVerb matches .get()/.head() calls.
var okHttpNoBodyVerb = regexp.MustCompile(`\.(get|head)\s*\(\s*\)`)

// javaMethodDecl matches a Java method signature line (access modifier
// required), used to find the method enclosing an OkHttp builder chain.
var javaMethodDecl = regexp.MustCompile(`^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?[\w<>\[\],.?\s]+?\s+(\w+)\s*\([^=;]*\)\s*(?:throws\s+[\w,.\s]+)?\s*\{?\s*$`)

// maxOkHttpChainLines bounds how far past a "new Request.Builder()" line we
// scan for its matching .build() call.
const maxOkHttpChainLines = 40

// maxEnclosingMethodLookback bounds how far back we scan for the Java method
// that encloses an OkHttp builder chain.
const maxEnclosingMethodLookback = 60

// ScanJadxOutput walks dir recursively, scanning every .java file for
// Retrofit HTTP annotations and OkHttp Request.Builder call sites, and
// returns a Mapping for each call site found. Source.File in each returned
// Mapping is relative to dir, using forward slashes.
func ScanJadxOutput(dir string) ([]Mapping, error) {
	var mappings []Mapping

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)

		ms, err := scanJavaFile(path, relPath)
		if err != nil {
			return err
		}
		mappings = append(mappings, ms...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mappings, nil
}

// scanJavaFile scans a single Java source file for Retrofit annotations and
// OkHttp builder call sites.
func scanJavaFile(absPath, relPath string) ([]Mapping, error) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")

	var mappings []Mapping
	mappings = append(mappings, scanRetrofitAnnotations(lines, relPath)...)
	mappings = append(mappings, scanOkHttpPatterns(lines, relPath)...)
	return mappings, nil
}

// scanRetrofitAnnotations finds @GET/@POST/etc annotations and pairs each
// with the method declared on the following line.
func scanRetrofitAnnotations(lines []string, relPath string) []Mapping {
	var mappings []Mapping
	for i, line := range lines {
		m := retrofitAnnotation.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		httpMethod, path := m[1], m[2]
		lineNum := i + 1

		if i+1 >= len(lines) {
			continue
		}
		decl := retrofitMethodDecl.FindStringSubmatch(lines[i+1])
		if decl == nil {
			continue
		}

		mappings = append(mappings, Mapping{
			URLPattern: httpMethod + " " + path,
			Source: types.SourceRef{
				File:   relPath,
				Method: decl[1],
				Line:   lineNum,
			},
		})
	}
	return mappings
}

// scanOkHttpPatterns finds "new Request.Builder()...build()" chains and
// extracts the URL (via .url(...)) and HTTP method (via .method(...),
// .post(...)/.put(...)/.delete(...)/.patch(...), or .get()/.head()).
func scanOkHttpPatterns(lines []string, relPath string) []Mapping {
	var mappings []Mapping

	for i := 0; i < len(lines); i++ {
		if !okHttpBuilderStart.MatchString(lines[i]) {
			continue
		}
		startLine := i

		end := len(lines)
		limit := i + maxOkHttpChainLines
		for j := i; j < len(lines) && j < limit; j++ {
			if j > i && okHttpBuilderStart.MatchString(lines[j]) {
				end = j
				break
			}
			if okHttpBuildEnd.MatchString(lines[j]) {
				end = j + 1
				break
			}
		}
		chunk := strings.Join(lines[i:end], "\n")

		urlMatch := okHttpURL.FindStringSubmatch(chunk)
		if urlMatch == nil {
			i = end - 1
			continue
		}
		path := extractPath(urlMatch[1])

		httpMethod := "GET"
		switch {
		case okHttpExplicitMethod.MatchString(chunk):
			httpMethod = okHttpExplicitMethod.FindStringSubmatch(chunk)[1]
		case okHttpBodyVerb.MatchString(chunk):
			httpMethod = strings.ToUpper(okHttpBodyVerb.FindStringSubmatch(chunk)[1])
		case okHttpNoBodyVerb.MatchString(chunk):
			httpMethod = strings.ToUpper(okHttpNoBodyVerb.FindStringSubmatch(chunk)[1])
		}

		mappings = append(mappings, Mapping{
			URLPattern: httpMethod + " " + path,
			Source: types.SourceRef{
				File:   relPath,
				Method: findEnclosingMethod(lines, startLine),
				Line:   startLine + 1,
			},
		})

		i = end - 1
	}

	return mappings
}

// extractPath reduces a possibly-absolute URL to just its path component so
// it can be compared against types.Flow.Path. Strings that are already a
// bare path (or that fail to parse as an absolute URL) are returned as-is.
func extractPath(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.IsAbs() && u.Path != "" {
		return u.Path
	}
	return raw
}

// findEnclosingMethod scans backward from just before the `before` line
// index for the nearest Java method declaration, returning its name ("" if
// none is found within maxEnclosingMethodLookback lines).
func findEnclosingMethod(lines []string, before int) string {
	limit := before - maxEnclosingMethodLookback
	if limit < 0 {
		limit = 0
	}
	for i := before - 1; i >= limit; i-- {
		if m := javaMethodDecl.FindStringSubmatch(lines[i]); m != nil {
			return m[1]
		}
	}
	return ""
}
