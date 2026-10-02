package codegen_test

import (
	"strings"
	"testing"

	"github.com/overkazaf/cap/internal/export/codegen"
	"github.com/overkazaf/cap/internal/types"
)

var testFlow = &types.Flow{
	Method:      "POST",
	URL:         "https://api.example.com/v1/login",
	ReqHeaders:  map[string]string{"Content-Type": "application/json", "Authorization": "Bearer tok123"},
	ReqBody:     []byte(`{"username":"test","password":"pass"}`),
	ReqBodyType: "application/json",
	Status:      200,
}

func TestGenerateCurl(t *testing.T) {
	out, err := codegen.Generate(testFlow, "curl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "curl") {
		t.Error("missing curl command")
	}
	if !strings.Contains(out, "-X") || !strings.Contains(out, "POST") {
		t.Error("missing method flag/value")
	}
	if !strings.Contains(out, "https://api.example.com/v1/login") {
		t.Error("missing URL")
	}
	if !strings.Contains(out, "Authorization") || !strings.Contains(out, "Bearer tok123") {
		t.Error("missing Authorization header")
	}
	if !strings.Contains(out, "username") || !strings.Contains(out, "test") {
		t.Error("missing request body")
	}
}

func TestGeneratePython(t *testing.T) {
	out, err := codegen.Generate(testFlow, "python")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "requests.post") {
		t.Error("missing requests.post call")
	}
	if !strings.Contains(out, "headers = {") {
		t.Error("missing headers dict")
	}
	if !strings.Contains(out, "Authorization") {
		t.Error("missing Authorization header")
	}
}

func TestGenerateGo(t *testing.T) {
	out, err := codegen.Generate(testFlow, "go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "http.NewRequest") {
		t.Error("missing http.NewRequest")
	}
	if !strings.Contains(out, "http.DefaultClient") {
		t.Error("missing http.DefaultClient.Do")
	}
}

func TestGenerateJava(t *testing.T) {
	out, err := codegen.Generate(testFlow, "java")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "OkHttpClient") {
		t.Error("missing OkHttpClient")
	}
	if !strings.Contains(out, "Request.Builder") {
		t.Error("missing Request.Builder")
	}
}

func TestGenerateJS(t *testing.T) {
	out, err := codegen.Generate(testFlow, "js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "fetch(") {
		t.Error("missing fetch")
	}
}

func TestAllLanguages(t *testing.T) {
	langs := codegen.Languages()
	if len(langs) < 5 {
		t.Fatalf("expected >= 5 languages, got %d", len(langs))
	}
	for _, lang := range langs {
		out, err := codegen.Generate(testFlow, lang)
		if err != nil {
			t.Errorf("lang %s: %v", lang, err)
			continue
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("lang %s: empty output", lang)
		}
	}
}

func TestGenerateGET(t *testing.T) {
	getFlow := &types.Flow{
		Method:     "GET",
		URL:        "https://api.example.com/v1/profile",
		ReqHeaders: map[string]string{"Authorization": "Bearer tok123"},
		Status:     200,
	}

	curlOut, err := codegen.Generate(getFlow, "curl")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(curlOut, "--data-raw") {
		t.Error("curl: GET with no body should not include --data-raw")
	}

	pyOut, err := codegen.Generate(getFlow, "python")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pyOut, "json_data") {
		t.Error("python: GET with no body should not build json_data")
	}

	goOut, err := codegen.Generate(getFlow, "go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(goOut, "strings.NewReader") {
		t.Error("go: GET with no body should not build a request body reader")
	}

	javaOut, err := codegen.Generate(getFlow, "java")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(javaOut, "RequestBody.create") {
		t.Error("java: GET with no body should not build a RequestBody")
	}

	jsOut, err := codegen.Generate(getFlow, "js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jsOut, "JSON.stringify") {
		t.Error("js: GET with no body should not include a JSON body")
	}
}
