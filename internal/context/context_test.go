package context_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nongjiawu/cap/internal/context"
	"github.com/nongjiawu/cap/internal/types"
)

// writeFile creates path (and any missing parent directories) with content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestParseRetrofitAnnotations(t *testing.T) {
	dir := t.TempDir()
	relFile := filepath.Join("com", "example", "api", "LoginApi.java")
	writeFile(t, filepath.Join(dir, relFile), `package com.example.api;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.GET;
import retrofit2.http.POST;
import retrofit2.http.Path;

public interface LoginApi {
    @POST("/api/v1/login")
    Call<LoginResp> login(@Body LoginReq req);

    @GET("/api/v1/user/{id}")
    Call<UserResp> getUser(@Path("id") String userId);
}
`)

	mappings, err := context.ScanJadxOutput(dir)
	if err != nil {
		t.Fatalf("ScanJadxOutput: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("len(mappings) = %d, want 2 (%+v)", len(mappings), mappings)
	}

	byPattern := make(map[string]context.Mapping, len(mappings))
	for _, m := range mappings {
		byPattern[m.URLPattern] = m
	}
	wantFile := filepath.ToSlash(relFile)

	login, ok := byPattern["POST /api/v1/login"]
	if !ok {
		t.Fatalf("missing mapping for %q, got %+v", "POST /api/v1/login", mappings)
	}
	if login.Source.File != wantFile {
		t.Errorf("login.Source.File = %q, want %q", login.Source.File, wantFile)
	}
	if login.Source.Method != "login" {
		t.Errorf("login.Source.Method = %q, want %q", login.Source.Method, "login")
	}
	if login.Source.Line != 10 {
		t.Errorf("login.Source.Line = %d, want 10", login.Source.Line)
	}

	getUser, ok := byPattern["GET /api/v1/user/{id}"]
	if !ok {
		t.Fatalf("missing mapping for %q, got %+v", "GET /api/v1/user/{id}", mappings)
	}
	if getUser.Source.File != wantFile {
		t.Errorf("getUser.Source.File = %q, want %q", getUser.Source.File, wantFile)
	}
	if getUser.Source.Method != "getUser" {
		t.Errorf("getUser.Source.Method = %q, want %q", getUser.Source.Method, "getUser")
	}
	if getUser.Source.Line != 13 {
		t.Errorf("getUser.Source.Line = %d, want 13", getUser.Source.Line)
	}
}

func TestParseOkHttpPatterns(t *testing.T) {
	t.Run("post with body", func(t *testing.T) {
		dir := t.TempDir()
		relFile := filepath.Join("com", "example", "api", "UploadApi.java")
		writeFile(t, filepath.Join(dir, relFile), `package com.example.api;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import java.io.IOException;

public class UploadApi {
    private final OkHttpClient client = new OkHttpClient();

    public Response upload(String token, byte[] data) throws IOException {
        RequestBody body = RequestBody.create(MediaType.parse("application/octet-stream"), data);
        Request request = new Request.Builder()
                .url("https://api.example.com/v1/upload")
                .post(body)
                .addHeader("Authorization", token)
                .build();
        return client.newCall(request).execute();
    }
}
`)

		mappings, err := context.ScanJadxOutput(dir)
		if err != nil {
			t.Fatalf("ScanJadxOutput: %v", err)
		}
		if len(mappings) != 1 {
			t.Fatalf("len(mappings) = %d, want 1 (%+v)", len(mappings), mappings)
		}

		got := mappings[0]
		if got.URLPattern != "POST /v1/upload" {
			t.Errorf("URLPattern = %q, want %q", got.URLPattern, "POST /v1/upload")
		}
		wantFile := filepath.ToSlash(relFile)
		if got.Source.File != wantFile {
			t.Errorf("Source.File = %q, want %q", got.Source.File, wantFile)
		}
		if got.Source.Method != "upload" {
			t.Errorf("Source.Method = %q, want %q", got.Source.Method, "upload")
		}
		if got.Source.Line != 15 {
			t.Errorf("Source.Line = %d, want 15", got.Source.Line)
		}
	})

	t.Run("explicit method call", func(t *testing.T) {
		dir := t.TempDir()
		relFile := filepath.Join("com", "example", "api", "StatusApi.java")
		writeFile(t, filepath.Join(dir, relFile), `package com.example.api;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class StatusApi {
    private final OkHttpClient client = new OkHttpClient();

    public Response checkStatus() throws Exception {
        Request request = new Request.Builder()
                .url("https://api.example.com/v1/status")
                .method("GET", null)
                .build();
        return client.newCall(request).execute();
    }
}
`)

		mappings, err := context.ScanJadxOutput(dir)
		if err != nil {
			t.Fatalf("ScanJadxOutput: %v", err)
		}
		if len(mappings) != 1 {
			t.Fatalf("len(mappings) = %d, want 1 (%+v)", len(mappings), mappings)
		}

		got := mappings[0]
		if got.URLPattern != "GET /v1/status" {
			t.Errorf("URLPattern = %q, want %q", got.URLPattern, "GET /v1/status")
		}
		if got.Source.Method != "checkStatus" {
			t.Errorf("Source.Method = %q, want %q", got.Source.Method, "checkStatus")
		}
	})
}

func TestMatchFlowToContext(t *testing.T) {
	mappings := []context.Mapping{
		{
			URLPattern: "POST /api/v1/login",
			Source: types.SourceRef{
				File:   "com/example/api/LoginApi.java",
				Method: "login",
				Line:   10,
			},
		},
		{
			URLPattern: "GET /user/{id}",
			Source: types.SourceRef{
				File:   "com/example/api/UserApi.java",
				Method: "getUser",
				Line:   20,
			},
		},
	}
	matcher := context.NewMatcher(mappings)

	t.Run("exact method and path", func(t *testing.T) {
		flow := &types.Flow{Method: "POST", Path: "/api/v1/login"}
		ref := matcher.Match(flow)
		if ref == nil {
			t.Fatal("expected match, got nil")
		}
		if ref.File != "com/example/api/LoginApi.java" || ref.Method != "login" || ref.Line != 10 {
			t.Errorf("ref = %+v, want File=com/example/api/LoginApi.java Method=login Line=10", ref)
		}
	})

	t.Run("case-insensitive method", func(t *testing.T) {
		flow := &types.Flow{Method: "post", Path: "/api/v1/login"}
		ref := matcher.Match(flow)
		if ref == nil {
			t.Fatal("expected match for lowercase method, got nil")
		}
	})

	t.Run("path parameter", func(t *testing.T) {
		flow := &types.Flow{Method: "GET", Path: "/user/12345"}
		ref := matcher.Match(flow)
		if ref == nil {
			t.Fatal("expected match for /user/12345, got nil")
		}
		if ref.Method != "getUser" {
			t.Errorf("ref.Method = %q, want getUser", ref.Method)
		}
	})
}

func TestNoMatch(t *testing.T) {
	t.Run("nil mappings", func(t *testing.T) {
		matcher := context.NewMatcher(nil)
		flow := &types.Flow{Method: "GET", Path: "/unknown"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil, got %+v", ref)
		}
	})

	t.Run("empty mappings", func(t *testing.T) {
		matcher := context.NewMatcher([]context.Mapping{})
		flow := &types.Flow{Method: "GET", Path: "/unknown"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil, got %+v", ref)
		}
	})

	t.Run("non-matching path", func(t *testing.T) {
		mappings := []context.Mapping{
			{URLPattern: "POST /api/v1/login", Source: types.SourceRef{File: "x.java"}},
		}
		matcher := context.NewMatcher(mappings)
		flow := &types.Flow{Method: "POST", Path: "/api/v1/other"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil, got %+v", ref)
		}
	})

	t.Run("non-matching method", func(t *testing.T) {
		mappings := []context.Mapping{
			{URLPattern: "POST /api/v1/login", Source: types.SourceRef{File: "x.java"}},
		}
		matcher := context.NewMatcher(mappings)
		flow := &types.Flow{Method: "GET", Path: "/api/v1/login"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil, got %+v", ref)
		}
	})
}

func TestMatchPathParams(t *testing.T) {
	mappings := []context.Mapping{
		{
			URLPattern: "GET /api/{version}/user/{id}/posts",
			Source:     types.SourceRef{File: "com/example/api/PostsApi.java", Method: "getPosts"},
		},
	}
	matcher := context.NewMatcher(mappings)

	t.Run("multiple path params match", func(t *testing.T) {
		flow := &types.Flow{Method: "GET", Path: "/api/v2/user/42/posts"}
		ref := matcher.Match(flow)
		if ref == nil {
			t.Fatal("expected match, got nil")
		}
		if ref.Method != "getPosts" {
			t.Errorf("ref.Method = %q, want getPosts", ref.Method)
		}
	})

	t.Run("extra segment returns nil", func(t *testing.T) {
		flow := &types.Flow{Method: "GET", Path: "/api/v2/user/42/posts/extra"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil for mismatched segment count, got %+v", ref)
		}
	})

	t.Run("too few segments returns nil", func(t *testing.T) {
		flow := &types.Flow{Method: "GET", Path: "/api/v2/user/42"}
		if ref := matcher.Match(flow); ref != nil {
			t.Errorf("expected nil for too few segments, got %+v", ref)
		}
	})
}
