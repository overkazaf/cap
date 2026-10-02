// Package context maps captured HTTP flows back to the source code that
// produced them, by scanning jadx-decompiled Android app output for
// Retrofit/OkHttp call sites and matching flow method+path against them.
package context

import "github.com/nongjiawu/cap/internal/types"

// Mapping associates an HTTP method+path pattern (e.g. "POST /api/v1/login")
// with the location in decompiled source code that issues that request.
type Mapping struct {
	URLPattern string          `yaml:"url_pattern" json:"url_pattern"` // e.g. "POST /api/v1/login"
	Source     types.SourceRef `yaml:"source" json:"source"`
}

// ContextFile is the on-disk representation of a set of mappings, e.g. one
// produced by scanning jadx output or hand-authored to document an app's API.
type ContextFile struct {
	Mappings []Mapping `yaml:"mappings" json:"mappings"`
}
