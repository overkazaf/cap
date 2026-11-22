// Package i18n provides zero-dependency, thread-safe multi-language
// localization (English and Simplified Chinese, extensible to additional
// locales) for cap's TUI and CLI.
package i18n

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Locale identifies a supported UI language.
type Locale string

const (
	EN Locale = "en"
	ZH Locale = "zh"
)

var (
	mu            sync.RWMutex
	currentLocale Locale = DetectFromEnv()
)

// SupportedLocales returns all supported locale codes in canonical order.
func SupportedLocales() []Locale {
	return []Locale{EN, ZH}
}

// ParseLocale parses a user-supplied language code (e.g. "en", "en-US", "zh",
// "zh-CN", "zh_CN", "zh-Hans"). Returns (locale, true) on match, or (EN, false)
// if unrecognized.
func ParseLocale(raw string) (Locale, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return EN, false
	}
	// Strip POSIX encoding/modifier suffix such as ".UTF-8" or "@euro".
	if idx := strings.IndexAny(s, ".@"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.ReplaceAll(s, "_", "-")
	switch {
	case s == "en" || strings.HasPrefix(s, "en-"):
		return EN, true
	case s == "zh" || strings.HasPrefix(s, "zh-"):
		return ZH, true
	default:
		return EN, false
	}
}

// Normalize maps any locale string to a supported Locale, defaulting to EN.
func Normalize(raw string) Locale {
	loc, ok := ParseLocale(raw)
	if !ok {
		return EN
	}
	return loc
}

// DetectFromEnv inspects CAP_LANG, LC_ALL, LC_MESSAGES, and LANG (in that
// priority order) and returns ZH when a Chinese locale is configured, or EN
// otherwise.
func DetectFromEnv() Locale {
	for _, envKey := range []string{"CAP_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		val := strings.TrimSpace(os.Getenv(envKey))
		if val == "" || strings.EqualFold(val, "C") || strings.EqualFold(val, "POSIX") {
			continue
		}
		if loc, ok := ParseLocale(val); ok {
			return loc
		}
	}
	return EN
}

// SetLang updates the process-wide active locale and returns the normalized Locale.
func SetLang(code string) Locale {
	loc := Normalize(code)
	mu.Lock()
	currentLocale = loc
	mu.Unlock()
	return loc
}

// Lang returns the current active locale.
func Lang() Locale {
	mu.RLock()
	loc := currentLocale
	mu.RUnlock()
	return loc
}

// ToggleLang switches between EN and ZH and returns the newly active locale.
func ToggleLang() Locale {
	mu.Lock()
	if currentLocale == ZH {
		currentLocale = EN
	} else {
		currentLocale = ZH
	}
	loc := currentLocale
	mu.Unlock()
	return loc
}

// ShortLabel returns a compact display badge for loc ("EN" or "中文").
func (l Locale) ShortLabel() string {
	if l == ZH {
		return "中文"
	}
	return "EN"
}

// NativeName returns the native display name for loc.
func (l Locale) NativeName() string {
	if l == ZH {
		return "简体中文"
	}
	return "English"
}

// T looks up key in the current active locale (falling back to EN, then key)
// and formats it with args when args is non-empty.
func T(key string, args ...any) string {
	return TLocale(Lang(), key, args...)
}

// TLocale looks up key in loc (falling back to EN, then key) and formats it
// with args when args is non-empty.
func TLocale(loc Locale, key string, args ...any) string {
	tmpl := lookup(loc, key)
	if len(args) > 0 {
		return fmt.Sprintf(tmpl, args...)
	}
	return tmpl
}

func lookup(loc Locale, key string) string {
	if table, ok := catalogs[loc]; ok {
		if val, found := table[key]; found {
			return val
		}
	}
	if val, found := catalogs[EN][key]; found {
		return val
	}
	return key
}

// Keys returns the sorted list of translation keys defined for loc.
func Keys(loc Locale) []string {
	table := catalogs[loc]
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
