package i18n

import (
	"sync"
	"testing"
)

func TestLocaleParsingAndEnvDetection(t *testing.T) {
	cases := []struct {
		in   string
		want Locale
		ok   bool
	}{
		{"en", EN, true},
		{"en-US", EN, true},
		{"en_GB.UTF-8", EN, true},
		{"zh", ZH, true},
		{"zh-CN", ZH, true},
		{"zh_CN.UTF-8", ZH, true},
		{"zh-Hans", ZH, true},
		{"fr", EN, false},
		{"", EN, false},
	}
	for _, tc := range cases {
		got, ok := ParseLocale(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseLocale(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	t.Setenv("CAP_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "zh_CN.UTF-8")
	if got := DetectFromEnv(); got != ZH {
		t.Fatalf("DetectFromEnv(LANG=zh_CN.UTF-8) = %q, want zh", got)
	}

	// CAP_LANG overrides LANG.
	t.Setenv("CAP_LANG", "en")
	if got := DetectFromEnv(); got != EN {
		t.Fatalf("DetectFromEnv(CAP_LANG=en) = %q, want en", got)
	}
}

func TestCatalogKeyParityAndFallback(t *testing.T) {
	enKeys := Keys(EN)
	zhKeys := Keys(ZH)

	if len(enKeys) == 0 {
		t.Fatal("EN catalog is empty")
	}

	enSet := make(map[string]bool, len(enKeys))
	for _, k := range enKeys {
		enSet[k] = true
		if catalogs[ZH][k] == "" {
			t.Errorf("missing ZH translation for key %q", k)
		}
	}
	for _, k := range zhKeys {
		if !enSet[k] {
			t.Errorf("extra ZH key %q not present in EN catalog", k)
		}
	}

	// Fallback returns key itself when missing from all catalogs.
	if got := TLocale(ZH, "nonexistent.key"); got != "nonexistent.key" {
		t.Fatalf("missing key fallback = %q, want key itself", got)
	}

	// Formatting works in both languages.
	if got := TLocale(EN, "tui.header.err", 3); got != "3 err" {
		t.Fatalf("EN format = %q", got)
	}
	if got := TLocale(ZH, "tui.header.err", 3); got != "3 错误" {
		t.Fatalf("ZH format = %q", got)
	}
}

func TestToggleAndConcurrency(t *testing.T) {
	orig := Lang()
	defer SetLang(string(orig))

	SetLang("en")
	if ToggleLang() != ZH {
		t.Fatal("expected ToggleLang to switch en -> zh")
	}
	if ToggleLang() != EN {
		t.Fatal("expected ToggleLang to switch zh -> en")
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if (i+j)%2 == 0 {
					SetLang("zh-CN")
				} else {
					SetLang("en")
				}
				_ = T("tui.mode.live")
			}
		}(i)
	}
	wg.Wait()
}
