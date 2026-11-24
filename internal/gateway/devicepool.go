package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/overkazaf/cap/internal/android"
)

// Injectable ADB hooks for network/device-free unit tests.
var (
	adbListDevicesFunc = android.ListDevices
	adbShellFunc       = android.AdbShell
)

var templateExprRe = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

// TemplateContext carries all dynamic values available during route template
// expansion (`{{input.*}}`, `{{device.*}}`, `{{env.*}}`, `{{timestamp}}`,
// `{{timestamp_ms}}`, `{{nonce}}`, `{{uuid}}`).
type TemplateContext struct {
	Input       map[string]string
	Device      *DeviceProfile
	Env         map[string]string
	Timestamp   int64
	TimestampMs int64
	Nonce       string
}

// DevicePool manages virtual fingerprint profiles and synced physical ADB
// devices with tag filtering, round-robin acquisition, and sticky proxy affinity.
type DevicePool struct {
	mu        sync.RWMutex
	devices   map[string]DeviceProfile
	rrCounter atomic.Uint64
}

// NewDevicePool creates an empty thread-safe DevicePool.
func NewDevicePool() *DevicePool {
	return &DevicePool{
		devices: make(map[string]DeviceProfile),
	}
}

// Load replaces all devices in the pool (used during persistence load).
func (d *DevicePool) Load(devices []DeviceProfile) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.devices = make(map[string]DeviceProfile, len(devices))
	for _, dev := range devices {
		if strings.TrimSpace(dev.ID) == "" {
			dev.ID = "dev-" + randomHex(4)
		}
		if dev.Kind == "" {
			dev.Kind = DeviceKindVirtual
		}
		dev.Tags = normalizeTags(dev.Tags)
		d.devices[dev.ID] = cloneDeviceProfile(dev)
	}
}

// List returns all device profiles sorted deterministically by name then ID.
func (d *DevicePool) List() []DeviceProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]DeviceProfile, 0, len(d.devices))
	for _, dev := range d.devices {
		out = append(out, cloneDeviceProfile(dev))
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get retrieves a device profile by ID.
func (d *DevicePool) Get(id string) (*DeviceProfile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	dev, ok := d.devices[strings.TrimSpace(id)]
	if !ok {
		return nil, false
	}
	cp := cloneDeviceProfile(dev)
	return &cp, true
}

// Upsert validates, normalizes, and stores a device profile.
func (d *DevicePool) Upsert(profile DeviceProfile) (*DeviceProfile, error) {
	profile.Name = strings.TrimSpace(profile.Name)
	profile.ID = strings.TrimSpace(profile.ID)
	if profile.Name == "" {
		if profile.Fingerprint.Model != "" {
			profile.Name = profile.Fingerprint.Model
		} else if profile.ADBSerial != "" {
			profile.Name = "ADB " + profile.ADBSerial
		} else {
			return nil, errors.New("device profile name is required")
		}
	}
	if profile.ID == "" {
		profile.ID = fmt.Sprintf("%s-%s", sanitizeID(profile.Name, "device"), randomHex(4))
	}
	switch strings.ToLower(strings.TrimSpace(profile.Kind)) {
	case DeviceKindPhysical:
		profile.Kind = DeviceKindPhysical
	default:
		profile.Kind = DeviceKindVirtual
	}
	profile.Tags = normalizeTags(profile.Tags)

	// Populate realistic unique identifiers for virtual profiles if left blank.
	if profile.Kind == DeviceKindVirtual {
		if profile.Fingerprint.DeviceID == "" {
			profile.Fingerprint.DeviceID = randomHex(8)
		}
		if profile.Fingerprint.AndroidID == "" {
			profile.Fingerprint.AndroidID = randomHex(8)
		}
		if profile.Fingerprint.OAID == "" {
			profile.Fingerprint.OAID = newUUID()
		}
	}

	now := nowRFC3339()
	d.mu.Lock()
	if prev, exists := d.devices[profile.ID]; exists {
		if profile.CreatedAt == "" {
			profile.CreatedAt = prev.CreatedAt
		}
		if profile.InUseCount == 0 {
			profile.InUseCount = prev.InUseCount
		}
		if profile.LastUsedAt == "" {
			profile.LastUsedAt = prev.LastUsedAt
		}
	}
	if profile.CreatedAt == "" {
		profile.CreatedAt = now
	}
	profile.UpdatedAt = now
	d.devices[profile.ID] = cloneDeviceProfile(profile)
	d.mu.Unlock()

	cp := cloneDeviceProfile(profile)
	return &cp, nil
}

// Delete removes a device profile by ID.
func (d *DevicePool) Delete(id string) error {
	id = strings.TrimSpace(id)
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.devices[id]; !ok {
		return fmt.Errorf("device %q not found", id)
	}
	delete(d.devices, id)
	return nil
}

// Counts returns (total, enabled) device counts.
func (d *DevicePool) Counts() (total int, enabled int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	total = len(d.devices)
	for _, dev := range d.devices {
		if dev.Enabled {
			enabled++
		}
	}
	return total, enabled
}

// CreateFromPreset creates and inserts a new virtual DeviceProfile from one of
// the built-in Android device presets with freshly randomized identifiers.
func (d *DevicePool) CreateFromPreset(presetID, name string, tags []string) (*DeviceProfile, error) {
	dev, err := GenerateVirtualDevice(presetID, name, tags)
	if err != nil {
		return nil, err
	}
	return d.Upsert(*dev)
}

// SeedDefaultPresets populates one virtual device per built-in preset when the
// pool is currently empty, returning the number of devices added.
func (d *DevicePool) SeedDefaultPresets() int {
	d.mu.RLock()
	empty := len(d.devices) == 0
	d.mu.RUnlock()
	if !empty {
		return 0
	}
	added := 0
	for _, preset := range BuiltinDevicePresets() {
		if _, err := d.CreateFromPreset(preset.ID, preset.Name, preset.Tags); err == nil {
			added++
		}
	}
	return added
}

// Acquire selects an enabled device profile matching explicitDeviceID (if set)
// or round-robin across enabled devices carrying all required tags.
// Usage counters and LastUsedAt are updated atomically.
func (d *DevicePool) Acquire(tags []string, explicitDeviceID string) (*DeviceProfile, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if id := strings.TrimSpace(explicitDeviceID); id != "" {
		dev, ok := d.devices[id]
		if !ok {
			return nil, fmt.Errorf("device %q not found", id)
		}
		if !dev.Enabled {
			return nil, fmt.Errorf("device %q is disabled", id)
		}
		dev.InUseCount++
		dev.LastUsedAt = nowRFC3339()
		d.devices[id] = dev
		cp := cloneDeviceProfile(dev)
		return &cp, nil
	}

	var candidates []DeviceProfile
	for _, dev := range d.devices {
		if !dev.Enabled {
			continue
		}
		if !hasAllTags(dev.Tags, tags) {
			continue
		}
		candidates = append(candidates, dev)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no enabled device profile available matching criteria")
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})

	idx := d.rrCounter.Add(1) - 1
	chosen := candidates[idx%uint64(len(candidates))]
	chosen.InUseCount++
	chosen.LastUsedAt = nowRFC3339()
	d.devices[chosen.ID] = chosen

	cp := cloneDeviceProfile(chosen)
	return &cp, nil
}

// StickyProxyFor returns the sticky proxy ID and preferred proxy region bound
// to device (or empty strings if none are configured).
func (d *DevicePool) StickyProxyFor(device *DeviceProfile) (proxyID string, region string) {
	if device == nil {
		return "", ""
	}
	return strings.TrimSpace(device.StickyProxyID), strings.TrimSpace(device.ProxyRegion)
}

// SyncADBDevices discovers connected, authorized physical Android devices via
// ADB, probes their hardware/OS fingerprint properties, and upserts them into
// the pool while preserving existing sticky proxy bindings and session tokens.
func (d *DevicePool) SyncADBDevices(ctx context.Context) ([]DeviceProfile, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	connected, err := adbListDevicesFunc()
	if err != nil {
		return nil, fmt.Errorf("list adb devices: %w", err)
	}

	var synced []DeviceProfile
	for _, dev := range connected {
		if err := ctx.Err(); err != nil {
			return synced, err
		}
		if dev.State != "device" {
			continue
		}
		fp := probeADBDeviceFingerprint(dev.Serial)
		id := "adb-" + sanitizeID(dev.Serial, "device")

		profile := DeviceProfile{
			ID:          id,
			Name:        buildPhysicalDeviceName(fp.Brand, fp.Model, dev.Serial),
			Kind:        DeviceKindPhysical,
			ADBSerial:   dev.Serial,
			Enabled:     true,
			Tags:        []string{"physical", "adb"},
			Fingerprint: fp,
		}

		// Preserve user-configured bindings & cookies/tokens if already synced before.
		if existing, ok := d.Get(id); ok {
			profile.StickyProxyID = existing.StickyProxyID
			profile.ProxyRegion = existing.ProxyRegion
			profile.Cookies = existing.Cookies
			profile.AuthHeaders = existing.AuthHeaders
			profile.Tokens = existing.Tokens
			profile.Tags = normalizeTags(append(existing.Tags, "physical", "adb"))
			if existing.Fingerprint.OAID != "" && profile.Fingerprint.OAID == "" {
				profile.Fingerprint.OAID = existing.Fingerprint.OAID
			}
		}

		saved, err := d.Upsert(profile)
		if err != nil {
			continue
		}
		synced = append(synced, *saved)
	}

	return synced, nil
}

func buildPhysicalDeviceName(brand, model, serial string) string {
	b := strings.TrimSpace(brand)
	m := strings.TrimSpace(model)
	switch {
	case b != "" && m != "" && !strings.HasPrefix(strings.ToLower(m), strings.ToLower(b)):
		return fmt.Sprintf("%s %s (%s)", b, m, serial)
	case m != "":
		return fmt.Sprintf("%s (%s)", m, serial)
	default:
		return "Android " + serial
	}
}

func probeADBDeviceFingerprint(serial string) DeviceFingerprint {
	script := strings.Join([]string{
		"echo MODEL=$(getprop ro.product.model)",
		"echo BRAND=$(getprop ro.product.brand)",
		"echo RELEASE=$(getprop ro.build.version.release)",
		"echo SDK=$(getprop ro.build.version.sdk)",
		"echo LOCALE=$(getprop persist.sys.locale)",
		"echo LOCALE2=$(getprop ro.product.locale)",
		"echo TZ=$(getprop persist.sys.timezone)",
		"echo ANDROID_ID=$(settings get secure android_id 2>/dev/null)",
		"echo SCREEN=$(wm size 2>/dev/null | tail -n 1)",
	}, "; ")

	out, _ := adbShellFunc(serial, script)
	kv := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" || v == "null" {
			continue
		}
		kv[strings.TrimSpace(k)] = v
	}

	model := kv["MODEL"]
	if model == "" {
		model = "Android"
	}
	brand := kv["BRAND"]
	if brand == "" {
		brand = "Android"
	}
	release := kv["RELEASE"]
	if release == "" {
		release = "14"
	}
	sdk, _ := strconv.Atoi(kv["SDK"])
	if sdk <= 0 {
		sdk = 34
	}
	locale := kv["LOCALE"]
	if locale == "" {
		locale = kv["LOCALE2"]
	}
	if locale == "" {
		locale = "en_US"
	}
	tz := kv["TZ"]
	if tz == "" {
		tz = "UTC"
	}
	screen := parseWMSize(kv["SCREEN"])
	androidID := kv["ANDROID_ID"]

	ua := fmt.Sprintf("Mozilla/5.0 (Linux; Android %s; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36", release, model)
	return DeviceFingerprint{
		Model:     model,
		Brand:     brand,
		OSVersion: release,
		SDK:       sdk,
		UserAgent: ua,
		DeviceID:  serial,
		AndroidID: androidID,
		Locale:    strings.ReplaceAll(locale, "-", "_"),
		Timezone:  tz,
		Screen:    screen,
	}
}

func parseWMSize(raw string) string {
	// Typical output: "Physical size: 1080x2400"
	if idx := strings.LastIndex(raw, ":"); idx >= 0 {
		return strings.TrimSpace(raw[idx+1:])
	}
	return strings.TrimSpace(raw)
}

// BuiltinDevicePresets returns realistic curated Android device fingerprint
// presets ready to instantiate virtual devices.
func BuiltinDevicePresets() []DevicePreset {
	return []DevicePreset{
		{
			ID:   "pixel-8-pro",
			Name: "Google Pixel 8 Pro",
			Tags: []string{"virtual", "android14", "google", "global"},
			Fingerprint: DeviceFingerprint{
				Model:     "Pixel 8 Pro",
				Brand:     "Google",
				OSVersion: "14",
				SDK:       34,
				UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/AP2A.240805.005) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
				Locale:    "en_US",
				Timezone:  "America/Los_Angeles",
				Screen:    "1344x2992",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "Pixel 8 Pro",
				},
			},
		},
		{
			ID:   "xiaomi-14",
			Name: "Xiaomi 14",
			Tags: []string{"virtual", "android14", "xiaomi", "cn"},
			Fingerprint: DeviceFingerprint{
				Model:     "23127PN0CC",
				Brand:     "Xiaomi",
				OSVersion: "14",
				SDK:       34,
				UserAgent: "Mozilla/5.0 (Linux; Android 14; 23127PN0CC Build/UKQ1.230804.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36",
				Locale:    "zh_CN",
				Timezone:  "Asia/Shanghai",
				Screen:    "1200x2670",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "23127PN0CC",
				},
			},
		},
		{
			ID:   "samsung-s24",
			Name: "Samsung Galaxy S24",
			Tags: []string{"virtual", "android14", "samsung", "global"},
			Fingerprint: DeviceFingerprint{
				Model:     "SM-S921B",
				Brand:     "samsung",
				OSVersion: "14",
				SDK:       34,
				UserAgent: "Mozilla/5.0 (Linux; Android 14; SM-S921B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.103 Mobile Safari/537.36",
				Locale:    "en_US",
				Timezone:  "America/New_York",
				Screen:    "1080x2340",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "SM-S921B",
				},
			},
		},
		{
			ID:   "oneplus-12",
			Name: "OnePlus 12",
			Tags: []string{"virtual", "android14", "oneplus", "cn"},
			Fingerprint: DeviceFingerprint{
				Model:     "PJD110",
				Brand:     "OnePlus",
				OSVersion: "14",
				SDK:       34,
				UserAgent: "Mozilla/5.0 (Linux; Android 14; PJD110 Build/UKQ1.230924.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.84 Mobile Safari/537.36",
				Locale:    "zh_CN",
				Timezone:  "Asia/Shanghai",
				Screen:    "1440x3168",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "PJD110",
				},
			},
		},
		{
			ID:   "huawei-mate60-pro",
			Name: "HUAWEI Mate 60 Pro",
			Tags: []string{"virtual", "huawei", "cn"},
			Fingerprint: DeviceFingerprint{
				Model:     "ALN-AL00",
				Brand:     "HUAWEI",
				OSVersion: "12",
				SDK:       31,
				UserAgent: "Mozilla/5.0 (Linux; Android 12; ALN-AL00 Build/HUAWEIALN-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Mobile Safari/537.36",
				Locale:    "zh_CN",
				Timezone:  "Asia/Shanghai",
				Screen:    "1260x2720",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "ALN-AL00",
				},
			},
		},
		{
			ID:   "pixel-7",
			Name: "Google Pixel 7",
			Tags: []string{"virtual", "android13", "google", "eu"},
			Fingerprint: DeviceFingerprint{
				Model:     "Pixel 7",
				Brand:     "Google",
				OSVersion: "13",
				SDK:       33,
				UserAgent: "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230901.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
				Locale:    "en_GB",
				Timezone:  "Europe/London",
				Screen:    "1080x2400",
				ExtraHeaders: map[string]string{
					"Sec-CH-UA-Mobile":   "?1",
					"Sec-CH-UA-Platform": `"Android"`,
					"X-Device-Model":     "Pixel 7",
				},
			},
		},
	}
}

// GenerateVirtualDevice instantiates a DeviceProfile from a built-in preset ID
// with fresh randomized DeviceID, AndroidID, and OAID values.
func GenerateVirtualDevice(presetID, name string, tags []string) (*DeviceProfile, error) {
	presetID = strings.ToLower(strings.TrimSpace(presetID))
	var chosen *DevicePreset
	for _, p := range BuiltinDevicePresets() {
		if strings.EqualFold(p.ID, presetID) || strings.EqualFold(p.Name, presetID) {
			cp := p
			chosen = &cp
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("unknown device preset %q", presetID)
	}

	fp := chosen.Fingerprint
	fp.ExtraHeaders = cloneStringMap(chosen.Fingerprint.ExtraHeaders)
	fp.DeviceID = randomHex(8)
	fp.AndroidID = randomHex(8)
	fp.OAID = newUUID()

	devName := strings.TrimSpace(name)
	if devName == "" {
		devName = fmt.Sprintf("%s #%s", chosen.Name, randomHex(2))
	}
	mergedTags := normalizeTags(append(cloneStringSlice(chosen.Tags), tags...))
	now := nowRFC3339()

	return &DeviceProfile{
		ID:          fmt.Sprintf("%s-%s", sanitizeID(chosen.ID, "virtual"), randomHex(4)),
		Name:        devName,
		Kind:        DeviceKindVirtual,
		Enabled:     true,
		Tags:        mergedTags,
		Fingerprint: fp,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// RenderTemplate expands `{{...}}` placeholders in tmpl using vars:
//   - `{{input.<key>}}`
//   - `{{device.<field>}}`, `{{device.token.<key>}}`, `{{device.cookie.<key>}}`, `{{device.header.<key>}}`
//   - `{{env.<key>}}`
//   - `{{timestamp}}`, `{{timestamp_ms}}`, `{{nonce}}`, `{{uuid}}`
func RenderTemplate(tmpl string, vars TemplateContext) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	now := time.Now()
	ts := vars.Timestamp
	if ts == 0 {
		ts = now.Unix()
	}
	tsMs := vars.TimestampMs
	if tsMs == 0 {
		tsMs = now.UnixMilli()
	}
	nonce := vars.Nonce
	if nonce == "" {
		nonce = randomHex(8)
	}

	return templateExprRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		sub := templateExprRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		expr := strings.TrimSpace(sub[1])
		if val, ok := resolveTemplateExpr(expr, vars, ts, tsMs, nonce); ok {
			return val
		}
		return ""
	})
}

func resolveTemplateExpr(expr string, vars TemplateContext, ts, tsMs int64, nonce string) (string, bool) {
	lower := strings.ToLower(expr)
	switch lower {
	case "timestamp", "ts":
		return strconv.FormatInt(ts, 10), true
	case "timestamp_ms", "ts_ms":
		return strconv.FormatInt(tsMs, 10), true
	case "nonce":
		return nonce, true
	case "uuid":
		return newUUID(), true
	}

	if key, ok := cutPrefixFold(expr, "input."); ok {
		if vars.Input != nil {
			if v, exists := vars.Input[key]; exists {
				return v, true
			}
		}
		return "", true
	}

	if key, ok := cutPrefixFold(expr, "env."); ok {
		if vars.Env != nil {
			if v, exists := vars.Env[key]; exists {
				return v, true
			}
		}
		// Only expose explicitly prefixed CAP_GW_* host environment variables to
		// prevent accidental exfiltration of unrelated host secrets.
		if strings.HasPrefix(strings.ToUpper(key), "CAP_GW_") {
			return os.Getenv(key), true
		}
		return "", true
	}

	if field, ok := cutPrefixFold(expr, "device."); ok {
		return resolveDeviceField(vars.Device, field), true
	}

	return "", false
}

func resolveDeviceField(dev *DeviceProfile, field string) string {
	if dev == nil {
		return ""
	}
	if key, ok := cutPrefixFold(field, "token."); ok {
		return dev.Tokens[key]
	}
	if key, ok := cutPrefixFold(field, "tokens."); ok {
		return dev.Tokens[key]
	}
	if key, ok := cutPrefixFold(field, "cookie."); ok {
		return dev.Cookies[key]
	}
	if key, ok := cutPrefixFold(field, "cookies."); ok {
		return dev.Cookies[key]
	}
	if key, ok := cutPrefixFold(field, "header."); ok {
		return lookupMapFold(dev.AuthHeaders, key)
	}
	if key, ok := cutPrefixFold(field, "auth."); ok {
		return lookupMapFold(dev.AuthHeaders, key)
	}
	if key, ok := cutPrefixFold(field, "extra."); ok {
		return lookupMapFold(dev.Fingerprint.ExtraHeaders, key)
	}

	switch strings.ToLower(field) {
	case "id":
		return dev.ID
	case "name":
		return dev.Name
	case "kind":
		return dev.Kind
	case "adb_serial", "serial":
		return dev.ADBSerial
	case "sticky_proxy_id":
		return dev.StickyProxyID
	case "proxy_region":
		return dev.ProxyRegion
	case "model":
		return dev.Fingerprint.Model
	case "brand":
		return dev.Fingerprint.Brand
	case "os_version", "os":
		return dev.Fingerprint.OSVersion
	case "sdk":
		if dev.Fingerprint.SDK > 0 {
			return strconv.Itoa(dev.Fingerprint.SDK)
		}
		return ""
	case "user_agent", "ua":
		return dev.Fingerprint.UserAgent
	case "device_id":
		return dev.Fingerprint.DeviceID
	case "android_id":
		return dev.Fingerprint.AndroidID
	case "oaid":
		return dev.Fingerprint.OAID
	case "locale":
		return dev.Fingerprint.Locale
	case "timezone", "tz":
		return dev.Fingerprint.Timezone
	case "screen":
		return dev.Fingerprint.Screen
	default:
		return ""
	}
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) {
		return "", false
	}
	if strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func lookupMapFold(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// ExtractTemplateInputKeys scans template strings and returns a sorted,
// deduplicated slice of all `{{input.<key>}}` variable names referenced.
func ExtractTemplateInputKeys(sources ...string) []string {
	seen := make(map[string]struct{})
	for _, src := range sources {
		if !strings.Contains(src, "{{") {
			continue
		}
		matches := templateExprRe.FindAllStringSubmatch(src, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			if key, ok := cutPrefixFold(strings.TrimSpace(m[1]), "input."); ok && key != "" {
				seen[key] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TemplateUsesDevice reports whether any template string references `{{device.*}}`.
func TemplateUsesDevice(sources ...string) bool {
	for _, src := range sources {
		if !strings.Contains(src, "{{") {
			continue
		}
		matches := templateExprRe.FindAllStringSubmatch(src, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				if _, ok := cutPrefixFold(strings.TrimSpace(m[1]), "device."); ok {
					return true
				}
			}
		}
	}
	return false
}

var (
	safeAuthorityExpansionRe = regexp.MustCompile(`^[a-zA-Z0-9._:-]*$`)
	jsonNumberRe             = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
)

// ValidateRouteURLTemplate checks that a route's UpstreamURL template uses an
// http or https scheme and has a valid host structure.
func ValidateRouteURLTemplate(rawTemplate string) error {
	rawTemplate = strings.TrimSpace(rawTemplate)
	if rawTemplate == "" {
		return errors.New("upstream_url is required")
	}
	sentinelRaw := templateExprRe.ReplaceAllString(rawTemplate, "capplaceholder")
	_, err := validateHTTPURL(sentinelRaw)
	return err
}

// RenderURLTemplate expands `{{...}}` placeholders in a route URL template
// safely:
//   - Only http/https schemes are permitted.
//   - Template expansions in URL path segments are escaped via url.PathEscape
//     (and "." / ".." traversal segments are percent-encoded).
//   - Template expansions in URL query strings are escaped via url.QueryEscape.
//   - Template expansions inside authority/host portions reject authority
//     delimiters (`@`, `/`, `?`, `#`, `\`, whitespace) to prevent host hijack.
//   - Non-templated (fixed) scheme and host components in rawTemplate are
//     verified unchanged after expansion.
func RenderURLTemplate(rawTemplate string, vars TemplateContext) (*url.URL, error) {
	rawTemplate = strings.TrimSpace(rawTemplate)
	if rawTemplate == "" {
		return nil, errors.New("upstream URL is empty")
	}

	const sentinel = "capplaceholder"
	sentinelRaw := templateExprRe.ReplaceAllString(rawTemplate, sentinel)
	tmplURL, err := validateHTTPURL(sentinelRaw)
	if err != nil {
		return nil, err
	}
	schemeFixed := !strings.Contains(tmplURL.Scheme, sentinel)
	hostFixed := !strings.Contains(tmplURL.Host, sentinel)
	userFixed := tmplURL.User == nil || !strings.Contains(tmplURL.User.String(), sentinel)

	now := time.Now()
	ts := vars.Timestamp
	if ts == 0 {
		ts = now.Unix()
	}
	tsMs := vars.TimestampMs
	if tsMs == 0 {
		tsMs = now.UnixMilli()
	}
	nonce := vars.Nonce
	if nonce == "" {
		nonce = randomHex(8)
	}

	schemeIdx := strings.Index(rawTemplate, "://")
	if schemeIdx < 0 {
		return nil, errors.New("upstream URL must include http:// or https:// scheme")
	}
	schemePart := rawTemplate[:schemeIdx]
	rest := rawTemplate[schemeIdx+3:]

	authEnd := strings.IndexAny(rest, "/?#")
	var authorityPart, tail string
	if authEnd < 0 {
		authorityPart = rest
	} else {
		authorityPart = rest[:authEnd]
		tail = rest[authEnd:]
	}

	var pathPart, queryPart, fragPart string
	hasQuery := false
	hasFrag := false
	if hashIdx := strings.IndexByte(tail, '#'); hashIdx >= 0 {
		fragPart = tail[hashIdx+1:]
		tail = tail[:hashIdx]
		hasFrag = true
	}
	if qIdx := strings.IndexByte(tail, '?'); qIdx >= 0 {
		queryPart = tail[qIdx+1:]
		pathPart = tail[:qIdx]
		hasQuery = true
	} else {
		pathPart = tail
	}

	expandWith := func(part string, transform func(string) (string, error)) (string, error) {
		if !strings.Contains(part, "{{") {
			return part, nil
		}
		var out strings.Builder
		last := 0
		for _, loc := range templateExprRe.FindAllStringSubmatchIndex(part, -1) {
			out.WriteString(part[last:loc[0]])
			expr := strings.TrimSpace(part[loc[2]:loc[3]])
			val, ok := resolveTemplateExpr(expr, vars, ts, tsMs, nonce)
			if !ok {
				val = ""
			}
			safeVal, err := transform(val)
			if err != nil {
				return "", err
			}
			out.WriteString(safeVal)
			last = loc[1]
		}
		out.WriteString(part[last:])
		return out.String(), nil
	}

	renderedScheme, err := expandWith(schemePart, func(v string) (string, error) {
		s := strings.ToLower(strings.TrimSpace(v))
		if s != "http" && s != "https" {
			return "", fmt.Errorf("disallowed URL scheme %q", v)
		}
		return s, nil
	})
	if err != nil {
		return nil, err
	}

	renderedAuthority, err := expandWith(authorityPart, func(v string) (string, error) {
		if !safeAuthorityExpansionRe.MatchString(v) {
			return "", fmt.Errorf("unsafe characters in host template expansion %q", redactSecrets(v))
		}
		return v, nil
	})
	if err != nil {
		return nil, err
	}

	renderedPath, err := expandWith(pathPart, func(v string) (string, error) {
		esc := url.PathEscape(v)
		switch esc {
		case ".":
			return "%2E", nil
		case "..":
			return "%2E%2E", nil
		default:
			return esc, nil
		}
	})
	if err != nil {
		return nil, err
	}

	renderedQuery, err := expandWith(queryPart, func(v string) (string, error) {
		return url.QueryEscape(v), nil
	})
	if err != nil {
		return nil, err
	}

	renderedFrag, err := expandWith(fragPart, func(v string) (string, error) {
		return url.QueryEscape(v), nil
	})
	if err != nil {
		return nil, err
	}

	var rebuilt strings.Builder
	rebuilt.WriteString(renderedScheme)
	rebuilt.WriteString("://")
	rebuilt.WriteString(renderedAuthority)
	rebuilt.WriteString(renderedPath)
	if hasQuery {
		rebuilt.WriteByte('?')
		rebuilt.WriteString(renderedQuery)
	}
	if hasFrag {
		rebuilt.WriteByte('#')
		rebuilt.WriteString(renderedFrag)
	}

	parsed, err := validateHTTPURL(rebuilt.String())
	if err != nil {
		return nil, err
	}
	if schemeFixed && !strings.EqualFold(parsed.Scheme, tmplURL.Scheme) {
		return nil, fmt.Errorf("rendered URL scheme %q changed fixed scheme %q", parsed.Scheme, tmplURL.Scheme)
	}
	if hostFixed && !strings.EqualFold(parsed.Host, tmplURL.Host) {
		return nil, fmt.Errorf("rendered URL host %q changed fixed host %q", parsed.Host, tmplURL.Host)
	}
	if userFixed && tmplURL.User == nil && parsed.User != nil {
		return nil, errors.New("rendered URL unexpectedly introduced userinfo")
	}
	return parsed, nil
}

// RenderJSONTemplate expands `{{...}}` placeholders inside a JSON body template
// while preventing JSON structure injection:
//   - Expansions inside JSON string literals (`"..."`) have quotes, backslashes,
//     and control characters JSON-escaped.
//   - Expansions outside JSON string literals remain unquoted only if they are
//     valid JSON numbers/booleans/null, otherwise they are JSON-quoted.
func RenderJSONTemplate(tmpl string, vars TemplateContext) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	now := time.Now()
	ts := vars.Timestamp
	if ts == 0 {
		ts = now.Unix()
	}
	tsMs := vars.TimestampMs
	if tsMs == 0 {
		tsMs = now.UnixMilli()
	}
	nonce := vars.Nonce
	if nonce == "" {
		nonce = randomHex(8)
	}

	var out strings.Builder
	last := 0
	inString := false
	escaped := false

	advanceJSONState := func(chunk string) {
		for i := 0; i < len(chunk); i++ {
			ch := chunk[i]
			if inString {
				if escaped {
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
				} else if ch == '"' {
					inString = false
				}
			} else if ch == '"' {
				inString = true
			}
		}
	}

	for _, loc := range templateExprRe.FindAllStringSubmatchIndex(tmpl, -1) {
		chunk := tmpl[last:loc[0]]
		out.WriteString(chunk)
		advanceJSONState(chunk)

		expr := strings.TrimSpace(tmpl[loc[2]:loc[3]])
		val, ok := resolveTemplateExpr(expr, vars, ts, tsMs, nonce)
		if !ok {
			val = ""
		}

		if inString {
			out.WriteString(escapeJSONStringContent(val))
		} else if isSafeJSONLiteral(val) {
			out.WriteString(val)
		} else {
			out.WriteString(jsonStringLiteral(val))
		}
		last = loc[1]
	}
	out.WriteString(tmpl[last:])
	return out.String()
}

func escapeJSONStringContent(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

func isSafeJSONLiteral(s string) bool {
	trimmed := strings.TrimSpace(s)
	switch trimmed {
	case "true", "false", "null":
		return true
	default:
		return jsonNumberRe.MatchString(trimmed)
	}
}
