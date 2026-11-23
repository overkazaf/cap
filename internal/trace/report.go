package trace

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/overkazaf/cap/internal/types"
)

const (
	maxGraphNodes       = 28
	maxParamRefsPerItem = 8
	maxModuleKeySymbols = 6
)

// TraceReport is a commercial-grade, evidence-backed architectural synthesis of
// a DeepTrace run answering: how the HTTP request originated, which modules and
// native libraries participated, where sensitive/signature parameters are
// produced, and how the call flow looks across 3 graph perspectives.
type TraceReport struct {
	Confidence        string          `json:"confidence"`          // "high" | "medium" | "low"
	ConfidenceScore   int             `json:"confidence_score"`    // 0..100
	ConfidenceReasons []string        `json:"confidence_reasons"`  // why this score was awarded
	ExecutiveSummary  string          `json:"executive_summary"`   // multi-sentence narrative
	Highlights        []string        `json:"highlights"`          // 3-6 crisp bullet findings
	RequestAnatomy    RequestAnatomy  `json:"request_anatomy"`     // structured HTTP breakdown
	OriginChain       []OriginHop     `json:"origin_chain"`        // ordered Entry -> ... -> HTTP
	Modules           []ModuleSummary `json:"modules"`             // architectural module cards
	ParamProvenance   []ParamTrace    `json:"param_provenance"`    // sign/auth/query param refs
	Graph             GraphModel      `json:"graph"`               // typed DAG + UML sequence
	SecurityPosture   SecurityPosture `json:"security_posture"`    // APK & transport posture
	Markdown          string          `json:"markdown"`            // export-ready Markdown report
}

// RequestAnatomy summarizes the traced HTTP flow's wire-level anatomy.
type RequestAnatomy struct {
	Method       string         `json:"method"`
	Scheme       string         `json:"scheme"`
	Host         string         `json:"host"`
	Path         string         `json:"path"`
	Status       int            `json:"status"`
	LatencyMs    int64          `json:"latency_ms"`
	ReqBodySize  int            `json:"req_body_size"`
	RespBodySize int            `json:"resp_body_size"`
	ContentType  string         `json:"content_type"`
	QueryParams  []AnatomyParam `json:"query_params"`
	KeyHeaders   []AnatomyParam `json:"key_headers"`
}

// AnatomyParam describes one query parameter or key HTTP header.
type AnatomyParam struct {
	Name        string `json:"name"`
	SampleValue string `json:"sample_value"`
	IsSignParam bool   `json:"is_sign_param"`
	Role        string `json:"role"` // "sign" | "auth" | "timestamp" | "identifier" | "pagination" | "param"
}

// OriginHop represents one chronological architectural hop in how the request
// was constructed and dispatched.
type OriginHop struct {
	Step       int    `json:"step"`
	Layer      string `json:"layer"` // "entry" | "business" | "network" | "crypto" | "native" | "http"
	Title      string `json:"title"`
	Module     string `json:"module"`
	Symbol     string `json:"symbol"`
	File       string `json:"file"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"` // "high" | "medium" | "low"
	Detail     string `json:"detail"`
}

// ModuleSummary aggregates classes, methods, and native libraries into an
// architectural module grouped by layer & package prefix.
type ModuleSummary struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Layer         string   `json:"layer"` // "entry" | "business" | "network" | "crypto" | "native" | "sdk" | "http"
	PackagePrefix string   `json:"package_prefix"`
	Role          string   `json:"role"`
	ClassCount    int      `json:"class_count"`
	MethodCount   int      `json:"method_count"`
	NativeLibs    []string `json:"native_libs,omitempty"`
	KeySymbols    []string `json:"key_symbols"`
	MatchedTerms  []string `json:"matched_terms"`
	EvidenceCount int      `json:"evidence_count"`
	Confidence    string   `json:"confidence"` // "high" | "medium" | "low"
}

// ParamTrace tracks where a specific sign/auth/query/header parameter appears
// across DEX bytecode, DEX strings, Java source, and native libraries.
type ParamTrace struct {
	Name        string     `json:"name"`
	Location    string     `json:"location"` // "query" | "header" | "body" | "sign"
	Role        string     `json:"role"`     // "sign" | "auth" | "timestamp" | "identifier" | "pagination" | "param"
	SampleValue string     `json:"sample_value"`
	HitCount    int        `json:"hit_count"`
	References  []ParamRef `json:"references"`
}

// ParamRef is a single concrete code or binary reference to a parameter.
type ParamRef struct {
	Source  string `json:"source"` // "dex_bytecode" | "dex_string" | "java" | "native"
	Symbol  string `json:"symbol"`
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// GraphModel feeds all 3 perspectives in TraceGraph.svelte: Execution Flow DAG,
// Module Architecture view, and UML Sequence Timeline.
type GraphModel struct {
	Nodes    []GraphNode    `json:"nodes"`
	Edges    []GraphEdge    `json:"edges"`
	Sequence []SequenceStep `json:"sequence"`
}

// GraphNode is a typed node in the Execution Flow and Module graphs.
type GraphNode struct {
	ID            string   `json:"id"`
	Label         string   `json:"label"`
	Sublabel      string   `json:"sublabel,omitempty"`
	Layer         string   `json:"layer"` // "entry" | "business" | "network" | "crypto" | "native" | "http"
	ModuleID      string   `json:"module_id"`
	Kind          string   `json:"kind"` // "activity" | "class" | "method" | "sdk" | "native_lib" | "native_fn" | "endpoint"
	Confidence    string   `json:"confidence"`
	EvidenceCount int      `json:"evidence_count"`
	Details       []string `json:"details,omitempty"`
	MatchedTerms  []string `json:"matched_terms,omitempty"`
	File          string   `json:"file,omitempty"`
}

// GraphEdge is a typed directed dependency between two GraphNodes.
type GraphEdge struct {
	ID     string `json:"id"`
	From   string `json:"from"`
	To     string `json:"to"`
	Type   string `json:"type"` // "call" | "builds_request" | "signs" | "loads_so" | "jni" | "native_call" | "http"
	Label  string `json:"label,omitempty"`
	Weight int    `json:"weight"`
}

// SequenceStep is one chronological interaction in the UML Sequence perspective.
type SequenceStep struct {
	Order     int    `json:"order"`
	From      string `json:"from"`
	FromLayer string `json:"from_layer"`
	To        string `json:"to"`
	ToLayer   string `json:"to_layer"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	Evidence  string `json:"evidence,omitempty"`
}

// SecurityPosture summarizes APK hardening, transport stack, crypto signals,
// and obfuscation indicators.
type SecurityPosture struct {
	MinSDK           string   `json:"min_sdk"`
	TargetSDK        string   `json:"target_sdk"`
	HasNSConfig      bool     `json:"has_ns_config"`
	PermissionsCount int      `json:"permissions_count"`
	NetworkStack     []string `json:"network_stack"`
	CryptoIndicators []string `json:"crypto_indicators"`
	NativeLibCount   int      `json:"native_lib_count"`
	DexCount         int      `json:"dex_count"`
	ObfuscationHint  string   `json:"obfuscation_hint"` // "none" | "moderate" | "heavy"
	Notes            []string `json:"notes"`
}

// SynthesizeReport builds a complete commercial-grade TraceReport from the
// collected TraceResult evidence (working seamlessly both with and without jadx).
func SynthesizeReport(flow *types.Flow, res *TraceResult, xref *DexXRefResult) *TraceReport {
	if flow == nil {
		flow = &types.Flow{}
	}
	if res == nil {
		res = &TraceResult{}
	}

	anatomy := buildRequestAnatomy(flow)
	modules := buildModuleSummaries(flow, res, xref)
	paramProv := buildParamProvenance(flow, anatomy, res)
	graph := buildGraphModel(flow, res, xref, modules)
	originChain := buildOriginChain(flow, anatomy, res, xref, modules, graph)
	posture := buildSecurityPosture(flow, res, xref)
	confLabel, confScore, confReasons := computeConfidence(res, xref, originChain, paramProv)
	highlights := buildHighlights(anatomy, res, originChain, modules, paramProv, posture)
	execSummary := buildExecutiveSummary(flow, anatomy, res, originChain, modules, paramProv, posture, confLabel, confScore)

	report := &TraceReport{
		Confidence:        confLabel,
		ConfidenceScore:   confScore,
		ConfidenceReasons: nonNilStrings(confReasons),
		ExecutiveSummary:  execSummary,
		Highlights:        nonNilStrings(highlights),
		RequestAnatomy:    anatomy,
		OriginChain:       originChain,
		Modules:           modules,
		ParamProvenance:   paramProv,
		Graph:             graph,
		SecurityPosture:   posture,
	}
	report.Markdown = renderReportMarkdown(flow, res, report)
	return report
}

// --- Request Anatomy ------------------------------------------------------

func buildRequestAnatomy(flow *types.Flow) RequestAnatomy {
	u, _ := url.Parse(flow.URL)
	scheme := "http"
	host := flow.Host
	path := cleanPath(flow.Path)
	if u != nil {
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		if host == "" {
			host = u.Host
		}
		if path == "" {
			path = u.Path
		}
	}
	if path == "" {
		path = "/"
	}

	signSet := make(map[string]bool, len(flow.SignParams))
	for _, sp := range flow.SignParams {
		signSet[strings.ToLower(strings.TrimSpace(sp))] = true
	}

	queryParams := make([]AnatomyParam, 0)
	if u != nil {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := q.Get(k)
			role := classifyParamRole(k, signSet[strings.ToLower(k)])
			isSign := signSet[strings.ToLower(k)] || role == "sign" || role == "auth"
			queryParams = append(queryParams, AnatomyParam{
				Name:        k,
				SampleValue: maskSampleValue(k, val, role),
				IsSignParam: isSign,
				Role:        role,
			})
		}
	}

	keyHeaders := make([]AnatomyParam, 0)
	contentType := ""
	if len(flow.ReqHeaders) > 0 {
		hKeys := make([]string, 0, len(flow.ReqHeaders))
		for k := range flow.ReqHeaders {
			hKeys = append(hKeys, k)
		}
		sort.Strings(hKeys)
		for _, k := range hKeys {
			val := flow.ReqHeaders[k]
			lk := strings.ToLower(k)
			if lk == "content-type" {
				contentType = val
			}
			if isKeyRequestHeader(lk) || signSet[lk] {
				role := classifyParamRole(k, signSet[lk])
				isSign := signSet[lk] || role == "sign" || role == "auth"
				keyHeaders = append(keyHeaders, AnatomyParam{
					Name:        k,
					SampleValue: maskSampleValue(k, val, role),
					IsSignParam: isSign,
					Role:        role,
				})
			}
		}
	}
	if contentType == "" && len(flow.RespHeaders) > 0 {
		for k, val := range flow.RespHeaders {
			if strings.EqualFold(k, "content-type") && val != "" {
				contentType = val
				break
			}
		}
	}

	return RequestAnatomy{
		Method:       strings.ToUpper(flow.Method),
		Scheme:       scheme,
		Host:         host,
		Path:         path,
		Status:       flow.Status,
		LatencyMs:    flow.LatencyMs,
		ReqBodySize:  len(flow.ReqBody),
		RespBodySize: len(flow.RespBody),
		ContentType:  contentType,
		QueryParams:  queryParams,
		KeyHeaders:   keyHeaders,
	}
}

func isKeyRequestHeader(lowerName string) bool {
	if strings.HasPrefix(lowerName, "x-") {
		return true
	}
	switch lowerName {
	case "authorization", "cookie", "user-agent", "content-type", "origin", "referer", "api-key", "apikey", "token":
		return true
	}
	return false
}

func classifyParamRole(name string, markedSign bool) string {
	l := strings.ToLower(strings.TrimSpace(name))
	if markedSign {
		if strings.Contains(l, "auth") || strings.Contains(l, "bearer") || strings.Contains(l, "cookie") || strings.Contains(l, "session") {
			return "auth"
		}
		return "sign"
	}
	switch {
	case strings.Contains(l, "sign") || strings.Contains(l, "sig") || strings.Contains(l, "hmac") ||
		strings.Contains(l, "digest") || strings.Contains(l, "checksum") || strings.Contains(l, "nonce") ||
		strings.Contains(l, "salt") || strings.Contains(l, "secret") || strings.Contains(l, "mac"):
		return "sign"
	case strings.Contains(l, "auth") || strings.Contains(l, "token") || strings.Contains(l, "cookie") ||
		strings.Contains(l, "session") || strings.Contains(l, "apikey") || strings.Contains(l, "api_key") ||
		strings.Contains(l, "api-key") || strings.Contains(l, "appkey") || strings.Contains(l, "app_key") ||
		strings.Contains(l, "jwt"):
		return "auth"
	case l == "ts" || l == "t" || l == "time" || strings.Contains(l, "timestamp") || strings.Contains(l, "expire"):
		return "timestamp"
	case l == "page" || l == "limit" || l == "offset" || l == "cursor" || l == "size" || strings.Contains(l, "page"):
		return "pagination"
	case l == "id" || strings.HasSuffix(l, "id") || strings.HasSuffix(l, "_id") || strings.Contains(l, "uid") ||
		strings.Contains(l, "uuid") || strings.Contains(l, "device"):
		return "identifier"
	default:
		return "param"
	}
}

func maskSampleValue(name, val, role string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	r := []rune(val)
	isSensitive := role == "auth" || role == "sign" || strings.EqualFold(name, "cookie") || strings.EqualFold(name, "authorization")
	if isSensitive {
		if len(r) <= 8 {
			return "••••"
		}
		return fmt.Sprintf("%s…%s (%d chars)", string(r[:4]), string(r[len(r)-4:]), len(r))
	}
	if len(r) > 40 {
		return string(r[:37]) + "…"
	}
	return val
}

// --- Architectural Modules ------------------------------------------------

type moduleAccum struct {
	id           string
	name         string
	layer        string
	pkgPrefix    string
	role         string
	classes      map[string]bool
	methods      map[string]bool
	nativeLibs   map[string]bool
	keySymbols   []string
	keySymSeen   map[string]bool
	matchedTerms map[string]bool
	evidenceCnt  int
}

func buildModuleSummaries(flow *types.Flow, res *TraceResult, xref *DexXRefResult) []ModuleSummary {
	mods := make(map[string]*moduleAccum)

	getOrCreate := func(layer, pkgPrefix, role string) *moduleAccum {
		normLayer := normalizeLayer(layer)
		if pkgPrefix == "" {
			pkgPrefix = normLayer
		}
		id := makeModuleID(normLayer, pkgPrefix)
		if m, ok := mods[id]; ok {
			if m.role == "" && role != "" {
				m.role = role
			}
			return m
		}
		m := &moduleAccum{
			id:           id,
			name:         shortModuleDisplayName(pkgPrefix),
			layer:        normLayer,
			pkgPrefix:    pkgPrefix,
			role:         role,
			classes:      make(map[string]bool),
			methods:      make(map[string]bool),
			nativeLibs:   make(map[string]bool),
			keySymSeen:   make(map[string]bool),
			matchedTerms: make(map[string]bool),
		}
		mods[id] = m
		return m
	}

	addSym := func(m *moduleAccum, sym string) {
		sym = strings.TrimSpace(sym)
		if sym == "" || m.keySymSeen[sym] {
			return
		}
		m.keySymSeen[sym] = true
		if len(m.keySymbols) < maxModuleKeySymbols {
			m.keySymbols = append(m.keySymbols, sym)
		}
	}

	// 1. Entry module (App / launcher activity)
	appPkg := res.Package
	if appPkg == "" && res.APKInfo != nil && res.APKInfo.Package != "" {
		appPkg = res.APKInfo.Package
	}
	if appPkg == "" {
		appPkg = "app.entry"
	}
	entryMod := getOrCreate("entry", appPkg, "Application entry point & UI trigger")
	if res.APKInfo != nil && len(res.APKInfo.Activities) > 0 {
		for i, act := range res.APKInfo.Activities {
			if i >= 4 {
				break
			}
			entryMod.classes[act] = true
			addSym(entryMod, shortClassName(act))
		}
	} else {
		addSym(entryMod, appPkg)
	}

	// 2. Java source references (Strategy 3)
	for _, jr := range res.JavaTrace {
		layer := classifyJavaRefLayer(jr)
		pkg := packagePrefix(jr.Class)
		m := getOrCreate(layer, pkg, defaultModuleRole(layer, pkg))
		m.classes[jr.Class] = true
		sym := shortClassName(jr.Class)
		if jr.Method != "" {
			sym += "." + jr.Method + "()"
			m.methods[jr.Class+"."+jr.Method] = true
		}
		addSym(m, sym)
		if jr.MatchedTerm != "" {
			m.matchedTerms[jr.MatchedTerm] = true
		}
		for _, nm := range jr.NativeMethods {
			if strings.HasSuffix(nm, ".so") {
				m.nativeLibs[nm] = true
			}
		}
		m.evidenceCnt += 2 // Java source hits carry high evidence weight
	}

	// 3. Pure-Go DEX Bytecode XRefs (Strategy 1B)
	for _, dm := range res.DexXRefs {
		layer := normalizeLayer(dm.Category)
		pkg := packagePrefix(dm.ClassName)
		m := getOrCreate(layer, pkg, defaultModuleRole(layer, pkg))
		m.classes[dm.ClassName] = true
		sym := shortClassName(dm.ClassName) + "." + dm.MethodName + "()"
		m.methods[dm.ClassName+"."+dm.MethodName] = true
		addSym(m, sym)
		for _, t := range dm.MatchedTerms {
			m.matchedTerms[t] = true
		}
		for _, lib := range dm.LoadsLibrary {
			m.nativeLibs[normalizeSOName(lib)] = true
		}
		m.evidenceCnt++
	}

	// Also group DEX native bridge classes if present in xref
	if xref != nil {
		for _, nc := range xref.NativeClasses {
			if len(nc.NativeMethods) == 0 && len(nc.MatchedTerms) == 0 {
				continue
			}
			layer := normalizeLayer(nc.Category)
			if layer == "business" {
				layer = "native"
			}
			pkg := packagePrefix(nc.ClassName)
			m := getOrCreate(layer, pkg, defaultModuleRole(layer, pkg))
			m.classes[nc.ClassName] = true
			for _, nm := range nc.NativeMethods {
				m.methods[nc.ClassName+"."+nm] = true
				addSym(m, shortClassName(nc.ClassName)+"."+nm+"()")
			}
			for _, t := range nc.MatchedTerms {
				m.matchedTerms[t] = true
			}
			m.evidenceCnt++
		}
	}

	// 4. Native SO findings (Strategy 4)
	if len(res.NativeTrace) > 0 {
		for _, nr := range res.NativeTrace {
			_, libName := parseSOABIAndLib(nr.SOFile)
			if libName == "" {
				libName = filepath.Base(nr.SOFile)
			}
			m := getOrCreate("native", libName, "Native JNI shared library (.so)")
			m.nativeLibs[libName] = true
			m.methods[libName+":"+nr.Function] = true
			addSym(m, nr.Function)
			for _, s := range nr.Strings {
				if len(m.matchedTerms) < 6 {
					m.matchedTerms[s] = true
				}
			}
			m.evidenceCnt++
		}
	}

	// 5. HTTP Wire Endpoint module
	host := flow.Host
	if host == "" {
		if u, err := url.Parse(flow.URL); err == nil {
			host = u.Host
		}
	}
	if host == "" {
		host = "http.endpoint"
	}
	httpMod := getOrCreate("http", host, "Remote HTTP(S) target endpoint")
	httpLabel := strings.TrimSpace(strings.ToUpper(flow.Method) + " " + cleanPath(flow.Path))
	if httpLabel == "" {
		httpLabel = flow.URL
	}
	addSym(httpMod, httpLabel)
	httpMod.evidenceCnt++

	// Convert & rank modules deterministically by architectural layer order, then evidence count
	out := make([]ModuleSummary, 0, len(mods))
	for _, m := range mods {
		terms := sortedMapKeys(m.matchedTerms, 8)
		libs := sortedMapKeys(m.nativeLibs, 8)
		conf := "low"
		switch {
		case m.evidenceCnt >= 3 || m.layer == "http":
			conf = "high"
		case m.evidenceCnt >= 1:
			conf = "medium"
		}
		out = append(out, ModuleSummary{
			ID:            m.id,
			Name:          m.name,
			Layer:         m.layer,
			PackagePrefix: m.pkgPrefix,
			Role:          m.role,
			ClassCount:    len(m.classes),
			MethodCount:   len(m.methods),
			NativeLibs:    libs,
			KeySymbols:    nonNilStrings(m.keySymbols),
			MatchedTerms:  nonNilStrings(terms),
			EvidenceCount: m.evidenceCnt,
			Confidence:    conf,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		li, lj := layerRank(out[i].Layer), layerRank(out[j].Layer)
		if li != lj {
			return li < lj
		}
		if out[i].EvidenceCount != out[j].EvidenceCount {
			return out[i].EvidenceCount > out[j].EvidenceCount
		}
		return out[i].ID < out[j].ID
	})

	// Keep modules list crisp & scannable (cap at 14 while never dropping entry/http)
	if len(out) > 14 {
		kept := make([]ModuleSummary, 0, 14)
		for _, m := range out {
			if m.Layer == "entry" || m.Layer == "http" || len(kept) < 13 {
				kept = append(kept, m)
			}
			if len(kept) == 14 {
				break
			}
		}
		out = kept
	}

	return out
}

// --- Parameter Provenance -------------------------------------------------

func buildParamProvenance(flow *types.Flow, anatomy RequestAnatomy, res *TraceResult) []ParamTrace {
	type cand struct {
		name     string
		location string
		role     string
		sample   string
		priority int
	}
	seen := make(map[string]*cand)
	addCand := func(name, loc, role, sample string, prio int) {
		name = strings.TrimSpace(name)
		if len(name) < 2 {
			return
		}
		key := strings.ToLower(name)
		if cur, ok := seen[key]; ok {
			if prio > cur.priority {
				cur.priority = prio
				cur.role = role
				if sample != "" {
					cur.sample = sample
				}
			}
			return
		}
		seen[key] = &cand{name: name, location: loc, role: role, sample: sample, priority: prio}
	}

	for _, sp := range flow.SignParams {
		addCand(sp, "sign", classifyParamRole(sp, true), "", 100)
	}
	for _, qp := range anatomy.QueryParams {
		prio := 20
		if qp.IsSignParam || qp.Role == "sign" || qp.Role == "auth" {
			prio = 90
		} else if qp.Role == "timestamp" || qp.Role == "identifier" {
			prio = 50
		}
		addCand(qp.Name, "query", qp.Role, qp.SampleValue, prio)
	}
	for _, kh := range anatomy.KeyHeaders {
		if kh.IsSignParam || kh.Role == "sign" || kh.Role == "auth" || strings.HasPrefix(strings.ToLower(kh.Name), "x-") {
			prio := 70
			if kh.IsSignParam {
				prio = 95
			}
			addCand(kh.Name, "header", kh.Role, kh.SampleValue, prio)
		}
	}

	cands := make([]*cand, 0, len(seen))
	for _, c := range seen {
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].priority != cands[j].priority {
			return cands[i].priority > cands[j].priority
		}
		return cands[i].name < cands[j].name
	})
	if len(cands) > 12 {
		cands = cands[:12]
	}

	traces := make([]ParamTrace, 0, len(cands))
	for _, c := range cands {
		lname := strings.ToLower(c.name)
		refs := make([]ParamRef, 0)
		refSeen := make(map[string]bool)
		addRef := func(ref ParamRef) {
			if len(refs) >= maxParamRefsPerItem {
				return
			}
			k := ref.Source + "|" + ref.Symbol + "|" + ref.File
			if refSeen[k] {
				return
			}
			refSeen[k] = true
			refs = append(refs, ref)
		}

		// Search DEX bytecode XRefs
		for _, dm := range res.DexXRefs {
			for _, term := range dm.MatchedTerms {
				if strings.Contains(strings.ToLower(term), lname) {
					addRef(ParamRef{
						Source:  "dex_bytecode",
						Symbol:  dm.ClassName + "." + dm.MethodName + "()",
						File:    dm.DexFile,
						Snippet: fmt.Sprintf("const-string %q", truncateRunes(term, 80)),
					})
					break
				}
			}
		}

		// Search Java source findings
		for _, jr := range res.JavaTrace {
			if strings.Contains(strings.ToLower(jr.Snippet), lname) || strings.Contains(strings.ToLower(jr.MatchedTerm), lname) {
				sym := jr.Class
				if jr.Method != "" {
					sym += "." + jr.Method + "()"
				}
				addRef(ParamRef{
					Source:  "java",
					Symbol:  sym,
					File:    fmt.Sprintf("%s:%d", jr.File, jr.Line),
					Snippet: truncateRunes(jr.Snippet, 100),
				})
			}
		}

		// Search Native .so findings
		for _, nr := range res.NativeTrace {
			if strings.Contains(strings.ToLower(nr.Function), lname) {
				addRef(ParamRef{
					Source:  "native",
					Symbol:  nr.Function,
					File:    nr.SOFile,
					Snippet: "exported native function " + nr.Function,
				})
				continue
			}
			for _, s := range nr.Strings {
				if strings.Contains(strings.ToLower(s), lname) {
					addRef(ParamRef{
						Source:  "native",
						Symbol:  nr.Function,
						File:    nr.SOFile,
						Snippet: fmt.Sprintf("rodata string %q", truncateRunes(s, 80)),
					})
					break
				}
			}
		}

		// Search raw DEX strings
		for _, ds := range res.DexStrings {
			if strings.Contains(strings.ToLower(ds.String), lname) {
				addRef(ParamRef{
					Source:  "dex_string",
					Symbol:  fmt.Sprintf("%s@0x%x", ds.DexFile, ds.Offset),
					File:    ds.DexFile,
					Snippet: truncateRunes(ds.String, 90),
				})
			}
		}

		traces = append(traces, ParamTrace{
			Name:        c.name,
			Location:    c.location,
			Role:        c.role,
			SampleValue: c.sample,
			HitCount:    len(refs),
			References:  refs,
		})
	}

	return traces
}

// --- Multi-Perspective Graph Model (DAG + Modules + Sequence) -------------

func buildGraphModel(flow *types.Flow, res *TraceResult, xref *DexXRefResult, modules []ModuleSummary) GraphModel {
	nodes := make([]GraphNode, 0, maxGraphNodes)
	nodeMap := make(map[string]int) // id -> index in nodes
	edges := make([]GraphEdge, 0, 32)
	edgeSeen := make(map[string]int) // from|to|type -> index in edges

	// Map (layer, pkgPrefix) -> moduleID with fallback by layer
	modByKey := make(map[string]string, len(modules))
	modByLayer := make(map[string]string, len(modules))
	for _, m := range modules {
		modByKey[makeModuleID(m.Layer, m.PackagePrefix)] = m.ID
		if _, ok := modByLayer[m.Layer]; !ok {
			modByLayer[m.Layer] = m.ID
		}
	}
	resolveModuleID := func(layer, pkgPrefix string) string {
		normLayer := normalizeLayer(layer)
		if id, ok := modByKey[makeModuleID(normLayer, pkgPrefix)]; ok {
			return id
		}
		if id, ok := modByLayer[normLayer]; ok {
			return id
		}
		if len(modules) > 0 {
			return modules[0].ID
		}
		return makeModuleID(normLayer, pkgPrefix)
	}

	addNode := func(n GraphNode) string {
		if idx, exists := nodeMap[n.ID]; exists {
			nodes[idx].EvidenceCount += n.EvidenceCount
			nodes[idx].MatchedTerms = mergeUnique(nodes[idx].MatchedTerms, n.MatchedTerms, 6)
			nodes[idx].Details = mergeUnique(nodes[idx].Details, n.Details, 6)
			return n.ID
		}
		if len(nodes) >= maxGraphNodes {
			return ""
		}
		n.Layer = normalizeLayer(n.Layer)
		if n.Layer == "sdk" {
			n.Layer = "business"
		}
		nodeMap[n.ID] = len(nodes)
		nodes = append(nodes, n)
		return n.ID
	}

	addEdge := func(from, to, edgeType, label string) {
		if from == "" || to == "" || from == to {
			return
		}
		if _, ok := nodeMap[from]; !ok {
			return
		}
		if _, ok := nodeMap[to]; !ok {
			return
		}
		key := from + "|" + to + "|" + edgeType
		if idx, exists := edgeSeen[key]; exists {
			edges[idx].Weight++
			return
		}
		edgeSeen[key] = len(edges)
		edges = append(edges, GraphEdge{
			ID:     fmt.Sprintf("e_%d", len(edges)+1),
			From:   from,
			To:     to,
			Type:   edgeType,
			Label:  label,
			Weight: 1,
		})
	}

	// 1. Entry root node
	appName := res.Package
	if appName == "" && res.APKInfo != nil && res.APKInfo.Package != "" {
		appName = res.APKInfo.Package
	}
	if appName == "" {
		appName = "Android App"
	}
	entryLabel := appName
	entrySub := "Application Entry"
	entryKind := "activity"
	if res.APKInfo != nil && len(res.APKInfo.Activities) > 0 {
		entryLabel = shortClassName(res.APKInfo.Activities[0])
		entrySub = appName
	}
	entryID := addNode(GraphNode{
		ID:            "n_entry_root",
		Label:         entryLabel,
		Sublabel:      entrySub,
		Layer:         "entry",
		ModuleID:      resolveModuleID("entry", appName),
		Kind:          entryKind,
		Confidence:    "high",
		EvidenceCount: 1,
		Details:       []string{"Package: " + appName},
	})

	// 2. HTTP endpoint destination node
	host := flow.Host
	if host == "" {
		if u, err := url.Parse(flow.URL); err == nil {
			host = u.Host
		}
	}
	path := cleanPath(flow.Path)
	if path == "" {
		path = cleanPath(pathFromURL(flow.URL))
	}
	if path == "" {
		path = "/"
	}
	httpID := addNode(GraphNode{
		ID:            "n_http_endpoint",
		Label:         strings.TrimSpace(strings.ToUpper(flow.Method) + " " + truncateRunes(path, 36)),
		Sublabel:      host,
		Layer:         "http",
		ModuleID:      resolveModuleID("http", host),
		Kind:          "endpoint",
		Confidence:    "high",
		EvidenceCount: 1,
		Details:       []string{flow.URL, fmt.Sprintf("Status: %d · Latency: %dms", flow.Status, flow.LatencyMs)},
	})

	// Track key layer nodes so we always link Entry -> ... -> HTTP without orphan islands
	var (
		businessIDs []string
		networkIDs  []string
		cryptoIDs   []string
		nativeIDs   []string
	)
	recordLayerNode := func(layer, id string) {
		if id == "" {
			return
		}
		switch layer {
		case "business":
			businessIDs = appendUnique(businessIDs, id)
		case "network":
			networkIDs = appendUnique(networkIDs, id)
		case "crypto":
			cryptoIDs = appendUnique(cryptoIDs, id)
		case "native":
			nativeIDs = appendUnique(nativeIDs, id)
		}
	}

	// 3. Add Java source nodes (highest fidelity when jadx ran)
	javaNodeBySym := make(map[string]string)
	for i, jr := range res.JavaTrace {
		if i >= 10 {
			break
		}
		layer := classifyJavaRefLayer(jr)
		if layer == "sdk" {
			layer = "network"
		}
		pkg := packagePrefix(jr.Class)
		sym := jr.Class
		sub := ""
		kind := "class"
		if jr.Method != "" {
			sym += "." + jr.Method
			sub = jr.Method + "()"
			kind = "method"
		}
		details := []string{jr.Snippet}
		if jr.Annotation != "" {
			details = append([]string{"Annotation: @" + jr.Annotation}, details...)
		}
		var terms []string
		if jr.MatchedTerm != "" {
			terms = []string{jr.MatchedTerm}
		}
		id := addNode(GraphNode{
			ID:            "n_java_" + mermaidNodeID(sym),
			Label:         shortClassName(jr.Class),
			Sublabel:      sub,
			Layer:         layer,
			ModuleID:      resolveModuleID(layer, pkg),
			Kind:          kind,
			Confidence:    "high",
			EvidenceCount: 2,
			Details:       details,
			MatchedTerms:  terms,
			File:          fmt.Sprintf("%s:%d", jr.File, jr.Line),
		})
		if id == "" {
			continue
		}
		javaNodeBySym[sym] = id
		recordLayerNode(layer, id)
		edgeType := "builds_request"
		edgeLabel := "builds request"
		if jr.Annotation != "" {
			edgeLabel = jr.Annotation
		} else if layer == "crypto" {
			edgeType = "signs"
			edgeLabel = "signs / params"
		}
		addEdge(id, httpID, edgeType, edgeLabel)
	}

	// 4. Add Pure-Go DEX Bytecode XRef nodes (rich graph even without jadx!)
	dexNodeBySym := make(map[string]string)
	// Prioritize methods with matched terms, callers, or native bridges
	sortedDex := append([]DexMethodRef(nil), res.DexXRefs...)
	sort.Slice(sortedDex, func(i, j int) bool {
		si := scoreDexMethodRef(sortedDex[i])
		sj := scoreDexMethodRef(sortedDex[j])
		if si != sj {
			return si > sj
		}
		return sortedDex[i].ClassName+"."+sortedDex[i].MethodName < sortedDex[j].ClassName+"."+sortedDex[j].MethodName
	})

	for i, dm := range sortedDex {
		if i >= 10 {
			break
		}
		layer := normalizeLayer(dm.Category)
		if layer == "sdk" {
			layer = "business"
		}
		sym := dm.ClassName + "." + dm.MethodName
		if existing, ok := javaNodeBySym[sym]; ok {
			dexNodeBySym[sym] = existing
			continue
		}
		pkg := packagePrefix(dm.ClassName)
		details := make([]string, 0, 4)
		details = append(details, fmt.Sprintf("DEX: %s (%s)", dm.DexFile, dm.Descriptor))
		if len(dm.Callers) > 0 {
			details = append(details, "Callers: "+strings.Join(limitSlice(dm.Callers, 3), ", "))
		}
		if len(dm.Callees) > 0 {
			details = append(details, "Callees: "+strings.Join(limitSlice(dm.Callees, 3), ", "))
		}
		if dm.IsNative {
			details = append(details, "Declares native JNI method")
		}
		id := addNode(GraphNode{
			ID:            "n_dex_" + mermaidNodeID(sym),
			Label:         shortClassName(dm.ClassName),
			Sublabel:      dm.MethodName + "()",
			Layer:         layer,
			ModuleID:      resolveModuleID(layer, pkg),
			Kind:          "method",
			Confidence:    "high",
			EvidenceCount: max(1, len(dm.MatchedTerms)),
			Details:       details,
			MatchedTerms:  limitSlice(dm.MatchedTerms, 5),
			File:          dm.DexFile,
		})
		if id == "" {
			continue
		}
		dexNodeBySym[sym] = id
		recordLayerNode(layer, id)

		// Add up to 1 caller node per top method to illustrate upstream origin
		if len(dm.Callers) > 0 && len(nodes) < maxGraphNodes-4 {
			callerSym := dm.Callers[0]
			callerCls, callerMethod := splitClassMethod(callerSym)
			callerLayer := "business"
			if looksLikeEntryClass(callerCls) {
				callerLayer = "entry"
			}
			callerID := addNode(GraphNode{
				ID:            "n_caller_" + mermaidNodeID(callerSym),
				Label:         shortClassName(callerCls),
				Sublabel:      callerMethod + "()",
				Layer:         callerLayer,
				ModuleID:      resolveModuleID(callerLayer, packagePrefix(callerCls)),
				Kind:          "method",
				Confidence:    "medium",
				EvidenceCount: 1,
				Details:       []string{"DEX invoke caller of " + shortClassName(dm.ClassName) + "." + dm.MethodName},
				File:          dm.DexFile,
			})
			if callerID != "" {
				if callerLayer == "entry" {
					addEdge(entryID, callerID, "call", "triggers")
				} else {
					recordLayerNode("business", callerID)
				}
				addEdge(callerID, id, "call", "invokes")
			}
		}

		// Connect request/network/crypto methods toward HTTP
		if layer == "network" || len(dm.MatchedTerms) > 0 {
			et, el := "builds_request", "constructs URL"
			if layer == "crypto" {
				et, el = "signs", "signs request"
			}
			addEdge(id, httpID, et, el)
		}
	}

	// Connect DEX method -> DEX callee edges when both nodes exist
	for _, dm := range sortedDex {
		fromID := dexNodeBySym[dm.ClassName+"."+dm.MethodName]
		if fromID == "" {
			continue
		}
		for _, callee := range dm.Callees {
			if toID := dexNodeBySym[callee]; toID != "" && toID != fromID {
				addEdge(fromID, toID, "call", "calls")
			}
		}
	}

	// 5. Native SO library & function nodes
	nativeLibNodeByName := make(map[string]string)
	for i, nr := range res.NativeTrace {
		if i >= 6 || len(nodes) >= maxGraphNodes {
			break
		}
		_, libName := parseSOABIAndLib(nr.SOFile)
		if libName == "" {
			libName = filepath.Base(nr.SOFile)
		}
		libID := nativeLibNodeByName[libName]
		if libID == "" && len(nodes) < maxGraphNodes {
			libID = addNode(GraphNode{
				ID:            "n_so_" + mermaidNodeID(libName),
				Label:         libName,
				Sublabel:      "Native JNI Library",
				Layer:         "native",
				ModuleID:      resolveModuleID("native", libName),
				Kind:          "native_lib",
				Confidence:    "medium",
				EvidenceCount: 1,
				Details:       []string{"ELF shared library: " + nr.SOFile},
				File:          nr.SOFile,
			})
			if libID != "" {
				nativeLibNodeByName[libName] = libID
				recordLayerNode("native", libID)
			}
		}

		fnDetails := make([]string, 0, 4)
		if nr.Address != "" {
			fnDetails = append(fnDetails, "Address: "+nr.Address)
		}
		if len(nr.Imports) > 0 {
			fnDetails = append(fnDetails, "Imports: "+strings.Join(limitSlice(nr.Imports, 5), ", "))
		}
		if len(nr.Calls) > 0 {
			fnDetails = append(fnDetails, "Calls: "+strings.Join(limitSlice(nr.Calls, 5), ", "))
		}
		fnID := addNode(GraphNode{
			ID:            "n_nat_" + mermaidNodeID(libName+"_"+nr.Function),
			Label:         truncateRunes(nr.Function, 32),
			Sublabel:      libName,
			Layer:         "native",
			ModuleID:      resolveModuleID("native", libName),
			Kind:          "native_fn",
			Confidence:    "high",
			EvidenceCount: max(1, len(nr.Strings)+len(nr.Calls)),
			Details:       fnDetails,
			MatchedTerms:  limitSlice(nr.Strings, 4),
			File:          nr.SOFile,
		})
		if fnID != "" {
			recordLayerNode("native", fnID)
			if libID != "" {
				addEdge(libID, fnID, "native_call", "exports")
			}
		}
	}

	// Link Java / DEX callers to Native libs & JNI functions
	for _, jr := range res.JavaTrace {
		sym := jr.Class
		if jr.Method != "" {
			sym += "." + jr.Method
		}
		fromID := javaNodeBySym[sym]
		if fromID == "" {
			continue
		}
		for _, nm := range jr.NativeMethods {
			if strings.HasSuffix(nm, ".so") {
				if libID := nativeLibNodeByName[nm]; libID != "" {
					addEdge(fromID, libID, "loads_so", "loadLibrary")
				}
				continue
			}
			for _, nr := range res.NativeTrace {
				if strings.Contains(nr.Function, nm) {
					_, libName := parseSOABIAndLib(nr.SOFile)
					if fnID := "n_nat_" + mermaidNodeID(libName+"_"+nr.Function); nodeMap[fnID] > 0 {
						addEdge(fromID, fnID, "jni", "JNI "+nm)
					}
				}
			}
		}
	}
	for _, dm := range sortedDex {
		fromID := dexNodeBySym[dm.ClassName+"."+dm.MethodName]
		if fromID == "" {
			continue
		}
		for _, lib := range dm.LoadsLibrary {
			if libID := nativeLibNodeByName[normalizeSOName(lib)]; libID != "" {
				addEdge(fromID, libID, "loads_so", "loadLibrary")
			}
		}
		if dm.IsNative {
			for _, nr := range res.NativeTrace {
				if strings.Contains(nr.Function, dm.MethodName) {
					_, libName := parseSOABIAndLib(nr.SOFile)
					if fnID := "n_nat_" + mermaidNodeID(libName+"_"+nr.Function); nodeMap[fnID] > 0 {
						addEdge(fromID, fnID, "jni", "JNI "+dm.MethodName)
					}
				}
			}
		}
	}

	// 6. Guarantee continuous connectivity from Entry -> Business -> Network/Crypto -> Native/HTTP
	// Track nodes that already have incoming/outgoing edges
	hasIn := make(map[string]bool, len(edges))
	hasOut := make(map[string]bool, len(edges))
	for _, e := range edges {
		hasOut[e.From] = true
		hasIn[e.To] = true
	}

	connectFirstLayer := func(targets []string, et, label string) {
		for _, id := range targets {
			if !hasIn[id] {
				addEdge(entryID, id, et, label)
				hasIn[id] = true
				hasOut[entryID] = true
			}
		}
	}

	if len(businessIDs) > 0 {
		connectFirstLayer(businessIDs, "call", "dispatches")
		if len(networkIDs) > 0 {
			for _, nid := range networkIDs {
				if !hasIn[nid] {
					addEdge(businessIDs[0], nid, "call", "requests")
					hasIn[nid] = true
				}
			}
		}
		if len(cryptoIDs) > 0 {
			src := businessIDs[0]
			if len(networkIDs) > 0 {
				src = networkIDs[0]
			}
			for _, cid := range cryptoIDs {
				if !hasIn[cid] {
					addEdge(src, cid, "signs", "computes sign")
					hasIn[cid] = true
				}
			}
		}
	} else {
		connectFirstLayer(networkIDs, "call", "initiates")
		connectFirstLayer(cryptoIDs, "signs", "signs")
	}

	// Ensure native nodes are connected into the graph (from crypto/network/business/entry)
	nativeParent := entryID
	switch {
	case len(cryptoIDs) > 0:
		nativeParent = cryptoIDs[0]
	case len(networkIDs) > 0:
		nativeParent = networkIDs[0]
	case len(businessIDs) > 0:
		nativeParent = businessIDs[0]
	}
	for _, nid := range nativeIDs {
		if !hasIn[nid] {
			addEdge(nativeParent, nid, "jni", "native bridge")
			hasIn[nid] = true
		}
	}

	// Ensure HTTP endpoint always has at least one incoming edge
	if !hasIn[httpID] {
		switch {
		case len(networkIDs) > 0:
			addEdge(networkIDs[0], httpID, "http", "HTTP "+strings.ToUpper(flow.Method))
		case len(businessIDs) > 0:
			addEdge(businessIDs[0], httpID, "http", "HTTP "+strings.ToUpper(flow.Method))
		case len(cryptoIDs) > 0:
			addEdge(cryptoIDs[0], httpID, "http", "HTTP "+strings.ToUpper(flow.Method))
		default:
			addEdge(entryID, httpID, "http", "HTTP "+strings.ToUpper(flow.Method))
		}
	}

	// 7. Build chronological UML Sequence steps from the synthesized layers & edges
	sequence := buildSequenceSteps(flow, nodes, edges)

	return GraphModel{
		Nodes:    nodes,
		Edges:    edges,
		Sequence: sequence,
	}
}

func buildSequenceSteps(flow *types.Flow, nodes []GraphNode, edges []GraphEdge) []SequenceStep {
	byID := make(map[string]GraphNode, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	// Order edges chronologically by source layer rank -> dest layer rank -> edge order
	ordered := append([]GraphEdge(nil), edges...)
	sort.SliceStable(ordered, func(i, j int) bool {
		fi, fj := byID[ordered[i].From], byID[ordered[j].From]
		ti, tj := byID[ordered[i].To], byID[ordered[j].To]
		if layerRank(fi.Layer) != layerRank(fj.Layer) {
			return layerRank(fi.Layer) < layerRank(fj.Layer)
		}
		return layerRank(ti.Layer) < layerRank(tj.Layer)
	})

	steps := make([]SequenceStep, 0, min(len(ordered)+1, 14))
	seenPair := make(map[string]bool)
	for _, e := range ordered {
		if len(steps) >= 12 {
			break
		}
		fn, ok1 := byID[e.From]
		tn, ok2 := byID[e.To]
		if !ok1 || !ok2 {
			continue
		}
		fromActor := actorDisplayName(fn)
		toActor := actorDisplayName(tn)
		pairKey := fromActor + "->" + toActor + "|" + e.Type
		if seenPair[pairKey] {
			continue
		}
		seenPair[pairKey] = true

		action := e.Label
		if action == "" {
			action = defaultActionForEdgeType(e.Type)
		}
		detail := ""
		if len(tn.MatchedTerms) > 0 {
			detail = "Matched: " + strings.Join(limitSlice(tn.MatchedTerms, 2), ", ")
		} else if tn.Sublabel != "" {
			detail = tn.Sublabel
		}
		ev := tn.File
		if ev == "" && len(tn.Details) > 0 {
			ev = truncateRunes(tn.Details[0], 60)
		}

		steps = append(steps, SequenceStep{
			Order:     len(steps) + 1,
			From:      fromActor,
			FromLayer: fn.Layer,
			To:        toActor,
			ToLayer:   tn.Layer,
			Action:    action,
			Detail:    detail,
			Evidence:  ev,
		})
	}

	// Append HTTP response return arrow if status is known
	if flow.Status > 0 && len(steps) > 0 {
		last := steps[len(steps)-1]
		if last.ToLayer == "http" {
			steps = append(steps, SequenceStep{
				Order:     len(steps) + 1,
				From:      last.To,
				FromLayer: "http",
				To:        last.From,
				ToLayer:   last.FromLayer,
				Action:    fmt.Sprintf("HTTP %d Response", flow.Status),
				Detail:    fmt.Sprintf("%d bytes in %dms", len(flow.RespBody), flow.LatencyMs),
				Evidence:  flow.URL,
			})
		}
	}

	return steps
}

// --- Request Origin Chain -------------------------------------------------

func buildOriginChain(flow *types.Flow, anatomy RequestAnatomy, res *TraceResult, xref *DexXRefResult, modules []ModuleSummary, graph GraphModel) []OriginHop {
	hops := make([]OriginHop, 0, 6)
	addHop := func(layer, title, module, symbol, file, evidence, conf, detail string) {
		hops = append(hops, OriginHop{
			Step:       len(hops) + 1,
			Layer:      layer,
			Title:      title,
			Module:     module,
			Symbol:     symbol,
			File:       file,
			Evidence:   evidence,
			Confidence: conf,
			Detail:     detail,
		})
	}

	// 1. Entry hop
	appPkg := res.Package
	if appPkg == "" && res.APKInfo != nil {
		appPkg = res.APKInfo.Package
	}
	if appPkg == "" {
		appPkg = "Android Application"
	}
	entrySym := appPkg
	entryDetail := "User action or background task initiates the request lifecycle"
	if res.APKInfo != nil && len(res.APKInfo.Activities) > 0 {
		entrySym = res.APKInfo.Activities[0]
		entryDetail = fmt.Sprintf("APK declares %d activity component(s); entry surface anchored at %s", len(res.APKInfo.Activities), shortClassName(entrySym))
	}
	// If a DEX caller in entry layer exists, surface it directly
	for _, dm := range res.DexXRefs {
		if dm.Category == "entry" {
			entrySym = dm.ClassName + "." + dm.MethodName + "()"
			entryDetail = fmt.Sprintf("DEX bytecode directly links UI/Entry method %s to request construction", shortClassName(dm.ClassName)+"."+dm.MethodName)
			break
		}
	}
	addHop("entry", "App Entry & Trigger", appPkg, entrySym, "AndroidManifest.xml", "Package & entry component", "high", entryDetail)

	// 2. Business / Caller hop
	if hop := pickBestLayerNode(graph.Nodes, "business"); hop != nil {
		addHop(
			"business",
			"Business Logic & Orchestration",
			findModuleName(modules, hop.ModuleID),
			formatNodeSymbol(*hop),
			hop.File,
			formatNodeEvidence(*hop),
			hop.Confidence,
			fmt.Sprintf("Coordinates parameters and delegates request construction (%d evidence hit(s))", hop.EvidenceCount),
		)
	}

	// 3. Network / Request Builder hop
	if hop := pickBestLayerNode(graph.Nodes, "network"); hop != nil {
		addHop(
			"network",
			"HTTP Client & Endpoint Builder",
			findModuleName(modules, hop.ModuleID),
			formatNodeSymbol(*hop),
			hop.File,
			formatNodeEvidence(*hop),
			hop.Confidence,
			fmt.Sprintf("Assembles %s %s request URL, headers, and transport call", anatomy.Method, anatomy.Path),
		)
	} else if len(res.DexStrings) > 0 {
		ds := res.DexStrings[0]
		addHop(
			"network",
			"Endpoint Constant Reference",
			ds.DexFile,
			fmt.Sprintf("%s@0x%x", ds.DexFile, ds.Offset),
			ds.DexFile,
			truncateRunes(ds.String, 72),
			"medium",
			fmt.Sprintf("Found %d matching endpoint/host string literal(s) in DEX bytecode", len(res.DexStrings)),
		)
	}

	// 4. Crypto / Signing hop
	if hop := pickBestLayerNode(graph.Nodes, "crypto"); hop != nil {
		addHop(
			"crypto",
			"Signature & Auth Material Generation",
			findModuleName(modules, hop.ModuleID),
			formatNodeSymbol(*hop),
			hop.File,
			formatNodeEvidence(*hop),
			hop.Confidence,
			"Computes request signatures, nonces, or authentication tokens before dispatch",
		)
	} else if len(flow.SignParams) > 0 {
		addHop(
			"crypto",
			"Detected Sign/Auth Parameters",
			"Parameter Analyzer",
			strings.Join(limitSlice(flow.SignParams, 4), ", "),
			"",
			fmt.Sprintf("%d signature/auth parameter(s) present on wire", len(flow.SignParams)),
			"medium",
			"Wire traffic includes signature/auth parameters; inspect DEX/Native modules for signing logic",
		)
	}

	// 5. Native JNI hop
	if hop := pickBestLayerNode(graph.Nodes, "native"); hop != nil {
		addHop(
			"native",
			"Native JNI / Shared Library Execution",
			findModuleName(modules, hop.ModuleID),
			formatNodeSymbol(*hop),
			hop.File,
			formatNodeEvidence(*hop),
			hop.Confidence,
			fmt.Sprintf("Native layer (%d finding(s)) provides JNI exports, crypto primitives, or request helpers", len(res.NativeTrace)),
		)
	}

	// 6. HTTP Wire hop
	httpEv := fmt.Sprintf("HTTP %d · %dms · %dB req / %dB resp", anatomy.Status, anatomy.LatencyMs, anatomy.ReqBodySize, anatomy.RespBodySize)
	addHop(
		"http",
		"HTTP(S) Wire Transmission",
		anatomy.Host,
		fmt.Sprintf("%s %s", anatomy.Method, anatomy.Path),
		flow.URL,
		httpEv,
		"high",
		fmt.Sprintf("Dispatched over %s to %s with %d query param(s) and %d key header(s)", strings.ToUpper(anatomy.Scheme), anatomy.Host, len(anatomy.QueryParams), len(anatomy.KeyHeaders)),
	)

	return hops
}

// --- Security Posture -----------------------------------------------------

func buildSecurityPosture(flow *types.Flow, res *TraceResult, xref *DexXRefResult) SecurityPosture {
	p := SecurityPosture{
		NetworkStack:     []string{},
		CryptoIndicators: []string{},
		ObfuscationHint:  "none",
		Notes:            []string{},
	}

	if res.APKInfo != nil {
		p.MinSDK = res.APKInfo.MinSDK
		p.TargetSDK = res.APKInfo.TargetSDK
		p.HasNSConfig = res.APKInfo.HasNSConfig
		p.PermissionsCount = len(res.APKInfo.Permissions)
		p.NativeLibCount = len(res.APKInfo.SOFiles)
		p.DexCount = res.APKInfo.DexCount
	}

	// Detect network stack & crypto indicators across JavaTrace, DexXRefs, DexStrings, NativeTrace
	stackSet := make(map[string]bool)
	cryptoSet := make(map[string]bool)

	scanText := func(s string) {
		l := strings.ToLower(s)
		if strings.Contains(l, "okhttp") {
			stackSet["OkHttp"] = true
		}
		if strings.Contains(l, "retrofit") {
			stackSet["Retrofit"] = true
		}
		if strings.Contains(l, "cronet") {
			stackSet["Cronet"] = true
		}
		if strings.Contains(l, "httpurlconnection") || strings.Contains(l, "java.net.url") {
			stackSet["HttpURLConnection"] = true
		}
		if strings.Contains(l, "volley") {
			stackSet["Volley"] = true
		}
		if strings.Contains(l, "ktor") {
			stackSet["Ktor"] = true
		}
		if strings.Contains(l, "hmac") {
			cryptoSet["HMAC"] = true
		}
		if strings.Contains(l, "sha256") || strings.Contains(l, "sha-256") || strings.Contains(l, "messagedigest") {
			cryptoSet["SHA/MessageDigest"] = true
		}
		if strings.Contains(l, "md5") {
			cryptoSet["MD5"] = true
		}
		if strings.Contains(l, "aes") || strings.Contains(l, "cipher") {
			cryptoSet["AES/Cipher"] = true
		}
		if strings.Contains(l, "rsa") || strings.Contains(l, "signature") {
			cryptoSet["RSA/Signature"] = true
		}
		if strings.Contains(l, "ssl") || strings.Contains(l, "x509") || strings.Contains(l, "trustmanager") || strings.Contains(l, "certificatepinner") {
			cryptoSet["TLS Pinning/Custom Trust"] = true
		}
	}

	for _, jr := range res.JavaTrace {
		scanText(jr.Class + " " + jr.Annotation + " " + jr.Snippet)
	}
	for _, dm := range res.DexXRefs {
		scanText(dm.ClassName + " " + dm.MethodName + " " + strings.Join(dm.Callees, " "))
		if dm.Category == "crypto" {
			cryptoSet["App Signing/Crypto Module"] = true
		}
	}
	for _, ds := range res.DexStrings {
		scanText(ds.String + " " + strings.Join(ds.Context, " "))
	}
	for _, nr := range res.NativeTrace {
		scanText(nr.SOFile + " " + nr.Function + " " + strings.Join(nr.Imports, " ") + " " + strings.Join(nr.Strings, " "))
	}
	if res.APKInfo != nil {
		for _, so := range res.APKInfo.SOFiles {
			scanText(so)
		}
	}

	p.NetworkStack = sortedMapKeys(stackSet, 8)
	p.CryptoIndicators = sortedMapKeys(cryptoSet, 8)

	// Obfuscation heuristic from short class/method names in DexXRefs + JavaTrace
	totalSymbols := 0
	shortSymbols := 0
	checkObf := func(cls, method string) {
		totalSymbols++
		sc := shortClassName(cls)
		if len(sc) <= 2 || (method != "" && len(method) <= 2 && method != "do" && method != "of") {
			shortSymbols++
		}
	}
	for _, dm := range res.DexXRefs {
		checkObf(dm.ClassName, dm.MethodName)
	}
	for _, jr := range res.JavaTrace {
		checkObf(jr.Class, jr.Method)
	}
	if totalSymbols > 0 {
		ratio := float64(shortSymbols) / float64(totalSymbols)
		switch {
		case ratio >= 0.55:
			p.ObfuscationHint = "heavy"
		case ratio >= 0.25:
			p.ObfuscationHint = "moderate"
		}
	}

	// Actionable security notes
	if p.HasNSConfig {
		p.Notes = append(p.Notes, "APK declares a custom network_security_config (may enforce certificate pinning or restrict user CAs).")
	}
	if strings.HasPrefix(strings.ToLower(flow.URL), "http://") {
		p.Notes = append(p.Notes, "Traced endpoint uses cleartext HTTP rather than HTTPS.")
	}
	if len(res.NativeTrace) > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("Native JNI layer active (%d finding(s) across %d APK .so files); signing or anti-tamper logic may live in native code.", len(res.NativeTrace), p.NativeLibCount))
	}
	if p.ObfuscationHint != "none" {
		p.Notes = append(p.Notes, fmt.Sprintf("Detected %s ProGuard/R8 identifier obfuscation among matched classes/methods.", p.ObfuscationHint))
	}
	if len(res.JavaTrace) == 0 && len(res.DexXRefs) > 0 {
		p.Notes = append(p.Notes, "Pure-Go DEX bytecode XRef attribution succeeded without jadx; install jadx for full decompiled Java snippets.")
	}

	return p
}

// --- Confidence, Highlights & Narrative -----------------------------------

func computeConfidence(res *TraceResult, xref *DexXRefResult, chain []OriginHop, params []ParamTrace) (string, int, []string) {
	score := 15 // baseline: APK + flow metadata present
	reasons := make([]string, 0, 6)

	if res.APKInfo != nil && (res.APKInfo.Package != "" || res.APKInfo.DexCount > 0) {
		score += 10
		reasons = append(reasons, fmt.Sprintf("APK manifest & structure parsed (%d DEX, %d .so)", res.APKInfo.DexCount, len(res.APKInfo.SOFiles)))
	}
	if len(res.JavaTrace) > 0 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("%d decompiled Java call-site(s) matched directly", len(res.JavaTrace)))
	}
	if len(res.DexXRefs) > 0 {
		add := 25
		if len(res.JavaTrace) > 0 {
			add = 15
		}
		score += add
		reasons = append(reasons, fmt.Sprintf("%d DEX bytecode method XRef(s) attributed via const-string/invoke", len(res.DexXRefs)))
	} else if len(res.DexStrings) > 0 {
		score += 12
		reasons = append(reasons, fmt.Sprintf("%d raw DEX string literal(s) matched flow terms", len(res.DexStrings)))
	}
	if len(res.NativeTrace) > 0 {
		score += 15
		reasons = append(reasons, fmt.Sprintf("%d native JNI/.so finding(s) correlated", len(res.NativeTrace)))
	}
	paramHits := 0
	for _, pt := range params {
		if pt.HitCount > 0 {
			paramHits++
		}
	}
	if paramHits > 0 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("%d key/sign parameter(s) traced to code/binary evidence", paramHits))
	}
	if len(chain) >= 4 {
		score += 5
	}
	if score > 100 {
		score = 100
	}

	label := "low"
	switch {
	case score >= 70:
		label = "high"
	case score >= 40:
		label = "medium"
	}
	return label, score, reasons
}

func buildHighlights(anatomy RequestAnatomy, res *TraceResult, chain []OriginHop, modules []ModuleSummary, params []ParamTrace, posture SecurityPosture) []string {
	hl := make([]string, 0, 6)
	hl = append(hl, fmt.Sprintf("Traced %s %s (%s) across %d architectural module(s) and %d origin hop(s).",
		anatomy.Method, anatomy.Path, anatomy.Host, len(modules), len(chain)))

	if len(res.JavaTrace) > 0 {
		jr := res.JavaTrace[0]
		sym := shortClassName(jr.Class)
		if jr.Method != "" {
			sym += "." + jr.Method + "()"
		}
		hl = append(hl, fmt.Sprintf("Primary Java call site identified at %s (%s:%d).", sym, jr.File, jr.Line))
	} else if len(res.DexXRefs) > 0 {
		dm := res.DexXRefs[0]
		hl = append(hl, fmt.Sprintf("DEX bytecode directly attributes endpoint strings to %s.%s() in %s.", shortClassName(dm.ClassName), dm.MethodName, dm.DexFile))
	}

	if len(posture.NetworkStack) > 0 {
		hl = append(hl, "Detected HTTP client stack: "+strings.Join(posture.NetworkStack, ", ")+".")
	}
	if len(res.NativeTrace) > 0 {
		hl = append(hl, fmt.Sprintf("Native layer surfaced %d JNI/ELF finding(s) across APK shared libraries.", len(res.NativeTrace)))
	}
	tracedParams := make([]string, 0, 4)
	for _, pt := range params {
		if pt.HitCount > 0 {
			tracedParams = append(tracedParams, pt.Name)
		}
	}
	if len(tracedParams) > 0 {
		hl = append(hl, fmt.Sprintf("Parameter provenance confirmed for: %s.", strings.Join(limitSlice(tracedParams, 4), ", ")))
	}
	return hl
}

func buildExecutiveSummary(flow *types.Flow, anatomy RequestAnatomy, res *TraceResult, chain []OriginHop, modules []ModuleSummary, params []ParamTrace, posture SecurityPosture, confLabel string, confScore int) string {
	pkg := res.Package
	if pkg == "" && res.APKInfo != nil && res.APKInfo.Package != "" {
		pkg = res.APKInfo.Package
	}
	if pkg == "" {
		pkg = "target APK"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "DeepTrace analyzed %s %s (%s) against %s with %s confidence (%d/100). ",
		anatomy.Method, anatomy.Path, anatomy.Host, pkg, confLabel, confScore)

	if len(res.JavaTrace) > 0 || len(res.DexXRefs) > 0 {
		fmt.Fprintf(&b, "Code provenance reconstructed a %d-hop origin chain spanning %d architectural module(s) (%d DEX bytecode XRefs, %d Java call sites, %d native JNI findings). ",
			len(chain), len(modules), len(res.DexXRefs), len(res.JavaTrace), len(res.NativeTrace))
	} else if len(res.DexStrings) > 0 || len(res.NativeTrace) > 0 {
		fmt.Fprintf(&b, "Static binary inspection uncovered %d DEX string match(es) and %d native ELF finding(s) across %d module(s). ",
			len(res.DexStrings), len(res.NativeTrace), len(modules))
	} else {
		fmt.Fprintf(&b, "APK structure and HTTP anatomy were captured across %d module(s); no direct URL literals were matched (endpoint may be dynamically constructed or encrypted). ",
			len(modules))
	}

	if len(posture.NetworkStack) > 0 {
		fmt.Fprintf(&b, "Detected transport stack: %s. ", strings.Join(posture.NetworkStack, ", "))
	}
	if len(params) > 0 {
		signCount := 0
		for _, pt := range params {
			if pt.Role == "sign" || pt.Role == "auth" {
				signCount++
			}
		}
		if signCount > 0 {
			fmt.Fprintf(&b, "Tracked %d request parameter(s) including %d signature/auth parameter(s).", len(params), signCount)
		}
	}
	return strings.TrimSpace(b.String())
}

// --- Markdown Report Export -----------------------------------------------

func renderReportMarkdown(flow *types.Flow, res *TraceResult, rep *TraceReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DeepTrace Intelligence Report\n\n")
	fmt.Fprintf(&b, "- **Target Request**: `%s %s`\n", rep.RequestAnatomy.Method, flow.URL)
	if res.Package != "" {
		fmt.Fprintf(&b, "- **Package**: `%s`\n", res.Package)
	}
	fmt.Fprintf(&b, "- **Confidence**: **%s** (%d/100)\n\n", strings.ToUpper(rep.Confidence), rep.ConfidenceScore)

	fmt.Fprintf(&b, "## Executive Summary\n\n%s\n\n", rep.ExecutiveSummary)
	if len(rep.Highlights) > 0 {
		for _, h := range rep.Highlights {
			fmt.Fprintf(&b, "- %s\n", h)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Request Origin Chain\n\n")
	for _, h := range rep.OriginChain {
		fmt.Fprintf(&b, "%d. **[%s] %s** — `%s` (%s)\n   - Evidence: %s\n   - Detail: %s\n",
			h.Step, strings.ToUpper(h.Layer), h.Title, h.Symbol, h.Module, h.Evidence, h.Detail)
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Involved Modules (%d)\n\n", len(rep.Modules))
	b.WriteString("| Module | Layer | Role | Classes | Methods | Key Symbols |\n")
	b.WriteString("| --- | --- | --- | ---: | ---: | --- |\n")
	for _, m := range rep.Modules {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %d | %d | %s |\n",
			m.Name, m.Layer, m.Role, m.ClassCount, m.MethodCount, strings.Join(limitSlice(m.KeySymbols, 3), ", "))
	}
	b.WriteString("\n")

	if len(rep.ParamProvenance) > 0 {
		fmt.Fprintf(&b, "## Parameter & Sign Provenance\n\n")
		b.WriteString("| Parameter | Location | Role | Sample | Hits |\n")
		b.WriteString("| --- | --- | --- | --- | ---: |\n")
		for _, p := range rep.ParamProvenance {
			fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` | %d |\n",
				p.Name, p.Location, p.Role, p.SampleValue, p.HitCount)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Security & Transport Posture\n\n")
	fmt.Fprintf(&b, "- **SDK**: minSdk `%s` / targetSdk `%s` · **Network Security Config**: `%v`\n",
		emptyDash(rep.SecurityPosture.MinSDK), emptyDash(rep.SecurityPosture.TargetSDK), rep.SecurityPosture.HasNSConfig)
	fmt.Fprintf(&b, "- **APK Footprint**: %d DEX file(s), %d native `.so` lib(s), %d permission(s), obfuscation: `%s`\n",
		rep.SecurityPosture.DexCount, rep.SecurityPosture.NativeLibCount, rep.SecurityPosture.PermissionsCount, rep.SecurityPosture.ObfuscationHint)
	if len(rep.SecurityPosture.NetworkStack) > 0 {
		fmt.Fprintf(&b, "- **Network Stack**: %s\n", strings.Join(rep.SecurityPosture.NetworkStack, ", "))
	}
	if len(rep.SecurityPosture.CryptoIndicators) > 0 {
		fmt.Fprintf(&b, "- **Crypto Indicators**: %s\n", strings.Join(rep.SecurityPosture.CryptoIndicators, ", "))
	}
	for _, note := range rep.SecurityPosture.Notes {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	b.WriteString("\n")

	if res.Mermaid != "" {
		fmt.Fprintf(&b, "## Call Graph (Mermaid)\n\n```mermaid\n%s\n```\n", res.Mermaid)
	}
	return b.String()
}

// --- Helpers --------------------------------------------------------------

func normalizeLayer(layer string) string {
	switch strings.ToLower(strings.TrimSpace(layer)) {
	case "entry", "ui", "activity":
		return "entry"
	case "business", "app", "service":
		return "business"
	case "network", "http_client", "api":
		return "network"
	case "crypto", "sign", "security", "auth":
		return "crypto"
	case "native", "jni", "so":
		return "native"
	case "sdk":
		return "sdk"
	case "http", "wire", "endpoint":
		return "http"
	default:
		return "business"
	}
}

func layerRank(layer string) int {
	switch layer {
	case "entry":
		return 1
	case "business":
		return 2
	case "sdk":
		return 3
	case "network":
		return 4
	case "crypto":
		return 5
	case "native":
		return 6
	case "http":
		return 7
	default:
		return 8
	}
}

func classifyJavaRefLayer(jr JavaRef) string {
	combined := strings.ToLower(jr.Class + " " + jr.Method + " " + jr.Annotation + " " + jr.Snippet)
	switch {
	case jr.CallsNative || len(jr.NativeMethods) > 0:
		return "native"
	case strings.Contains(combined, "sign") || strings.Contains(combined, "hmac") ||
		strings.Contains(combined, "encrypt") || strings.Contains(combined, "cipher") ||
		strings.Contains(combined, "digest") || strings.Contains(combined, "token") ||
		strings.Contains(combined, "auth"):
		return "crypto"
	case jr.Annotation != "" || strings.Contains(combined, "okhttp") ||
		strings.Contains(combined, "retrofit") || strings.Contains(combined, "http") ||
		strings.Contains(combined, "api") || strings.Contains(combined, "client") ||
		strings.Contains(combined, "request"):
		return "network"
	case looksLikeEntryClass(jr.Class):
		return "entry"
	default:
		return "business"
	}
}

func looksLikeEntryClass(cls string) bool {
	l := strings.ToLower(cls)
	return strings.HasSuffix(l, "activity") || strings.HasSuffix(l, "fragment") ||
		strings.HasSuffix(l, "viewmodel") || strings.HasSuffix(l, "service") ||
		strings.HasSuffix(l, "receiver") || strings.HasSuffix(l, "application")
}

func packagePrefix(className string) string {
	className = strings.TrimSpace(className)
	if className == "" {
		return "default"
	}
	parts := strings.Split(className, ".")
	if len(parts) <= 1 {
		return className
	}
	pkg := parts[:len(parts)-1]
	if len(pkg) > 3 {
		pkg = pkg[:3]
	}
	return strings.Join(pkg, ".")
}

func shortClassName(className string) string {
	if idx := strings.LastIndex(className, "."); idx >= 0 && idx+1 < len(className) {
		return className[idx+1:]
	}
	return className
}

func shortModuleDisplayName(pkgPrefix string) string {
	if strings.HasSuffix(pkgPrefix, ".so") {
		return pkgPrefix
	}
	return pkgPrefix
}

func makeModuleID(layer, pkgPrefix string) string {
	return "mod_" + layer + "_" + mermaidNodeID(pkgPrefix)
}

func defaultModuleRole(layer, pkg string) string {
	switch layer {
	case "entry":
		return "UI / Activity entry point"
	case "network":
		return "HTTP client & request assembly"
	case "crypto":
		return "Signing, encryption & auth helpers"
	case "native":
		return "Native JNI bridge / shared library"
	case "sdk":
		return "Third-party SDK (" + pkg + ")"
	case "http":
		return "Remote HTTP(S) endpoint"
	default:
		return "Application business module"
	}
}

func normalizeSOName(lib string) string {
	lib = strings.TrimSpace(lib)
	if lib == "" {
		return ""
	}
	if !strings.HasSuffix(lib, ".so") {
		if !strings.HasPrefix(lib, "lib") {
			lib = "lib" + lib
		}
		lib += ".so"
	}
	return lib
}

func splitClassMethod(sym string) (cls, method string) {
	if idx := strings.LastIndex(sym, "."); idx > 0 && idx+1 < len(sym) {
		return sym[:idx], strings.TrimSuffix(sym[idx+1:], "()")
	}
	return sym, ""
}

func scoreDexMethodRef(dm DexMethodRef) int {
	score := len(dm.MatchedTerms) * 10
	if dm.Category == "network" || dm.Category == "crypto" {
		score += 8
	}
	if dm.IsNative || len(dm.LoadsLibrary) > 0 {
		score += 12
	}
	if len(dm.Callers) > 0 {
		score += 4
	}
	if len(dm.Callees) > 0 {
		score += 3
	}
	return score
}

func pickBestLayerNode(nodes []GraphNode, layer string) *GraphNode {
	var best *GraphNode
	for i := range nodes {
		if nodes[i].Layer != layer {
			continue
		}
		if best == nil || nodes[i].EvidenceCount > best.EvidenceCount {
			best = &nodes[i]
		}
	}
	return best
}

func findModuleName(modules []ModuleSummary, modID string) string {
	for _, m := range modules {
		if m.ID == modID {
			return m.Name
		}
	}
	return modID
}

func formatNodeSymbol(n GraphNode) string {
	if n.Sublabel != "" && n.Kind == "method" {
		return n.Label + "." + n.Sublabel
	}
	if n.Sublabel != "" && n.Kind == "native_fn" {
		return n.Sublabel + ":" + n.Label
	}
	return n.Label
}

func formatNodeEvidence(n GraphNode) string {
	if len(n.MatchedTerms) > 0 {
		return "Matched: " + strings.Join(limitSlice(n.MatchedTerms, 3), ", ")
	}
	if len(n.Details) > 0 {
		return truncateRunes(n.Details[0], 80)
	}
	return fmt.Sprintf("%d evidence reference(s)", n.EvidenceCount)
}

func actorDisplayName(n GraphNode) string {
	if n.Kind == "endpoint" {
		if n.Sublabel != "" {
			return n.Sublabel
		}
		return n.Label
	}
	if n.Sublabel != "" && n.Kind == "method" {
		return n.Label + "." + n.Sublabel
	}
	return n.Label
}

func defaultActionForEdgeType(t string) string {
	switch t {
	case "builds_request":
		return "Build HTTP request"
	case "signs":
		return "Sign / attach auth"
	case "loads_so":
		return "System.loadLibrary"
	case "jni":
		return "JNI native call"
	case "native_call":
		return "Native function call"
	case "http":
		return "Send HTTP request"
	default:
		return "Invoke"
	}
}

func sortedMapKeys(m map[string]bool, limit int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func limitSlice(s []string, maxLen int) []string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func appendUnique(dst []string, v string) []string {
	for _, x := range dst {
		if x == v {
			return dst
		}
	}
	return append(dst, v)
}

func mergeUnique(dst, src []string, limit int) []string {
	seen := make(map[string]bool, len(dst))
	for _, x := range dst {
		seen[x] = true
	}
	for _, x := range src {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		dst = append(dst, x)
		if limit > 0 && len(dst) >= limit {
			break
		}
	}
	return dst
}

func truncateRunes(s string, maxRunes int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	if maxRunes <= 1 {
		return "…"
	}
	return string(r[:maxRunes-1]) + "…"
}

func emptyDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
