package trace

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dexAccNative       = 0x0100
	dexHeaderMinSize   = 112
	dexEndianConstant  = 0x12345678
	dexMaxStringBytes  = 64 * 1024
	dexMaxRefsDefault  = 60
	dexMaxCalleesPerFn = 24
	dexMaxCallersPerFn = 12
	dexMaxNativeClasses = 40
)

// DexMethodRef attributes matched flow/parameter strings and call edges
// directly to a concrete Dalvik class & method decoded from classes*.dex.
type DexMethodRef struct {
	ClassName    string   `json:"class_name"`
	MethodName   string   `json:"method_name"`
	Descriptor   string   `json:"descriptor"`
	DexFile      string   `json:"dex_file"`
	MatchedTerms []string `json:"matched_terms"`
	Callees      []string `json:"callees"`
	Callers      []string `json:"callers"`
	IsNative     bool     `json:"is_native"`
	LoadsLibrary []string `json:"loads_library,omitempty"`
	Category     string   `json:"category"` // "network"|"crypto"|"native"|"business"|"sdk"|"entry"
}

// DexClassSummary summarizes a class declaring native methods or matched terms.
type DexClassSummary struct {
	ClassName     string   `json:"class_name"`
	DexFile       string   `json:"dex_file"`
	NativeMethods []string `json:"native_methods,omitempty"`
	MatchedTerms  []string `json:"matched_terms,omitempty"`
	Category      string   `json:"category"`
}

// DexXRefResult aggregates pure-Go DEX bytecode cross-references across all
// classes*.dex files inside an APK (or a single DEX buffer).
type DexXRefResult struct {
	Methods       []DexMethodRef    `json:"methods"`
	NativeClasses []DexClassSummary `json:"native_classes"`
	LoadLibraries []string          `json:"load_libraries"`
	TotalClasses  int               `json:"total_classes"`
	TotalMethods  int               `json:"total_methods"`
}

// dalvikOpWidth maps each Dalvik opcode byte (0x00..0xff) to its instruction
// width in 16-bit code units (covering DEX 035–041 including 0xfa..0xff).
var dalvikOpWidth = [256]uint8{
	// 0x00..0x0f
	1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
	// 0x10..0x1f
	1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
	// 0x20..0x2f
	2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
	// 0x30..0x3f
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
	// 0x40..0x4f
	1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0x50..0x5f
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0x60..0x6f
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
	// 0x70..0x7f
	3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
	// 0x80..0x8f
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0x90..0x9f
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xa0..0xaf
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xb0..0xbf
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xc0..0xcf
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xd0..0xdf
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	// 0xe0..0xef
	2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	// 0xf0..0xff (DEX 038+: 0xfa/0xfb=4, 0xfc/0xfd=3, 0xfe/0xff=2)
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
}

type dexFile struct {
	name string
	data []byte

	stringIDsSize uint32
	stringIDsOff  uint32
	typeIDsSize   uint32
	typeIDsOff    uint32
	protoIDsSize  uint32
	protoIDsOff   uint32
	methodIDsSize uint32
	methodIDsOff  uint32
	classDefsSize uint32
	classDefsOff  uint32

	stringsCache []string
	stringsReady []bool
}

func parseDexHeader(name string, data []byte) (*dexFile, error) {
	if len(data) < dexHeaderMinSize {
		return nil, fmt.Errorf("dex %s: too small (%d bytes)", name, len(data))
	}
	if string(data[0:4]) != "dex\n" || data[7] != 0 {
		return nil, fmt.Errorf("dex %s: invalid magic", name)
	}
	for i := 4; i <= 6; i++ {
		if data[i] < '0' || data[i] > '9' {
			return nil, fmt.Errorf("dex %s: invalid version bytes", name)
		}
	}
	headerSize := binary.LittleEndian.Uint32(data[0x24:0x28])
	if headerSize < dexHeaderMinSize {
		return nil, fmt.Errorf("dex %s: invalid header size %d", name, headerSize)
	}
	endian := binary.LittleEndian.Uint32(data[0x28:0x2c])
	if endian != dexEndianConstant {
		return nil, fmt.Errorf("dex %s: unsupported endian tag 0x%x", name, endian)
	}

	df := &dexFile{
		name:          name,
		data:          data,
		stringIDsSize: binary.LittleEndian.Uint32(data[0x38:0x3c]),
		stringIDsOff:  binary.LittleEndian.Uint32(data[0x3c:0x40]),
		typeIDsSize:   binary.LittleEndian.Uint32(data[0x40:0x44]),
		typeIDsOff:    binary.LittleEndian.Uint32(data[0x44:0x48]),
		protoIDsSize:  binary.LittleEndian.Uint32(data[0x48:0x4c]),
		protoIDsOff:   binary.LittleEndian.Uint32(data[0x4c:0x50]),
		methodIDsSize: binary.LittleEndian.Uint32(data[0x58:0x5c]),
		methodIDsOff:  binary.LittleEndian.Uint32(data[0x5c:0x60]),
		classDefsSize: binary.LittleEndian.Uint32(data[0x60:0x64]),
		classDefsOff:  binary.LittleEndian.Uint32(data[0x64:0x68]),
	}

	// Validate table bounds defensively so malformed headers never panic or OOM.
	if !tableInBounds(len(data), df.stringIDsOff, df.stringIDsSize, 4) ||
		!tableInBounds(len(data), df.typeIDsOff, df.typeIDsSize, 4) ||
		!tableInBounds(len(data), df.protoIDsOff, df.protoIDsSize, 12) ||
		!tableInBounds(len(data), df.methodIDsOff, df.methodIDsSize, 8) ||
		!tableInBounds(len(data), df.classDefsOff, df.classDefsSize, 32) {
		return nil, fmt.Errorf("dex %s: section tables out of bounds", name)
	}

	df.stringsCache = make([]string, df.stringIDsSize)
	df.stringsReady = make([]bool, df.stringIDsSize)
	return df, nil
}

func tableInBounds(dataLen int, off, count, elemSize uint32) bool {
	if count == 0 {
		return true
	}
	end := uint64(off) + uint64(count)*uint64(elemSize)
	return end <= uint64(dataLen)
}

func (df *dexFile) getString(idx uint32) string {
	if idx >= df.stringIDsSize {
		return ""
	}
	if df.stringsReady[idx] {
		return df.stringsCache[idx]
	}
	df.stringsReady[idx] = true

	pos := int(df.stringIDsOff) + int(idx)*4
	if pos+4 > len(df.data) {
		return ""
	}
	strDataOff := int(binary.LittleEndian.Uint32(df.data[pos : pos+4]))
	if strDataOff < 0 || strDataOff >= len(df.data) {
		return ""
	}

	// Skip utf16_size ULEB128 prefix.
	_, next, ok := readULEB128(df.data, strDataOff)
	if !ok || next >= len(df.data) {
		return ""
	}

	limit := next + dexMaxStringBytes
	if limit > len(df.data) {
		limit = len(df.data)
	}
	end := next
	for end < limit && df.data[end] != 0 {
		end++
	}
	s := decodeMUTF8(df.data[next:end])
	df.stringsCache[idx] = s
	return s
}

func decodeMUTF8(b []byte) string {
	// Fast path: standard ASCII / UTF-8 with no MUTF-8 0xC0 0x80 encoded NUL.
	hasEncodedNul := false
	for i := 0; i+1 < len(b); i++ {
		if b[i] == 0xc0 && b[i+1] == 0x80 {
			hasEncodedNul = true
			break
		}
	}
	if !hasEncodedNul {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0xc0 && i+1 < len(b) && b[i+1] == 0x80 {
			out = append(out, 0)
			i++
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

func (df *dexFile) getTypeDescriptor(typeIdx uint32) string {
	if typeIdx >= df.typeIDsSize {
		return ""
	}
	pos := int(df.typeIDsOff) + int(typeIdx)*4
	if pos+4 > len(df.data) {
		return ""
	}
	strIdx := binary.LittleEndian.Uint32(df.data[pos : pos+4])
	return df.getString(strIdx)
}

func (df *dexFile) getClassName(typeIdx uint32) string {
	return dexTypeToClassName(df.getTypeDescriptor(typeIdx))
}

func dexTypeToClassName(desc string) string {
	if desc == "" {
		return ""
	}
	if strings.HasPrefix(desc, "L") && strings.HasSuffix(desc, ";") {
		return strings.ReplaceAll(desc[1:len(desc)-1], "/", ".")
	}
	return desc
}

func (df *dexFile) getProtoDescriptor(protoIdx uint32) string {
	if protoIdx >= df.protoIDsSize {
		return ""
	}
	pos := int(df.protoIDsOff) + int(protoIdx)*12
	if pos+12 > len(df.data) {
		return ""
	}
	retTypeIdx := binary.LittleEndian.Uint32(df.data[pos+4 : pos+8])
	paramsOff := int(binary.LittleEndian.Uint32(df.data[pos+8 : pos+12]))

	var b strings.Builder
	b.WriteByte('(')
	if paramsOff > 0 && paramsOff+4 <= len(df.data) {
		pCount := int(binary.LittleEndian.Uint32(df.data[paramsOff : paramsOff+4]))
		if pCount > 0 && pCount <= 255 && paramsOff+4+pCount*2 <= len(df.data) {
			for i := 0; i < pCount; i++ {
				tIdx := uint32(binary.LittleEndian.Uint16(df.data[paramsOff+4+i*2 : paramsOff+6+i*2]))
				b.WriteString(df.getTypeDescriptor(tIdx))
			}
		}
	}
	b.WriteByte(')')
	b.WriteString(df.getTypeDescriptor(retTypeIdx))
	return b.String()
}

func (df *dexFile) getMethodInfo(methodIdx uint32) (className, methodName string, protoIdx uint16, ok bool) {
	if methodIdx >= df.methodIDsSize {
		return "", "", 0, false
	}
	pos := int(df.methodIDsOff) + int(methodIdx)*8
	if pos+8 > len(df.data) {
		return "", "", 0, false
	}
	classIdx := uint32(binary.LittleEndian.Uint16(df.data[pos : pos+2]))
	protoIdx = binary.LittleEndian.Uint16(df.data[pos+2 : pos+4])
	nameIdx := binary.LittleEndian.Uint32(df.data[pos+4 : pos+8])
	return df.getClassName(classIdx), df.getString(nameIdx), protoIdx, true
}

func readULEB128(data []byte, off int) (val uint32, next int, ok bool) {
	var result uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(data) {
			return 0, off, false
		}
		b := data[off+i]
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, off + i + 1, true
		}
		shift += 7
	}
	return 0, off, false
}

type dexParsedMethod struct {
	methodIdx   uint32
	accessFlags uint32
	codeOff     uint32
}

func (df *dexFile) parseClassMethods(classDataOff uint32) []dexParsedMethod {
	if classDataOff == 0 || int(classDataOff) >= len(df.data) {
		return nil
	}
	pos := int(classDataOff)
	staticFields, pos, ok := readULEB128(df.data, pos)
	if !ok {
		return nil
	}
	instFields, pos, ok := readULEB128(df.data, pos)
	if !ok {
		return nil
	}
	directMethods, pos, ok := readULEB128(df.data, pos)
	if !ok {
		return nil
	}
	virtualMethods, pos, ok := readULEB128(df.data, pos)
	if !ok {
		return nil
	}

	// Skip static + instance encoded_field entries (2 ULEB128s each).
	totalFields := uint64(staticFields) + uint64(instFields)
	if totalFields > 200000 {
		return nil
	}
	for i := uint64(0); i < totalFields; i++ {
		if _, pos, ok = readULEB128(df.data, pos); !ok {
			return nil
		}
		if _, pos, ok = readULEB128(df.data, pos); !ok {
			return nil
		}
	}

	totalMethods := uint64(directMethods) + uint64(virtualMethods)
	if totalMethods == 0 || totalMethods > 200000 {
		return nil
	}
	methods := make([]dexParsedMethod, 0, totalMethods)

	readMethodList := func(count uint32) bool {
		var curIdx uint32
		for i := uint32(0); i < count; i++ {
			var diff, flags, codeOff uint32
			if diff, pos, ok = readULEB128(df.data, pos); !ok {
				return false
			}
			if flags, pos, ok = readULEB128(df.data, pos); !ok {
				return false
			}
			if codeOff, pos, ok = readULEB128(df.data, pos); !ok {
				return false
			}
			curIdx += diff
			methods = append(methods, dexParsedMethod{
				methodIdx:   curIdx,
				accessFlags: flags,
				codeOff:     codeOff,
			})
		}
		return true
	}

	if !readMethodList(directMethods) {
		return methods
	}
	readMethodList(virtualMethods)
	return methods
}

// dalvikStep returns the instruction width in 16-bit code units at pc inside
// insnsBytes (little-endian 16-bit units), properly handling nop payload
// pseudo-instructions (0x0100 packed-switch, 0x0200 sparse-switch,
// 0x0300 fill-array-data) so bytecode walking never desyncs.
func dalvikStep(insnsBytes []byte, pc, totalUnits int) int {
	unit := binary.LittleEndian.Uint16(insnsBytes[pc*2 : pc*2+2])
	op := byte(unit & 0xff)
	if op == 0x00 {
		switch unit {
		case 0x0100: // packed-switch-payload
			if pc+2 <= totalUnits {
				sz := int(binary.LittleEndian.Uint16(insnsBytes[(pc+1)*2 : (pc+2)*2]))
				return sz*2 + 4
			}
		case 0x0200: // sparse-switch-payload
			if pc+2 <= totalUnits {
				sz := int(binary.LittleEndian.Uint16(insnsBytes[(pc+1)*2 : (pc+2)*2]))
				return sz*4 + 2
			}
		case 0x0300: // fill-array-data-payload
			if pc+4 <= totalUnits {
				elemW := uint64(binary.LittleEndian.Uint16(insnsBytes[(pc+1)*2 : (pc+2)*2]))
				sz := uint64(binary.LittleEndian.Uint32(insnsBytes[(pc+2)*2 : (pc+4)*2]))
				w64 := (sz*elemW+1)/2 + 4
				if w64 > uint64(totalUnits-pc) {
					return totalUnits - pc + 1
				}
				return int(w64)
			}
		}
		return 1
	}
	w := int(dalvikOpWidth[op])
	if w <= 0 {
		return 1
	}
	return w
}

func isInvokeOpcode(op byte) bool {
	return (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78) || op == 0xfa || op == 0xfb
}

type termSpec struct {
	raw     string
	lower   string
	isParam bool
	weight  int
}

func prepareDexTerms(searchTerms, paramTerms []string) []termSpec {
	seen := make(map[string]bool)
	var out []termSpec
	add := func(raw string, isParam bool, idx int) {
		raw = strings.TrimSpace(raw)
		if len(raw) < minSearchTermLen {
			return
		}
		low := strings.ToLower(raw)
		if seen[low] {
			return
		}
		seen[low] = true
		weight := 25
		if !isParam {
			// Earlier search terms (URL, host+path, path) are most specific.
			weight = 50 - min(idx*6, 30)
		}
		out = append(out, termSpec{raw: raw, lower: low, isParam: isParam, weight: weight})
	}
	for i, t := range searchTerms {
		add(t, false, i)
	}
	for i, t := range paramTerms {
		add(t, true, i)
	}
	return out
}

type candidateMethod struct {
	ref   DexMethodRef
	score int
	key   string // "ClassName.MethodName"
}

// AnalyzeDexBytes parses a single DEX buffer in memory and extracts string-to-
// method attributions, outgoing callees, 1-hop reverse callers, ACC_NATIVE
// declarations, and System.loadLibrary calls. Malformed or truncated DEX data
// degrades gracefully without panicking.
func AnalyzeDexBytes(dexName string, data []byte, searchTerms, paramTerms []string, maxRefs int) (*DexXRefResult, error) {
	return analyzeMultipleDexBuffers(context.Background(), []namedDex{{name: dexName, data: data}}, searchTerms, paramTerms, maxRefs)
}

// AnalyzeDexXRefsContext scans every classes*.dex entry in the APK at apkPath
// using pure Go bytecode analysis (no jadx required) to produce structured
// method-level cross-references, 1-hop cross-DEX callers, native declarations,
// and loaded shared libraries.
func AnalyzeDexXRefsContext(ctx context.Context, apkPath string, searchTerms []string, paramTerms []string, maxRefs int) (*DexXRefResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk %s: %w", apkPath, err)
	}
	defer zr.Close()

	dexEntries := filterAndSortDexFiles(zr.File)
	buffers := make([]namedDex, 0, len(dexEntries))
	for _, f := range dexEntries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readZipFile(f)
		if err != nil {
			continue
		}
		buffers = append(buffers, namedDex{name: f.Name, data: data})
	}
	return analyzeMultipleDexBuffers(ctx, buffers, searchTerms, paramTerms, maxRefs)
}

type namedDex struct {
	name string
	data []byte
}

func analyzeMultipleDexBuffers(ctx context.Context, buffers []namedDex, searchTerms, paramTerms []string, maxRefs int) (res *DexXRefResult, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			if res == nil {
				res = &DexXRefResult{}
			}
			retErr = fmt.Errorf("dex parser recovered from malformed input: %v", r)
		}
	}()

	if maxRefs <= 0 {
		maxRefs = dexMaxRefsDefault
	}
	terms := prepareDexTerms(searchTerms, paramTerms)

	result := &DexXRefResult{}
	parsedDexes := make([]*dexFile, 0, len(buffers))
	var candidates []candidateMethod
	nativeClassMap := make(map[string]*DexClassSummary)
	loadLibSet := make(map[string]bool)

	// Pass 1: Parse each DEX, match strings/loadLibrary/ACC_NATIVE, collect outgoing callees.
	for _, buf := range buffers {
		if ctx != nil && ctx.Err() != nil {
			return result, ctx.Err()
		}
		df, err := parseDexHeader(buf.name, buf.data)
		if err != nil {
			continue // gracefully skip corrupt/compact/non-standard DEX entries
		}
		parsedDexes = append(parsedDexes, df)

		// Step A: Find string_ids matching any searchTerms or paramTerms.
		matchedStrings := make(map[uint32][]termSpec)
		if len(terms) > 0 {
			for sIdx := uint32(0); sIdx < df.stringIDsSize; sIdx++ {
				s := df.getString(sIdx)
				if len(s) < minSearchTermLen {
					continue
				}
				low := strings.ToLower(s)
				for _, ts := range terms {
					if strings.Contains(low, ts.lower) {
						matchedStrings[sIdx] = append(matchedStrings[sIdx], ts)
					}
				}
			}
		}

		// Track loadLibrary method_ids and notable network/crypto method_ids.
		loadLibMethods := make(map[uint32]bool)
		netCryptoMethods := make(map[uint32]string) // methodIdx -> "network"|"crypto"
		for mIdx := uint32(0); mIdx < df.methodIDsSize; mIdx++ {
			cls, meth, _, ok := df.getMethodInfo(mIdx)
			if !ok {
				continue
			}
			if meth == "loadLibrary" && (cls == "java.lang.System" || cls == "java.lang.Runtime") {
				loadLibMethods[mIdx] = true
			}
			if kind := classifyWellKnownAPI(cls, meth); kind != "" {
				netCryptoMethods[mIdx] = kind
			}
		}

		// Step B: Walk class_defs -> class_data_item -> code_item.
		result.TotalClasses += int(df.classDefsSize)
		for cIdx := uint32(0); cIdx < df.classDefsSize; cIdx++ {
			if cIdx%512 == 0 && ctx != nil && ctx.Err() != nil {
				return result, ctx.Err()
			}
			cPos := int(df.classDefsOff) + int(cIdx)*32
			if cPos+32 > len(df.data) {
				break
			}
			classTypeIdx := binary.LittleEndian.Uint32(df.data[cPos : cPos+4])
			classDataOff := binary.LittleEndian.Uint32(df.data[cPos+24 : cPos+28])
			if classDataOff == 0 {
				continue
			}
			className := df.getClassName(classTypeIdx)
			if className == "" {
				continue
			}

			methods := df.parseClassMethods(classDataOff)
			result.TotalMethods += len(methods)

			var classNativeMethods []string
			classMatchedTerms := make(map[string]bool)

			for _, m := range methods {
				isNative := m.accessFlags&dexAccNative != 0
				_, mName, protoIdx, ok := df.getMethodInfo(m.methodIdx)
				if !ok {
					continue
				}
				if isNative {
					classNativeMethods = append(classNativeMethods, mName)
				}
				if m.codeOff == 0 {
					continue
				}

				hitTerms, hitScore, callees, loadedLibs, invokedNet, invokedCrypto := scanCodeItem(
					df, m.codeOff, matchedStrings, loadLibMethods, netCryptoMethods,
				)
				for _, lib := range loadedLibs {
					loadLibSet[lib] = true
				}
				if len(hitTerms) == 0 && len(loadedLibs) == 0 {
					continue
				}
				for _, ht := range hitTerms {
					classMatchedTerms[ht] = true
				}

				cat := categorizeDexSymbol(className, mName, isNative, len(loadedLibs) > 0, invokedNet, invokedCrypto)
				score := hitScore + categoryBonus(cat)
				if invokedNet {
					score += 25
				}
				if invokedCrypto {
					score += 20
				}
				if len(loadedLibs) > 0 {
					score += 18
				}
				if isFrameworkOrNoiseClass(className) {
					score -= 35
				}

				ref := DexMethodRef{
					ClassName:    className,
					MethodName:   mName,
					Descriptor:   df.getProtoDescriptor(uint32(protoIdx)),
					DexFile:      df.name,
					MatchedTerms: hitTerms,
					Callees:      callees,
					IsNative:     isNative,
					LoadsLibrary: loadedLibs,
					Category:     cat,
				}
				candidates = append(candidates, candidateMethod{
					ref:   ref,
					score: score,
					key:   className + "." + mName,
				})
			}

			if len(classNativeMethods) > 0 {
				sort.Strings(classNativeMethods)
				var mt []string
				for t := range classMatchedTerms {
					mt = append(mt, t)
				}
				sort.Strings(mt)
				cat := categorizeDexSymbol(className, "", true, false, false, false)
				nativeClassMap[className] = &DexClassSummary{
					ClassName:     className,
					DexFile:       df.name,
					NativeMethods: classNativeMethods,
					MatchedTerms:  mt,
					Category:      cat,
				}
			}
		}
	}

	// Rank & cap highest-signal methods before Pass 2 caller extraction so Pass 2
	// targets only the winning methods (fast!).
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].ref.ClassName != candidates[j].ref.ClassName {
			return candidates[i].ref.ClassName < candidates[j].ref.ClassName
		}
		return candidates[i].ref.MethodName < candidates[j].ref.MethodName
	})

	// Deduplicate by ClassName.MethodName keeping highest score.
	seenMethod := make(map[string]bool, len(candidates))
	selected := make([]candidateMethod, 0, min(len(candidates), maxRefs))
	for _, c := range candidates {
		if seenMethod[c.key] {
			continue
		}
		seenMethod[c.key] = true
		selected = append(selected, c)
		if len(selected) >= maxRefs {
			break
		}
	}

	// Pass 2: Lightweight cross-DEX 1-hop reverse caller resolution for selected methods.
	if len(selected) > 0 {
		targetKeys := make(map[string]int, len(selected)) // "Class.method" -> index in selected
		for i, s := range selected {
			targetKeys[s.key] = i
		}
		callerSets := make([]map[string]bool, len(selected))
		for i := range callerSets {
			callerSets[i] = make(map[string]bool)
		}

		for _, df := range parsedDexes {
			if ctx != nil && ctx.Err() != nil {
				break
			}
			// Map methodIdx in this DEX -> index in selected.
			localTargetIdx := make(map[uint32]int)
			for mIdx := uint32(0); mIdx < df.methodIDsSize; mIdx++ {
				cls, meth, _, ok := df.getMethodInfo(mIdx)
				if !ok {
					continue
				}
				if selIdx, hit := targetKeys[cls+"."+meth]; hit {
					localTargetIdx[mIdx] = selIdx
				}
			}
			if len(localTargetIdx) == 0 {
				continue
			}

			for cIdx := uint32(0); cIdx < df.classDefsSize; cIdx++ {
				if cIdx%512 == 0 && ctx != nil && ctx.Err() != nil {
					break
				}
				cPos := int(df.classDefsOff) + int(cIdx)*32
				if cPos+32 > len(df.data) {
					break
				}
				classDataOff := binary.LittleEndian.Uint32(df.data[cPos+24 : cPos+28])
				if classDataOff == 0 {
					continue
				}
				methods := df.parseClassMethods(classDataOff)
				for _, m := range methods {
					if m.codeOff == 0 {
						continue
					}
					hitSelIdxs := findInvokedTargets(df, m.codeOff, localTargetIdx)
					if len(hitSelIdxs) == 0 {
						continue
					}
					callerCls, callerMeth, _, ok := df.getMethodInfo(m.methodIdx)
					if !ok || callerCls == "" {
						continue
					}
					callerKey := callerCls + "." + callerMeth
					for _, selIdx := range hitSelIdxs {
						if callerKey == selected[selIdx].key {
							continue // skip self-recursion noise
						}
						if len(callerSets[selIdx]) < dexMaxCallersPerFn {
							callerSets[selIdx][callerKey] = true
						}
					}
				}
			}
		}

		for i := range selected {
			if len(callerSets[i]) > 0 {
				callers := make([]string, 0, len(callerSets[i]))
				for k := range callerSets[i] {
					callers = append(callers, k)
				}
				sort.Strings(callers)
				selected[i].ref.Callers = callers
			}
		}
	}

	result.Methods = make([]DexMethodRef, len(selected))
	matchedPackages := make(map[string]bool)
	for i, s := range selected {
		result.Methods[i] = s.ref
		if pkg := packagePrefix2(s.ref.ClassName); pkg != "" {
			matchedPackages[pkg] = true
		}
	}

	// Prioritize native classes relevant to matched packages or security/network/crypto.
	nativeList := make([]DexClassSummary, 0, len(nativeClassMap))
	for _, nc := range nativeClassMap {
		nativeList = append(nativeList, *nc)
	}
	sort.Slice(nativeList, func(i, j int) bool {
		pi := nativeClassPriority(nativeList[i], matchedPackages)
		pj := nativeClassPriority(nativeList[j], matchedPackages)
		if pi != pj {
			return pi > pj
		}
		return nativeList[i].ClassName < nativeList[j].ClassName
	})
	if len(nativeList) > dexMaxNativeClasses {
		nativeList = nativeList[:dexMaxNativeClasses]
	}
	result.NativeClasses = nativeList

	if len(loadLibSet) > 0 {
		libs := make([]string, 0, len(loadLibSet))
		for lib := range loadLibSet {
			libs = append(libs, lib)
		}
		sort.Strings(libs)
		result.LoadLibraries = libs
	}

	return result, nil
}

func scanCodeItem(
	df *dexFile,
	codeOff uint32,
	matchedStrings map[uint32][]termSpec,
	loadLibMethods map[uint32]bool,
	netCryptoMethods map[uint32]string,
) (hitTerms []string, score int, callees []string, loadedLibs []string, invokedNet bool, invokedCrypto bool) {
	pos := int(codeOff)
	if pos < 0 || pos+16 > len(df.data) {
		return
	}
	insnsSizeU32 := binary.LittleEndian.Uint32(df.data[pos+12 : pos+16])
	if insnsSizeU32 == 0 {
		return
	}
	insnsStart := pos + 16
	availUnits := (len(df.data) - insnsStart) / 2
	if availUnits <= 0 {
		return
	}
	insnsSize := availUnits
	if uint64(insnsSizeU32) < uint64(availUnits) {
		insnsSize = int(insnsSizeU32)
	}
	insns := df.data[insnsStart : insnsStart+insnsSize*2]

	// Fast check: scan instructions tracking matched strings, recent const-string
	// (for System.loadLibrary argument attribution), and invoked method indices.
	var (
		hitTermSet  map[string]bool
		libSet      map[string]bool
		invokedIdxs []uint32
		lastStrIdx  uint32
		hasLastStr  bool
	)

	for pc := 0; pc < insnsSize; {
		unit := binary.LittleEndian.Uint16(insns[pc*2 : pc*2+2])
		op := byte(unit & 0xff)
		step := dalvikStep(insns, pc, insnsSize)
		if pc+step > insnsSize {
			break
		}

		switch op {
		case 0x1a: // const-string vAA, string@BBBB
			strIdx := uint32(binary.LittleEndian.Uint16(insns[(pc+1)*2 : (pc+2)*2]))
			lastStrIdx = strIdx
			hasLastStr = true
			if specs, ok := matchedStrings[strIdx]; ok {
				if hitTermSet == nil {
					hitTermSet = make(map[string]bool)
				}
				for _, sp := range specs {
					if !hitTermSet[sp.raw] {
						hitTermSet[sp.raw] = true
						score += sp.weight
					}
				}
			}
		case 0x1b: // const-string/jumbo vAA, string@BBBBBBBB
			strIdx := binary.LittleEndian.Uint32(insns[(pc+1)*2 : (pc+3)*2])
			lastStrIdx = strIdx
			hasLastStr = true
			if specs, ok := matchedStrings[strIdx]; ok {
				if hitTermSet == nil {
					hitTermSet = make(map[string]bool)
				}
				for _, sp := range specs {
					if !hitTermSet[sp.raw] {
						hitTermSet[sp.raw] = true
						score += sp.weight
					}
				}
			}
		default:
			if isInvokeOpcode(op) && pc+2 <= insnsSize {
				mIdx := uint32(binary.LittleEndian.Uint16(insns[(pc+1)*2 : (pc+2)*2]))
				if loadLibMethods[mIdx] {
					if hasLastStr {
						if libName := normalizeLoadLibName(df.getString(lastStrIdx)); libName != "" {
							if libSet == nil {
								libSet = make(map[string]bool)
							}
							libSet[libName] = true
						}
						hasLastStr = false
					}
				}
				if kind, ok := netCryptoMethods[mIdx]; ok {
					if kind == "network" {
						invokedNet = true
					} else if kind == "crypto" {
						invokedCrypto = true
					}
				}
				invokedIdxs = append(invokedIdxs, mIdx)
			}
		}

		pc += step
	}

	if len(hitTermSet) == 0 && len(libSet) == 0 {
		return nil, 0, nil, nil, false, false
	}

	if len(hitTermSet) > 0 {
		hitTerms = make([]string, 0, len(hitTermSet))
		for t := range hitTermSet {
			hitTerms = append(hitTerms, t)
		}
		sort.Strings(hitTerms)
	}
	if len(libSet) > 0 {
		loadedLibs = make([]string, 0, len(libSet))
		for lib := range libSet {
			loadedLibs = append(loadedLibs, lib)
		}
		sort.Strings(loadedLibs)
	}

	// Resolve outgoing callees only for matched methods (skip trivial stdlib noise).
	calleeSet := make(map[string]bool)
	for _, mIdx := range invokedIdxs {
		cls, meth, _, ok := df.getMethodInfo(mIdx)
		if !ok || cls == "" || meth == "" {
			continue
		}
		if isTrivialStdlibCallee(cls, meth) {
			continue
		}
		sig := cls + "." + meth
		if !calleeSet[sig] {
			calleeSet[sig] = true
			callees = append(callees, sig)
			if len(callees) >= dexMaxCalleesPerFn {
				break
			}
		}
	}
	return hitTerms, score, callees, loadedLibs, invokedNet, invokedCrypto
}

func findInvokedTargets(df *dexFile, codeOff uint32, targets map[uint32]int) []int {
	pos := int(codeOff)
	if pos < 0 || pos+16 > len(df.data) {
		return nil
	}
	insnsSizeU32 := binary.LittleEndian.Uint32(df.data[pos+12 : pos+16])
	if insnsSizeU32 == 0 {
		return nil
	}
	insnsStart := pos + 16
	availUnits := (len(df.data) - insnsStart) / 2
	if availUnits <= 0 {
		return nil
	}
	insnsSize := availUnits
	if uint64(insnsSizeU32) < uint64(availUnits) {
		insnsSize = int(insnsSizeU32)
	}
	insns := df.data[insnsStart : insnsStart+insnsSize*2]

	var hits []int
	var seen map[int]bool
	for pc := 0; pc < insnsSize; {
		unit := binary.LittleEndian.Uint16(insns[pc*2 : pc*2+2])
		op := byte(unit & 0xff)
		step := dalvikStep(insns, pc, insnsSize)
		if pc+step > insnsSize {
			break
		}
		if isInvokeOpcode(op) && pc+2 <= insnsSize {
			mIdx := uint32(binary.LittleEndian.Uint16(insns[(pc+1)*2 : (pc+2)*2]))
			if selIdx, ok := targets[mIdx]; ok {
				if seen == nil {
					seen = make(map[int]bool)
				}
				if !seen[selIdx] {
					seen[selIdx] = true
					hits = append(hits, selIdx)
				}
			}
		}
		pc += step
	}
	return hits
}

func normalizeLoadLibName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 64 || strings.ContainsAny(s, " \t\r\n/") {
		return ""
	}
	if !strings.HasPrefix(s, "lib") {
		s = "lib" + s
	}
	if !strings.HasSuffix(s, ".so") {
		s += ".so"
	}
	return filepath.Base(s)
}

func classifyWellKnownAPI(cls, meth string) string {
	lowCls := strings.ToLower(cls)
	switch {
	case strings.Contains(lowCls, "okhttp") ||
		strings.Contains(lowCls, "retrofit") ||
		strings.Contains(lowCls, "httpurlconnection") ||
		strings.Contains(lowCls, "cronet") ||
		strings.Contains(lowCls, "volley") ||
		lowCls == "java.net.url":
		return "network"
	case lowCls == "java.security.messagedigest" ||
		lowCls == "javax.crypto.mac" ||
		lowCls == "javax.crypto.cipher" ||
		lowCls == "java.security.signature":
		return "crypto"
	}
	_ = meth
	return ""
}

func isTrivialStdlibCallee(cls, meth string) bool {
	if meth == "<init>" && (strings.HasPrefix(cls, "java.lang.") || strings.HasPrefix(cls, "java.util.")) {
		return true
	}
	switch cls {
	case "java.lang.Object", "java.lang.String", "java.lang.StringBuilder",
		"java.lang.StringBuffer", "java.lang.Integer", "java.lang.Long",
		"java.lang.Boolean", "java.util.ArrayList", "java.util.HashMap",
		"java.util.Iterator", "java.util.List", "java.util.Map",
		"kotlin.jvm.internal.Intrinsics":
		return true
	}
	return false
}

func isFrameworkOrNoiseClass(cls string) bool {
	for _, p := range []string{"android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "com.google.android.gms.", "com.google.firebase."} {
		if strings.HasPrefix(cls, p) {
			return true
		}
	}
	return false
}

func categorizeDexSymbol(className, methodName string, isNative, loadsLib, invokedNet, invokedCrypto bool) string {
	lowCls := strings.ToLower(className)
	lowMeth := strings.ToLower(methodName)
	combined := lowCls + "." + lowMeth

	if isNative || loadsLib || strings.Contains(lowCls, "jni") {
		return "native"
	}
	for _, kw := range []string{"activity", "fragment", "viewmodel", "broadcastreceiver", "contentprovider", "application", "service"} {
		if strings.HasSuffix(lowCls, kw) || strings.Contains(lowCls, "."+kw) {
			return "entry"
		}
	}
	if invokedCrypto || containsAnySubstr(combined, []string{"sign", "encrypt", "decrypt", "cipher", "hash", "md5", "sha256", "sha1", "hmac", "auth", "token", "crypto", "secret"}) {
		return "crypto"
	}
	if invokedNet || containsAnySubstr(combined, []string{"okhttp", "retrofit", "http", "api", "client", "request", "network", "net.", "rpc", "grpc", "endpoint", "fetch", "service"}) {
		return "network"
	}
	for _, sdkPrefix := range []string{"com.google.", "com.facebook.", "com.tencent.", "com.alibaba.", "com.bytedance.", "com.umeng.", "com.squareup.", "io.reactivex.", "org.apache.", "com.amazonaws.", "com.sentry.", "io.flutter."} {
		if strings.HasPrefix(lowCls, sdkPrefix) {
			return "sdk"
		}
	}
	return "business"
}

func containsAnySubstr(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func categoryBonus(cat string) int {
	switch cat {
	case "network":
		return 20
	case "crypto":
		return 20
	case "native":
		return 18
	case "entry":
		return 12
	case "business":
		return 10
	default:
		return 0
	}
}

func packagePrefix2(cls string) string {
	parts := strings.Split(cls, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

func nativeClassPriority(nc DexClassSummary, matchedPkgs map[string]bool) int {
	score := 0
	if len(nc.MatchedTerms) > 0 {
		score += 100
	}
	if pkg := packagePrefix2(nc.ClassName); pkg != "" && matchedPkgs[pkg] {
		score += 60
	}
	if isSecurityKeywordName(nc.ClassName) {
		score += 30
	}
	if !isFrameworkOrNoiseClass(nc.ClassName) {
		score += 15
	}
	return score
}
