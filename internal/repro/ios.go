package repro

import (
	"archive/zip"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Mach-O load command IDs (strictly static header inspection).
	lcEncryptionInfo   = 0x21
	lcVersionMinMacOSX = 0x24
	lcVersionMinIPhone = 0x25
	lcEncryptionInfo64 = 0x2c
	lcVersionMinTVOS   = 0x2f
	lcVersionMinWatch  = 0x30
	lcBuildVersion     = 0x32

	// Mach-O header flags.
	mhFlagAllowStackExec = 0x00020000
	mhFlagPIE            = 0x00200000

	// Safety limits for IPA archive extraction and Mach-O/plist parsing.
	maxIPAPlistBytes     = 4 * 1024 * 1024
	maxIPABinaryBytes    = 256 * 1024 * 1024
	maxIPAEntries        = 50000
	maxObjCStrings       = 4000
	maxMachOExports      = 1000
	maxMachOSectionBytes = 32 * 1024 * 1024
	maxPlistDepth        = 64
)

// AnalyzeIOSBinary performs static security and metadata inspection on a
// standalone Mach-O (thin or Universal Fat) or an iOS .ipa archive.
//
// FairPlay inspection is strictly static Mach-O load command header analysis
// (LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 cryptid != 0) with no decryption.
func AnalyzeIOSBinary(filePath string) (*IOSBinaryReport, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, errors.New("filePath is required")
	}
	st, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat iOS binary: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%q is a directory", filePath)
	}

	report := &IOSBinaryReport{
		FilePath:      filePath,
		FileName:      filepath.Base(filePath),
		FileSize:      st.Size(),
		Architectures: []IOSArchInfo{},
		LinkedDylibs:  []string{},
		Frameworks:    []string{},
		ObjCClasses:   []string{},
		ObjCSelectors: []string{},
		AnalyzedAt:    nowRFC3339(),
	}

	head, err := readLeadingBytes(filePath, 4)
	if err != nil {
		return nil, err
	}

	// Detect .ipa ZIP archive by ZIP magic or extension.
	if bytes.HasPrefix(head, []byte{'P', 'K', 0x03, 0x04}) || strings.EqualFold(filepath.Ext(filePath), ".ipa") {
		if err := analyzeIPA(filePath, report); err != nil {
			return nil, err
		}
		finalizeIOSReportSummary(report)
		return report, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	report.MainBinaryName = filepath.Base(filePath)
	if err := analyzeMachOReaderAt(f, report); err != nil {
		return nil, err
	}
	finalizeIOSReportSummary(report)
	return report, nil
}

func analyzeIPA(ipaPath string, report *IOSBinaryReport) error {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return fmt.Errorf("open IPA zip archive: %w", err)
	}
	defer zr.Close()

	if len(zr.File) > maxIPAEntries {
		return fmt.Errorf("IPA archive has %d entries (exceeds %d safety limit)", len(zr.File), maxIPAEntries)
	}

	report.FileKind = IOSKindIPA

	var appDir string
	var plistEntry *zip.File
	filesByCleanName := make(map[string]*zip.File, len(zr.File))

	for _, zf := range zr.File {
		cleanName, ok := validateZipEntryPath(zf.Name)
		if !ok {
			return fmt.Errorf("zip-slip path rejected in IPA entry %q", zf.Name)
		}
		filesByCleanName[cleanName] = zf

		parts := strings.Split(cleanName, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			if plistEntry == nil {
				appDir = parts[0] + "/" + parts[1]
				plistEntry = zf
			}
		} else if appDir == "" && len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			appDir = parts[0] + "/" + parts[1]
		}
	}

	if appDir == "" {
		return errors.New("IPA archive missing Payload/*.app bundle directory")
	}

	execName := strings.TrimSuffix(filepath.Base(appDir), ".app")
	if plistEntry != nil {
		plistBytes, perr := readZipFileBounded(plistEntry, maxIPAPlistBytes)
		if perr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("read Info.plist failed: %v", perr))
		} else {
			plistInfo, pWarn := parseInfoPlist(plistBytes)
			report.InfoPlist = plistInfo
			if pWarn != "" {
				report.Warnings = append(report.Warnings, pWarn)
			}
			if plistInfo != nil && plistInfo.Executable != "" {
				execName = plistInfo.Executable
			}
		}
	} else {
		report.Warnings = append(report.Warnings, "Payload/*.app/Info.plist not found in IPA")
	}

	// Validate executable name to ensure no traversal within the archive lookup.
	if strings.Contains(execName, "/") || strings.Contains(execName, "\\") || strings.Contains(execName, "..") || execName == "" {
		return fmt.Errorf("invalid CFBundleExecutable %q in Info.plist", execName)
	}

	mainEntryPath := appDir + "/" + execName
	mainEntry := filesByCleanName[mainEntryPath]
	if mainEntry == nil {
		// Fallback: deterministically locate the first top-level Mach-O inside Payload/<App>.app/.
		prefix := appDir + "/"
		candNames := make([]string, 0, len(filesByCleanName))
		for name := range filesByCleanName {
			if strings.HasPrefix(name, prefix) {
				candNames = append(candNames, name)
			}
		}
		sort.Strings(candNames)
		for _, name := range candNames {
			zf := filesByCleanName[name]
			if zf.FileInfo().IsDir() {
				continue
			}
			rest := strings.TrimPrefix(name, prefix)
			if strings.Contains(rest, "/") || strings.HasSuffix(rest, ".plist") || strings.HasSuffix(rest, ".mobileprovision") {
				continue
			}
			head, herr := peekZipFileHead(zf, 4)
			if herr == nil && isMachOMagic(head) {
				mainEntry = zf
				execName = rest
				break
			}
		}
	}

	if mainEntry == nil {
		return fmt.Errorf("main Mach-O executable %q not found inside %s", execName, appDir)
	}

	report.MainBinaryName = execName
	binBytes, err := readZipFileBounded(mainEntry, maxIPABinaryBytes)
	if err != nil {
		return fmt.Errorf("extract main binary %q from IPA: %w", execName, err)
	}

	if err := analyzeMachOReaderAt(bytes.NewReader(binBytes), report); err != nil {
		return fmt.Errorf("parse Mach-O %q in IPA: %w", execName, err)
	}
	report.FileKind = IOSKindIPA
	return nil
}

func validateZipEntryPath(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, "\\") {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(name)), "/")
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	return clean, true
}

func peekZipFileHead(zf *zip.File, n int) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	buf := make([]byte, n)
	readN, err := io.ReadFull(io.LimitReader(rc, int64(n)), buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:readN], nil
}

func readZipFileBounded(zf *zip.File, limit int64) ([]byte, error) {
	if zf.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("zip entry %q uncompressed size %d exceeds limit %d", zf.Name, zf.UncompressedSize64, limit)
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("zip entry %q exceeds %d byte safety limit", zf.Name, limit)
	}
	return data, nil
}

func isMachOMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	be := binary.BigEndian.Uint32(b)
	le := binary.LittleEndian.Uint32(b)
	switch be {
	case macho.Magic32, macho.Magic64, macho.MagicFat:
		return true
	}
	switch le {
	case macho.Magic32, macho.Magic64, macho.MagicFat:
		return true
	}
	return false
}

func analyzeMachOReaderAt(ra io.ReaderAt, report *IOSBinaryReport) error {
	var slices []*macho.File

	if fat, err := macho.NewFatFile(ra); err == nil {
		defer fat.Close()
		report.IsUniversal = true
		if report.FileKind == "" {
			report.FileKind = IOSKindFatMachO
		}
		for _, arch := range fat.Arches {
			if arch.File != nil {
				slices = append(slices, arch.File)
			}
		}
	} else {
		mf, merr := macho.NewFile(ra)
		if merr != nil {
			return fmt.Errorf("invalid Mach-O binary: %w", merr)
		}
		defer mf.Close()
		if report.FileKind == "" {
			report.FileKind = IOSKindMachO
		}
		slices = append(slices, mf)
	}

	if len(slices) == 0 {
		return errors.New("Mach-O contains zero architecture slices")
	}

	dylibSet := make(map[string]bool)
	fwSet := make(map[string]bool)
	classSet := make(map[string]bool)
	selSet := make(map[string]bool)
	exportSet := make(map[string]bool)

	allPIE := true
	allNX := true
	anyARC := false
	anyCanary := false

	for _, mf := range slices {
		archInfo := inspectMachOSlice(mf, dylibSet, fwSet, classSet, selSet, exportSet)
		report.Architectures = append(report.Architectures, archInfo)
		if !archInfo.PIE {
			allPIE = false
		}
		if !archInfo.NX {
			allNX = false
		}
		if archInfo.ARC {
			anyARC = true
		}
		if archInfo.StackCanary {
			anyCanary = true
		}
		if archInfo.Encrypted {
			report.FairPlayEncrypted = true
			if report.CryptID == 0 {
				report.CryptID = archInfo.CryptID
			}
		}
		if report.MinOS == "" && archInfo.MinOS != "" {
			report.MinOS = archInfo.MinOS
		}
	}

	report.PIE = allPIE
	report.NX = allNX
	report.ARC = anyARC
	report.StackCanary = anyCanary

	report.LinkedDylibs = sortedKeys(dylibSet)
	report.Frameworks = sortedKeys(fwSet)
	report.ObjCClasses = sortedKeysLimit(classSet, maxObjCStrings)
	report.ObjCSelectors = sortedKeysLimit(selSet, maxObjCStrings)
	report.ExportedSymbols = sortedKeysLimit(exportSet, maxMachOExports)
	return nil
}

func inspectMachOSlice(
	mf *macho.File,
	dylibSet, fwSet, classSet, selSet, exportSet map[string]bool,
) IOSArchInfo {
	bits := 32
	if mf.Magic == macho.Magic64 {
		bits = 64
	}
	info := IOSArchInfo{
		Arch:       machoArchName(mf.Cpu, mf.SubCpu),
		CPUType:    mf.Cpu.String(),
		CPUSubtype: fmt.Sprintf("0x%x", mf.SubCpu),
		Bits:       bits,
		FileType:   machoFileTypeName(mf.Type),
		PIE:        (mf.Flags & mhFlagPIE) != 0,
		NX:         (mf.Flags & mhFlagAllowStackExec) == 0,
	}

	// Inspect raw load commands for FairPlay LC_ENCRYPTION_INFO(_64) and MinOS.
	bo := mf.ByteOrder
	for _, ld := range mf.Loads {
		raw := ld.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := bo.Uint32(raw[0:4])
		switch cmd {
		case lcEncryptionInfo, lcEncryptionInfo64:
			if len(raw) >= 20 {
				info.CryptOff = bo.Uint32(raw[8:12])
				info.CryptSize = bo.Uint32(raw[12:16])
				info.CryptID = bo.Uint32(raw[16:20])
				info.Encrypted = info.CryptID != 0
			}
		case lcVersionMinIPhone:
			if len(raw) >= 16 {
				info.Platform = "iOS"
				info.MinOS = decodeMachOVersion(bo.Uint32(raw[8:12]))
				info.SDKVersion = decodeMachOVersion(bo.Uint32(raw[12:16]))
			}
		case lcVersionMinMacOSX:
			if len(raw) >= 16 {
				info.Platform = "macOS"
				info.MinOS = decodeMachOVersion(bo.Uint32(raw[8:12]))
				info.SDKVersion = decodeMachOVersion(bo.Uint32(raw[12:16]))
			}
		case lcVersionMinTVOS:
			if len(raw) >= 16 {
				info.Platform = "tvOS"
				info.MinOS = decodeMachOVersion(bo.Uint32(raw[8:12]))
				info.SDKVersion = decodeMachOVersion(bo.Uint32(raw[12:16]))
			}
		case lcVersionMinWatch:
			if len(raw) >= 16 {
				info.Platform = "watchOS"
				info.MinOS = decodeMachOVersion(bo.Uint32(raw[8:12]))
				info.SDKVersion = decodeMachOVersion(bo.Uint32(raw[12:16]))
			}
		case lcBuildVersion:
			if len(raw) >= 20 {
				info.Platform = decodeBuildPlatform(bo.Uint32(raw[8:12]))
				info.MinOS = decodeMachOVersion(bo.Uint32(raw[12:16]))
				info.SDKVersion = decodeMachOVersion(bo.Uint32(raw[16:20]))
			}
		}
	}

	// Linked dylibs & frameworks.
	if libs, err := mf.ImportedLibraries(); err == nil {
		for _, lib := range libs {
			lib = strings.TrimSpace(lib)
			if lib == "" {
				continue
			}
			dylibSet[lib] = true
			if fw := extractFrameworkName(lib); fw != "" {
				fwSet[fw] = true
			}
		}
	}

	// Symbols: ARC, stack canary, exports, and _OBJC_CLASS_$_* fallback.
	checkSymIndicators := func(name string) {
		switch name {
		case "_objc_release", "objc_release", "_objc_retain", "objc_retain",
			"_objc_autoreleaseReturnValue", "_objc_storeStrong":
			info.ARC = true
		case "___stack_chk_fail", "__stack_chk_fail", "___stack_chk_guard", "__stack_chk_guard":
			info.StackCanary = true
		}
		if strings.HasPrefix(name, "_OBJC_CLASS_$_") {
			cls := strings.TrimPrefix(name, "_OBJC_CLASS_$_")
			if cls != "" {
				classSet[cls] = true
			}
		}
	}

	if imps, err := mf.ImportedSymbols(); err == nil {
		for _, sym := range imps {
			checkSymIndicators(sym)
		}
	}
	if mf.Symtab != nil {
		for _, sym := range mf.Symtab.Syms {
			// Skip STAB debug symbols (N_STAB = 0xe0) for export classification.
			if (sym.Type & 0xe0) != 0 {
				continue
			}
			checkSymIndicators(sym.Name)
			// Defined external symbol: non-STAB, N_EXT (0x01), and sect != 0
			if sym.Name != "" && sym.Sect != 0 && (sym.Type&0x01) != 0 {
				exportSet[sym.Name] = true
			}
		}
	}

	// ObjC sections: __TEXT/__objc_classname, __TEXT/__objc_methname, __DATA/__objc_classlist
	for _, sec := range mf.Sections {
		if sec.Size == 0 || sec.Size > maxMachOSectionBytes {
			continue
		}
		switch {
		case sec.Name == "__objc_classname":
			if data, err := sec.Data(); err == nil {
				for _, s := range extractNullStrings(data, maxObjCStrings) {
					classSet[s] = true
				}
			}
		case sec.Name == "__objc_methname":
			if data, err := sec.Data(); err == nil {
				for _, s := range extractNullStrings(data, maxObjCStrings) {
					selSet[s] = true
				}
			}
		case sec.Name == "__objc_classlist":
			// Static pointer table; if __objc_classname was stripped, try resolving
			// pointers to defined symbols in Symtab.
			if data, err := sec.Data(); err == nil && mf.Symtab != nil {
				ptrSize := 8
				if bits == 32 {
					ptrSize = 4
				}
				symByAddr := make(map[uint64]string)
				for _, sym := range mf.Symtab.Syms {
					if (sym.Type&0xe0) == 0 && sym.Value != 0 && strings.HasPrefix(sym.Name, "_OBJC_CLASS_$_") {
						symByAddr[sym.Value] = strings.TrimPrefix(sym.Name, "_OBJC_CLASS_$_")
					}
				}
				for off := 0; off+ptrSize <= len(data); off += ptrSize {
					var ptr uint64
					if ptrSize == 8 {
						ptr = bo.Uint64(data[off : off+8])
					} else {
						ptr = uint64(bo.Uint32(data[off : off+4]))
					}
					if name, ok := symByAddr[ptr]; ok {
						classSet[name] = true
					}
				}
			}
		}
	}

	return info
}

func extractNullStrings(data []byte, limit int) []string {
	var out []string
	start := 0
	for i := 0; i < len(data) && len(out) < limit; i++ {
		if data[i] == 0 {
			if i > start {
				s := string(data[start:i])
				if isPrintableASCII(s) {
					out = append(out, s)
				}
			}
			start = i + 1
		}
	}
	if start < len(data) && len(out) < limit {
		s := string(data[start:])
		if isPrintableASCII(s) {
			out = append(out, s)
		}
	}
	return out
}

func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func decodeMachOVersion(v uint32) string {
	major := (v >> 16) & 0xffff
	minor := (v >> 8) & 0xff
	patch := v & 0xff
	if patch == 0 {
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func decodeBuildPlatform(p uint32) string {
	switch p {
	case 1:
		return "macOS"
	case 2:
		return "iOS"
	case 3:
		return "tvOS"
	case 4:
		return "watchOS"
	case 5:
		return "bridgeOS"
	case 6:
		return "macCatalyst"
	case 7:
		return "iOSSimulator"
	default:
		return fmt.Sprintf("platform_%d", p)
	}
}

func machoArchName(cpu macho.Cpu, sub uint32) string {
	switch cpu {
	case macho.CpuArm64:
		if (sub & 0xff) == 2 {
			return "arm64e"
		}
		return "arm64"
	case macho.CpuArm:
		return "armv7"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.Cpu386:
		return "i386"
	default:
		return cpu.String()
	}
}

func machoFileTypeName(t macho.Type) string {
	switch t {
	case macho.TypeExec:
		return "MH_EXECUTE"
	case macho.TypeDylib:
		return "MH_DYLIB"
	case macho.TypeBundle:
		return "MH_BUNDLE"
	case macho.TypeObj:
		return "MH_OBJECT"
	default:
		return fmt.Sprintf("0x%x", uint32(t))
	}
}

func extractFrameworkName(libPath string) string {
	idx := strings.Index(libPath, ".framework/")
	if idx < 0 {
		return ""
	}
	prefix := libPath[:idx]
	if slash := strings.LastIndexByte(prefix, '/'); slash >= 0 {
		return prefix[slash+1:]
	}
	return prefix
}

// --- XML Info.plist Parser ---------------------------------------------------

func parseInfoPlist(data []byte) (*IOSPlistInfo, string) {
	if bytes.HasPrefix(data, []byte("bplist")) {
		return &IOSPlistInfo{RawFormat: "bplist"}, "Info.plist is in binary plist (bplist) format; XML metadata extraction skipped"
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	rootDict, err := parseXMLPlistRoot(dec)
	if err != nil {
		return nil, fmt.Sprintf("parse XML Info.plist: %v", err)
	}

	info := &IOSPlistInfo{
		RawFormat:        "xml",
		BundleID:         plistString(rootDict["CFBundleIdentifier"]),
		BundleName:       plistString(rootDict["CFBundleName"]),
		DisplayName:      plistString(rootDict["CFBundleDisplayName"]),
		Executable:       plistString(rootDict["CFBundleExecutable"]),
		Version:          plistString(rootDict["CFBundleShortVersionString"]),
		BuildVersion:     plistString(rootDict["CFBundleVersion"]),
		MinimumOSVersion: plistString(rootDict["MinimumOSVersion"]),
	}

	// CFBundleURLTypes -> []dict -> CFBundleURLSchemes -> []string
	if urlTypes, ok := rootDict["CFBundleURLTypes"].([]any); ok {
		schemeSet := make(map[string]bool)
		for _, item := range urlTypes {
			if d, ok := item.(map[string]any); ok {
				if schemes, ok := d["CFBundleURLSchemes"].([]any); ok {
					for _, s := range schemes {
						if str := plistString(s); str != "" {
							schemeSet[str] = true
						}
					}
				}
			}
		}
		info.URLSchemes = sortedKeys(schemeSet)
	}

	// LSApplicationQueriesSchemes -> []string
	if qSchemes, ok := rootDict["LSApplicationQueriesSchemes"].([]any); ok {
		qSet := make(map[string]bool)
		for _, s := range qSchemes {
			if str := plistString(s); str != "" {
				qSet[str] = true
			}
		}
		info.QueriesSchemes = sortedKeys(qSet)
	}

	// NSAppTransportSecurity -> dict
	if ats, ok := rootDict["NSAppTransportSecurity"].(map[string]any); ok {
		if allow, ok := ats["NSAllowsArbitraryLoads"].(bool); ok {
			info.ATSAllowsArbitraryLoads = allow
		}
		if domains, ok := ats["NSExceptionDomains"].(map[string]any); ok {
			dSet := make(map[string]bool)
			for dom := range domains {
				dSet[dom] = true
			}
			info.ATSExceptionDomains = sortedKeys(dSet)
		}
	}

	return info, ""
}

func parseXMLPlistRoot(dec *xml.Decoder) (map[string]any, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "dict" {
			return parseXMLPlistDict(dec, 1)
		}
	}
}

func parseXMLPlistDict(dec *xml.Decoder, depth int) (map[string]any, error) {
	if depth > maxPlistDepth {
		return nil, fmt.Errorf("XML plist nesting depth exceeds %d", maxPlistDepth)
	}
	out := make(map[string]any)
	var currentKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name.Local == "dict" {
				return out, nil
			}
		case xml.StartElement:
			if t.Name.Local == "key" {
				var k string
				if err := dec.DecodeElement(&k, &t); err != nil {
					return out, err
				}
				currentKey = strings.TrimSpace(k)
			} else {
				val, err := parseXMLPlistValue(dec, t, depth+1)
				if err != nil {
					return out, err
				}
				if currentKey != "" {
					out[currentKey] = val
					currentKey = ""
				}
			}
		}
	}
}

func parseXMLPlistArray(dec *xml.Decoder, depth int) ([]any, error) {
	if depth > maxPlistDepth {
		return nil, fmt.Errorf("XML plist nesting depth exceeds %d", maxPlistDepth)
	}
	var out []any
	for {
		tok, err := dec.Token()
		if err != nil {
			return out, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name.Local == "array" {
				return out, nil
			}
		case xml.StartElement:
			val, err := parseXMLPlistValue(dec, t, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, val)
		}
	}
}

func parseXMLPlistValue(dec *xml.Decoder, start xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, fmt.Errorf("XML plist nesting depth exceeds %d", maxPlistDepth)
	}
	switch start.Name.Local {
	case "dict":
		return parseXMLPlistDict(dec, depth)
	case "array":
		return parseXMLPlistArray(dec, depth)
	case "true":
		_ = dec.Skip()
		return true, nil
	case "false":
		_ = dec.Skip()
		return false, nil
	case "string", "integer", "real", "date", "data":
		var s string
		if err := dec.DecodeElement(&s, &start); err != nil {
			return "", err
		}
		return strings.TrimSpace(s), nil
	default:
		_ = dec.Skip()
		return nil, nil
	}
}

func plistString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func finalizeIOSReportSummary(r *IOSBinaryReport) {
	var archNames []string
	for _, a := range r.Architectures {
		archNames = append(archNames, a.Arch)
	}
	encLabel := "unencrypted"
	if r.FairPlayEncrypted {
		encLabel = fmt.Sprintf("FairPlay-encrypted (cryptid=%d)", r.CryptID)
	}
	r.Summary = fmt.Sprintf(
		"%s (%s, arch=%s, %s, PIE=%v, NX=%v, ARC=%v, Canary=%v, %d dylibs, %d ObjC classes, %d selectors)",
		r.FileName,
		r.FileKind,
		strings.Join(archNames, "+"),
		encLabel,
		r.PIE,
		r.NX,
		r.ARC,
		r.StackCanary,
		len(r.LinkedDylibs),
		len(r.ObjCClasses),
		len(r.ObjCSelectors),
	)
}

// --- Unidbg iOS DarwinEmulatorBuilder Harness --------------------------------

// GenerateUnidbgIOSHarness synthesizes a compilable Java
// DarwinEmulatorBuilder.for64Bit() Unidbg iOS harness targeting a Mach-O
// C symbol, offset, or Objective-C selector with [CAP_RE] structured JSON output.
func GenerateUnidbgIOSHarness(opts UnidbgIOSOptions) *GeneratedToolScript {
	className := sanitizeJavaIdent(opts.ClassName, "CapUnidbgIOSHarness")
	bundleID := firstNonEmptyStr(opts.BundleID, "com.example.iosapp")
	binPath := firstNonEmptyStr(opts.BinaryPath, "/path/to/Payload/App.app/App")
	ipaPath := strings.TrimSpace(opts.IPAPath)
	targetSym := strings.TrimSpace(opts.TargetSymbol)
	objcClass := strings.TrimSpace(opts.ObjCClass)
	objcSel := strings.TrimSpace(opts.ObjCSelector)
	targetOff := strings.TrimSpace(opts.TargetOffset)
	if targetSym == "" && targetOff == "" && (objcClass == "" || objcSel == "") {
		targetSym = "_sign_payload"
	}
	sampleArg := "payload=hello&ts=1700000000"
	if len(opts.Args) > 0 && strings.TrimSpace(opts.Args[0]) != "" {
		sampleArg = opts.Args[0]
	}

	var b strings.Builder
	b.WriteString("// ─── cap Auto-Generated Unidbg iOS (ARM64) Harness ───────────────────\n")
	fmt.Fprintf(&b, "// Bundle ID: %s\n", sanitizeComment(bundleID))
	fmt.Fprintf(&b, "// Binary:    %s\n", sanitizeComment(binPath))
	if objcClass != "" && objcSel != "" {
		fmt.Fprintf(&b, "// Target:    +[%s %s]\n", sanitizeComment(objcClass), sanitizeComment(objcSel))
	} else if targetSym != "" {
		fmt.Fprintf(&b, "// Target:    %s\n", sanitizeComment(targetSym))
	} else if targetOff != "" {
		fmt.Fprintf(&b, "// Target:    offset %s\n", sanitizeComment(targetOff))
	}
	b.WriteString("\n")
	b.WriteString(`import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.DarwinEmulatorBuilder;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import java.io.File;
import java.io.IOException;
`)

	fmt.Fprintf(&b, "\npublic class %s {\n", className)
	fmt.Fprintf(&b, "    private static final String BUNDLE_ID = %s;\n", javaQuote(bundleID))
	fmt.Fprintf(&b, "    private static final String BINARY_PATH = envOr(\"CAP_RE_BINARY\", %s);\n", javaQuote(binPath))
	fmt.Fprintf(&b, "    private static final String IPA_PATH = envOr(\"CAP_RE_IPA\", %s);\n", javaQuote(ipaPath))
	fmt.Fprintf(&b, "    private static final String TARGET_SYMBOL = %s;\n", javaQuote(targetSym))
	fmt.Fprintf(&b, "    private static final String OBJC_CLASS = %s;\n", javaQuote(objcClass))
	fmt.Fprintf(&b, "    private static final String OBJC_SELECTOR = %s;\n", javaQuote(objcSel))
	fmt.Fprintf(&b, "    private static final String TARGET_OFFSET = %s;\n\n", javaQuote(targetOff))

	b.WriteString(`    private final Emulator<?> emulator;
    private final Module module;

    public ` + className + `() throws IOException {
        if (!IPA_PATH.isEmpty() && new File(IPA_PATH).isFile()) {
            LoadedIpa ipa = new IpaLoader64(new File(IPA_PATH), new File("target/rootfs")).load();
            this.emulator = ipa.getEmulator();
            this.module = ipa.getExecutable();
        } else {
            this.emulator = DarwinEmulatorBuilder.for64Bit()
                    .setProcessName(BUNDLE_ID)
                    .build();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new DarwinResolver("7.1"));
            this.module = emulator.loadLibrary(new File(BINARY_PATH), true);
        }
    }

    public String invokeTarget(String input) {
        if (!OBJC_CLASS.isEmpty() && !OBJC_SELECTOR.isEmpty()) {
            ObjC objc = ObjC.getInstance(emulator);
            ObjcClass cls = objc.getClass(OBJC_CLASS);
            ObjcObject nsInput = objc.getClass("NSString").callObjc("stringWithUTF8String:", input);
            ObjcObject res = cls.callObjc(OBJC_SELECTOR, nsInput);
            if (res == null) {
                return "";
            }
            return res.getDescription();
        }

        Number ret;
        if (!TARGET_SYMBOL.isEmpty()) {
            Symbol sym = module.findSymbolByName(TARGET_SYMBOL, false);
            if (sym == null) {
                throw new IllegalStateException("Mach-O symbol not found: " + TARGET_SYMBOL);
            }
            ret = sym.call(emulator, input);
        } else if (!TARGET_OFFSET.isEmpty()) {
            long off = Long.decode(TARGET_OFFSET);
            ret = module.callFunction(emulator, off, input);
        } else {
            throw new IllegalStateException("No target symbol, ObjC class+selector, or offset configured");
        }
        if (ret == null) {
            return "";
        }
        UnidbgPointer ptr = UnidbgPointer.pointer(emulator, ret.longValue());
        return ptr != null ? ptr.getString(0) : Long.toHexString(ret.longValue());
    }

    public void close() throws IOException {
        if (emulator != null) {
            emulator.close();
        }
    }

    private static String envOr(String key, String fallback) {
        String v = System.getenv(key);
        return (v != null && !v.trim().isEmpty()) ? v.trim() : fallback;
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    public static void main(String[] args) throws Exception {
        String input = args.length > 0 ? args[0] : ` + javaQuote(sampleArg) + `;
        ` + className + ` harness = new ` + className + `();
        try {
            String result = harness.invokeTarget(input);
            String target = !OBJC_CLASS.isEmpty() ? (OBJC_CLASS + "." + OBJC_SELECTOR) : (!TARGET_SYMBOL.isEmpty() ? TARGET_SYMBOL : TARGET_OFFSET);
            System.out.println("[CAP_RE] {\"kind\":\"ios_emulation\",\"bundle_id\":\"" + jsonEscape(BUNDLE_ID) + "\",\"target\":\"" + jsonEscape(target) + "\",\"input\":\"" + jsonEscape(input) + "\",\"result\":\"" + jsonEscape(result) + "\"}");
        } finally {
            harness.close();
        }
    }
}
`)

	return &GeneratedToolScript{
		Name:        fmt.Sprintf("Unidbg iOS Harness · %s", bundleID),
		Kind:        "unidbg_ios_harness",
		Engine:      "unidbg",
		Language:    "java",
		FileName:    className + ".java",
		Description: fmt.Sprintf("Unidbg ARM64 DarwinEmulatorBuilder harness for iOS binary %s (%s).", filepath.Base(binPath), bundleID),
		Summary:     fmt.Sprintf("Generated Unidbg iOS harness %s.java emitting [CAP_RE] JSON.", className),
		Code:        b.String(),
		Notes: []string{
			"Requires an unencrypted (decrypted on test device) ARM64 Mach-O or IPA; FairPlay-encrypted binaries (cryptid != 0) cannot be emulated directly.",
			"Override CAP_RE_BINARY or CAP_RE_IPA environment variables at runtime to swap target paths without recompiling.",
		},
		Tags:        []string{"unidbg", "ios", "arm64", "macho", "objc"},
		GeneratedAt: nowRFC3339(),
	}
}

// --- iOS Anti-Debug / Jailbreak Stealth Frida Script -------------------------

// GenerateIOSStealthScript synthesizes a syntax-verified Frida JS script for
// authorized iOS dynamic security analysis covering PT_DENY_ATTACH (ptrace),
// sysctl P_TRACED, getppid, dyld image/dladdr inspection, and common jailbreak
// path/URL scheme checks.
func GenerateIOSStealthScript(opts IOSStealthOptions) *GeneratedToolScript {
	anySet := opts.BypassPtrace || opts.BypassSysctl || opts.BypassGetppid ||
		opts.BypassDyldChecks || opts.BypassJailbreakChecks
	if !anySet {
		opts.BypassPtrace = true
		opts.BypassSysctl = true
		opts.BypassGetppid = true
		opts.BypassDyldChecks = true
		opts.BypassJailbreakChecks = true
	}

	hidePaths := []string{
		"/Applications/Cydia.app",
		"/Applications/Sileo.app",
		"/Applications/Zebra.app",
		"/Library/MobileSubstrate",
		"/usr/sbin/sshd",
		"/usr/bin/sshd",
		"/bin/bash",
		"/etc/apt",
		"/private/var/lib/apt",
		"/private/var/lib/cydia",
		"/private/var/stash",
		"/var/jb",
		"/usr/lib/libhooker.dylib",
		"/usr/lib/substitute-inserter.dylib",
		"/usr/lib/TweakInject",
	}
	for _, p := range opts.CustomHidePaths {
		if t := strings.TrimSpace(p); t != "" {
			hidePaths = append(hidePaths, t)
		}
	}

	hideSchemes := []string{
		"cydia://",
		"sileo://",
		"zbra://",
		"filza://",
		"undecimus://",
	}
	for _, s := range opts.CustomHideSchemes {
		if t := strings.TrimSpace(s); t != "" {
			hideSchemes = append(hideSchemes, t)
		}
	}

	dyldTokens := []string{
		"frida", "FridaGadget", "Substrate", "MobileSubstrate",
		"TweakInject", "libhooker", "substitute", "ElleKit", "Cydia",
	}

	var modules []string
	if opts.BypassPtrace {
		modules = append(modules, "ptrace")
	}
	if opts.BypassSysctl {
		modules = append(modules, "sysctl")
	}
	if opts.BypassGetppid {
		modules = append(modules, "getppid")
	}
	if opts.BypassDyldChecks {
		modules = append(modules, "dyld/dladdr")
	}
	if opts.BypassJailbreakChecks {
		modules = append(modules, "jailbreak-fs-url")
	}

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap iOS Dynamic Analysis Stealth Script (Frida) ─────────────────\n")
	if opts.BundleID != "" {
		fmt.Fprintf(&b, "// Bundle ID:      %s\n", sanitizeComment(opts.BundleID))
	}
	if opts.TargetBinary != "" {
		fmt.Fprintf(&b, "// Target Binary:  %s\n", sanitizeComment(opts.TargetBinary))
	}
	fmt.Fprintf(&b, "// Active Modules: %s\n\n", strings.Join(modules, ", "))

	fmt.Fprintf(&b, "const CONFIG = {\n")
	fmt.Fprintf(&b, "    bundleId: %s,\n", jsQuote(opts.BundleID))
	fmt.Fprintf(&b, "    targetBinary: %s,\n", jsQuote(opts.TargetBinary))
	fmt.Fprintf(&b, "    hidePaths: [%s],\n", joinJSQuoted(hidePaths))
	fmt.Fprintf(&b, "    hideSchemes: [%s],\n", joinJSQuoted(hideSchemes))
	fmt.Fprintf(&b, "    dyldTokens: [%s]\n", joinJSQuoted(dyldTokens))
	fmt.Fprintf(&b, "};\n\n")

	b.WriteString(`function emitEvent(moduleName, hook, detail) {
    send(Object.assign({
        cap_cat: 'ios_stealth',
        module: moduleName,
        hook: hook
    }, detail || {}));
}

function matchesAnyToken(str, list) {
    if (!str) return false;
    const low = String(str).toLowerCase();
    for (let i = 0; i < list.length; i++) {
        if (low.indexOf(list[i].toLowerCase()) !== -1) {
            return list[i];
        }
    }
    return false;
}

function findExport(name) {
    return Module.findExportByName('libsystem_kernel.dylib', name) ||
        Module.findExportByName('libsystem_c.dylib', name) ||
        Module.findExportByName('libdyld.dylib', name) ||
        Module.findExportByName(null, name);
}
`)

	if opts.BypassPtrace {
		b.WriteString(`
// 1. PT_DENY_ATTACH (ptrace / syscall SYS_ptrace)
(function installPtraceHooks() {
    const PT_DENY_ATTACH = 31;
    const SYS_PTRACE = 26;

    const ptracePtr = findExport('ptrace');
    if (ptracePtr) {
        Interceptor.attach(ptracePtr, {
            onEnter: function (args) {
                if (args[0].toInt32() === PT_DENY_ATTACH) {
                    args[0] = ptr(0);
                    this.blocked = true;
                    emitEvent('ptrace', 'ptrace', { request: 'PT_DENY_ATTACH', action: 'neutralized' });
                }
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    retval.replace(ptr(0));
                }
            }
        });
    }

    const syscallPtr = findExport('syscall');
    if (syscallPtr) {
        Interceptor.attach(syscallPtr, {
            onEnter: function (args) {
                if (args[0].toInt32() === SYS_PTRACE && args[1].toInt32() === PT_DENY_ATTACH) {
                    args[1] = ptr(0);
                    this.blocked = true;
                    emitEvent('ptrace', 'syscall', { syscall: SYS_PTRACE, request: 'PT_DENY_ATTACH', action: 'neutralized' });
                }
            },
            onLeave: function (retval) {
                if (this.blocked) {
                    retval.replace(ptr(0));
                }
            }
        });
    }
})();
`)
	}

	if opts.BypassSysctl {
		b.WriteString(`
// 2. sysctl CTL_KERN / KERN_PROC / KERN_PROC_PID -> clear P_TRACED (0x800)
(function installSysctlHook() {
    const CTL_KERN = 1;
    const KERN_PROC = 14;
    const KERN_PROC_PID = 1;
    const P_TRACED = 0x00000800;
    const KINFO_P_FLAG_OFFSET = 32; // arm64 / x86_64 Darwin kinfo_proc.kp_proc.p_flag

    const sysctlPtr = findExport('sysctl');
    if (!sysctlPtr) return;

    Interceptor.attach(sysctlPtr, {
        onEnter: function (args) {
            this.patchInfo = false;
            const mib = args[0];
            const namelen = args[1].toInt32();
            if (!mib.isNull() && namelen >= 3) {
                const c0 = mib.readS32();
                const c1 = mib.add(4).readS32();
                const c2 = mib.add(8).readS32();
                if (c0 === CTL_KERN && c1 === KERN_PROC && c2 === KERN_PROC_PID) {
                    this.oldp = args[2];
                    this.patchInfo = !this.oldp.isNull();
                }
            }
        },
        onLeave: function (retval) {
            if (this.patchInfo && retval.toInt32() === 0) {
                try {
                    const flagPtr = this.oldp.add(KINFO_P_FLAG_OFFSET);
                    const flags = flagPtr.readU32();
                    if ((flags & P_TRACED) !== 0) {
                        flagPtr.writeU32((flags & (~P_TRACED)) >>> 0);
                        emitEvent('sysctl', 'sysctl', { cleared: 'P_TRACED', prev_flags: '0x' + flags.toString(16) });
                    }
                } catch (_) {
                    // Ignore short probe buffers
                }
            }
        }
    });
})();
`)
	}

	if opts.BypassGetppid {
		b.WriteString(`
// 3. getppid -> normalize debugger parent PID to launchd (1)
(function installGetppidHook() {
    const getppidPtr = findExport('getppid');
    if (!getppidPtr) return;

    Interceptor.attach(getppidPtr, {
        onLeave: function (retval) {
            const ppid = retval.toInt32();
            if (ppid !== 1) {
                retval.replace(ptr(1));
                emitEvent('getppid', 'getppid', { original_ppid: ppid, spoofed_ppid: 1 });
            }
        }
    });
})();
`)
	}

	if opts.BypassDyldChecks {
		b.WriteString(`
// 4. dyld image enumeration & dladdr instrumentation filtering
(function installDyldHooks() {
    const countPtr = findExport('_dyld_image_count');
    const namePtr = findExport('_dyld_get_image_name');
    const dladdrPtr = findExport('dladdr');

    if (namePtr) {
        const cleanImagePath = Memory.allocUtf8String('/usr/lib/libSystem.B.dylib');
        Interceptor.attach(namePtr, {
            onLeave: function (retval) {
                if (retval.isNull()) return;
                const img = retval.readCString();
                const hit = matchesAnyToken(img, CONFIG.dyldTokens);
                if (hit) {
                    retval.replace(cleanImagePath);
                    emitEvent('dyld', '_dyld_get_image_name', { hidden_image: img, token: hit });
                }
            }
        });
    }

    if (countPtr) {
        Interceptor.attach(countPtr, {
            onLeave: function (retval) {
                this.count = retval.toUInt32();
            }
        });
    }

    if (dladdrPtr) {
        Interceptor.attach(dladdrPtr, {
            onEnter: function (args) {
                this.infoPtr = args[1];
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0 && this.infoPtr && !this.infoPtr.isNull()) {
                    try {
                        const fnamePtr = this.infoPtr.readPointer();
                        if (!fnamePtr.isNull()) {
                            const fname = fnamePtr.readCString();
                            const hit = matchesAnyToken(fname, CONFIG.dyldTokens);
                            if (hit) {
                                retval.replace(ptr(0));
                                emitEvent('dyld', 'dladdr', { hidden_fname: fname, token: hit });
                            }
                        }
                    } catch (_) {
                        // Ignore unreadable Dl_info
                    }
                }
            }
        });
    }
})();
`)
	}

	if opts.BypassJailbreakChecks {
		b.WriteString(`
// 5. Common jailbreak filesystem & URL scheme checks
(function installJailbreakHooks() {
    const hookPathFunc = function (fnName, failRet) {
        const p = findExport(fnName);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function (args) {
                this.hide = false;
                if (!args[0].isNull()) {
                    const path = args[0].readCString();
                    if (matchesAnyToken(path, CONFIG.hidePaths)) {
                        this.hide = true;
                        this.path = path;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.hide) {
                    retval.replace(ptr(failRet));
                    emitEvent('jailbreak', fnName, { path: this.path, result: failRet });
                }
            }
        });
    };

    hookPathFunc('access', -1);
    hookPathFunc('stat', -1);
    hookPathFunc('lstat', -1);
    hookPathFunc('fopen', 0);

    if (typeof ObjC !== 'undefined' && ObjC.available) {
        if (ObjC.classes.NSFileManager) {
            const existsMeth = ObjC.classes.NSFileManager['- fileExistsAtPath:'];
            if (existsMeth) {
                Interceptor.attach(existsMeth.implementation, {
                    onEnter: function (args) {
                        this.hide = false;
                        const path = new ObjC.Object(args[2]).toString();
                        if (matchesAnyToken(path, CONFIG.hidePaths)) {
                            this.hide = true;
                            this.path = path;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.hide) {
                            retval.replace(ptr(0));
                            emitEvent('jailbreak', 'NSFileManager.fileExistsAtPath:', { path: this.path });
                        }
                    }
                });
            }
        }

        if (ObjC.classes.UIApplication) {
            const canOpenMeth = ObjC.classes.UIApplication['- canOpenURL:'];
            if (canOpenMeth) {
                Interceptor.attach(canOpenMeth.implementation, {
                    onEnter: function (args) {
                        this.hide = false;
                        const urlStr = new ObjC.Object(args[2]).toString();
                        if (matchesAnyToken(urlStr, CONFIG.hideSchemes)) {
                            this.hide = true;
                            this.url = urlStr;
                        }
                    },
                    onLeave: function (retval) {
                        if (this.hide) {
                            retval.replace(ptr(0));
                            emitEvent('jailbreak', 'UIApplication.canOpenURL:', { url: this.url });
                        }
                    }
                });
            }
        }
    }
})();
`)
	}

	return &GeneratedToolScript{
		Name:        fmt.Sprintf("iOS Stealth Suite · %s", firstNonEmptyStr(opts.BundleID, "generic")),
		Kind:        "ios_stealth_frida",
		Engine:      "frida",
		Language:    "javascript",
		FileName:    "ios_stealth.js",
		Description: fmt.Sprintf("Frida iOS dynamic-analysis stealth script covering %s.", strings.Join(modules, ", ")),
		Summary:     fmt.Sprintf("Generated iOS stealth script with %d active module(s): %s.", len(modules), strings.Join(modules, ", ")),
		Code:        b.String(),
		Notes: []string{
			"Intended for authorized iOS security testing and dynamic instrumentation on test devices.",
			"Listen for Frida messages with cap_cat == 'ios_stealth' to audit triggered anti-debug and jailbreak checks.",
		},
		Tags:        []string{"frida", "ios", "stealth", "anti-debug"},
		GeneratedAt: nowRFC3339(),
	}
}

func joinJSQuoted(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, it := range items {
		quoted = append(quoted, jsQuote(it))
	}
	return strings.Join(quoted, ", ")
}

func sanitizeJavaIdent(raw, fallback string) string {
	s := strings.TrimSpace(strings.TrimSuffix(raw, ".java"))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return fallback
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "Cap" + out
	}
	return strings.ToUpper(out[:1]) + out[1:]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysLimit(m map[string]bool, limit int) []string {
	out := sortedKeys(m)
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}
