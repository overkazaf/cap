package retools

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultR2AnalyzeTimeout = 45 * time.Second
	defaultR2CmdTimeout     = 20 * time.Second
	maxPureGoSectionBytes   = 4 * 1024 * 1024 // 4 MiB per section
	maxExtractedStrings     = 1500
	maxExtractedFunctions   = 5000
	minPrintableStringLen   = 4
)

var (
	safeFuncTargetRe = regexp.MustCompile(`^[a-zA-Z0-9_.$:@+-]{1,256}$`)
	elfDF1Now        = uint64(0x00000001) // DF_1_NOW (Full RELRO with PT_GNU_RELRO)
	elfDF1Pie        = uint64(0x08000000) // DF_1_PIE
)

// AnalyzeBinary performs static analysis on a native binary using radare2
// (`r2 -q -e scr.color=0 -c "aaa;ij;aflj;iEj;iij;izzj" <bin>`) when available,
// and gracefully falls back to pure-Go ELF (`debug/elf`) or Mach-O inspection
// when radare2 is not installed or fails.
func AnalyzeBinary(ctx context.Context, binaryPath, r2Path string) (*BinaryAnalysis, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return nil, fmt.Errorf("binary path is required")
	}
	fi, err := os.Stat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("stat binary %s: %w", binaryPath, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("binary path is a directory: %s", binaryPath)
	}
	if abs, err := filepath.Abs(binaryPath); err == nil {
		binaryPath = abs
	}

	started := time.Now()
	resolvedR2 := resolveR2Binary(r2Path)
	if resolvedR2 != "" {
		res, r2Err := analyzeBinaryWithR2(ctx, binaryPath, fi.Size(), resolvedR2)
		if r2Err == nil {
			res.ElapsedMs = time.Since(started).Milliseconds()
			return res, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Fallback to pure-Go inspection if r2 failed on a readable binary.
		fb, fbErr := analyzeBinaryPureGo(binaryPath, fi.Size())
		if fbErr == nil {
			fb.Warnings = append(fb.Warnings, fmt.Sprintf("radare2 failed (%v); fell back to %s", r2Err, fb.Engine))
			fb.ElapsedMs = time.Since(started).Milliseconds()
			return fb, nil
		}
		return nil, fmt.Errorf("radare2 analysis failed (%v) and pure-Go fallback failed (%v)", r2Err, fbErr)
	}

	fb, err := analyzeBinaryPureGo(binaryPath, fi.Size())
	if err != nil {
		return nil, err
	}
	fb.Warnings = append(fb.Warnings, "radare2 (r2) not found; using pure-Go static binary inspection")
	fb.ElapsedMs = time.Since(started).Milliseconds()
	return fb, nil
}

// InspectFunction retrieves disassembly (pdfj with pdj fallback), pseudo-C
// (pdg with pdc fallback), and cross-references (axtj/axfj) for a single
// function name or hex address. Falls back gracefully to pure-Go ELF symbol
// preview when radare2 is unavailable.
func InspectFunction(ctx context.Context, binaryPath, funcNameOrAddr, r2Path string) (*FunctionDetail, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return nil, fmt.Errorf("binary path is required")
	}
	if fi, err := os.Stat(binaryPath); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("binary file not accessible: %s", binaryPath)
	}

	target := strings.TrimSpace(funcNameOrAddr)
	if target == "" {
		return nil, fmt.Errorf("function name or address is required")
	}
	if !safeFuncTargetRe.MatchString(target) {
		return nil, fmt.Errorf("invalid function target %q: contains unsafe characters", target)
	}

	resolvedR2 := resolveR2Binary(r2Path)
	if resolvedR2 == "" {
		return inspectFunctionPureGoELF(binaryPath, target)
	}

	runCtx, cancel := withDefaultTimeout(ctx, defaultR2CmdTimeout)
	defer cancel()

	// Single r2 invocation using section delimiters for fast, reliable parsing.
	r2Cmd := strings.Join([]string{
		fmt.Sprintf("s %s", target),
		"af",
		"?e __CAP_PDFJ__",
		"pdfj",
		"?e __CAP_PDJ__",
		"pdj 48",
		"?e __CAP_AXTJ__",
		"axtj",
		"?e __CAP_AXFJ__",
		"axfj",
		"?e __CAP_PDG__",
		"pdg",
		"?e __CAP_PDC__",
		"pdc",
	}, "; ")

	cmd := exec.CommandContext(runCtx, resolvedR2,
		"-q",
		"-e", "cfg.sandbox=true",
		"-e", "scr.color=0",
		"-c", r2Cmd,
		binaryPath,
	)
	configureProcGroup(cmd)
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if fb, fbErr := inspectFunctionPureGoELF(binaryPath, target); fbErr == nil {
			fb.Warnings = append(fb.Warnings, fmt.Sprintf("radare2 inspect failed (%v); returned pure-Go symbol info", err))
			return fb, nil
		}
		return nil, fmt.Errorf("radare2 inspect %s: %w", target, err)
	}

	return parseInspectFunctionOutput(target, string(out)), nil
}

// ValidateR2Command enforces read-only safety on an r2 command string,
// rejecting shell escapes (`!`), piping (`|`), redirection (`>`/`<`),
// backticks, command substitution (`$(`), write/patch families (`w*`), and
// sandbox/IO reconfiguration commands.
func ValidateR2Command(r2Cmd string) error {
	trimmed := strings.TrimSpace(r2Cmd)
	if trimmed == "" {
		return fmt.Errorf("r2 command is required")
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return fmt.Errorf("r2 command must be a single line without control characters")
	}
	for _, forbidden := range []string{"!", "`", "|", ">", "<", "$("} {
		if strings.Contains(trimmed, forbidden) {
			return fmt.Errorf("unsafe r2 command rejected: contains forbidden token %q", forbidden)
		}
	}

	segments := strings.Split(trimmed, ";")
	for _, seg := range segments {
		s := strings.TrimSpace(seg)
		if s == "" {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) == 0 {
			continue
		}
		head := fields[0]
		lowHead := strings.ToLower(head)

		// Reject write/patch commands (r2's `w*` family), script/lang loaders,
		// remote/macro commands, and file-reopen write commands.
		if strings.HasPrefix(lowHead, "w") {
			return fmt.Errorf("unsafe r2 write command rejected: %q", head)
		}
		if strings.HasPrefix(head, "#") || strings.HasPrefix(head, "(") || strings.HasPrefix(head, "=") {
			return fmt.Errorf("unsafe r2 command prefix rejected: %q", head)
		}
		if strings.HasPrefix(head, ".") && head != "." {
			return fmt.Errorf("unsafe r2 interpret command rejected: %q", head)
		}
		if strings.HasPrefix(lowHead, "oo+") || lowHead == "o+" || lowHead == "rm" || lowHead == "mv" || lowHead == "cp" || lowHead == "chmod" {
			return fmt.Errorf("unsafe r2 filesystem/io command rejected: %q", head)
		}
		if strings.HasPrefix(head, "P") && len(head) >= 2 && (head[1] == 's' || head[1] == 'd') {
			return fmt.Errorf("unsafe r2 project write command rejected: %q", head)
		}
		if head == "e" || strings.HasPrefix(head, "e ") {
			lowSeg := strings.ToLower(s)
			for _, badKey := range []string{"cfg.sandbox", "io.cache", "io.write", "cmd.", "file."} {
				if strings.Contains(lowSeg, badKey) {
					return fmt.Errorf("unsafe r2 config mutation rejected: %q", s)
				}
			}
		}
	}
	return nil
}

// RunR2Command runs a sanitized read-only radare2 command against binaryPath
// with `cfg.sandbox=true` enabled as defense-in-depth.
func RunR2Command(ctx context.Context, binaryPath, r2Cmd, r2Path string) (*R2CommandResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateR2Command(r2Cmd); err != nil {
		return nil, err
	}

	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return nil, fmt.Errorf("binary path is required")
	}
	if fi, err := os.Stat(binaryPath); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("binary file not accessible: %s", binaryPath)
	}

	resolvedR2 := resolveR2Binary(r2Path)
	if resolvedR2 == "" {
		return nil, fmt.Errorf("radare2 (r2) binary not found")
	}

	runCtx, cancel := withDefaultTimeout(ctx, defaultR2CmdTimeout)
	defer cancel()

	started := time.Now()
	cmd := exec.CommandContext(runCtx, resolvedR2,
		"-q",
		"-e", "cfg.sandbox=true",
		"-e", "scr.color=0",
		"-c", strings.TrimSpace(r2Cmd),
		binaryPath,
	)
	configureProcGroup(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("r2 command failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return &R2CommandResult{
		BinaryPath: binaryPath,
		Command:    strings.TrimSpace(r2Cmd),
		Output:     strings.TrimRight(string(out), "\r\n"),
		ElapsedMs:  time.Since(started).Milliseconds(),
	}, nil
}

func resolveR2Binary(preferred string) string {
	preferred = strings.TrimSpace(preferred)
	cands := buildBinaryCandidates(preferred, "r2", "radare2")
	for _, c := range cands {
		if isExecutableFile(c) {
			return c
		}
	}
	return ""
}

func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func analyzeBinaryWithR2(ctx context.Context, binaryPath string, fileSize int64, r2Bin string) (*BinaryAnalysis, error) {
	runCtx, cancel := withDefaultTimeout(ctx, defaultR2AnalyzeTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, r2Bin,
		"-q",
		"-e", "scr.color=0",
		"-c", "aaa;ij;aflj;iEj;iij;izzj",
		binaryPath,
	)
	configureProcGroup(cmd)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run r2: %w", err)
	}
	return parseR2AnalyzeOutput(binaryPath, fileSize, out)
}

// parseR2AnalyzeOutput parses the sequential JSON documents produced by
// `r2 -q -e scr.color=0 -c "aaa;ij;aflj;iEj;iij;izzj" <bin>`.
func parseR2AnalyzeOutput(binaryPath string, fileSize int64, raw []byte) (*BinaryAnalysis, error) {
	docs := decodeR2JSONSequence(raw)
	if len(docs) == 0 {
		return nil, fmt.Errorf("r2 returned no parseable JSON output")
	}

	analysis := &BinaryAnalysis{
		FilePath:    binaryPath,
		FileName:    filepath.Base(binaryPath),
		FileSize:    fileSize,
		Mitigations: SecurityMitigations{RELRO: RELROUnknown},
		Functions:   []BinaryFunction{},
		Exports:     []BinarySymbol{},
		Imports:     []BinarySymbol{},
		Strings:     []BinaryString{},
		XRefs:       []BinaryXRef{},
		Engine:      EngineRadare2,
		AnalyzedAt:  nowRFC3339(),
	}

	// Document 0: ij
	if len(docs) >= 1 {
		parseR2IJ(docs[0], analysis)
	}
	// Document 1: aflj
	if len(docs) >= 2 {
		parseR2AFLJ(docs[1], analysis)
	}
	// Document 2: iEj
	if len(docs) >= 3 {
		parseR2ExportsJSON(docs[2], analysis)
	}
	// Document 3: iij
	if len(docs) >= 4 {
		parseR2ImportsJSON(docs[3], analysis)
	}
	// Document 4: izzj
	if len(docs) >= 5 {
		parseR2StringsJSON(docs[4], analysis)
	}

	return analysis, nil
}

// decodeR2JSONSequence extracts consecutive top-level JSON objects/arrays from
// radare2 stdout while skipping stray diagnostic/warning lines.
func decodeR2JSONSequence(raw []byte) []json.RawMessage {
	data := bytes.TrimSpace(raw)
	var docs []json.RawMessage
	pos := 0
	for pos < len(data) {
		idxObj := bytes.IndexByte(data[pos:], '{')
		idxArr := bytes.IndexByte(data[pos:], '[')
		rel := -1
		switch {
		case idxObj >= 0 && idxArr >= 0:
			if idxObj < idxArr {
				rel = idxObj
			} else {
				rel = idxArr
			}
		case idxObj >= 0:
			rel = idxObj
		case idxArr >= 0:
			rel = idxArr
		}
		if rel < 0 {
			break
		}
		pos += rel
		dec := json.NewDecoder(bytes.NewReader(data[pos:]))
		var msg json.RawMessage
		if err := dec.Decode(&msg); err != nil {
			pos++
			continue
		}
		docs = append(docs, msg)
		consumed := int(dec.InputOffset())
		if consumed <= 0 {
			pos++
		} else {
			pos += consumed
		}
	}
	return docs
}

func parseR2IJ(doc json.RawMessage, out *BinaryAnalysis) {
	var ij struct {
		Core struct {
			Format string `json:"format"`
			Size   int64  `json:"size"`
		} `json:"core"`
		Bin struct {
			Arch     string `json:"arch"`
			Bits     int    `json:"bits"`
			Endian   string `json:"endian"`
			BinType  string `json:"bintype"`
			Class    string `json:"class"`
			OS       string `json:"os"`
			Machine  string `json:"machine"`
			BAddr    uint64 `json:"baddr"`
			PIE      bool   `json:"pic"`
			NX       bool   `json:"nx"`
			Canary   bool   `json:"canary"`
			RELRO    string `json:"relro"`
			Stripped bool   `json:"stripped"`
		} `json:"bin"`
	}
	if err := json.Unmarshal(doc, &ij); err != nil {
		return
	}
	if out.FileSize == 0 && ij.Core.Size > 0 {
		out.FileSize = ij.Core.Size
	}
	out.Arch = normalizeArchName(ij.Bin.Arch, ij.Bin.Bits, ij.Bin.Machine)
	out.Bits = ij.Bin.Bits
	out.Endian = strings.ToLower(strings.TrimSpace(ij.Bin.Endian))
	if out.Endian == "" {
		out.Endian = "little"
	}
	out.OS = ij.Bin.OS
	out.Format = strings.ToLower(strings.TrimSpace(ij.Bin.Class))
	if out.Format == "" {
		out.Format = strings.ToLower(strings.TrimSpace(ij.Bin.BinType))
	}
	if out.Format == "" {
		out.Format = strings.ToLower(strings.TrimSpace(ij.Core.Format))
	}
	if ij.Bin.BAddr > 0 {
		out.EntryPoint = fmt.Sprintf("0x%x", ij.Bin.BAddr)
	}
	out.Mitigations = SecurityMitigations{
		PIE:      ij.Bin.PIE,
		NX:       ij.Bin.NX,
		Canary:   ij.Bin.Canary,
		RELRO:    normalizeRELRO(ij.Bin.RELRO),
		Stripped: ij.Bin.Stripped,
	}
}

func parseR2AFLJ(doc json.RawMessage, out *BinaryAnalysis) {
	var funcs []struct {
		Name      string `json:"name"`
		Offset    uint64 `json:"offset"`
		Size      uint64 `json:"size"`
		RealSz    uint64 `json:"realsz"`
		Signature string `json:"signature"`
		CallRefs  []struct {
			Addr uint64 `json:"addr"`
			Type string `json:"type"`
			At   uint64 `json:"at"`
		} `json:"callrefs"`
	}
	if err := json.Unmarshal(doc, &funcs); err != nil {
		return
	}
	if len(funcs) > maxExtractedFunctions {
		funcs = funcs[:maxExtractedFunctions]
	}
	for _, f := range funcs {
		sz := f.Size
		if sz == 0 {
			sz = f.RealSz
		}
		clean := stripR2SymPrefix(f.Name)
		out.Functions = append(out.Functions, BinaryFunction{
			Name:      f.Name,
			Addr:      fmt.Sprintf("0x%x", f.Offset),
			Offset:    f.Offset,
			Size:      sz,
			Signature: f.Signature,
			CallCount: len(f.CallRefs),
			IsJNI:     isJNISymbolName(clean),
		})
		for _, cr := range f.CallRefs {
			if len(out.XRefs) >= 2000 {
				break
			}
			fromAddr := cr.At
			if fromAddr == 0 {
				fromAddr = f.Offset
			}
			out.XRefs = append(out.XRefs, BinaryXRef{
				From:     fmt.Sprintf("0x%x", fromAddr),
				FromName: f.Name,
				To:       fmt.Sprintf("0x%x", cr.Addr),
				Type:     strings.ToUpper(cr.Type),
			})
		}
	}
}

func parseR2ExportsJSON(doc json.RawMessage, out *BinaryAnalysis) {
	var exps []struct {
		Name  string `json:"name"`
		VAddr uint64 `json:"vaddr"`
		PAddr uint64 `json:"paddr"`
		Size  uint64 `json:"size"`
		Type  string `json:"type"`
		Bind  string `json:"bind"`
	}
	if err := json.Unmarshal(doc, &exps); err != nil {
		return
	}
	for _, e := range exps {
		if strings.TrimSpace(e.Name) == "" {
			continue
		}
		addr := e.VAddr
		if addr == 0 {
			addr = e.PAddr
		}
		out.Exports = append(out.Exports, BinarySymbol{
			Name:   e.Name,
			Addr:   fmt.Sprintf("0x%x", addr),
			Offset: addr,
			Size:   e.Size,
			Type:   e.Type,
			Bind:   e.Bind,
			IsJNI:  isJNISymbolName(stripR2SymPrefix(e.Name)),
		})
	}
}

func parseR2ImportsJSON(doc json.RawMessage, out *BinaryAnalysis) {
	var imps []struct {
		Name    string `json:"name"`
		PLT     uint64 `json:"plt"`
		VAddr   uint64 `json:"vaddr"`
		Type    string `json:"type"`
		Bind    string `json:"bind"`
		LibName string `json:"libname"`
	}
	if err := json.Unmarshal(doc, &imps); err != nil {
		return
	}
	for _, imp := range imps {
		if strings.TrimSpace(imp.Name) == "" {
			continue
		}
		addr := imp.PLT
		if addr == 0 {
			addr = imp.VAddr
		}
		addrStr := ""
		if addr > 0 {
			addrStr = fmt.Sprintf("0x%x", addr)
		}
		out.Imports = append(out.Imports, BinarySymbol{
			Name:    imp.Name,
			Addr:    addrStr,
			Offset:  addr,
			Type:    imp.Type,
			Bind:    imp.Bind,
			Library: imp.LibName,
		})
	}
}

func parseR2StringsJSON(doc json.RawMessage, out *BinaryAnalysis) {
	type r2Str struct {
		VAddr   uint64 `json:"vaddr"`
		PAddr   uint64 `json:"paddr"`
		Length  int    `json:"length"`
		Section string `json:"section"`
		Type    string `json:"type"`
		String  string `json:"string"`
	}
	var list []r2Str
	if err := json.Unmarshal(doc, &list); err != nil {
		var wrapped struct {
			Strings []r2Str `json:"strings"`
		}
		if err2 := json.Unmarshal(doc, &wrapped); err2 != nil {
			return
		}
		list = wrapped.Strings
	}
	if len(list) > maxExtractedStrings {
		list = list[:maxExtractedStrings]
	}
	for _, s := range list {
		if s.String == "" {
			continue
		}
		addr := s.VAddr
		if addr == 0 {
			addr = s.PAddr
		}
		length := s.Length
		if length == 0 {
			length = len(s.String)
		}
		out.Strings = append(out.Strings, BinaryString{
			Value:   s.String,
			Addr:    fmt.Sprintf("0x%x", addr),
			Offset:  addr,
			Section: s.Section,
			Length:  length,
			Type:    s.Type,
		})
	}
}

func parseInspectFunctionOutput(target, raw string) *FunctionDetail {
	sections := splitMarkedSections(raw, []string{
		"__CAP_PDFJ__",
		"__CAP_PDJ__",
		"__CAP_AXTJ__",
		"__CAP_AXFJ__",
		"__CAP_PDG__",
		"__CAP_PDC__",
	})

	detail := &FunctionDetail{
		Name:      target,
		Engine:    EngineRadare2,
		XRefsTo:   []BinaryXRef{},
		XRefsFrom: []BinaryXRef{},
	}

	type r2Op struct {
		Offset  uint64 `json:"offset"`
		Bytes   string `json:"bytes"`
		Disasm  string `json:"disasm"`
		Opcode  string `json:"opcode"`
		Type    string `json:"type"`
		Comment string `json:"comment"`
		Jump    uint64 `json:"jump"`
	}

	var ops []r2Op
	// Try pdfj first
	if pdfDocs := decodeR2JSONSequence([]byte(sections["__CAP_PDFJ__"])); len(pdfDocs) > 0 {
		var pdf struct {
			Name string `json:"name"`
			Addr uint64 `json:"addr"`
			Size uint64 `json:"size"`
			Ops  []r2Op `json:"ops"`
		}
		if json.Unmarshal(pdfDocs[0], &pdf) == nil && len(pdf.Ops) > 0 {
			if pdf.Name != "" {
				detail.Name = pdf.Name
			}
			if pdf.Addr > 0 {
				detail.Addr = fmt.Sprintf("0x%x", pdf.Addr)
			}
			detail.Size = pdf.Size
			ops = pdf.Ops
		}
	}

	// Fallback to pdj when pdfj did not yield ops
	if len(ops) == 0 {
		if pdjDocs := decodeR2JSONSequence([]byte(sections["__CAP_PDJ__"])); len(pdjDocs) > 0 {
			var pdOps []r2Op
			if json.Unmarshal(pdjDocs[0], &pdOps) == nil && len(pdOps) > 0 {
				ops = pdOps
				if detail.Addr == "" && pdOps[0].Offset > 0 {
					detail.Addr = fmt.Sprintf("0x%x", pdOps[0].Offset)
				}
			}
		}
	}

	var disasmBuf strings.Builder
	for _, op := range ops {
		text := op.Disasm
		if text == "" {
			text = op.Opcode
		}
		jumpStr := ""
		if op.Jump > 0 {
			jumpStr = fmt.Sprintf("0x%x", op.Jump)
		}
		line := DisasmLine{
			Addr:    fmt.Sprintf("0x%x", op.Offset),
			Bytes:   op.Bytes,
			Disasm:  text,
			Type:    op.Type,
			Comment: op.Comment,
			Jump:    jumpStr,
		}
		detail.DisasmLines = append(detail.DisasmLines, line)
		fmt.Fprintf(&disasmBuf, "0x%08x  %-16s  %s\n", op.Offset, op.Bytes, text)
	}
	detail.Disasm = strings.TrimRight(disasmBuf.String(), "\n")

	// Parse axtj (xrefs TO this function)
	if axtDocs := decodeR2JSONSequence([]byte(sections["__CAP_AXTJ__"])); len(axtDocs) > 0 {
		var refs []struct {
			From    uint64 `json:"from"`
			Type    string `json:"type"`
			Opcode  string `json:"opcode"`
			FcnName string `json:"fcn_name"`
		}
		if json.Unmarshal(axtDocs[0], &refs) == nil {
			for _, r := range refs {
				detail.XRefsTo = append(detail.XRefsTo, BinaryXRef{
					From:     fmt.Sprintf("0x%x", r.From),
					FromName: r.FcnName,
					To:       detail.Addr,
					ToName:   detail.Name,
					Type:     strings.ToUpper(r.Type),
					Opcode:   r.Opcode,
				})
			}
		}
	}

	// Parse axfj (xrefs FROM this function)
	if axfDocs := decodeR2JSONSequence([]byte(sections["__CAP_AXFJ__"])); len(axfDocs) > 0 {
		var refs []struct {
			From   uint64 `json:"from"`
			To     uint64 `json:"to"`
			Type   string `json:"type"`
			Opcode string `json:"opcode"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(axfDocs[0], &refs) == nil {
			for _, r := range refs {
				detail.XRefsFrom = append(detail.XRefsFrom, BinaryXRef{
					From:     fmt.Sprintf("0x%x", r.From),
					FromName: detail.Name,
					To:       fmt.Sprintf("0x%x", r.To),
					ToName:   r.Name,
					Type:     strings.ToUpper(r.Type),
					Opcode:   r.Opcode,
				})
			}
		}
	}

	// Pick pseudo-C: prefer pdg (r2ghidra), fallback to pdc (built-in)
	pdg := cleanPseudoC(sections["__CAP_PDG__"])
	pdc := cleanPseudoC(sections["__CAP_PDC__"])
	if pdg != "" {
		detail.PseudoC = pdg
		detail.PseudoCEngine = "pdg"
	} else if pdc != "" {
		detail.PseudoC = pdc
		detail.PseudoCEngine = "pdc"
	}

	return detail
}

func splitMarkedSections(raw string, markers []string) map[string]string {
	out := make(map[string]string, len(markers))
	markerSet := make(map[string]bool, len(markers))
	for _, m := range markers {
		markerSet[m] = true
	}
	var current string
	var buf strings.Builder
	flush := func() {
		if current != "" {
			out[current] = strings.TrimSpace(buf.String())
		}
		buf.Reset()
	}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if markerSet[trimmed] {
			flush()
			current = trimmed
			continue
		}
		if current != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	flush()
	return out
}

func cleanPseudoC(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	for _, errPrefix := range []string{"cannot find", "unknown command", "invalid command", "error:"} {
		if strings.HasPrefix(low, errPrefix) {
			return ""
		}
	}
	return s
}

// --- Pure-Go ELF & Mach-O Fallback -----------------------------------------

func analyzeBinaryPureGo(binaryPath string, fileSize int64) (*BinaryAnalysis, error) {
	if res, err := analyzeBinaryPureGoELF(binaryPath, fileSize); err == nil {
		return res, nil
	} else if moRes, moErr := analyzeBinaryPureGoMachO(binaryPath, fileSize); moErr == nil {
		return moRes, nil
	} else {
		return nil, fmt.Errorf("unsupported binary format (elf: %v; macho: %v)", err, moErr)
	}
}

func analyzeBinaryPureGoELF(binaryPath string, fileSize int64) (*BinaryAnalysis, error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	bits := 64
	format := "elf64"
	if ef.Class == elf.ELFCLASS32 {
		bits = 32
		format = "elf32"
	}
	endian := "little"
	if ef.Data == elf.ELFDATA2MSB {
		endian = "big"
	}

	entry := ""
	if ef.Entry > 0 {
		entry = fmt.Sprintf("0x%x", ef.Entry)
	}

	res := &BinaryAnalysis{
		FilePath:   binaryPath,
		FileName:   filepath.Base(binaryPath),
		FileSize:   fileSize,
		Format:     format,
		Arch:       elfMachineToArch(ef.Machine),
		Bits:       bits,
		Endian:     endian,
		OS:         elfOSABIToString(ef.OSABI),
		BinaryType: elfTypeToString(ef.Type),
		EntryPoint: entry,
		Functions:  []BinaryFunction{},
		Exports:    []BinarySymbol{},
		Imports:    []BinarySymbol{},
		Strings:    []BinaryString{},
		XRefs:      []BinaryXRef{},
		Engine:     EnginePureGoELF,
		AnalyzedAt: nowRFC3339(),
	}

	// Mitigations: PIE, NX (PT_GNU_STACK), RELRO (PT_GNU_RELRO + BIND_NOW), Stripped, Canary
	mit := SecurityMitigations{
		PIE:      ef.Type == elf.ET_DYN,
		RELRO:    RELRONone,
		Stripped: ef.Section(".symtab") == nil,
	}
	hasRELRO := false
	for _, p := range ef.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			mit.NX = (p.Flags & elf.PF_X) == 0
		case elf.PT_GNU_RELRO:
			hasRELRO = true
		}
	}

	bindNow := false
	if vals, err := ef.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		bindNow = true
	}
	if vals, err := ef.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range vals {
			if elf.DynFlag(v)&elf.DF_BIND_NOW != 0 {
				bindNow = true
			}
		}
	}
	if vals, err := ef.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&elfDF1Now != 0 {
				bindNow = true
			}
			if v&elfDF1Pie != 0 {
				mit.PIE = true
			}
		}
	}
	if hasRELRO {
		if bindNow {
			mit.RELRO = RELROFull
		} else {
			mit.RELRO = RELROPartial
		}
	}

	// Symbols: exports, functions, imports, and stack canary detection
	expSeen := make(map[string]bool)
	fnSeen := make(map[string]bool)
	impSeen := make(map[string]bool)

	checkCanary := func(name string) {
		if name == "__stack_chk_fail" || name == "__stack_chk_guard" || name == "__stack_chk_fail_local" {
			mit.Canary = true
		}
	}

	processSymList := func(syms []elf.Symbol, isDynamic bool) {
		for _, s := range syms {
			if s.Name == "" {
				continue
			}
			checkCanary(s.Name)
			sType := elf.ST_TYPE(s.Info)
			sBind := elf.ST_BIND(s.Info)

			if s.Section == elf.SHN_UNDEF {
				if isDynamic && !impSeen[s.Name] {
					impSeen[s.Name] = true
					res.Imports = append(res.Imports, BinarySymbol{
						Name: s.Name,
						Type: elfSymTypeName(sType),
						Bind: elfSymBindName(sBind),
					})
				}
				continue
			}

			addrStr := fmt.Sprintf("0x%x", s.Value)
			isJNI := isJNISymbolName(s.Name)

			if (isDynamic || sBind == elf.STB_GLOBAL || sBind == elf.STB_WEAK) && !expSeen[s.Name] {
				expSeen[s.Name] = true
				res.Exports = append(res.Exports, BinarySymbol{
					Name:   s.Name,
					Addr:   addrStr,
					Offset: s.Value,
					Size:   s.Size,
					Type:   elfSymTypeName(sType),
					Bind:   elfSymBindName(sBind),
					IsJNI:  isJNI,
				})
			}

			if (sType == elf.STT_FUNC || isJNI) && !fnSeen[s.Name] && len(res.Functions) < maxExtractedFunctions {
				fnSeen[s.Name] = true
				res.Functions = append(res.Functions, BinaryFunction{
					Name:   s.Name,
					Addr:   addrStr,
					Offset: s.Value,
					Size:   s.Size,
					IsJNI:  isJNI,
				})
			}
		}
	}

	if dynSyms, err := ef.DynamicSymbols(); err == nil {
		processSymList(dynSyms, true)
	}
	if allSyms, err := ef.Symbols(); err == nil {
		mit.Stripped = false
		processSymList(allSyms, false)
	} else if errors.Is(err, elf.ErrNoSymbols) {
		mit.Stripped = true
	}

	if impSyms, err := ef.ImportedSymbols(); err == nil {
		for _, imp := range impSyms {
			if imp.Name == "" {
				continue
			}
			checkCanary(imp.Name)
			if !impSeen[imp.Name] {
				impSeen[imp.Name] = true
				res.Imports = append(res.Imports, BinarySymbol{
					Name:    imp.Name,
					Library: imp.Library,
					Type:    "FUNC",
				})
			} else if imp.Library != "" {
				for i := range res.Imports {
					if res.Imports[i].Name == imp.Name && res.Imports[i].Library == "" {
						res.Imports[i].Library = imp.Library
						break
					}
				}
			}
		}
	}

	res.Mitigations = mit

	// Sort symbols stably for deterministic output
	sort.Slice(res.Functions, func(i, j int) bool {
		if res.Functions[i].Offset != res.Functions[j].Offset {
			return res.Functions[i].Offset < res.Functions[j].Offset
		}
		return res.Functions[i].Name < res.Functions[j].Name
	})
	sort.Slice(res.Exports, func(i, j int) bool { return res.Exports[i].Name < res.Exports[j].Name })
	sort.Slice(res.Imports, func(i, j int) bool { return res.Imports[i].Name < res.Imports[j].Name })

	// Strings from .rodata / .data / .rodata.str*
	strSeen := make(map[string]bool)
	for _, sec := range ef.Sections {
		if sec == nil || sec.Size == 0 || sec.Type == elf.SHT_NOBITS {
			continue
		}
		if sec.Name != ".rodata" && sec.Name != ".data" && !strings.HasPrefix(sec.Name, ".rodata.") {
			continue
		}
		r := sec.Open()
		if r == nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(r, maxPureGoSectionBytes))
		if err != nil || len(data) == 0 {
			continue
		}
		for _, run := range extractASCIIPrintable(data, minPrintableStringLen) {
			if strSeen[run.value] {
				continue
			}
			strSeen[run.value] = true
			vaddr := sec.Addr + uint64(run.offset)
			res.Strings = append(res.Strings, BinaryString{
				Value:   run.value,
				Addr:    fmt.Sprintf("0x%x", vaddr),
				Offset:  vaddr,
				Section: sec.Name,
				Length:  len(run.value),
				Type:    "ascii",
			})
			if len(res.Strings) >= maxExtractedStrings {
				break
			}
		}
		if len(res.Strings) >= maxExtractedStrings {
			break
		}
	}

	return res, nil
}

func analyzeBinaryPureGoMachO(binaryPath string, fileSize int64) (*BinaryAnalysis, error) {
	mf, err := macho.Open(binaryPath)
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	bits := 64
	format := "macho64"
	if mf.Magic == macho.Magic32 {
		bits = 32
		format = "macho32"
	}
	arch := "unknown"
	switch mf.Cpu {
	case macho.CpuArm64:
		arch = "aarch64"
	case macho.CpuArm:
		arch = "arm"
	case macho.CpuAmd64:
		arch = "x86_64"
	case macho.Cpu386:
		arch = "x86"
	}

	res := &BinaryAnalysis{
		FilePath: binaryPath,
		FileName: filepath.Base(binaryPath),
		FileSize: fileSize,
		Format:   format,
		Arch:     arch,
		Bits:     bits,
		Endian:   "little",
		OS:       "darwin",
		Mitigations: SecurityMitigations{
			PIE:      mf.Flags&macho.FlagPIE != 0,
			NX:       mf.Flags&macho.FlagAllowStackExecution == 0,
			RELRO:    RELROUnknown,
			Stripped: mf.Symtab == nil || len(mf.Symtab.Syms) == 0,
		},
		Functions:  []BinaryFunction{},
		Exports:    []BinarySymbol{},
		Imports:    []BinarySymbol{},
		Strings:    []BinaryString{},
		XRefs:      []BinaryXRef{},
		Engine:     EnginePureGoMO,
		AnalyzedAt: nowRFC3339(),
	}

	if mf.Symtab != nil {
		for _, s := range mf.Symtab.Syms {
			if s.Name == "" {
				continue
			}
			if s.Name == "___stack_chk_fail" || s.Name == "__stack_chk_fail" {
				res.Mitigations.Canary = true
			}
			if s.Sect == 0 {
				res.Imports = append(res.Imports, BinarySymbol{Name: s.Name})
				continue
			}
			addrStr := fmt.Sprintf("0x%x", s.Value)
			res.Exports = append(res.Exports, BinarySymbol{
				Name:   s.Name,
				Addr:   addrStr,
				Offset: s.Value,
				IsJNI:  isJNISymbolName(strings.TrimPrefix(s.Name, "_")),
			})
			if len(res.Functions) < maxExtractedFunctions {
				res.Functions = append(res.Functions, BinaryFunction{
					Name:   s.Name,
					Addr:   addrStr,
					Offset: s.Value,
					IsJNI:  isJNISymbolName(strings.TrimPrefix(s.Name, "_")),
				})
			}
		}
	}

	if sec := mf.Section("__cstring"); sec != nil {
		if data, err := io.ReadAll(io.LimitReader(sec.Open(), maxPureGoSectionBytes)); err == nil {
			for _, run := range extractASCIIPrintable(data, minPrintableStringLen) {
				vaddr := sec.Addr + uint64(run.offset)
				res.Strings = append(res.Strings, BinaryString{
					Value:   run.value,
					Addr:    fmt.Sprintf("0x%x", vaddr),
					Offset:  vaddr,
					Section: sec.Name,
					Length:  len(run.value),
					Type:    "ascii",
				})
				if len(res.Strings) >= maxExtractedStrings {
					break
				}
			}
		}
	}

	return res, nil
}

func inspectFunctionPureGoELF(binaryPath, target string) (*FunctionDetail, error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("radare2 not available and pure-Go ELF open failed: %w", err)
	}
	defer ef.Close()

	cleanTarget := stripR2SymPrefix(target)
	targetAddr, isAddr := parseHexUint64(target)

	var matched *elf.Symbol
	search := func(list []elf.Symbol) {
		for i := range list {
			s := list[i]
			if s.Section == elf.SHN_UNDEF {
				continue
			}
			if (isAddr && s.Value == targetAddr) || s.Name == target || s.Name == cleanTarget {
				cp := s
				matched = &cp
				return
			}
		}
	}
	if syms, err := ef.DynamicSymbols(); err == nil {
		search(syms)
	}
	if matched == nil {
		if syms, err := ef.Symbols(); err == nil {
			search(syms)
		}
	}

	detail := &FunctionDetail{
		Name:      target,
		Engine:    EnginePureGoELF,
		XRefsTo:   []BinaryXRef{},
		XRefsFrom: []BinaryXRef{},
		Warnings:  []string{"radare2 (r2) not found; install radare2 for full disassembly, pseudo-C (pdg/pdc), and xrefs"},
	}

	if matched != nil {
		detail.Name = matched.Name
		detail.Addr = fmt.Sprintf("0x%x", matched.Value)
		detail.Size = matched.Size
		if int(matched.Section) > 0 && int(matched.Section) < len(ef.Sections) {
			sec := ef.Sections[matched.Section]
			if sec != nil && matched.Value >= sec.Addr {
				relOff := matched.Value - sec.Addr
				readLen := matched.Size
				if readLen == 0 || readLen > 128 {
					readLen = 64
				}
				if data, err := sec.Data(); err == nil && relOff < uint64(len(data)) {
					end := relOff + readLen
					if end > uint64(len(data)) {
						end = uint64(len(data))
					}
					rawBytes := data[relOff:end]
					detail.Disasm = fmt.Sprintf("; raw bytes @ 0x%x (%d bytes, install r2 to disassemble)\n%s",
						matched.Value, len(rawBytes), hex.Dump(rawBytes))
				}
			}
		}
		return detail, nil
	}

	if isAddr {
		detail.Addr = fmt.Sprintf("0x%x", targetAddr)
		return detail, nil
	}
	return nil, fmt.Errorf("symbol %q not found in ELF %s (radare2 unavailable)", target, filepath.Base(binaryPath))
}

// BuiltinR2Projects returns built-in radare2 static-analysis starter projects.
func BuiltinR2Projects() []REProject {
	return []REProject{
		{
			ID:          "builtin:r2-jni-audit",
			Name:        "radare2 JNI & Crypto Audit",
			Engine:      EngineRadare2,
			Description: "Read-only radare2 command batch inspecting binary info, JNI exports, crypto imports, and signature-related strings.",
			Code:        "ij; iEj; iij; izz~sign",
			Builtin:     true,
			Tags:        []string{"radare2", "static", "jni", "elf"},
		},
	}
}

// GenerateR2Harness builds a read-only radare2 inspection script tailored to opts.
func GenerateR2Harness(opts GenerateOptions) *GeneratedHarness {
	binPath := firstNonEmpty(opts.BinaryPath, opts.SOFile, "/path/to/libnative.so")
	target := firstNonEmpty(opts.TargetAddr, opts.TargetSymbol, "JNI_OnLoad")

	var cmds []string
	cmds = append(cmds, "ij", "iEj", "iij")
	if target != "" {
		cmds = append(cmds, fmt.Sprintf("s %s", target), "af", "pdf", "axtj", "axfj")
	}
	code := strings.Join(cmds, "; ")

	name := fmt.Sprintf("radare2 Inspect · %s", filepath.Base(binPath))
	desc := fmt.Sprintf("Read-only radare2 analysis commands targeting %s in %s.", target, filepath.Base(binPath))
	proj := REProject{
		Name:         name,
		Engine:       EngineRadare2,
		Description:  desc,
		BinaryPath:   binPath,
		APKPath:      opts.APKPath,
		TargetClass:  opts.TargetClass,
		TargetMethod: opts.TargetMethod,
		TargetSymbol: opts.TargetSymbol,
		TargetAddr:   opts.TargetAddr,
		Code:         code,
		Tags:         []string{"radare2", "generated", "static"},
	}

	return &GeneratedHarness{
		Name:         name,
		Engine:       EngineRadare2,
		Language:     "r2",
		FileName:     "inspect.r2",
		Description:  desc,
		Summary:      fmt.Sprintf("Generated radare2 read-only inspection script for %s (%s)", filepath.Base(binPath), target),
		Code:         code,
		Project:      proj,
		BinaryPath:   binPath,
		APKPath:      opts.APKPath,
		TargetClass:  opts.TargetClass,
		TargetMethod: opts.TargetMethod,
		TargetSymbol: opts.TargetSymbol,
		TargetAddr:   opts.TargetAddr,
		GeneratedAt:  nowRFC3339(),
	}
}

// --- Helpers ---------------------------------------------------------------

type asciiRun struct {
	offset int
	value  string
}

func extractASCIIPrintable(data []byte, minLen int) []asciiRun {
	if minLen <= 0 {
		minLen = minPrintableStringLen
	}
	var out []asciiRun
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minLen {
			out = append(out, asciiRun{offset: start, value: string(data[start:end])})
		}
		start = -1
	}
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return out
}

func elfMachineToArch(m elf.Machine) string {
	switch m {
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_386:
		return "x86"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_RISCV:
		return "riscv"
	default:
		return strings.ToLower(strings.TrimPrefix(m.String(), "EM_"))
	}
}

func elfTypeToString(t elf.Type) string {
	return strings.TrimPrefix(t.String(), "ET_")
}

func elfOSABIToString(o elf.OSABI) string {
	switch o {
	case elf.ELFOSABI_NONE, elf.ELFOSABI_LINUX:
		return "linux"
	default:
		return strings.ToLower(strings.TrimPrefix(o.String(), "ELFOSABI_"))
	}
}

func elfSymTypeName(t elf.SymType) string {
	return strings.TrimPrefix(t.String(), "STT_")
}

func elfSymBindName(b elf.SymBind) string {
	return strings.TrimPrefix(b.String(), "STB_")
}

func normalizeArchName(arch string, bits int, machine string) string {
	a := strings.ToLower(strings.TrimSpace(arch))
	m := strings.ToLower(strings.TrimSpace(machine))
	switch {
	case a == "arm" && bits == 64:
		return "aarch64"
	case a == "x86" && bits == 64:
		return "x86_64"
	case strings.Contains(m, "aarch64"):
		return "aarch64"
	case a != "":
		return a
	default:
		return "unknown"
	}
}

func normalizeRELRO(raw string) string {
	low := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(low, "full"):
		return RELROFull
	case strings.Contains(low, "partial"):
		return RELROPartial
	case low == "no" || low == "none" || low == "false":
		return RELRONone
	default:
		return RELROUnknown
	}
}

func stripR2SymPrefix(name string) string {
	for _, p := range []string{"sym.imp.", "sym.", "fcn.", "reloc.", "imp."} {
		if strings.HasPrefix(name, p) {
			return strings.TrimPrefix(name, p)
		}
	}
	return name
}

func isJNISymbolName(name string) bool {
	return name == "JNI_OnLoad" || name == "JNI_OnUnload" || strings.HasPrefix(name, "Java_")
}

func parseHexUint64(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return v, err == nil
	}
	return 0, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}
