package repro

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// normalizeHexAddr parses a hexadecimal address (with or without 0x/0X prefix)
// and returns the numeric uint64 value alongside its canonical lowercase 0x...
// representation.
func normalizeHexAddr(raw string) (uint64, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, "", errors.New("address is empty")
	}
	if strings.HasPrefix(s, "-") {
		return 0, "", fmt.Errorf("negative address %q is invalid", raw)
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, "", fmt.Errorf("malformed hex address %q", raw)
	}
	val, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid hex address %q: %w", raw, err)
	}
	return val, fmt.Sprintf("0x%x", val), nil
}

// validateAndNormalizeSymbolBundle returns a validated, address-normalized copy
// of bundle.
func validateAndNormalizeSymbolBundle(in *SymbolBundle) (*SymbolBundle, error) {
	if in == nil {
		return nil, errors.New("symbol bundle is nil")
	}
	binaryName := strings.TrimSpace(in.BinaryName)
	if binaryName == "" {
		return nil, errors.New("symbol bundle binary_name is required")
	}

	out := &SymbolBundle{
		Version:     firstNonEmptyStr(in.Version, SymbolBundleVersion),
		BinaryName:  binaryName,
		Arch:        strings.TrimSpace(in.Arch),
		Functions:   make([]SymbolItem, 0, len(in.Functions)),
		Comments:    make([]CommentItem, 0, len(in.Comments)),
		JNIBindings: make([]JavaNativeBinding, 0, len(in.JNIBindings)),
		CreatedAt:   firstNonEmptyStr(in.CreatedAt, nowRFC3339()),
	}

	if strings.TrimSpace(in.ImageBase) != "" {
		_, normBase, err := normalizeHexAddr(in.ImageBase)
		if err != nil {
			return nil, fmt.Errorf("invalid image_base: %w", err)
		}
		out.ImageBase = normBase
	} else {
		out.ImageBase = "0x0"
	}

	for i, fn := range in.Functions {
		name := strings.TrimSpace(fn.Name)
		if name == "" {
			return nil, fmt.Errorf("functions[%d]: name is required", i)
		}
		_, normAddr, err := normalizeHexAddr(fn.Address)
		if err != nil {
			return nil, fmt.Errorf("functions[%d] (%s): %w", i, name, err)
		}
		out.Functions = append(out.Functions, SymbolItem{
			Name:      name,
			Address:   normAddr,
			Size:      fn.Size,
			Signature: strings.TrimSpace(fn.Signature),
			Type:      firstNonEmptyStr(fn.Type, "function"),
			Comment:   fn.Comment,
		})
	}

	for i, cmt := range in.Comments {
		_, normAddr, err := normalizeHexAddr(cmt.Address)
		if err != nil {
			return nil, fmt.Errorf("comments[%d]: %w", i, err)
		}
		text := strings.TrimSpace(cmt.Text)
		if text == "" {
			return nil, fmt.Errorf("comments[%d] (%s): text is required", i, normAddr)
		}
		out.Comments = append(out.Comments, CommentItem{
			Address:    normAddr,
			Text:       text,
			Repeatable: cmt.Repeatable,
		})
	}

	for i, jb := range in.JNIBindings {
		copyJB := jb
		if strings.TrimSpace(copyJB.NativeAddr) != "" {
			val, normAddr, err := normalizeHexAddr(copyJB.NativeAddr)
			if err != nil {
				return nil, fmt.Errorf("jni_bindings[%d]: %w", i, err)
			}
			copyJB.NativeAddr = normAddr
			if copyJB.NativeOffset == 0 {
				copyJB.NativeOffset = val
			}
		} else if copyJB.NativeOffset > 0 {
			copyJB.NativeAddr = fmt.Sprintf("0x%x", copyJB.NativeOffset)
		}
		out.JNIBindings = append(out.JNIBindings, copyJB)
	}

	return out, nil
}

// ImportSymbolBundleJSON parses, strictly validates, and normalizes a
// SymbolBundle JSON document.
func ImportSymbolBundleJSON(raw string) (*SymbolBundle, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("symbol bundle JSON is empty")
	}
	var bundle SymbolBundle
	if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal symbol bundle: %w", err)
	}
	return validateAndNormalizeSymbolBundle(&bundle)
}

// ExportSymbolBundleJSON validates, normalizes, and serializes a SymbolBundle
// into pretty-printed JSON.
func ExportSymbolBundleJSON(bundle *SymbolBundle) (string, error) {
	norm, err := validateAndNormalizeSymbolBundle(bundle)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(norm, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal symbol bundle: %w", err)
	}
	return string(data) + "\n", nil
}

// ExportIDAPython synthesizes a Python 3 IDAPython script that applies function
// names, disassembly comments, and Java<->JNI bindings using idaapi and idc.
func ExportIDAPython(bundle *SymbolBundle) string {
	norm, err := validateAndNormalizeSymbolBundle(bundle)
	if err != nil {
		norm = &SymbolBundle{
			Version:    SymbolBundleVersion,
			BinaryName: "unknown",
			ImageBase:  "0x0",
		}
	}

	baseVal, _, _ := normalizeHexAddr(norm.ImageBase)

	var b strings.Builder
	b.WriteString("#!/usr/bin/env python3\n")
	b.WriteString("# -*- coding: utf-8 -*-\n")
	b.WriteString("# ─── cap Symbol & Comment Bridge for IDA Pro ─────────────────────────\n")
	fmt.Fprintf(&b, "# Binary:     %s\n", sanitizeComment(norm.BinaryName))
	if norm.Arch != "" {
		fmt.Fprintf(&b, "# Arch:       %s\n", sanitizeComment(norm.Arch))
	}
	fmt.Fprintf(&b, "# Image Base: %s\n", norm.ImageBase)
	b.WriteString("\n")
	b.WriteString("import idaapi\n")
	b.WriteString("import idc\n\n")
	fmt.Fprintf(&b, "BINARY_NAME = %s\n", pyQuote(norm.BinaryName))
	fmt.Fprintf(&b, "BUNDLE_IMAGE_BASE = 0x%x\n", baseVal)
	b.WriteString("AUTO_REBASE = False\n\n")

	b.WriteString("FUNCTIONS = [\n")
	for _, fn := range norm.Functions {
		addrVal, _, _ := normalizeHexAddr(fn.Address)
		fmt.Fprintf(&b, "    (0x%x, %s, %s, %s),\n", addrVal, pyQuote(fn.Name), pyQuote(fn.Signature), pyQuote(fn.Comment))
	}
	b.WriteString("]\n\n")

	b.WriteString("COMMENTS = [\n")
	for _, cmt := range norm.Comments {
		addrVal, _, _ := normalizeHexAddr(cmt.Address)
		rep := 0
		if cmt.Repeatable {
			rep = 1
		}
		fmt.Fprintf(&b, "    (0x%x, %s, %d),\n", addrVal, pyQuote(cmt.Text), rep)
	}
	b.WriteString("]\n\n")

	b.WriteString("JNI_BINDINGS = [\n")
	for _, jb := range norm.JNIBindings {
		addrVal, _, aerr := normalizeHexAddr(jb.NativeAddr)
		if aerr != nil {
			continue
		}
		symName := firstNonEmptyStr(jb.NativeSymbol, jb.MangledName)
		label := fmt.Sprintf("JNI %s.%s%s [%s]", jb.JavaClass, jb.JavaMethod, jb.JavaSignature, jb.BindingKind)
		fmt.Fprintf(&b, "    (0x%x, %s, %s),\n", addrVal, pyQuote(symName), pyQuote(label))
	}
	b.WriteString("]\n\n")

	b.WriteString(`def resolve_ea(raw_ea):
    if AUTO_REBASE and BUNDLE_IMAGE_BASE:
        current_base = idaapi.get_imagebase()
        return current_base + (raw_ea - BUNDLE_IMAGE_BASE)
    return raw_ea


def sanitize_ida_name(name):
    out = []
    for ch in name:
        if ch.isalnum() or ch in ("_", "$", "?"):
            out.append(ch)
        else:
            out.append("_")
    cleaned = "".join(out)
    if cleaned and cleaned[0].isdigit():
        cleaned = "sub_" + cleaned
    return cleaned


def apply_bundle():
    flags = idc.SN_NOWARN | idc.SN_NOCHECK
    applied_names = 0
    applied_comments = 0
    applied_jni = 0

    for raw_ea, name, sig, comment in FUNCTIONS:
        ea = resolve_ea(raw_ea)
        safe_name = sanitize_ida_name(name)
        if safe_name and idc.set_name(ea, safe_name, flags):
            applied_names += 1
        note_parts = []
        if sig:
            note_parts.append("Signature: " + sig)
        if comment:
            note_parts.append(comment)
        if note_parts:
            if idc.set_cmt(ea, " | ".join(note_parts), 1):
                applied_comments += 1

    for raw_ea, text, repeatable in COMMENTS:
        ea = resolve_ea(raw_ea)
        if idc.set_cmt(ea, text, repeatable):
            applied_comments += 1

    for raw_ea, sym_name, jni_desc in JNI_BINDINGS:
        ea = resolve_ea(raw_ea)
        safe_name = sanitize_ida_name(sym_name)
        if safe_name:
            idc.set_name(ea, safe_name, flags)
        if idc.set_cmt(ea, jni_desc, 1):
            applied_jni += 1

    print("[cap] IDA symbol bridge applied to %s: names=%d comments=%d jni=%d" % (
        BINARY_NAME, applied_names, applied_comments, applied_jni
    ))


if __name__ == "__main__":
    apply_bundle()
`)

	return b.String()
}

// ExportGhidraPython synthesizes a valid Ghidra Python script using
// currentProgram, createLabel, and setEOLComment to import function symbols,
// disassembly comments, and Java<->JNI bindings.
func ExportGhidraPython(bundle *SymbolBundle) string {
	norm, err := validateAndNormalizeSymbolBundle(bundle)
	if err != nil {
		norm = &SymbolBundle{
			Version:    SymbolBundleVersion,
			BinaryName: "unknown",
			ImageBase:  "0x0",
		}
	}

	baseVal, _, _ := normalizeHexAddr(norm.ImageBase)

	var b strings.Builder
	b.WriteString("# -*- coding: utf-8 -*-\n")
	b.WriteString("# ─── cap Symbol & Comment Bridge for Ghidra ──────────────────────────\n")
	b.WriteString("# @category cap.RE\n")
	b.WriteString("# @menupath Tools.cap.Import Symbols\n")
	fmt.Fprintf(&b, "# Binary:     %s\n", sanitizeComment(norm.BinaryName))
	if norm.Arch != "" {
		fmt.Fprintf(&b, "# Arch:       %s\n", sanitizeComment(norm.Arch))
	}
	fmt.Fprintf(&b, "# Image Base: %s\n\n", norm.ImageBase)

	fmt.Fprintf(&b, "BINARY_NAME = %s\n", pyQuote(norm.BinaryName))
	fmt.Fprintf(&b, "BUNDLE_IMAGE_BASE = 0x%x\n", baseVal)
	b.WriteString("AUTO_REBASE = False\n\n")

	b.WriteString("FUNCTIONS = [\n")
	for _, fn := range norm.Functions {
		addrVal, _, _ := normalizeHexAddr(fn.Address)
		fmt.Fprintf(&b, "    (0x%x, %s, %s, %s),\n", addrVal, pyQuote(fn.Name), pyQuote(fn.Signature), pyQuote(fn.Comment))
	}
	b.WriteString("]\n\n")

	b.WriteString("COMMENTS = [\n")
	for _, cmt := range norm.Comments {
		addrVal, _, _ := normalizeHexAddr(cmt.Address)
		fmt.Fprintf(&b, "    (0x%x, %s),\n", addrVal, pyQuote(cmt.Text))
	}
	b.WriteString("]\n\n")

	b.WriteString("JNI_BINDINGS = [\n")
	for _, jb := range norm.JNIBindings {
		addrVal, _, aerr := normalizeHexAddr(jb.NativeAddr)
		if aerr != nil {
			continue
		}
		symName := firstNonEmptyStr(jb.NativeSymbol, jb.MangledName)
		label := fmt.Sprintf("JNI %s.%s%s [%s]", jb.JavaClass, jb.JavaMethod, jb.JavaSignature, jb.BindingKind)
		fmt.Fprintf(&b, "    (0x%x, %s, %s),\n", addrVal, pyQuote(symName), pyQuote(label))
	}
	b.WriteString("]\n\n")

	b.WriteString(`def resolve_addr(raw_addr):
    base = currentProgram.getImageBase().getOffset()
    if AUTO_REBASE and BUNDLE_IMAGE_BASE:
        return toAddr(base + (raw_addr - BUNDLE_IMAGE_BASE))
    return toAddr(raw_addr)


def sanitize_label(name):
    out = []
    for ch in name:
        if ch.isalnum() or ch in ("_", "$"):
            out.append(ch)
        else:
            out.append("_")
    cleaned = "".join(out)
    if cleaned and cleaned[0].isdigit():
        cleaned = "fn_" + cleaned
    return cleaned


def apply_bundle():
    if currentProgram is None:
        raise RuntimeError("No active currentProgram in Ghidra")

    applied_labels = 0
    applied_comments = 0
    applied_jni = 0

    for raw_addr, name, sig, comment in FUNCTIONS:
        addr = resolve_addr(raw_addr)
        safe_name = sanitize_label(name)
        if safe_name:
            createLabel(addr, safe_name, True)
            applied_labels += 1
        note_parts = []
        if sig:
            note_parts.append("Signature: " + sig)
        if comment:
            note_parts.append(comment)
        if note_parts:
            setEOLComment(addr, " | ".join(note_parts))
            applied_comments += 1

    for raw_addr, text in COMMENTS:
        addr = resolve_addr(raw_addr)
        setEOLComment(addr, text)
        applied_comments += 1

    for raw_addr, sym_name, jni_desc in JNI_BINDINGS:
        addr = resolve_addr(raw_addr)
        safe_name = sanitize_label(sym_name)
        if safe_name:
            createLabel(addr, safe_name, True)
        setEOLComment(addr, jni_desc)
        applied_jni += 1

    print("[cap] Ghidra symbol bridge applied to %s: labels=%d comments=%d jni=%d" % (
        BINARY_NAME, applied_labels, applied_comments, applied_jni
    ))


if __name__ == "__main__":
    apply_bundle()
`)

	return b.String()
}

// pyQuote returns a safe, single-line Python string literal with all control
// characters, quotes, backslashes, and non-ASCII runes escaped.
func pyQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else if r > 0x7f {
				if r <= 0xffff {
					fmt.Fprintf(&b, `\u%04x`, r)
				} else {
					fmt.Fprintf(&b, `\U%08x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
