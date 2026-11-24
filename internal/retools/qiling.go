package retools

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// BuiltinQilingProjects returns curated Qiling ARM64/ARM emulation starter templates.
func BuiltinQilingProjects() []REProject {
	elfTpl := GenerateQilingHarness(GenerateOptions{
		BinaryPath:   "/path/to/libnative.so",
		TargetSymbol: "Java_com_example_Signer_nativeSign",
		TargetAddr:   "0x1200",
		RootFS:       "/path/to/qiling/rootfs/arm64_linux",
		Arch:         "arm64",
		Args:         []string{"sample_payload"},
	})
	return []REProject{
		{
			ID:           "builtin:qiling-arm64-elf",
			Name:         "Qiling ARM64 ELF / .so Function Emulator",
			Engine:       EngineQiling,
			Description:  "Emulates an ARM64 Linux/Android ELF or shared library function in Qiling with argument buffer setup, instruction/syscall hooks, and [CAP_RE] JSON reporting.",
			BinaryPath:   elfTpl.BinaryPath,
			TargetSymbol: elfTpl.TargetSymbol,
			TargetAddr:   elfTpl.TargetAddr,
			RootFS:       elfTpl.Project.RootFS,
			Args:         elfTpl.Project.Args,
			Code:         elfTpl.Code,
			Builtin:      true,
			Tags:         []string{"qiling", "arm64", "elf", "so", "emulation"},
		},
		{
			ID:          "builtin:qiling-android-so-hook",
			Name:        "Qiling Android .so Crypto & Syscall Tracer",
			Engine:      EngineQiling,
			Description: "Traces openat/read/write syscalls and hooks libc/crypto symbols inside a Qiling ARM64 Android/Linux rootfs session.",
			BinaryPath:  "/path/to/libcrypto_target.so",
			RootFS:      "/path/to/qiling/rootfs/arm64_linux",
			Code:        qilingCryptoTracerTemplate,
			Builtin:     true,
			Tags:        []string{"qiling", "syscall", "crypto", "trace"},
		},
	}
}

// GenerateQilingHarness synthesizes a Qiling Python emulation script targeting
// an ELF executable or shared library function offset/symbol.
func GenerateQilingHarness(opts GenerateOptions) *GeneratedHarness {
	binPath := firstNonEmpty(opts.BinaryPath, opts.SOFile, "/path/to/libnative.so")
	arch := normalizeEmulationArch(opts.Arch, binPath)
	rootfs := strings.TrimSpace(opts.RootFS)
	if rootfs == "" {
		rootfs = defaultQilingRootFS(arch)
	}
	targetSymbol := firstNonEmpty(opts.TargetSymbol, opts.TargetMethod)
	targetAddr := normalizeHexAddr(opts.TargetAddr)

	arg0 := "test_payload"
	if len(opts.Args) > 0 && strings.TrimSpace(opts.Args[0]) != "" {
		arg0 = opts.Args[0]
	}

	code := renderQilingPythonSource(qilingTemplateParams{
		BinaryPath:   binPath,
		RootFS:       rootfs,
		Arch:         arch,
		TargetSymbol: targetSymbol,
		TargetAddr:   targetAddr,
		SampleArg:    arg0,
		Args:         opts.Args,
	})

	targetLabel := firstNonEmpty(targetSymbol, targetAddr, filepath.Base(binPath))
	name := fmt.Sprintf("Qiling %s · %s", strings.ToUpper(arch), targetLabel)
	desc := fmt.Sprintf("Qiling %s emulation script for %s (%s) with syscall/code hooks and [CAP_RE] JSON output.", arch, filepath.Base(binPath), targetLabel)

	proj := REProject{
		Name:         name,
		Engine:       EngineQiling,
		Description:  desc,
		BinaryPath:   binPath,
		APKPath:      opts.APKPath,
		TargetClass:  opts.TargetClass,
		TargetMethod: opts.TargetMethod,
		TargetSymbol: targetSymbol,
		TargetAddr:   targetAddr,
		RootFS:       rootfs,
		Args:         opts.Args,
		Code:         code,
		Tags:         []string{"qiling", arch, "emulation", "generated"},
	}

	notes := []string{
		fmt.Sprintf("Requires Qiling rootfs matching %s (set QILING_ROOTFS or edit ROOTFS).", arch),
		"Set CAP_RE_BINARY / CAP_RE_ROOTFS / CAP_RE_ADDR environment variables to override targets without editing the script.",
	}

	return &GeneratedHarness{
		Name:         name,
		Engine:       EngineQiling,
		Language:     "python",
		FileName:     "emulate_qiling.py",
		Description:  desc,
		Summary:      fmt.Sprintf("Generated Qiling %s script targeting %s in %s", arch, targetLabel, filepath.Base(binPath)),
		Code:         code,
		Project:      proj,
		BinaryPath:   binPath,
		APKPath:      opts.APKPath,
		TargetClass:  opts.TargetClass,
		TargetMethod: opts.TargetMethod,
		TargetSymbol: targetSymbol,
		TargetAddr:   targetAddr,
		Notes:        notes,
		GeneratedAt:  nowRFC3339(),
	}
}

type qilingTemplateParams struct {
	BinaryPath   string
	RootFS       string
	Arch         string
	TargetSymbol string
	TargetAddr   string
	SampleArg    string
	Args         []string
}

func renderQilingPythonSource(p qilingTemplateParams) string {
	regSetup := `    ql.arch.regs.x0 = in_addr
    ql.arch.regs.x1 = len(payload)
    ql.arch.regs.x2 = out_addr
    ql.arch.regs.x3 = 0x100
    ql.arch.regs.lr = stop_addr`
	retReg := "ql.arch.regs.x0"
	switch p.Arch {
	case "arm":
		regSetup = `    ql.arch.regs.r0 = in_addr
    ql.arch.regs.r1 = len(payload)
    ql.arch.regs.r2 = out_addr
    ql.arch.regs.r3 = 0x100
    ql.arch.regs.lr = stop_addr`
		retReg = "ql.arch.regs.r0"
	case "x86_64":
		regSetup = `    ql.arch.regs.rdi = in_addr
    ql.arch.regs.rsi = len(payload)
    ql.arch.regs.rdx = out_addr
    ql.arch.regs.rcx = 0x100`
		retReg = "ql.arch.regs.rax"
	case "x86":
		regSetup = `    ql.arch.regs.eax = in_addr`
		retReg = "ql.arch.regs.eax"
	}

	argsJSON, _ := json.Marshal(p.Args)
	if len(p.Args) == 0 {
		argsJSON = []byte("[]")
	}

	return fmt.Sprintf(`#!/usr/bin/env python3
"""cap Auto-Generated Qiling Emulation Harness (%s)."""

import json
import os
import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE

BINARY_PATH = os.environ.get("CAP_RE_BINARY") or %s
ROOTFS = os.environ.get("CAP_RE_ROOTFS") or %s
TARGET_SYMBOL = os.environ.get("CAP_RE_SYMBOL") or %s
TARGET_ADDR_STR = os.environ.get("CAP_RE_ADDR") or %s
SAMPLE_INPUT = sys.argv[1] if len(sys.argv) > 1 else %s
EXTRA_ARGS = %s


def emit(kind: str, **payload):
    data = {"kind": kind, **payload}
    print("[CAP_RE] " + json.dumps(data, ensure_ascii=False), flush=True)


def trace_syscall_enter(ql, *args):
    emit("hook", hook="syscall", pc=hex(ql.arch.regs.arch_pc), args=[hex(a) if isinstance(a, int) else str(a) for a in args[:4]])


def hook_first_instructions(ql, address, size):
    count = getattr(ql, "_cap_step_count", 0)
    if count < 12:
        ql._cap_step_count = count + 1
        print(f"[trace] pc={hex(address)} size={size}", flush=True)


def main():
    if not os.path.isfile(BINARY_PATH):
        raise FileNotFoundError(f"Target binary not found: {BINARY_PATH}")
    if not os.path.isdir(ROOTFS):
        raise FileNotFoundError(f"Qiling rootfs directory not found: {ROOTFS}")

    argv = [BINARY_PATH] + list(EXTRA_ARGS)
    ql = Qiling(argv, ROOTFS, verbose=QL_VERBOSE.OFF)

    # Lightweight syscall & code tracing hooks
    try:
        ql.os.set_syscall("openat", trace_syscall_enter)
    except Exception:
        pass
    ql.hook_code(hook_first_instructions)

    base = ql.loader.load_address
    target_addr = int(TARGET_ADDR_STR, 16) if TARGET_ADDR_STR else 0

    if target_addr > 0:
        begin = base + target_addr if target_addr < base else target_addr
        scratch_base = 0x50000000
        ql.mem.map(scratch_base, 0x4000, info="[cap_scratch]")
        in_addr = scratch_base + 0x100
        out_addr = scratch_base + 0x1000
        stop_addr = scratch_base + 0x3F00

        payload = SAMPLE_INPUT.encode("utf-8") + b"\x00"
        ql.mem.write(in_addr, payload)
        ql.mem.write(stop_addr, b"\x00" * 16)

%s

        emit("info", stage="start", binary=BINARY_PATH, symbol=TARGET_SYMBOL, begin=hex(begin), base=hex(base))
        ql.run(begin=begin, end=stop_addr)

        ret_val = %s
        out_preview = ql.mem.read(out_addr, 64)
        emit(
            "return_value",
            symbol=TARGET_SYMBOL or hex(target_addr),
            retval=hex(ret_val),
            output_hex=out_preview.hex(),
            output_ascii=out_preview.split(b"\x00", 1)[0].decode("utf-8", errors="replace"),
        )
    else:
        emit("info", stage="start", binary=BINARY_PATH, mode="full_binary")
        ql.run()
        emit("return_value", symbol="entry", retval=hex(%s))


if __name__ == "__main__":
    main()
`,
		p.Arch,
		pyQuote(p.BinaryPath),
		pyQuote(p.RootFS),
		pyQuote(p.TargetSymbol),
		pyQuote(p.TargetAddr),
		pyQuote(p.SampleArg),
		string(argsJSON),
		regSetup,
		retReg,
		retReg,
	)
}

func defaultQilingRootFS(arch string) string {
	switch arch {
	case "arm":
		return "/path/to/qiling/rootfs/arm_linux"
	case "x86_64":
		return "/path/to/qiling/rootfs/x8664_linux"
	case "x86":
		return "/path/to/qiling/rootfs/x86_linux"
	default:
		return "/path/to/qiling/rootfs/arm64_linux"
	}
}

func normalizeHexAddr(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return "0x" + strings.ToLower(s[2:])
	}
	return s
}

func pyQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

const qilingCryptoTracerTemplate = `#!/usr/bin/env python3
"""cap Qiling Android .so Crypto & Syscall Tracer."""

import json
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE

BINARY_PATH = os.environ.get("CAP_RE_BINARY") or "/path/to/libcrypto_target.so"
ROOTFS = os.environ.get("CAP_RE_ROOTFS") or "/path/to/qiling/rootfs/arm64_linux"


def emit(kind: str, **payload):
    print("[CAP_RE] " + json.dumps({"kind": kind, **payload}, ensure_ascii=False), flush=True)


def main():
    ql = Qiling([BINARY_PATH], ROOTFS, verbose=QL_VERBOSE.OFF)

    def on_write(ql, fd, buf, count):
        try:
            data = bytes(ql.mem.read(buf, min(count, 128)))
            emit("hook", hook="write", fd=fd, count=count, preview=data.decode("utf-8", errors="replace"))
        except Exception:
            pass

    try:
        ql.os.set_syscall("write", on_write)
    except Exception:
        pass

    emit("info", stage="running", binary=BINARY_PATH)
    ql.run()
    emit("return_value", status="completed")


if __name__ == "__main__":
    main()
`
