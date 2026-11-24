package retools

import (
	"fmt"
	"path/filepath"
)

// BuiltinAngrProjects returns curated angr symbolic execution starter templates.
func BuiltinAngrProjects() []REProject {
	std := GenerateAngrHarness(GenerateOptions{
		BinaryPath: "/path/to/target_binary",
		FindAddr:   "0x401234",
		AvoidAddr:  "0x401280",
		InputLen:   32,
	})
	funcSolve := GenerateAngrHarness(GenerateOptions{
		BinaryPath:   "/path/to/libnative.so",
		TargetSymbol: "verify_token",
		TargetAddr:   "0x1200",
		FindAddr:     "0x1340",
		AvoidAddr:    "0x1380",
		InputLen:     24,
	})
	return []REProject{
		{
			ID:          "builtin:angr-symbolic-solve",
			Name:        "angr Symbolic Input Solver (entry_state)",
			Engine:      EngineAngr,
			Description: "Explores paths from entry_state with a symbolic claripy.BVS stdin/argv buffer using find/avoid addresses and prints concrete solutions as [CAP_RE] JSON.",
			BinaryPath:  std.BinaryPath,
			FindAddr:    std.Project.FindAddr,
			AvoidAddr:   std.Project.AvoidAddr,
			Code:        std.Code,
			Builtin:     true,
			Tags:        []string{"angr", "symbolic", "claripy", "solver"},
		},
		{
			ID:           "builtin:angr-func-call-state",
			Name:         "angr Function-Level Solver (call_state)",
			Engine:       EngineAngr,
			Description:  "Invokes a single native .so function via proj.factory.call_state(TARGET_ADDR, ...) with a symbolic buffer argument to solve branch conditions.",
			BinaryPath:   funcSolve.BinaryPath,
			TargetSymbol: funcSolve.TargetSymbol,
			TargetAddr:   funcSolve.TargetAddr,
			FindAddr:     funcSolve.Project.FindAddr,
			AvoidAddr:    funcSolve.Project.AvoidAddr,
			Code:         funcSolve.Code,
			Builtin:      true,
			Tags:         []string{"angr", "call_state", "so", "jni", "symbolic"},
		},
	}
}

// GenerateAngrHarness synthesizes an angr symbolic execution script using
// either entry_state or function-level call_state (when TargetAddr is provided).
func GenerateAngrHarness(opts GenerateOptions) *GeneratedHarness {
	binPath := firstNonEmpty(opts.BinaryPath, opts.SOFile, "/path/to/target_binary")
	targetAddr := normalizeHexAddr(opts.TargetAddr)
	findAddr := normalizeHexAddr(opts.FindAddr)
	avoidAddr := normalizeHexAddr(opts.AvoidAddr)
	targetSymbol := firstNonEmpty(opts.TargetSymbol, opts.TargetMethod)

	inputLen := opts.InputLen
	if inputLen <= 0 {
		inputLen = 32
	}

	code := renderAngrPythonSource(angrTemplateParams{
		BinaryPath:   binPath,
		TargetSymbol: targetSymbol,
		TargetAddr:   targetAddr,
		FindAddr:     findAddr,
		AvoidAddr:    avoidAddr,
		InputLen:     inputLen,
	})

	label := firstNonEmpty(targetSymbol, targetAddr, filepath.Base(binPath))
	name := fmt.Sprintf("angr Symbolic · %s", label)
	desc := fmt.Sprintf("angr symbolic execution script for %s (input=%d bytes, find=%s, avoid=%s).",
		filepath.Base(binPath), inputLen, firstNonEmpty(findAddr, "auto"), firstNonEmpty(avoidAddr, "none"))

	proj := REProject{
		Name:         name,
		Engine:       EngineAngr,
		Description:  desc,
		BinaryPath:   binPath,
		APKPath:      opts.APKPath,
		TargetClass:  opts.TargetClass,
		TargetMethod: opts.TargetMethod,
		TargetSymbol: targetSymbol,
		TargetAddr:   targetAddr,
		FindAddr:     findAddr,
		AvoidAddr:    avoidAddr,
		Args:         opts.Args,
		Code:         code,
		Tags:         []string{"angr", "symbolic", "generated"},
	}

	notes := []string{
		"Set FIND_ADDR (and optionally AVOID_ADDR) to target branch addresses discovered in radare2.",
		"Printable ASCII constraints are applied by default; relax them for binary/key solving.",
	}
	if targetAddr != "" {
		notes = append(notes, fmt.Sprintf("Using proj.factory.call_state starting at %s (rebased automatically for PIE/.so).", targetAddr))
	}

	return &GeneratedHarness{
		Name:         name,
		Engine:       EngineAngr,
		Language:     "python",
		FileName:     "solve_angr.py",
		Description:  desc,
		Summary:      fmt.Sprintf("Generated angr symbolic execution script for %s (%s)", filepath.Base(binPath), label),
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

type angrTemplateParams struct {
	BinaryPath   string
	TargetSymbol string
	TargetAddr   string
	FindAddr     string
	AvoidAddr    string
	InputLen     int
}

func renderAngrPythonSource(p angrTemplateParams) string {
	return fmt.Sprintf(`#!/usr/bin/env python3
"""cap Auto-Generated angr Symbolic Execution Harness."""

import json
import os
import sys
import angr
import claripy

BINARY_PATH = os.environ.get("CAP_RE_BINARY") or %s
TARGET_SYMBOL = os.environ.get("CAP_RE_SYMBOL") or %s
TARGET_ADDR_STR = os.environ.get("CAP_RE_TARGET_ADDR") or %s
FIND_ADDR_STR = os.environ.get("CAP_RE_FIND_ADDR") or %s
AVOID_ADDR_STR = os.environ.get("CAP_RE_AVOID_ADDR") or %s
INPUT_LEN = int(os.environ.get("CAP_RE_INPUT_LEN") or %d)


def emit(kind: str, **payload):
    print("[CAP_RE] " + json.dumps({"kind": kind, **payload}, ensure_ascii=False), flush=True)


def parse_addr(proj: angr.Project, raw: str) -> int:
    raw = (raw or "").strip()
    if not raw:
        return 0
    val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    base = proj.loader.main_object.mapped_base
    if proj.loader.main_object.pic and val < base:
        return base + val
    return val


def main():
    if not os.path.isfile(BINARY_PATH):
        raise FileNotFoundError(f"Binary not found: {BINARY_PATH}")

    proj = angr.Project(BINARY_PATH, auto_load_libs=False)
    sym_chars = [claripy.BVS(f"b_{i}", 8) for i in range(INPUT_LEN)]
    sym_input = claripy.Concat(*sym_chars)

    target_addr = parse_addr(proj, TARGET_ADDR_STR)
    if target_addr == 0 and TARGET_SYMBOL:
        sym = proj.loader.find_symbol(TARGET_SYMBOL)
        if sym is not None:
            target_addr = sym.rebased_addr

    find_addr = parse_addr(proj, FIND_ADDR_STR)
    avoid_addr = parse_addr(proj, AVOID_ADDR_STR)

    if target_addr > 0:
        buf_addr = 0x70000000
        state = proj.factory.call_state(
            target_addr,
            buf_addr,
            INPUT_LEN,
            add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
        )
        state.memory.store(buf_addr, sym_input)
        state.memory.store(buf_addr + INPUT_LEN, claripy.BVV(0, 8))
    else:
        state = proj.factory.entry_state(
            stdin=angr.SimFileStream(name="stdin", content=sym_input, has_end=False),
            add_options={angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
        )

    # Constrain symbolic input bytes to printable ASCII (0x20..0x7e)
    for ch in sym_chars:
        state.solver.add(ch >= 0x20, ch <= 0x7E)

    simgr = proj.factory.simulation_manager(state)
    emit(
        "info",
        stage="exploring",
        binary=BINARY_PATH,
        arch=proj.arch.name,
        target=hex(target_addr) if target_addr else "entry",
        find=hex(find_addr) if find_addr else "",
        avoid=hex(avoid_addr) if avoid_addr else "",
    )

    explore_kwargs = {}
    if find_addr > 0:
        explore_kwargs["find"] = find_addr
    else:
        explore_kwargs["find"] = lambda s: b"ok" in s.posix.dumps(1).lower() or b"success" in s.posix.dumps(1).lower()
    if avoid_addr > 0:
        explore_kwargs["avoid"] = avoid_addr

    simgr.explore(**explore_kwargs)

    if not simgr.found:
        emit("error", message="No satisfying path found", deadended=len(simgr.deadended), active=len(simgr.active))
        sys.exit(1)

    found = simgr.found[0]
    concrete = found.solver.eval(sym_input, cast_to=bytes)
    emit(
        "solution",
        target=TARGET_SYMBOL or (hex(target_addr) if target_addr else "entry"),
        found_addr=hex(found.addr),
        solution_utf8=concrete.decode("utf-8", errors="replace"),
        solution_hex=concrete.hex(),
        stdout=found.posix.dumps(1).decode("utf-8", errors="replace"),
    )


if __name__ == "__main__":
    main()
`,
		pyQuote(p.BinaryPath),
		pyQuote(p.TargetSymbol),
		pyQuote(p.TargetAddr),
		pyQuote(p.FindAddr),
		pyQuote(p.AvoidAddr),
		p.InputLen,
	)
}
