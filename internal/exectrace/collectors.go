package exectrace

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SupportedCollectors returns the canonical collector kinds supported by GenerateCollector.
func SupportedCollectors() []string {
	return []string{"stalker", "java_call", "unidbg", "qiling"}
}

// DefaultCollectorConfig returns balanced defaults for trace collector generation.
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		TargetModule: "libnative-lib.so",
		TargetSymbol: "Java_com_example_app_NativeSigner_sign",
		Arch:         "arm64",
		ClassFilter:  "com.example.*",
		MethodFilter: "*",
		IncludeRegs:  true,
		IncludeMem:   true,
		IncludeCalls: true,
		MaxEvents:    50000,
	}
}

// GenerateCollector produces a ready-to-run trace collector script for Frida
// Stalker ("stalker"), Frida Java/JNI Call Tree ("java_call"), Unidbg ("unidbg"),
// or Qiling ("qiling"), emitting output directly parseable by ParseTrace.
func GenerateCollector(kind string, cfg CollectorConfig) *GeneratedCollector {
	normalized := normalizeCollectorKind(kind)
	cfg = fillCollectorDefaults(cfg)

	switch normalized {
	case "java_call":
		return generateJavaCallCollector(cfg)
	case "unidbg":
		return generateUnidbgCollector(cfg)
	case "qiling":
		return generateQilingCollector(cfg)
	default:
		return generateStalkerCollector(cfg)
	}
}

func normalizeCollectorKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "stalker", "frida", "frida_stalker", "native":
		return "stalker"
	case "java_call", "java", "jni", "call_tree":
		return "java_call"
	case "unidbg":
		return "unidbg"
	case "qiling":
		return "qiling"
	default:
		return "stalker"
	}
}

func fillCollectorDefaults(cfg CollectorConfig) CollectorConfig {
	if strings.TrimSpace(cfg.TargetModule) == "" {
		cfg.TargetModule = "libnative-lib.so"
	}
	if strings.TrimSpace(cfg.Arch) == "" {
		cfg.Arch = "arm64"
	} else {
		cfg.Arch = strings.ToLower(strings.TrimSpace(cfg.Arch))
	}
	if strings.TrimSpace(cfg.ClassFilter) == "" {
		if cfg.TargetPackage != "" {
			cfg.ClassFilter = cfg.TargetPackage + ".*"
		} else {
			cfg.ClassFilter = "com.example.*"
		}
	}
	if strings.TrimSpace(cfg.MethodFilter) == "" {
		cfg.MethodFilter = "*"
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 50000
	}
	return cfg
}

// jsonQuote encodes s as a double-quoted string literal valid in JavaScript,
// Java, and Python (using RFC 8259 / \uXXXX escapes, never Go-only \U/\x/\a).
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	out := string(b)
	// Escape JS line separators U+2028 / U+2029 so embedded JS literals never split lines.
	out = strings.ReplaceAll(out, "\u2028", `\u2028`)
	out = strings.ReplaceAll(out, "\u2029", `\u2029`)
	return out
}

// sanitizeComment strips newlines and block-comment terminators from strings
// interpolated inside single-line or block comments.
func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\u2028", " ")
	s = strings.ReplaceAll(s, "\u2029", " ")
	s = strings.ReplaceAll(s, "*/", "* /")
	return strings.TrimSpace(s)
}

func generateStalkerCollector(cfg CollectorConfig) *GeneratedCollector {
	targetExpr := ""
	if strings.TrimSpace(cfg.TargetOffset) != "" {
		off := strings.TrimSpace(cfg.TargetOffset)
		if !strings.HasPrefix(off, "0x") && !strings.HasPrefix(off, "0X") {
			off = "0x" + off
		}
		targetExpr = fmt.Sprintf("mod.base.add(ptr(%s))", jsonQuote(off))
	} else if strings.TrimSpace(cfg.TargetSymbol) != "" {
		targetExpr = fmt.Sprintf("Module.findExportByName(TARGET_MODULE, %s)", jsonQuote(cfg.TargetSymbol))
	} else {
		targetExpr = "mod.base"
	}

	regSnippet := `      const regs = {};`
	if cfg.IncludeRegs {
		switch cfg.Arch {
		case "arm":
			regSnippet = `      const regs = {
        r0: ctx.r0.toString(), r1: ctx.r1.toString(), r2: ctx.r2.toString(), r3: ctx.r3.toString(),
        r4: ctx.r4.toString(), r5: ctx.r5.toString(), r6: ctx.r6.toString(), r7: ctx.r7.toString(),
        sp: ctx.sp.toString(), lr: ctx.lr.toString(), pc: ctx.pc.toString()
      };`
		case "x86_64":
			regSnippet = `      const regs = {
        rax: ctx.rax.toString(), rbx: ctx.rbx.toString(), rcx: ctx.rcx.toString(), rdx: ctx.rdx.toString(),
        rsi: ctx.rsi.toString(), rdi: ctx.rdi.toString(), rsp: ctx.rsp.toString(), rbp: ctx.rbp.toString(),
        rip: ctx.rip.toString()
      };`
		default: // arm64
			regSnippet = `      const regs = {
        x0: ctx.x0.toString(), x1: ctx.x1.toString(), x2: ctx.x2.toString(), x3: ctx.x3.toString(),
        x4: ctx.x4.toString(), x5: ctx.x5.toString(), x6: ctx.x6.toString(), x7: ctx.x7.toString(),
        x8: ctx.x8.toString(), sp: ctx.sp.toString(), lr: ctx.lr.toString(), pc: ctx.pc.toString()
      };`
		}
	}

	pkgComment := sanitizeComment(nonEmpty(cfg.TargetPackage, "com.example.app"))
	symName := nonEmpty(cfg.TargetSymbol, "target_entry")

	code := fmt.Sprintf(`// cap ExecTrace — Frida Stalker Module-Bounded Instruction & Call Collector
// Paste directly into cap Frida Studio or run via: frida -U -f %s -l cap_stalker_trace.js
'use strict';

const TARGET_MODULE = %s;
const MAX_EVENTS = %d;
const INCLUDE_REGS = %t;
const INCLUDE_CALLS = %t;

let seq = 0;
let activeTid = -1;

function emit(ev) {
  if (seq >= MAX_EVENTS) return;
  ev.seq = ++seq;
  ev.ts = Date.now();
  console.log('[CAP_TRACE] ' + JSON.stringify(ev));
}

function attachStalker() {
  const mod = Process.findModuleByName(TARGET_MODULE);
  if (!mod) {
    console.log('[cap_stalker] waiting for module: ' + TARGET_MODULE);
    return false;
  }
  const modStart = mod.base;
  const modEnd = mod.base.add(mod.size);
  const targetPtr = %s;
  if (!targetPtr || targetPtr.isNull()) {
    console.log('[cap_stalker] target symbol/offset not found in ' + TARGET_MODULE);
    return false;
  }

  console.log('[cap_stalker] attached to ' + TARGET_MODULE + ' @ ' + targetPtr + ' (base=' + modStart + ')');

  Interceptor.attach(targetPtr, {
    onEnter(args) {
      this.stalking = false;
      if (activeTid !== -1) return;
      this.stalking = true;
      activeTid = this.threadId;
      const tid = this.threadId;

      if (INCLUDE_CALLS) {
        emit({
          kind: 'call',
          source: 'stalker',
          arch: %s,
          thread_id: tid,
          module: TARGET_MODULE,
          module_base: modStart.toString(),
          address: targetPtr.toString(),
          offset: targetPtr.sub(modStart).toString(),
          symbol: %s,
          args: [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()]
        });
      }

      Stalker.follow(tid, {
        events: { call: false, ret: false, exec: false },
        transform(iterator) {
          let insn = iterator.next();
          while (insn !== null) {
            const addr = insn.address;
            const inMod = addr.compare(modStart) >= 0 && addr.compare(modEnd) < 0;
            if (inMod && seq < MAX_EVENTS) {
              const offsetStr = addr.sub(modStart).toString();
              const mnem = insn.mnemonic;
              const ops = insn.opStr;
              const addrStr = addr.toString();
              iterator.putCallout((ctx) => {
                if (seq >= MAX_EVENTS) return;
%s
                const kind = (mnem === 'bl' || mnem === 'blr' || mnem === 'call') ? 'call'
                  : (mnem === 'ret' || mnem === 'retaa' || mnem === 'retab') ? 'ret' : 'insn';
                emit({
                  kind: kind,
                  source: 'stalker',
                  arch: %s,
                  thread_id: tid,
                  module: TARGET_MODULE,
                  module_base: modStart.toString(),
                  address: addrStr,
                  offset: offsetStr,
                  mnemonic: mnem,
                  operands: ops,
                  regs_after: INCLUDE_REGS ? regs : undefined
                });
              });
            }
            iterator.keep();
            insn = iterator.next();
          }
        }
      });
    },
    onLeave(retval) {
      if (!this.stalking) return;
      Stalker.unfollow(this.threadId);
      Stalker.flush();
      if (INCLUDE_CALLS) {
        emit({
          kind: 'ret',
          source: 'stalker',
          thread_id: this.threadId,
          module: TARGET_MODULE,
          address: targetPtr.toString(),
          offset: targetPtr.sub(modStart).toString(),
          symbol: %s,
          ret_val: retval.toString()
        });
      }
      this.stalking = false;
      activeTid = -1;
    }
  });
  return true;
}

if (!attachStalker()) {
  const dlopen = Module.findExportByName(null, 'android_dlopen_ext') || Module.findExportByName(null, 'dlopen');
  if (dlopen) {
    Interceptor.attach(dlopen, {
      onEnter(args) {
        this.path = args[0].isNull() ? '' : args[0].readCString();
      },
      onLeave() {
        if (this.path && this.path.indexOf(TARGET_MODULE) >= 0) {
          attachStalker();
        }
      }
    });
  }
}
`,
		pkgComment,
		jsonQuote(cfg.TargetModule),
		cfg.MaxEvents,
		cfg.IncludeRegs,
		cfg.IncludeCalls,
		targetExpr,
		jsonQuote(cfg.Arch),
		jsonQuote(symName),
		regSnippet,
		jsonQuote(cfg.Arch),
		jsonQuote(symName),
	)

	return &GeneratedCollector{
		Kind:        "stalker",
		Name:        fmt.Sprintf("Frida Stalker · %s", cfg.TargetModule),
		Language:    "javascript",
		Filename:    "cap_stalker_trace.js",
		Description: fmt.Sprintf("Module-bounded Frida Stalker collector for %s (%s) emitting [CAP_TRACE] JSONL", cfg.TargetModule, cfg.Arch),
		Code:        code,
		UsageSteps: []string{
			"Run in cap Frida Studio or attach via `frida -U -f <pkg> -l cap_stalker_trace.js`.",
			"Trigger the target signing/encryption operation once.",
			"Import the `[CAP_TRACE]` output directly into cap ExecTrace (`format=auto` or `stalker`).",
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func generateJavaCallCollector(cfg CollectorConfig) *GeneratedCollector {
	classRegex := wildcardToRegex(cfg.ClassFilter)
	methodRegex := wildcardToRegex(cfg.MethodFilter)

	code := fmt.Sprintf(`// cap ExecTrace — Frida Java/JNI Wildcard Call-Tree Collector
// Emits [CAP_TRACE] JSONL events with thread-local call depth, timing, args, and return values.
'use strict';

const CLASS_PATTERN = new RegExp(%s);
const METHOD_PATTERN = new RegExp(%s);
const MAX_EVENTS = %d;

let seq = 0;
const depthByTid = {};

function fmtVal(v) {
  if (v === null || v === undefined) return 'null';
  try {
    const s = v.toString();
    return s.length > 160 ? s.slice(0, 160) + '...' : s;
  } catch (_) {
    return '<unprintable>';
  }
}

function emit(ev) {
  if (seq >= MAX_EVENTS) return;
  ev.seq = ++seq;
  ev.ts = Date.now();
  console.log('[CAP_TRACE] ' + JSON.stringify(ev));
}

Java.perform(function () {
  const matched = [];
  Java.enumerateLoadedClassesSync().forEach(function (clsName) {
    if (CLASS_PATTERN.test(clsName)) {
      matched.push(clsName);
    }
  });
  console.log('[cap_java_trace] hooking ' + matched.length + ' class(es) matching ' + CLASS_PATTERN);

  matched.forEach(function (clsName) {
    let cls;
    try {
      cls = Java.use(clsName);
    } catch (_) {
      return;
    }
    const methods = cls.class.getDeclaredMethods();
    const seen = new Set();
    for (let i = 0; i < methods.length; i++) {
      const mName = methods[i].getName();
      if (seen.has(mName) || !METHOD_PATTERN.test(mName)) continue;
      seen.add(mName);
      if (!cls[mName] || !cls[mName].overloads) continue;

      cls[mName].overloads.forEach(function (ov) {
        ov.implementation = function () {
          const tid = Process.getCurrentThreadId();
          const depth = depthByTid[tid] || 0;
          depthByTid[tid] = depth + 1;
          const sym = clsName + '.' + mName;
          const argList = [];
          for (let a = 0; a < arguments.length; a++) {
            argList.push(fmtVal(arguments[a]));
          }
          emit({
            kind: 'java_enter',
            source: 'java',
            thread_id: tid,
            depth: depth,
            symbol: sym,
            args: argList
          });
          try {
            const ret = ov.apply(this, arguments);
            emit({
              kind: 'java_exit',
              source: 'java',
              thread_id: tid,
              depth: depth,
              symbol: sym,
              ret_val: fmtVal(ret)
            });
            return ret;
          } finally {
            depthByTid[tid] = Math.max(0, (depthByTid[tid] || 1) - 1);
          }
        };
      });
    }
  });
});
`,
		jsonQuote(classRegex),
		jsonQuote(methodRegex),
		cfg.MaxEvents,
	)

	return &GeneratedCollector{
		Kind:        "java_call",
		Name:        fmt.Sprintf("Frida Java Call-Tree · %s", cfg.ClassFilter),
		Language:    "javascript",
		Filename:    "cap_java_call_trace.js",
		Description: fmt.Sprintf("Wildcard Java/JNI call-tree tracer for %s.%s emitting [CAP_TRACE] JSONL", cfg.ClassFilter, cfg.MethodFilter),
		Code:        code,
		UsageSteps: []string{
			"Launch target app in cap Frida Studio with `cap_java_call_trace.js`.",
			"Exercise the target user flow to record call depths, arguments, and return values.",
			"Import the `[CAP_TRACE]` output into cap ExecTrace to inspect reconstructed Call Trees.",
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func generateUnidbgCollector(cfg CollectorConfig) *GeneratedCollector {
	builderCall := "AndroidEmulatorBuilder.for64Bit()"
	if cfg.Arch == "arm" {
		builderCall = "AndroidEmulatorBuilder.for32Bit()"
	}
	pkg := nonEmpty(cfg.TargetPackage, "com.example.app")
	apkPath := nonEmpty(cfg.APKPath, "app-release.apk")
	soPath := nonEmpty(cfg.BinaryPath, cfg.TargetModule)
	targetSym := nonEmpty(cfg.TargetSymbol, "Java_com_example_app_NativeSigner_sign")

	memTraceLines := ""
	if cfg.IncludeMem {
		memTraceLines = `        emulator.traceRead().setRedirect(traceOut);
        emulator.traceWrite().setRedirect(traceOut);`
	} else {
		memTraceLines = `        // Memory tracing disabled in CollectorConfig (enable IncludeMem to add traceRead/traceWrite)`
	}

	code := fmt.Sprintf(`package com.cap.exectrace;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.Arrays;

/**
 * cap ExecTrace — Unidbg Code, Memory & JNI Trace Collector.
 * Output file (cap_unidbg_trace.log) imports directly into cap ExecTrace (format="unidbg").
 */
public class CapUnidbgTracer extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final PrintStream traceOut;

    public CapUnidbgTracer() throws Exception {
        this.traceOut = new PrintStream(new FileOutputStream("cap_unidbg_trace.log"), true, "UTF-8");
        this.emulator = %s
                .setProcessName(%s)
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        this.vm = emulator.createDalvikVM(new File(%s));
        this.vm.setJni(this);
        this.vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(new File(%s), true);
        dm.callJNI_OnLoad(emulator);
        this.module = dm.getModule();
    }

    public void runTracedCall() {
        long start = module.base;
        long end = module.base + module.size;
        emulator.traceCode(start, end).setRedirect(traceOut);
%s

        // Invoke exported native function (adjust arguments as needed for %s)
        Number[] ret = module.callFunction(emulator, %s);
        traceOut.printf("[CAP_UNIDBG_DONE] base=0x%%x ret=%%s%%n", module.base, Arrays.toString(ret));
        traceOut.flush();
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(com.github.unidbg.linux.android.dvm.BaseVM vm,
                                                com.github.unidbg.linux.android.dvm.DvmClass dvmClass,
                                                String signature, VaList vaList) {
        traceOut.printf("JNIEnv->CallStaticObjectMethodV(%%s, %%s)%%n", dvmClass.getClassName(), signature);
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject<?> newObjectV(com.github.unidbg.linux.android.dvm.BaseVM vm,
                                   com.github.unidbg.linux.android.dvm.DvmClass dvmClass,
                                   String signature, VaList vaList) {
        traceOut.printf("JNIEnv->NewObjectV(%%s, %%s)%%n", dvmClass.getClassName(), signature);
        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    public static void main(String[] args) throws Exception {
        CapUnidbgTracer tracer = new CapUnidbgTracer();
        tracer.runTracedCall();
    }
}
`,
		builderCall,
		jsonQuote(pkg),
		jsonQuote(apkPath),
		jsonQuote(soPath),
		memTraceLines,
		sanitizeComment(targetSym),
		jsonQuote(targetSym),
	)

	return &GeneratedCollector{
		Kind:        "unidbg",
		Name:        fmt.Sprintf("Unidbg Tracer · %s", cfg.TargetModule),
		Language:    "java",
		Filename:    "CapUnidbgTracer.java",
		Description: fmt.Sprintf("Unidbg traceCode + traceRead/traceWrite + JNI logger for %s (%s)", cfg.TargetModule, cfg.Arch),
		Code:        code,
		UsageSteps: []string{
			"Place CapUnidbgTracer.java in your Unidbg project and adjust the APK/.so paths and target arguments.",
			"Run CapUnidbgTracer to generate `cap_unidbg_trace.log`.",
			"Import `cap_unidbg_trace.log` into cap ExecTrace (`format=unidbg` or `auto`).",
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func generateQilingCollector(cfg CollectorConfig) *GeneratedCollector {
	binPath := nonEmpty(cfg.BinaryPath, "./"+cfg.TargetModule)
	rootfs := nonEmpty(cfg.RootFS, "./rootfs/arm64_linux")
	if cfg.Arch == "arm" && cfg.RootFS == "" {
		rootfs = "./rootfs/arm_linux"
	} else if cfg.Arch == "x86_64" && cfg.RootFS == "" {
		rootfs = "./rootfs/x8664_linux"
	}

	regList := `["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "sp", "lr"]`
	switch cfg.Arch {
	case "arm":
		regList = `["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "sp", "lr"]`
	case "x86_64":
		regList = `["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"]`
	}

	argv := []string{binPath}
	argv = append(argv, cfg.Args...)
	argvQuoted := make([]string, len(argv))
	for i, a := range argv {
		argvQuoted[i] = jsonQuote(a)
	}

	memHookSnippet := ""
	if cfg.IncludeMem {
		memHookSnippet = `def on_mem_read(ql, access, address, size, value):
    if event_count[0] >= MAX_EVENTS:
        return
    try:
        data = bytes(ql.mem.read(address, min(size, 16))).hex()
    except Exception:
        data = ""
    emit({
        "kind": "mem_read",
        "source": "qiling",
        "module": TARGET_MODULE,
        "address": hex(ql.arch.regs.arch_pc),
        "mem_addr": hex(address),
        "mem_size": size,
        "mem_value_hex": data,
    })

def on_mem_write(ql, access, address, size, value):
    if event_count[0] >= MAX_EVENTS:
        return
    emit({
        "kind": "mem_write",
        "source": "qiling",
        "module": TARGET_MODULE,
        "address": hex(ql.arch.regs.arch_pc),
        "mem_addr": hex(address),
        "mem_size": size,
        "mem_value_hex": f"{value:0{max(size * 2, 2)}x}",
    })

ql.hook_mem_read(on_mem_read)
ql.hook_mem_write(on_mem_write)`
	} else {
		memHookSnippet = `# Memory hooks disabled in CollectorConfig`
	}

	code := fmt.Sprintf(`#!/usr/bin/env python3
"""cap ExecTrace — Qiling Instruction, Memory & Syscall Collector.
Emits [CAP_TRACE] JSONL directly importable by cap ExecTrace.
"""
import json
import time
from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE

TARGET_MODULE = %s
ARCH = %s
MAX_EVENTS = %d
INCLUDE_REGS = %s
WATCH_REGS = %s
OUT_PATH = "cap_qiling_trace.jsonl"

event_count = [0]
out_file = open(OUT_PATH, "w", encoding="utf-8")


def emit(ev):
    if event_count[0] >= MAX_EVENTS:
        return
    event_count[0] += 1
    ev["seq"] = event_count[0]
    ev["ts"] = int(time.time() * 1000)
    out_file.write("[CAP_TRACE] " + json.dumps(ev) + "\n")


ql = Qiling([%s], %s, verbose=QL_VERBOSE.OFF)
md = ql.arch.disassembler


def on_code(ql, address, size):
    if event_count[0] >= MAX_EVENTS:
        ql.emu_stop()
        return
    try:
        raw = bytes(ql.mem.read(address, size))
    except Exception:
        raw = b""
    mnem, ops = "", ""
    if raw:
        for insn in md.disasm(raw, address):
            mnem = insn.mnemonic
            ops = insn.op_str
            break
    regs = {}
    if INCLUDE_REGS:
        for r in WATCH_REGS:
            try:
                regs[r] = hex(ql.arch.regs.read(r))
            except Exception:
                pass
    emit({
        "kind": "insn",
        "source": "qiling",
        "arch": ARCH,
        "module": TARGET_MODULE,
        "address": hex(address),
        "mnemonic": mnem,
        "operands": ops,
        "raw_bytes": raw.hex(),
        "regs_after": regs if INCLUDE_REGS else None,
    })


def make_syscall_hook(name):
    def _on_syscall(ql, *args):
        if event_count[0] >= MAX_EVENTS:
            return
        emit({
            "kind": "syscall",
            "source": "qiling",
            "arch": ARCH,
            "module": TARGET_MODULE,
            "address": hex(ql.arch.regs.arch_pc),
            "symbol": name,
            "args": [hex(a) if isinstance(a, int) else str(a) for a in args[:6]],
        })
    return _on_syscall


for _sc_name in ("openat", "open", "read", "write", "close", "ioctl", "mmap", "mprotect", "socket", "connect"):
    try:
        ql.os.set_syscall(_sc_name, make_syscall_hook(_sc_name), QL_INTERCEPT.ENTER)
    except Exception:
        pass


ql.hook_code(on_code)
%s

try:
    ql.run()
finally:
    out_file.close()
    print(f"[cap_qiling] wrote {event_count[0]} events to {OUT_PATH}")
`,
		jsonQuote(cfg.TargetModule),
		jsonQuote(cfg.Arch),
		cfg.MaxEvents,
		pyBool(cfg.IncludeRegs),
		regList,
		strings.Join(argvQuoted, ", "),
		jsonQuote(rootfs),
		memHookSnippet,
	)

	return &GeneratedCollector{
		Kind:        "qiling",
		Name:        fmt.Sprintf("Qiling Tracer · %s", cfg.TargetModule),
		Language:    "python",
		Filename:    "cap_qiling_trace.py",
		Description: fmt.Sprintf("Qiling hook_code + memory + syscall tracer for %s (%s)", cfg.TargetModule, cfg.Arch),
		Code:        code,
		UsageSteps: []string{
			"Install Qiling (`pip install qiling`) and point ROOTFS to your target rootfs directory.",
			"Run `python3 cap_qiling_trace.py` to generate `cap_qiling_trace.jsonl`.",
			"Import `cap_qiling_trace.jsonl` into cap ExecTrace (`format=auto` or `jsonl`).",
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func wildcardToRegex(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return ".*"
	}
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '.', '+', '(', ')', '|', '^', '$', '[', ']', '{', '}', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('$')
	return b.String()
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}
