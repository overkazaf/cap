package deobf

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// GenerateVMPStalkerScript synthesizes a precision Frida Stalker.follow ARM64/ARM
// native VMP tracer scoped strictly to soName's module bounds. It records a live
// dispatcher PC histogram, register deltas, virtual bytecode memory reads, and
// external libc/JNI calls, emitting [CAP_VMP] JSON lines compatible with
// AnalyzeVMPTrace.
func GenerateVMPStalkerScript(soName, entrySymbolOrOffset string, maxEvents int) *GeneratedScript {
	soName = nonEmptyOr(soName, "libvmp.so")
	entry := nonEmptyOr(entrySymbolOrOffset, "JNI_OnLoad")
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	isHexOffset := strings.HasPrefix(strings.ToLower(entry), "0x")

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Native VMP Precision Stalker Tracer ─────────────────────────\n")
	fmt.Fprintf(&b, "// Target Module: %s\n", soName)
	fmt.Fprintf(&b, "// Entry Point:   %s\n", entry)
	fmt.Fprintf(&b, "// Max Events:    %d\n\n", maxEvents)

	fmt.Fprintf(&b, "const TARGET_SO = %s;\n", jsQuote(soName))
	fmt.Fprintf(&b, "const ENTRY_SPEC = %s;\n", jsQuote(entry))
	fmt.Fprintf(&b, "const ENTRY_IS_OFFSET = %s;\n", boolJS(isHexOffset))
	fmt.Fprintf(&b, "const MAX_EVENTS = %d;\n\n", maxEvents)

	b.WriteString(`let emittedEvents = 0;
let activeTid = null;
const pcHistogram = {};
const edgeFanout = {};

function emitVMP(record) {
    console.log('[CAP_VMP] ' + JSON.stringify(record));
    send(Object.assign({ cap_cat: 'deobf_vmp' }, record));
}

function formatRegSnapshot(ctx) {
    if (Process.arch === 'arm64') {
        return {
            x0: ctx.x0.toString(), x1: ctx.x1.toString(), x2: ctx.x2.toString(),
            x3: ctx.x3.toString(), x8: ctx.x8.toString(), x9: ctx.x9.toString(),
            sp: ctx.sp.toString(), lr: ctx.lr.toString()
        };
    }
    return {
        r0: ctx.r0.toString(), r1: ctx.r1.toString(), r2: ctx.r2.toString(),
        r3: ctx.r3.toString(), sp: ctx.sp.toString(), lr: ctx.lr.toString()
    };
}

function diffRegs(prev, cur) {
    if (!prev) return cur;
    const delta = {};
    Object.keys(cur).forEach(function (k) {
        if (prev[k] !== cur[k]) delta[k] = cur[k];
    });
    return delta;
}

function attachStalker(mod, entryAddr) {
    const modBase = mod.base;
    const modEnd = mod.base.add(mod.size);
    const inBounds = function (addr) {
        return addr.compare(modBase) >= 0 && addr.compare(modEnd) < 0;
    };

    emitVMP({
        event: 'attached',
        module: mod.name,
        base: modBase.toString(),
        size: mod.size,
        entry: entryAddr.toString(),
    });

    Interceptor.attach(entryAddr, {
        onEnter(args) {
            if (activeTid !== null || emittedEvents >= MAX_EVENTS) return;
            activeTid = Process.getCurrentThreadId();
            let lastPC = null;
            let lastRegs = null;

            emitVMP({
                event: 'trace_begin',
                tid: activeTid,
                module_base: modBase.toString(),
                args: [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()],
            });

            Stalker.follow(activeTid, {
                transform(iterator) {
                    let insn = iterator.next();
                    while (insn !== null) {
                        const addr = insn.address;
                        if (inBounds(addr)) {
                            const insnText = insn.mnemonic + (insn.opStr ? ' ' + insn.opStr : '');
                            const isIndirectBr = /^(br|blr|bx|blx)$/i.test(insn.mnemonic);
                            const isCall = /^(bl|blr|blx)$/i.test(insn.mnemonic);
                            const callImm = (insn.mnemonic.toLowerCase() === 'bl' && insn.opStr && insn.opStr.indexOf('#0x') === 0)
                                ? insn.opStr.slice(1)
                                : null;
                            const isMemRead = /^ldr/i.test(insn.mnemonic);
                            const isMemWrite = /^str/i.test(insn.mnemonic);
                            const pcStr = addr.toString();
                            const offStr = addr.sub(modBase).toString();

                            iterator.putCallout(function (context) {
                                if (emittedEvents >= MAX_EVENTS) return;
                                emittedEvents++;

                                // Track dispatcher histogram & edge fan-out
                                pcHistogram[offStr] = (pcHistogram[offStr] || 0) + 1;
                                if (lastPC !== null) {
                                    if (!edgeFanout[lastPC]) edgeFanout[lastPC] = new Set();
                                    edgeFanout[lastPC].add(offStr);
                                }
                                lastPC = offStr;

                                const curRegs = formatRegSnapshot(context);
                                const regDelta = diffRegs(lastRegs, curRegs);
                                lastRegs = curRegs;

                                const rec = {
                                    event: 'insn',
                                    pc: pcStr,
                                    offset: offStr,
                                    insn: insnText,
                                    regs: regDelta,
                                };

                                // Resolve external libc/JNI call targets
                                if (isCall) {
                                    const targetAddr = callImm
                                        ? ptr(callImm)
                                        : (isIndirectBr && Process.arch === 'arm64' ? context.x8 : context.lr);
                                    const sym = DebugSymbol.fromAddress(targetAddr);
                                    if (sym && sym.name && (!sym.moduleName || sym.moduleName !== mod.name)) {
                                        rec.call = (sym.moduleName ? sym.moduleName + '!' : '') + sym.name;
                                    }
                                }
                                if (isMemRead && Process.arch === 'arm64') {
                                    rec.mem_r = context.x9.toString();
                                }
                                if (isMemWrite && Process.arch === 'arm64') {
                                    rec.mem_w = context.sp.toString();
                                }
                                emitVMP(rec);
                            });
                        }
                        iterator.keep();
                        insn = iterator.next();
                    }
                }
            });
        },
        onLeave(retval) {
            if (activeTid === null) return;
            Stalker.unfollow(activeTid);
            Stalker.flush();
            Stalker.garbageCollect();

            // Summarize top dispatcher candidates locally before closing
            const topDispatchers = Object.keys(edgeFanout)
                .map(function (off) {
                    return { offset: off, hits: pcHistogram[off] || 0, fanout: edgeFanout[off].size };
                })
                .filter(function (x) { return x.fanout >= 2; })
                .sort(function (a, b) { return (b.fanout * b.hits) - (a.fanout * a.hits); })
                .slice(0, 8);

            emitVMP({
                event: 'trace_end',
                tid: activeTid,
                retval: retval.toString(),
                total_events: emittedEvents,
                top_dispatchers: topDispatchers,
            });
            activeTid = null;
        }
    });
}

function tryAttach() {
    const mod = Process.findModuleByName(TARGET_SO);
    if (!mod) return false;
    const entryAddr = ENTRY_IS_OFFSET
        ? mod.base.add(ptr(ENTRY_SPEC))
        : (Module.findExportByName(TARGET_SO, ENTRY_SPEC) || mod.findSymbolByName(ENTRY_SPEC));
    if (!entryAddr) {
        emitVMP({ event: 'error', message: 'Entry point not found: ' + ENTRY_SPEC + ' in ' + TARGET_SO });
        return false;
    }
    attachStalker(mod, entryAddr);
    return true;
}

if (!tryAttach()) {
    ['dlopen', 'android_dlopen_ext'].forEach(function (loader) {
        const addr = Module.findExportByName(null, loader);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.hit = !args[0].isNull() && args[0].readCString().indexOf(TARGET_SO) !== -1;
            },
            onLeave() {
                if (this.hit) tryAttach();
            }
        });
    });
}
`)

	return &GeneratedScript{
		ID:          "deobf:vmp-stalker",
		Name:        fmt.Sprintf("VMP Frida Stalker Tracer (%s!%s)", soName, entry),
		Category:    "vmp_stalker",
		Engine:      EngineFrida,
		Language:    "javascript",
		Target:      fmt.Sprintf("%s!%s", soName, entry),
		Description: fmt.Sprintf("Scoped Frida Stalker ARM64/ARM VMP tracer on %s!%s (up to %d events) emitting [CAP_VMP] JSON lines for AnalyzeVMPTrace.", soName, entry, maxEvents),
		Code:        b.String(),
		Modules:     []string{"ModuleBoundsScoping", "StalkerInstructionCallout", "DispatcherFanoutTracker", "ExternalCallResolver"},
		Usage:       fmt.Sprintf("frida -U -f <com.example.app> -l cap_vmp_stalker.js > vmp_trace.log"),
		Notes: []string{
			"Feed captured [CAP_VMP] trace output directly into cap's AnalyzeVMPTrace(rawTrace, moduleBase) to pinpoint the dispatcher loop and handler table.",
		},
		GeneratedAt: nowRFC3339(),
	}
}

// GenerateVMPRegisterNativesScript generates a Frida script hooking libart.so
// RegisterNatives to map every VMP/Dex2C-protected Java method to its native
// (.so + offset) implementation and automatically highlight shared VMP
// dispatcher entries when multiple Java methods bind to the exact same address.
func GenerateVMPRegisterNativesScript(filterPkg string) *GeneratedScript {
	cleanPkg := strings.TrimSpace(filterPkg)
	pkgSlash := strings.ReplaceAll(cleanPkg, ".", "/")

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap VMP / Dex2C RegisterNatives Mapper & Dispatcher Detector ───\n")
	fmt.Fprintf(&b, "// Package Filter: %s\n\n", nonEmptyOr(cleanPkg, "*"))

	fmt.Fprintf(&b, "const FILTER_PKG_DOT = %s;\n", jsQuote(cleanPkg))
	fmt.Fprintf(&b, "const FILTER_PKG_SLASH = %s;\n\n", jsQuote(pkgSlash))

	b.WriteString(`const addrToMethods = {}; // fnPtrHex -> [{ className, method, sig, module, offset }]
const allBindings = [];

function matchesFilter(className) {
    if (!FILTER_PKG_DOT) return true;
    return className.indexOf(FILTER_PKG_DOT) !== -1 || className.indexOf(FILTER_PKG_SLASH) !== -1;
}

function installRegisterNativesHook() {
    const libart = Process.findModuleByName('libart.so');
    if (!libart) {
        send({ cap_cat: 'deobf_vmp_jni', event: 'error', detail: 'libart.so not found' });
        return;
    }

    let addrRegisterNatives = null;
    const syms = libart.enumerateSymbols();
    for (let i = 0; i < syms.length; i++) {
        const n = syms[i].name;
        if (n.indexOf('art') >= 0 && n.indexOf('JNI') >= 0 &&
            n.indexOf('RegisterNatives') >= 0 && n.indexOf('CheckJNI') < 0) {
            addrRegisterNatives = syms[i].address;
            break;
        }
    }
    if (!addrRegisterNatives) {
        send({ cap_cat: 'deobf_vmp_jni', event: 'error', detail: 'RegisterNatives symbol not found in libart.so' });
        return;
    }

    Interceptor.attach(addrRegisterNatives, {
        onEnter(args) {
            const javaClass = args[1];
            const methodsPtr = ptr(args[2]);
            const methodCount = args[3].toInt32();
            let className = '';
            try {
                className = Java.vm.tryGetEnv().getClassName(javaClass);
            } catch (_) {}

            if (className && !matchesFilter(className)) return;

            for (let i = 0; i < methodCount; i++) {
                const entry = methodsPtr.add(i * Process.pointerSize * 3);
                const mName = entry.readPointer().readCString();
                const mSig = entry.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = entry.add(Process.pointerSize * 2).readPointer();
                const mod = Process.findModuleByAddress(fnPtr);
                const modName = mod ? mod.name : 'unknown';
                const offHex = mod ? fnPtr.sub(mod.base).toString() : fnPtr.toString();
                const addrKey = fnPtr.toString();

                const binding = {
                    class_name: className,
                    method: mName,
                    signature: mSig,
                    module: modName,
                    offset: offHex,
                    address: addrKey,
                };
                allBindings.push(binding);

                if (!addrToMethods[addrKey]) addrToMethods[addrKey] = [];
                addrToMethods[addrKey].push(binding);

                const sharedCount = addrToMethods[addrKey].length;
                const isSharedVMP = sharedCount >= 2;

                send({
                    cap_cat: 'deobf_vmp_jni',
                    event: isSharedVMP ? 'shared_vmp_dispatcher' : 'register_native',
                    shared_vmp_dispatcher: isSharedVMP,
                    shared_method_count: sharedCount,
                    co_bound_methods: isSharedVMP
                        ? addrToMethods[addrKey].map(function (b) { return b.class_name + '.' + b.method; })
                        : undefined,
                    binding: binding,
                });
            }
        }
    });

    send({ cap_cat: 'deobf_vmp_jni', event: 'ready', register_natives: addrRegisterNatives.toString() });
}

installRegisterNativesHook();

rpc.exports = {
    dumpBindings: function () {
        const shared = {};
        Object.keys(addrToMethods).forEach(function (k) {
            if (addrToMethods[k].length >= 2) shared[k] = addrToMethods[k];
        });
        return { total: allBindings.length, shared_vmp_dispatchers: shared, bindings: allBindings };
    }
};
`)

	return &GeneratedScript{
		ID:          "deobf:vmp-register-natives",
		Name:        "VMP RegisterNatives & Shared Dispatcher Mapper",
		Category:    "vmp_jni",
		Engine:      EngineFrida,
		Language:    "javascript",
		Target:      nonEmptyOr(cleanPkg, "*"),
		Description: "Hooks libart.so RegisterNatives to map dynamic native methods to .so+offset and flag shared VMP dispatcher entry points.",
		Code:        b.String(),
		Modules:     []string{"LibArtRegisterNativesHook", "SharedVMPDispatcherDetector"},
		Usage:       fmt.Sprintf("frida -U -f %s -l cap_vmp_register_natives.js", nonEmptyOr(cleanPkg, "<com.example.app>")),
		GeneratedAt: nowRFC3339(),
	}
}

// GenerateUnidbgVMPTraceScript synthesizes an offline Unidbg instruction,
// memory read/write, and JNI trace harness immune to runtime anti-debug checks.
func GenerateUnidbgVMPTraceScript(apkPath, soName, className, methodName string) *GeneratedScript {
	apkPath = nonEmptyOr(apkPath, "./target.apk")
	soName = nonEmptyOr(soName, "libvmp.so")
	className = nonEmptyOr(className, "com/example/security/VmpBridge")
	methodName = nonEmptyOr(methodName, "sign(Ljava/lang/String;)Ljava/lang/String;")

	slashClass := strings.ReplaceAll(className, ".", "/")
	libShort := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(soName), "lib"), ".so")
	if libShort == "" {
		libShort = "vmp"
	}

	var b strings.Builder
	b.WriteString("// cap Unidbg Offline VMP Instruction + Memory + JNI Trace Harness\n")
	fmt.Fprintf(&b, "// APK:    %s\n", apkPath)
	fmt.Fprintf(&b, "// SO:     %s\n", soName)
	fmt.Fprintf(&b, "// Method: %s.%s\n\n", slashClass, methodName)

	b.WriteString(`import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;

public class CapUnidbgVMPTracer extends AbstractJni {
`)
	fmt.Fprintf(&b, "    private static final String APK_PATH    = %s;\n", javaQuote(apkPath))
	fmt.Fprintf(&b, "    private static final String LIB_NAME    = %s;\n", javaQuote(libShort))
	fmt.Fprintf(&b, "    private static final String TARGET_CLS  = %s;\n", javaQuote(slashClass))
	fmt.Fprintf(&b, "    private static final String TARGET_METH = %s;\n", javaQuote(methodName))
	fmt.Fprintf(&b, "    private static final String TRACE_FILE  = %s;\n\n", javaQuote(sanitizeSlug(libShort)+"_vmp_trace.log"))

	b.WriteString(`    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    public CapUnidbgVMPTracer() {
        this.emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.cap.vmptrace")
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        this.vm = emulator.createDalvikVM(new File(APK_PATH));
        this.vm.setJni(this);
        this.vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(LIB_NAME, true);
        this.module = dm.getModule();
        dm.callJNI_OnLoad(emulator);
    }

    public void runTrace(String sampleInput) throws Exception {
        PrintStream traceStream = new PrintStream(new FileOutputStream(TRACE_FILE), true, "UTF-8");
        try {
            System.out.printf("[CAP_VMP] {\"event\":\"module_loaded\",\"module\":\"%s\",\"base\":\"0x%x\",\"size\":%d}%n",
                    LIB_NAME, module.base, module.size);

            // Attach instruction, memory-read, and memory-write tracers scoped to module bounds
            emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
            emulator.traceRead(module.base, module.base + module.size).setRedirect(traceStream);
            emulator.traceWrite(module.base, module.base + module.size).setRedirect(traceStream);

            DvmClass targetClass = vm.resolveClass(TARGET_CLS);
            DvmObject<?> result = targetClass.callStaticJniMethodObject(
                    emulator,
                    TARGET_METH,
                    new StringObject(vm, sampleInput)
            );
            System.out.printf("[CAP_VMP] {\"event\":\"trace_done\",\"trace_file\":\"%s\",\"result\":\"%s\"}%n",
                    TRACE_FILE, result != null ? String.valueOf(result.getValue()) : "null");
        } finally {
            traceStream.close();
            emulator.close();
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        System.out.printf("CALL JNI::%s%n", signature);
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.printf("CALL JNI::%s%n", signature);
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    public static void main(String[] args) throws Exception {
        String input = args.length > 0 ? args[0] : "cap_vmp_test_payload";
        new CapUnidbgVMPTracer().runTrace(input);
    }
}
`)

	return &GeneratedScript{
		ID:          "deobf:vmp-unidbg",
		Name:        fmt.Sprintf("Unidbg Offline VMP Tracer (%s)", filepath.Base(soName)),
		Category:    "vmp_unidbg",
		Engine:      EngineUnidbg,
		Language:    "java",
		Target:      fmt.Sprintf("%s -> %s.%s", filepath.Base(soName), slashClass, methodName),
		Description: "Offline Unidbg instruction (traceCode), memory (traceRead/traceWrite), and JNI trace harness immune to anti-debug checks.",
		Code:        b.String(),
		Modules:     []string{"UnidbgTraceCode", "UnidbgTraceReadWrite", "AbstractJniTracer"},
		Usage:       "Run CapUnidbgVMPTracer in your Unidbg project and load the generated *_vmp_trace.log into cap AnalyzeVMPTrace.",
		GeneratedAt: nowRFC3339(),
	}
}

// ─── Pure-Go VMP Trace Analyzer ───────────────────────────────────────────────

var (
	reBracketHexInsn = regexp.MustCompile(`^\[(?:[^\]]*?\+)?0x([0-9a-fA-F]+)\]\s*(.*)$`)
	reUnidbgLine     = regexp.MustCompile(`0x([0-9a-fA-F]+):\s*"([^"]+)"`)
	rePlainHexInsn   = regexp.MustCompile(`^0x([0-9a-fA-F]+):?\s+(.+)$`)
	reMemRead        = regexp.MustCompile(`(?i)(?:\bMEM_R\b|\bmr\b|\bREAD\b)\s*[=:@]?\s*0x([0-9a-fA-F]+)`)
	reMemWrite       = regexp.MustCompile(`(?i)(?:\bMEM_W\b|\bmw\b|\bWRITE\b)\s*[=:@]?\s*0x([0-9a-fA-F]+)`)
	reCallLine       = regexp.MustCompile(`(?i)^(?:\[CALL\]|CALL)\s+(?:(0x[0-9a-fA-F]+)\s*->\s*)?(.+)$`)
	reInlineCall     = regexp.MustCompile(`(?i)\b(?:bl|blr|call)\s+([a-zA-Z_][a-zA-Z0-9_!:.@$<>()-]+)`)
)

type capVMPJSONLine struct {
	Event string `json:"event"`
	PC    string `json:"pc"`
	Insn  string `json:"insn"`
	MemR  string `json:"mem_r"`
	MemW  string `json:"mem_w"`
	Call  string `json:"call"`
}

// AnalyzeVMPTrace parses raw Frida Stalker, Unidbg, or Tenet execution traces
// in pure Go to identify VMP fetch-decode dispatcher loops (high frequency +
// high branch fan-out), virtual opcode handler table entries, VM stack/context
// memory hotspots, and external libc/crypto/JNI calls.
func AnalyzeVMPTrace(rawTrace string, moduleBase uint64) *VMPTraceAnalysis {
	res := &VMPTraceAnalysis{
		DispatcherCandidates: []VMPHotspot{},
		HandlerEntries:       []VMPHotspot{},
		MemoryHotspots:       []VMPMemSpot{},
		ExternalCalls:        []VMPExternalCall{},
		RecommendedHooks:     []string{},
	}
	if moduleBase > 0 {
		res.ModuleBase = fmt.Sprintf("0x%x", moduleBase)
	}
	if strings.TrimSpace(rawTrace) == "" {
		res.Summary = "Empty trace input (0 instructions parsed)"
		return res
	}

	pcHits := make(map[uint64]int)
	pcInsn := make(map[uint64]string)
	outEdges := make(map[uint64]map[uint64]int)
	inEdges := make(map[uint64]map[uint64]int)

	type memAcc struct {
		reads  int
		writes int
	}
	memSpots := make(map[uint64]*memAcc)

	type extAcc struct {
		count  int
		caller string
	}
	extCalls := make(map[string]*extAcc)

	recordMem := func(addr uint64, isWrite bool) {
		acc, ok := memSpots[addr]
		if !ok {
			acc = &memAcc{}
			memSpots[addr] = acc
		}
		if isWrite {
			acc.writes++
		} else {
			acc.reads++
		}
	}

	recordCall := func(target, caller string) {
		target = strings.TrimSpace(target)
		if target == "" {
			return
		}
		acc, ok := extCalls[target]
		if !ok {
			acc = &extAcc{caller: caller}
			extCalls[target] = acc
		}
		acc.count++
		if acc.caller == "" && caller != "" {
			acc.caller = caller
		}
	}

	var prevPC uint64
	hasPrevPC := false
	totalInsns := 0

	lines := strings.Split(rawTrace, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Format 1: [CAP_VMP] JSON lines
		if idx := strings.Index(line, "[CAP_VMP]"); idx >= 0 {
			jsonPart := strings.TrimSpace(line[idx+len("[CAP_VMP]"):])
			var rec capVMPJSONLine
			if json.Unmarshal([]byte(jsonPart), &rec) == nil {
				if rec.PC != "" {
					if pc, ok := parseHexUint64(rec.PC); ok {
						totalInsns++
						pcHits[pc]++
						if pcInsn[pc] == "" && rec.Insn != "" {
							pcInsn[pc] = strings.TrimSpace(rec.Insn)
						}
						if hasPrevPC && prevPC != pc {
							addEdge(outEdges, prevPC, pc)
							addEdge(inEdges, pc, prevPC)
						}
						prevPC = pc
						hasPrevPC = true
					}
				}
				if rec.MemR != "" {
					if addr, ok := parseHexUint64(rec.MemR); ok {
						recordMem(addr, false)
					}
				}
				if rec.MemW != "" {
					if addr, ok := parseHexUint64(rec.MemW); ok {
						recordMem(addr, true)
					}
				}
				if rec.Call != "" {
					caller := ""
					if hasPrevPC {
						caller = fmt.Sprintf("0x%x", prevPC)
					}
					recordCall(rec.Call, caller)
				}
				continue
			}
		}

		// Format 2: Explicit CALL line ("CALL EVP_DigestUpdate" or "CALL 0x... -> JNI::...")
		if m := reCallLine.FindStringSubmatch(line); len(m) == 3 {
			caller := strings.TrimSpace(m[1])
			if caller == "" && hasPrevPC {
				caller = fmt.Sprintf("0x%x", prevPC)
			}
			recordCall(m[2], caller)
			continue
		}

		// Extract any inline or standalone MEM_R / MEM_W markers on the line.
		for _, m := range reMemRead.FindAllStringSubmatch(line, -1) {
			if addr, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				recordMem(addr, false)
			}
		}
		for _, m := range reMemWrite.FindAllStringSubmatch(line, -1) {
			if addr, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				recordMem(addr, true)
			}
		}

		// Pure MEM_R / MEM_W line without an instruction PC
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "MEM_R") || strings.HasPrefix(upper, "MEM_W") ||
			strings.HasPrefix(upper, "READ ") || strings.HasPrefix(upper, "WRITE ") {
			continue
		}

		// Format 3: Unidbg / Bracketed / Plain hex PC instruction lines
		var pc uint64
		var insn string
		var parsed bool

		if m := reUnidbgLine.FindStringSubmatch(line); len(m) == 3 {
			if v, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				pc = v
				insn = strings.TrimSpace(m[2])
				parsed = true
			}
		} else if m := reBracketHexInsn.FindStringSubmatch(line); len(m) == 3 {
			if v, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				pc = v
				insn = cleanInsnText(m[2])
				parsed = true
			}
		} else if m := rePlainHexInsn.FindStringSubmatch(line); len(m) == 3 {
			if v, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				pc = v
				insn = cleanInsnText(m[2])
				parsed = true
			}
		}

		if !parsed {
			continue
		}

		totalInsns++
		pcHits[pc]++
		if pcInsn[pc] == "" && insn != "" {
			pcInsn[pc] = insn
		}
		if hasPrevPC && prevPC != pc {
			addEdge(outEdges, prevPC, pc)
			addEdge(inEdges, pc, prevPC)
		}
		prevPC = pc
		hasPrevPC = true

		// Check inline named calls (e.g. "bl EVP_MD_CTX_new" — skip bare register operands like x8/r0)
		if cm := reInlineCall.FindStringSubmatch(insn); len(cm) == 2 {
			sym := cm[1]
			if !isRegisterName(sym) {
				recordCall(sym, fmt.Sprintf("0x%x", pc))
			}
		}
	}

	res.TotalInstructions = totalInsns
	res.UniquePCs = len(pcHits)

	if totalInsns == 0 {
		res.Summary = "No instruction records recognized in trace"
		return res
	}

	// 1. Score and rank VMP Dispatcher Candidates by branch fan-out * log2(hits+1).
	type dispCand struct {
		pc      uint64
		hits    int
		fanOut  int
		score   float64
		targets []uint64
	}
	var dispCands []dispCand
	for pc, hits := range pcHits {
		outs := outEdges[pc]
		fanOut := len(outs)
		if fanOut < 2 {
			continue
		}
		insnLow := strings.ToLower(pcInsn[pc])
		isIndirect := strings.HasPrefix(insnLow, "br ") || strings.HasPrefix(insnLow, "blr ") ||
			strings.HasPrefix(insnLow, "bx ") || strings.HasPrefix(insnLow, "jmp ") ||
			strings.Contains(insnLow, "ldr pc")

		// Require either fan-out >= 3 or an indirect register branch with fan-out >= 2.
		if fanOut < 3 && !isIndirect {
			continue
		}

		score := float64(fanOut) * math.Log2(float64(hits)+1.0)
		if isIndirect {
			score *= 2.5
		}
		if fanOut >= 5 {
			score *= 1.4
		}

		tgts := sortedEdgeTargets(outs)
		dispCands = append(dispCands, dispCand{
			pc:      pc,
			hits:    hits,
			fanOut:  fanOut,
			score:   score,
			targets: tgts,
		})
	}

	sort.Slice(dispCands, func(i, j int) bool {
		if dispCands[i].score != dispCands[j].score {
			return dispCands[i].score > dispCands[j].score
		}
		return dispCands[i].hits > dispCands[j].hits
	})
	if len(dispCands) > 10 {
		dispCands = dispCands[:10]
	}

	dispatcherSet := make(map[uint64]bool, len(dispCands))
	for _, dc := range dispCands {
		dispatcherSet[dc.pc] = true
		nextStrs := make([]string, 0, min(len(dc.targets), 12))
		for i := 0; i < len(dc.targets) && i < 12; i++ {
			nextStrs = append(nextStrs, fmt.Sprintf("0x%x", dc.targets[i]))
		}
		res.DispatcherCandidates = append(res.DispatcherCandidates, VMPHotspot{
			Address:       fmt.Sprintf("0x%x", dc.pc),
			OffsetHex:     formatOffset(dc.pc, moduleBase),
			Hits:          dc.hits,
			UniqueTargets: dc.fanOut,
			SharePercent:  round3(100 * float64(dc.hits) / float64(totalInsns)),
			SampleInsn:    pcInsn[dc.pc],
			Role:          "dispatcher",
			NextTargets:   nextStrs,
		})
	}

	// 2. Identify Virtual Opcode Handler Entries (distinct targets jumped to by top dispatcher(s)).
	handlerMap := make(map[uint64]bool)
	if len(dispCands) > 0 {
		topCount := min(len(dispCands), 3)
		for i := 0; i < topCount; i++ {
			for _, tgt := range dispCands[i].targets {
				if !dispatcherSet[tgt] {
					handlerMap[tgt] = true
				}
			}
		}
	}

	var handlers []VMPHotspot
	for hpc := range handlerMap {
		hits := pcHits[hpc]
		handlers = append(handlers, VMPHotspot{
			Address:       fmt.Sprintf("0x%x", hpc),
			OffsetHex:     formatOffset(hpc, moduleBase),
			Hits:          hits,
			UniqueTargets: len(outEdges[hpc]),
			SharePercent:  round3(100 * float64(hits) / float64(totalInsns)),
			SampleInsn:    pcInsn[hpc],
			Role:          "handler",
		})
	}
	sort.Slice(handlers, func(i, j int) bool {
		if handlers[i].Hits != handlers[j].Hits {
			return handlers[i].Hits > handlers[j].Hits
		}
		return handlers[i].Address < handlers[j].Address
	})
	if len(handlers) > 32 {
		handlers = handlers[:32]
	}
	res.HandlerEntries = handlers

	// 3. Rank & classify memory hotspots (VM context, VM stack, bytecode/handler lookup tables).
	var memList []VMPMemSpot
	for addr, acc := range memSpots {
		tot := acc.reads + acc.writes
		role := classifyMemRole(acc.reads, acc.writes, tot, totalInsns)
		memList = append(memList, VMPMemSpot{
			Address:  fmt.Sprintf("0x%x", addr),
			Reads:    acc.reads,
			Writes:   acc.writes,
			TotalOps: tot,
			Role:     role,
		})
	}
	sort.Slice(memList, func(i, j int) bool {
		if memList[i].TotalOps != memList[j].TotalOps {
			return memList[i].TotalOps > memList[j].TotalOps
		}
		return memList[i].Address < memList[j].Address
	})
	if len(memList) > 20 {
		memList = memList[:20]
	}
	res.MemoryHotspots = memList

	// 4. Rank & categorize external calls.
	var callList []VMPExternalCall
	for tgt, acc := range extCalls {
		callList = append(callList, VMPExternalCall{
			Target:   tgt,
			CallerPC: acc.caller,
			Count:    acc.count,
			Category: categorizeExternalCall(tgt),
		})
	}
	sort.Slice(callList, func(i, j int) bool {
		if callList[i].Count != callList[j].Count {
			return callList[i].Count > callList[j].Count
		}
		return callList[i].Target < callList[j].Target
	})
	res.ExternalCalls = callList

	// 5. Generate actionable devirtualization hook recommendations.
	if len(res.DispatcherCandidates) > 0 {
		top := res.DispatcherCandidates[0]
		loc := top.Address
		if top.OffsetHex != "" {
			loc = fmt.Sprintf("%s (%s)", top.Address, top.OffsetHex)
		}
		res.RecommendedHooks = append(res.RecommendedHooks,
			fmt.Sprintf("Hook primary VMP dispatcher at %s (%d hits, %d handler targets) to log virtual opcode stream & register context", loc, top.Hits, top.UniqueTargets))
	}
	if len(res.HandlerEntries) > 0 {
		res.RecommendedHooks = append(res.RecommendedHooks,
			fmt.Sprintf("Lift %d discovered handler entry points (top handler %s @ %d hits) into symbolic IR via angr/Triton or trace register diffs per handler", len(res.HandlerEntries), res.HandlerEntries[0].Address, res.HandlerEntries[0].Hits))
	}
	for _, ms := range res.MemoryHotspots {
		if ms.Role == "vm_context" || ms.Role == "bytecode_cursor" {
			res.RecommendedHooks = append(res.RecommendedHooks,
				fmt.Sprintf("Watch %s memory hotspot at %s (%d reads / %d writes) to track virtual PC & bytecode fetch pointer", ms.Role, ms.Address, ms.Reads, ms.Writes))
			break
		}
	}
	for _, ec := range res.ExternalCalls {
		if ec.Category == "crypto" || ec.Category == "jni" {
			res.RecommendedHooks = append(res.RecommendedHooks,
				fmt.Sprintf("Intercept external %s boundary call %s (%d calls) to capture plaintext inputs/outputs without full devirtualization", ec.Category, ec.Target, ec.Count))
			if len(res.RecommendedHooks) >= 6 {
				break
			}
		}
	}

	res.Summary = fmt.Sprintf(
		"Parsed %d instructions across %d unique PCs: %d dispatcher candidate(s), %d handler entry point(s), %d memory hotspot(s), %d external call(s)",
		res.TotalInstructions, res.UniquePCs,
		len(res.DispatcherCandidates), len(res.HandlerEntries),
		len(res.MemoryHotspots), len(res.ExternalCalls),
	)
	return res
}

func addEdge(g map[uint64]map[uint64]int, from, to uint64) {
	m, ok := g[from]
	if !ok {
		m = make(map[uint64]int)
		g[from] = m
	}
	m[to]++
}

func sortedEdgeTargets(m map[uint64]int) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

func parseHexUint64(raw string) (uint64, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func formatOffset(pc, base uint64) string {
	if base == 0 || pc < base {
		return ""
	}
	return fmt.Sprintf("+0x%x", pc-base)
}

func cleanInsnText(raw string) string {
	s := strings.TrimSpace(raw)
	if idx := strings.Index(s, ";"); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	return s
}

func isRegisterName(tok string) bool {
	low := strings.ToLower(strings.TrimSpace(tok))
	if low == "sp" || low == "lr" || low == "pc" || low == "fp" || low == "ip" ||
		low == "xzr" || low == "wzr" || low == "rax" || low == "rbx" || low == "rcx" || low == "rdx" {
		return true
	}
	if len(low) >= 2 && len(low) <= 3 && (low[0] == 'x' || low[0] == 'w' || low[0] == 'r') {
		if _, err := strconv.Atoi(low[1:]); err == nil {
			return true
		}
	}
	return false
}

func classifyMemRole(reads, writes, totalOps, totalInsns int) string {
	if reads > 0 && writes == 0 {
		if reads >= 4 {
			return "lookup_table"
		}
		return "bytecode_cursor"
	}
	if writes > 0 && reads == 0 {
		return "vm_stack"
	}
	// Both reads and writes: very hot balanced access suggests VM context (vPC/vSP); otherwise VM stack.
	if reads >= writes*3 {
		return "bytecode_cursor"
	}
	if totalOps >= 6 && totalInsns > 0 && float64(totalOps)/float64(totalInsns) >= 0.08 {
		return "vm_context"
	}
	return "vm_stack"
}

func categorizeExternalCall(target string) string {
	low := strings.ToLower(target)
	switch {
	case strings.Contains(low, "jni") || strings.Contains(low, "findclass") ||
		strings.Contains(low, "getmethodid") || strings.Contains(low, "callobject") ||
		strings.Contains(low, "getstringutf") || strings.Contains(low, "newstringutf") ||
		strings.Contains(low, "registernatives"):
		return "jni"
	case strings.Contains(low, "aes") || strings.Contains(low, "sha") ||
		strings.Contains(low, "md5") || strings.Contains(low, "hmac") ||
		strings.Contains(low, "evp_") || strings.Contains(low, "rsa") ||
		strings.Contains(low, "cipher") || strings.Contains(low, "crypto") ||
		strings.Contains(low, "digest"):
		return "crypto"
	case strings.Contains(low, "ptrace") || strings.Contains(low, "tgkill") ||
		strings.Contains(low, "inotify") || strings.Contains(low, "tracerpid"):
		return "antidebug"
	case strings.Contains(low, "syscall") || strings.Contains(low, "svc"):
		return "syscall"
	case strings.Contains(low, "libc") || strings.Contains(low, "memcpy") ||
		strings.Contains(low, "memset") || strings.Contains(low, "strlen") ||
		strings.Contains(low, "strcmp") || strings.Contains(low, "malloc") ||
		strings.Contains(low, "free") || strings.Contains(low, "openat") ||
		strings.Contains(low, "pthread"):
		return "libc"
	default:
		return "external"
	}
}
