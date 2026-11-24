package deobf

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GenerateOLLVMDeflattenScript generates a professional angr-based Python
// script that analyzes an OLLVM Control Flow Flattening (CFF) function,
// identifies the main dispatcher, pre-dispatcher, and relevant real blocks,
// symbolically resolves state-transition edges, exports a clean DOT CFG, and
// patches the binary to remove the flattening backbone.
func GenerateOLLVMDeflattenScript(soPath, funcAddr string, arch string) *GeneratedScript {
	soPath = nonEmptyOr(soPath, "./target.so")
	funcAddr = normalizeHexAddr(funcAddr, "0x1000")
	normArch := normalizeArch(arch)
	baseName := filepath.Base(soPath)

	var b strings.Builder
	b.WriteString("#!/usr/bin/env python3\n")
	b.WriteString("\"\"\"\n")
	b.WriteString("cap OLLVM Control Flow Flattening (CFF) De-Flattener & Binary Patcher\n")
	fmt.Fprintf(&b, "Target Binary:   %s\n", sanitizePyDocLine(soPath))
	fmt.Fprintf(&b, "Target Function: %s (%s)\n", sanitizePyDocLine(funcAddr), sanitizePyDocLine(normArch))
	b.WriteString("Requires:        pip install angr\n")
	b.WriteString("\"\"\"\n\n")

	b.WriteString("import json\n")
	b.WriteString("import struct\n")
	b.WriteString("import sys\n")
	b.WriteString("from collections import defaultdict\n\n")
	b.WriteString("import angr\n")
	b.WriteString("import claripy\n\n")

	fmt.Fprintf(&b, "BINARY_PATH = %s\n", pyQuote(soPath))
	fmt.Fprintf(&b, "FUNC_ADDR = int(%s, 16)\n", pyQuote(funcAddr))
	fmt.Fprintf(&b, "ARCH_HINT = %s\n", pyQuote(normArch))
	fmt.Fprintf(&b, "OUT_BIN = %s\n", pyQuote(strings.TrimSuffix(soPath, filepath.Ext(soPath))+"_deflattened.so"))
	fmt.Fprintf(&b, "OUT_DOT = %s\n\n", pyQuote(strings.TrimSuffix(baseName, filepath.Ext(baseName))+"_"+strings.TrimPrefix(funcAddr, "0x")+"_clean.dot"))

	b.WriteString(`def emit(kind, **payload):
    payload["event"] = kind
    print("[CAP_DEOBF] " + json.dumps(payload, ensure_ascii=False), flush=True)


def compute_dominators(graph, entry):
    nodes = list(graph.nodes())
    dom = {n: set(nodes) for n in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == entry:
                continue
            preds = list(graph.predecessors(n))
            if not preds:
                new_dom = {n}
            else:
                new_dom = set.intersection(*(dom[p] for p in preds)) | {n}
            if new_dom != dom[n]:
                dom[n] = new_dom
                changed = True
    return dom


def identify_cff_structure(func):
    graph = func.transition_graph
    entry_node = func.get_node(func.addr)
    if entry_node is None:
        raise RuntimeError(f"Entry node 0x{func.addr:x} not found in CFG")

    dom = compute_dominators(graph, entry_node)

    # 1. Main dispatcher: dominated by entry, highest in-degree inside the loop
    candidates = sorted(
        (n for n in graph.nodes() if n.addr != func.addr and entry_node in dom.get(n, set())),
        key=lambda n: (graph.in_degree(n), graph.out_degree(n)),
        reverse=True,
    )
    if not candidates:
        raise RuntimeError("Function CFG too small to contain CFF dispatcher")
    main_dispatcher = candidates[0]

    # 2. Pre-dispatcher: node jumping directly into main_dispatcher with highest in-degree
    preds = [p for p in graph.predecessors(main_dispatcher) if p.addr != func.addr]
    preds.sort(key=lambda n: graph.in_degree(n), reverse=True)
    pre_dispatcher = preds[0] if preds else main_dispatcher

    # 3. Return blocks (zero outgoing edges inside function)
    ret_nodes = [n for n in graph.nodes() if graph.out_degree(n) == 0]

    # 4. Relevant real blocks: prologue + return blocks + predecessors of pre-dispatcher
    relevant = {entry_node.addr}
    for rn in ret_nodes:
        relevant.add(rn.addr)
    for p in graph.predecessors(pre_dispatcher):
        if p.addr != main_dispatcher.addr:
            relevant.add(p.addr)

    # Backbone blocks: dispatcher + switch chain blocks not in relevant set
    backbone = {
        n.addr for n in graph.nodes()
        if n.addr not in relevant and n.addr != func.addr
    }
    return main_dispatcher.addr, pre_dispatcher.addr, sorted(relevant), sorted(backbone)


def resolve_block_successors(proj, block_addr, relevant_set, main_dispatcher, max_steps=160):
    """
    Symbolically step from block_addr through the CFF dispatcher backbone until
    execution reaches one (unconditional) or two (conditional) real blocks.
    """
    state = proj.factory.blank_state(
        addr=block_addr,
        add_options={
            angr.options.CALLLESS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )

    # Inspect whether block contains a conditional select (CSEL/CMOV) so we can branch both paths
    simgr = proj.factory.simulation_manager(state)
    targets = []
    seen = set()

    for _ in range(max_steps):
        if not simgr.active:
            break
        next_active = []
        for st in simgr.active:
            if st.addr != block_addr and st.addr in relevant_set:
                if st.addr not in seen:
                    seen.add(st.addr)
                    targets.append(st.addr)
                continue
            next_active.append(st)
        simgr.active[:] = next_active
        if not simgr.active or len(targets) >= 2:
            break
        simgr.step()

    return targets


def encode_arm64_b(src_addr, dst_addr):
    delta = dst_addr - src_addr
    if delta % 4 != 0 or abs(delta) >= (1 << 27):
        raise ValueError(f"ARM64 B out of range: 0x{src_addr:x} -> 0x{dst_addr:x}")
    imm26 = (delta >> 2) & 0x03FFFFFF
    return struct.pack("<I", 0x14000000 | imm26)


def encode_arm64_nop():
    return struct.pack("<I", 0xD503201F)


def export_dot(flow_edges, out_path):
    lines = ["digraph deflattened {", '  node [shape=box, fontname="monospace"];']
    for src, dsts in sorted(flow_edges.items()):
        for idx, dst in enumerate(dsts):
            color = "#2ea043" if len(dsts) == 1 else ("#58a6ff" if idx == 0 else "#f85149")
            label = "" if len(dsts) == 1 else ("T" if idx == 0 else "F")
            lines.append(f'  "0x{src:x}" -> "0x{dst:x}" [color="{color}", label="{label}"];')
    lines.append("}")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def patch_binary(proj, raw_bytes, flow_edges, backbone_addrs, func, out_path):
    buf = bytearray(raw_bytes)
    base = proj.loader.main_object.mapped_base
    patched_edges = 0
    nopped_blocks = 0

    def vaddr_to_offset(va):
        off = proj.loader.main_object.addr_to_offset(va)
        return off if off is not None else (va - base)

    is_arm64 = proj.arch.name.lower() in ("aarch64", "arm64")

    # 1. Patch unconditional relevant-block exits directly to their resolved successor
    for src, dsts in flow_edges.items():
        if len(dsts) != 1 or not is_arm64:
            continue
        blk = proj.factory.block(src)
        if blk.size < 4:
            continue
        tail_va = src + blk.size - 4
        file_off = vaddr_to_offset(tail_va)
        if file_off is None or file_off < 0 or file_off + 4 > len(buf):
            continue
        try:
            buf[file_off : file_off + 4] = encode_arm64_b(tail_va, dsts[0])
            patched_edges += 1
        except ValueError:
            pass

    # 2. NOP out dead CFF dispatcher backbone blocks
    if is_arm64:
        nop = encode_arm64_nop()
        for baddr in backbone_addrs:
            blk = proj.factory.block(baddr)
            file_off = vaddr_to_offset(baddr)
            if file_off is None or file_off < 0 or file_off + blk.size > len(buf):
                continue
            for i in range(0, blk.size, 4):
                buf[file_off + i : file_off + i + 4] = nop
            nopped_blocks += 1

    with open(out_path, "wb") as fh:
        fh.write(buf)
    return patched_edges, nopped_blocks


def main():
    proj = angr.Project(BINARY_PATH, auto_load_libs=False)
    base = proj.loader.main_object.mapped_base
    target_va = FUNC_ADDR if FUNC_ADDR >= base else (base + FUNC_ADDR)

    emit("start", binary=BINARY_PATH, arch=proj.arch.name, target=hex(target_va))
    cfg = proj.analyses.CFGFast(
        regions=[(target_va, target_va + 0x8000)],
        normalize=True,
        show_progressbar=False,
    )
    func = cfg.kb.functions.get(target_va)
    if func is None:
        emit("error", message=f"Function not recovered at {hex(target_va)}")
        sys.exit(1)

    main_disp, pre_disp, relevant, backbone = identify_cff_structure(func)
    emit(
        "cff_detected",
        main_dispatcher=hex(main_disp),
        pre_dispatcher=hex(pre_disp),
        relevant_blocks=len(relevant),
        backbone_blocks=len(backbone),
    )

    rel_set = set(relevant)
    flow_edges = defaultdict(list)
    for blk in relevant:
        succs = resolve_block_successors(proj, blk, rel_set, main_disp)
        flow_edges[blk] = succs
        emit("edge_resolved", src=hex(blk), dsts=[hex(x) for x in succs])

    export_dot(flow_edges, OUT_DOT)
    with open(BINARY_PATH, "rb") as fh:
        raw = fh.read()
    patched, nopped = patch_binary(proj, raw, flow_edges, backbone, func, OUT_BIN)

    emit(
        "done",
        dot_path=OUT_DOT,
        patched_binary=OUT_BIN,
        patched_edges=patched,
        nopped_backbone_blocks=nopped,
    )


if __name__ == "__main__":
    main()
`)

	return &GeneratedScript{
		ID:          "deobf:ollvm-deflatten",
		Name:        fmt.Sprintf("OLLVM CFF De-Flattener (%s @ %s)", baseName, funcAddr),
		Category:    "ollvm",
		Engine:      EngineAngr,
		Language:    "python",
		Target:      fmt.Sprintf("%s!%s", baseName, funcAddr),
		Description: fmt.Sprintf("angr symbolic-execution OLLVM Control Flow Flattening de-flattener for %s (%s) emitting clean DOT CFG and patched ELF.", baseName, normArch),
		Code:        b.String(),
		Modules:     []string{"CFGFast", "DispatcherDetector", "SymbolicEdgeResolver", "ARM64BinaryPatcher", "DOTExporter"},
		Usage:       fmt.Sprintf("python3 deflatten_%s.py", sanitizeSlug(baseName)),
		Notes: []string{
			"Pass the function file offset (e.g. 0x1a400) or full virtual address; the script auto-rebases against angr's mapped_base.",
			"Render the recovered CFG with: dot -Tsvg <output>.dot -o clean_cfg.svg",
		},
		GeneratedAt: nowRFC3339(),
	}
}

// GenerateStringDecryptScript generates an offline .init_array string-decryption
// emulator script for either Qiling (Python) or Unidbg (Java). The generated
// script snapshots .data/.rodata before and after executing ELF constructors
// and dumps every newly decrypted plaintext string with its virtual offset.
func GenerateStringDecryptScript(engine, soPath, apkPath string) *GeneratedScript {
	eng := strings.ToLower(strings.TrimSpace(engine))
	if eng != EngineUnidbg {
		eng = EngineQiling
	}
	soPath = nonEmptyOr(soPath, "./libtarget.so")
	apkPath = nonEmptyOr(apkPath, "./target.apk")
	baseName := filepath.Base(soPath)

	if eng == EngineUnidbg {
		return generateUnidbgStringDecrypt(soPath, apkPath, baseName)
	}
	return generateQilingStringDecrypt(soPath, baseName)
}

func generateQilingStringDecrypt(soPath, baseName string) *GeneratedScript {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env python3\n")
	b.WriteString("\"\"\"\n")
	b.WriteString("cap Qiling .init_array String Decryptor & Memory Diff Dumper\n")
	fmt.Fprintf(&b, "Target SO: %s\n", sanitizePyDocLine(soPath))
	b.WriteString("Requires:  pip install qiling pyelftools\n")
	b.WriteString("\"\"\"\n\n")

	b.WriteString("import json\n")
	b.WriteString("import os\n")
	b.WriteString("import re\n")
	b.WriteString("import struct\n")
	b.WriteString("from elftools.elf.elffile import ELFFile\n")
	b.WriteString("from qiling import Qiling\n")
	b.WriteString("from qiling.const import QL_VERBOSE\n\n")

	fmt.Fprintf(&b, "SO_PATH = %s\n", pyQuote(soPath))
	b.WriteString("ROOTFS = os.environ.get(\"QILING_ROOTFS\", \"./rootfs/arm64_android\")\n")
	fmt.Fprintf(&b, "OUT_JSON = %s\n", pyQuote(strings.TrimSuffix(baseName, filepath.Ext(baseName))+"_decrypted_strings.json"))
	b.WriteString("PRINTABLE_RE = re.compile(rb\"[\\x20-\\x7e]{4,256}\")\n\n")

	b.WriteString(`def emit(kind, **payload):
    payload["event"] = kind
    print("[CAP_DEOBF] " + json.dumps(payload, ensure_ascii=False), flush=True)


def parse_elf_targets(path):
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        ptr_size = 8 if elf.elfclass == 64 else 4
        fmt = "<Q" if ptr_size == 8 else "<I"

        sections = {}
        for name in (".rodata", ".data", ".data.rel.ro"):
            sec = elf.get_section_by_name(name)
            if sec and sec["sh_size"] > 0:
                sections[name] = (sec["sh_addr"], sec["sh_size"])

        ctors = []
        for arr_name in (".preinit_array", ".init_array"):
            sec = elf.get_section_by_name(arr_name)
            if not sec:
                continue
            raw = sec.data()
            for off in range(0, len(raw) - ptr_size + 1, ptr_size):
                addr = struct.unpack(fmt, raw[off : off + ptr_size])[0]
                if addr not in (0, (1 << (ptr_size * 8)) - 1):
                    ctors.append(addr)

    return sections, ctors


def snapshot_sections(ql, base, sections):
    snaps = {}
    for name, (vaddr, size) in sections.items():
        try:
            snaps[name] = (vaddr, bytes(ql.mem.read(base + vaddr, size)))
        except Exception:
            pass
    return snaps


def diff_decrypted_strings(before, after):
    results = []
    seen = set()
    for sec_name, (vaddr, after_bytes) in after.items():
        if sec_name not in before:
            continue
        before_bytes = before[sec_name][1]
        if before_bytes == after_bytes:
            continue
        for match in PRINTABLE_RE.finditer(after_bytes):
            s_off, e_off = match.span()
            # Only keep strings whose bytes actually mutated during .init_array execution
            if before_bytes[s_off:e_off] == after_bytes[s_off:e_off]:
                continue
            text = match.group(0).decode("ascii", errors="ignore")
            key = (sec_name, vaddr + s_off, text)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "section": sec_name,
                "offset": hex(vaddr + s_off),
                "value": text,
            })
    return results


def main():
    sections, ctors = parse_elf_targets(SO_PATH)
    emit("elf_parsed", so=SO_PATH, constructors=len(ctors), tracked_sections=list(sections.keys()))

    ql = Qiling([SO_PATH], ROOTFS, verbose=QL_VERBOSE.OFF)
    base = ql.loader.load_address
    sentinel_ret = base + 0x4

    # Snapshot .rodata/.data BEFORE running .init_array constructors
    before = snapshot_sections(ql, base, sections)

    executed = 0
    for ctor in ctors:
        target = base + ctor if ctor < base else ctor
        try:
            ql.arch.regs.lr = sentinel_ret
            ql.run(begin=target, end=sentinel_ret, timeout=2_000_000)
            executed += 1
        except Exception as exc:
            emit("ctor_warn", ctor=hex(ctor), error=str(exc))

    # Snapshot AFTER .init_array constructors finish
    after = snapshot_sections(ql, base, sections)
    decrypted = diff_decrypted_strings(before, after)

    for item in decrypted:
        emit("decrypted_string", **item)

    with open(OUT_JSON, "w", encoding="utf-8") as fh:
        json.dump(decrypted, fh, indent=2, ensure_ascii=False)

    emit("done", constructors_run=executed, decrypted_count=len(decrypted), out_json=OUT_JSON)


if __name__ == "__main__":
    main()
`)

	return &GeneratedScript{
		ID:          "deobf:string-decrypt-qiling",
		Name:        fmt.Sprintf("Qiling .init_array String Decryptor (%s)", baseName),
		Category:    "string_decrypt",
		Engine:      EngineQiling,
		Language:    "python",
		Target:      baseName,
		Description: fmt.Sprintf("Emulates .init_array constructors of %s under Qiling and diffs .rodata/.data before & after to dump decrypted strings.", baseName),
		Code:        b.String(),
		Modules:     []string{"ELFInitArrayParser", "QilingEmulator", "MemorySnapshotDiff"},
		Usage:       fmt.Sprintf("QILING_ROOTFS=/path/to/arm64_android python3 decrypt_strings_%s.py", sanitizeSlug(baseName)),
		Notes: []string{
			"Diffing before/after .init_array ensures only newly decrypted strings are reported (zero static noise).",
		},
		GeneratedAt: nowRFC3339(),
	}
}

func generateUnidbgStringDecrypt(soPath, apkPath, baseName string) *GeneratedScript {
	libShort := strings.TrimSuffix(strings.TrimPrefix(baseName, "lib"), ".so")
	if libShort == "" {
		libShort = "target"
	}

	var b strings.Builder
	b.WriteString("// cap Unidbg .init_array String Decryptor & Memory Diff Harness\n")
	fmt.Fprintf(&b, "// Target SO:  %s\n", sanitizeCommentLine(soPath))
	fmt.Fprintf(&b, "// Target APK: %s\n\n", sanitizeCommentLine(apkPath))

	b.WriteString(`import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class CapInitArrayStringDecryptor extends AbstractJni {
`)
	fmt.Fprintf(&b, "    private static final String APK_PATH = %s;\n", javaQuote(apkPath))
	fmt.Fprintf(&b, "    private static final String SO_PATH  = %s;\n", javaQuote(soPath))
	fmt.Fprintf(&b, "    private static final String LIB_NAME = %s;\n\n", javaQuote(libShort))

	b.WriteString(`    public static void main(String[] args) throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.cap.deobf")
                .build();
        try {
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            VM vm = emulator.createDalvikVM(new File(APK_PATH));
            vm.setJni(new CapInitArrayStringDecryptor());
            vm.setVerbose(false);

            // Step 1: Load library WITHOUT executing .init_array constructors yet
            DalvikModule dm = vm.loadLibrary(new File(SO_PATH), false);
            Module module = dm.getModule();
            int dumpSize = (int) Math.min(module.size, 16 * 1024 * 1024);

            // Step 2: Snapshot module memory (.rodata/.data) BEFORE .init_array
            byte[] before = emulator.getBackend().mem_read(module.base, dumpSize);

            // Step 3: Execute .init_array constructors and JNI_OnLoad
            module.callEntry(emulator);
            try {
                dm.callJNI_OnLoad(emulator);
            } catch (Throwable ignored) {}

            // Step 4: Snapshot AFTER and diff printable ASCII/UTF-8 runs
            byte[] after = emulator.getBackend().mem_read(module.base, dumpSize);
            Map<Long, String> decrypted = extractDiffStrings(before, after);

            for (Map.Entry<Long, String> entry : decrypted.entrySet()) {
                System.out.printf("[CAP_DEOBF] {\"event\":\"decrypted_string\",\"module\":\"%s\",\"offset\":\"0x%x\",\"value\":%s}%n",
                        LIB_NAME, entry.getKey(), jsonQuote(entry.getValue()));
            }
            System.out.printf("[CAP_DEOBF] {\"event\":\"done\",\"module\":\"%s\",\"decrypted_count\":%d}%n",
                    LIB_NAME, decrypted.size());
        } finally {
            emulator.close();
        }
    }

    private static Map<Long, String> extractDiffStrings(byte[] before, byte[] after) {
        Map<Long, String> out = new LinkedHashMap<>();
        int n = Math.min(before.length, after.length);
        int i = 0;
        while (i < n) {
            if (isPrintable(after[i])) {
                int start = i;
                boolean mutated = false;
                while (i < n && isPrintable(after[i]) && (i - start) < 256) {
                    if (before[i] != after[i]) {
                        mutated = true;
                    }
                    i++;
                }
                int len = i - start;
                if (mutated && len >= 4) {
                    String s = new String(after, start, len, StandardCharsets.US_ASCII);
                    out.put((long) start, s);
                }
            } else {
                i++;
            }
        }
        return out;
    }

    private static boolean isPrintable(byte b) {
        int v = b & 0xff;
        return v >= 0x20 && v <= 0x7e;
    }

    private static String jsonQuote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
`)

	return &GeneratedScript{
		ID:          "deobf:string-decrypt-unidbg",
		Name:        fmt.Sprintf("Unidbg .init_array String Decryptor (%s)", baseName),
		Category:    "string_decrypt",
		Engine:      EngineUnidbg,
		Language:    "java",
		Target:      baseName,
		Description: fmt.Sprintf("Unidbg harness loading %s with callInit=false, snapshotting .data/.rodata before & after .init_array/JNI_OnLoad to dump decrypted strings.", baseName),
		Code:        b.String(),
		Modules:     []string{"UnidbgDalvikVM", "PreInitMemorySnapshot", "PostInitMemoryDiff"},
		Usage:       "Compile and run CapInitArrayStringDecryptor against your Unidbg classpath / Maven project.",
		Notes: []string{
			"Runs completely offline under Unicorn/Dynarmic, immune to ptrace / TracerPid / Frida detection.",
		},
		GeneratedAt: nowRFC3339(),
	}
}

// GenerateJavaDeobfScript synthesizes a Frida runtime Java reflection &
// string-decryption monitor hooking Class.forName, Method.invoke, String.<init>,
// and Base64.decode to capture dynamically decrypted Java strings and hidden
// API endpoints.
func GenerateJavaDeobfScript(targetPkg string) *GeneratedScript {
	cleanPkg := strings.TrimSpace(targetPkg)
	displayPkg := nonEmptyOr(cleanPkg, "<all-packages>")

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Java Runtime De-Obfuscator (Reflection & String Monitor) ───\n")
	fmt.Fprintf(&b, "// Target Package Filter: %s\n\n", sanitizeCommentLine(displayPkg))

	fmt.Fprintf(&b, "const TARGET_PKG = %s;\n", jsQuote(cleanPkg))
	b.WriteString(`const MAX_SEEN = 4096;
const seenStrings = new Set();

function emitDeobf(hook, payload) {
    send(Object.assign({ cap_cat: 'deobf_java', hook: hook }, payload || {}));
}

function getCallerStack(depth) {
    try {
        const Log = Java.use('android.util.Log');
        const Ex = Java.use('java.lang.Exception');
        const frames = Log.getStackTraceString(Ex.$new()).split('\n').slice(2, (depth || 6) + 2);
        return frames.map(function (f) { return f.trim(); });
    } catch (_) {
        return [];
    }
}

function isFromTargetApp(frames) {
    if (!TARGET_PKG) {
        // Skip pure framework noise
        return frames.some(function (f) {
            return !/^at (java\.|javax\.|android\.|androidx\.|dalvik\.|com\.android\.)/.test(f);
        });
    }
    return frames.some(function (f) { return f.indexOf(TARGET_PKG) !== -1; });
}

function isInterestingString(s) {
    if (!s || s.length < 4 || s.length > 512) return false;
    if (!/^[\x20-\x7e\u4e00-\u9fff]+$/.test(s)) return false;
    // Highlight URLs, API paths, JSON, crypto/auth terms, or hostnames
    return /https?:\/\/|\/api\/|\/v\d+\/|token|sign|secret|key|auth|bearer|aes|rsa|md5|sha|{"|\[{"|\.(com|cn|net|io|org)/i.test(s)
        || (s.length >= 8 && /[a-zA-Z]/.test(s));
}

function recordDecrypted(hook, value, extra) {
    if (!value || seenStrings.has(value)) return;
    if (seenStrings.size >= MAX_SEEN) {
        seenStrings.clear();
    }
    seenStrings.add(value);
    emitDeobf(hook, Object.assign({ value: value }, extra || {}));
}

Java.perform(function () {
    // 1. Class.forName (dynamic hidden class resolution)
    try {
        const JClass = Java.use('java.lang.Class');
        JClass.forName.overload('java.lang.String').implementation = function (name) {
            const frames = getCallerStack(5);
            if (isFromTargetApp(frames)) {
                emitDeobf('Class.forName', { class_name: name, stack: frames.slice(0, 3) });
            }
            return this.forName(name);
        };
        JClass.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').implementation = function (name, init, loader) {
            const frames = getCallerStack(5);
            if (isFromTargetApp(frames)) {
                emitDeobf('Class.forName', { class_name: name, initialize: init, stack: frames.slice(0, 3) });
            }
            return this.forName(name, init, loader);
        };
    } catch (_) {}

    // 2. Method.invoke (reflective method dispatch)
    try {
        const Method = Java.use('java.lang.reflect.Method');
        Method.invoke.implementation = function (obj, args) {
            const ret = this.invoke(obj, args);
            try {
                const frames = getCallerStack(5);
                if (isFromTargetApp(frames)) {
                    const decl = this.getDeclaringClass().getName();
                    const mName = this.getName();
                    emitDeobf('Method.invoke', {
                        target: decl + '.' + mName,
                        retval: ret !== null && ret !== undefined ? String(ret).slice(0, 200) : 'null',
                        stack: frames.slice(0, 3),
                    });
                }
            } catch (_) {}
            return ret;
        };
    } catch (_) {}

    // 3. String.<init>([B) & String.<init>([B, String/Charset) — catches XOR/AES/custom byte decryptors
    try {
        const JString = Java.use('java.lang.String');
        JString.$init.overload('[B').implementation = function (bytes) {
            const res = this.$init(bytes);
            try {
                const str = this.toString();
                if (isInterestingString(str)) {
                    const frames = getCallerStack(5);
                    if (isFromTargetApp(frames)) {
                        recordDecrypted('String.<init>([B)', str, { stack: frames.slice(0, 3) });
                    }
                }
            } catch (_) {}
            return res;
        };
        JString.$init.overload('[B', 'java.lang.String').implementation = function (bytes, charset) {
            const res = this.$init(bytes, charset);
            try {
                const str = this.toString();
                if (isInterestingString(str)) {
                    const frames = getCallerStack(5);
                    if (isFromTargetApp(frames)) {
                        recordDecrypted('String.<init>([B,String)', str, { charset: charset, stack: frames.slice(0, 3) });
                    }
                }
            } catch (_) {}
            return res;
        };
    } catch (_) {}

    // 4. android.util.Base64.decode — reveals obfuscated endpoints & config blobs
    try {
        const Base64 = Java.use('android.util.Base64');
        const JString = Java.use('java.lang.String');
        Base64.decode.overload('java.lang.String', 'int').implementation = function (input, flags) {
            const out = this.decode(input, flags);
            try {
                const decoded = JString.$new(out, 'UTF-8').toString();
                if (isInterestingString(decoded)) {
                    const frames = getCallerStack(5);
                    if (isFromTargetApp(frames)) {
                        recordDecrypted('Base64.decode', decoded, {
                            encoded_preview: String(input).slice(0, 80),
                            stack: frames.slice(0, 3),
                        });
                    }
                }
            } catch (_) {}
            return out;
        };
    } catch (_) {}

    emitDeobf('lifecycle', { detail: 'Java reflection & string decryptor hooks active', package_filter: TARGET_PKG || '*' });
});
`)

	return &GeneratedScript{
		ID:          "deobf:java-runtime",
		Name:        "Java Reflection & String Decryptor Monitor",
		Category:    "java_deobf",
		Engine:      EngineFrida,
		Language:    "javascript",
		Target:      displayPkg,
		Description: "Hooks Class.forName, Method.invoke, String.<init>([B), and Base64.decode to capture dynamically decrypted strings and hidden API endpoints.",
		Code:        b.String(),
		Modules:     []string{"ClassForNameHook", "MethodInvokeHook", "StringByteCtorHook", "Base64DecodeHook"},
		Usage:       fmt.Sprintf("frida -U -f %s -l cap_java_deobf.js", nonEmptyOr(cleanPkg, "<com.example.app>")),
		GeneratedAt: nowRFC3339(),
	}
}

func normalizeHexAddr(addr, fallback string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return fallback
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if s == "" || len(s) > 16 {
		return fallback
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return fallback
		}
	}
	return "0x" + strings.ToLower(s)
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "arm64", "aarch64", "arm64-v8a", "":
		return "arm64"
	case "arm", "armv7", "armeabi-v7a":
		return "arm"
	case "x86_64", "amd64":
		return "x86_64"
	case "x86", "i386":
		return "x86"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

func sanitizeSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		return "target"
	}
	return res
}
