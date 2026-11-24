package deobf

import (
	"fmt"
	"strings"
)

// DefaultStealthOptions returns a balanced default Anti-Debug / Anti-Frida
// configuration suitable for most hardened Android apps.
func DefaultStealthOptions() StealthOptions {
	return StealthOptions{
		BypassTracerPidAndProcFS: true,
		BypassPtraceAndSignals:   true,
		PatchInlineSVC:           false,
		BypassTimingAndInotify:   true,
		BypassJavaDebugChecks:    true,
	}
}

// StealthOptionsFromReport derives an automatically tailored StealthOptions
// profile from a ProtectionReport.
func StealthOptionsFromReport(report *ProtectionReport) StealthOptions {
	opts := DefaultStealthOptions()
	if report == nil {
		return opts
	}

	opts.BypassTimingAndInotify = false
	opts.PatchInlineSVC = false

	for _, ad := range report.AntiDebugFindings {
		switch ad.Kind {
		case AntiDebugTracerPid, AntiDebugProcMaps, AntiDebugFridaDetect:
			opts.BypassTracerPidAndProcFS = true
		case AntiDebugPtrace, AntiDebugWatchdogThread:
			opts.BypassPtraceAndSignals = true
		case AntiDebugInlineSVC:
			opts.PatchInlineSVC = true
		case AntiDebugTimingCheck, AntiDebugInotify:
			opts.BypassTimingAndInotify = true
		case AntiDebugJavaDebug, AntiDebugRootDetect:
			opts.BypassJavaDebugChecks = true
		}
	}

	// Pick the SO with the highest inline SVC / anti-debug density as default TargetSO.
	bestSO := ""
	bestWeight := -1
	for _, so := range report.SOAudits {
		w := so.InlineSVCCount*10 + so.IndirectBranchCount + len(so.SuspiciousSections)*5
		if w > bestWeight {
			bestWeight = w
			bestSO = so.Name
		}
	}
	if bestSO != "" {
		opts.TargetSO = bestSO
	}
	return opts
}

// GenerateStealthScript synthesizes a composable, production-grade Frida
// Anti-Debug & Anti-Frida stealth script tailored to opts and an optional
// ProtectionReport.
func GenerateStealthScript(opts StealthOptions, report *ProtectionReport) *GeneratedScript {
	anySet := opts.BypassTracerPidAndProcFS || opts.BypassPtraceAndSignals ||
		opts.PatchInlineSVC || opts.BypassTimingAndInotify || opts.BypassJavaDebugChecks

	if report != nil {
		auto := StealthOptionsFromReport(report)
		if !anySet {
			auto.TargetPackage = opts.TargetPackage
			if opts.TargetSO != "" {
				auto.TargetSO = opts.TargetSO
			}
			auto.WatchdogBlockOffsets = opts.WatchdogBlockOffsets
			auto.CustomHideTokens = opts.CustomHideTokens
			auto.DryRunSVCPatch = opts.DryRunSVCPatch
			opts = auto
		} else if opts.TargetSO == "" && auto.TargetSO != "" {
			opts.TargetSO = auto.TargetSO
		}
	} else if !anySet {
		def := DefaultStealthOptions()
		def.TargetPackage = opts.TargetPackage
		def.TargetSO = opts.TargetSO
		def.WatchdogBlockOffsets = opts.WatchdogBlockOffsets
		def.CustomHideTokens = opts.CustomHideTokens
		def.DryRunSVCPatch = opts.DryRunSVCPatch
		opts = def
	}

	var enabledModules []string
	if opts.BypassTracerPidAndProcFS {
		enabledModules = append(enabledModules, "BypassTracerPidAndProcFS")
	}
	if opts.BypassPtraceAndSignals {
		enabledModules = append(enabledModules, "BypassPtraceAndSignals")
	}
	if opts.PatchInlineSVC {
		enabledModules = append(enabledModules, "PatchInlineSVC")
	}
	if opts.BypassTimingAndInotify {
		enabledModules = append(enabledModules, "BypassTimingAndInotify")
	}
	if opts.BypassJavaDebugChecks {
		enabledModules = append(enabledModules, "BypassJavaDebugChecks")
	}

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap Anti-Debug & Anti-Frida Stealth Suite ───────────────────────\n")
	if opts.TargetPackage != "" {
		fmt.Fprintf(&b, "// Target Package: %s\n", sanitizeCommentLine(opts.TargetPackage))
	}
	if opts.TargetSO != "" {
		fmt.Fprintf(&b, "// Target Native:  %s\n", sanitizeCommentLine(opts.TargetSO))
	}
	fmt.Fprintf(&b, "// Active Modules: %s\n", sanitizeCommentLine(strings.Join(enabledModules, ", ")))
	if report != nil {
		fmt.Fprintf(&b, "// Audit Context:  %s\n", sanitizeCommentLine(report.Summary))
	}
	b.WriteString("\n")

	// Shared configuration & helper utilities
	hideTokens := []string{
		"frida", "gum-js-loop", "gmain", "gdbus", "linjector", "libfrida",
		"re.frida.server", "frida-agent", "frida-gadget", "27042",
		"magisk", "zygisk", "lsposed", "xposed", "riru", "shamiko",
	}
	for _, tok := range opts.CustomHideTokens {
		t := strings.TrimSpace(tok)
		if t != "" {
			hideTokens = append(hideTokens, t)
		}
	}

	fmt.Fprintf(&b, "const CONFIG = {\n")
	fmt.Fprintf(&b, "    targetPackage: %s,\n", jsQuote(opts.TargetPackage))
	fmt.Fprintf(&b, "    targetSO: %s,\n", jsQuote(opts.TargetSO))
	fmt.Fprintf(&b, "    dryRunSVCPatch: %s,\n", boolJS(opts.DryRunSVCPatch))
	fmt.Fprintf(&b, "    watchdogBlockOffsets: [%s],\n", joinJSQuoted(opts.WatchdogBlockOffsets))
	fmt.Fprintf(&b, "    hideTokens: [%s],\n", joinJSQuoted(hideTokens))
	fmt.Fprintf(&b, "};\n\n")

	b.WriteString(`function emitStealth(moduleName, hook, detail) {
    send(Object.assign({
        cap_cat: 'deobf_stealth',
        module: moduleName,
        hook: hook,
    }, detail || {}));
}

function formatBacktrace(ctx, limit) {
    try {
        return Thread.backtrace(ctx, Backtracer.ACCURATE)
            .slice(0, limit || 10)
            .map(function (addr) {
                const mod = Process.findModuleByAddress(addr);
                const sym = DebugSymbol.fromAddress(addr);
                if (mod) {
                    const off = addr.sub(mod.base);
                    return mod.name + '+' + off + (sym && sym.name ? ' (' + sym.name + ')' : '');
                }
                return sym ? sym.toString() : addr.toString();
            });
    } catch (_) {
        return [];
    }
}

function containsHiddenToken(str) {
    if (!str) return false;
    const low = String(str).toLowerCase();
    for (let i = 0; i < CONFIG.hideTokens.length; i++) {
        if (low.indexOf(CONFIG.hideTokens[i].toLowerCase()) !== -1) {
            return CONFIG.hideTokens[i];
        }
    }
    return false;
}

function findLibcExport(name) {
    return Module.findExportByName('libc.so', name) || Module.findExportByName(null, name);
}

// Encode UTF-8 string into at most maxBytes raw bytes (NO trailing NUL) so
// fixed-size read() and readlink()/readlinkat() buffers can never overflow by 1 byte.
function encodeUtf8Bytes(str, maxBytes) {
    const out = [];
    for (let i = 0; i < str.length && out.length < maxBytes; i++) {
        const code = str.charCodeAt(i);
        if (code < 0x80) {
            out.push(code);
        } else if (code < 0x800) {
            if (out.length + 2 > maxBytes) break;
            out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
            const next = str.charCodeAt(i + 1);
            if (next >= 0xdc00 && next <= 0xdfff) {
                if (out.length + 4 > maxBytes) break;
                const cp = ((code - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
                out.push(
                    0xf0 | (cp >> 18),
                    0x80 | ((cp >> 12) & 0x3f),
                    0x80 | ((cp >> 6) & 0x3f),
                    0x80 | (cp & 0x3f)
                );
                i++;
            }
        } else {
            if (out.length + 3 > maxBytes) break;
            out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
    }
    return out;
}

function writeRawBytesClamped(bufPtr, str, maxBytes, padByte) {
    if (maxBytes <= 0) return 0;
    const bytes = encodeUtf8Bytes(str, maxBytes);
    if (padByte !== undefined && padByte !== null) {
        while (bytes.length < maxBytes) {
            bytes.push(padByte);
        }
    }
    if (bytes.length > 0) {
        bufPtr.writeByteArray(bytes);
    }
    return bytes.length;
}
`)

	// Module 1: BypassTracerPidAndProcFS
	if opts.BypassTracerPidAndProcFS {
		b.WriteString(`
// ─── Module 1: BypassTracerPidAndProcFS ──────────────────────────────
(function installProcFSCloak() {
    const trackedFds = new Map(); // fd -> 'status' | 'maps' | 'net_tcp'
    const trackedFiles = new Map(); // FILE* str -> 'status' | 'maps' | 'net_tcp'

    function classifyProcPath(path) {
        if (!path) return null;
        const p = String(path);
        if (/^\/proc\/(self|\d+)(\/task\/\d+)?\/status$/.test(p)) return 'status';
        if (/^\/proc\/(self|\d+)\/(s?maps|wchan)$/.test(p)) return 'maps';
        if (/^\/proc\/net\/tcp6?$/.test(p)) return 'net_tcp';
        return null;
    }

    function sanitizeStatusInPlace(bufPtr, byteLen) {
        if (byteLen <= 0 || byteLen > 131072) return false;
        let text = '';
        try {
            text = bufPtr.readUtf8String(byteLen);
        } catch (_) {
            return false;
        }
        if (!text) return false;
        let modified = false;
        const patched = text
            .replace(/TracerPid:\s*[1-9]\d*/g, function (m) {
                modified = true;
                const pad = m.length - 'TracerPid:\t0'.length;
                return 'TracerPid:\t0' + (pad > 0 ? ' '.repeat(pad) : '');
            })
            .replace(/State:\s*t\s*\(tracing stop\)/gi, function (m) {
                modified = true;
                const rep = 'State:\tS (sleeping)';
                const pad = m.length - rep.length;
                return pad >= 0 ? rep + ' '.repeat(pad) : rep.slice(0, m.length);
            });
        if (modified) {
            // Write exact byteLen raw bytes (no trailing NUL overflow)
            writeRawBytesClamped(bufPtr, patched, byteLen, 0x20);
            emitStealth('BypassTracerPidAndProcFS', 'proc_status', { action: 'spoofed TracerPid=0 & State=S' });
        }
        return modified;
    }

    function sanitizeMapsInPlace(bufPtr, byteLen) {
        if (byteLen <= 0 || byteLen > 262144) return false;
        let text = '';
        try {
            text = bufPtr.readUtf8String(byteLen);
        } catch (_) {
            return false;
        }
        if (!text) return false;
        const lines = text.split('\n');
        let hitCount = 0;
        const cleaned = lines.map(function (line) {
            if (containsHiddenToken(line)) {
                hitCount++;
                // Preserve exact line byte length with harmless anonymous rw-p padding
                const fake = '00000000-00000000 ---p 00000000 00:00 0';
                if (line.length <= fake.length) {
                    return ' '.repeat(line.length);
                }
                return fake + ' '.repeat(line.length - fake.length);
            }
            return line;
        });
        if (hitCount > 0) {
            // Write exact byteLen raw bytes (no trailing NUL overflow)
            writeRawBytesClamped(bufPtr, cleaned.join('\n'), byteLen, 0x20);
            emitStealth('BypassTracerPidAndProcFS', 'proc_maps', { filtered_lines: hitCount });
        }
        return hitCount > 0;
    }

    // openat(dirfd, pathname, flags, mode) & open(pathname, flags, mode)
    ['openat', 'open', '__openat'].forEach(function (fn) {
        const addr = findLibcExport(fn);
        if (!addr) return;
        const pathArgIdx = fn.indexOf('openat') !== -1 ? 1 : 0;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.kind = null;
                this.path = '';
                try {
                    if (!args[pathArgIdx].isNull()) {
                        this.path = args[pathArgIdx].readCString();
                        this.kind = classifyProcPath(this.path);
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (this.kind && fd >= 0) {
                    trackedFds.set(fd, this.kind);
                    emitStealth('BypassTracerPidAndProcFS', fn, { path: this.path, fd: fd, kind: this.kind });
                }
            }
        });
    });

    // close(fd)
    const closeAddr = findLibcExport('close');
    if (closeAddr) {
        Interceptor.attach(closeAddr, {
            onEnter(args) {
                trackedFds.delete(args[0].toInt32());
            }
        });
    }

    // read(fd, buf, count)
    const readAddr = findLibcExport('read');
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.kind = trackedFds.get(this.fd) || null;
            },
            onLeave(retval) {
                const n = retval.toInt32();
                if (!this.kind || n <= 0) return;
                if (this.kind === 'status') {
                    sanitizeStatusInPlace(this.buf, n);
                } else if (this.kind === 'maps' || this.kind === 'net_tcp') {
                    sanitizeMapsInPlace(this.buf, n);
                }
            }
        });
    }

    // fopen(path, mode) & fgets(s, size, stream)
    const fopenAddr = findLibcExport('fopen');
    if (fopenAddr) {
        Interceptor.attach(fopenAddr, {
            onEnter(args) {
                this.kind = null;
                this.path = '';
                try {
                    if (!args[0].isNull()) {
                        this.path = args[0].readCString();
                        this.kind = classifyProcPath(this.path);
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                if (this.kind && !retval.isNull()) {
                    trackedFiles.set(retval.toString(), this.kind);
                }
            }
        });
    }

    const fcloseAddr = findLibcExport('fclose');
    if (fcloseAddr) {
        Interceptor.attach(fcloseAddr, {
            onEnter(args) {
                if (!args[0].isNull()) trackedFiles.delete(args[0].toString());
            }
        });
    }

    const fgetsAddr = findLibcExport('fgets');
    if (fgetsAddr) {
        Interceptor.attach(fgetsAddr, {
            onEnter(args) {
                this.buf = args[0];
                this.size = args[1].toInt32();
                this.kind = args[2].isNull() ? null : (trackedFiles.get(args[2].toString()) || null);
            },
            onLeave(retval) {
                if (!this.kind || retval.isNull()) return;
                const line = retval.readCString();
                if (!line) return;
                const byteLen = encodeUtf8Bytes(line, this.size > 0 ? this.size - 1 : line.length).length;
                if (byteLen <= 0) return;
                if (this.kind === 'status') {
                    sanitizeStatusInPlace(retval, byteLen);
                } else if (this.kind === 'maps' || this.kind === 'net_tcp') {
                    sanitizeMapsInPlace(retval, byteLen);
                }
            }
        });
    }

    // readlinkat(dirfd, pathname, buf, bufsiz) & readlink(pathname, buf, bufsiz)
    ['readlinkat', 'readlink'].forEach(function (fn) {
        const addr = findLibcExport(fn);
        if (!addr) return;
        const bufIdx = fn === 'readlinkat' ? 2 : 1;
        Interceptor.attach(addr, {
            onEnter(args) {
                this.buf = args[bufIdx];
                this.bufsiz = args[bufIdx + 1].toInt32();
            },
            onLeave(retval) {
                const n = retval.toInt32();
                if (n <= 0 || this.buf.isNull() || this.bufsiz <= 0) return;
                try {
                    const target = this.buf.readUtf8String(n);
                    const tok = containsHiddenToken(target);
                    if (tok) {
                        const spoof = '/system/lib64/libc.so';
                        const maxWrite = Math.min(spoof.length, this.bufsiz);
                        const written = writeRawBytesClamped(this.buf, spoof, maxWrite);
                        retval.replace(ptr(written));
                        emitStealth('BypassTracerPidAndProcFS', fn, { blocked: target, token: tok, bytes: written });
                    }
                } catch (_) {}
            }
        });
    });

    // strstr fallback cloak for Frida / Magisk probes
    const strstrAddr = findLibcExport('strstr');
    if (strstrAddr) {
        Interceptor.attach(strstrAddr, {
            onEnter(args) {
                this.hide = false;
                try {
                    if (!args[1].isNull()) {
                        const needle = args[1].readCString();
                        const tok = containsHiddenToken(needle);
                        if (tok) {
                            this.hide = true;
                            this.tok = tok;
                        }
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                if (this.hide && !retval.isNull()) {
                    retval.replace(ptr(0));
                    emitStealth('BypassTracerPidAndProcFS', 'strstr', { blocked_token: this.tok });
                }
            }
        });
    }
})();
`)
	}

	// Module 2: BypassPtraceAndSignals
	if opts.BypassPtraceAndSignals {
		b.WriteString(`
// ─── Module 2: BypassPtraceAndSignals ────────────────────────────────
(function installPtraceAndSignalBypass() {
    const selfPid = Process.id;

    // 1. ptrace(PTRACE_TRACEME, ...) -> return 0
    const ptraceAddr = findLibcExport('ptrace');
    if (ptraceAddr) {
        Interceptor.attach(ptraceAddr, {
            onEnter(args) {
                this.req = args[0].toInt32();
                this.bt = formatBacktrace(this.context, 8);
            },
            onLeave(retval) {
                if (this.req === 0) { // PTRACE_TRACEME
                    retval.replace(ptr(0));
                    emitStealth('BypassPtraceAndSignals', 'ptrace', {
                        request: 'PTRACE_TRACEME',
                        spoofed_retval: 0,
                        backtrace: this.bt,
                    });
                }
            }
        });
    }

    // 2. kill / tgkill / abort / exit / _exit interception with native backtrace
    const killAddr = findLibcExport('kill');
    if (killAddr) {
        Interceptor.attach(killAddr, {
            onEnter(args) {
                const pid = args[0].toInt32();
                const sig = args[1].toInt32();
                if (pid === selfPid && (sig === 9 || sig === 6 || sig === 5 || sig === 19 || sig === 15)) {
                    emitStealth('BypassPtraceAndSignals', 'kill', {
                        pid: pid,
                        sig: sig,
                        action: 'neutralized self-kill (sig -> 0)',
                        backtrace: formatBacktrace(this.context, 10),
                    });
                    args[1] = ptr(0); // signal 0 = harmless existence check
                }
            }
        });
    }

    const tgkillAddr = findLibcExport('tgkill');
    if (tgkillAddr) {
        Interceptor.attach(tgkillAddr, {
            onEnter(args) {
                const tgid = args[0].toInt32();
                const tid = args[1].toInt32();
                const sig = args[2].toInt32();
                if (tgid === selfPid && (sig === 9 || sig === 6 || sig === 5 || sig === 19 || sig === 15)) {
                    emitStealth('BypassPtraceAndSignals', 'tgkill', {
                        tgid: tgid,
                        tid: tid,
                        sig: sig,
                        action: 'neutralized self-tgkill (sig -> 0)',
                        backtrace: formatBacktrace(this.context, 10),
                    });
                    args[2] = ptr(0);
                }
            }
        });
    }

    ['abort', 'exit', '_exit'].forEach(function (fn) {
        const addr = findLibcExport(fn);
        if (!addr) return;
        Interceptor.attach(addr, {
            onEnter(args) {
                emitStealth('BypassPtraceAndSignals', fn, {
                    code: fn === 'abort' ? -1 : args[0].toInt32(),
                    backtrace: formatBacktrace(this.context, 12),
                });
            }
        });
    });

    // 3. pthread_create watchdog thread inspector & blocker
    const noopThread = new NativeCallback(function () {
        return ptr(0);
    }, 'pointer', ['pointer']);

    const blockSet = new Set(CONFIG.watchdogBlockOffsets.map(function (s) {
        return String(s).toLowerCase().replace(/^0x/, '');
    }));

    const pthreadCreateAddr = findLibcExport('pthread_create');
    if (pthreadCreateAddr) {
        Interceptor.attach(pthreadCreateAddr, {
            onEnter(args) {
                const startRoutine = args[2];
                const mod = Process.findModuleByAddress(startRoutine);
                if (!mod) return;
                const off = startRoutine.sub(mod.base);
                const offHex = off.toString(16).toLowerCase();
                const matchesTarget = !CONFIG.targetSO || mod.name.indexOf(CONFIG.targetSO) !== -1;

                if (matchesTarget && (blockSet.has(offHex) || blockSet.has('0x' + offHex))) {
                    args[2] = noopThread;
                    emitStealth('BypassPtraceAndSignals', 'pthread_create', {
                        action: 'blocked watchdog thread',
                        module: mod.name,
                        offset: '0x' + offHex,
                    });
                } else if (CONFIG.targetSO && mod.name.indexOf(CONFIG.targetSO) !== -1) {
                    emitStealth('BypassPtraceAndSignals', 'pthread_create', {
                        action: 'observed thread in target SO',
                        module: mod.name,
                        offset: '0x' + offHex,
                    });
                }
            }
        });
    }
})();
`)
	}

	// Module 3: PatchInlineSVC
	if opts.PatchInlineSVC {
		b.WriteString(`
// ─── Module 3: PatchInlineSVC (ARM64 SVC #0 Scanner & Patcher) ───────
(function installInlineSVCPatcher() {
    if (Process.arch !== 'arm64') {
        emitStealth('PatchInlineSVC', 'init', { skipped: 'ARM64 required, detected ' + Process.arch });
        return;
    }

    const ARM64_SYSCALLS = {
        26: 'inotify_init1', 27: 'inotify_add_watch', 48: 'faccessat',
        56: 'openat', 63: 'read', 78: 'readlinkat', 93: 'exit',
        94: 'exit_group', 113: 'clock_gettime', 117: 'ptrace',
        129: 'kill', 131: 'tgkill', 167: 'prctl'
    };
    const DANGEROUS_SYSCALLS = new Set([93, 94, 117, 129, 131]);
    const patchedModules = new Set();

    function inspectPrecedingSyscallNr(svcAddr) {
        for (let back = 4; back <= 24; back += 4) {
            try {
                const insn = svcAddr.sub(back).readU32();
                // MOVZ X8, #imm16 or MOVZ W8, #imm16
                if (((insn & 0xFFE0001F) >>> 0) === 0xD2800008 || ((insn & 0xFFE0001F) >>> 0) === 0x52800008) {
                    return (insn >>> 5) & 0xFFFF;
                }
            } catch (_) {
                break;
            }
        }
        return -1;
    }

    function scanAndPatchModule(mod) {
        if (!mod || patchedModules.has(mod.name)) return;
        patchedModules.add(mod.name);

        const ranges = mod.enumerateRanges('r-x');
        let totalFound = 0;
        let totalPatched = 0;

        ranges.forEach(function (range) {
            const matches = Memory.scanSync(range.base, range.size, '01 00 00 d4');
            matches.forEach(function (m) {
                if (!m.address.and(3).isNull()) return; // must be 4-byte aligned ARM64 insn
                totalFound++;
                const off = m.address.sub(mod.base);
                const sysNr = inspectPrecedingSyscallNr(m.address);
                const sysName = sysNr >= 0 ? (ARM64_SYSCALLS[sysNr] || ('sys_' + sysNr)) : 'unknown';
                let patched = false;

                if (!CONFIG.dryRunSVCPatch && DANGEROUS_SYSCALLS.has(sysNr)) {
                    try {
                        Memory.patchCode(m.address, 4, function (code) {
                            const cw = new Arm64Writer(code, { pc: m.address });
                            // Replace SVC #0 with MOV X0, #0 (0xD2800000) to simulate syscall success
                            cw.putInstruction(0xD2800000);
                            cw.flush();
                        });
                        patched = true;
                        totalPatched++;
                    } catch (e) {
                        emitStealth('PatchInlineSVC', 'patch_error', {
                            module: mod.name, offset: off.toString(), error: e.message
                        });
                    }
                }

                emitStealth('PatchInlineSVC', 'svc_hit', {
                    module: mod.name,
                    offset: off.toString(),
                    syscall_nr: sysNr,
                    syscall: sysName,
                    patched: patched,
                    dry_run: CONFIG.dryRunSVCPatch,
                });
            });
        });

        emitStealth('PatchInlineSVC', 'summary', {
            module: mod.name,
            inline_svc_found: totalFound,
            inline_svc_patched: totalPatched,
        });
    }

    const existing = CONFIG.targetSO ? Process.findModuleByName(CONFIG.targetSO) : null;
    if (existing) {
        scanAndPatchModule(existing);
    } else if (CONFIG.targetSO) {
        ['dlopen', 'android_dlopen_ext'].forEach(function (loader) {
            const addr = findLibcExport(loader);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter(args) {
                    this.hit = false;
                    try {
                        if (!args[0].isNull()) {
                            this.hit = args[0].readCString().indexOf(CONFIG.targetSO) !== -1;
                        }
                    } catch (_) {}
                },
                onLeave() {
                    if (this.hit) {
                        const mod = Process.findModuleByName(CONFIG.targetSO);
                        if (mod) scanAndPatchModule(mod);
                    }
                }
            });
        });
    }
})();
`)
	}

	// Module 4: BypassTimingAndInotify
	if opts.BypassTimingAndInotify {
		b.WriteString(`
// ─── Module 4: BypassTimingAndInotify ────────────────────────────────
(function installTimingAndInotifyBypass() {
    // 1. Neutralize inotify_add_watch on /proc/*, /maps, /mem, /pagemap
    const inotifyAddr = findLibcExport('inotify_add_watch');
    if (inotifyAddr) {
        Interceptor.attach(inotifyAddr, {
            onEnter(args) {
                this.block = false;
                this.path = '';
                try {
                    if (!args[1].isNull()) {
                        this.path = args[1].readCString();
                        if (/\/proc\/|maps|mem|pagemap|frida|tmp/i.test(this.path)) {
                            this.block = true;
                        }
                    }
                } catch (_) {}
            },
            onLeave(retval) {
                if (this.block) {
                    emitStealth('BypassTimingAndInotify', 'inotify_add_watch', {
                        blocked_path: this.path,
                        spoofed_wd: 1,
                    });
                    retval.replace(ptr(1));
                }
            }
        });
    }

    // 2. Clamp single-step/hook latency spikes in clock_gettime & gettimeofday
    const MAX_DELTA_NS = 80000000; // 80ms ceiling between consecutive anti-debug samples
    let lastRealNs = null;
    let virtualNs = null;
    const is64Bit = Process.pointerSize === 8;

    function readTimeField(p) {
        return is64Bit ? p.readS64().toNumber() : p.readS32();
    }

    function writeTimeField(p, v) {
        if (is64Bit) {
            p.writeS64(v);
        } else {
            p.writeS32(v | 0);
        }
    }

    const clockAddr = findLibcExport('clock_gettime');
    if (clockAddr) {
        Interceptor.attach(clockAddr, {
            onEnter(args) {
                this.clkId = args[0].toInt32();
                this.ts = args[1];
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0 || this.ts.isNull()) return;
                // Only clamp CLOCK_MONOTONIC (1) / CLOCK_MONOTONIC_RAW (4)
                if (this.clkId !== 1 && this.clkId !== 4) return;
                try {
                    const sec = readTimeField(this.ts);
                    const nsec = readTimeField(this.ts.add(Process.pointerSize));
                    const nowNs = sec * 1e9 + nsec;
                    if (lastRealNs !== null) {
                        const delta = nowNs - lastRealNs;
                        if (delta > MAX_DELTA_NS && delta < 5e9) {
                            virtualNs += 1000000; // advance smoothly by 1ms
                            const vSec = Math.floor(virtualNs / 1e9);
                            const vNsec = Math.floor(virtualNs - vSec * 1e9);
                            writeTimeField(this.ts, vSec);
                            writeTimeField(this.ts.add(Process.pointerSize), vNsec);
                        } else {
                            virtualNs = nowNs;
                        }
                    } else {
                        virtualNs = nowNs;
                    }
                    lastRealNs = nowNs;
                } catch (_) {}
            }
        });
    }

    const gtodAddr = findLibcExport('gettimeofday');
    if (gtodAddr) {
        let lastUs = null;
        Interceptor.attach(gtodAddr, {
            onEnter(args) {
                this.tv = args[0];
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0 || this.tv.isNull()) return;
                try {
                    const sec = readTimeField(this.tv);
                    const usec = readTimeField(this.tv.add(Process.pointerSize));
                    const nowUs = sec * 1e6 + usec;
                    if (lastUs !== null && (nowUs - lastUs) > 150000 && (nowUs - lastUs) < 5000000) {
                        const clamped = lastUs + 1000;
                        writeTimeField(this.tv, Math.floor(clamped / 1e6));
                        writeTimeField(this.tv.add(Process.pointerSize), Math.floor(clamped % 1e6));
                        lastUs = clamped;
                    } else {
                        lastUs = nowUs;
                    }
                } catch (_) {}
            }
        });
    }
})();
`)
	}

	// Module 5: BypassJavaDebugChecks
	if opts.BypassJavaDebugChecks {
		b.WriteString(`
// ─── Module 5: BypassJavaDebugChecks ─────────────────────────────────
Java.perform(function () {
    // 1. android.os.Debug
    try {
        const Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            emitStealth('BypassJavaDebugChecks', 'Debug.isDebuggerConnected', { spoofed: false });
            return false;
        };
        Debug.waitingForDebugger.implementation = function () {
            emitStealth('BypassJavaDebugChecks', 'Debug.waitingForDebugger', { spoofed: false });
            return false;
        };
    } catch (_) {}

    // 2. Settings.Global & Settings.Secure (adb_enabled / development_settings_enabled)
    const BLOCKED_SETTINGS = new Set(['adb_enabled', 'development_settings_enabled', 'adb_wifi_enabled']);
    ['android.provider.Settings$Global', 'android.provider.Settings$Secure'].forEach(function (clsName) {
        try {
            const Cls = Java.use(clsName);
            Cls.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, defVal) {
                if (BLOCKED_SETTINGS.has(String(name))) {
                    emitStealth('BypassJavaDebugChecks', clsName + '.getInt', { setting: name, spoofed: 0 });
                    return 0;
                }
                return this.getInt(cr, name, defVal);
            };
            Cls.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (cr, name) {
                if (BLOCKED_SETTINGS.has(String(name))) {
                    emitStealth('BypassJavaDebugChecks', clsName + '.getInt', { setting: name, spoofed: 0 });
                    return 0;
                }
                return this.getInt(cr, name);
            };
        } catch (_) {}
    });

    // 3. Clear ApplicationInfo.FLAG_DEBUGGABLE (0x2)
    try {
        const PM = Java.use('android.app.ApplicationPackageManager');
        PM.getApplicationInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            const info = this.getApplicationInfo(pkg, flags);
            if (info && (info.flags.value & 0x2) !== 0) {
                info.flags.value = info.flags.value & ~0x2;
                emitStealth('BypassJavaDebugChecks', 'ApplicationInfo.FLAG_DEBUGGABLE', { pkg: pkg, cleared: true });
            }
            return info;
        };
    } catch (_) {}

    emitStealth('BypassJavaDebugChecks', 'ready', { detail: 'Java anti-debug & ADB flag hooks active' });
});
`)
	}

	b.WriteString("\nemitStealth('core', 'loaded', { active_modules: [" + joinJSQuoted(enabledModules) + "] });\n")

	target := opts.TargetPackage
	if target == "" {
		target = opts.TargetSO
	}
	usage := fmt.Sprintf("frida -U -f %s -l cap_stealth.js", nonEmptyOr(opts.TargetPackage, "<com.example.app>"))

	var notes []string
	if opts.PatchInlineSVC && opts.TargetSO == "" {
		notes = append(notes, "Set TargetSO (e.g. libjiagu_64.so) so PatchInlineSVC knows which shared library's RX pages to scan.")
	}
	if report != nil && len(report.Packers) > 0 {
		notes = append(notes, fmt.Sprintf("Auto-configured against %s (risk %d/100).", report.Packers[0].Name, report.RiskScore))
	}

	return &GeneratedScript{
		ID:          "deobf:stealth",
		Name:        "Anti-Debug & Anti-Frida Stealth Suite",
		Category:    "stealth",
		Engine:      EngineFrida,
		Language:    "javascript",
		Target:      target,
		Description: fmt.Sprintf("Composable Frida stealth bypass enabling %d module(s): %s.", len(enabledModules), strings.Join(enabledModules, ", ")),
		Code:        b.String(),
		Modules:     enabledModules,
		Usage:       usage,
		Notes:       notes,
		GeneratedAt: nowRFC3339(),
	}
}

// GenerateDexUnpackerScript synthesizes a Frida in-memory DEX unpacker that
// hooks libart.so DexFile/OpenMemory symbols AND actively sweeps process memory
// for valid dex\n035..041 headers, dumping unpacked DEX files into
// /data/data/<pkg>/files/cap_dump/.
func GenerateDexUnpackerScript(pkg string) *GeneratedScript {
	cleanPkg := strings.TrimSpace(pkg)
	displayPkg := nonEmptyOr(cleanPkg, "<package>")
	dumpPath := fmt.Sprintf("/data/data/%s/files/cap_dump/", displayPkg)

	var b strings.Builder
	b.WriteString("'use strict';\n\n")
	b.WriteString("// ─── cap In-Memory DEX Unpacker (libart OpenMemory + Memory Sweep) ──\n")
	fmt.Fprintf(&b, "// Target Package: %s\n", sanitizeCommentLine(displayPkg))
	fmt.Fprintf(&b, "// Dump Directory: %s\n\n", sanitizeCommentLine(dumpPath))

	fmt.Fprintf(&b, "const CONFIGURED_PKG = %s;\n", jsQuote(cleanPkg))
	b.WriteString(`const MAX_DEX_SIZE = 64 * 1024 * 1024; // 64 MiB safety cap
const dumpedKeys = new Set();
let dumpCounter = 0;

function emitUnpack(event, payload) {
    send(Object.assign({ cap_cat: 'deobf_unpack', event: event }, payload || {}));
}

function resolvePackageName() {
    if (CONFIGURED_PKG) return CONFIGURED_PKG;
    let pkg = '';
    try {
        Java.performNow(function () {
            const AT = Java.use('android.app.ActivityThread');
            pkg = AT.currentPackageName() || '';
        });
    } catch (_) {}
    if (!pkg) {
        try {
            const cmdline = new File('/proc/self/cmdline', 'r').readAllText();
            pkg = cmdline.split('\0')[0].trim();
        } catch (_) {}
    }
    return pkg || 'unknown.pkg';
}

function ensureDumpDir(dirPath) {
    const mkdirAddr = Module.findExportByName('libc.so', 'mkdir');
    if (mkdirAddr) {
        const mkdirFn = new NativeFunction(mkdirAddr, 'int', ['pointer', 'int']);
        mkdirFn(Memory.allocUtf8String(dirPath), 0o755);
    }
}

function validateDexHeader(basePtr) {
    try {
        const magic = basePtr.readByteArray(8);
        if (!magic) return null;
        const m = new Uint8Array(magic);
        // "dex\n035\0" .. "dex\n041\0"
        if (m[0] !== 0x64 || m[1] !== 0x65 || m[2] !== 0x78 || m[3] !== 0x0a || m[7] !== 0x00) {
            return null;
        }
        const ver = String.fromCharCode(m[4], m[5], m[6]);
        if (!/^0(3[5-9]|4[01])$/.test(ver)) return null;

        const fileSize = basePtr.add(0x20).readU32();
        const headerSize = basePtr.add(0x24).readU32();
        const endianTag = basePtr.add(0x28).readU32();
        const checksum = basePtr.add(0x08).readU32();

        if (headerSize !== 0x70 || endianTag !== 0x12345678) return null;
        if (fileSize < 0x70 || fileSize > MAX_DEX_SIZE) return null;
        return { version: ver, size: fileSize, checksum: checksum >>> 0 };
    } catch (_) {
        return null;
    }
}

function dumpDexBuffer(basePtr, hintSize, source) {
    const info = validateDexHeader(basePtr);
    const size = info ? info.size : (hintSize > 0x70 && hintSize <= MAX_DEX_SIZE ? hintSize : 0);
    if (!info || size <= 0) return false;

    const dedupKey = size + ':' + info.checksum;
    if (dumpedKeys.has(dedupKey)) return false;
    dumpedKeys.add(dedupKey);

    const pkg = resolvePackageName();
    const outDir = '/data/data/' + pkg + '/files/cap_dump/';
    ensureDumpDir(outDir);

    dumpCounter++;
    const filePath = outDir + 'classes_' + dumpCounter + '_' + size + '_v' + info.version + '.dex';
    try {
        const bytes = basePtr.readByteArray(size);
        const f = new File(filePath, 'wb');
        f.write(bytes);
        f.flush();
        f.close();
        emitUnpack('dex_dumped', {
            path: filePath,
            size: size,
            version: info.version,
            checksum: '0x' + info.checksum.toString(16),
            address: basePtr.toString(),
            source: source,
        });
        return true;
    } catch (e) {
        emitUnpack('dump_error', { path: filePath, source: source, error: e.message });
        return false;
    }
}

// Strategy A: Hook libart.so DexFile / OpenMemory / OpenCommon loaders
function hookLibArtDexLoaders() {
    const libart = Process.findModuleByName('libart.so');
    if (!libart) {
        emitUnpack('warn', { detail: 'libart.so not loaded; falling back to memory sweep only' });
        return;
    }
    const syms = libart.enumerateSymbols();
    let hooked = 0;

    for (let i = 0; i < syms.length; i++) {
        const name = syms[i].name;
        const isOpenMemory = name.indexOf('DexFile') !== -1 && name.indexOf('OpenMemory') !== -1;
        const isOpenCommon = name.indexOf('DexFileLoader') !== -1 && name.indexOf('OpenCommon') !== -1;
        if (!isOpenMemory && !isOpenCommon) continue;

        try {
            Interceptor.attach(syms[i].address, {
                onEnter(args) {
                    // Check arg0/arg1/arg2 for a valid DEX buffer base pointer
                    for (let idx = 0; idx <= 2; idx++) {
                        try {
                            const cand = args[idx];
                            if (!cand.isNull() && validateDexHeader(cand)) {
                                dumpDexBuffer(cand, 0, 'libart:' + name);
                                break;
                            }
                        } catch (_) {}
                    }
                }
            });
            hooked++;
        } catch (_) {}
    }
    emitUnpack('hooks_installed', { libart_hooks: hooked });
}

// Strategy B: Active memory sweep for dex\n035..041 headers across readable ranges
function scanAndDumpDex() {
    let found = 0;
    const patterns = [
        '64 65 78 0a 30 33 ?? 00', // dex\n035..039
        '64 65 78 0a 30 34 ?? 00', // dex\n040..041
    ];
    Process.enumerateRanges('r--').forEach(function (range) {
        if (range.size < 0x70 || range.size > 256 * 1024 * 1024) return;
        // Skip system framework boot oat/vdex paths to focus on app unpacked DEX
        if (range.file && /^\/(system|apex)\//.test(range.file.path)) return;

        patterns.forEach(function (pat) {
            try {
                const hits = Memory.scanSync(range.base, range.size, pat);
                hits.forEach(function (h) {
                    if (dumpDexBuffer(h.address, 0, 'memory_scan')) {
                        found++;
                    }
                });
            } catch (_) {}
        });
    });
    emitUnpack('scan_complete', { newly_dumped: found, total_dumped: dumpCounter });
    return dumpCounter;
}

hookLibArtDexLoaders();
setTimeout(scanAndDumpDex, 3000);

rpc.exports = {
    dumpNow: scanAndDumpDex,
};
`)

	return &GeneratedScript{
		ID:          "deobf:dex-unpacker",
		Name:        "In-Memory DEX Unpacker",
		Category:    "unpack",
		Engine:      EngineFrida,
		Language:    "javascript",
		Target:      displayPkg,
		Description: fmt.Sprintf("Hooks libart.so DexFile/OpenMemory & sweeps memory for dex\\n035..041 headers, dumping unpacked DEX files to %s.", dumpPath),
		Code:        b.String(),
		Modules:     []string{"LibArtOpenMemoryHook", "DexHeaderMemoryScanner"},
		Usage:       fmt.Sprintf("frida -U -f %s -l cap_dex_unpacker.js && adb pull %s ./unpacked_dex/", displayPkg, dumpPath),
		Notes: []string{
			"Combine with cap Anti-Debug Stealth script when unpacking 360 Jiagu, Tencent Legu, Bangcle, or Ijiami shells.",
			"Call rpc.exports.dumpNow() after logging in or exercising lazy-loaded activities to capture delayed DEX loads.",
		},
		GeneratedAt: nowRFC3339(),
	}
}

func joinJSQuoted(items []string) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = jsQuote(it)
	}
	return strings.Join(parts, ", ")
}

func nonEmptyOr(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}
