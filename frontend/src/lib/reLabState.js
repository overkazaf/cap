import { writable } from 'svelte/store'
import { navigate } from './navigation.js'

// Persistent UI state for RE Lab across route switches
export const reLabState = {
  // Active top-level sub-tab: 'native' | 'emulate' | 'deobf' | 'exectrace'
  subTab: 'native',

  // Sub-tab 1: Native Binary & Radare2
  binaryPath: '',
  binaryAnalysis: null,
  nativeLeftTab: 'functions', // 'functions' | 'exports' | 'imports' | 'strings' | 'xrefs'
  nativeSearch: '',
  nativeJniOnly: false,
  selectedFuncKey: '',
  functionDetail: null,
  funcViewTab: 'disasm', // 'disasm' | 'pseudoc' | 'xrefs'
  r2Cmd: 'iI',
  r2History: [],

  // Sub-tab 2: Emulation & Symbolic (Unidbg / Qiling / angr)
  projectEngineFilter: 'all', // 'all' | 'unidbg' | 'qiling' | 'angr' | 'radare2'
  projectSearch: '',
  projId: '',
  projName: '',
  projEngine: 'unidbg',
  projDescription: '',
  projBinaryPath: '',
  projAPKPath: '',
  projTargetClass: '',
  projTargetMethod: '',
  projTargetSymbol: '',
  projTargetAddr: '',
  projFindAddr: '',
  projAvoidAddr: '',
  projRootFS: '',
  projArgsText: '',
  projTimeoutSec: 60,
  projCode: '',
  projBuiltin: false,
  projDirty: false,
  jobConsoleFilter: 'all', // 'all' | 'result' | 'stdout' | 'stderr' | 'system'
  jobConsoleSearch: '',
  jobAutoScroll: true,

  // Sub-tab 3: Deobf · Anti-Debug · VMP
  deobfView: 'audit', // 'audit' | 'scripts' | 'vmp_trace'
  scanPath: '',
  protectionReport: null,
  selectedGenerator: 'stealth', // 'stealth' | 'unpack' | 'ollvm' | 'string_decrypt' | 'java_deobf' | 'vmp_stalker' | 'vmp_jni' | 'vmp_unidbg'
  stealthOpts: {
    target_package: '',
    target_so: '',
    bypass_tracer_pid_and_proc_fs: true,
    bypass_ptrace_and_signals: true,
    patch_inline_svc: false,
    bypass_timing_and_inotify: true,
    bypass_java_debug_checks: true,
    dry_run_svc_patch: false,
  },
  stealthWatchdogOffsets: '',
  stealthCustomTokens: '',
  stealthUseReport: true,
  genTargetPkg: '',
  genSoPath: '',
  genApkPath: '',
  genFuncAddr: '0x1000',
  genArch: 'arm64',
  genStrEngine: 'qiling',
  genVmpSoName: 'libvmp.so',
  genVmpEntry: 'JNI_OnLoad',
  genVmpMaxEvents: 50000,
  genVmpClassName: 'com/example/security/VmpBridge',
  genVmpMethodName: 'sign(Ljava/lang/String;)Ljava/lang/String;',
  generatedScript: null,
  vmpTraceRaw: '',
  vmpTraceBaseHex: '',
  vmpTraceAnalysis: null,

  // Sub-tab 4: ExecTrace & Taint
  selectedTraceId: '',
  traceViewTab: 'overview', // 'overview' | 'events' | 'taint' | 'diff'
  traceListSearch: '',
  eventFilterKind: '',
  eventFilterSearch: '',
  eventFilterAddr: '',
  eventPageSize: 150,
  taintDirection: 'backward', // 'forward' | 'backward'
  taintStartSeq: 1,
  taintSeedReg: '',
  taintSeedMemAddr: '',
  taintSeedValueHex: '',
  taintMaxSteps: 5000,
  taintResult: null,
  diffSessionA: '',
  diffSessionB: '',
  diffMaxDivergences: 25,
  diffResult: null,
  generatedCollector: null,
}

// Reactive handoff store for jumping into RE Lab from DeepTrace, Capture, Flows, or Frida
export const reLabHandoff = writable(null)

/**
 * Jump directly to the RE Lab workspace with optional sub-tab selection,
 * binary/APK paths, target emulation engine, generated harness, or scan target.
 */
export function openRELab({
  subTab = '',
  binaryPath = '',
  apkPath = '',
  engine = '',
  generatedHarness = null,
  scanPath = '',
} = {}) {
  const validTabs = ['native', 'emulate', 'deobf', 'exectrace']
  if (validTabs.includes(subTab)) {
    reLabState.subTab = subTab
  } else if (generatedHarness) {
    reLabState.subTab = 'emulate'
  } else if (scanPath) {
    reLabState.subTab = 'deobf'
  } else if (binaryPath) {
    reLabState.subTab = 'native'
  }

  if (binaryPath) {
    reLabState.binaryPath = binaryPath
    reLabState.projBinaryPath = binaryPath
    if (!reLabState.genSoPath) reLabState.genSoPath = binaryPath
  }
  if (apkPath) {
    reLabState.projAPKPath = apkPath
    if (!reLabState.genApkPath) reLabState.genApkPath = apkPath
  }
  if (engine) {
    reLabState.projEngine = engine
  }
  if (scanPath) {
    reLabState.scanPath = scanPath
    reLabState.deobfView = 'audit'
  }
  if (generatedHarness) {
    const p = generatedHarness.project || {}
    reLabState.projId = ''
    reLabState.projName = generatedHarness.name || p.name || 'Generated Harness'
    reLabState.projEngine = generatedHarness.engine || p.engine || engine || 'unidbg'
    reLabState.projDescription = generatedHarness.description || generatedHarness.summary || p.description || ''
    reLabState.projBinaryPath = generatedHarness.binary_path || p.binary_path || binaryPath || reLabState.projBinaryPath
    reLabState.projAPKPath = generatedHarness.apk_path || p.apk_path || apkPath || reLabState.projAPKPath
    reLabState.projTargetClass = generatedHarness.target_class || p.target_class || ''
    reLabState.projTargetMethod = generatedHarness.target_method || p.target_method || ''
    reLabState.projTargetSymbol = generatedHarness.target_symbol || p.target_symbol || ''
    reLabState.projTargetAddr = generatedHarness.target_addr || p.target_addr || ''
    reLabState.projFindAddr = p.find_addr || ''
    reLabState.projAvoidAddr = p.avoid_addr || ''
    reLabState.projRootFS = p.rootfs || ''
    reLabState.projArgsText = Array.isArray(p.args) ? p.args.join(' ') : ''
    reLabState.projCode = generatedHarness.code || p.code || ''
    reLabState.projBuiltin = false
    reLabState.projDirty = true
  }

  reLabHandoff.set({
    ts: Date.now(),
    subTab: reLabState.subTab,
    binaryPath,
    apkPath,
    engine,
    generatedHarness,
    scanPath,
  })
  navigate('relab')
}
