import { writable } from 'svelte/store'
import { navigate } from './navigation.js'

export function pageForSubTab(subTab) {
  switch (subTab) {
    case 'native':
    case 'jadx':
      return 're-static'
    case 'emulate':
    case 'exectrace':
      return 're-emulate'
    case 'deobf':
      return 're-defense'
    case 'cryptolab':
      return 're-crypto'
    default:
      return 're-static'
  }
}

// Persistent UI state for RE Lab across route switches
export const reLabState = {
  // Active internal sub-tab: 'native' | 'emulate' | 'jadx' | 'deobf' | 'exectrace' | 'cryptolab'
  subTab: 'native',
  lastStaticTab: 'native', // 'native' | 'jadx'
  lastEmulateTab: 'emulate', // 'emulate' | 'exectrace'

  // Sub-tab 1: Native Binary & Radare2 + iOS Mach-O/IPA + Symbol Bridge
  binaryPath: '',
  binaryAnalysis: null,
  nativeMode: 'r2', // 'r2' | 'ios'
  nativeLeftTab: 'functions', // 'functions' | 'exports' | 'imports' | 'strings' | 'xrefs'
  nativeSearch: '',
  nativeJniOnly: false,
  selectedFuncKey: '',
  functionDetail: null,
  funcViewTab: 'disasm', // 'disasm' | 'pseudoc' | 'xrefs'
  r2Cmd: 'iI',
  r2History: [],
  iosReport: null,
  iosLeftTab: 'objc_classes', // 'objc_classes' | 'objc_selectors' | 'exports' | 'dylibs'
  iosSearch: '',
  iosTargetObjCClass: '',
  iosTargetObjCSelector: '',
  iosTargetSymbol: '',
  iosTargetOffset: '',
  symExportFormat: 'ida', // 'ida' | 'ghidra' | 'json'
  symImageBase: '0x0',
  symExportOutput: '',
  symImportRaw: '',
  importedSymbolBundle: null,
  symCustomComments: [],
  appliedSymbolComments: {},

  // Sub-tab 2: Emulation & Symbolic (Unidbg / Qiling / angr) + Auto-Stub Assistant
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
  autoStubRawLog: '',
  autoStubDiagnosis: null,
  autoStubSnippetTab: 'combined', // 'combined' | 'jni' | 'io' | 'sysprop'
  autoStubPkg: '',

  // Sub-tab 3: JADX Decompiler & Java<->JNI Cross-Link
  jadxApkPath: '',
  jadxInfo: null,
  jadxWorkspace: null,
  jadxClasses: [],
  jadxLeftTab: 'classes', // 'classes' | 'search'
  jadxClassFilter: '',
  jadxNativeOnly: false,
  jadxSearchQuery: '',
  jadxSearchHits: [],
  jadxSelectedClass: '',
  jadxClassSource: null,
  jadxSoPath: '',
  jadxRegisterNativesJSON: '',
  jadxLinkReport: null,
  jadxLinkFilter: 'all', // 'all' | 'static_export' | 'dynamic_register' | 'unresolved'

  // Sub-tab 4: Deobf · Anti-Debug · VMP · TLS/Proxy Compat
  deobfView: 'audit', // 'audit' | 'scripts' | 'vmp_trace' | 'tls'
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
  tlsApkPath: '',
  tlsCertReport: null,
  tlsMtlsCertPath: '',
  tlsMtlsKeyPath: '',
  tlsMtlsResult: null,
  tlsProfiles: [],
  tlsSelectedProfileId: 'chrome_131',
  tlsProfileJA3: null,
  tlsCurlInfo: null,
  tlsCompatKind: 'flutter', // 'flutter' | 'cronet' | 'mtls_observer'
  tlsFlutterOpts: {
    package_name: '',
    platform: 'android',
    module_name: 'libflutter.so',
    proxy_host: '127.0.0.1',
    proxy_port: 8080,
    offset_hex: '',
    verify_symbol: 'ssl_crypto_x509_session_verify_cert_chain',
    force_allow_local_verify: false,
  },
  tlsCronetOpts: {
    package_name: '',
    disable_quic: true,
    configure_okhttp_protocols: true,
    log_alt_svc_headers: true,
    proxy_hint: '127.0.0.1:8080',
  },
  tlsMtlsObsOpts: {
    package_name: '',
    observe_keystore: true,
    observe_key_manager: true,
    observe_ssl_context: true,
    observe_certificates: true,
    max_aliases_per_store: 32,
  },
  tlsGeneratedScript: null,

  // Sub-tab 5: ExecTrace & Taint
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

  // Sub-tab 6: CryptoLab (Pipeline · Protobuf · White-Box AES DFA)
  cryptoMode: 'pipeline', // 'pipeline' | 'protobuf' | 'dfa'
  cryptoOps: [],
  cryptoOpSearch: '',
  cryptoOpCategory: 'all',
  cryptoInput: '',
  cryptoInputEncoding: 'utf8',
  cryptoSteps: [],
  cryptoOutputTab: 'utf8', // 'utf8' | 'hex' | 'base64'
  cryptoResult: null,
  cryptoIdentify: null,
  protoInput: '',
  protoTree: null,
  protoEncodedHex: '',
  dfaValidHex: '',
  dfaFaultsText: '',
  dfaPlaintextHex: '',
  dfaResult: null,
  dfaScriptEngine: 'unidbg', // 'unidbg' | 'qiling'
  dfaScriptCfg: {
    binary_path: '',
    apk_path: '',
    package_name: '',
    arch: 'arm64',
    rootfs: '',
    target_class: '',
    target_method: '',
    method_signature: '',
    target_symbol: '',
    target_addr: '',
    fault_hook_addr: '',
    state_buf_reg: 'x0',
    state_buf_addr: '',
    plaintext_hex: '',
    fault_xor: 1,
    faults_per_byte: 2,
    class_name: 'WhiteboxDFAHarness',
  },
  dfaGeneratedScript: null,
}

// Reactive handoff store for jumping into RE Lab from DeepTrace, Capture, Flows, or Frida
export const reLabHandoff = writable(null)

/**
 * Jump directly to the matching RE workspace with optional sub-tab / view selection,
 * binary/APK paths, target emulation engine, generated harness, or scan target.
 */
export function openRELab({
  subTab = '',
  deobfView = '',
  cryptoMode = '',
  binaryPath = '',
  apkPath = '',
  engine = '',
  generatedHarness = null,
  scanPath = '',
} = {}) {
  const validTabs = ['native', 'emulate', 'jadx', 'deobf', 'exectrace', 'cryptolab']
  const validDeobfViews = ['audit', 'scripts', 'vmp_trace', 'tls']
  const validCryptoModes = ['pipeline', 'protobuf', 'dfa']

  let targetSubTab = reLabState.subTab || 'native'
  if (validTabs.includes(subTab)) {
    targetSubTab = subTab
  } else if (validDeobfViews.includes(deobfView)) {
    targetSubTab = 'deobf'
  } else if (validCryptoModes.includes(cryptoMode)) {
    targetSubTab = 'cryptolab'
  } else if (generatedHarness) {
    targetSubTab = 'emulate'
  } else if (scanPath) {
    targetSubTab = 'deobf'
  } else if (binaryPath) {
    targetSubTab = 'native'
  }

  reLabState.subTab = targetSubTab
  if (targetSubTab === 'native' || targetSubTab === 'jadx') {
    reLabState.lastStaticTab = targetSubTab
  } else if (targetSubTab === 'emulate' || targetSubTab === 'exectrace') {
    reLabState.lastEmulateTab = targetSubTab
  }

  if (binaryPath) {
    reLabState.binaryPath = binaryPath
    reLabState.projBinaryPath = binaryPath
    if (!reLabState.genSoPath) reLabState.genSoPath = binaryPath
    if (!reLabState.jadxSoPath) reLabState.jadxSoPath = binaryPath
  }
  if (apkPath) {
    reLabState.projAPKPath = apkPath
    if (!reLabState.genApkPath) reLabState.genApkPath = apkPath
    if (!reLabState.jadxApkPath) reLabState.jadxApkPath = apkPath
    if (!reLabState.tlsApkPath) reLabState.tlsApkPath = apkPath
  }
  if (engine) {
    reLabState.projEngine = engine
  }
  if (scanPath) {
    reLabState.scanPath = scanPath
    if (!validDeobfViews.includes(deobfView)) {
      reLabState.deobfView = 'audit'
    }
  }
  if (validDeobfViews.includes(deobfView)) {
    reLabState.deobfView = deobfView
  }
  if (validCryptoModes.includes(cryptoMode)) {
    reLabState.cryptoMode = cryptoMode
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
    subTab: targetSubTab,
    deobfView: validDeobfViews.includes(deobfView) ? deobfView : (scanPath ? 'audit' : ''),
    cryptoMode: validCryptoModes.includes(cryptoMode) ? cryptoMode : '',
    binaryPath,
    apkPath,
    engine,
    generatedHarness,
    scanPath,
  })
  navigate(pageForSubTab(targetSubTab))
}
