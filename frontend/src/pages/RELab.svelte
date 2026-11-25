<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/reLab.js'
  import { t, translate } from '../lib/i18n.js'
  import { reLabState as S, reLabHandoff } from '../lib/reLabState.js'
  import { openFridaStudio } from '../lib/fridaState.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatBytes, formatDuration } from '../lib/format.js'
  import { hasPrimaryMod, MOD_LABEL } from '../lib/shortcuts.js'
  import { registerCommands } from '../lib/commandPalette.js'

  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import CodeEditor from '../components/CodeEditor.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  // ==================== Global Sub-Tab & Toolchain ====================
  let subTab = S.subTab || 'native'
  let toolchain = null
  let probingToolchain = false
  let showToolchainDrawer = false
  let savingToolchain = false
  let tcForm = {
    r2_path: '',
    java_path: '',
    mvn_path: '',
    unidbg_dir: '',
    python_path: '',
    qiling_python_path: '',
    angr_python_path: '',
    qiling_rootfs: '',
  }

  // ==================== Sub-Tab 1: Native Binary & Radare2 + iOS + Symbol Bridge ====================
  let binaryPath = S.binaryPath || ''
  let binaryAnalysis = S.binaryAnalysis || null
  let analyzingBinary = false
  let nativeMode = S.nativeMode || 'r2' // 'r2' | 'ios'
  let nativeLeftTab = S.nativeLeftTab || 'functions'
  let nativeSearch = S.nativeSearch || ''
  let nativeJniOnly = Boolean(S.nativeJniOnly)
  let selectedFuncKey = S.selectedFuncKey || ''
  let functionDetail = S.functionDetail || null
  let inspectingFunc = false
  let funcViewTab = S.funcViewTab || 'disasm'
  let r2Cmd = S.r2Cmd || 'iI'
  let r2Running = false
  let r2History = Array.isArray(S.r2History) ? S.r2History : []
  let r2ConsoleEl = null

  // iOS Mach-O / IPA Inspector
  let iosReport = S.iosReport || null
  let analyzingIOS = false
  let iosLeftTab = S.iosLeftTab || 'objc_classes'
  let iosSearch = S.iosSearch || ''
  let iosTargetObjCClass = S.iosTargetObjCClass || ''
  let iosTargetObjCSelector = S.iosTargetObjCSelector || ''
  let iosTargetSymbol = S.iosTargetSymbol || ''
  let iosTargetOffset = S.iosTargetOffset || ''
  let generatingIOSHarness = false
  let generatingIOSStealth = false

  // Symbol Bridge (IDA / Ghidra / JSON)
  let showSymbolBridgeDrawer = false
  let symBridgeTab = 'export' // 'export' | 'import'
  let symExportFormat = S.symExportFormat || 'ida'
  let symImageBase = S.symImageBase || '0x0'
  let symExportOutput = S.symExportOutput || ''
  let exportingSymbols = false
  let symNewCmtAddr = ''
  let symNewCmtText = ''
  let symCustomComments = Array.isArray(S.symCustomComments) ? S.symCustomComments : []
  let symImportRaw = S.symImportRaw || ''
  let importingSymbols = false
  let importedSymbolBundle = S.importedSymbolBundle || null
  let appliedSymbolComments = S.appliedSymbolComments ? { ...S.appliedSymbolComments } : {}

  const R2_PRESETS = ['iI', 'iS', 'afl', 'iE', 'ii', 'iz', 'pdf @ main']

  // ==================== Sub-Tab 2: Emulation & Symbolic ====================
  let projects = []
  let loadingProjects = false
  let projectEngineFilter = S.projectEngineFilter || 'all'
  let projectSearch = S.projectSearch || ''
  let projId = S.projId || ''
  let projName = S.projName || ''
  let projEngine = S.projEngine || 'unidbg'
  let projDescription = S.projDescription || ''
  let projBinaryPath = S.projBinaryPath || ''
  let projAPKPath = S.projAPKPath || ''
  let projTargetClass = S.projTargetClass || ''
  let projTargetMethod = S.projTargetMethod || ''
  let projTargetSymbol = S.projTargetSymbol || ''
  let projTargetAddr = S.projTargetAddr || ''
  let projFindAddr = S.projFindAddr || ''
  let projAvoidAddr = S.projAvoidAddr || ''
  let projRootFS = S.projRootFS || ''
  let projArgsText = S.projArgsText || ''
  let projTimeoutSec = S.projTimeoutSec || 60
  let projCode = S.projCode || ''
  let projBuiltin = Boolean(S.projBuiltin)
  let projDirty = Boolean(S.projDirty)
  let savingProject = false
  let showConfigStrip = true
  let emuEditorRef = null

  // DeepTrace -> Harness modal/drawer
  let showTraceGenDrawer = false
  let deepTraceState = null
  let traceGenEngine = 'unidbg'
  let traceGenArch = 'arm64'
  let traceGenHttpMode = false
  let traceGenHttpPort = 8899
  let traceGenInputLen = 32
  let generatingHarness = false

  // Live RE Job state & console
  let jobState = null
  let startingJob = false
  let jobConsoleFilter = S.jobConsoleFilter || 'all'
  let jobConsoleSearch = S.jobConsoleSearch || ''
  let jobAutoScroll = S.jobAutoScroll ?? true
  let expandedJobEvents = new Set()
  let jobConsoleEl = null
  let elapsedTick = Date.now()
  let clockTimer = null

  // Auto-Stub Assistant (Unidbg Smart Env Diagnosis)
  let showAutoStubDrawer = false
  let autoStubRawLog = S.autoStubRawLog || ''
  let analyzingAutoStub = false
  let autoStubDiagnosis = S.autoStubDiagnosis || null
  let autoStubSnippetTab = S.autoStubSnippetTab || 'combined'
  let autoStubPkg = S.autoStubPkg || ''
  let generatingEnvSnap = false

  // ==================== Sub-Tab 3: JADX Decompiler & Java<->JNI Cross-Link ====================
  let jadxApkPath = S.jadxApkPath || ''
  let jadxInfo = S.jadxInfo || null
  let probingJadx = false
  let jadxWorkspace = S.jadxWorkspace || null
  let decompilingJadx = false
  let jadxClasses = Array.isArray(S.jadxClasses) ? S.jadxClasses : []
  let jadxLeftTab = S.jadxLeftTab || 'classes'
  let jadxClassFilter = S.jadxClassFilter || ''
  let jadxNativeOnly = Boolean(S.jadxNativeOnly)
  let jadxSearchQuery = S.jadxSearchQuery || ''
  let searchingJadx = false
  let jadxSearchHits = Array.isArray(S.jadxSearchHits) ? S.jadxSearchHits : []
  let jadxSelectedClass = S.jadxSelectedClass || ''
  let jadxClassSource = S.jadxClassSource || null
  let loadingJadxSource = false
  let jadxSoPath = S.jadxSoPath || ''
  let showRegNativesInput = false
  let jadxRegisterNativesJSON = S.jadxRegisterNativesJSON || ''
  let linkingJadx = false
  let jadxLinkReport = S.jadxLinkReport || null
  let jadxLinkFilter = S.jadxLinkFilter || 'all'
  let jadxEditorRef = null

  // ==================== Sub-Tab 4: Deobf · Anti-Debug · VMP · TLS/Proxy Compat ====================
  let deobfView = S.deobfView || 'audit'
  let scanPath = S.scanPath || ''
  let scanningProtection = false
  let protectionReport = S.protectionReport || null

  let selectedGenerator = S.selectedGenerator || 'stealth'
  let stealthOpts = { ...(S.stealthOpts || {}) }
  let stealthWatchdogOffsets = S.stealthWatchdogOffsets || ''
  let stealthCustomTokens = S.stealthCustomTokens || ''
  let stealthUseReport = S.stealthUseReport ?? true
  let genTargetPkg = S.genTargetPkg || ''
  let genSoPath = S.genSoPath || ''
  let genApkPath = S.genApkPath || ''
  let genFuncAddr = S.genFuncAddr || '0x1000'
  let genArch = S.genArch || 'arm64'
  let genStrEngine = S.genStrEngine || 'qiling'
  let genVmpSoName = S.genVmpSoName || 'libvmp.so'
  let genVmpEntry = S.genVmpEntry || 'JNI_OnLoad'
  let genVmpMaxEvents = S.genVmpMaxEvents || 50000
  let genVmpClassName = S.genVmpClassName || 'com/example/security/VmpBridge'
  let genVmpMethodName = S.genVmpMethodName || 'sign(Ljava/lang/String;)Ljava/lang/String;'
  let generatingScript = false
  let generatedScript = S.generatedScript || null
  let deobfEditorRef = null

  let vmpTraceRaw = S.vmpTraceRaw || ''
  let vmpTraceBaseHex = S.vmpTraceBaseHex || ''
  let analyzingVmpTrace = false
  let vmpTraceAnalysis = S.vmpTraceAnalysis || null

  // TLS / Certs / Proxy Compat inside Deobf
  let tlsApkPath = S.tlsApkPath || ''
  let scanningTlsCerts = false
  let tlsCertReport = S.tlsCertReport || null
  let tlsMtlsCertPath = S.tlsMtlsCertPath || ''
  let tlsMtlsKeyPath = S.tlsMtlsKeyPath || ''
  let validatingMtls = false
  let tlsMtlsResult = S.tlsMtlsResult || null
  let tlsProfiles = Array.isArray(S.tlsProfiles) ? S.tlsProfiles : []
  let loadingTlsProfiles = false
  let tlsSelectedProfileId = S.tlsSelectedProfileId || 'chrome_131'
  let tlsProfileJA3 = S.tlsProfileJA3 || null
  let tlsCurlInfo = S.tlsCurlInfo || null
  let tlsCompatKind = S.tlsCompatKind || 'flutter'
  let tlsFlutterOpts = { ...(S.tlsFlutterOpts || {}) }
  let tlsCronetOpts = { ...(S.tlsCronetOpts || {}) }
  let tlsMtlsObsOpts = { ...(S.tlsMtlsObsOpts || {}) }
  let generatingTlsScript = false
  let tlsGeneratedScript = S.tlsGeneratedScript || null
  let tlsEditorRef = null

  const DEOBF_GENERATORS = [
    { id: 'stealth', engine: 'frida', icon: 'shield' },
    { id: 'unpack', engine: 'frida', icon: 'unlock' },
    { id: 'ollvm', engine: 'angr', icon: 'git-branch' },
    { id: 'string_decrypt', engine: 'qiling', icon: 'key' },
    { id: 'java_deobf', engine: 'frida', icon: 'code' },
    { id: 'vmp_stalker', engine: 'frida', icon: 'radar' },
    { id: 'vmp_jni', engine: 'frida', icon: 'link' },
    { id: 'vmp_unidbg', engine: 'unidbg', icon: 'cpu' },
  ]

  // ==================== Sub-Tab 4: ExecTrace & Taint ====================
  let traceSessions = []
  let loadingTraces = false
  let traceListSearch = S.traceListSearch || ''
  let selectedTraceId = S.selectedTraceId || ''
  let activeTrace = null
  let traceViewTab = S.traceViewTab || 'overview'

  // Import Drawer
  let showImportDrawer = false
  let importMode = 'paste' // 'paste' | 'file'
  let importName = ''
  let importFormat = 'auto'
  let importBaseHex = ''
  let importFilePath = ''
  let importRawContent = ''
  let importingTrace = false

  // Collector Generator Drawer
  let showCollectorDrawer = false
  let collectorKind = 'stalker'
  let collectorCfg = {
    target_package: '',
    target_module: 'libnative-lib.so',
    target_symbol: '',
    target_offset: '',
    arch: 'arm64',
    class_filter: 'com.example.*',
    method_filter: '*',
    include_regs: true,
    include_mem: true,
    include_calls: true,
    max_events: 50000,
    binary_path: '',
    apk_path: '',
    rootfs: '',
    args: [],
  }
  let generatingCollector = false
  let generatedCollector = S.generatedCollector || null

  // Call Tree expand state
  let collapsedCallNodes = new Set()

  // Events Pagination
  let eventFilterKind = S.eventFilterKind || ''
  let eventFilterSearch = S.eventFilterSearch || ''
  let eventFilterAddr = S.eventFilterAddr || ''
  let eventPageSize = S.eventPageSize || 150
  let eventOffset = 0
  let eventPage = null
  let loadingEvents = false
  let selectedEventRow = null

  // Taint Analysis
  let taintDirection = S.taintDirection || 'backward'
  let taintStartSeq = S.taintStartSeq || 1
  let taintSeedReg = S.taintSeedReg || ''
  let taintSeedMemAddr = S.taintSeedMemAddr || ''
  let taintSeedValueHex = S.taintSeedValueHex || ''
  let taintMaxSteps = S.taintMaxSteps || 5000
  let runningTaint = false
  let taintResult = S.taintResult || null

  // Trace Diff
  let diffSessionA = S.diffSessionA || ''
  let diffSessionB = S.diffSessionB || ''
  let diffMaxDivergences = S.diffMaxDivergences || 25
  let runningDiff = false
  let diffResult = S.diffResult || null

  // ==================== Sub-Tab 6: CryptoLab (Pipeline · Protobuf · White-Box AES DFA) ====================
  let cryptoMode = S.cryptoMode || 'pipeline'
  let cryptoOps = Array.isArray(S.cryptoOps) ? S.cryptoOps : []
  let loadingCryptoOps = false
  let cryptoOpSearch = S.cryptoOpSearch || ''
  let cryptoOpCategory = S.cryptoOpCategory || 'all'
  let cryptoInput = S.cryptoInput || ''
  let cryptoInputEncoding = S.cryptoInputEncoding || 'utf8'
  let cryptoSteps = Array.isArray(S.cryptoSteps) ? S.cryptoSteps : []
  let cryptoOutputTab = S.cryptoOutputTab || 'utf8'
  let runningCrypto = false
  let cryptoResult = S.cryptoResult || null
  let identifyingCrypto = false
  let cryptoIdentify = S.cryptoIdentify || null
  let expandedCryptoSteps = new Set()

  // Protobuf Inspector
  let protoInput = S.protoInput || ''
  let decodingProto = false
  let protoTree = S.protoTree || null
  let encodingProto = false
  let protoEncodedHex = S.protoEncodedHex || ''
  let collapsedProtoNodes = new Set()

  // White-Box AES-128 Round-9 DFA
  let dfaValidHex = S.dfaValidHex || ''
  let dfaFaultsText = S.dfaFaultsText || ''
  let dfaPlaintextHex = S.dfaPlaintextHex || ''
  let solvingDfa = false
  let dfaResult = S.dfaResult || null
  let dfaScriptEngine = S.dfaScriptEngine || 'unidbg'
  let dfaScriptCfg = { ...(S.dfaScriptCfg || {}) }
  let generatingDfaScript = false
  let dfaGeneratedScript = S.dfaGeneratedScript || null

  // Subscriptions
  let unsubs = []
  let unsubHandoff = null
  let unregisterCmds = null

  // ==================== State Persistence ====================
  $: {
    S.subTab = subTab
    S.binaryPath = binaryPath
    S.binaryAnalysis = binaryAnalysis
    S.nativeMode = nativeMode
    S.nativeLeftTab = nativeLeftTab
    S.nativeSearch = nativeSearch
    S.nativeJniOnly = nativeJniOnly
    S.selectedFuncKey = selectedFuncKey
    S.functionDetail = functionDetail
    S.funcViewTab = funcViewTab
    S.r2Cmd = r2Cmd
    S.r2History = r2History
    S.iosReport = iosReport
    S.iosLeftTab = iosLeftTab
    S.iosSearch = iosSearch
    S.iosTargetObjCClass = iosTargetObjCClass
    S.iosTargetObjCSelector = iosTargetObjCSelector
    S.iosTargetSymbol = iosTargetSymbol
    S.iosTargetOffset = iosTargetOffset
    S.symExportFormat = symExportFormat
    S.symImageBase = symImageBase
    S.symExportOutput = symExportOutput
    S.symImportRaw = symImportRaw
    S.importedSymbolBundle = importedSymbolBundle
    S.symCustomComments = symCustomComments
    S.appliedSymbolComments = appliedSymbolComments

    S.projectEngineFilter = projectEngineFilter
    S.projectSearch = projectSearch
    S.projId = projId
    S.projName = projName
    S.projEngine = projEngine
    S.projDescription = projDescription
    S.projBinaryPath = projBinaryPath
    S.projAPKPath = projAPKPath
    S.projTargetClass = projTargetClass
    S.projTargetMethod = projTargetMethod
    S.projTargetSymbol = projTargetSymbol
    S.projTargetAddr = projTargetAddr
    S.projFindAddr = projFindAddr
    S.projAvoidAddr = projAvoidAddr
    S.projRootFS = projRootFS
    S.projArgsText = projArgsText
    S.projTimeoutSec = projTimeoutSec
    S.projCode = projCode
    S.projBuiltin = projBuiltin
    S.projDirty = projDirty
    S.jobConsoleFilter = jobConsoleFilter
    S.jobConsoleSearch = jobConsoleSearch
    S.jobAutoScroll = jobAutoScroll
    S.autoStubRawLog = autoStubRawLog
    S.autoStubDiagnosis = autoStubDiagnosis
    S.autoStubSnippetTab = autoStubSnippetTab
    S.autoStubPkg = autoStubPkg

    S.jadxApkPath = jadxApkPath
    S.jadxInfo = jadxInfo
    S.jadxWorkspace = jadxWorkspace
    S.jadxClasses = jadxClasses
    S.jadxLeftTab = jadxLeftTab
    S.jadxClassFilter = jadxClassFilter
    S.jadxNativeOnly = jadxNativeOnly
    S.jadxSearchQuery = jadxSearchQuery
    S.jadxSearchHits = jadxSearchHits
    S.jadxSelectedClass = jadxSelectedClass
    S.jadxClassSource = jadxClassSource
    S.jadxSoPath = jadxSoPath
    S.jadxRegisterNativesJSON = jadxRegisterNativesJSON
    S.jadxLinkReport = jadxLinkReport
    S.jadxLinkFilter = jadxLinkFilter

    S.deobfView = deobfView
    S.scanPath = scanPath
    S.protectionReport = protectionReport
    S.selectedGenerator = selectedGenerator
    S.stealthOpts = stealthOpts
    S.stealthWatchdogOffsets = stealthWatchdogOffsets
    S.stealthCustomTokens = stealthCustomTokens
    S.stealthUseReport = stealthUseReport
    S.genTargetPkg = genTargetPkg
    S.genSoPath = genSoPath
    S.genApkPath = genApkPath
    S.genFuncAddr = genFuncAddr
    S.genArch = genArch
    S.genStrEngine = genStrEngine
    S.genVmpSoName = genVmpSoName
    S.genVmpEntry = genVmpEntry
    S.genVmpMaxEvents = genVmpMaxEvents
    S.genVmpClassName = genVmpClassName
    S.genVmpMethodName = genVmpMethodName
    S.generatedScript = generatedScript
    S.vmpTraceRaw = vmpTraceRaw
    S.vmpTraceBaseHex = vmpTraceBaseHex
    S.vmpTraceAnalysis = vmpTraceAnalysis
    S.tlsApkPath = tlsApkPath
    S.tlsCertReport = tlsCertReport
    S.tlsMtlsCertPath = tlsMtlsCertPath
    S.tlsMtlsKeyPath = tlsMtlsKeyPath
    S.tlsMtlsResult = tlsMtlsResult
    S.tlsProfiles = tlsProfiles
    S.tlsSelectedProfileId = tlsSelectedProfileId
    S.tlsProfileJA3 = tlsProfileJA3
    S.tlsCurlInfo = tlsCurlInfo
    S.tlsCompatKind = tlsCompatKind
    S.tlsFlutterOpts = tlsFlutterOpts
    S.tlsCronetOpts = tlsCronetOpts
    S.tlsMtlsObsOpts = tlsMtlsObsOpts
    S.tlsGeneratedScript = tlsGeneratedScript

    S.selectedTraceId = selectedTraceId
    S.traceViewTab = traceViewTab
    S.traceListSearch = traceListSearch
    S.eventFilterKind = eventFilterKind
    S.eventFilterSearch = eventFilterSearch
    S.eventFilterAddr = eventFilterAddr
    S.eventPageSize = eventPageSize
    S.taintDirection = taintDirection
    S.taintStartSeq = taintStartSeq
    S.taintSeedReg = taintSeedReg
    S.taintSeedMemAddr = taintSeedMemAddr
    S.taintSeedValueHex = taintSeedValueHex
    S.taintMaxSteps = taintMaxSteps
    S.taintResult = taintResult
    S.diffSessionA = diffSessionA
    S.diffSessionB = diffSessionB
    S.diffMaxDivergences = diffMaxDivergences
    S.diffResult = diffResult
    S.generatedCollector = generatedCollector

    S.cryptoMode = cryptoMode
    S.cryptoOps = cryptoOps
    S.cryptoOpSearch = cryptoOpSearch
    S.cryptoOpCategory = cryptoOpCategory
    S.cryptoInput = cryptoInput
    S.cryptoInputEncoding = cryptoInputEncoding
    S.cryptoSteps = cryptoSteps
    S.cryptoOutputTab = cryptoOutputTab
    S.cryptoResult = cryptoResult
    S.cryptoIdentify = cryptoIdentify
    S.protoInput = protoInput
    S.protoTree = protoTree
    S.protoEncodedHex = protoEncodedHex
    S.dfaValidHex = dfaValidHex
    S.dfaFaultsText = dfaFaultsText
    S.dfaPlaintextHex = dfaPlaintextHex
    S.dfaResult = dfaResult
    S.dfaScriptEngine = dfaScriptEngine
    S.dfaScriptCfg = dfaScriptCfg
    S.dfaGeneratedScript = dfaGeneratedScript
  }

  // ==================== Derived Computations ====================
  $: toolchainPills = [
    { key: 'r2', label: 'r2', ready: Boolean(toolchain?.r2_ready), info: toolchain?.r2 },
    { key: 'java', label: 'Java', ready: Boolean(toolchain?.java?.ready), info: toolchain?.java },
    { key: 'unidbg', label: 'Unidbg', ready: Boolean(toolchain?.unidbg_ready), info: toolchain?.unidbg },
    { key: 'qiling', label: 'Qiling', ready: Boolean(toolchain?.qiling_ready), info: toolchain?.qiling },
    { key: 'angr', label: 'angr', ready: Boolean(toolchain?.angr_ready), info: toolchain?.angr },
  ]

  // Sub-Tab 1 derived
  $: nativeFunctions = binaryAnalysis?.functions || []
  $: nativeExports = binaryAnalysis?.exports || []
  $: nativeImports = binaryAnalysis?.imports || []
  $: nativeStrings = binaryAnalysis?.strings || []
  $: nativeXRefs = binaryAnalysis?.xrefs || []

  $: filteredNativeItems = (() => {
    const q = nativeSearch.trim().toLowerCase()
    if (nativeLeftTab === 'functions') {
      return nativeFunctions.filter((fn) => {
        if (nativeJniOnly && !fn.is_jni) return false
        if (!q) return true
        return (
          (fn.name || '').toLowerCase().includes(q) ||
          (fn.addr || '').toLowerCase().includes(q) ||
          (fn.signature || '').toLowerCase().includes(q)
        )
      })
    }
    if (nativeLeftTab === 'exports') {
      return nativeExports.filter((sym) => {
        if (nativeJniOnly && !sym.is_jni) return false
        if (!q) return true
        return (
          (sym.name || '').toLowerCase().includes(q) ||
          (sym.addr || '').toLowerCase().includes(q) ||
          (sym.type || '').toLowerCase().includes(q)
        )
      })
    }
    if (nativeLeftTab === 'imports') {
      return nativeImports.filter((sym) => {
        if (!q) return true
        return (
          (sym.name || '').toLowerCase().includes(q) ||
          (sym.library || '').toLowerCase().includes(q) ||
          (sym.addr || '').toLowerCase().includes(q)
        )
      })
    }
    if (nativeLeftTab === 'strings') {
      return nativeStrings.filter((st) => {
        if (!q) return true
        return (
          (st.value || '').toLowerCase().includes(q) ||
          (st.addr || '').toLowerCase().includes(q) ||
          (st.section || '').toLowerCase().includes(q)
        )
      })
    }
    return nativeXRefs.filter((xr) => {
      if (!q) return true
      return (
        (xr.from || '').toLowerCase().includes(q) ||
        (xr.from_name || '').toLowerCase().includes(q) ||
        (xr.to || '').toLowerCase().includes(q) ||
        (xr.to_name || '').toLowerCase().includes(q) ||
        (xr.opcode || '').toLowerCase().includes(q)
      )
    })
  })()

  // Sub-Tab 2 derived
  $: filteredProjects = projects.filter((p) => {
    if (projectEngineFilter !== 'all' && p.engine !== projectEngineFilter) return false
    const q = projectSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (p.name || '').toLowerCase().includes(q) ||
      (p.description || '').toLowerCase().includes(q) ||
      (p.target_symbol || '').toLowerCase().includes(q) ||
      (p.target_class || '').toLowerCase().includes(q) ||
      (p.tags || []).some((tg) => tg.toLowerCase().includes(q))
    )
  })

  $: isJobRunning = Boolean(jobState?.running)
  $: jobEvents = jobState?.events || []
  $: jobResults = jobState?.results || []
  $: jobLiveElapsedMs = isJobRunning && jobState?.started_at_ms
    ? Math.max(0, elapsedTick - jobState.started_at_ms)
    : (jobState?.elapsed_ms || 0)

  $: jobEventCounts = {
    all: jobEvents.length,
    result: jobEvents.filter((e) => e.stream === 'result' || e.level === 'result').length,
    stdout: jobEvents.filter((e) => e.stream === 'stdout').length,
    stderr: jobEvents.filter((e) => e.stream === 'stderr' || e.level === 'error').length,
    system: jobEvents.filter((e) => e.stream === 'system' || e.level === 'system').length,
  }

  $: filteredJobEvents = jobEvents.filter((ev) => {
    if (jobConsoleFilter === 'result' && ev.stream !== 'result' && ev.level !== 'result') return false
    if (jobConsoleFilter === 'stdout' && ev.stream !== 'stdout') return false
    if (jobConsoleFilter === 'stderr' && ev.stream !== 'stderr' && ev.level !== 'error') return false
    if (jobConsoleFilter === 'system' && ev.stream !== 'system' && ev.level !== 'system') return false
    const q = jobConsoleSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (ev.message || '').toLowerCase().includes(q) ||
      (ev.raw || '').toLowerCase().includes(q)
    )
  })

  $: emuEditorRuntime =
    projEngine === 'qiling' || projEngine === 'angr'
      ? 'python3'
      : projEngine === 'radare2'
        ? 'sh'
        : 'node'

  // Sub-Tab 3 derived
  $: riskScore = Number(protectionReport?.risk_score) || 0
  $: riskLevel = protectionReport?.hardening_level || 'none'
  $: riskColorVar =
    riskScore >= 80
      ? 'var(--status-danger)'
      : riskScore >= 55
        ? 'var(--method-put)'
        : riskScore >= 30
          ? 'var(--status-warning)'
          : 'var(--status-success)'

  $: deobfEditorRuntime =
    generatedScript?.language === 'python'
      ? 'python3'
      : 'node'

  // Sub-Tab 4 derived
  $: filteredTraceSessions = traceSessions.filter((s) => {
    const q = traceListSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (s.name || '').toLowerCase().includes(q) ||
      (s.target_module || '').toLowerCase().includes(q) ||
      (s.source || '').toLowerCase().includes(q) ||
      (s.arch || '').toLowerCase().includes(q)
    )
  })

  $: traceSummary = activeTrace?.summary || null
  $: maxMemOps = Math.max(
    1,
    ...((traceSummary?.memory_regions || []).map((m) => (m.read_count || 0) + (m.write_count || 0)))
  )

  $: flatCallTree = (() => {
    const out = []
    const walk = (nodes, depth) => {
      if (!Array.isArray(nodes)) return
      for (const n of nodes) {
        const hasChildren = Array.isArray(n.children) && n.children.length > 0
        const isCollapsed = collapsedCallNodes.has(n.id)
        out.push({ node: n, depth, hasChildren, isCollapsed })
        if (hasChildren && !isCollapsed) {
          walk(n.children, depth + 1)
        }
      }
    }
    walk(traceSummary?.call_tree || [], 0)
    return out
  })()

  // New Pro Derived Computations
  $: filteredIOSItems = (() => {
    const q = iosSearch.trim().toLowerCase()
    const list =
      iosLeftTab === 'objc_classes'
        ? (iosReport?.objc_classes || [])
        : iosLeftTab === 'objc_selectors'
          ? (iosReport?.objc_selectors || [])
          : iosLeftTab === 'exports'
            ? (iosReport?.exported_symbols || [])
            : [...(iosReport?.linked_dylibs || []), ...(iosReport?.frameworks || [])]
    if (!q) return list
    return list.filter((item) => String(item || '').toLowerCase().includes(q))
  })()

  $: appliedSymbolCount = Object.keys(appliedSymbolComments || {}).length

  $: hasAnyAutoStubSnippet = Boolean(
    autoStubDiagnosis?.combined_java_snippet ||
    autoStubDiagnosis?.abstract_jni_snippet ||
    autoStubDiagnosis?.io_resolver_snippet ||
    autoStubDiagnosis?.sys_prop_hook_snippet
  )

  $: activeAutoStubSnippet = (() => {
    if (!autoStubDiagnosis) return ''
    if (autoStubSnippetTab === 'jni') return autoStubDiagnosis.abstract_jni_snippet || ''
    if (autoStubSnippetTab === 'io') return autoStubDiagnosis.io_resolver_snippet || ''
    if (autoStubSnippetTab === 'sysprop') return autoStubDiagnosis.sys_prop_hook_snippet || ''
    return autoStubDiagnosis.combined_java_snippet || ''
  })()

  $: filteredJadxClasses = jadxClasses.filter((cls) => {
    if (jadxNativeOnly && !cls.has_native) return false
    const q = jadxClassFilter.trim().toLowerCase()
    if (!q) return true
    return (
      (cls.class_name || '').toLowerCase().includes(q) ||
      (cls.package_name || '').toLowerCase().includes(q) ||
      (cls.simple_name || '').toLowerCase().includes(q) ||
      (cls.native_methods || []).some((m) => m.toLowerCase().includes(q))
    )
  })

  $: filteredJadxBindings = (jadxLinkReport?.bindings || []).filter((b) => {
    if (jadxLinkFilter !== 'all' && b.binding_kind !== jadxLinkFilter) return false
    return true
  })

  $: selectedTlsProfile = tlsProfiles.find((p) => p.id === tlsSelectedProfileId) || tlsProfiles[0] || null

  $: cryptoOpByName = Object.fromEntries((cryptoOps || []).map((op) => [op.name, op]))

  $: cryptoOpCategories = ['all', ...Array.from(new Set((cryptoOps || []).map((op) => op.category).filter(Boolean)))]

  $: filteredCryptoOps = (cryptoOps || []).filter((op) => {
    if (cryptoOpCategory !== 'all' && op.category !== cryptoOpCategory) return false
    const q = cryptoOpSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (op.name || '').toLowerCase().includes(q) ||
      (op.label || '').toLowerCase().includes(q) ||
      (op.description || '').toLowerCase().includes(q) ||
      (op.category || '').toLowerCase().includes(q)
    )
  })

  $: flatProtoRows = (() => {
    const rows = []
    const walk = (msgNode, depth, prefix) => {
      if (!msgNode || !Array.isArray(msgNode.fields)) return
      msgNode.fields.forEach((field, idx) => {
        const pathKey = prefix ? `${prefix}.${idx}` : `${idx}`
        const hasNested = field.kind === 'message' && Boolean(field.nested)
        const isCollapsed = collapsedProtoNodes.has(pathKey)
        rows.push({
          field,
          parentMsg: msgNode,
          indexInParent: idx,
          pathKey,
          depth,
          hasNested,
          isCollapsed,
        })
        if (hasNested && !isCollapsed) {
          walk(field.nested, depth + 1, pathKey)
        }
      })
    }
    walk(protoTree, 0, '')
    return rows
  })()

  $: dfaFaultLines = String(dfaFaultsText || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)

  // Command palette registration
  $: {
    const _t = $t
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      unregisterCmds = registerCommands([
        {
          id: 'relab:native',
          label: `RE Lab: ${_t('reLab.tabs.native')}`,
          category: 'RE Lab',
          icon: 'cpu',
          keywords: 'radare2 r2 elf disasm binary native ios macho ipa symbols ida ghidra',
          run: () => (subTab = 'native'),
        },
        {
          id: 'relab:emulate',
          label: `RE Lab: ${_t('reLab.tabs.emulate')}`,
          category: 'RE Lab',
          icon: 'play',
          keywords: 'unidbg qiling angr emulate symbolic autostub',
          run: () => (subTab = 'emulate'),
        },
        {
          id: 'relab:jadx',
          label: `RE Lab: ${_t('reLab.tabs.jadx')}`,
          category: 'RE Lab',
          icon: 'file-code',
          keywords: 'jadx dex apk decompile java jni crosslink native',
          run: () => {
            subTab = 'jadx'
            if (!jadxInfo) detectJadx()
          },
        },
        {
          id: 'relab:deobf',
          label: `RE Lab: ${_t('reLab.tabs.deobf')}`,
          category: 'RE Lab',
          icon: 'shield',
          keywords: 'deobf ollvm antidebug vmp packer stealth tls cert mtls flutter cronet',
          run: () => (subTab = 'deobf'),
        },
        {
          id: 'relab:exectrace',
          label: `RE Lab: ${_t('reLab.tabs.exectrace')}`,
          category: 'RE Lab',
          icon: 'activity',
          keywords: 'exectrace taint diff stalker tenet crypto',
          run: () => {
            subTab = 'exectrace'
            loadExecTraces()
          },
        },
        {
          id: 'relab:cryptolab',
          label: `RE Lab: ${_t('reLab.tabs.cryptolab')}`,
          category: 'RE Lab',
          icon: 'key',
          keywords: 'crypto cyberchef aes sm4 chacha20 rc4 md5 sha256 protobuf dfa whitebox',
          run: () => {
            subTab = 'cryptolab'
            if (!cryptoOps.length) loadCryptoOperations()
          },
        },
      ])
    }
  }

  // ==================== Helpers ====================
  function formatHex(val) {
    if (val === null || val === undefined || val === 0 || val === '') return '—'
    if (typeof val === 'string') return val.startsWith('0x') ? val : `0x${val}`
    const n = Number(val)
    if (!Number.isFinite(n) || n === 0) return '—'
    return `0x${n.toString(16)}`
  }

  function parseAddrNumber(raw) {
    const s = String(raw || '').trim()
    if (!s) return { ok: true, value: 0 }
    const hex = s.replace(/^0[xX]/, '')
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      return { ok: false, value: 0 }
    }
    const n = Number.parseInt(hex, 16)
    if (!Number.isSafeInteger(n) || n < 0) {
      return { ok: false, value: 0 }
    }
    return { ok: true, value: n }
  }

  function engineVariant(eng) {
    switch (eng) {
      case 'unidbg': return 'accent'
      case 'qiling': return 'info'
      case 'angr': return 'purple'
      case 'radare2': return 'success'
      case 'frida': return 'warning'
      default: return 'neutral'
    }
  }

  function severityVariant(sev) {
    switch (sev) {
      case 'critical': return 'danger'
      case 'high': return 'danger'
      case 'medium': return 'warning'
      case 'low': return 'info'
      default: return 'neutral'
    }
  }

  function hardeningVariant(lvl) {
    switch (lvl) {
      case 'extreme': return 'danger'
      case 'high': return 'danger'
      case 'medium': return 'warning'
      case 'low': return 'info'
      default: return 'success'
    }
  }

  function roleVariant(role) {
    switch (role) {
      case 'lookup_table': return 'purple'
      case 'input_buffer': return 'info'
      case 'output_buffer': return 'success'
      case 'stack': return 'neutral'
      case 'state': return 'warning'
      case 'bytecode_cursor': return 'danger'
      case 'vm_stack': return 'warning'
      case 'vm_context': return 'accent'
      default: return 'neutral'
    }
  }

  function eventKindVariant(kind) {
    switch (kind) {
      case 'insn': return 'neutral'
      case 'call':
      case 'java_enter': return 'accent'
      case 'ret':
      case 'java_exit': return 'info'
      case 'mem_read': return 'success'
      case 'mem_write': return 'warning'
      case 'jni': return 'purple'
      case 'syscall': return 'danger'
      default: return 'neutral'
    }
  }

  function formatClock(ms) {
    const safe = Math.max(0, Number(ms) || 0)
    const sec = Math.floor(safe / 1000)
    return `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`
  }

  function formatEventTime(tsMs) {
    if (!tsMs) return ''
    try {
      return new Date(tsMs).toLocaleTimeString('en-US', { hour12: false })
    } catch (_) {
      return ''
    }
  }

  function splitCSV(text) {
    return String(text || '')
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  }

  function downloadTextFile(filename, content, mime = 'text/plain;charset=utf-8') {
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  function tooltipForTool(pill) {
    const info = pill.info
    if (!info) return `${pill.label}`
    if (pill.ready) {
      return `${pill.label}: ${info.version || 'OK'}${info.path ? ` (${info.path})` : ''}`
    }
    return `${pill.label}: ${info.issue || 'Missing'}${info.install ? ` — ${info.install}` : ''}`
  }

  // ==================== Toolchain Actions ====================
  async function loadToolchain(force = false) {
    const app = api()
    if (!app) return
    probingToolchain = true
    try {
      const [tc, settings] = await Promise.all([
        app.GetREToolchain?.(force).catch(() => null),
        app.GetSettings?.().catch(() => null),
      ])
      if (tc) toolchain = tc
      if (settings) {
        tcForm = {
          r2_path: settings.re_r2_path || '',
          java_path: settings.re_java_path || '',
          mvn_path: settings.re_mvn_path || '',
          unidbg_dir: settings.re_unidbg_dir || '',
          python_path: settings.re_python_path || '',
          qiling_python_path: settings.re_qiling_python_path || '',
          angr_python_path: settings.re_angr_python_path || '',
          qiling_rootfs: settings.re_qiling_rootfs || '',
        }
      }
    } finally {
      probingToolchain = false
    }
  }

  async function saveToolchainConfig() {
    const app = api()
    if (!app?.UpdateREToolchainConfig || savingToolchain) return
    savingToolchain = true
    try {
      const cleaned = {
        r2_path: tcForm.r2_path.trim(),
        java_path: tcForm.java_path.trim(),
        mvn_path: tcForm.mvn_path.trim(),
        unidbg_dir: tcForm.unidbg_dir.trim(),
        python_path: tcForm.python_path.trim(),
        qiling_python_path: tcForm.qiling_python_path.trim(),
        angr_python_path: tcForm.angr_python_path.trim(),
        qiling_rootfs: tcForm.qiling_rootfs.trim(),
      }
      toolchain = await app.UpdateREToolchainConfig(cleaned)
      toast.success(translate('reLab.toast.toolchainUpdated'))
    } catch (e) {
      toast.error(translate('reLab.toast.toolchainFailed', { err: e?.message || e }))
    } finally {
      savingToolchain = false
    }
  }

  // ==================== Sub-Tab 1 Actions: Native / r2 ====================
  async function analyzeBinary() {
    const app = api()
    const path = binaryPath.trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterBinaryFirst'))
      return
    }
    if (!app?.AnalyzeBinary || analyzingBinary) return
    analyzingBinary = true
    try {
      const res = await app.AnalyzeBinary(path)
      binaryAnalysis = res
      selectedFuncKey = ''
      functionDetail = null
      toast.success(
        translate('reLab.toast.analyzeDone', {
          name: res?.file_name || path,
          engine: res?.engine || 'analyzer',
          funcs: res?.functions?.length || 0,
          exports: res?.exports?.length || 0,
        })
      )
      // Auto-select first JNI function or first function for instant inspection
      const firstJni = (res?.functions || []).find((f) => f.is_jni)
      const firstFn = firstJni || (res?.functions || [])[0] || (res?.exports || [])[0]
      if (firstFn) {
        inspectFunction(firstFn.addr || firstFn.name, firstFn.name)
      }
    } catch (e) {
      toast.error(translate('reLab.toast.analyzeFailed', { err: e?.message || e }))
    } finally {
      analyzingBinary = false
    }
  }

  async function inspectFunction(addrOrName, displayKey = '') {
    const app = api()
    const path = binaryAnalysis?.file_path || binaryPath.trim()
    if (!app?.InspectBinaryFunction || !path || !addrOrName) return
    selectedFuncKey = displayKey || addrOrName
    inspectingFunc = true
    try {
      functionDetail = await app.InspectBinaryFunction(path, addrOrName)
      if (!functionDetail?.disasm_lines?.length && !functionDetail?.disasm && functionDetail?.pseudo_c) {
        funcViewTab = 'pseudoc'
      }
    } catch (e) {
      toast.error(translate('reLab.toast.inspectFailed', { err: e?.message || e }))
    } finally {
      inspectingFunc = false
    }
  }

  async function runR2Command(overrideCmd = '') {
    const app = api()
    const path = binaryAnalysis?.file_path || binaryPath.trim()
    const cmd = (overrideCmd || r2Cmd).trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterBinaryFirst'))
      return
    }
    if (!cmd || !app?.RunR2Command || r2Running) return
    if (overrideCmd) r2Cmd = overrideCmd
    r2Running = true
    try {
      const res = await app.RunR2Command(path, cmd)
      r2History = [
        ...r2History.slice(-29),
        {
          id: Date.now() + Math.random(),
          cmd: res?.command || cmd,
          output: res?.output || '',
          elapsed_ms: res?.elapsed_ms || 0,
          error: '',
        },
      ]
      await tick()
      if (r2ConsoleEl) r2ConsoleEl.scrollTop = r2ConsoleEl.scrollHeight
    } catch (e) {
      const errMsg = e?.message || String(e)
      r2History = [
        ...r2History.slice(-29),
        { id: Date.now() + Math.random(), cmd, output: '', elapsed_ms: 0, error: errMsg },
      ]
      toast.error(translate('reLab.toast.r2Failed', { err: errMsg }))
    } finally {
      r2Running = false
    }
  }

  async function emulateFunctionIn(engine, fnOverride = null) {
    const app = api()
    const bin = binaryAnalysis?.file_path || binaryPath.trim()
    const targetFn = fnOverride || functionDetail
    const sym = targetFn?.name || ''
    const addr = targetFn?.addr || ''
    const arch = binaryAnalysis?.arch || 'arm64'

    if (app?.GenerateREHarnessFromTrace) {
      try {
        const harness = await app.GenerateREHarnessFromTrace(engine, {
          binary_path: bin,
          so_file: bin,
          target_symbol: sym,
          target_addr: addr,
          arch,
        })
        if (harness) {
          applyGeneratedHarness(harness)
          subTab = 'emulate'
          toast.success(translate('reLab.toast.harnessGenerated', { engine, name: harness.name }))
          return
        }
      } catch (e) {
        toast.error(translate('reLab.toast.harnessFailed', { err: e?.message || e }))
      }
    }

    // Fallback: populate emulation config manually
    projId = ''
    projEngine = engine
    projName = `${engine.toUpperCase()} · ${sym || binaryAnalysis?.file_name || 'target'}`
    projBinaryPath = bin
    projTargetSymbol = sym
    projTargetAddr = addr
    projBuiltin = false
    projDirty = true
    subTab = 'emulate'
  }

  function sendBinaryToProtectionScan() {
    const path = binaryAnalysis?.file_path || binaryPath.trim()
    if (!path) return
    scanPath = path
    deobfView = 'audit'
    subTab = 'deobf'
    scanProtection()
  }

  // ---- Sub-Tab 1 Pro: iOS Mach-O / IPA & Symbol Bridge ----
  async function analyzeIOSBinary() {
    const app = api()
    const path = binaryPath.trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterBinaryFirst'))
      return
    }
    if (!app?.AnalyzeIOSBinary || analyzingIOS) return
    analyzingIOS = true
    try {
      const res = await app.AnalyzeIOSBinary(path)
      const isNewBinary = !iosReport || iosReport.file_path !== (res?.file_path || path)
      iosReport = res
      nativeMode = 'ios'
      if (isNewBinary) {
        iosTargetObjCClass = res?.objc_classes?.[0] || ''
        iosTargetObjCSelector = res?.objc_selectors?.[0] || ''
        iosTargetSymbol = ''
        iosTargetOffset = ''
      } else {
        if (res?.objc_classes?.length && !iosTargetObjCClass) {
          iosTargetObjCClass = res.objc_classes[0]
        }
        if (res?.objc_selectors?.length && !iosTargetObjCSelector) {
          iosTargetObjCSelector = res.objc_selectors[0]
        }
      }
      toast.success(
        translate('reLab.toast.iosAnalyzeDone', {
          kind: res?.file_kind || 'macho',
          name: res?.file_name || path,
          arches: res?.architectures?.length || 0,
          classes: res?.objc_classes?.length || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.iosAnalyzeFailed', { err: e?.message || e }))
    } finally {
      analyzingIOS = false
    }
  }

  function selectIOSTarget(item) {
    if (iosLeftTab === 'objc_classes') iosTargetObjCClass = item
    else if (iosLeftTab === 'objc_selectors') iosTargetObjCSelector = item
    else if (iosLeftTab === 'exports') iosTargetSymbol = item
  }

  async function generateUnidbgIOSHarness() {
    const app = api()
    if (!app?.GenerateUnidbgIOSHarness || generatingIOSHarness) return
    generatingIOSHarness = true
    try {
      const isIPA = iosReport?.file_kind === 'ipa'
      const opts = {
        class_name: 'IOSUnidbgHarness',
        bundle_id: iosReport?.info_plist?.bundle_id || '',
        binary_path: isIPA ? '' : (iosReport?.file_path || binaryPath.trim()),
        ipa_path: isIPA ? (iosReport?.file_path || binaryPath.trim()) : '',
        target_symbol: iosTargetSymbol.trim(),
        objc_class: iosTargetObjCClass.trim(),
        objc_selector: iosTargetObjCSelector.trim(),
        target_offset: iosTargetOffset.trim(),
        args: [],
      }
      const script = await app.GenerateUnidbgIOSHarness(opts)
      if (script) {
        loadScriptIntoEmulation(
          script.name || 'Unidbg iOS Harness',
          'unidbg',
          script.description || script.summary || '',
          script.code || '',
          {
            binary_path: iosReport?.file_path || binaryPath.trim(),
            target_class: opts.objc_class,
            target_method: opts.objc_selector,
            target_addr: opts.target_offset,
          }
        )
        toast.success(translate('reLab.toast.iosHarnessLoaded', { name: script.name || 'Unidbg iOS' }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingIOSHarness = false
    }
  }

  async function generateIOSStealthScript() {
    const app = api()
    if (!app?.GenerateIOSStealthScript || generatingIOSStealth) return
    generatingIOSStealth = true
    try {
      const opts = {
        bundle_id: iosReport?.info_plist?.bundle_id || '',
        target_binary: iosReport?.main_binary_name || iosReport?.file_name || '',
        bypass_ptrace: true,
        bypass_sysctl: true,
        bypass_getppid: true,
        bypass_dyld_checks: true,
        bypass_jailbreak_checks: true,
      }
      const script = await app.GenerateIOSStealthScript(opts)
      if (script) {
        sendScriptToFrida(
          script.name || 'iOS Stealth Suite',
          'anti-detect',
          script.description || script.summary || '',
          script.code || '',
          opts.bundle_id
        )
        toast.success(translate('reLab.toast.iosStealthOpened'))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingIOSStealth = false
    }
  }

  function buildCurrentSymbolBundle() {
    const byAddr = new Map()
    const addSym = (item, fallbackType) => {
      const addr = item?.addr || (item?.offset ? formatHex(item.offset) : '')
      const name = String(item?.name || '').trim()
      if (!addr || addr === '—' || !name) return
      const key = addr.toLowerCase()
      if (!byAddr.has(key)) {
        byAddr.set(key, {
          name,
          address: addr,
          size: Number(item?.size) || 0,
          signature: item?.signature || '',
          type: item?.type || fallbackType,
          comment: appliedSymbolComments[key] || '',
        })
      }
    }
    for (const fn of binaryAnalysis?.functions || []) addSym(fn, 'function')
    for (const ex of binaryAnalysis?.exports || []) addSym(ex, 'export')
    for (const fn of importedSymbolBundle?.functions || []) {
      if (fn?.address && fn?.name) {
        byAddr.set(fn.address.toLowerCase(), { ...fn })
      }
    }

    const comments = []
    const seenCmt = new Set()
    const pushCmt = (address, text, repeatable = false) => {
      const a = String(address || '').trim()
      const tx = String(text || '').trim()
      if (!a || !tx) return
      const k = `${a.toLowerCase()}:${tx}`
      if (seenCmt.has(k)) return
      seenCmt.add(k)
      comments.push({ address: a, text: tx, repeatable: Boolean(repeatable) })
    }
    for (const c of importedSymbolBundle?.comments || []) pushCmt(c.address, c.text, c.repeatable)
    for (const c of symCustomComments) pushCmt(c.address, c.text, c.repeatable)

    return {
      version: '1.0',
      binary_name:
        binaryAnalysis?.file_name ||
        iosReport?.main_binary_name ||
        iosReport?.file_name ||
        importedSymbolBundle?.binary_name ||
        (binaryPath.trim().split(/[/\\]/).pop() || 'target.so'),
      arch: binaryAnalysis?.arch || iosReport?.architectures?.[0]?.arch || importedSymbolBundle?.arch || 'arm64',
      image_base: symImageBase.trim() || '0x0',
      functions: Array.from(byAddr.values()),
      comments,
      jni_bindings: jadxLinkReport?.bindings?.length
        ? jadxLinkReport.bindings
        : (importedSymbolBundle?.jni_bindings || []),
    }
  }

  function addCustomSymbolComment() {
    const rawAddr = (symNewCmtAddr.trim() || functionDetail?.addr || '').trim()
    const text = symNewCmtText.trim()
    if (!rawAddr || !text) return
    const parsed = parseAddrNumber(rawAddr)
    if (!parsed.ok) {
      toast.warning(translate('reLab.toast.invalidHexAddr', { val: rawAddr }))
      return
    }
    const normAddr = `0x${parsed.value.toString(16)}`
    symCustomComments = [...symCustomComments, { address: normAddr, text, repeatable: false }]
    appliedSymbolComments = { ...appliedSymbolComments, [normAddr.toLowerCase()]: text }
    symNewCmtAddr = normAddr
    symNewCmtText = ''
  }

  function clearCustomSymbolComments() {
    if (!symCustomComments.length) return
    const customAddrs = new Set(symCustomComments.map((c) => String(c.address || '').toLowerCase()))
    const nextApplied = { ...appliedSymbolComments }
    for (const addr of customAddrs) {
      delete nextApplied[addr]
    }
    // Re-apply any imported annotations that may have shared an address
    for (const c of importedSymbolBundle?.comments || []) {
      if (c.address && c.text) nextApplied[c.address.toLowerCase()] = c.text
    }
    for (const fn of importedSymbolBundle?.functions || []) {
      if (fn.address && (fn.comment || fn.name) && !(fn.address.toLowerCase() in nextApplied)) {
        nextApplied[fn.address.toLowerCase()] = fn.comment ? `${fn.name}: ${fn.comment}` : fn.name
      }
    }
    symCustomComments = []
    appliedSymbolComments = nextApplied
  }

  async function exportSymbolBridge() {
    const app = api()
    if (!app?.ExportSymbolScript || exportingSymbols) return
    exportingSymbols = true
    try {
      const bundle = buildCurrentSymbolBundle()
      symExportOutput = await app.ExportSymbolScript(bundle, symExportFormat)
      toast.success(translate('reLab.toast.symExportDone', { format: symExportFormat.toUpperCase() }))
    } catch (e) {
      toast.error(translate('reLab.toast.symExportFailed', { err: e?.message || e }))
    } finally {
      exportingSymbols = false
    }
  }

  function downloadSymbolBridge() {
    if (!symExportOutput) return
    const base = (binaryAnalysis?.file_name || iosReport?.file_name || 'symbols').replace(/[^a-zA-Z0-9._-]+/g, '_')
    const ext = symExportFormat === 'json' ? 'json' : `${symExportFormat}.py`
    downloadTextFile(`${base}.${ext}`, symExportOutput)
  }

  async function importSymbolBridge() {
    const app = api()
    if (!app?.ImportSymbolBundleJSON || importingSymbols || !symImportRaw.trim()) return
    importingSymbols = true
    try {
      const bundle = await app.ImportSymbolBundleJSON(symImportRaw)
      importedSymbolBundle = bundle
      toast.success(
        translate('reLab.toast.symImportDone', {
          binary: bundle?.binary_name || 'binary',
          funcs: bundle?.functions?.length || 0,
          comments: bundle?.comments?.length || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.symImportFailed', { err: e?.message || e }))
    } finally {
      importingSymbols = false
    }
  }

  function applyImportedSymbols() {
    if (!importedSymbolBundle) return
    const nextComments = { ...appliedSymbolComments }
    let count = 0
    for (const c of importedSymbolBundle.comments || []) {
      if (c.address && c.text) {
        nextComments[c.address.toLowerCase()] = c.text
        count++
      }
    }
    for (const fn of importedSymbolBundle.functions || []) {
      if (fn.address && (fn.comment || fn.name)) {
        const key = fn.address.toLowerCase()
        nextComments[key] = fn.comment ? `${fn.name}: ${fn.comment}` : fn.name
        count++
      }
    }
    appliedSymbolComments = nextComments
    toast.success(translate('reLab.toast.symApplied', { count }))
  }

  // ==================== Sub-Tab 2 Actions: Emulation & Symbolic ====================
  async function loadProjects() {
    const app = api()
    if (!app?.ListREProjects) return
    loadingProjects = true
    try {
      const list = await app.ListREProjects('')
      projects = Array.isArray(list) ? list : []
      if (!projCode && !projName && projects.length > 0) {
        selectProject(projects[0], false)
      }
    } catch (_) {}
    finally {
      loadingProjects = false
    }
  }

  function selectProject(p, resetEd = true) {
    if (!p) return
    projId = p.id || ''
    projName = p.name || 'Untitled'
    projEngine = p.engine || 'unidbg'
    projDescription = p.description || ''
    projBinaryPath = p.binary_path || ''
    projAPKPath = p.apk_path || ''
    projTargetClass = p.target_class || ''
    projTargetMethod = p.target_method || ''
    projTargetSymbol = p.target_symbol || ''
    projTargetAddr = p.target_addr || ''
    projFindAddr = p.find_addr || ''
    projAvoidAddr = p.avoid_addr || ''
    projRootFS = p.rootfs || ''
    projArgsText = Array.isArray(p.args) ? p.args.join(' ') : ''
    projCode = p.code || ''
    projBuiltin = Boolean(p.builtin)
    projDirty = false
    if (resetEd && emuEditorRef?.resetHistory) {
      emuEditorRef.resetHistory(projCode)
    }
  }

  function createNewProject() {
    const eng = projectEngineFilter !== 'all' ? projectEngineFilter : (projEngine || 'unidbg')
    projId = ''
    projEngine = eng
    projName = `Custom ${eng.toUpperCase()} Project`
    projDescription = ''
    projBuiltin = false
    projDirty = true
    if (eng === 'unidbg') {
      projCode = `// Unidbg Harness\n// Emit structured results via: System.out.println("[CAP_RE] {\\"kind\\":\\"sign\\",\\"summary\\":\\"...\\"}");\n`
    } else if (eng === 'qiling') {
      projCode = `#!/usr/bin/env python3\nimport json\nfrom qiling import Qiling\n\n# Emit structured concrete output:\nprint("[CAP_RE] " + json.dumps({"kind": "result", "summary": "ready"}))\n`
    } else if (eng === 'angr') {
      projCode = `#!/usr/bin/env python3\nimport json, angr, claripy\n\n# Emit solved input:\nprint("[CAP_RE] " + json.dumps({"kind": "solution", "summary": "ready"}))\n`
    } else {
      projCode = `iI; afl; iz~sign\n`
    }
    emuEditorRef?.resetHistory?.(projCode)
  }

  async function saveCurrentProject() {
    const app = api()
    if (!app?.SaveREProject || savingProject) return
    savingProject = true
    try {
      const nameToSave = projName.trim() || `Untitled ${projEngine}`
      const saved = await app.SaveREProject({
        id: projBuiltin ? '' : projId,
        name: projBuiltin ? `${nameToSave} (Custom)` : nameToSave,
        engine: projEngine,
        description: projDescription,
        binary_path: projBinaryPath.trim(),
        apk_path: projAPKPath.trim(),
        target_class: projTargetClass.trim(),
        target_method: projTargetMethod.trim(),
        target_symbol: projTargetSymbol.trim(),
        target_addr: projTargetAddr.trim(),
        find_addr: projFindAddr.trim(),
        avoid_addr: projAvoidAddr.trim(),
        rootfs: projRootFS.trim(),
        args: splitCSV(projArgsText),
        code: projCode,
        builtin: false,
      })
      if (saved) {
        projId = saved.id
        projName = saved.name
        projBuiltin = false
        projDirty = false
      }
      await loadProjects()
      toast.success(translate('reLab.toast.projectSaved', { name: saved?.name || nameToSave }))
    } catch (e) {
      toast.error(translate('reLab.toast.projectSaveFailed', { err: e?.message || e }))
    } finally {
      savingProject = false
    }
  }

  async function deleteProject(p, ev) {
    ev?.stopPropagation?.()
    if (!p || p.builtin) return
    const app = api()
    if (!app?.DeleteREProject) return
    try {
      await app.DeleteREProject(p.id)
      if (projId === p.id) projId = ''
      await loadProjects()
      toast.info(translate('reLab.toast.projectDeleted', { name: p.name }))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  function applyGeneratedHarness(h) {
    if (!h) return
    const p = h.project || {}
    projId = ''
    projName = h.name || p.name || 'Generated Harness'
    projEngine = h.engine || p.engine || 'unidbg'
    projDescription = h.description || h.summary || p.description || ''
    projBinaryPath = h.binary_path || p.binary_path || projBinaryPath
    projAPKPath = h.apk_path || p.apk_path || projAPKPath
    projTargetClass = h.target_class || p.target_class || ''
    projTargetMethod = h.target_method || p.target_method || ''
    projTargetSymbol = h.target_symbol || p.target_symbol || ''
    projTargetAddr = h.target_addr || p.target_addr || ''
    projFindAddr = p.find_addr || ''
    projAvoidAddr = p.avoid_addr || ''
    projRootFS = p.rootfs || projRootFS
    projArgsText = Array.isArray(p.args) ? p.args.join(' ') : ''
    projCode = h.code || p.code || ''
    projBuiltin = false
    projDirty = true
    tick().then(() => emuEditorRef?.resetHistory?.(projCode))
  }

  async function openTraceGenDrawer() {
    showTraceGenDrawer = !showTraceGenDrawer
    if (showTraceGenDrawer) {
      try {
        deepTraceState = await api()?.GetDeepTraceState?.()
      } catch (_) {}
    }
  }

  async function generateHarnessFromTrace() {
    const app = api()
    if (!app?.GenerateREHarnessFromTrace || generatingHarness) return
    generatingHarness = true
    try {
      const harness = await app.GenerateREHarnessFromTrace(traceGenEngine, {
        binary_path: projBinaryPath.trim(),
        apk_path: projAPKPath.trim(),
        target_class: projTargetClass.trim(),
        target_method: projTargetMethod.trim(),
        target_symbol: projTargetSymbol.trim(),
        target_addr: projTargetAddr.trim(),
        find_addr: projFindAddr.trim(),
        avoid_addr: projAvoidAddr.trim(),
        rootfs: projRootFS.trim(),
        arch: traceGenArch,
        http_server_mode: traceGenEngine === 'unidbg' && traceGenHttpMode,
        http_port: Number(traceGenHttpPort) || 8899,
        input_len: Number(traceGenInputLen) || 32,
      })
      if (harness) {
        applyGeneratedHarness(harness)
        showTraceGenDrawer = false
        toast.success(translate('reLab.toast.harnessGenerated', { engine: harness.engine, name: harness.name }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.harnessFailed', { err: e?.message || e }))
    } finally {
      generatingHarness = false
    }
  }

  let retiredJobIds = new Set()

  function mergeJobEvents(existing, incoming) {
    const bySeq = new Map()
    const extras = []
    for (const ev of existing || []) {
      if (ev && ev.seq) bySeq.set(ev.seq, ev)
      else if (ev) extras.push(ev)
    }
    for (const ev of incoming || []) {
      if (ev && ev.seq) bySeq.set(ev.seq, ev)
      else if (ev) extras.push(ev)
    }
    const ordered = [...bySeq.values()].sort((a, b) => (a.seq || 0) - (b.seq || 0))
    return [...ordered, ...extras].slice(-1000)
  }

  function extractResultFromLog(ev) {
    if (!ev || (ev.stream !== 'result' && ev.level !== 'result') || !ev.data) return null
    return {
      kind: ev.data.kind || 'result',
      summary: ev.data.summary || ev.message || '',
      payload: ev.data,
    }
  }

  function mergeJobResults(existing, incoming) {
    const inc = Array.isArray(incoming) ? incoming : []
    const cur = Array.isArray(existing) ? existing : []
    if (inc.length >= cur.length) return inc
    return cur
  }

  function applyJobStatus(st, { fromStartReturn = false } = {}) {
    if (!st) return
    const prevId = jobState?.id || ''
    const nextId = st.id || ''
    if (nextId && retiredJobIds.has(nextId)) return

    const isSameJob = Boolean(jobState && nextId && prevId === nextId)

    if (!isSameJob) {
      if (prevId && nextId && prevId !== nextId) {
        retiredJobIds.add(prevId)
      }
      expandedJobEvents = new Set()
      jobState = {
        ...st,
        events: Array.isArray(st.events) ? st.events.slice(-1000) : [],
        results: Array.isArray(st.results) ? st.results : [],
      }
      return
    }

    // Same job ID reconciliation
    if (fromStartReturn) {
      // StartREJob returns an early snapshot; never downgrade live status or wipe streamed logs/results.
      const mergedEvents = mergeJobEvents(jobState.events, st.events)
      const mergedResults = mergeJobResults(jobState.results, st.results)
      const alreadyTerminal = jobState.status && jobState.status !== 'idle' && jobState.status !== 'running'
      jobState = {
        ...st,
        ...jobState,
        status: alreadyTerminal ? jobState.status : (st.status || jobState.status),
        running: alreadyTerminal ? false : Boolean(jobState.running || st.running),
        events: mergedEvents,
        results: mergedResults,
        event_count: Math.max(jobState.event_count || 0, st.event_count || 0, mergedEvents.length),
      }
      return
    }

    // Explicit clear from ClearJobLogs emits event_count === 0 with empty events & results
    const isExplicitClear =
      st.event_count === 0 &&
      (!st.events || st.events.length === 0) &&
      (!st.results || st.results.length === 0) &&
      (jobState.events?.length > 0 || jobState.results?.length > 0)

    if (isExplicitClear) {
      expandedJobEvents = new Set()
      jobState = { ...st, events: [], results: [], event_count: 0 }
      return
    }

    const mergedEvents = mergeJobEvents(jobState.events, st.events)
    const mergedResults = mergeJobResults(jobState.results, st.results)
    jobState = {
      ...st,
      events: mergedEvents,
      results: mergedResults,
      event_count: Math.max(st.event_count || 0, mergedEvents.length),
    }
  }

  function appendJobLogEvent(ev) {
    if (!ev) return
    if (ev.job_id && retiredJobIds.has(ev.job_id)) return

    const resEntry = extractResultFromLog(ev)
    const isNewJob = !jobState || (ev.job_id && jobState.id && ev.job_id !== jobState.id)

    if (isNewJob) {
      if (jobState?.id && ev.job_id && jobState.id !== ev.job_id) {
        retiredJobIds.add(jobState.id)
      }
      expandedJobEvents = new Set()
      jobState = {
        id: ev.job_id || '',
        engine: projEngine,
        status: 'running',
        running: true,
        event_count: 1,
        events: [ev],
        results: resEntry ? [resEntry] : [],
      }
      scrollJobConsole()
      return
    }

    const existingEvents = jobState.events || []
    if (ev.seq && existingEvents.some((e) => e.seq === ev.seq)) {
      return
    }
    const nextEvents = [...existingEvents, ev].slice(-1000)
    const nextResults = [...(jobState.results || [])]
    if (resEntry) {
      const sig = JSON.stringify(resEntry)
      if (!nextResults.some((r) => JSON.stringify(r) === sig)) {
        nextResults.push(resEntry)
      }
    }
    jobState = {
      ...jobState,
      id: jobState.id || ev.job_id || '',
      events: nextEvents,
      results: nextResults,
      event_count: Math.max((jobState.event_count || 0) + 1, nextEvents.length),
    }
    scrollJobConsole()
  }

  async function startREJob() {
    const app = api()
    if (!app?.StartREJob || startingJob) return
    startingJob = true
    try {
      const snap = await app.StartREJob({
        project_id: projId,
        project_name: projName.trim() || `${projEngine.toUpperCase()} Job`,
        engine: projEngine,
        code: projCode,
        binary_path: projBinaryPath.trim(),
        apk_path: projAPKPath.trim(),
        rootfs: projRootFS.trim(),
        target_symbol: projTargetSymbol.trim(),
        target_addr: projTargetAddr.trim(),
        find_addr: projFindAddr.trim(),
        avoid_addr: projAvoidAddr.trim(),
        args: splitCSV(projArgsText),
        timeout_sec: Number(projTimeoutSec) || 60,
        r2_command: projEngine === 'radare2' ? projCode.trim() : '',
      })
      applyJobStatus(snap, { fromStartReturn: true })
      toast.success(translate('reLab.toast.jobStarted', { engine: projEngine }))
    } catch (e) {
      toast.error(translate('reLab.toast.jobStartFailed', { err: e?.message || e }))
    } finally {
      startingJob = false
    }
  }

  async function cancelREJob() {
    const app = api()
    if (!app?.CancelREJob) return
    try {
      await app.CancelREJob()
      toast.info(translate('reLab.toast.jobCancelled'))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  function clearJobConsole() {
    api()?.ClearREJobLogs?.()
    if (jobState) {
      jobState = { ...jobState, events: [], results: [], event_count: 0 }
    }
    expandedJobEvents = new Set()
  }

  async function scrollJobConsole() {
    if (!jobAutoScroll) return
    await tick()
    if (jobConsoleEl) jobConsoleEl.scrollTop = jobConsoleEl.scrollHeight
  }

  function toggleJobEventExpand(seq) {
    const next = new Set(expandedJobEvents)
    if (next.has(seq)) next.delete(seq)
    else next.add(seq)
    expandedJobEvents = next
  }

  // ---- Sub-Tab 2 Pro: Auto-Stub Assistant ----
  function pullConsoleLogsForAutoStub() {
    const lines = (jobEvents || [])
      .filter((ev) => ev && (ev.stream === 'stdout' || ev.stream === 'stderr' || ev.level === 'error'))
      .map((ev) => ev.raw || ev.message || '')
      .filter(Boolean)
    autoStubRawLog = lines.join('\n')
  }

  function openAutoStubAssistant() {
    showAutoStubDrawer = !showAutoStubDrawer
    if (showAutoStubDrawer) {
      if (!autoStubRawLog.trim() && jobEvents.length > 0) {
        pullConsoleLogsForAutoStub()
      }
      if (autoStubRawLog.trim()) {
        analyzeUnidbgLog()
      }
    }
  }

  async function analyzeUnidbgLog() {
    const app = api()
    if (!app?.AnalyzeUnidbgLog || analyzingAutoStub) return
    analyzingAutoStub = true
    try {
      const diag = await app.AnalyzeUnidbgLog(autoStubRawLog)
      autoStubDiagnosis = diag
      const tabMap = {
        combined: diag?.combined_java_snippet,
        jni: diag?.abstract_jni_snippet,
        io: diag?.io_resolver_snippet,
        sysprop: diag?.sys_prop_hook_snippet,
      }
      if (!tabMap[autoStubSnippetTab]) {
        autoStubSnippetTab = 'combined'
      }
      toast.success(translate('reLab.toast.autoStubDone', { count: diag?.total_errors || 0 }))
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      analyzingAutoStub = false
    }
  }

  function appendAutoStubToEditor() {
    const snippet = (activeAutoStubSnippet || autoStubDiagnosis?.combined_java_snippet || '').trim()
    if (!snippet) return
    const cur = String(projCode || '')
    const lastBrace = cur.lastIndexOf('}')
    let nextCode
    if (lastBrace !== -1) {
      const before = cur.slice(0, lastBrace).trimEnd()
      const after = cur.slice(lastBrace)
      nextCode = `${before}\n\n    // ─── Auto-Stub Assistant Generated Methods ───\n${snippet}\n${after}`
    } else {
      nextCode = cur ? `${cur}\n\n${snippet}\n` : `${snippet}\n`
    }
    projCode = nextCode
    projDirty = true
    emuEditorRef?.replaceValue?.(nextCode, { undoable: true })
    toast.success(translate('reLab.toast.autoStubAppended'))
  }

  async function generateFridaEnvSnapshot() {
    const app = api()
    if (!app?.GenerateFridaEnvSnapshotScript || generatingEnvSnap) return
    generatingEnvSnap = true
    try {
      const pkg = autoStubPkg.trim() || stealthOpts.target_package || genTargetPkg || ''
      const script = await app.GenerateFridaEnvSnapshotScript(pkg)
      if (script) {
        sendScriptToFrida(
          script.name || 'Frida Env Snapshot',
          'trace',
          script.description || script.summary || '',
          script.code || '',
          pkg
        )
        toast.success(translate('reLab.toast.fridaSnapshotOpened'))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingEnvSnap = false
    }
  }

  // ==================== Sub-Tab 3 Actions: JADX & Java<->JNI Cross-Link ====================
  async function detectJadx() {
    const app = api()
    if (!app?.DetectJadx || probingJadx) return
    probingJadx = true
    try {
      jadxInfo = await app.DetectJadx('')
    } catch (_) {}
    finally {
      probingJadx = false
    }
  }

  async function decompileWithJadx() {
    const app = api()
    const path = jadxApkPath.trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterApkFirst'))
      return
    }
    if (!app?.DecompileAPKWithJadx || decompilingJadx) return
    decompilingJadx = true
    try {
      const ws = await app.DecompileAPKWithJadx(path, 2000)
      jadxWorkspace = ws
      jadxSelectedClass = ''
      jadxClassSource = null
      jadxSearchHits = []
      jadxLinkReport = null
      jadxLeftTab = 'classes'
      if (ws?.workspace_dir) {
        await loadJadxClasses(ws.workspace_dir)
      }
      toast.success(
        translate('reLab.toast.jadxDecompileDone', {
          mode: ws?.mode || 'jadx',
          classes: ws?.class_count || 0,
          native: ws?.native_class_count || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.jadxDecompileFailed', { err: e?.message || e }))
    } finally {
      decompilingJadx = false
    }
  }

  async function loadJadxClasses(wsDir = '') {
    const app = api()
    const dir = wsDir || jadxWorkspace?.workspace_dir
    if (!app?.ListJadxClasses || !dir) return
    try {
      const list = await app.ListJadxClasses(dir, '', 2000)
      jadxClasses = Array.isArray(list) ? list : []
      const firstNative = jadxClasses.find((c) => c.has_native)
      const pick = firstNative || jadxClasses[0]
      if (pick && !jadxSelectedClass) {
        readJadxClassSource(pick.class_name)
      }
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  async function readJadxClassSource(className) {
    const app = api()
    const dir = jadxWorkspace?.workspace_dir
    if (!app?.ReadJadxClassSource || !dir || !className) return
    jadxSelectedClass = className
    loadingJadxSource = true
    try {
      const src = await app.ReadJadxClassSource(dir, className)
      jadxClassSource = src
      tick().then(() => jadxEditorRef?.resetHistory?.(src?.source || ''))
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      loadingJadxSource = false
    }
  }

  async function searchJadxSource() {
    const app = api()
    const dir = jadxWorkspace?.workspace_dir
    const q = jadxSearchQuery.trim()
    if (!app?.SearchJadxSource || !dir || !q || searchingJadx) return
    searchingJadx = true
    try {
      const hits = await app.SearchJadxSource(dir, q, 200)
      jadxSearchHits = Array.isArray(hits) ? hits : []
      jadxLeftTab = 'search'
      toast.success(translate('reLab.toast.jadxSearchDone', { count: jadxSearchHits.length }))
    } catch (e) {
      toast.error(translate('reLab.toast.jadxSearchFailed', { err: e?.message || e }))
    } finally {
      searchingJadx = false
    }
  }

  async function linkJavaToNative() {
    const app = api()
    const dir = jadxWorkspace?.workspace_dir
    if (!app?.LinkJavaToNative || !dir || linkingJadx) return
    linkingJadx = true
    try {
      const report = await app.LinkJavaToNative(dir, jadxSoPath.trim(), jadxRegisterNativesJSON.trim())
      jadxLinkReport = report
      toast.success(
        translate('reLab.toast.jadxLinkDone', {
          total: report?.total_native_methods || 0,
          static: report?.static_count || 0,
          dynamic: report?.dynamic_count || 0,
          unresolved: report?.unresolved_count || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.jadxLinkFailed', { err: e?.message || e }))
    } finally {
      linkingJadx = false
    }
  }

  async function inspectJadxBindingInR2(binding) {
    const soPath = jadxLinkReport?.so_path || jadxSoPath.trim()
    const targetSym = binding?.native_addr || binding?.native_symbol || binding?.mangled_name || ''
    if (soPath) {
      binaryPath = soPath
    }
    nativeMode = 'r2'
    subTab = 'native'
    if (soPath && binaryAnalysis?.file_path !== soPath) {
      await analyzeBinary()
    }
    if (targetSym && (binaryAnalysis?.file_path || binaryPath.trim())) {
      inspectFunction(targetSym, binding?.native_symbol || binding?.mangled_name || targetSym)
    }
  }

  async function emulateJadxBindingInUnidbg(binding) {
    const app = api()
    const soPath = jadxLinkReport?.so_path || jadxSoPath.trim()
    const apk = jadxWorkspace?.apk_path || jadxApkPath.trim()
    const javaCls = String(binding?.java_class || '').replace(/\./g, '/')
    const javaMethod = `${binding?.java_method || ''}${binding?.java_signature || ''}`
    const sym = binding?.native_symbol || binding?.mangled_name || ''
    const addr = binding?.native_addr || ''

    if (app?.GenerateREHarnessFromTrace) {
      try {
        const harness = await app.GenerateREHarnessFromTrace('unidbg', {
          binary_path: soPath,
          so_file: soPath,
          apk_path: apk,
          target_class: javaCls,
          target_method: javaMethod,
          target_symbol: sym,
          target_addr: addr,
          arch: jadxLinkReport?.so_arch || 'arm64',
        })
        if (harness) {
          applyGeneratedHarness(harness)
          subTab = 'emulate'
          toast.success(translate('reLab.toast.harnessGenerated', { engine: 'unidbg', name: harness.name }))
          return
        }
      } catch (_) {}
    }

    projId = ''
    projEngine = 'unidbg'
    projName = `Unidbg · ${binding?.java_method || sym || 'native'}`
    projBinaryPath = soPath
    projAPKPath = apk
    projTargetClass = javaCls
    projTargetMethod = javaMethod
    projTargetSymbol = sym
    projTargetAddr = addr
    projBuiltin = false
    projDirty = true
    subTab = 'emulate'
  }

  // ==================== Sub-Tab 3 Actions: Deobf · Anti-Debug · VMP ====================
  function deriveStealthOptsFromReport(report, prevOpts, scannedPath) {
    // Mirrors deobf.StealthOptionsFromReport so UI toggles and generated scripts
    // stay 100% tailored to the latest protection audit.
    const next = {
      ...prevOpts,
      bypass_tracer_pid_and_proc_fs: true,
      bypass_ptrace_and_signals: true,
      patch_inline_svc: false,
      bypass_timing_and_inotify: false,
      bypass_java_debug_checks: true,
    }
    for (const ad of report?.anti_debug_findings || []) {
      switch (ad.kind) {
        case 'tracer_pid':
        case 'proc_maps':
        case 'frida_detect':
          next.bypass_tracer_pid_and_proc_fs = true
          break
        case 'ptrace':
        case 'watchdog_thread':
          next.bypass_ptrace_and_signals = true
          break
        case 'inline_svc':
          next.patch_inline_svc = true
          break
        case 'timing_check':
        case 'inotify':
          next.bypass_timing_and_inotify = true
          break
        case 'java_debug':
        case 'root_detect':
          next.bypass_java_debug_checks = true
          break
      }
    }

    let bestSO = ''
    let bestWeight = -1
    for (const so of report?.so_audits || []) {
      const w =
        (so.inline_svc_count || 0) * 10 +
        (so.indirect_branch_count || 0) +
        (so.suspicious_sections?.length || 0) * 5
      if (w > bestWeight) {
        bestWeight = w
        bestSO = so.name || ''
      }
    }
    if (!bestSO && report?.target_kind !== 'apk' && scannedPath) {
      const parts = scannedPath.split(/[/\\]/)
      bestSO = parts[parts.length - 1] || ''
    }
    next.target_so = bestSO
    return { nextOpts: next, bestSO }
  }

  async function scanProtection() {
    const app = api()
    const path = scanPath.trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterScanPath'))
      return
    }
    if (!app?.ScanProtection || scanningProtection) return
    scanningProtection = true
    try {
      const report = await app.ScanProtection(path)
      protectionReport = report
      deobfView = 'audit'

      // Smart pre-fill generator parameters & stealth modules from scan report
      if (report?.target_kind === 'apk') {
        genApkPath = path
      } else {
        genSoPath = path
      }
      const { nextOpts, bestSO } = deriveStealthOptsFromReport(report, stealthOpts, path)
      stealthOpts = nextOpts
      if (bestSO) {
        genVmpSoName = bestSO
      }

      toast.success(
        translate('reLab.toast.scanDone', {
          score: report?.risk_score ?? 0,
          level: report?.hardening_level || 'none',
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.scanFailed', { err: e?.message || e }))
    } finally {
      scanningProtection = false
    }
  }

  async function generateDeobfScript(overrideGenId = '') {
    const app = api()
    if (!app || generatingScript) return
    const genId = overrideGenId || selectedGenerator
    if (overrideGenId) {
      selectedGenerator = overrideGenId
      deobfView = 'scripts'
    }
    generatingScript = true
    try {
      let res = null
      if (genId === 'stealth') {
        if (overrideGenId === 'stealth' && protectionReport) {
          stealthUseReport = true
          const { nextOpts, bestSO } = deriveStealthOptsFromReport(protectionReport, stealthOpts, scanPath)
          stealthOpts = nextOpts
          if (bestSO) genVmpSoName = bestSO
        }
        const opts = {
          ...stealthOpts,
          watchdog_block_offsets: splitCSV(stealthWatchdogOffsets),
          custom_hide_tokens: splitCSV(stealthCustomTokens),
        }
        res = await app.GenerateStealthScript?.(opts, stealthUseReport ? protectionReport : null)
      } else if (genId === 'unpack') {
        res = await app.GenerateDexUnpackerScript?.(genTargetPkg.trim())
      } else if (genId === 'ollvm') {
        res = await app.GenerateOLLVMDeflattenScript?.(genSoPath.trim(), genFuncAddr.trim(), genArch)
      } else if (genId === 'string_decrypt') {
        res = await app.GenerateStringDecryptScript?.(genStrEngine, genSoPath.trim(), genApkPath.trim())
      } else if (genId === 'java_deobf') {
        res = await app.GenerateJavaDeobfScript?.(genTargetPkg.trim())
      } else if (genId === 'vmp_stalker') {
        res = await app.GenerateVMPStalkerScript?.(genVmpSoName.trim(), genVmpEntry.trim(), Number(genVmpMaxEvents) || 50000)
      } else if (genId === 'vmp_jni') {
        res = await app.GenerateVMPRegisterNativesScript?.(genTargetPkg.trim())
      } else if (genId === 'vmp_unidbg') {
        res = await app.GenerateUnidbgVMPTraceScript?.(
          genApkPath.trim(),
          genVmpSoName.trim(),
          genVmpClassName.trim(),
          genVmpMethodName.trim()
        )
      }
      if (res) {
        generatedScript = res
        deobfEditorRef?.resetHistory?.(res.code || '')
        toast.success(translate('reLab.toast.scriptGenerated', { name: res.name || genId }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingScript = false
    }
  }

  function sendScriptToFrida(name, category, description, code, targetPkg = '') {
    openFridaStudio({
      target: targetPkg || stealthOpts.target_package || genTargetPkg || '',
      scriptName: name || 'RE Lab Script',
      scriptCategory: category || 'native',
      scriptDescription: description || '',
      scriptCode: code || '',
    })
  }

  function loadScriptIntoEmulation(name, engine, description, code, extra = {}) {
    projId = ''
    projName = name || 'Generated RE Script'
    projEngine = engine || 'angr'
    projDescription = description || ''
    projCode = code || ''
    if (extra.binary_path) projBinaryPath = extra.binary_path
    if (extra.apk_path) projAPKPath = extra.apk_path
    if (extra.target_addr) projTargetAddr = extra.target_addr
    if (extra.target_class) projTargetClass = extra.target_class
    if (extra.target_method) projTargetMethod = extra.target_method
    if (extra.rootfs) projRootFS = extra.rootfs
    projBuiltin = false
    projDirty = true
    subTab = 'emulate'
    tick().then(() => emuEditorRef?.resetHistory?.(projCode))
    toast.success(translate('reLab.toast.loadedIntoEmulation', { name: projName, engine: projEngine }))
  }

  async function analyzeVmpTrace() {
    const app = api()
    if (!app?.AnalyzeVMPTrace || analyzingVmpTrace) return
    analyzingVmpTrace = true
    try {
      const res = await app.AnalyzeVMPTrace(vmpTraceRaw, vmpTraceBaseHex.trim())
      vmpTraceAnalysis = res
      toast.success(
        translate('reLab.toast.vmpAnalyzed', {
          insns: res?.total_instructions || 0,
          dispatchers: res?.dispatcher_candidates?.length || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.vmpAnalyzeFailed', { err: e?.message || e }))
    } finally {
      analyzingVmpTrace = false
    }
  }

  // ---- Sub-Tab 4 Pro: TLS / APK Certs / mTLS / Local-Proxy Compat ----
  async function loadTlsEnvironment() {
    const app = api()
    if (!app || loadingTlsProfiles) return
    loadingTlsProfiles = true
    try {
      const [profiles, curlInfo] = await Promise.all([
        app.ListTLSProfiles?.().catch(() => []),
        app.DetectCurlImpersonate?.().catch(() => null),
      ])
      if (Array.isArray(profiles) && profiles.length > 0) {
        tlsProfiles = profiles
        if (!tlsSelectedProfileId || !profiles.some((p) => p.id === tlsSelectedProfileId)) {
          tlsSelectedProfileId = profiles[0].id
        }
        await selectTlsProfile(tlsSelectedProfileId)
      }
      if (curlInfo) tlsCurlInfo = curlInfo
    } finally {
      loadingTlsProfiles = false
    }
  }

  let tlsJa3ReqSeq = 0

  async function selectTlsProfile(profileId) {
    tlsSelectedProfileId = profileId
    const reqId = ++tlsJa3ReqSeq
    if (tlsProfileJA3?.profile_id !== profileId) {
      tlsProfileJA3 = null
    }
    const app = api()
    if (!app?.ComputeTLSProfileJA3 || !profileId) return
    try {
      const res = await app.ComputeTLSProfileJA3(profileId)
      if (reqId === tlsJa3ReqSeq && tlsSelectedProfileId === profileId) {
        tlsProfileJA3 = res
      }
    } catch (_) {}
  }

  async function scanApkCertificates() {
    const app = api()
    const path = tlsApkPath.trim() || scanPath.trim()
    if (!path) {
      toast.warning(translate('reLab.toast.enterApkFirst'))
      return
    }
    if (!tlsApkPath.trim()) tlsApkPath = path
    if (!app?.ScanAPKForCertificates || scanningTlsCerts) return
    scanningTlsCerts = true
    try {
      const rep = await app.ScanAPKForCertificates(path)
      tlsCertReport = rep
      toast.success(
        translate('reLab.toast.tlsCertScanDone', {
          certs: rep?.certificates?.length || 0,
          pins: rep?.pins?.length || 0,
          keystores: rep?.keystores?.length || 0,
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.tlsCertScanFailed', { err: e?.message || e }))
    } finally {
      scanningTlsCerts = false
    }
  }

  async function validateMtlsKeyPair() {
    const app = api()
    if (!app?.ValidateMTLSKeyPair || validatingMtls) return
    validatingMtls = true
    try {
      const res = await app.ValidateMTLSKeyPair(tlsMtlsCertPath.trim(), tlsMtlsKeyPath.trim())
      tlsMtlsResult = res
      toast.success(
        translate('reLab.toast.mtlsValidateDone', {
          status: res?.valid ? 'VALID' : 'INVALID',
        })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.mtlsValidateFailed', { err: e?.message || e }))
    } finally {
      validatingMtls = false
    }
  }

  async function generateTlsCompatScript() {
    const app = api()
    if (!app || generatingTlsScript) return
    generatingTlsScript = true
    try {
      let res = null
      if (tlsCompatKind === 'flutter') {
        res = await app.GenerateFlutterProxyDebugScript?.({
          ...tlsFlutterOpts,
          proxy_port: Number(tlsFlutterOpts.proxy_port) || 8080,
        })
      } else if (tlsCompatKind === 'cronet') {
        res = await app.GenerateCronetHTTP2Script?.({ ...tlsCronetOpts })
      } else {
        res = await app.GenerateMTLSObserverScript?.({
          ...tlsMtlsObsOpts,
          max_aliases_per_store: Number(tlsMtlsObsOpts.max_aliases_per_store) || 32,
        })
      }
      if (res) {
        tlsGeneratedScript = res
        tlsEditorRef?.resetHistory?.(res.code || '')
        toast.success(translate('reLab.toast.tlsCompatGenerated', { name: res.name || tlsCompatKind }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingTlsScript = false
    }
  }

  // ==================== Sub-Tab 4 Actions: ExecTrace & Taint ====================
  async function loadExecTraces() {
    const app = api()
    if (!app?.ListExecTraces) return
    loadingTraces = true
    try {
      const list = await app.ListExecTraces()
      traceSessions = Array.isArray(list) ? list : []
      if (selectedTraceId && traceSessions.some((s) => s.id === selectedTraceId)) {
        if (!activeTrace || activeTrace.id !== selectedTraceId) {
          await selectTraceSession(selectedTraceId)
        }
      } else if (traceSessions.length > 0 && !selectedTraceId) {
        await selectTraceSession(traceSessions[0].id)
      }
      if (!diffSessionA && traceSessions.length >= 1) diffSessionA = traceSessions[0].id
      if (!diffSessionB && traceSessions.length >= 2) diffSessionB = traceSessions[1].id
    } catch (_) {}
    finally {
      loadingTraces = false
    }
  }

  async function selectTraceSession(id) {
    const app = api()
    if (!app?.GetExecTrace || !id) return
    selectedTraceId = id
    selectedEventRow = null
    eventOffset = 0
    taintResult = null
    try {
      activeTrace = await app.GetExecTrace(id)
      await queryTraceEvents(0)
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  async function importTrace() {
    const app = api()
    if (!app || importingTrace) return
    importingTrace = true
    try {
      let sess = null
      if (importMode === 'file') {
        sess = await app.ImportExecTraceFile?.(importFilePath.trim(), importFormat, importBaseHex.trim())
      } else {
        sess = await app.ImportExecTrace?.(
          importName.trim() || `trace-${new Date().toISOString().slice(11, 19)}`,
          importFormat,
          importRawContent,
          importBaseHex.trim()
        )
      }
      if (sess) {
        showImportDrawer = false
        importRawContent = ''
        await loadExecTraces()
        await selectTraceSession(sess.id)
        traceViewTab = 'overview'
        toast.success(
          translate('reLab.toast.traceImported', {
            name: sess.name || sess.id,
            events: sess.total_events || 0,
          })
        )
      }
    } catch (e) {
      toast.error(translate('reLab.toast.traceImportFailed', { err: e?.message || e }))
    } finally {
      importingTrace = false
    }
  }

  async function deleteTraceSession(sess, ev) {
    ev?.stopPropagation?.()
    const app = api()
    if (!app?.DeleteExecTrace || !sess?.id) return
    try {
      await app.DeleteExecTrace(sess.id)
      if (selectedTraceId === sess.id) {
        selectedTraceId = ''
        activeTrace = null
        eventPage = null
      }
      if (diffSessionA === sess.id || diffSessionB === sess.id) {
        if (diffSessionA === sess.id) diffSessionA = ''
        if (diffSessionB === sess.id) diffSessionB = ''
        diffResult = null
      }
      await loadExecTraces()
      toast.info(translate('reLab.toast.traceDeleted', { name: sess.name || sess.id }))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  async function queryTraceEvents(newOffset = 0) {
    const app = api()
    if (!app?.QueryExecTraceEvents || !selectedTraceId) return
    const parsedAddr = parseAddrNumber(eventFilterAddr)
    if (!parsedAddr.ok) {
      toast.warning(translate('reLab.toast.invalidHexAddr', { val: eventFilterAddr }))
      return
    }
    loadingEvents = true
    eventOffset = Math.max(0, newOffset)
    try {
      eventPage = await app.QueryExecTraceEvents(selectedTraceId, {
        offset: eventOffset,
        limit: Number(eventPageSize) || 150,
        kind: eventFilterKind,
        address: parsedAddr.value,
        search: eventFilterSearch.trim(),
      })
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      loadingEvents = false
    }
  }

  function seedTaintFromEvent(ev, direction = 'backward', specificReg = '', specificMem = '') {
    if (!ev) return
    taintDirection = direction
    taintStartSeq = ev.seq || 1
    if (specificReg) {
      taintSeedReg = specificReg
      taintSeedMemAddr = ''
    } else if (specificMem) {
      taintSeedMemAddr = specificMem
      taintSeedReg = ''
    } else {
      const regKeys = Object.keys(ev.regs_after || ev.regs_before || {})
      if (ev.mem_addr) {
        taintSeedMemAddr = formatHex(ev.mem_addr)
        taintSeedReg = ''
        taintSeedValueHex = ev.mem_value_hex || ''
      } else if (regKeys.length > 0) {
        taintSeedReg = regKeys[0]
        taintSeedMemAddr = ''
        taintSeedValueHex = ''
      } else {
        // Attempt to extract first register token from operands (e.g. "x0, x1, #4")
        const m = (ev.operands || '').match(/\b([xwr]\d+|sp|lr|rax|rbx|rcx|rdx|rsi|rdi|eax|ebx|ecx|edx)\b/i)
        taintSeedReg = m ? m[1].toLowerCase() : 'x0'
        taintSeedMemAddr = ''
      }
    }
    traceViewTab = 'taint'
  }

  function seedTaintFromCryptoHit(hit) {
    if (!hit) return
    const ev = (activeTrace?.events || []).find((e) => e.seq === hit.seq)
    if (ev) {
      seedTaintFromEvent(ev, 'backward')
      return
    }
    taintDirection = 'backward'
    taintStartSeq = hit.seq || 1
    taintSeedReg = ''
    taintSeedMemAddr = ''
    taintSeedValueHex = ''
    traceViewTab = 'taint'
  }

  function seedTaintFromMemRegion(mr) {
    if (!mr || !activeTrace) return
    const dir = mr.role_hint === 'input_buffer' ? 'forward' : 'backward'
    const evs = activeTrace.events || []
    const firstSeq = evs.length > 0 ? (evs[0].seq || 1) : 1
    const lastSeq =
      evs.length > 0
        ? (evs[evs.length - 1].seq || activeTrace.total_events || 1)
        : (activeTrace.total_events || 1)
    taintDirection = dir
    taintStartSeq = dir === 'forward' ? firstSeq : lastSeq
    taintSeedReg = ''
    taintSeedMemAddr = mr.base_addr_hex || formatHex(mr.base_addr)
    taintSeedValueHex = ''
    traceViewTab = 'taint'
  }

  async function runTaintAnalysis() {
    const app = api()
    if (!app?.RunExecTraceTaint || !selectedTraceId || runningTaint) return
    const parsedMem = parseAddrNumber(taintSeedMemAddr)
    if (!parsedMem.ok) {
      toast.warning(translate('reLab.toast.invalidHexAddr', { val: taintSeedMemAddr }))
      return
    }
    runningTaint = true
    try {
      taintResult = await app.RunExecTraceTaint({
        session_id: selectedTraceId,
        direction: taintDirection,
        start_seq: Number(taintStartSeq) || 1,
        seed_reg: taintSeedReg.trim(),
        seed_mem_addr: parsedMem.value,
        seed_value_hex: taintSeedValueHex.trim(),
        max_steps: Number(taintMaxSteps) || 5000,
      })
      toast.success(
        translate('reLab.toast.taintDone', { steps: taintResult?.tainted_steps?.length || 0 })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.taintFailed', { err: e?.message || e }))
    } finally {
      runningTaint = false
    }
  }

  async function runTraceDiff() {
    const app = api()
    if (!app?.DiffExecTraces || !diffSessionA || !diffSessionB || runningDiff) return
    runningDiff = true
    try {
      diffResult = await app.DiffExecTraces(diffSessionA, diffSessionB, Number(diffMaxDivergences) || 25)
      toast.success(
        translate('reLab.toast.diffDone', { prefix: diffResult?.common_prefix_len ?? 0 })
      )
    } catch (e) {
      toast.error(translate('reLab.toast.diffFailed', { err: e?.message || e }))
    } finally {
      runningDiff = false
    }
  }

  async function generateCollector() {
    const app = api()
    if (!app?.GenerateExecTraceCollector || generatingCollector) return
    generatingCollector = true
    try {
      generatedCollector = await app.GenerateExecTraceCollector(collectorKind, {
        ...collectorCfg,
        max_events: Number(collectorCfg.max_events) || 50000,
      })
      toast.success(translate('reLab.toast.collectorGenerated', { kind: collectorKind }))
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      generatingCollector = false
    }
  }

  async function exportCurrentTrace(format) {
    const app = api()
    if (!app?.ExportExecTrace || !selectedTraceId) return
    try {
      const content = await app.ExportExecTrace(selectedTraceId, format)
      const ext = format === 'markdown' ? 'md' : format === 'jsonl' ? 'jsonl' : 'tenet.txt'
      const slug = (activeTrace?.name || selectedTraceId).replace(/[^a-zA-Z0-9._-]+/g, '_')
      downloadTextFile(`${slug}.${ext}`, content)
      toast.success(translate('reLab.toast.exportedTrace', { format: format.toUpperCase() }))
    } catch (e) {
      toast.error(translate('reLab.toast.exportFailed', { err: e?.message || e }))
    }
  }

  function toggleCallNode(nodeId) {
    const next = new Set(collapsedCallNodes)
    if (next.has(nodeId)) next.delete(nodeId)
    else next.add(nodeId)
    collapsedCallNodes = next
  }

  // ==================== Sub-Tab 6 Actions: CryptoLab (Pipeline · Protobuf · DFA) ====================
  async function loadCryptoOperations() {
    const app = api()
    if (!app?.ListCryptoOperations || loadingCryptoOps) return
    loadingCryptoOps = true
    try {
      const list = await app.ListCryptoOperations()
      cryptoOps = Array.isArray(list) ? list : []
    } catch (_) {}
    finally {
      loadingCryptoOps = false
    }
  }

  function addCryptoStep(opSpec) {
    if (!opSpec) return
    const params = {}
    for (const p of opSpec.params || []) {
      params[p.name] = p.default !== undefined && p.default !== null ? String(p.default) : ''
    }
    cryptoSteps = [
      ...cryptoSteps,
      {
        uid: `${opSpec.name}_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        op: opSpec.name,
        params,
        disabled: false,
      },
    ]
  }

  function removeCryptoStep(idx) {
    cryptoSteps = cryptoSteps.filter((_, i) => i !== idx)
  }

  function moveCryptoStep(idx, dir) {
    const target = idx + dir
    if (target < 0 || target >= cryptoSteps.length) return
    const next = [...cryptoSteps]
    const [item] = next.splice(idx, 1)
    next.splice(target, 0, item)
    cryptoSteps = next
  }

  function toggleCryptoStep(idx) {
    cryptoSteps = cryptoSteps.map((s, i) => (i === idx ? { ...s, disabled: !s.disabled } : s))
  }

  function updateCryptoStepParam(idx, paramName, val) {
    cryptoSteps = cryptoSteps.map((s, i) =>
      i === idx
        ? { ...s, params: { ...(s.params || {}), [paramName]: String(val ?? '') } }
        : s
    )
  }

  async function runCryptoPipeline() {
    const app = api()
    if (!app?.RunCryptoPipeline || runningCrypto) return
    runningCrypto = true
    try {
      const stepsPayload = cryptoSteps.map((s) => {
        const cleanParams = {}
        for (const [k, v] of Object.entries(s.params || {})) {
          cleanParams[k] = String(v ?? '')
        }
        return {
          op: s.op,
          params: cleanParams,
          disabled: Boolean(s.disabled),
        }
      })
      const res = await app.RunCryptoPipeline({
        input: cryptoInput,
        input_encoding: cryptoInputEncoding,
        steps: stepsPayload,
      })
      cryptoResult = res
      if (res && !res.success && res.error) {
        toast.error(translate('reLab.toast.cryptoRunFailed', { err: res.error }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.cryptoRunFailed', { err: e?.message || e }))
    } finally {
      runningCrypto = false
    }
  }

  async function identifyCryptoPayload() {
    const app = api()
    if (!app?.IdentifyCryptoPayload || identifyingCrypto || !cryptoInput.trim()) return
    identifyingCrypto = true
    try {
      const res = await app.IdentifyCryptoPayload(cryptoInput)
      cryptoIdentify = res
      toast.success(
        translate('reLab.toast.cryptoIdentified', {
          count: res?.candidates?.length || 0,
          entropy: (res?.entropy || 0).toFixed(2),
        })
      )
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      identifyingCrypto = false
    }
  }

  async function applyCryptoRecipe(recipe) {
    if (!recipe) return
    if (recipe.input_encoding) {
      cryptoInputEncoding = recipe.input_encoding
    }
    cryptoSteps = (recipe.steps || []).map((st, idx) => {
      const spec = cryptoOpByName[st.op]
      const defaults = {}
      for (const p of spec?.params || []) {
        defaults[p.name] = p.default !== undefined && p.default !== null ? String(p.default) : ''
      }
      const merged = { ...defaults }
      for (const [k, v] of Object.entries(st.params || {})) {
        merged[k] = String(v ?? '')
      }
      return {
        uid: `${st.op}_${Date.now()}_${idx}`,
        op: st.op,
        params: merged,
        disabled: Boolean(st.disabled),
      }
    })
    await runCryptoPipeline()
  }

  function swapCryptoOutputToInput() {
    if (!cryptoResult) return
    if (cryptoOutputTab === 'hex') {
      cryptoInput = cryptoResult.output_hex || ''
      cryptoInputEncoding = 'hex'
    } else if (cryptoOutputTab === 'base64') {
      cryptoInput = cryptoResult.output_base64 || ''
      cryptoInputEncoding = 'base64'
    } else {
      cryptoInput = cryptoResult.output_utf8 || ''
      cryptoInputEncoding = 'utf8'
    }
  }

  function toggleCryptoStepTrace(idx) {
    const next = new Set(expandedCryptoSteps)
    if (next.has(idx)) next.delete(idx)
    else next.add(idx)
    expandedCryptoSteps = next
  }

  // ---- Protobuf Wire Inspector ----
  async function decodeProtobuf() {
    const app = api()
    if (!app?.DecodeProtobufRawHex || decodingProto || !protoInput.trim()) return
    decodingProto = true
    try {
      const tree = await app.DecodeProtobufRawHex(protoInput.trim())
      protoTree = tree
      protoEncodedHex = ''
      collapsedProtoNodes = new Set()
      toast.success(translate('reLab.toast.protoDecodeDone', { count: tree?.fields?.length || 0 }))
    } catch (e) {
      toast.error(translate('reLab.toast.protoDecodeFailed', { err: e?.message || e }))
    } finally {
      decodingProto = false
    }
  }

  function sanitizeProtoMessageForEncode(msg) {
    if (!msg || !Array.isArray(msg.fields)) {
      return { fields: [], byte_len: 0 }
    }
    const cleanNum = (v, isFloat = false) => {
      if (v === null || v === undefined || v === '') return undefined
      const s = String(v).trim()
      if (!s || s === '-' || s === '+' || s === '.' || s === '-.' || s === '+.') return undefined
      const n = isFloat ? Number.parseFloat(s) : Number.parseInt(s, 10)
      return Number.isFinite(n) ? n : undefined
    }
    const fields = msg.fields.map((f) => {
      const hasDraft = f._draft !== undefined
      const out = {
        field_number: Math.max(1, Number.parseInt(String(f.field_number || 1), 10) || 1),
        wire_type: Number(f.wire_type ?? 0),
        wire_type_name: f.wire_type_name || '',
        kind: f.kind || 'varint',
      }
      if (out.wire_type === 0) {
        if (out.kind === 'sint64') out.varint_s64 = (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.varint_s64) ?? 0
        else if (out.kind === 'int64') out.varint_i64 = (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.varint_i64) ?? 0
        else out.varint_u64 = Math.max(0, (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.varint_u64) ?? 0)
      } else if (out.wire_type === 1) {
        if (out.kind === 'double') out.double_val = (hasDraft ? cleanNum(f._draft, true) : undefined) ?? cleanNum(f.double_val, true) ?? 0
        else if (out.kind === 'sfixed64') out.fixed64_s = (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.fixed64_s) ?? 0
        else out.fixed64_u = Math.max(0, (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.fixed64_u) ?? 0)
      } else if (out.wire_type === 5) {
        if (out.kind === 'float') out.float_val = (hasDraft ? cleanNum(f._draft, true) : undefined) ?? cleanNum(f.float_val, true) ?? 0
        else if (out.kind === 'sfixed32') out.fixed32_s = (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.fixed32_s) ?? 0
        else out.fixed32_u = Math.max(0, (hasDraft ? cleanNum(f._draft) : undefined) ?? cleanNum(f.fixed32_u) ?? 0)
      } else if (out.wire_type === 2) {
        if (out.kind === 'message') {
          out.nested = sanitizeProtoMessageForEncode(f.nested || { fields: [] })
        } else if (out.kind === 'bytes') {
          out.bytes_hex = String(hasDraft ? f._draft : (f.bytes_hex || ''))
        } else {
          out.string_val = String(hasDraft ? f._draft : (f.string_val ?? ''))
        }
      }
      return out
    })
    return { fields, byte_len: msg.byte_len || 0 }
  }

  async function encodeProtobuf() {
    const app = api()
    if (!app?.EncodeProtobufRawHex || !protoTree || encodingProto) return
    encodingProto = true
    try {
      const payload = sanitizeProtoMessageForEncode(protoTree)
      const hexOut = await app.EncodeProtobufRawHex(payload)
      protoEncodedHex = hexOut || ''
      toast.success(translate('reLab.toast.protoEncodeDone', { bytes: Math.floor(protoEncodedHex.length / 2) }))
    } catch (e) {
      toast.error(translate('reLab.toast.protoEncodeFailed', { err: e?.message || e }))
    } finally {
      encodingProto = false
    }
  }

  function protoFieldDisplayValue(field) {
    if (!field) return ''
    if (field._draft !== undefined) return String(field._draft)
    if (field.wire_type === 0) {
      if (field.kind === 'sint64') return String(field.varint_s64 ?? 0)
      if (field.kind === 'int64') return String(field.varint_i64 ?? 0)
      return String(field.varint_u64 ?? 0)
    }
    if (field.wire_type === 1) {
      if (field.kind === 'double') return String(field.double_val ?? 0)
      if (field.kind === 'sfixed64') return String(field.fixed64_s ?? 0)
      return String(field.fixed64_u ?? 0)
    }
    if (field.wire_type === 5) {
      if (field.kind === 'float') return String(field.float_val ?? 0)
      if (field.kind === 'sfixed32') return String(field.fixed32_s ?? 0)
      return String(field.fixed32_u ?? 0)
    }
    if (field.kind === 'bytes') return String(field.bytes_hex ?? '')
    return String(field.string_val ?? '')
  }

  function updateProtoFieldValue(field, rawVal) {
    if (!field) return
    const str = String(rawVal ?? '')
    field._draft = str
    const trimmed = str.trim()
    const isInt = /^[+-]?\d+$/.test(trimmed)
    const isFloat = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(trimmed)
    if (field.wire_type === 0) {
      if (isInt) {
        const n = Number.parseInt(trimmed, 10)
        if (Number.isFinite(n)) {
          if (field.kind === 'sint64') field.varint_s64 = n
          else if (field.kind === 'int64') field.varint_i64 = n
          else field.varint_u64 = Math.max(0, n)
        }
      }
    } else if (field.wire_type === 1) {
      if (field.kind === 'double') {
        if (isFloat) {
          const f = Number.parseFloat(trimmed)
          if (Number.isFinite(f)) field.double_val = f
        }
      } else if (isInt) {
        const n = Number.parseInt(trimmed, 10)
        if (Number.isFinite(n)) {
          if (field.kind === 'sfixed64') field.fixed64_s = n
          else field.fixed64_u = Math.max(0, n)
        }
      }
    } else if (field.wire_type === 5) {
      if (field.kind === 'float') {
        if (isFloat) {
          const f = Number.parseFloat(trimmed)
          if (Number.isFinite(f)) field.float_val = f
        }
      } else if (isInt) {
        const n = Number.parseInt(trimmed, 10)
        if (Number.isFinite(n)) {
          if (field.kind === 'sfixed32') field.fixed32_s = n
          else field.fixed32_u = Math.max(0, n)
        }
      }
    } else if (field.wire_type === 2) {
      if (field.kind === 'bytes') field.bytes_hex = str
      else field.string_val = str
    }
    protoTree = protoTree
  }

  function updateProtoFieldKind(field, nextKind) {
    if (!field) return
    delete field._draft
    field.kind = nextKind
    if (field.wire_type === 2 && nextKind === 'message' && !field.nested) {
      field.nested = { fields: [], byte_len: 0 }
    }
    protoTree = protoTree
  }

  function addProtoField(targetMsg = null) {
    if (!protoTree) {
      protoTree = { fields: [], byte_len: 0 }
    }
    const container = targetMsg || protoTree
    if (!Array.isArray(container.fields)) container.fields = []
    const maxNum = container.fields.reduce((m, f) => Math.max(m, Number(f.field_number) || 0), 0)
    container.fields.push({
      field_number: maxNum + 1,
      wire_type: 2,
      wire_type_name: 'length_delimited',
      kind: 'string',
      string_val: '',
      bytes_hex: '',
    })
    protoTree = protoTree
  }

  function removeProtoField(parentMsg, indexInParent) {
    if (!parentMsg || !Array.isArray(parentMsg.fields)) return
    parentMsg.fields.splice(indexInParent, 1)
    protoTree = protoTree
  }

  function toggleProtoCollapse(pathKey) {
    const next = new Set(collapsedProtoNodes)
    if (next.has(pathKey)) next.delete(pathKey)
    else next.add(pathKey)
    collapsedProtoNodes = next
  }

  // ---- White-Box AES-128 Round-9 DFA ----
  async function solveAes128Dfa() {
    const app = api()
    if (!app?.SolveAES128DFA || solvingDfa) return
    solvingDfa = true
    try {
      const res = await app.SolveAES128DFA({
        valid_ciphertext_hex: dfaValidHex.trim(),
        faulty_ciphertexts_hex: dfaFaultLines,
        plaintext_hex: dfaPlaintextHex.trim(),
      })
      dfaResult = res
      if (res?.solved) {
        toast.success(translate('reLab.toast.dfaSolved', { key: res.master_key_hex }))
      } else {
        const solvedCols = (res?.columns || []).filter((c) => c.solved).length
        toast.info(translate('reLab.toast.dfaPartial', { solved: solvedCols }))
      }
    } catch (e) {
      toast.error(translate('reLab.toast.dfaFailed', { err: e?.message || e }))
    } finally {
      solvingDfa = false
    }
  }

  async function generateDfaScript() {
    const app = api()
    if (!app?.GenerateDFAFaultScript || generatingDfaScript) return
    generatingDfaScript = true
    try {
      const xorVal = Math.max(1, Math.min(255, Number(dfaScriptCfg.fault_xor) || 1))
      const fpbVal = Math.max(1, Math.min(32, Number(dfaScriptCfg.faults_per_byte) || 2))
      const script = await app.GenerateDFAFaultScript(dfaScriptEngine, {
        ...dfaScriptCfg,
        plaintext_hex: dfaScriptCfg.plaintext_hex || dfaPlaintextHex.trim(),
        fault_xor: xorVal,
        faults_per_byte: fpbVal,
      })
      dfaGeneratedScript = script
      toast.success(translate('reLab.toast.dfaScriptGenerated', { engine: dfaScriptEngine }))
    } catch (e) {
      toast.error(translate('reLab.toast.scriptGenFailed', { err: e?.message || e }))
    } finally {
      generatingDfaScript = false
    }
  }

  function loadDfaScriptIntoEmulation() {
    if (!dfaGeneratedScript) return
    loadScriptIntoEmulation(
      dfaGeneratedScript.title || `AES-128 DFA (${dfaGeneratedScript.engine})`,
      dfaGeneratedScript.engine || dfaScriptEngine,
      dfaGeneratedScript.description || '',
      dfaGeneratedScript.code || '',
      {
        binary_path: dfaScriptCfg.binary_path,
        apk_path: dfaScriptCfg.apk_path,
        target_class: dfaScriptCfg.target_class,
        target_method: dfaScriptCfg.target_method,
        target_addr: dfaScriptCfg.target_addr,
        rootfs: dfaScriptCfg.rootfs,
      }
    )
  }

  // ==================== Events, Handoff & Lifecycle ====================
  function applyHandoff(h) {
    if (!h) return
    if (h.subTab) subTab = h.subTab
    if (h.binaryPath) {
      binaryPath = h.binaryPath
      projBinaryPath = h.binaryPath
      if (!genSoPath) genSoPath = h.binaryPath
      if (!jadxSoPath) jadxSoPath = h.binaryPath
    }
    if (h.apkPath) {
      projAPKPath = h.apkPath
      if (!genApkPath) genApkPath = h.apkPath
      if (!jadxApkPath) jadxApkPath = h.apkPath
      if (!tlsApkPath) tlsApkPath = h.apkPath
    }
    if (h.engine) projEngine = h.engine
    if (h.scanPath) {
      scanPath = h.scanPath
      deobfView = 'audit'
    }
    if (h.generatedHarness) {
      applyGeneratedHarness(h.generatedHarness)
    }
    reLabHandoff.set(null)
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return
    const on = (name, fn) => {
      const off = rt.EventsOn(name, fn)
      if (typeof off === 'function') unsubs.push(off)
    }
    on('re:log', (ev) => {
      appendJobLogEvent(ev)
    })
    on('re:status', (st) => {
      applyJobStatus(st)
    })
  }

  function handleKeydown(e) {
    if (!hasPrimaryMod(e)) return
    const k = e.key.toLowerCase()
    if (subTab === 'emulate') {
      if (k === 's') {
        e.preventDefault()
        saveCurrentProject()
      } else if (k === 'enter' && !isJobRunning) {
        e.preventDefault()
        startREJob()
      }
    }
  }

  onMount(async () => {
    subscribeEvents()
    unsubHandoff = reLabHandoff.subscribe((h) => {
      if (h) applyHandoff(h)
    })
    const app = api()
    await Promise.all([
      loadToolchain(false),
      loadProjects(),
      loadExecTraces(),
      detectJadx(),
      loadCryptoOperations(),
      app?.GetREJobState?.().then((st) => { if (st) applyJobStatus(st) }).catch(() => {}),
    ])
    if (subTab === 'deobf' && deobfView === 'tls' && !tlsProfiles.length) {
      loadTlsEnvironment()
    }
    if (projCode && emuEditorRef?.resetHistory) {
      emuEditorRef.resetHistory(projCode)
    }
    clockTimer = setInterval(() => {
      if (isJobRunning) elapsedTick = Date.now()
    }, 500)
  })

  onDestroy(() => {
    if (clockTimer) clearInterval(clockTimer)
    if (unsubHandoff) unsubHandoff()
    if (unregisterCmds) unregisterCmds()
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
  })
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="relab-page">
  <!-- ==================== 1. TOP STRIP: Sub-Tab Switcher + Host Toolchain ==================== -->
  <header class="top-strip">
    <div class="subtab-nav" role="tablist">
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'native'}
        class="subtab-btn"
        class:active={subTab === 'native'}
        on:click={() => (subTab = 'native')}
      >
        <Icon name="cpu" size={13} />
        <span>{$t('reLab.tabs.native')}</span>
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'emulate'}
        class="subtab-btn"
        class:active={subTab === 'emulate'}
        on:click={() => (subTab = 'emulate')}
      >
        <Icon name="play" size={13} />
        <span>{$t('reLab.tabs.emulate')}</span>
        {#if isJobRunning}
          <span class="live-dot"></span>
        {/if}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'jadx'}
        class="subtab-btn"
        class:active={subTab === 'jadx'}
        on:click={() => {
          subTab = 'jadx'
          if (!jadxInfo) detectJadx()
        }}
      >
        <Icon name="file-code" size={13} />
        <span>{$t('reLab.tabs.jadx')}</span>
        {#if jadxWorkspace?.class_count > 0}
          <span class="tab-cnt mono tabular-nums">{jadxWorkspace.class_count}</span>
        {/if}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'deobf'}
        class="subtab-btn"
        class:active={subTab === 'deobf'}
        on:click={() => {
          subTab = 'deobf'
          if (deobfView === 'tls' && !tlsProfiles.length) loadTlsEnvironment()
        }}
      >
        <Icon name="shield" size={13} />
        <span>{$t('reLab.tabs.deobf')}</span>
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'exectrace'}
        class="subtab-btn"
        class:active={subTab === 'exectrace'}
        on:click={() => {
          subTab = 'exectrace'
          loadExecTraces()
        }}
      >
        <Icon name="activity" size={13} />
        <span>{$t('reLab.tabs.exectrace')}</span>
        {#if traceSessions.length > 0}
          <span class="tab-cnt mono tabular-nums">{traceSessions.length}</span>
        {/if}
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={subTab === 'cryptolab'}
        class="subtab-btn"
        class:active={subTab === 'cryptolab'}
        on:click={() => {
          subTab = 'cryptolab'
          if (!cryptoOps.length) loadCryptoOperations()
        }}
      >
        <Icon name="key" size={13} />
        <span>{$t('reLab.tabs.cryptolab')}</span>
      </button>
    </div>

    <div class="strip-spacer"></div>

    <!-- Live Host Toolchain Pills -->
    <div class="toolchain-strip">
      <span class="strip-label">{$t('reLab.toolchain.label')}</span>
      <div class="tc-pills">
        {#each toolchainPills as pill (pill.key)}
          <button
            type="button"
            class="tc-pill"
            class:ready={pill.ready}
            title={tooltipForTool(pill)}
            on:click={() => (showToolchainDrawer = !showToolchainDrawer)}
          >
            <span class="tc-dot"></span>
            <span class="mono">{pill.label}</span>
          </button>
        {/each}
      </div>
      <Button
        variant="ghost"
        size="xs"
        icon="refresh"
        iconOnly
        loading={probingToolchain}
        title={$t('reLab.toolchain.reprobe')}
        on:click={() => loadToolchain(true)}
      />
      <Button
        variant="secondary"
        size="xs"
        icon="settings"
        active={showToolchainDrawer}
        on:click={() => (showToolchainDrawer = !showToolchainDrawer)}
      >
        {$t('reLab.toolchain.configBtn')}
      </Button>
    </div>
  </header>

  <!-- Collapsible Host Toolchain Config Drawer -->
  {#if showToolchainDrawer}
    <section class="drawer-panel cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('reLab.toolchain.title')}</div>
          <div class="drawer-sub">{$t('reLab.toolchain.subtitle')}</div>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (showToolchainDrawer = false)}>
          {$t('common.actions.close')}
        </Button>
      </div>

      <div class="drawer-grid three-col">
        <label class="d-field">
          <span>{$t('reLab.toolchain.r2Path')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.r2_path} placeholder={toolchain?.r2?.path || $t('reLab.toolchain.r2Placeholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.javaPath')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.java_path} placeholder={toolchain?.java?.path || $t('reLab.toolchain.javaPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.mvnPath')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.mvn_path} placeholder={toolchain?.mvn?.path || $t('reLab.toolchain.mvnPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.unidbgDir')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.unidbg_dir} placeholder={toolchain?.unidbg?.path || $t('reLab.toolchain.unidbgPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.pythonPath')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.python_path} placeholder={toolchain?.python?.path || $t('reLab.toolchain.pythonPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.qilingPythonPath')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.qiling_python_path} placeholder={toolchain?.qiling?.path || $t('reLab.toolchain.qilingPythonPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.angrPythonPath')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.angr_python_path} placeholder={toolchain?.angr?.path || $t('reLab.toolchain.angrPythonPlaceholder')} />
        </label>
        <label class="d-field">
          <span>{$t('reLab.toolchain.qilingRootfs')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.qiling_rootfs} placeholder={toolchain?.qiling_rootfs || $t('reLab.toolchain.qilingPlaceholder')} />
        </label>
      </div>

      <div class="tc-detail-row">
        {#each toolchainPills as pill (pill.key)}
          <div class="tc-stat-chip" title={tooltipForTool(pill)}>
            <Badge variant={pill.ready ? 'success' : 'neutral'} size="xs" dot>{pill.label}</Badge>
            <span class="mono truncate">
              {pill.info?.version || pill.info?.issue || '—'}{#if (pill.key === 'qiling' || pill.key === 'angr') && pill.ready && pill.info?.path} · {pill.info.path}{/if}
            </span>
          </div>
        {/each}
        {#if toolchain?.unidbg_mode}
          <Badge variant="accent" size="xs" mono>{$t('reLab.toolchain.unidbgModeLabel', { mode: toolchain.unidbg_mode })}</Badge>
        {/if}
        {#if toolchain?.unidbg_jars?.length > 0}
          <Badge variant="info" size="xs" mono>{$t('reLab.toolchain.jarsFound', { count: toolchain.unidbg_jars.length })}</Badge>
        {/if}
      </div>

      {#if toolchain?.issues?.length > 0}
        <div class="issues-box">
          {#each toolchain.issues as iss, i (i)}
            <div class="issue-line">
              <Icon name="alert-triangle" size={12} />
              <span>{iss}</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="drawer-foot">
        <span class="hint-muted mono">
          javac: {toolchain?.javac_path || '—'} · qiling: {toolchain?.qiling?.path || toolchain?.python?.path || '—'} · angr: {toolchain?.angr?.path || toolchain?.python?.path || '—'}
        </span>
        <div class="strip-spacer"></div>
        <Button variant="secondary" size="xs" icon="refresh" loading={probingToolchain} on:click={() => loadToolchain(true)}>
          {$t('reLab.toolchain.reprobe')}
        </Button>
        <Button variant="primary" size="xs" icon="check" loading={savingToolchain} on:click={saveToolchainConfig}>
          {$t('reLab.toolchain.saveProbe')}
        </Button>
      </div>
    </section>
  {/if}

  <!-- ==================== 2. WORKSPACE CONTENT ==================== -->
  <div class="relab-body">
    <!-- ======================================================================
         SUB-TAB 1: NATIVE BINARY & RADARE2
         ====================================================================== -->
    {#if subTab === 'native'}
      <div class="subtab-pane">
        <!-- Binary Path Bar -->
        <section class="action-bar">
          <div class="input-with-icon wide">
            <Icon name="file-code" size={13} />
            <input
              type="text"
              class="cap-input mono flex-1"
              bind:value={binaryPath}
              placeholder={$t('reLab.native.pathPlaceholder')}
              on:keydown={(e) => { if (e.key === 'Enter') analyzeBinary() }}
            />
          </div>
          <Button variant="primary" size="sm" icon="search" loading={analyzingBinary} on:click={() => { nativeMode = 'r2'; analyzeBinary() }}>
            {analyzingBinary ? $t('reLab.native.analyzing') : $t('reLab.native.analyzeBtn')}
          </Button>
          <Button variant="secondary" size="sm" icon="smartphone" loading={analyzingIOS} on:click={analyzeIOSBinary}>
            {analyzingIOS ? $t('reLab.native.ios.analyzing') : $t('reLab.native.ios.analyzeBtn')}
          </Button>
          <div class="seg-toggle">
            <button type="button" class="seg-btn" class:active={nativeMode === 'r2'} on:click={() => (nativeMode = 'r2')}>
              {$t('reLab.native.ios.modeR2')}
            </button>
            <button type="button" class="seg-btn" class:active={nativeMode === 'ios'} on:click={() => (nativeMode = 'ios')}>
              {$t('reLab.native.ios.modeIOS')}
            </button>
          </div>
          <Button
            variant="secondary"
            size="sm"
            icon="link"
            active={showSymbolBridgeDrawer}
            on:click={() => (showSymbolBridgeDrawer = !showSymbolBridgeDrawer)}
          >
            {$t('reLab.native.symbolBridge.btn')}
            {#if appliedSymbolCount > 0}
              <Badge variant="accent" size="xs" mono>{appliedSymbolCount}</Badge>
            {/if}
          </Button>
          {#if binaryAnalysis && nativeMode === 'r2'}
            <span class="v-sep"></span>
            <Button variant="secondary" size="sm" icon="shield" on:click={sendBinaryToProtectionScan}>
              {$t('reLab.native.scanDeobfBtn')}
            </Button>
            <Button variant="subtle" size="sm" icon="play" on:click={() => emulateFunctionIn('unidbg')}>
              Unidbg
            </Button>
            <Button variant="subtle" size="sm" icon="cpu" on:click={() => emulateFunctionIn('qiling')}>
              Qiling
            </Button>
            <Button variant="subtle" size="sm" icon="sparkles" on:click={() => emulateFunctionIn('angr')}>
              angr
            </Button>
          {/if}
        </section>

        <!-- Collapsible Symbol Bridge Drawer (IDA / Ghidra / JSON) -->
        {#if showSymbolBridgeDrawer}
          <section class="drawer-panel cap-card">
            <div class="drawer-head">
              <div>
                <div class="drawer-title">{$t('reLab.native.symbolBridge.title')}</div>
                <div class="drawer-sub">{$t('reLab.native.symbolBridge.subtitle')}</div>
              </div>
              <div class="ph-right">
                <div class="seg-toggle">
                  <button type="button" class="seg-btn" class:active={symBridgeTab === 'export'} on:click={() => (symBridgeTab = 'export')}>
                    {$t('reLab.native.symbolBridge.exportTab')}
                  </button>
                  <button type="button" class="seg-btn" class:active={symBridgeTab === 'import'} on:click={() => (symBridgeTab = 'import')}>
                    {$t('reLab.native.symbolBridge.importTab')}
                  </button>
                </div>
                <Button variant="ghost" size="xs" icon="x" on:click={() => (showSymbolBridgeDrawer = false)}>
                  {$t('common.actions.close')}
                </Button>
              </div>
            </div>

            {#if symBridgeTab === 'export'}
              <div class="drawer-grid four-col">
                <label class="d-field">
                  <span>{$t('reLab.native.symbolBridge.formatLabel')}</span>
                  <select class="cap-input mono" bind:value={symExportFormat}>
                    <option value="ida">{$t('reLab.native.symbolBridge.formatIda')}</option>
                    <option value="ghidra">{$t('reLab.native.symbolBridge.formatGhidra')}</option>
                    <option value="json">{$t('reLab.native.symbolBridge.formatJson')}</option>
                  </select>
                </label>
                <label class="d-field">
                  <span>{$t('reLab.native.symbolBridge.imageBase')}</span>
                  <input type="text" class="cap-input mono" bind:value={symImageBase} placeholder="0x0" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.native.symbolBridge.addCommentAddr')}</span>
                  <input type="text" class="cap-input mono" bind:value={symNewCmtAddr} placeholder={functionDetail?.addr || '0x1000'} />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.native.symbolBridge.addCommentText')}</span>
                  <div class="inline-action-row">
                    <input
                      type="text"
                      class="cap-input flex-1"
                      bind:value={symNewCmtText}
                      placeholder="AES key schedule"
                      on:keydown={(e) => { if (e.key === 'Enter') addCustomSymbolComment() }}
                    />
                    <Button variant="secondary" size="xs" icon="plus" on:click={addCustomSymbolComment}>
                      {$t('reLab.native.symbolBridge.addCommentBtn')}
                    </Button>
                  </div>
                </label>
              </div>

              <div class="drawer-foot">
                <span class="hint-muted mono">
                  funcs: {(binaryAnalysis?.functions?.length || 0) + (binaryAnalysis?.exports?.length || 0)} · comments: {symCustomComments.length + (importedSymbolBundle?.comments?.length || 0)} · jni: {jadxLinkReport?.bindings?.length || importedSymbolBundle?.jni_bindings?.length || 0}
                </span>
                {#if symCustomComments.length > 0}
                  <Button variant="ghost" size="xs" icon="trash" on:click={clearCustomSymbolComments}>
                    {$t('reLab.native.symbolBridge.clearCommentsBtn')} ({symCustomComments.length})
                  </Button>
                {/if}
                <div class="strip-spacer"></div>
                {#if symExportOutput}
                  <Button variant="secondary" size="xs" icon="copy" on:click={() => copyToClipboard(symExportOutput, translate('reLab.toast.copied'))}>
                    {$t('common.actions.copy')}
                  </Button>
                  <Button variant="secondary" size="xs" icon="download" on:click={downloadSymbolBridge}>
                    {$t('reLab.native.symbolBridge.downloadBtn')}
                  </Button>
                {/if}
                <Button variant="primary" size="xs" icon="sparkles" loading={exportingSymbols} on:click={exportSymbolBridge}>
                  {$t('reLab.native.symbolBridge.exportBtn')}
                </Button>
              </div>

              {#if symExportOutput}
                <pre class="collector-code mono">{symExportOutput}</pre>
              {/if}
            {:else}
              <textarea
                class="cap-textarea mono"
                rows="4"
                bind:value={symImportRaw}
                placeholder={$t('reLab.native.symbolBridge.importPlaceholder')}
              ></textarea>
              <div class="drawer-foot">
                {#if importedSymbolBundle}
                  <Badge variant="success" size="xs" mono>
                    {$t('reLab.native.symbolBridge.importedSummary', {
                      binary: importedSymbolBundle.binary_name || 'binary',
                      funcs: importedSymbolBundle.functions?.length || 0,
                      comments: importedSymbolBundle.comments?.length || 0,
                      jni: importedSymbolBundle.jni_bindings?.length || 0,
                    })}
                  </Badge>
                {/if}
                <div class="strip-spacer"></div>
                {#if importedSymbolBundle}
                  <Button variant="success" size="xs" icon="check" on:click={applyImportedSymbols}>
                    {$t('reLab.native.symbolBridge.applyBtn')}
                  </Button>
                {/if}
                <Button variant="primary" size="xs" icon="upload" loading={importingSymbols} disabled={!symImportRaw.trim()} on:click={importSymbolBridge}>
                  {$t('reLab.native.symbolBridge.importBtn')}
                </Button>
              </div>
              {#if importedSymbolBundle && (importedSymbolBundle.functions?.length > 0 || importedSymbolBundle.comments?.length > 0)}
                <div class="table-wrap compact-table-box">
                  <table class="data-table mono">
                    <thead>
                      <tr>
                        <th>Addr</th>
                        <th>Symbol / Comment</th>
                        <th>Type</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each (importedSymbolBundle.functions || []).slice(0, 40) as fn, idx (`impfn:${fn.address}:${idx}`)}
                        <tr>
                          <td class="accent-txt">{fn.address}</td>
                          <td class="bold">{fn.name}{fn.comment ? ` — ${fn.comment}` : ''}</td>
                          <td><Badge variant="info" size="xs" mono>{fn.type || 'function'}</Badge></td>
                          <td>
                            <Button variant="ghost" size="xs" on:click={() => { nativeMode = 'r2'; inspectFunction(fn.address, fn.name) }}>
                              Inspect
                            </Button>
                          </td>
                        </tr>
                      {/each}
                      {#each (importedSymbolBundle.comments || []).slice(0, 40) as cmt, idx (`impcmt:${cmt.address}:${idx}`)}
                        <tr>
                          <td class="accent-txt">{cmt.address}</td>
                          <td>{cmt.text}</td>
                          <td><Badge variant="neutral" size="xs" mono>comment</Badge></td>
                          <td>
                            <Button variant="ghost" size="xs" on:click={() => { nativeMode = 'r2'; inspectFunction(cmt.address, cmt.address) }}>
                              Inspect
                            </Button>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            {/if}
          </section>
        {/if}

        <!-- VIEW: iOS Mach-O / IPA Static Inspector -->
        {#if nativeMode === 'ios'}
          {#if !iosReport}
            <div class="scroll-workspace">
              <EmptyState
                icon="smartphone"
                title={$t('reLab.native.ios.emptyTitle')}
                description={$t('reLab.native.ios.emptyDesc')}
              >
                <Button variant="primary" size="sm" icon="smartphone" loading={analyzingIOS} on:click={analyzeIOSBinary}>
                  {$t('reLab.native.ios.analyzeBtn')}
                </Button>
              </EmptyState>
            </div>
          {:else}
            <!-- iOS FairPlay & Mitigations Strip -->
            <section class="mitigation-strip">
              <div class="mit-group">
                <strong class="mono file-tag">{iosReport.main_binary_name || iosReport.file_name}</strong>
                <Badge variant="accent" size="xs" mono>{(iosReport.file_kind || 'macho').toUpperCase()}</Badge>
                {#if iosReport.is_universal}
                  <Badge variant="purple" size="xs">{$t('reLab.native.ios.universal')}</Badge>
                {/if}
                <Badge variant={iosReport.fairplay_encrypted ? 'danger' : 'success'} size="xs" solid={iosReport.fairplay_encrypted} mono>
                  {iosReport.fairplay_encrypted
                    ? $t('reLab.native.ios.fairplayEncrypted', { id: iosReport.crypt_id })
                    : $t('reLab.native.ios.fairplayClear')}
                </Badge>
                <span class="meta-text mono tabular-nums">{formatBytes(iosReport.file_size)}</span>
                {#if iosReport.min_os}
                  <Badge variant="neutral" size="xs" mono>{$t('reLab.native.ios.minOS')}: {iosReport.min_os}</Badge>
                {/if}
              </div>

              <div class="strip-spacer"></div>

              <div class="mit-group">
                <Badge variant={iosReport.pie ? 'success' : 'warning'} size="xs" mono>PIE: {iosReport.pie ? 'ON' : 'OFF'}</Badge>
                <Badge variant={iosReport.nx ? 'success' : 'danger'} size="xs" mono>NX: {iosReport.nx ? 'ON' : 'OFF'}</Badge>
                <Badge variant={iosReport.arc ? 'success' : 'warning'} size="xs" mono>{$t('reLab.native.ios.arc')}: {iosReport.arc ? 'ON' : 'OFF'}</Badge>
                <Badge variant={iosReport.stack_canary ? 'success' : 'warning'} size="xs" mono>{$t('reLab.native.mitigations.canary')}: {iosReport.stack_canary ? 'ON' : 'OFF'}</Badge>
                <span class="v-sep"></span>
                <Button variant="primary" size="xs" icon="play" loading={generatingIOSHarness} on:click={generateUnidbgIOSHarness}>
                  {$t('reLab.native.ios.harnessBtn')}
                </Button>
                <Button variant="secondary" size="xs" icon="shield" loading={generatingIOSStealth} on:click={generateIOSStealthScript}>
                  {$t('reLab.native.ios.stealthBtn')}
                </Button>
              </div>
            </section>

            <div class="pane-fill">
              <SplitPane direction="horizontal" initialSize={38} minPrimary={24} minSecondary={40} storageKey="cap.relab.ios.hsplit">
                <!-- LEFT: Searchable ObjC Classes / Selectors / Exports / Dylibs -->
                <div slot="primary" class="panel-col surface">
                  <div class="inner-tabs">
                    {#each [
                      { id: 'objc_classes', count: iosReport.objc_classes?.length || 0 },
                      { id: 'objc_selectors', count: iosReport.objc_selectors?.length || 0 },
                      { id: 'exports', count: iosReport.exported_symbols?.length || 0 },
                      { id: 'dylibs', count: (iosReport.linked_dylibs?.length || 0) + (iosReport.frameworks?.length || 0) },
                    ] as tab (tab.id)}
                      <button
                        type="button"
                        class="itab"
                        class:active={iosLeftTab === tab.id}
                        on:click={() => (iosLeftTab = tab.id)}
                      >
                        <span>{$t(`reLab.native.ios.tabs.${tab.id}`)}</span>
                        <span class="itab-cnt mono tabular-nums">{tab.count}</span>
                      </button>
                    {/each}
                  </div>
                  <div class="list-toolbar">
                    <div class="search-box">
                      <Icon name="search" size={12} />
                      <input type="text" class="search-input" bind:value={iosSearch} placeholder={$t('reLab.native.ios.searchPlaceholder')} />
                      {#if iosSearch}
                        <button type="button" class="mini-icon-btn" title={$t('common.actions.clear')} aria-label={$t('common.actions.clear')} on:click={() => (iosSearch = '')}>
                          <Icon name="x" size={11} />
                        </button>
                      {/if}
                    </div>
                  </div>
                  <div class="list-scroll">
                    {#if filteredIOSItems.length === 0}
                      <EmptyState icon="search" title={$t('reLab.native.emptyFilterTitle')} compact />
                    {:else}
                      {#each filteredIOSItems.slice(0, 500) as item, idx (`ios:${iosLeftTab}:${idx}`)}
                        <button
                          type="button"
                          class="sym-row"
                          class:active={item === iosTargetObjCClass || item === iosTargetObjCSelector || item === iosTargetSymbol}
                          on:click={() => selectIOSTarget(item)}
                        >
                          <span class="sym-name mono truncate" title={item}>{item}</span>
                        </button>
                      {/each}
                    {/if}
                  </div>
                </div>

                <!-- RIGHT: Architectures, Info.plist, Harness Target & Warnings -->
                <div slot="secondary" class="scroll-workspace">
                  {#if iosReport.summary}
                    <div class="summary-banner cap-card">{iosReport.summary}</div>
                  {/if}

                  <!-- Unidbg iOS Target Quick Config -->
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="play" size={13} />
                      <span>{$t('reLab.native.ios.harnessTargetTitle')}</span>
                    </div>
                    <div class="drawer-grid four-col">
                      <label class="d-field">
                        <span>{$t('reLab.native.ios.objcClass')}</span>
                        <input type="text" class="cap-input mono" bind:value={iosTargetObjCClass} placeholder="SignManager" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.native.ios.objcSelector')}</span>
                        <input type="text" class="cap-input mono" bind:value={iosTargetObjCSelector} placeholder="signWithPayload:" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.native.ios.targetSymbol')}</span>
                        <input type="text" class="cap-input mono" bind:value={iosTargetSymbol} placeholder="_compute_sig" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.native.ios.targetOffset')}</span>
                        <input type="text" class="cap-input mono" bind:value={iosTargetOffset} placeholder="0x100004000" />
                      </label>
                    </div>
                  </div>

                  <!-- Mach-O Architecture Slices -->
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="cpu" size={13} />
                      <span>{$t('reLab.native.ios.archTitle', { count: iosReport.architectures?.length || 0 })}</span>
                    </div>
                    <div class="table-wrap">
                      <table class="data-table mono">
                        <thead>
                          <tr>
                            <th>Arch</th>
                            <th>CPU</th>
                            <th>Type</th>
                            <th>MinOS / SDK</th>
                            <th>Mitigations</th>
                            <th>FairPlay (LC_ENCRYPTION_INFO)</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each iosReport.architectures || [] as sl, idx (`arch:${sl.arch}:${idx}`)}
                            <tr>
                              <td class="bold accent-txt">{sl.arch} ({sl.bits}-bit)</td>
                              <td>{sl.cpu_type}{sl.cpu_subtype ? ` / ${sl.cpu_subtype}` : ''}</td>
                              <td>{sl.file_type || '—'}</td>
                              <td>{sl.min_os || '—'}{sl.sdk_version ? ` / SDK ${sl.sdk_version}` : ''}</td>
                              <td>
                                <div class="chip-wrap">
                                  <Badge variant={sl.pie ? 'success' : 'warning'} size="xs" mono>PIE</Badge>
                                  <Badge variant={sl.nx ? 'success' : 'danger'} size="xs" mono>NX</Badge>
                                  <Badge variant={sl.arc ? 'success' : 'neutral'} size="xs" mono>ARC</Badge>
                                  <Badge variant={sl.stack_canary ? 'success' : 'warning'} size="xs" mono>Canary</Badge>
                                </div>
                              </td>
                              <td>
                                <Badge variant={sl.encrypted ? 'danger' : 'success'} size="xs" mono>
                                  {sl.encrypted ? `ENCRYPTED id=${sl.crypt_id} (${sl.crypt_size}B)` : 'CLEAR (id=0)'}
                                </Badge>
                              </td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <!-- Info.plist Summary -->
                  {#if iosReport.info_plist}
                    {@const pl = iosReport.info_plist}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="file-text" size={13} />
                        <span>{$t('reLab.native.ios.plistTitle')}</span>
                        {#if pl.raw_format}
                          <Badge variant="neutral" size="xs" mono>{pl.raw_format}</Badge>
                        {/if}
                      </div>
                      <div class="plist-kv-grid mono">
                        <div><span class="meta-text">{$t('reLab.native.ios.bundleId')}:</span> <span class="bold">{pl.bundle_id || '—'}</span></div>
                        <div><span class="meta-text">{$t('reLab.native.ios.displayName')}:</span> <span>{pl.display_name || pl.bundle_name || '—'}</span></div>
                        <div><span class="meta-text">{$t('reLab.native.ios.executable')}:</span> <span>{pl.executable || '—'}</span></div>
                        <div><span class="meta-text">{$t('reLab.native.ios.version')}:</span> <span>{pl.version || '—'}{pl.build_version ? ` (${pl.build_version})` : ''}</span></div>
                        <div>
                          <span class="meta-text">{$t('reLab.native.ios.atsArbitrary')}:</span>
                          <Badge variant={pl.ats_allows_arbitrary_loads ? 'warning' : 'success'} size="xs" mono>
                            {pl.ats_allows_arbitrary_loads ? 'YES' : 'NO'}
                          </Badge>
                        </div>
                      </div>
                      {#if pl.url_schemes?.length}
                        <div class="fi-note">{$t('reLab.native.ios.urlSchemes')}:</div>
                        <div class="chip-wrap">
                          {#each pl.url_schemes as s, j (j)}<span class="mono-chip">{s}://</span>{/each}
                        </div>
                      {/if}
                      {#if pl.queries_schemes?.length}
                        <div class="fi-note">{$t('reLab.native.ios.queriesSchemes')}:</div>
                        <div class="chip-wrap">
                          {#each pl.queries_schemes as s, j (j)}<span class="mono-chip">{s}</span>{/each}
                        </div>
                      {/if}
                      {#if pl.ats_exception_domains?.length}
                        <div class="fi-note">{$t('reLab.native.ios.atsExceptions')}:</div>
                        <div class="chip-wrap">
                          {#each pl.ats_exception_domains as d, j (j)}<Badge variant="warning" size="xs" mono>{d}</Badge>{/each}
                        </div>
                      {/if}
                    </div>
                  {/if}

                  {#if iosReport.warnings?.length > 0}
                    <div class="issues-box">
                      {#each iosReport.warnings as w, idx (idx)}
                        <div class="issue-line"><Icon name="alert-triangle" size={12} /><span>{w}</span></div>
                      {/each}
                    </div>
                  {/if}
                </div>
              </SplitPane>
            </div>
          {/if}
        {:else}
        <!-- Security Mitigation Strip -->
        {#if binaryAnalysis}
          <section class="mitigation-strip">
            <div class="mit-group">
              <strong class="mono file-tag">{binaryAnalysis.file_name}</strong>
              <Badge variant={binaryAnalysis.engine === 'radare2' ? 'success' : 'info'} size="xs" mono>
                {binaryAnalysis.engine}
              </Badge>
              <Badge variant="neutral" size="xs" mono>{binaryAnalysis.format}</Badge>
              <Badge variant="accent" size="xs" mono>{binaryAnalysis.arch} · {binaryAnalysis.bits}-bit · {binaryAnalysis.endian}</Badge>
              <span class="meta-text mono tabular-nums">{formatBytes(binaryAnalysis.file_size)}</span>
              {#if binaryAnalysis.entry_point}
                <span class="meta-text mono">{$t('reLab.native.entryPoint')}: {binaryAnalysis.entry_point}</span>
              {/if}
            </div>

            <div class="strip-spacer"></div>

            <div class="mit-group">
              <Badge variant={binaryAnalysis.mitigations?.pie ? 'success' : 'warning'} size="xs" mono>
                {$t('reLab.native.mitigations.pie')}: {binaryAnalysis.mitigations?.pie ? 'ON' : 'OFF'}
              </Badge>
              <Badge variant={binaryAnalysis.mitigations?.nx ? 'success' : 'danger'} size="xs" mono>
                {$t('reLab.native.mitigations.nx')}: {binaryAnalysis.mitigations?.nx ? 'ON' : 'OFF'}
              </Badge>
              <Badge variant={binaryAnalysis.mitigations?.canary ? 'success' : 'warning'} size="xs" mono>
                {$t('reLab.native.mitigations.canary')}: {binaryAnalysis.mitigations?.canary ? 'ON' : 'OFF'}
              </Badge>
              <Badge
                variant={binaryAnalysis.mitigations?.relro === 'full'
                  ? 'success'
                  : binaryAnalysis.mitigations?.relro === 'partial'
                    ? 'warning'
                    : 'danger'}
                size="xs"
                mono
              >
                {$t('reLab.native.mitigations.relro')}: {(binaryAnalysis.mitigations?.relro || 'unknown').toUpperCase()}
              </Badge>
              <Badge variant={binaryAnalysis.mitigations?.stripped ? 'warning' : 'info'} size="xs">
                {binaryAnalysis.mitigations?.stripped
                  ? $t('reLab.native.mitigations.stripped')
                  : $t('reLab.native.mitigations.unstripped')}
              </Badge>
              {#if binaryAnalysis.elapsed_ms > 0}
                <span class="meta-text mono tabular-nums">{formatDuration(binaryAnalysis.elapsed_ms)}</span>
              {/if}
            </div>
          </section>
        {/if}

        <!-- Main Native SplitPane -->
        <div class="pane-fill">
          <SplitPane direction="horizontal" initialSize={36} minPrimary={22} minSecondary={42} storageKey="cap.relab.native.hsplit">
            <!-- LEFT: Functions / Exports / Imports / Strings / XRefs -->
            <div slot="primary" class="panel-col surface">
              <div class="inner-tabs">
                {#each [
                  { id: 'functions', count: nativeFunctions.length },
                  { id: 'exports', count: nativeExports.length },
                  { id: 'imports', count: nativeImports.length },
                  { id: 'strings', count: nativeStrings.length },
                  { id: 'xrefs', count: nativeXRefs.length },
                ] as tab (tab.id)}
                  <button
                    type="button"
                    class="itab"
                    class:active={nativeLeftTab === tab.id}
                    on:click={() => (nativeLeftTab = tab.id)}
                  >
                    <span>{$t(`reLab.native.tabs.${tab.id}`)}</span>
                    <span class="itab-cnt mono tabular-nums">{tab.count}</span>
                  </button>
                {/each}
              </div>

              <div class="list-toolbar">
                <div class="search-box">
                  <Icon name="search" size={12} />
                  <input
                    type="text"
                    class="search-input"
                    bind:value={nativeSearch}
                    placeholder={$t('reLab.native.searchPlaceholder')}
                  />
                  {#if nativeSearch}
                    <button type="button" class="mini-icon-btn" on:click={() => (nativeSearch = '')}>
                      <Icon name="x" size={11} />
                    </button>
                  {/if}
                </div>
                {#if nativeLeftTab === 'functions' || nativeLeftTab === 'exports'}
                  <button
                    type="button"
                    class="filter-chip"
                    class:active={nativeJniOnly}
                    on:click={() => (nativeJniOnly = !nativeJniOnly)}
                  >
                    {$t('reLab.native.jniOnly')}
                  </button>
                {/if}
              </div>

              <div class="list-scroll">
                {#if !binaryAnalysis}
                  <EmptyState
                    icon="cpu"
                    title={$t('reLab.native.emptyLeftTitle')}
                    description={$t('reLab.native.emptyLeftDesc')}
                    compact
                  />
                {:else if filteredNativeItems.length === 0}
                  <EmptyState
                    icon="search"
                    title={$t('reLab.native.emptyFilterTitle')}
                    description={$t('reLab.native.emptyFilterDesc')}
                    compact
                  />
                {:else if nativeLeftTab === 'functions'}
                  {#each filteredNativeItems.slice(0, 500) as fn, idx (`${fn.addr}:${fn.name}:${idx}`)}
                    <button
                      type="button"
                      class="sym-row"
                      class:active={selectedFuncKey === fn.name || selectedFuncKey === fn.addr}
                      on:click={() => inspectFunction(fn.addr || fn.name, fn.name)}
                    >
                      <span class="sym-addr mono tabular-nums">{fn.addr || formatHex(fn.offset)}</span>
                      <span class="sym-name mono truncate" title={fn.name}>{fn.name}</span>
                      {#if fn.is_jni}
                        <Badge variant="purple" size="xs" mono>JNI</Badge>
                      {/if}
                      {#if fn.size > 0}
                        <span class="sym-meta mono tabular-nums">{fn.size}B</span>
                      {/if}
                    </button>
                  {/each}
                {:else if nativeLeftTab === 'exports' || nativeLeftTab === 'imports'}
                  {#each filteredNativeItems.slice(0, 500) as sym, idx (`${sym.addr}:${sym.name}:${idx}`)}
                    <button
                      type="button"
                      class="sym-row"
                      class:active={selectedFuncKey === sym.name}
                      on:click={() => inspectFunction(sym.addr || sym.name, sym.name)}
                    >
                      <span class="sym-addr mono tabular-nums">{sym.addr || formatHex(sym.offset)}</span>
                      <span class="sym-name mono truncate" title={sym.name}>{sym.name}</span>
                      {#if sym.is_jni}
                        <Badge variant="purple" size="xs" mono>JNI</Badge>
                      {/if}
                      {#if sym.library}
                        <span class="sym-meta mono truncate">{sym.library}</span>
                      {:else if sym.type}
                        <span class="sym-meta mono">{sym.type}</span>
                      {/if}
                    </button>
                  {/each}
                {:else if nativeLeftTab === 'strings'}
                  {#each filteredNativeItems.slice(0, 500) as st, idx (`${st.addr}:${st.offset}:${idx}`)}
                    <button
                      type="button"
                      class="sym-row"
                      on:click={() => copyToClipboard(st.value, translate('reLab.toast.copied'))}
                    >
                      <span class="sym-addr mono tabular-nums">{st.addr || formatHex(st.offset)}</span>
                      <span class="sym-name mono truncate" title={st.value}>{st.value}</span>
                      {#if st.section}
                        <Badge variant="neutral" size="xs" mono>{st.section}</Badge>
                      {/if}
                    </button>
                  {/each}
                {:else}
                  {#each filteredNativeItems.slice(0, 500) as xr, idx (`${xr.from}:${xr.to}:${idx}`)}
                    <button
                      type="button"
                      class="sym-row xref-row"
                      on:click={() => inspectFunction(xr.from || xr.to, xr.from_name || xr.from)}
                    >
                      <div class="xref-line mono">
                        <span class="accent-txt">{xr.from_name || xr.from}</span>
                        <Icon name="arrow-right" size={11} />
                        <span>{xr.to_name || xr.to}</span>
                      </div>
                      {#if xr.opcode}
                        <div class="xref-op mono truncate">{xr.opcode}</div>
                      {/if}
                    </button>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- RIGHT: Function Disassembly/Pseudo-C + Read-Only r2 Console -->
            <div slot="secondary" class="panel-col">
              <SplitPane direction="vertical" initialSize={66} minPrimary={30} minSecondary={22} storageKey="cap.relab.native.vsplit">
                <!-- TOP: Disassembly + Pseudo-C Inspector -->
                <div slot="primary" class="panel-col">
                  <div class="pane-header">
                    <div class="ph-left">
                      {#if functionDetail}
                        <strong class="mono truncate fn-title">{functionDetail.name}</strong>
                        <Badge variant="accent" size="xs" mono>{functionDetail.addr}</Badge>
                        {#if functionDetail.size > 0}
                          <Badge variant="neutral" size="xs" mono>{functionDetail.size} B</Badge>
                        {/if}
                        {#if functionDetail.pseudo_c_engine}
                          <Badge variant="purple" size="xs" mono>{functionDetail.pseudo_c_engine}</Badge>
                        {/if}
                        {#if appliedSymbolComments[(functionDetail.addr || '').toLowerCase()]}
                          <Badge variant="warning" size="xs" mono>{appliedSymbolComments[(functionDetail.addr || '').toLowerCase()]}</Badge>
                        {/if}
                      {:else}
                        <span class="ph-title">{$t('reLab.native.inspector.disasmTab')}</span>
                      {/if}
                    </div>

                    <div class="ph-right">
                      <div class="seg-toggle">
                        <button type="button" class="seg-btn" class:active={funcViewTab === 'disasm'} on:click={() => (funcViewTab = 'disasm')}>
                          {$t('reLab.native.inspector.disasmTab')}
                        </button>
                        <button type="button" class="seg-btn" class:active={funcViewTab === 'pseudoc'} on:click={() => (funcViewTab = 'pseudoc')}>
                          {$t('reLab.native.inspector.pseudoCTab')}
                        </button>
                        <button type="button" class="seg-btn" class:active={funcViewTab === 'xrefs'} on:click={() => (funcViewTab = 'xrefs')}>
                          {$t('reLab.native.inspector.xrefsTab')}
                        </button>
                      </div>

                      {#if functionDetail}
                        <span class="v-sep"></span>
                        <span class="emulate-lbl">{$t('reLab.native.inspector.emulateIn')}</span>
                        <Button variant="subtle" size="xs" on:click={() => emulateFunctionIn('unidbg', functionDetail)}>Unidbg</Button>
                        <Button variant="subtle" size="xs" on:click={() => emulateFunctionIn('qiling', functionDetail)}>Qiling</Button>
                        <Button variant="subtle" size="xs" on:click={() => emulateFunctionIn('angr', functionDetail)}>angr</Button>
                        <Button
                          variant="ghost"
                          size="xs"
                          icon="copy"
                          on:click={() =>
                            copyToClipboard(
                              funcViewTab === 'pseudoc' ? (functionDetail.pseudo_c || '') : (functionDetail.disasm || ''),
                              translate('reLab.toast.copied')
                            )}
                        >
                          {$t('reLab.native.inspector.copyCode')}
                        </Button>
                      {/if}
                    </div>
                  </div>

                  <div class="code-viewer-scroll">
                    {#if inspectingFunc}
                      <div class="center-loading">
                        <span class="meta-text">{$t('reLab.native.inspector.loading')}</span>
                      </div>
                    {:else if !functionDetail}
                      <EmptyState
                        icon="code"
                        title={$t('reLab.native.inspector.emptyTitle')}
                        description={$t('reLab.native.inspector.emptyDesc')}
                        compact
                      />
                    {:else if funcViewTab === 'disasm'}
                      {#if functionDetail.disasm_lines && functionDetail.disasm_lines.length > 0}
                        <table class="disasm-table mono">
                          <tbody>
                            {#each functionDetail.disasm_lines as line, idx (`${line.addr}:${idx}`)}
                              <tr class:is-jump={Boolean(line.jump)}>
                                <td class="d-addr tabular-nums">{line.addr}</td>
                                <td class="d-bytes">{line.bytes || ''}</td>
                                <td class="d-insn">{line.disasm}</td>
                                <td class="d-cmt">
                                  {#if line.jump}
                                    <button
                                      type="button"
                                      class="jump-link mono"
                                      on:click={() => inspectFunction(line.jump, line.jump)}
                                    >
                                      → {line.jump}
                                    </button>
                                  {/if}
                                  {#if line.comment}
                                    <span>; {line.comment}</span>
                                  {/if}
                                </td>
                              </tr>
                            {/each}
                          </tbody>
                        </table>
                      {:else}
                        <pre class="raw-code mono">{functionDetail.disasm || '—'}</pre>
                      {/if}
                    {:else if funcViewTab === 'pseudoc'}
                      {#if functionDetail.pseudo_c}
                        <pre class="raw-code mono">{functionDetail.pseudo_c}</pre>
                      {:else}
                        <EmptyState
                          icon="info"
                          title={$t('reLab.native.inspector.pseudoCTab')}
                          description={$t('reLab.native.inspector.noPseudoC')}
                          compact
                        />
                      {/if}
                    {:else}
                      <div class="xrefs-grid">
                        <div class="xref-card cap-card">
                          <div class="card-head">{$t('reLab.native.inspector.xrefsTo', { count: functionDetail.xrefs_to?.length || 0 })}</div>
                          {#if !functionDetail.xrefs_to?.length}
                            <div class="card-empty">{$t('reLab.native.inspector.noXRefs')}</div>
                          {:else}
                            {#each functionDetail.xrefs_to as xr, idx (`to:${xr.from}:${idx}`)}
                              <button type="button" class="sym-row" on:click={() => inspectFunction(xr.from, xr.from_name || xr.from)}>
                                <span class="sym-addr mono">{xr.from}</span>
                                <span class="sym-name mono truncate">{xr.from_name || xr.opcode || xr.type}</span>
                                {#if xr.type}<Badge variant="neutral" size="xs" mono>{xr.type}</Badge>{/if}
                              </button>
                            {/each}
                          {/if}
                        </div>
                        <div class="xref-card cap-card">
                          <div class="card-head">{$t('reLab.native.inspector.xrefsFrom', { count: functionDetail.xrefs_from?.length || 0 })}</div>
                          {#if !functionDetail.xrefs_from?.length}
                            <div class="card-empty">{$t('reLab.native.inspector.noXRefs')}</div>
                          {:else}
                            {#each functionDetail.xrefs_from as xr, idx (`from:${xr.to}:${idx}`)}
                              <button type="button" class="sym-row" on:click={() => inspectFunction(xr.to, xr.to_name || xr.to)}>
                                <span class="sym-addr mono">{xr.to}</span>
                                <span class="sym-name mono truncate">{xr.to_name || xr.opcode || xr.type}</span>
                                {#if xr.type}<Badge variant="neutral" size="xs" mono>{xr.type}</Badge>{/if}
                              </button>
                            {/each}
                          {/if}
                        </div>
                      </div>
                    {/if}
                  </div>
                </div>

                <!-- BOTTOM: Read-Only r2 Command Console -->
                <div slot="secondary" class="panel-col surface">
                  <div class="pane-header compact">
                    <div class="ph-left">
                      <Icon name="terminal" size={13} />
                      <span class="ph-title">{$t('reLab.native.console.title')}</span>
                      <div class="preset-chips">
                        {#each R2_PRESETS as preset (preset)}
                          <button type="button" class="preset-chip mono" on:click={() => runR2Command(preset)}>
                            {preset}
                          </button>
                        {/each}
                      </div>
                    </div>
                    <Button variant="ghost" size="xs" icon="trash" disabled={r2History.length === 0} on:click={() => (r2History = [])}>
                      {$t('common.actions.clear')}
                    </Button>
                  </div>

                  <div class="r2-input-row">
                    <span class="r2-prompt mono">r2&gt;</span>
                    <input
                      type="text"
                      class="cap-input mono flex-1"
                      bind:value={r2Cmd}
                      placeholder={$t('reLab.native.console.placeholder')}
                      on:keydown={(e) => { if (e.key === 'Enter') runR2Command() }}
                    />
                    <Button variant="primary" size="xs" icon="play" loading={r2Running} on:click={() => runR2Command()}>
                      {r2Running ? $t('reLab.native.console.running') : $t('reLab.native.console.runBtn')}
                    </Button>
                  </div>

                  <div class="r2-output-scroll mono" bind:this={r2ConsoleEl}>
                    {#if r2History.length === 0}
                      <div class="r2-empty">{$t('reLab.native.console.emptyHint')}</div>
                    {:else}
                      {#each r2History as entry (entry.id)}
                        <div class="r2-entry">
                          <div class="r2-entry-cmd">
                            <span>[0x00000000]&gt; {entry.cmd}</span>
                            {#if entry.elapsed_ms > 0}
                              <span class="meta-text tabular-nums">{formatDuration(entry.elapsed_ms)}</span>
                            {/if}
                          </div>
                          {#if entry.error}
                            <pre class="r2-err">{entry.error}</pre>
                          {:else}
                            <pre class="r2-out">{entry.output || '(empty)'}</pre>
                          {/if}
                        </div>
                      {/each}
                    {/if}
                  </div>
                </div>
              </SplitPane>
            </div>
          </SplitPane>
        </div>
        {/if}
      </div>

    <!-- ======================================================================
         SUB-TAB 2: EMULATION & SYMBOLIC (UNIDBG / QILING / ANGR)
         ====================================================================== -->
    {:else if subTab === 'emulate'}
      <div class="subtab-pane">
        <!-- Optional Drawer: Generate Harness from DeepTrace -->
        {#if showTraceGenDrawer}
          <section class="drawer-panel cap-card">
            <div class="drawer-head">
              <div>
                <div class="drawer-title">{$t('reLab.emulate.fromTraceTitle')}</div>
                <div class="drawer-sub">{$t('reLab.emulate.fromTraceSub')}</div>
              </div>
              <Button variant="ghost" size="xs" icon="x" on:click={() => (showTraceGenDrawer = false)}>
                {$t('common.actions.close')}
              </Button>
            </div>

            <div class="drawer-grid four-col">
              <label class="d-field">
                <span>{$t('reLab.emulate.engineLabel')}</span>
                <select class="cap-input mono" bind:value={traceGenEngine}>
                  <option value="unidbg">Unidbg (Java JNI)</option>
                  <option value="qiling">Qiling (Python)</option>
                  <option value="angr">angr (Symbolic Python)</option>
                  <option value="radare2">radare2 Script</option>
                </select>
              </label>
              <label class="d-field">
                <span>{$t('reLab.emulate.archLabel')}</span>
                <select class="cap-input mono" bind:value={traceGenArch}>
                  <option value="arm64">arm64</option>
                  <option value="arm">arm</option>
                  <option value="x86_64">x86_64</option>
                  <option value="x86">x86</option>
                </select>
              </label>
              {#if traceGenEngine === 'unidbg'}
                <label class="d-field">
                  <span>{$t('reLab.emulate.httpPort')}</span>
                  <input type="number" class="cap-input mono" bind:value={traceGenHttpPort} min="1024" max="65535" disabled={!traceGenHttpMode} />
                </label>
                <div class="d-field center-v">
                  <label class="check-opt">
                    <input type="checkbox" bind:checked={traceGenHttpMode} />
                    <span>{$t('reLab.emulate.httpMode')}</span>
                  </label>
                </div>
              {:else if traceGenEngine === 'angr'}
                <label class="d-field">
                  <span>{$t('reLab.emulate.inputLen')}</span>
                  <input type="number" class="cap-input mono" bind:value={traceGenInputLen} min="4" max="512" />
                </label>
              {/if}
            </div>

            <div class="drawer-foot">
              {#if deepTraceState?.result}
                <Badge variant="success" size="xs" dot>
                  {$t('reLab.emulate.traceReady', { pkg: deepTraceState.result.package || deepTraceState.package || 'Active Flow' })}
                </Badge>
              {:else}
                <Badge variant="neutral" size="xs">{$t('reLab.emulate.traceNone')}</Badge>
              {/if}
              <div class="strip-spacer"></div>
              <Button variant="primary" size="xs" icon="sparkles" loading={generatingHarness} on:click={generateHarnessFromTrace}>
                {generatingHarness ? $t('reLab.emulate.generating') : $t('reLab.emulate.generateLoadBtn')}
              </Button>
            </div>
          </section>
        {/if}

        <!-- Optional Drawer: Unidbg Auto-Stub Assistant -->
        {#if showAutoStubDrawer}
          <section class="drawer-panel cap-card">
            <div class="drawer-head">
              <div>
                <div class="drawer-title">{$t('reLab.emulate.autoStub.title')}</div>
                <div class="drawer-sub">{$t('reLab.emulate.autoStub.subtitle')}</div>
              </div>
              <div class="ph-right">
                <Button variant="secondary" size="xs" icon="terminal" disabled={jobEvents.length === 0} on:click={pullConsoleLogsForAutoStub}>
                  {$t('reLab.emulate.autoStub.loadConsoleBtn')}
                </Button>
                <Button variant="ghost" size="xs" icon="x" on:click={() => (showAutoStubDrawer = false)}>
                  {$t('common.actions.close')}
                </Button>
              </div>
            </div>

            <textarea
              class="cap-textarea mono"
              rows="4"
              bind:value={autoStubRawLog}
              placeholder={$t('reLab.emulate.autoStub.rawPlaceholder')}
            ></textarea>

            <div class="drawer-foot">
              <label class="inline-field">
                <span class="meta-text">{$t('reLab.emulate.autoStub.pkgLabel')}:</span>
                <input type="text" class="cap-input mono compact-input" bind:value={autoStubPkg} placeholder={stealthOpts.target_package || 'com.example.app'} />
              </label>
              <Button variant="secondary" size="xs" icon="zap" loading={generatingEnvSnap} on:click={generateFridaEnvSnapshot}>
                {$t('reLab.emulate.autoStub.fridaSnapBtn')}
              </Button>
              <div class="strip-spacer"></div>
              <Button variant="primary" size="xs" icon="sparkles" loading={analyzingAutoStub} disabled={!autoStubRawLog.trim()} on:click={analyzeUnidbgLog}>
                {analyzingAutoStub ? $t('reLab.emulate.autoStub.analyzing') : $t('reLab.emulate.autoStub.analyzeBtn')}
              </Button>
            </div>

            {#if autoStubDiagnosis}
              <div class="summary-banner cap-card">
                <Badge variant={autoStubDiagnosis.total_errors > 0 ? 'warning' : 'success'} size="xs" mono>
                  {autoStubDiagnosis.total_errors || 0} errors
                </Badge>
                <span>{autoStubDiagnosis.summary || $t('reLab.emulate.autoStub.noIssues')}</span>
              </div>

              {#if autoStubDiagnosis.missing_jni?.length > 0 || autoStubDiagnosis.missing_files?.length > 0 || autoStubDiagnosis.missing_sys_props?.length > 0 || autoStubDiagnosis.missing_libraries?.length > 0 || autoStubDiagnosis.missing_classes?.length > 0}
                <div class="findings-grid">
                  {#if autoStubDiagnosis.missing_jni?.length > 0}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="code" size={12} />
                        <span>{$t('reLab.emulate.autoStub.cards.jni', { count: autoStubDiagnosis.missing_jni.length })}</span>
                      </div>
                      <div class="finding-list">
                        {#each autoStubDiagnosis.missing_jni as item, idx (`jni:${item.callback}:${item.signature}:${idx}`)}
                          <div class="finding-item">
                            <div class="fi-top">
                              <Badge variant="accent" size="xs" mono>{item.callback}</Badge>
                              <Badge variant="neutral" size="xs" mono>×{item.count}</Badge>
                              {#if item.smart_match}
                                <Badge variant="success" size="xs">{$t('reLab.emulate.autoStub.smartMatch')}</Badge>
                              {/if}
                            </div>
                            <div class="mono fi-pattern">{item.signature}</div>
                            {#if item.note}<div class="fi-note">{item.note}</div>{/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  {#if autoStubDiagnosis.missing_files?.length > 0}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="folder" size={12} />
                        <span>{$t('reLab.emulate.autoStub.cards.files', { count: autoStubDiagnosis.missing_files.length })}</span>
                      </div>
                      <div class="finding-list">
                        {#each autoStubDiagnosis.missing_files as item, idx (`file:${item.path}:${idx}`)}
                          <div class="finding-item">
                            <div class="fi-top">
                              <span class="mono bold truncate">{item.path}</span>
                              <Badge variant="neutral" size="xs" mono>×{item.count}</Badge>
                            </div>
                            {#if item.note}<div class="fi-note">{item.note}</div>{/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  {#if autoStubDiagnosis.missing_sys_props?.length > 0}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="sliders" size={12} />
                        <span>{$t('reLab.emulate.autoStub.cards.sysProps', { count: autoStubDiagnosis.missing_sys_props.length })}</span>
                      </div>
                      <div class="finding-list">
                        {#each autoStubDiagnosis.missing_sys_props as item, idx (`sp:${item.key}:${idx}`)}
                          <div class="finding-item">
                            <div class="fi-top">
                              <span class="mono bold">{item.key}</span>
                              <Badge variant="info" size="xs" mono>{item.suggested_value}</Badge>
                              <Badge variant="neutral" size="xs" mono>×{item.count}</Badge>
                            </div>
                            {#if item.note}<div class="fi-note">{item.note}</div>{/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  {#if autoStubDiagnosis.missing_libraries?.length > 0 || autoStubDiagnosis.missing_classes?.length > 0}
                    <div class="section-card cap-card">
                      {#if autoStubDiagnosis.missing_libraries?.length > 0}
                        <div class="card-head">
                          <Icon name="box" size={12} />
                          <span>{$t('reLab.emulate.autoStub.cards.libs', { count: autoStubDiagnosis.missing_libraries.length })}</span>
                        </div>
                        <div class="chip-wrap">
                          {#each autoStubDiagnosis.missing_libraries as lib, idx (`lib:${lib.name}:${idx}`)}
                            <Badge variant="danger" size="xs" mono>{lib.name} ×{lib.count}</Badge>
                          {/each}
                        </div>
                      {/if}
                      {#if autoStubDiagnosis.missing_classes?.length > 0}
                        <div class="card-head">
                          <Icon name="layers" size={12} />
                          <span>{$t('reLab.emulate.autoStub.cards.classes', { count: autoStubDiagnosis.missing_classes.length })}</span>
                        </div>
                        <div class="chip-wrap">
                          {#each autoStubDiagnosis.missing_classes as cls, idx (`cls:${cls}:${idx}`)}
                            <span class="mono-chip">{cls}</span>
                          {/each}
                        </div>
                      {/if}
                    </div>
                  {/if}
                </div>
              {/if}

              {#if hasAnyAutoStubSnippet}
                <div class="collector-preview">
                  <div class="cp-head">
                    <div class="seg-toggle">
                      <button type="button" class="seg-btn" class:active={autoStubSnippetTab === 'combined'} disabled={!autoStubDiagnosis.combined_java_snippet} on:click={() => (autoStubSnippetTab = 'combined')}>
                        {$t('reLab.emulate.autoStub.tabs.combined')}
                      </button>
                      <button type="button" class="seg-btn" class:active={autoStubSnippetTab === 'jni'} disabled={!autoStubDiagnosis.abstract_jni_snippet} on:click={() => (autoStubSnippetTab = 'jni')}>
                        {$t('reLab.emulate.autoStub.tabs.jni')}
                      </button>
                      <button type="button" class="seg-btn" class:active={autoStubSnippetTab === 'io'} disabled={!autoStubDiagnosis.io_resolver_snippet} on:click={() => (autoStubSnippetTab = 'io')}>
                        {$t('reLab.emulate.autoStub.tabs.io')}
                      </button>
                      <button type="button" class="seg-btn" class:active={autoStubSnippetTab === 'sysprop'} disabled={!autoStubDiagnosis.sys_prop_hook_snippet} on:click={() => (autoStubSnippetTab = 'sysprop')}>
                        {$t('reLab.emulate.autoStub.tabs.sysprop')}
                      </button>
                    </div>
                    <div class="strip-spacer"></div>
                    <Button variant="secondary" size="xs" icon="copy" disabled={!activeAutoStubSnippet} on:click={() => copyToClipboard(activeAutoStubSnippet, translate('reLab.toast.copied'))}>
                      {$t('reLab.emulate.autoStub.copyStubBtn')}
                    </Button>
                    <Button variant="primary" size="xs" icon="plus" disabled={!activeAutoStubSnippet} on:click={appendAutoStubToEditor}>
                      {$t('reLab.emulate.autoStub.appendStubBtn')}
                    </Button>
                  </div>
                  {#if activeAutoStubSnippet}
                    <pre class="collector-code mono">{activeAutoStubSnippet}</pre>
                  {:else}
                    <div class="r2-output-scroll"><div class="r2-empty">{$t('reLab.emulate.autoStub.noSnippetForTab')}</div></div>
                  {/if}
                </div>
              {/if}
            {/if}
          </section>
        {/if}

        <div class="pane-fill">
          <SplitPane direction="horizontal" initialSize={27} minPrimary={20} minSecondary={52} storageKey="cap.relab.emu.hsplit">
            <!-- LEFT: Saved RE Projects & Templates -->
            <div slot="primary" class="panel-col surface">
              <div class="list-toolbar">
                <div class="search-box">
                  <Icon name="search" size={12} />
                  <input
                    type="text"
                    class="search-input"
                    bind:value={projectSearch}
                    placeholder={$t('reLab.emulate.searchPlaceholder')}
                  />
                </div>
                <Button variant="secondary" size="xs" icon="plus" on:click={createNewProject}>
                  {$t('reLab.emulate.newProject')}
                </Button>
              </div>

              <div class="left-action-banner">
                <Button variant="primary" size="xs" icon="sparkles" fullWidth on:click={openTraceGenDrawer}>
                  {$t('reLab.emulate.fromTraceBtn')}
                </Button>
              </div>

              <div class="cat-pills">
                {#each ['all', 'unidbg', 'qiling', 'angr', 'radare2'] as eng (eng)}
                  <button
                    type="button"
                    class="cat-pill"
                    class:active={projectEngineFilter === eng}
                    on:click={() => (projectEngineFilter = eng)}
                  >
                    {eng === 'all' ? $t('reLab.emulate.engineAll') : eng}
                  </button>
                {/each}
              </div>

              <div class="list-scroll padded">
                {#if filteredProjects.length === 0}
                  <EmptyState
                    icon="file-code"
                    title={$t('reLab.emulate.emptyProjectsTitle')}
                    description={$t('reLab.emulate.emptyProjectsDesc')}
                    compact
                  />
                {:else}
                  {#each filteredProjects as p (p.id)}
                    <button
                      type="button"
                      class="item-card"
                      class:active={projId === p.id}
                      on:click={() => selectProject(p)}
                    >
                      <div class="ic-top">
                        <Badge variant={engineVariant(p.engine)} size="xs" mono>{p.engine}</Badge>
                        <span class="ic-origin">
                          {p.builtin ? $t('reLab.emulate.builtin') : $t('reLab.emulate.custom')}
                        </span>
                        {#if !p.builtin}
                          <span
                            class="ic-del"
                            role="button"
                            tabindex="0"
                            title={$t('common.actions.delete')}
                            on:click={(ev) => deleteProject(p, ev)}
                            on:keydown={(ev) => { if (ev.key === 'Enter') deleteProject(p, ev) }}
                          >
                            <Icon name="trash" size={11} />
                          </span>
                        {/if}
                      </div>
                      <div class="ic-name truncate">{p.name}</div>
                      {#if p.description}
                        <div class="ic-desc">{p.description}</div>
                      {/if}
                      {#if p.target_symbol || p.target_class}
                        <div class="ic-meta mono truncate">{p.target_symbol || p.target_class}</div>
                      {/if}
                    </button>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- RIGHT: Config Strip + CodeEditor (Top) | Live Job Console (Bottom) -->
            <div slot="secondary" class="panel-col">
              <SplitPane direction="vertical" initialSize={60} minPrimary={28} minSecondary={24} storageKey="cap.relab.emu.vsplit">
                <!-- TOP: Project Config & CodeEditor -->
                <div slot="primary" class="panel-col">
                  <div class="editor-header">
                    <input
                      type="text"
                      class="cap-input ed-name"
                      bind:value={projName}
                      placeholder={$t('reLab.emulate.namePlaceholder')}
                      on:input={() => (projDirty = true)}
                    />
                    <select class="cap-input ed-cat mono" bind:value={projEngine} on:change={() => (projDirty = true)}>
                      <option value="unidbg">unidbg</option>
                      <option value="qiling">qiling</option>
                      <option value="angr">angr</option>
                      <option value="radare2">radare2</option>
                    </select>
                    {#if projDirty}
                      <Badge variant="warning" size="xs">●</Badge>
                    {/if}
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="sliders"
                      active={showConfigStrip}
                      on:click={() => (showConfigStrip = !showConfigStrip)}
                    >
                      {$t('reLab.emulate.configToggle')}
                    </Button>
                    <div class="strip-spacer"></div>
                    <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(projCode, translate('reLab.toast.copied'))}>
                      {$t('common.actions.copy')}
                    </Button>
                    <Button variant="secondary" size="xs" icon="save" loading={savingProject} on:click={saveCurrentProject}>
                      {projBuiltin ? $t('reLab.emulate.forkSaveBtn') : $t('reLab.emulate.saveBtn')}
                    </Button>
                    {#if !isJobRunning}
                      <Button variant="primary" size="xs" icon="play" loading={startingJob} on:click={startREJob}>
                        {startingJob ? $t('reLab.emulate.starting') : $t('reLab.emulate.runJob')}
                      </Button>
                    {:else}
                      <Button variant="danger" size="xs" icon="square" on:click={cancelREJob}>
                        {$t('reLab.emulate.cancelJob')}
                      </Button>
                    {/if}
                  </div>

                  {#if showConfigStrip}
                    <div class="config-strip">
                      <label class="c-field">
                        <span>{$t('reLab.emulate.fields.binaryPath')}</span>
                        <input type="text" class="cap-input mono" bind:value={projBinaryPath} on:input={() => (projDirty = true)} placeholder="/path/to/libtarget.so" />
                      </label>
                      {#if projEngine === 'unidbg'}
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.apkPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={projAPKPath} on:input={() => (projDirty = true)} placeholder="/path/to/app.apk" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.targetClass')}</span>
                          <input type="text" class="cap-input mono" bind:value={projTargetClass} on:input={() => (projDirty = true)} placeholder="com/example/Signer" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.targetMethod')}</span>
                          <input type="text" class="cap-input mono" bind:value={projTargetMethod} on:input={() => (projDirty = true)} placeholder="sign(Ljava/lang/String;)Ljava/lang/String;" />
                        </label>
                      {:else if projEngine === 'angr'}
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.targetAddr')}</span>
                          <input type="text" class="cap-input mono" bind:value={projTargetAddr} on:input={() => (projDirty = true)} placeholder="0x401000" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.findAddr')}</span>
                          <input type="text" class="cap-input mono" bind:value={projFindAddr} on:input={() => (projDirty = true)} placeholder="0x401180" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.avoidAddr')}</span>
                          <input type="text" class="cap-input mono" bind:value={projAvoidAddr} on:input={() => (projDirty = true)} placeholder="0x401190" />
                        </label>
                      {:else if projEngine === 'qiling'}
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.rootfs')}</span>
                          <input type="text" class="cap-input mono" bind:value={projRootFS} on:input={() => (projDirty = true)} placeholder="./rootfs/arm64_linux" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.targetSymbol')}</span>
                          <input type="text" class="cap-input mono" bind:value={projTargetSymbol} on:input={() => (projDirty = true)} placeholder="Java_com_example_sign" />
                        </label>
                        <label class="c-field">
                          <span>{$t('reLab.emulate.fields.targetAddr')}</span>
                          <input type="text" class="cap-input mono" bind:value={projTargetAddr} on:input={() => (projDirty = true)} placeholder="0x1000" />
                        </label>
                      {/if}
                      <label class="c-field">
                        <span>{$t('reLab.emulate.fields.args')}</span>
                        <input type="text" class="cap-input mono" bind:value={projArgsText} on:input={() => (projDirty = true)} placeholder="arg1 arg2" />
                      </label>
                      <label class="c-field narrow">
                        <span>{$t('reLab.emulate.fields.timeoutSec')}</span>
                        <input type="number" class="cap-input mono" bind:value={projTimeoutSec} min="5" max="3600" />
                      </label>
                    </div>
                  {/if}

                  <div class="editor-host">
                    <CodeEditor
                      bind:this={emuEditorRef}
                      bind:value={projCode}
                      runtime={emuEditorRuntime}
                      minHeight="140px"
                      placeholder={$t('reLab.emulate.editorPlaceholder')}
                      shortcutHint={$t('reLab.emulate.shortcutHint', { mod: MOD_LABEL })}
                      on:input={() => (projDirty = true)}
                      on:save={saveCurrentProject}
                      on:run={() => { if (!isJobRunning) startREJob() }}
                    />
                  </div>
                </div>

                <!-- BOTTOM: Live Streaming Job Console + Extracted [CAP_RE] Results -->
                <div slot="secondary" class="panel-col surface">
                  <div class="console-bar">
                    <div class="c-tabs">
                      <button type="button" class="c-tab" class:active={jobConsoleFilter === 'all'} on:click={() => (jobConsoleFilter = 'all')}>
                        {$t('reLab.emulate.console.filterAll')} <span class="mono">{jobEventCounts.all}</span>
                      </button>
                      <button type="button" class="c-tab" class:active={jobConsoleFilter === 'result'} on:click={() => (jobConsoleFilter = 'result')}>
                        [CAP_RE] <span class="mono">{jobEventCounts.result}</span>
                      </button>
                      <button type="button" class="c-tab" class:active={jobConsoleFilter === 'stdout'} on:click={() => (jobConsoleFilter = 'stdout')}>
                        {$t('reLab.emulate.console.filterStdout')} <span class="mono">{jobEventCounts.stdout}</span>
                      </button>
                      <button type="button" class="c-tab" class:active={jobConsoleFilter === 'stderr'} on:click={() => (jobConsoleFilter = 'stderr')}>
                        {$t('reLab.emulate.console.filterStderr')} <span class="mono">{jobEventCounts.stderr}</span>
                      </button>
                      <button type="button" class="c-tab" class:active={jobConsoleFilter === 'system'} on:click={() => (jobConsoleFilter = 'system')}>
                        {$t('reLab.emulate.console.filterSystem')} <span class="mono">{jobEventCounts.system}</span>
                      </button>
                    </div>

                    <div class="c-tools">
                      {#if jobState && jobState.status !== 'idle'}
                        <Badge
                          variant={isJobRunning ? 'success' : jobState.status === 'error' ? 'danger' : jobState.status === 'done' ? 'info' : 'neutral'}
                          size="xs"
                          dot
                          pulse={isJobRunning}
                          mono
                        >
                          {jobState.status.toUpperCase()} · {formatClock(jobLiveElapsedMs)}
                        </Badge>
                      {/if}
                      <div class="search-box small">
                        <Icon name="search" size={11} />
                        <input type="text" class="search-input" bind:value={jobConsoleSearch} placeholder={$t('reLab.emulate.console.searchPlaceholder')} />
                      </div>
                      <label class="check-opt compact">
                        <input type="checkbox" bind:checked={jobAutoScroll} />
                        <span>{$t('reLab.emulate.console.autoScroll')}</span>
                      </label>
                      <Button
                        variant="secondary"
                        size="xs"
                        icon="sparkles"
                        active={showAutoStubDrawer}
                        on:click={openAutoStubAssistant}
                      >
                        {$t('reLab.emulate.autoStub.btn')}
                      </Button>
                      <Button variant="ghost" size="xs" icon="trash" disabled={jobEvents.length === 0 && jobResults.length === 0} on:click={clearJobConsole}>
                        {$t('common.actions.clear')}
                      </Button>
                    </div>
                  </div>

                  <!-- Extracted [CAP_RE] Concrete Results Strip -->
                  {#if jobResults.length > 0}
                    <div class="cap-re-results">
                      <div class="res-strip-head">
                        <Icon name="sparkles" size={12} />
                        <span>{$t('reLab.emulate.console.resultsHeader', { count: jobResults.length })}</span>
                      </div>
                      <div class="res-cards">
                        {#each jobResults as res, idx (idx)}
                          <div class="res-card">
                            <div class="res-card-top">
                              <Badge variant="success" size="xs" mono>{res.kind || 'result'}</Badge>
                              <span class="res-summary mono truncate">{res.summary}</span>
                              <button
                                type="button"
                                class="mini-icon-btn"
                                title={$t('common.actions.copy')}
                                on:click={() => copyToClipboard(JSON.stringify(res.payload || res, null, 2), translate('reLab.toast.copied'))}
                              >
                                <Icon name="copy" size={11} />
                              </button>
                            </div>
                            {#if res.payload && Object.keys(res.payload).length > 0}
                              <pre class="res-payload mono">{JSON.stringify(res.payload, null, 2)}</pre>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  <div class="console-stream" bind:this={jobConsoleEl}>
                    {#if filteredJobEvents.length === 0}
                      <EmptyState
                        icon="terminal"
                        title={$t('reLab.emulate.console.emptyTitle')}
                        description={$t('reLab.emulate.console.emptyDesc')}
                        compact
                      />
                    {:else}
                      {#each filteredJobEvents as ev, idx (`${ev.seq}:${idx}`)}
                        {@const hasData = Boolean(ev.data && Object.keys(ev.data).length > 0)}
                        {@const isExp = expandedJobEvents.has(ev.seq)}
                        <div class="ev-row lvl-{ev.level || ev.stream}">
                          <button
                            type="button"
                            class="ev-head"
                            class:clickable={hasData}
                            on:click={() => hasData && toggleJobEventExpand(ev.seq)}
                          >
                            <span class="ev-time mono tabular-nums">{formatEventTime(ev.timestamp_ms)}</span>
                            <Badge
                              variant={ev.stream === 'result' || ev.level === 'result'
                                ? 'success'
                                : ev.stream === 'stderr' || ev.level === 'error'
                                  ? 'danger'
                                  : ev.stream === 'system'
                                    ? 'info'
                                    : 'neutral'}
                              size="xs"
                              mono
                            >
                              {ev.stream || ev.level}
                            </Badge>
                            <span class="ev-msg mono">{ev.message}</span>
                            {#if hasData}
                              <Icon name={isExp ? 'chevron-down' : 'chevron-right'} size={12} />
                            {/if}
                          </button>
                          {#if hasData && isExp}
                            <pre class="ev-detail-pre mono">{JSON.stringify(ev.data, null, 2)}</pre>
                          {/if}
                        </div>
                      {/each}
                    {/if}
                  </div>
                </div>
              </SplitPane>
            </div>
          </SplitPane>
        </div>
      </div>

    <!-- ======================================================================
         SUB-TAB 3: JADX DECOMPILER & JAVA<->JNI CROSS-LINK
         ====================================================================== -->
    {:else if subTab === 'jadx'}
      <div class="subtab-pane">
        <!-- Top APK / DEX Bar + DetectJadx Badge + Search -->
        <section class="action-bar">
          <div class="input-with-icon wide">
            <Icon name="file-code" size={13} />
            <input
              type="text"
              class="cap-input mono flex-1"
              bind:value={jadxApkPath}
              placeholder={$t('reLab.jadx.apkPlaceholder')}
              on:keydown={(e) => { if (e.key === 'Enter') decompileWithJadx() }}
            />
          </div>
          <Button variant="primary" size="sm" icon="code" loading={decompilingJadx} on:click={decompileWithJadx}>
            {decompilingJadx ? $t('reLab.jadx.decompiling') : $t('reLab.jadx.decompileBtn')}
          </Button>

          <span class="v-sep"></span>

          <span title={jadxInfo?.available ? `${jadxInfo.path} (${jadxInfo.version})` : (jadxInfo?.issue || '')}>
            <Badge variant={jadxInfo?.available ? 'success' : 'info'} size="sm" dot>
              {jadxInfo?.available
                ? $t('reLab.jadx.jadxReady', { version: jadxInfo.version || 'OK' })
                : $t('reLab.jadx.jadxFallback')}
            </Badge>
          </span>
          <Button variant="ghost" size="xs" icon="refresh" iconOnly loading={probingJadx} title={$t('common.actions.refresh')} on:click={detectJadx} />

          {#if jadxWorkspace}
            <span class="v-sep"></span>
            <div class="search-box jadx-src-search">
              <Icon name="search" size={12} />
              <input
                type="text"
                class="search-input"
                bind:value={jadxSearchQuery}
                placeholder={$t('reLab.jadx.searchPlaceholder')}
                on:keydown={(e) => { if (e.key === 'Enter') searchJadxSource() }}
              />
            </div>
            <Button variant="secondary" size="sm" icon="search" loading={searchingJadx} disabled={!jadxSearchQuery.trim()} on:click={searchJadxSource}>
              {searchingJadx ? $t('reLab.jadx.searching') : $t('reLab.jadx.searchBtn')}
            </Button>
          {/if}
        </section>

        <!-- JADX Workspace Metadata Strip -->
        {#if jadxWorkspace}
          <section class="mitigation-strip">
            <div class="mit-group">
              <Badge variant={jadxWorkspace.mode === 'jadx' ? 'success' : 'info'} size="xs" mono>
                {jadxWorkspace.mode === 'jadx' ? $t('reLab.jadx.modeJadx') : $t('reLab.jadx.modeDex')}
              </Badge>
              {#if jadxWorkspace.cache_hit}
                <Badge variant="accent" size="xs">{$t('reLab.jadx.cacheHit')}</Badge>
              {/if}
              <span class="meta-text mono tabular-nums">
                {$t('reLab.jadx.statsClasses', {
                  classes: jadxWorkspace.class_count || 0,
                  native: jadxWorkspace.native_class_count || 0,
                })}
              </span>
              {#if jadxWorkspace.elapsed_ms > 0}
                <span class="meta-text mono tabular-nums">{formatDuration(jadxWorkspace.elapsed_ms)}</span>
              {/if}
            </div>
            <div class="strip-spacer"></div>
            <span class="meta-text mono truncate">{jadxWorkspace.workspace_dir}</span>
          </section>
        {/if}

        <div class="pane-fill">
          <SplitPane direction="horizontal" initialSize={32} minPrimary={22} minSecondary={44} storageKey="cap.relab.jadx.hsplit">
            <!-- LEFT: Class Tree List & Search Hits -->
            <div slot="primary" class="panel-col surface">
              <div class="inner-tabs">
                <button type="button" class="itab" class:active={jadxLeftTab === 'classes'} on:click={() => (jadxLeftTab = 'classes')}>
                  <span>{$t('reLab.jadx.classesTab')}</span>
                  <span class="itab-cnt mono tabular-nums">{filteredJadxClasses.length}</span>
                </button>
                <button type="button" class="itab" class:active={jadxLeftTab === 'search'} on:click={() => (jadxLeftTab = 'search')}>
                  <span>{$t('reLab.jadx.hitsTab')}</span>
                  <span class="itab-cnt mono tabular-nums">{jadxSearchHits.length}</span>
                </button>
              </div>

              {#if jadxLeftTab === 'classes'}
                <div class="list-toolbar">
                  <div class="search-box">
                    <Icon name="search" size={12} />
                    <input
                      type="text"
                      class="search-input"
                      bind:value={jadxClassFilter}
                      placeholder={$t('reLab.jadx.classFilterPlaceholder')}
                    />
                  </div>
                  <button
                    type="button"
                    class="filter-chip"
                    class:active={jadxNativeOnly}
                    on:click={() => (jadxNativeOnly = !jadxNativeOnly)}
                  >
                    {$t('reLab.jadx.nativeOnly')}
                  </button>
                </div>

                <div class="list-scroll">
                  {#if !jadxWorkspace}
                    <EmptyState icon="file-code" title={$t('reLab.jadx.emptyLeftTitle')} description={$t('reLab.jadx.emptyLeftDesc')} compact />
                  {:else if filteredJadxClasses.length === 0}
                    <EmptyState icon="search" title={$t('reLab.native.emptyFilterTitle')} compact />
                  {:else}
                    {#each filteredJadxClasses.slice(0, 600) as cls (cls.class_name)}
                      <button
                        type="button"
                        class="sym-row jadx-cls-row"
                        class:active={jadxSelectedClass === cls.class_name}
                        on:click={() => readJadxClassSource(cls.class_name)}
                      >
                        <div class="jadx-cls-main">
                          <span class="sym-name mono bold truncate" title={cls.class_name}>{cls.simple_name || cls.class_name}</span>
                          {#if cls.has_native}
                            <Badge variant="purple" size="xs" mono>native{cls.native_methods?.length ? ` ×${cls.native_methods.length}` : ''}</Badge>
                          {/if}
                        </div>
                        {#if cls.package_name}
                          <span class="meta-text mono truncate">{cls.package_name}</span>
                        {/if}
                      </button>
                    {/each}
                  {/if}
                </div>
              {:else}
                <div class="list-scroll">
                  {#if jadxSearchHits.length === 0}
                    <EmptyState icon="search" title={$t('reLab.native.emptyFilterTitle')} compact />
                  {:else}
                    {#each jadxSearchHits as hit, idx (`hit:${hit.class_name}:${hit.line}:${idx}`)}
                      <button
                        type="button"
                        class="sym-row xref-row"
                        class:active={jadxSelectedClass === hit.class_name}
                        on:click={() => readJadxClassSource(hit.class_name)}
                      >
                        <div class="xref-line mono">
                          <span class="accent-txt bold truncate">{hit.class_name}</span>
                          <Badge variant="neutral" size="xs" mono>L{hit.line}:{hit.column}</Badge>
                        </div>
                        <div class="xref-op mono truncate">{hit.snippet}</div>
                      </button>
                    {/each}
                  {/if}
                </div>
              {/if}
            </div>

            <!-- RIGHT: Read-Only Java Source Viewer (Top) + Java<->JNI Cross-Linker (Bottom) -->
            <div slot="secondary" class="panel-col">
              <SplitPane direction="vertical" initialSize={58} minPrimary={28} minSecondary={26} storageKey="cap.relab.jadx.vsplit">
                <!-- TOP: Decompiled Java Source Viewer -->
                <div slot="primary" class="panel-col">
                  <div class="pane-header">
                    <div class="ph-left">
                      {#if jadxClassSource}
                        <strong class="mono truncate fn-title">{jadxClassSource.class_name}</strong>
                        <Badge variant="neutral" size="xs" mono>{jadxClassSource.line_count} lines</Badge>
                        {#if jadxClassSource.has_native}
                          <Badge variant="purple" size="xs" mono>
                            {$t('reLab.jadx.nativeDeclsHeader', { count: jadxClassSource.native_methods?.length || 0 })}
                          </Badge>
                        {/if}
                      {:else}
                        <span class="ph-title">{$t('reLab.jadx.emptySourceTitle')}</span>
                      {/if}
                    </div>
                    <div class="ph-right">
                      {#if jadxClassSource?.source}
                        <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(jadxClassSource.source, translate('reLab.toast.copied'))}>
                          {$t('common.actions.copy')}
                        </Button>
                      {/if}
                    </div>
                  </div>

                  {#if jadxClassSource?.native_methods?.length > 0}
                    <div class="gen-meta-strip">
                      <div class="chip-wrap">
                        {#each jadxClassSource.native_methods as nm, idx (`nm:${nm.method_name}:${idx}`)}
                          <Badge variant="purple" size="xs" mono>
                            L{nm.line} {nm.is_static ? 'static ' : ''}{nm.method_name}{nm.jni_signature}
                          </Badge>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  <div class="editor-host">
                    {#if loadingJadxSource}
                      <div class="center-loading"><span class="meta-text">{$t('common.actions.loading')}</span></div>
                    {:else if !jadxClassSource}
                      <EmptyState icon="code" title={$t('reLab.jadx.emptySourceTitle')} description={$t('reLab.jadx.emptySourceDesc')} compact />
                    {:else}
                      <CodeEditor
                        bind:this={jadxEditorRef}
                        value={jadxClassSource.source || ''}
                        runtime="node"
                        readonly={true}
                        minHeight="140px"
                      />
                    {/if}
                  </div>
                </div>

                <!-- BOTTOM: Java <-> JNI Cross-Linker -->
                <div slot="secondary" class="panel-col surface">
                  <div class="pane-header compact">
                    <div class="ph-left">
                      <Icon name="link" size={13} />
                      <span class="ph-title">{$t('reLab.jadx.linker.title')}</span>
                      {#if jadxLinkReport}
                        <Badge variant="success" size="xs" mono>static:{jadxLinkReport.static_count}</Badge>
                        <Badge variant="purple" size="xs" mono>dynamic:{jadxLinkReport.dynamic_count}</Badge>
                        <Badge variant="warning" size="xs" mono>unresolved:{jadxLinkReport.unresolved_count}</Badge>
                      {/if}
                    </div>
                    <div class="ph-right">
                      {#if jadxLinkReport}
                        <div class="seg-toggle">
                          <button type="button" class="seg-btn" class:active={jadxLinkFilter === 'all'} on:click={() => (jadxLinkFilter = 'all')}>{$t('reLab.jadx.linker.filterAll')}</button>
                          <button type="button" class="seg-btn" class:active={jadxLinkFilter === 'static_export'} on:click={() => (jadxLinkFilter = 'static_export')}>{$t('reLab.jadx.linker.filterStatic')}</button>
                          <button type="button" class="seg-btn" class:active={jadxLinkFilter === 'dynamic_register'} on:click={() => (jadxLinkFilter = 'dynamic_register')}>{$t('reLab.jadx.linker.filterDynamic')}</button>
                          <button type="button" class="seg-btn" class:active={jadxLinkFilter === 'unresolved'} on:click={() => (jadxLinkFilter = 'unresolved')}>{$t('reLab.jadx.linker.filterUnresolved')}</button>
                        </div>
                      {/if}
                    </div>
                  </div>

                  <div class="r2-input-row">
                    <input
                      type="text"
                      class="cap-input mono flex-1"
                      bind:value={jadxSoPath}
                      placeholder={$t('reLab.jadx.linker.soPlaceholder')}
                    />
                    <Button variant="ghost" size="xs" icon="code" active={showRegNativesInput} on:click={() => (showRegNativesInput = !showRegNativesInput)}>
                      {$t('reLab.jadx.linker.regNativesToggle')}
                    </Button>
                    <Button variant="primary" size="xs" icon="link" loading={linkingJadx} disabled={!jadxWorkspace} on:click={linkJavaToNative}>
                      {linkingJadx ? $t('reLab.jadx.linker.linking') : $t('reLab.jadx.linker.linkBtn')}
                    </Button>
                  </div>

                  {#if showRegNativesInput}
                    <div class="jadx-reg-box">
                      <textarea
                        class="cap-textarea mono"
                        rows="3"
                        bind:value={jadxRegisterNativesJSON}
                        placeholder={$t('reLab.jadx.linker.regNativesPlaceholder')}
                      ></textarea>
                    </div>
                  {/if}

                  <div class="events-table-scroll">
                    {#if !jadxLinkReport}
                      <div class="r2-output-scroll"><div class="r2-empty">{$t('reLab.jadx.linker.emptyDesc')}</div></div>
                    {:else if filteredJadxBindings.length === 0}
                      <EmptyState icon="link" title={$t('reLab.native.emptyFilterTitle')} compact />
                    {:else}
                      <table class="data-table mono">
                        <thead>
                          <tr>
                            <th>{$t('reLab.jadx.linker.cols.javaMethod')}</th>
                            <th>{$t('reLab.jadx.linker.cols.kind')}</th>
                            <th>{$t('reLab.jadx.linker.cols.nativeTarget')}</th>
                            <th>{$t('reLab.jadx.linker.cols.actions')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each filteredJadxBindings as b, idx (`jb:${b.java_class}:${b.java_method}:${idx}`)}
                            <tr>
                              <td>
                                <button type="button" class="jump-link mono bold" on:click={() => readJadxClassSource(b.java_class)}>
                                  {b.java_class}.{b.java_method}
                                </button>
                                <div class="meta-text truncate">{b.java_signature}</div>
                              </td>
                              <td>
                                <Badge
                                  variant={b.binding_kind === 'static_export'
                                    ? 'success'
                                    : b.binding_kind === 'dynamic_register'
                                      ? 'purple'
                                      : 'warning'}
                                  size="xs"
                                  mono
                                >
                                  {b.binding_kind}
                                </Badge>
                              </td>
                              <td>
                                <div class="bold truncate">{b.native_symbol || b.mangled_name}</div>
                                {#if b.native_addr || b.so_name}
                                  <div class="meta-text">{b.so_name ? `${b.so_name} · ` : ''}{b.native_addr || formatHex(b.native_offset)}</div>
                                {/if}
                              </td>
                              <td>
                                <div class="inline-action-row">
                                  <Button variant="subtle" size="xs" icon="cpu" on:click={() => inspectJadxBindingInR2(b)}>
                                    {$t('reLab.jadx.linker.inspectR2')}
                                  </Button>
                                  <Button variant="subtle" size="xs" icon="play" on:click={() => emulateJadxBindingInUnidbg(b)}>
                                    {$t('reLab.jadx.linker.emulateUnidbg')}
                                  </Button>
                                </div>
                              </td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                      {#if jadxLinkReport.orphan_exports?.length > 0}
                        <div class="gen-footer">
                          <span class="gf-lbl">{$t('reLab.jadx.linker.orphanExports', { count: jadxLinkReport.orphan_exports.length })}:</span>
                          <div class="chip-wrap">
                            {#each jadxLinkReport.orphan_exports.slice(0, 30) as oe, idx (idx)}
                              <span class="mono-chip">{oe}</span>
                            {/each}
                          </div>
                        </div>
                      {/if}
                    {/if}
                  </div>
                </div>
              </SplitPane>
            </div>
          </SplitPane>
        </div>
      </div>

    <!-- ======================================================================
         SUB-TAB 4: DEOBF · ANTI-DEBUG · VMP · TLS/PROXY COMPAT
         ====================================================================== -->
    {:else if subTab === 'deobf'}
      <div class="subtab-pane">
        <!-- Top Scanner Bar + Inner View Switcher -->
        <section class="action-bar">
          <div class="input-with-icon wide">
            <Icon name="shield" size={13} />
            <input
              type="text"
              class="cap-input mono flex-1"
              bind:value={scanPath}
              placeholder={$t('reLab.deobf.scanPlaceholder')}
              on:keydown={(e) => { if (e.key === 'Enter') scanProtection() }}
            />
          </div>
          <Button variant="primary" size="sm" icon="radar" loading={scanningProtection} on:click={scanProtection}>
            {scanningProtection ? $t('reLab.deobf.scanning') : $t('reLab.deobf.scanBtn')}
          </Button>

          <span class="v-sep"></span>

          <div class="seg-toggle">
            <button type="button" class="seg-btn" class:active={deobfView === 'audit'} on:click={() => (deobfView = 'audit')}>
              {$t('reLab.deobf.views.audit')}
            </button>
            <button type="button" class="seg-btn" class:active={deobfView === 'scripts'} on:click={() => (deobfView = 'scripts')}>
              {$t('reLab.deobf.views.scripts')}
            </button>
            <button type="button" class="seg-btn" class:active={deobfView === 'vmp_trace'} on:click={() => (deobfView = 'vmp_trace')}>
              {$t('reLab.deobf.views.vmpTrace')}
            </button>
            <button
              type="button"
              class="seg-btn"
              class:active={deobfView === 'tls'}
              on:click={() => {
                deobfView = 'tls'
                if (!tlsApkPath && scanPath) tlsApkPath = scanPath
                if (!tlsProfiles.length) loadTlsEnvironment()
              }}
            >
              {$t('reLab.deobf.views.tls')}
            </button>
          </div>
        </section>

        <!-- VIEW A: Protection Audit Report -->
        {#if deobfView === 'audit'}
          <div class="scroll-workspace">
            {#if !protectionReport}
              <EmptyState
                icon="shield"
                title={$t('reLab.deobf.emptyAuditTitle')}
                description={$t('reLab.deobf.emptyAuditDesc')}
              >
                <Button variant="secondary" size="sm" icon="code" on:click={() => (deobfView = 'scripts')}>
                  {$t('reLab.deobf.views.scripts')}
                </Button>
                <Button variant="secondary" size="sm" icon="radar" on:click={() => (deobfView = 'vmp_trace')}>
                  {$t('reLab.deobf.views.vmpTrace')}
                </Button>
              </EmptyState>
            {:else}
              <!-- Risk Score Gauge + Hardening Banner -->
              <div class="risk-banner cap-card">
                <div class="risk-gauge">
                  <svg viewBox="0 0 80 80" class="gauge-svg">
                    <circle cx="40" cy="40" r="32" class="gauge-track" />
                    <circle
                      cx="40"
                      cy="40"
                      r="32"
                      class="gauge-fill"
                      style="stroke: {riskColorVar}; stroke-dasharray: {2 * Math.PI * 32}; stroke-dashoffset: {2 * Math.PI * 32 * (1 - Math.min(100, Math.max(0, riskScore)) / 100)};"
                    />
                  </svg>
                  <div class="gauge-val mono tabular-nums" style="color: {riskColorVar};">{riskScore}</div>
                </div>

                <div class="risk-info">
                  <div class="risk-top">
                    <Badge variant={hardeningVariant(riskLevel)} size="md" solid={riskLevel === 'extreme'}>
                      {$t(`reLab.deobf.hardening.${riskLevel}`)}
                    </Badge>
                    <Badge variant="neutral" size="xs" mono>{(protectionReport.target_kind || '').toUpperCase()}</Badge>
                    <span class="mono truncate target-path-lbl">{protectionReport.target_path}</span>
                  </div>
                  <p class="risk-summary">{protectionReport.summary}</p>
                  <div class="quick-gen-bar">
                    <Button variant="primary" size="xs" icon="shield" on:click={() => generateDeobfScript('stealth')}>
                      {$t('reLab.deobf.quickGenerate.stealth')}
                    </Button>
                    {#if protectionReport.packers?.length > 0}
                      <Button variant="secondary" size="xs" icon="unlock" on:click={() => generateDeobfScript('unpack')}>
                        {$t('reLab.deobf.quickGenerate.unpack')}
                      </Button>
                    {/if}
                    {#if protectionReport.obfuscation?.length > 0}
                      <Button variant="secondary" size="xs" icon="git-branch" on:click={() => generateDeobfScript('ollvm')}>
                        {$t('reLab.deobf.quickGenerate.ollvm')}
                      </Button>
                    {/if}
                    {#if protectionReport.vmp_indicators?.length > 0}
                      <Button variant="secondary" size="xs" icon="radar" on:click={() => generateDeobfScript('vmp_stalker')}>
                        {$t('reLab.deobf.quickGenerate.vmp')}
                      </Button>
                    {/if}
                  </div>
                </div>
              </div>

              <!-- Actionable Recommendations -->
              {#if protectionReport.recommendations?.length > 0}
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="sparkles" size={13} />
                    <span>{$t('reLab.deobf.sections.recommendations')}</span>
                    <Badge variant="accent" size="xs" mono>{protectionReport.recommendations.length}</Badge>
                  </div>
                  <ul class="rec-list">
                    {#each protectionReport.recommendations as rec, idx (idx)}
                      <li>{rec}</li>
                    {/each}
                  </ul>
                </div>
              {/if}

              <!-- Structured 2x2 Findings Grid -->
              <div class="findings-grid">
                <!-- Packers -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="lock" size={13} />
                    <span>{$t('reLab.deobf.sections.packers')}</span>
                    <Badge variant={protectionReport.packers?.length ? 'danger' : 'neutral'} size="xs" mono>
                      {protectionReport.packers?.length || 0}
                    </Badge>
                  </div>
                  {#if !protectionReport.packers?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="finding-list">
                      {#each protectionReport.packers as pk, idx (`${pk.name}:${idx}`)}
                        <div class="finding-item">
                          <div class="fi-top">
                            <strong>{pk.name}</strong>
                            {#if pk.vendor}<Badge variant="neutral" size="xs">{pk.vendor}</Badge>{/if}
                            <Badge variant="danger" size="xs" mono>{Math.round((pk.confidence || 0) * 100)}%</Badge>
                          </div>
                          {#if pk.evidence?.length}
                            <div class="chip-wrap">
                              {#each pk.evidence as ev, j (j)}
                                <span class="mono-chip">{ev}</span>
                              {/each}
                            </div>
                          {/if}
                          {#if pk.unpack_strategy}
                            <div class="fi-note">{pk.unpack_strategy}</div>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>

                <!-- Obfuscation (OLLVM CFF/BCF/SUB, Indirect Branch, String Encryption) -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="git-branch" size={13} />
                    <span>{$t('reLab.deobf.sections.obfuscation')}</span>
                    <Badge variant={protectionReport.obfuscation?.length ? 'warning' : 'neutral'} size="xs" mono>
                      {protectionReport.obfuscation?.length || 0}
                    </Badge>
                  </div>
                  {#if !protectionReport.obfuscation?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="finding-list">
                      {#each protectionReport.obfuscation as obf, idx (`${obf.kind}:${obf.module}:${idx}`)}
                        <div class="finding-item">
                          <div class="fi-top">
                            <Badge variant="warning" size="xs" mono>{obf.kind}</Badge>
                            <span class="mono truncate">{obf.module}</span>
                            <Badge variant="neutral" size="xs" mono>{Math.round((obf.confidence || 0) * 100)}%</Badge>
                            {#if obf.entropy > 0}
                              <Badge variant="info" size="xs" mono>H={obf.entropy.toFixed(2)}</Badge>
                            {/if}
                          </div>
                          {#if obf.evidence?.length}
                            <div class="chip-wrap">
                              {#each obf.evidence as ev, j (j)}
                                <span class="mono-chip">{ev}</span>
                              {/each}
                            </div>
                          {/if}
                          {#if obf.remediation}
                            <div class="fi-note">{obf.remediation}</div>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>

                <!-- VMP Indicators -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="cpu" size={13} />
                    <span>{$t('reLab.deobf.sections.vmp')}</span>
                    <Badge variant={protectionReport.vmp_indicators?.length ? 'purple' : 'neutral'} size="xs" mono>
                      {protectionReport.vmp_indicators?.length || 0}
                    </Badge>
                  </div>
                  {#if !protectionReport.vmp_indicators?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="finding-list">
                      {#each protectionReport.vmp_indicators as vmp, idx (`${vmp.kind}:${vmp.module}:${idx}`)}
                        <div class="finding-item">
                          <div class="fi-top">
                            <Badge variant="purple" size="xs" mono>{vmp.kind}</Badge>
                            <span class="mono truncate">{vmp.module}{vmp.section ? ` (${vmp.section})` : ''}</span>
                            <Badge variant="neutral" size="xs" mono>{Math.round((vmp.confidence || 0) * 100)}%</Badge>
                            {#if vmp.handler_table_estimate > 0}
                              <Badge variant="accent" size="xs" mono>~{vmp.handler_table_estimate} handlers</Badge>
                            {/if}
                          </div>
                          {#if vmp.evidence?.length}
                            <div class="chip-wrap">
                              {#each vmp.evidence as ev, j (j)}
                                <span class="mono-chip">{ev}</span>
                              {/each}
                            </div>
                          {/if}
                          {#if vmp.strategy}
                            <div class="fi-note">{vmp.strategy}</div>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>

                <!-- Anti-Debug & ARM64 SVC #0 -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="bug" size={13} />
                    <span>{$t('reLab.deobf.sections.antiDebug')}</span>
                    <Badge variant={protectionReport.anti_debug_findings?.length ? 'danger' : 'neutral'} size="xs" mono>
                      {protectionReport.anti_debug_findings?.length || 0}
                    </Badge>
                  </div>
                  {#if !protectionReport.anti_debug_findings?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="finding-list">
                      {#each protectionReport.anti_debug_findings as ad, idx (`${ad.kind}:${ad.module}:${ad.offset_hex}:${idx}`)}
                        <div class="finding-item">
                          <div class="fi-top">
                            <Badge variant={severityVariant(ad.severity)} size="xs" mono>{ad.severity}</Badge>
                            <Badge variant="neutral" size="xs" mono>{ad.kind}</Badge>
                            <span class="mono truncate">{ad.module}</span>
                            {#if ad.offset_hex}
                              <Badge variant="accent" size="xs" mono>{ad.offset_hex}</Badge>
                            {/if}
                          </div>
                          <div class="mono fi-pattern">{ad.symbol_or_pattern}</div>
                          {#if ad.countermeasure}
                            <div class="fi-note">{ad.countermeasure}</div>
                          {/if}
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              </div>

              <!-- SO Entropy & Security Audit Table -->
              {#if protectionReport.so_audits?.length > 0}
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="layers" size={13} />
                    <span>{$t('reLab.deobf.sections.soAudits')}</span>
                    <Badge variant="neutral" size="xs" mono>{protectionReport.so_audits.length}</Badge>
                  </div>
                  <div class="table-wrap">
                    <table class="data-table mono">
                      <thead>
                        <tr>
                          <th>{$t('reLab.deobf.soCols.name')}</th>
                          <th>{$t('reLab.deobf.soCols.arch')}</th>
                          <th>{$t('reLab.deobf.soCols.size')}</th>
                          <th>{$t('reLab.deobf.soCols.entropy')}</th>
                          <th>{$t('reLab.deobf.soCols.textRodata')}</th>
                          <th>{$t('reLab.deobf.soCols.initArray')}</th>
                          <th>{$t('reLab.deobf.soCols.svc')}</th>
                          <th>{$t('reLab.deobf.soCols.indBr')}</th>
                          <th>{$t('reLab.deobf.soCols.sections')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each protectionReport.so_audits as so, idx (`${so.name}:${idx}`)}
                          <tr>
                            <td class="bold">{so.name}</td>
                            <td><Badge variant="neutral" size="xs" mono>{so.arch || '—'}</Badge></td>
                            <td class="tabular-nums">{so.file_size ? formatBytes(so.file_size) : '—'}</td>
                            <td>
                              <div class="entropy-cell">
                                <span class="tabular-nums" class:danger-txt={so.entropy >= 7.2} class:warn-txt={so.entropy >= 6.5 && so.entropy < 7.2}>
                                  {(so.entropy || 0).toFixed(2)}
                                </span>
                                <div class="mini-bar">
                                  <div
                                    class="mini-bar-fill"
                                    style="width: {Math.min(100, ((so.entropy || 0) / 8) * 100)}%; background: {so.entropy >= 7.2 ? 'var(--status-danger)' : so.entropy >= 6.5 ? 'var(--status-warning)' : 'var(--status-success)'};"
                                  ></div>
                                </div>
                              </div>
                            </td>
                            <td class="tabular-nums">{(so.text_entropy || 0).toFixed(2)} / {(so.rodata_entropy || 0).toFixed(2)}</td>
                            <td class="tabular-nums">{so.init_array_count || 0}</td>
                            <td>
                              <Badge variant={so.inline_svc_count > 0 ? 'danger' : 'neutral'} size="xs" mono>
                                {so.inline_svc_count || 0}
                              </Badge>
                            </td>
                            <td>
                              <Badge variant={so.indirect_branch_count > 20 ? 'warning' : 'neutral'} size="xs" mono>
                                {so.indirect_branch_count || 0}
                              </Badge>
                            </td>
                            <td>
                              {#if so.suspicious_sections?.length}
                                <div class="chip-wrap">
                                  {#each so.suspicious_sections as sec, j (j)}
                                    <Badge variant="purple" size="xs" mono>{sec}</Badge>
                                  {/each}
                                </div>
                              {:else}
                                <span class="meta-text">—</span>
                              {/if}
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                </div>
              {/if}
            {/if}
          </div>

        <!-- VIEW B: Composable Script Generators -->
        {:else if deobfView === 'scripts'}
          <div class="pane-fill">
            <SplitPane direction="horizontal" initialSize={36} minPrimary={26} minSecondary={42} storageKey="cap.relab.deobf.hsplit">
              <!-- LEFT: Generator Picker & Parameter Form -->
              <div slot="primary" class="panel-col surface">
                <div class="pane-header compact">
                  <span class="ph-title">{$t('reLab.deobf.generators.listTitle')}</span>
                </div>

                <div class="gen-scroll">
                  <div class="gen-list">
                    {#each DEOBF_GENERATORS as g (g.id)}
                      <button
                        type="button"
                        class="gen-card"
                        class:active={selectedGenerator === g.id}
                        on:click={() => (selectedGenerator = g.id)}
                      >
                        <div class="gc-top">
                          <Icon name={g.icon} size={13} />
                          <span class="gc-title">{$t(`reLab.deobf.generators.items.${g.id}.title`)}</span>
                          <Badge variant={engineVariant(g.engine)} size="xs" mono>{g.engine}</Badge>
                        </div>
                        <div class="gc-sub">{$t(`reLab.deobf.generators.items.${g.id}.sub`)}</div>
                      </button>
                    {/each}
                  </div>

                  <!-- Dynamic Generator Config Box -->
                  <div class="gen-form cap-card">
                    {#if selectedGenerator === 'stealth'}
                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.stealth.targetPkg')}</span>
                          <input type="text" class="cap-input mono" bind:value={stealthOpts.target_package} placeholder="com.example.app" />
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.stealth.targetSO')}</span>
                          <input type="text" class="cap-input mono" bind:value={stealthOpts.target_so} placeholder="libsec.so" />
                        </label>
                      </div>

                      <div class="form-section-label">{$t('reLab.deobf.generators.stealth.modules')}</div>
                      <div class="check-col">
                        <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.bypass_tracer_pid_and_proc_fs} /><span>{$t('reLab.deobf.generators.stealth.tracerPid')}</span></label>
                        <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.bypass_ptrace_and_signals} /><span>{$t('reLab.deobf.generators.stealth.ptrace')}</span></label>
                        <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.patch_inline_svc} /><span>{$t('reLab.deobf.generators.stealth.inlineSvc')}</span></label>
                        <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.bypass_timing_and_inotify} /><span>{$t('reLab.deobf.generators.stealth.timing')}</span></label>
                        <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.bypass_java_debug_checks} /><span>{$t('reLab.deobf.generators.stealth.javaDebug')}</span></label>
                        {#if stealthOpts.patch_inline_svc}
                          <label class="check-opt"><input type="checkbox" bind:checked={stealthOpts.dry_run_svc_patch} /><span>{$t('reLab.deobf.generators.stealth.dryRunSvc')}</span></label>
                        {/if}
                        {#if protectionReport}
                          <label class="check-opt">
                            <input
                              type="checkbox"
                              bind:checked={stealthUseReport}
                              on:change={() => {
                                if (stealthUseReport && protectionReport) {
                                  const { nextOpts } = deriveStealthOptsFromReport(protectionReport, stealthOpts, scanPath)
                                  stealthOpts = nextOpts
                                }
                              }}
                            />
                            <span>{$t('reLab.deobf.generators.stealth.useReport')}</span>
                          </label>
                        {/if}
                      </div>

                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.stealth.watchdogOffsets')}</span>
                          <input type="text" class="cap-input mono" bind:value={stealthWatchdogOffsets} placeholder="0x12340, 0x18a00" />
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.stealth.customTokens')}</span>
                          <input type="text" class="cap-input mono" bind:value={stealthCustomTokens} placeholder="hluda, re.frida" />
                        </label>
                      </div>

                    {:else if selectedGenerator === 'unpack' || selectedGenerator === 'java_deobf' || selectedGenerator === 'vmp_jni'}
                      <label class="d-field">
                        <span>{$t('reLab.deobf.generators.fields.targetPkg')}</span>
                        <input type="text" class="cap-input mono" bind:value={genTargetPkg} placeholder="com.example.app" />
                      </label>

                    {:else if selectedGenerator === 'ollvm'}
                      <label class="d-field">
                        <span>{$t('reLab.deobf.generators.fields.soPath')}</span>
                        <input type="text" class="cap-input mono" bind:value={genSoPath} placeholder="./libobf.so" />
                      </label>
                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.funcAddr')}</span>
                          <input type="text" class="cap-input mono" bind:value={genFuncAddr} placeholder="0x1000" />
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.arch')}</span>
                          <select class="cap-input mono" bind:value={genArch}>
                            <option value="arm64">arm64</option>
                            <option value="arm">arm</option>
                            <option value="x86_64">x86_64</option>
                            <option value="x86">x86</option>
                          </select>
                        </label>
                      </div>

                    {:else if selectedGenerator === 'string_decrypt'}
                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.engine')}</span>
                          <select class="cap-input mono" bind:value={genStrEngine}>
                            <option value="qiling">qiling (Python)</option>
                            <option value="unidbg">unidbg (Java)</option>
                          </select>
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.soPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={genSoPath} placeholder="./libtarget.so" />
                        </label>
                      </div>
                      {#if genStrEngine === 'unidbg'}
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.apkPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={genApkPath} placeholder="./target.apk" />
                        </label>
                      {/if}

                    {:else if selectedGenerator === 'vmp_stalker'}
                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.soName')}</span>
                          <input type="text" class="cap-input mono" bind:value={genVmpSoName} placeholder="libvmp.so" />
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.entrySym')}</span>
                          <input type="text" class="cap-input mono" bind:value={genVmpEntry} placeholder="JNI_OnLoad or 0x1a40" />
                        </label>
                      </div>
                      <label class="d-field">
                        <span>{$t('reLab.deobf.generators.fields.maxEvents')}</span>
                        <input type="number" class="cap-input mono" bind:value={genVmpMaxEvents} min="100" max="500000" />
                      </label>

                    {:else if selectedGenerator === 'vmp_unidbg'}
                      <div class="form-grid two-col">
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.apkPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={genApkPath} placeholder="./target.apk" />
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.deobf.generators.fields.soName')}</span>
                          <input type="text" class="cap-input mono" bind:value={genVmpSoName} placeholder="libvmp.so" />
                        </label>
                      </div>
                      <label class="d-field">
                        <span>{$t('reLab.deobf.generators.fields.className')}</span>
                        <input type="text" class="cap-input mono" bind:value={genVmpClassName} placeholder="com/example/security/VmpBridge" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.deobf.generators.fields.methodName')}</span>
                        <input type="text" class="cap-input mono" bind:value={genVmpMethodName} placeholder="sign(Ljava/lang/String;)Ljava/lang/String;" />
                      </label>
                    {/if}

                    <Button variant="primary" size="sm" icon="sparkles" fullWidth loading={generatingScript} on:click={() => generateDeobfScript()}>
                      {$t('reLab.deobf.generators.generateBtn')}
                    </Button>
                  </div>
                </div>
              </div>

              <!-- RIGHT: Generated Script Preview + Direct Handoff Buttons -->
              <div slot="secondary" class="panel-col">
                {#if !generatedScript}
                  <EmptyState
                    icon="code"
                    title={$t('reLab.deobf.generators.emptyPreviewTitle')}
                    description={$t('reLab.deobf.generators.emptyPreviewDesc')}
                  />
                {:else}
                  <div class="pane-header">
                    <div class="ph-left">
                      <strong class="truncate">{generatedScript.name}</strong>
                      <Badge variant={engineVariant(generatedScript.engine)} size="xs" mono>{generatedScript.engine}</Badge>
                      <Badge variant="neutral" size="xs" mono>{generatedScript.language}</Badge>
                    </div>
                    <div class="ph-right">
                      <Button
                        variant="secondary"
                        size="xs"
                        icon="copy"
                        on:click={() => copyToClipboard(generatedScript.code, translate('reLab.toast.copied'))}
                      >
                        {$t('reLab.deobf.generators.copyScript')}
                      </Button>
                      {#if generatedScript.engine === 'frida'}
                        <Button
                          variant="primary"
                          size="xs"
                          icon="zap"
                          on:click={() =>
                            sendScriptToFrida(
                              generatedScript.name,
                              generatedScript.category === 'stealth' ? 'anti-detect' : 'native',
                              generatedScript.description,
                              generatedScript.code,
                              stealthOpts.target_package || genTargetPkg
                            )}
                        >
                          {$t('reLab.deobf.generators.openFrida')}
                        </Button>
                      {:else}
                        <Button
                          variant="primary"
                          size="xs"
                          icon="play"
                          on:click={() =>
                            loadScriptIntoEmulation(
                              generatedScript.name,
                              generatedScript.engine,
                              generatedScript.description,
                              generatedScript.code,
                              {
                                binary_path: genSoPath,
                                apk_path: genApkPath,
                                target_addr: genFuncAddr,
                                target_class: genVmpClassName,
                                target_method: genVmpMethodName,
                              }
                            )}
                        >
                          {$t('reLab.deobf.generators.loadEmu')}
                        </Button>
                      {/if}
                    </div>
                  </div>

                  {#if generatedScript.modules?.length > 0 || generatedScript.description}
                    <div class="gen-meta-strip">
                      {#if generatedScript.description}
                        <div class="meta-desc">{generatedScript.description}</div>
                      {/if}
                      {#if generatedScript.modules?.length > 0}
                        <div class="chip-wrap">
                          {#each generatedScript.modules as m, idx (idx)}
                            <Badge variant="accent" size="xs" mono>{m}</Badge>
                          {/each}
                        </div>
                      {/if}
                    </div>
                  {/if}

                  <div class="editor-host">
                    <CodeEditor
                      bind:this={deobfEditorRef}
                      bind:value={generatedScript.code}
                      runtime={deobfEditorRuntime}
                      minHeight="160px"
                    />
                  </div>

                  {#if generatedScript.usage || generatedScript.notes?.length}
                    <div class="gen-footer">
                      {#if generatedScript.usage}
                        <div class="gf-line">
                          <span class="gf-lbl">{$t('reLab.deobf.generators.usageLabel')}:</span>
                          <code class="mono">{generatedScript.usage}</code>
                        </div>
                      {/if}
                      {#if generatedScript.notes?.length}
                        {#each generatedScript.notes as note, idx (idx)}
                          <div class="gf-note">• {note}</div>
                        {/each}
                      {/if}
                    </div>
                  {/if}
                {/if}
              </div>
            </SplitPane>
          </div>

        <!-- VIEW C: Interactive VMP Trace Analyzer -->
        {:else if deobfView === 'vmp_trace'}
          <div class="scroll-workspace">
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="radar" size={13} />
                <span>{$t('reLab.deobf.vmpAnalyzer.title')}</span>
              </div>
              <p class="sub-copy">{$t('reLab.deobf.vmpAnalyzer.subtitle')}</p>

              <div class="vmp-input-bar">
                <label class="d-field narrow-med">
                  <span>{$t('reLab.deobf.vmpAnalyzer.moduleBase')}</span>
                  <input type="text" class="cap-input mono" bind:value={vmpTraceBaseHex} placeholder={$t('reLab.deobf.vmpAnalyzer.moduleBasePlaceholder')} />
                </label>
                <div class="strip-spacer"></div>
                <Button variant="ghost" size="sm" icon="trash" disabled={!vmpTraceRaw} on:click={() => { vmpTraceRaw = ''; vmpTraceAnalysis = null }}>
                  {$t('reLab.deobf.vmpAnalyzer.clearBtn')}
                </Button>
                <Button variant="primary" size="sm" icon="radar" loading={analyzingVmpTrace} disabled={!vmpTraceRaw.trim()} on:click={analyzeVmpTrace}>
                  {$t('reLab.deobf.vmpAnalyzer.analyzeBtn')}
                </Button>
              </div>

              <textarea
                class="cap-textarea mono"
                rows="6"
                bind:value={vmpTraceRaw}
                placeholder={$t('reLab.deobf.vmpAnalyzer.tracePlaceholder')}
              ></textarea>
            </div>

            {#if vmpTraceAnalysis}
              <!-- KPIs -->
              <div class="kpi-grid six-col">
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums">{(vmpTraceAnalysis.total_instructions || 0).toLocaleString()}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.insns')}</div>
                </div>
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums">{(vmpTraceAnalysis.unique_pcs || 0).toLocaleString()}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.uniquePcs')}</div>
                </div>
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums accent-txt">{vmpTraceAnalysis.dispatcher_candidates?.length || 0}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.dispatchers')}</div>
                </div>
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums purple-txt">{vmpTraceAnalysis.handler_entries?.length || 0}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.handlers')}</div>
                </div>
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums warn-txt">{vmpTraceAnalysis.memory_hotspots?.length || 0}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.memSpots')}</div>
                </div>
                <div class="kpi-card cap-card">
                  <div class="kpi-val mono tabular-nums success-txt">{vmpTraceAnalysis.external_calls?.length || 0}</div>
                  <div class="kpi-lbl">{$t('reLab.deobf.vmpAnalyzer.kpis.extCalls')}</div>
                </div>
              </div>

              {#if vmpTraceAnalysis.summary}
                <div class="summary-banner cap-card">{vmpTraceAnalysis.summary}</div>
              {/if}

              <!-- Candidate Dispatcher Loops -->
              <div class="section-card cap-card">
                <div class="card-head">
                  <Icon name="flame" size={13} />
                  <span>{$t('reLab.deobf.vmpAnalyzer.dispatchersTitle')}</span>
                </div>
                {#if !vmpTraceAnalysis.dispatcher_candidates?.length}
                  <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                {:else}
                  <div class="table-wrap">
                    <table class="data-table mono">
                      <thead>
                        <tr>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.addr')}</th>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.fanout')}</th>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.hits')}</th>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.share')}</th>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.insn')}</th>
                          <th>{$t('reLab.deobf.vmpAnalyzer.cols.targets')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each vmpTraceAnalysis.dispatcher_candidates as d, idx (`disp:${d.address}:${idx}`)}
                          <tr>
                            <td class="bold accent-txt">{d.offset_hex ? `${d.address} (+${d.offset_hex})` : d.address}</td>
                            <td><Badge variant="danger" size="xs" mono>{d.unique_targets} targets</Badge></td>
                            <td class="tabular-nums">{d.hits}</td>
                            <td class="tabular-nums">{(d.share_percent || 0).toFixed(1)}%</td>
                            <td>{d.sample_insn || '—'}</td>
                            <td>
                              <div class="chip-wrap">
                                {#each (d.next_targets || []).slice(0, 6) as tgt, j (j)}
                                  <span class="mono-chip">{tgt}</span>
                                {/each}
                              </div>
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}
              </div>

              <div class="findings-grid">
                <!-- Virtual Handler Entries -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="layers" size={13} />
                    <span>{$t('reLab.deobf.vmpAnalyzer.handlersTitle')}</span>
                  </div>
                  {#if !vmpTraceAnalysis.handler_entries?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="table-wrap">
                      <table class="data-table mono">
                        <thead>
                          <tr>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.addr')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.hits')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.share')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.insn')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each vmpTraceAnalysis.handler_entries as h, idx (`hdl:${h.address}:${idx}`)}
                            <tr>
                              <td class="purple-txt">{h.offset_hex ? `${h.address} (+${h.offset_hex})` : h.address}</td>
                              <td class="tabular-nums">{h.hits}</td>
                              <td class="tabular-nums">{(h.share_percent || 0).toFixed(1)}%</td>
                              <td>{h.sample_insn || '—'}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  {/if}
                </div>

                <!-- Memory Hotspots -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="database" size={13} />
                    <span>{$t('reLab.deobf.vmpAnalyzer.memTitle')}</span>
                  </div>
                  {#if !vmpTraceAnalysis.memory_hotspots?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="table-wrap">
                      <table class="data-table mono">
                        <thead>
                          <tr>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.addr')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.role')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.readsWrites')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each vmpTraceAnalysis.memory_hotspots as ms, idx (`mem:${ms.address}:${idx}`)}
                            <tr>
                              <td>{ms.address}</td>
                              <td><Badge variant={roleVariant(ms.role)} size="xs" mono>{ms.role}</Badge></td>
                              <td class="tabular-nums">R:{ms.reads} / W:{ms.writes} ({ms.total_ops})</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  {/if}
                </div>
              </div>

              <div class="findings-grid">
                <!-- External Calls -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="external-link" size={13} />
                    <span>{$t('reLab.deobf.vmpAnalyzer.callsTitle')}</span>
                  </div>
                  {#if !vmpTraceAnalysis.external_calls?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <div class="table-wrap">
                      <table class="data-table mono">
                        <thead>
                          <tr>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.target')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.category')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.caller')}</th>
                            <th>{$t('reLab.deobf.vmpAnalyzer.cols.hits')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each vmpTraceAnalysis.external_calls as ec, idx (`call:${ec.target}:${idx}`)}
                            <tr>
                              <td class="bold">{ec.target}</td>
                              <td>
                                <Badge variant={ec.category === 'crypto' ? 'warning' : ec.category === 'jni' ? 'purple' : ec.category === 'antidebug' ? 'danger' : 'info'} size="xs" mono>
                                  {ec.category}
                                </Badge>
                              </td>
                              <td>{ec.caller_pc || '—'}</td>
                              <td class="tabular-nums">{ec.count}</td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    </div>
                  {/if}
                </div>

                <!-- Recommended Devirtualization Hooks -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="sparkles" size={13} />
                    <span>{$t('reLab.deobf.vmpAnalyzer.hooksTitle')}</span>
                  </div>
                  {#if !vmpTraceAnalysis.recommended_hooks?.length}
                    <div class="card-empty">{$t('reLab.deobf.noneDetected')}</div>
                  {:else}
                    <ul class="rec-list">
                      {#each vmpTraceAnalysis.recommended_hooks as hk, idx (idx)}
                        <li class="mono">{hk}</li>
                      {/each}
                    </ul>
                  {/if}
                </div>
              </div>
            {/if}
          </div>

        <!-- VIEW D: TLS / APK Certs / mTLS / Local-Proxy Compat -->
        {:else}
          <div class="scroll-workspace">
            <!-- 1. APK Certificate, Pin & mTLS Keystore Scanner -->
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="shield-check" size={13} />
                <span>{$t('reLab.deobf.tls.apkCertTitle')}</span>
                {#if tlsCertReport}
                  <Badge variant="info" size="xs" mono>{$t('reLab.deobf.tls.certsCount', { count: tlsCertReport.certificates?.length || 0 })}</Badge>
                  <Badge variant={tlsCertReport.has_pinning ? 'warning' : 'neutral'} size="xs" mono>{$t('reLab.deobf.tls.pinsCount', { count: tlsCertReport.pins?.length || 0 })}</Badge>
                  <Badge variant={tlsCertReport.has_mtls_indicators ? 'danger' : 'neutral'} size="xs" mono>{$t('reLab.deobf.tls.keystoresCount', { count: tlsCertReport.keystores?.length || 0 })}</Badge>
                {/if}
              </div>

              <div class="inline-action-row">
                <input
                  type="text"
                  class="cap-input mono flex-1"
                  bind:value={tlsApkPath}
                  placeholder={$t('reLab.deobf.tls.apkCertPlaceholder')}
                  on:keydown={(e) => { if (e.key === 'Enter') scanApkCertificates() }}
                />
                <Button variant="primary" size="sm" icon="search" loading={scanningTlsCerts} on:click={scanApkCertificates}>
                  {scanningTlsCerts ? $t('reLab.deobf.tls.scanningCerts') : $t('reLab.deobf.tls.scanCertsBtn')}
                </Button>
              </div>

              {#if tlsCertReport}
                <div class="chip-wrap">
                  {#if tlsCertReport.has_pinning}
                    <Badge variant="warning" size="xs" dot>{$t('reLab.deobf.tls.pinningDetected')}</Badge>
                  {/if}
                  {#if tlsCertReport.has_mtls_indicators}
                    <Badge variant="danger" size="xs" dot>{$t('reLab.deobf.tls.mtlsDetected')}</Badge>
                  {/if}
                  {#if tlsCertReport.truncated}
                    <Badge variant="warning" size="xs">{$t('reLab.deobf.tls.truncated')}</Badge>
                  {/if}
                  <span class="meta-text mono tabular-nums">{tlsCertReport.entries_scanned} entries · {formatBytes(tlsCertReport.total_bytes_read)}</span>
                </div>

                {#if tlsCertReport.certificates?.length > 0}
                  <div class="form-section-label">{$t('reLab.deobf.tls.certsSubTitle', { count: tlsCertReport.certificates.length })}</div>
                  <div class="table-wrap">
                    <table class="data-table mono">
                      <thead>
                        <tr>
                          <th>Subject / Source</th>
                          <th>Key</th>
                          <th>Status</th>
                          <th>SHA-256 / SPKI</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each tlsCertReport.certificates as cert, idx (`cert:${cert.sha256_fingerprint}:${idx}`)}
                          <tr>
                            <td>
                              <div class="bold">{cert.common_name || cert.subject}</div>
                              <div class="meta-text truncate">{cert.source_path || cert.issuer}</div>
                            </td>
                            <td>
                              <Badge variant="neutral" size="xs" mono>{cert.public_key_algorithm} {cert.public_key_bits}b</Badge>
                              {#if cert.is_ca}<Badge variant="purple" size="xs">CA</Badge>{/if}
                              {#if cert.self_signed}<Badge variant="warning" size="xs">Self-Signed</Badge>{/if}
                            </td>
                            <td>
                              <Badge variant={cert.expired ? 'danger' : cert.not_yet_valid ? 'warning' : 'success'} size="xs" mono>
                                {cert.expired
                                  ? $t('reLab.deobf.tls.certExpired')
                                  : cert.not_yet_valid
                                    ? $t('reLab.deobf.tls.certNotYetValid')
                                    : $t('reLab.deobf.tls.certValid')}
                              </Badge>
                              <div class="meta-text">{String(cert.not_after || '').slice(0, 10)}</div>
                            </td>
                            <td>
                              <div class="inline-action-row">
                                <span class="truncate-cell">{cert.spki_sha256 || cert.sha256_fingerprint}</span>
                                <button
                                  type="button"
                                  class="mini-icon-btn"
                                  title={$t('common.actions.copy')}
                                  aria-label={$t('common.actions.copy')}
                                  on:click={() => copyToClipboard(cert.spki_sha256 || cert.sha256_fingerprint, translate('reLab.toast.copied'))}
                                >
                                  <Icon name="copy" size={11} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}

                {#if tlsCertReport.pins?.length > 0 || tlsCertReport.network_security_configs?.length > 0}
                  <div class="form-section-label">{$t('reLab.deobf.tls.pinsSubTitle', { count: tlsCertReport.pins?.length || 0 })}</div>
                  <div class="finding-list">
                    {#each tlsCertReport.network_security_configs || [] as nsc, idx (`nsc:${nsc.path}:${idx}`)}
                      <div class="finding-item">
                        <div class="fi-top">
                          <span class="mono bold">{nsc.path}</span>
                          <Badge variant={nsc.trusts_user_certs ? 'success' : 'warning'} size="xs">
                            {$t('reLab.deobf.tls.nscTrustsUser')}: {nsc.trusts_user_certs ? 'YES' : 'NO'}
                          </Badge>
                          {#if nsc.cleartext_permitted !== null && nsc.cleartext_permitted !== undefined}
                            <Badge variant={nsc.cleartext_permitted ? 'warning' : 'info'} size="xs">
                              {$t('reLab.deobf.tls.nscCleartext')}: {nsc.cleartext_permitted ? 'YES' : 'NO'}
                            </Badge>
                          {/if}
                        </div>
                        {#if nsc.domains?.length}
                          <div class="chip-wrap">
                            {#each nsc.domains as d, j (j)}<span class="mono-chip">{d}</span>{/each}
                          </div>
                        {/if}
                      </div>
                    {/each}
                    {#each tlsCertReport.pins || [] as pin, idx (`pin:${pin.value}:${idx}`)}
                      <div class="finding-item">
                        <div class="fi-top">
                          <Badge variant="warning" size="xs" mono>{pin.digest || 'SHA-256'}</Badge>
                          <span class="mono bold truncate">{pin.value}</span>
                          {#if pin.expiration}<Badge variant="neutral" size="xs" mono>exp {pin.expiration}</Badge>{/if}
                          <button
                            type="button"
                            class="mini-icon-btn"
                            title={$t('common.actions.copy')}
                            aria-label={$t('common.actions.copy')}
                            on:click={() => copyToClipboard(pin.value, translate('reLab.toast.copied'))}
                          >
                            <Icon name="copy" size={11} />
                          </button>
                        </div>
                        {#if pin.domains?.length}
                          <div class="chip-wrap">
                            {#each pin.domains as d, j (j)}<span class="mono-chip">{d}</span>{/each}
                          </div>
                        {/if}
                      </div>
                    {/each}
                  </div>
                {/if}

                {#if tlsCertReport.keystores?.length > 0}
                  <div class="form-section-label">{$t('reLab.deobf.tls.keystoresSubTitle', { count: tlsCertReport.keystores.length })}</div>
                  <div class="finding-list">
                    {#each tlsCertReport.keystores as ks, idx (`ks:${ks.path}:${idx}`)}
                      <div class="finding-item">
                        <div class="fi-top">
                          <Badge variant="danger" size="xs" mono>{ks.format}</Badge>
                          <span class="mono bold truncate">{ks.path}</span>
                          <span class="meta-text mono tabular-nums">{formatBytes(ks.size_bytes)}</span>
                          {#if ks.magic_verified}<Badge variant="success" size="xs">Magic OK</Badge>{/if}
                          {#if ks.requires_mtls_config}<Badge variant="warning" size="xs">mTLS</Badge>{/if}
                        </div>
                        {#if ks.note}<div class="fi-note">{ks.note}</div>{/if}
                      </div>
                    {/each}
                  </div>
                {/if}

                {#if tlsCertReport.warnings?.length > 0}
                  <div class="issues-box">
                    {#each tlsCertReport.warnings as w, idx (idx)}
                      <div class="issue-line"><Icon name="alert-triangle" size={12} /><span>{w}</span></div>
                    {/each}
                  </div>
                {/if}
              {/if}
            </div>

            <!-- 2. mTLS KeyPair Validator & Host curl-impersonate / TLS Profiles -->
            <div class="findings-grid">
              <!-- mTLS Validator -->
              <div class="section-card cap-card">
                <div class="card-head">
                  <Icon name="key" size={13} />
                  <span>{$t('reLab.deobf.tls.mtlsTitle')}</span>
                </div>
                <label class="d-field">
                  <span>{$t('reLab.deobf.tls.certPath')}</span>
                  <input type="text" class="cap-input mono" bind:value={tlsMtlsCertPath} placeholder="/path/to/client.crt.pem" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.deobf.tls.keyPath')}</span>
                  <input type="text" class="cap-input mono" bind:value={tlsMtlsKeyPath} placeholder="/path/to/client.key.pem" />
                </label>
                <div class="inline-action-row">
                  <div class="strip-spacer"></div>
                  <Button variant="primary" size="xs" icon="check-circle" loading={validatingMtls} disabled={!tlsMtlsCertPath.trim() || !tlsMtlsKeyPath.trim()} on:click={validateMtlsKeyPair}>
                    {validatingMtls ? $t('reLab.deobf.tls.validating') : $t('reLab.deobf.tls.validateBtn')}
                  </Button>
                </div>

                {#if tlsMtlsResult}
                  <div class="finding-item">
                    <div class="fi-top">
                      <Badge variant={tlsMtlsResult.valid ? 'success' : 'danger'} size="xs" solid={!tlsMtlsResult.valid}>
                        {tlsMtlsResult.valid ? $t('reLab.deobf.tls.pairValid') : $t('reLab.deobf.tls.pairInvalid')}
                      </Badge>
                      <Badge variant={tlsMtlsResult.key_pair_match ? 'success' : 'danger'} size="xs">
                        {$t('reLab.deobf.tls.pairMatch')}: {tlsMtlsResult.key_pair_match ? 'OK' : 'NO'}
                      </Badge>
                      {#if tlsMtlsResult.has_client_auth_eku}
                        <Badge variant="info" size="xs">{$t('reLab.deobf.tls.clientAuthEku')}</Badge>
                      {/if}
                      {#if !tlsMtlsResult.expired && tlsMtlsResult.expires_in_days > 0}
                        <Badge variant="neutral" size="xs" mono>{$t('reLab.deobf.tls.expiresIn', { days: tlsMtlsResult.expires_in_days })}</Badge>
                      {/if}
                    </div>
                    {#if tlsMtlsResult.leaf}
                      <div class="mono fi-pattern">{tlsMtlsResult.leaf.subject}</div>
                      <div class="fi-note mono">Issuer: {tlsMtlsResult.leaf.issuer} · Chain: {tlsMtlsResult.chain_length}</div>
                    {/if}
                    {#if tlsMtlsResult.error}
                      <div class="danger-txt fi-note">{tlsMtlsResult.error}</div>
                    {/if}
                    {#each tlsMtlsResult.warnings || [] as w, j (j)}
                      <div class="warn-txt fi-note">• {w}</div>
                    {/each}
                  </div>
                {/if}
              </div>

              <!-- Host curl-impersonate & Curated TLS Profiles -->
              <div class="section-card cap-card">
                <div class="card-head">
                  <Icon name="globe" size={13} />
                  <span>{$t('reLab.deobf.tls.profilesTitle')}</span>
                  <div class="strip-spacer"></div>
                  <Button variant="ghost" size="xs" icon="refresh" iconOnly loading={loadingTlsProfiles} title={$t('common.actions.refresh')} on:click={loadTlsEnvironment} />
                </div>

                {#if tlsCurlInfo}
                  <div class="finding-item">
                    <div class="fi-top">
                      <Badge variant={tlsCurlInfo.available ? 'success' : 'neutral'} size="xs" dot>
                        {tlsCurlInfo.available
                          ? $t('reLab.deobf.tls.curlReady', { bin: tlsCurlInfo.primary_binary || 'available' })
                          : $t('reLab.deobf.tls.curlMissing')}
                      </Badge>
                    </div>
                    {#if tlsCurlInfo.binaries?.length > 0}
                      <div class="chip-wrap">
                        {#each tlsCurlInfo.binaries as b, idx (`curl:${b.name}:${idx}`)}
                          <Badge variant="accent" size="xs" mono>{b.name} ({b.family})</Badge>
                        {/each}
                      </div>
                    {:else if tlsCurlInfo.install_hint}
                      <div class="fi-note">{tlsCurlInfo.install_hint}</div>
                    {/if}
                  </div>
                {/if}

                <div class="cat-pills inline-pills">
                  {#each tlsProfiles as prof (prof.id)}
                    <button
                      type="button"
                      class="cat-pill"
                      class:active={tlsSelectedProfileId === prof.id}
                      on:click={() => selectTlsProfile(prof.id)}
                    >
                      {prof.name}
                    </button>
                  {/each}
                </div>

                {#if selectedTlsProfile}
                  {@const ja3 = tlsProfileJA3?.profile_id === selectedTlsProfile.id ? tlsProfileJA3 : selectedTlsProfile.ja3}
                  <div class="finding-item">
                    <div class="fi-top">
                      <strong>{selectedTlsProfile.name}</strong>
                      <Badge variant="info" size="xs" mono>{selectedTlsProfile.platform}</Badge>
                      <Badge variant="neutral" size="xs" mono>{selectedTlsProfile.min_version_name}–{selectedTlsProfile.max_version_name}</Badge>
                      <Badge variant="accent" size="xs" mono>ALPN: {(selectedTlsProfile.alpn || []).join(', ')}</Badge>
                    </div>
                    <div class="fi-note">{selectedTlsProfile.description}</div>
                    {#if ja3}
                      <div class="ja3-box mono">
                        <div class="inline-action-row">
                          <span class="meta-text">{$t('reLab.deobf.tls.ja3Hash')}:</span>
                          <span class="accent-txt bold truncate">{ja3.ja3_hash}</span>
                          <button
                            type="button"
                            class="mini-icon-btn"
                            title={$t('common.actions.copy')}
                            aria-label={$t('common.actions.copy')}
                            on:click={() => copyToClipboard(ja3.ja3_hash, translate('reLab.toast.copied'))}
                          >
                            <Icon name="copy" size={11} />
                          </button>
                        </div>
                        <div class="fi-note truncate" title={ja3.ja3_string}>{$t('reLab.deobf.tls.ja3String')}: {ja3.ja3_string}</div>
                        <div class="meta-text">
                          {$t('reLab.deobf.tls.ciphersCurves', { ciphers: ja3.cipher_count, curves: ja3.curve_count })}
                        </div>
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>

            <!-- 3. Local-Proxy Compat Frida Script Generators -->
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="zap" size={13} />
                <span>{$t('reLab.deobf.tls.compatTitle')}</span>
                <div class="strip-spacer"></div>
                <div class="seg-toggle">
                  <button type="button" class="seg-btn" class:active={tlsCompatKind === 'flutter'} on:click={() => (tlsCompatKind = 'flutter')}>
                    {$t('reLab.deobf.tls.kinds.flutter')}
                  </button>
                  <button type="button" class="seg-btn" class:active={tlsCompatKind === 'cronet'} on:click={() => (tlsCompatKind = 'cronet')}>
                    {$t('reLab.deobf.tls.kinds.cronet')}
                  </button>
                  <button type="button" class="seg-btn" class:active={tlsCompatKind === 'mtls_observer'} on:click={() => (tlsCompatKind = 'mtls_observer')}>
                    {$t('reLab.deobf.tls.kinds.mtls_observer')}
                  </button>
                </div>
              </div>

              {#if tlsCompatKind === 'flutter'}
                <div class="drawer-grid four-col">
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.packageName')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsFlutterOpts.package_name} placeholder="com.example.flutterapp" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.platform')}</span>
                    <select class="cap-input mono" bind:value={tlsFlutterOpts.platform}>
                      <option value="android">android</option>
                      <option value="ios">ios</option>
                    </select>
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.moduleName')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsFlutterOpts.module_name} placeholder="libflutter.so" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.offsetHex')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsFlutterOpts.offset_hex} placeholder="0x5a1230" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.proxyHost')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsFlutterOpts.proxy_host} placeholder="127.0.0.1" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.proxyPort')}</span>
                    <input type="number" class="cap-input mono" bind:value={tlsFlutterOpts.proxy_port} min="1" max="65535" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.verifySymbol')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsFlutterOpts.verify_symbol} />
                  </label>
                  <div class="d-field center-v">
                    <label class="check-opt">
                      <input type="checkbox" bind:checked={tlsFlutterOpts.force_allow_local_verify} />
                      <span>{$t('reLab.deobf.tls.fields.forceLocalVerify')}</span>
                    </label>
                  </div>
                </div>
              {:else if tlsCompatKind === 'cronet'}
                <div class="drawer-grid four-col">
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.packageName')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsCronetOpts.package_name} placeholder="com.example.app" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.proxyHint')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsCronetOpts.proxy_hint} placeholder="127.0.0.1:8080" />
                  </label>
                  <div class="d-field center-v">
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsCronetOpts.disable_quic} /><span>{$t('reLab.deobf.tls.fields.disableQuic')}</span></label>
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsCronetOpts.configure_okhttp_protocols} /><span>{$t('reLab.deobf.tls.fields.okHttpProto')}</span></label>
                  </div>
                  <div class="d-field center-v">
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsCronetOpts.log_alt_svc_headers} /><span>{$t('reLab.deobf.tls.fields.logAltSvc')}</span></label>
                  </div>
                </div>
              {:else}
                <div class="drawer-grid four-col">
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.packageName')}</span>
                    <input type="text" class="cap-input mono" bind:value={tlsMtlsObsOpts.package_name} placeholder="com.example.app" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.deobf.tls.fields.maxAliases')}</span>
                    <input type="number" class="cap-input mono" bind:value={tlsMtlsObsOpts.max_aliases_per_store} min="1" max="256" />
                  </label>
                  <div class="d-field center-v">
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsMtlsObsOpts.observe_keystore} /><span>{$t('reLab.deobf.tls.fields.obsKeyStore')}</span></label>
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsMtlsObsOpts.observe_key_manager} /><span>{$t('reLab.deobf.tls.fields.obsKeyMgr')}</span></label>
                  </div>
                  <div class="d-field center-v">
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsMtlsObsOpts.observe_ssl_context} /><span>{$t('reLab.deobf.tls.fields.obsSslCtx')}</span></label>
                    <label class="check-opt"><input type="checkbox" bind:checked={tlsMtlsObsOpts.observe_certificates} /><span>{$t('reLab.deobf.tls.fields.obsCerts')}</span></label>
                  </div>
                </div>
              {/if}

              <div class="drawer-foot">
                <div class="strip-spacer"></div>
                {#if tlsGeneratedScript}
                  <Button variant="secondary" size="xs" icon="copy" on:click={() => copyToClipboard(tlsGeneratedScript.code, translate('reLab.toast.copied'))}>
                    {$t('common.actions.copy')}
                  </Button>
                  <Button
                    variant="success"
                    size="xs"
                    icon="zap"
                    on:click={() =>
                      sendScriptToFrida(
                        tlsGeneratedScript.name,
                        'ssl',
                        tlsGeneratedScript.description,
                        tlsGeneratedScript.code,
                        tlsGeneratedScript.package_name || ''
                      )}
                  >
                    {$t('reLab.deobf.tls.openFrida')}
                  </Button>
                {/if}
                <Button variant="primary" size="xs" icon="sparkles" loading={generatingTlsScript} on:click={generateTlsCompatScript}>
                  {$t('reLab.deobf.tls.generateBtn')}
                </Button>
              </div>

              {#if tlsGeneratedScript}
                <div class="collector-preview">
                  <div class="cp-head">
                    <strong class="mono">{tlsGeneratedScript.name}</strong>
                    <Badge variant="warning" size="xs" mono>{tlsGeneratedScript.kind}</Badge>
                    <span class="meta-text truncate">{tlsGeneratedScript.description}</span>
                  </div>
                  <div class="tls-editor-box">
                    <CodeEditor
                      bind:this={tlsEditorRef}
                      bind:value={tlsGeneratedScript.code}
                      runtime="node"
                      minHeight="210px"
                    />
                  </div>
                  {#if tlsGeneratedScript.notes?.length || tlsGeneratedScript.warnings?.length}
                    <div class="cp-steps">
                      {#each tlsGeneratedScript.notes || [] as note, idx (idx)}
                        <div>• {note}</div>
                      {/each}
                      {#each tlsGeneratedScript.warnings || [] as w, idx (idx)}
                        <div class="warn-txt">! {w}</div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </div>

    <!-- ======================================================================
         SUB-TAB 5: EXECTRACE & TAINT
         ====================================================================== -->
    {:else if subTab === 'exectrace'}
      <div class="subtab-pane">
        <!-- Top Actions Bar -->
        <section class="action-bar">
          <Button
            variant="primary"
            size="sm"
            icon="upload"
            active={showImportDrawer}
            on:click={() => {
              showImportDrawer = !showImportDrawer
              if (showImportDrawer) showCollectorDrawer = false
            }}
          >
            {$t('reLab.exectrace.importBtn')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="code"
            active={showCollectorDrawer}
            on:click={() => {
              showCollectorDrawer = !showCollectorDrawer
              if (showCollectorDrawer) showImportDrawer = false
            }}
          >
            {$t('reLab.exectrace.collectorBtn')}
          </Button>
          <Button variant="ghost" size="sm" icon="refresh" loading={loadingTraces} on:click={loadExecTraces}>
            {$t('common.actions.refresh')}
          </Button>

          <div class="strip-spacer"></div>

          {#if activeTrace}
            <span class="strip-label">{$t('reLab.exectrace.exportLabel')}</span>
            <Button variant="subtle" size="xs" icon="download" on:click={() => exportCurrentTrace('tenet')}>Tenet</Button>
            <Button variant="subtle" size="xs" icon="download" on:click={() => exportCurrentTrace('jsonl')}>JSONL</Button>
            <Button variant="subtle" size="xs" icon="download" on:click={() => exportCurrentTrace('markdown')}>Markdown</Button>
          {/if}
        </section>

        <!-- Drawer: Import Execution Trace -->
        {#if showImportDrawer}
          <section class="drawer-panel cap-card">
            <div class="drawer-head">
              <div class="ph-left">
                <div class="drawer-title">{$t('reLab.exectrace.importDrawer.title')}</div>
                <div class="seg-toggle">
                  <button type="button" class="seg-btn" class:active={importMode === 'paste'} on:click={() => (importMode = 'paste')}>
                    {$t('reLab.exectrace.importDrawer.modePaste')}
                  </button>
                  <button type="button" class="seg-btn" class:active={importMode === 'file'} on:click={() => (importMode = 'file')}>
                    {$t('reLab.exectrace.importDrawer.modeFile')}
                  </button>
                </div>
              </div>
              <Button variant="ghost" size="xs" icon="x" on:click={() => (showImportDrawer = false)}>
                {$t('common.actions.close')}
              </Button>
            </div>

            <div class="drawer-grid three-col">
              {#if importMode === 'paste'}
                <label class="d-field">
                  <span>{$t('reLab.exectrace.importDrawer.nameLabel')}</span>
                  <input type="text" class="cap-input mono" bind:value={importName} placeholder={$t('reLab.exectrace.importDrawer.namePlaceholder')} />
                </label>
              {:else}
                <label class="d-field">
                  <span>{$t('reLab.exectrace.importDrawer.filePathLabel')}</span>
                  <input type="text" class="cap-input mono" bind:value={importFilePath} placeholder={$t('reLab.exectrace.importDrawer.filePathPlaceholder')} />
                </label>
              {/if}
              <label class="d-field">
                <span>{$t('reLab.exectrace.importDrawer.formatLabel')}</span>
                <select class="cap-input mono" bind:value={importFormat}>
                  <option value="auto">{$t('reLab.exectrace.importDrawer.formatAuto')}</option>
                  <option value="unidbg">Unidbg</option>
                  <option value="stalker">Frida Stalker</option>
                  <option value="qiling">Qiling</option>
                  <option value="java_call">Java Call-Tree</option>
                  <option value="jsonl">JSONL</option>
                  <option value="tenet">Tenet</option>
                </select>
              </label>
              <label class="d-field">
                <span>{$t('reLab.exectrace.importDrawer.baseHexLabel')}</span>
                <input type="text" class="cap-input mono" bind:value={importBaseHex} placeholder="0x7a00000000" />
              </label>
            </div>

            {#if importMode === 'paste'}
              <textarea
                class="cap-textarea mono"
                rows="5"
                bind:value={importRawContent}
                placeholder={$t('reLab.exectrace.importDrawer.rawPlaceholder')}
              ></textarea>
            {/if}

            <div class="drawer-foot">
              <div class="strip-spacer"></div>
              <Button
                variant="primary"
                size="xs"
                icon="upload"
                loading={importingTrace}
                disabled={importMode === 'file' ? !importFilePath.trim() : !importRawContent.trim()}
                on:click={importTrace}
              >
                {importingTrace ? $t('reLab.exectrace.importDrawer.importing') : $t('reLab.exectrace.importDrawer.submitBtn')}
              </Button>
            </div>
          </section>
        {/if}

        <!-- Drawer: Collector Script Generator -->
        {#if showCollectorDrawer}
          <section class="drawer-panel cap-card">
            <div class="drawer-head">
              <div>
                <div class="drawer-title">{$t('reLab.exectrace.collectorDrawer.title')}</div>
                <div class="drawer-sub">{$t('reLab.exectrace.collectorDrawer.subtitle')}</div>
              </div>
              <Button variant="ghost" size="xs" icon="x" on:click={() => (showCollectorDrawer = false)}>
                {$t('common.actions.close')}
              </Button>
            </div>

            <div class="drawer-grid four-col">
              <label class="d-field">
                <span>{$t('reLab.exectrace.collectorDrawer.kindLabel')}</span>
                <select class="cap-input mono" bind:value={collectorKind}>
                  <option value="stalker">{$t('reLab.exectrace.collectorDrawer.kinds.stalker')}</option>
                  <option value="java_call">{$t('reLab.exectrace.collectorDrawer.kinds.java_call')}</option>
                  <option value="unidbg">{$t('reLab.exectrace.collectorDrawer.kinds.unidbg')}</option>
                  <option value="qiling">{$t('reLab.exectrace.collectorDrawer.kinds.qiling')}</option>
                </select>
              </label>
              <label class="d-field">
                <span>{$t('reLab.exectrace.collectorDrawer.targetPkg')}</span>
                <input type="text" class="cap-input mono" bind:value={collectorCfg.target_package} placeholder="com.example.app" />
              </label>
              {#if collectorKind === 'java_call'}
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.classFilter')}</span>
                  <input type="text" class="cap-input mono" bind:value={collectorCfg.class_filter} placeholder="com.example.*" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.methodFilter')}</span>
                  <input type="text" class="cap-input mono" bind:value={collectorCfg.method_filter} placeholder="*" />
                </label>
              {:else}
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.targetModule')}</span>
                  <input type="text" class="cap-input mono" bind:value={collectorCfg.target_module} placeholder="libnative-lib.so" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.targetSymbol')}</span>
                  <input type="text" class="cap-input mono" bind:value={collectorCfg.target_symbol} placeholder="Java_com_example_sign" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.targetOffset')}</span>
                  <input type="text" class="cap-input mono" bind:value={collectorCfg.target_offset} placeholder="0x1234 (opt)" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.exectrace.collectorDrawer.arch')}</span>
                  <select class="cap-input mono" bind:value={collectorCfg.arch}>
                    <option value="arm64">arm64</option>
                    <option value="arm">arm</option>
                    <option value="x86_64">x86_64</option>
                  </select>
                </label>
                {#if collectorKind === 'unidbg' || collectorKind === 'qiling'}
                  <label class="d-field">
                    <span>{$t('reLab.exectrace.collectorDrawer.binaryPath')}</span>
                    <input type="text" class="cap-input mono" bind:value={collectorCfg.binary_path} placeholder="./libnative-lib.so" />
                  </label>
                {/if}
                {#if collectorKind === 'unidbg'}
                  <label class="d-field">
                    <span>{$t('reLab.exectrace.collectorDrawer.apkPath')}</span>
                    <input type="text" class="cap-input mono" bind:value={collectorCfg.apk_path} placeholder="./app.apk" />
                  </label>
                {/if}
                {#if collectorKind === 'qiling'}
                  <label class="d-field">
                    <span>{$t('reLab.exectrace.collectorDrawer.rootfs')}</span>
                    <input type="text" class="cap-input mono" bind:value={collectorCfg.rootfs} placeholder="./rootfs/arm64_linux" />
                  </label>
                {/if}
              {/if}
              <label class="d-field">
                <span>{$t('reLab.exectrace.collectorDrawer.maxEvents')}</span>
                <input type="number" class="cap-input mono" bind:value={collectorCfg.max_events} min="100" max="500000" />
              </label>
            </div>

            <div class="drawer-foot">
              <label class="check-opt"><input type="checkbox" bind:checked={collectorCfg.include_regs} /><span>{$t('reLab.exectrace.collectorDrawer.includeRegs')}</span></label>
              <label class="check-opt"><input type="checkbox" bind:checked={collectorCfg.include_mem} /><span>{$t('reLab.exectrace.collectorDrawer.includeMem')}</span></label>
              <label class="check-opt"><input type="checkbox" bind:checked={collectorCfg.include_calls} /><span>{$t('reLab.exectrace.collectorDrawer.includeCalls')}</span></label>
              <div class="strip-spacer"></div>
              <Button variant="primary" size="xs" icon="sparkles" loading={generatingCollector} on:click={generateCollector}>
                {$t('reLab.exectrace.collectorDrawer.generateBtn')}
              </Button>
            </div>

            {#if generatedCollector}
              <div class="collector-preview">
                <div class="cp-head">
                  <strong class="mono">{generatedCollector.name}</strong>
                  <Badge variant="info" size="xs" mono>{generatedCollector.filename}</Badge>
                  <div class="strip-spacer"></div>
                  <Button variant="secondary" size="xs" icon="copy" on:click={() => copyToClipboard(generatedCollector.code, translate('reLab.toast.copied'))}>
                    {$t('common.actions.copy')}
                  </Button>
                  {#if generatedCollector.kind === 'stalker' || generatedCollector.kind === 'java_call'}
                    <Button
                      variant="primary"
                      size="xs"
                      icon="zap"
                      on:click={() =>
                        sendScriptToFrida(
                          generatedCollector.name,
                          'trace',
                          generatedCollector.description,
                          generatedCollector.code,
                          collectorCfg.target_package
                        )}
                    >
                      {$t('reLab.exectrace.collectorDrawer.openFrida')}
                    </Button>
                  {:else}
                    <Button
                      variant="primary"
                      size="xs"
                      icon="play"
                      on:click={() => {
                        showCollectorDrawer = false
                        loadScriptIntoEmulation(
                          generatedCollector.name,
                          generatedCollector.kind,
                          generatedCollector.description,
                          generatedCollector.code,
                          {
                            binary_path: collectorCfg.binary_path,
                            apk_path: collectorCfg.apk_path,
                            rootfs: collectorCfg.rootfs,
                          }
                        )
                      }}
                    >
                      {$t('reLab.exectrace.collectorDrawer.loadEmu')}
                    </Button>
                  {/if}
                </div>
                <pre class="collector-code mono">{generatedCollector.code}</pre>
                {#if generatedCollector.usage_steps?.length}
                  <div class="cp-steps">
                    {#each generatedCollector.usage_steps as st, idx (idx)}
                      <div>{idx + 1}. {st}</div>
                    {/each}
                  </div>
                {/if}
              </div>
            {/if}
          </section>
        {/if}

        <!-- Main ExecTrace SplitPane -->
        <div class="pane-fill">
          <SplitPane direction="horizontal" initialSize={25} minPrimary={19} minSecondary={54} storageKey="cap.relab.trace.hsplit">
            <!-- LEFT: Saved Sessions List -->
            <div slot="primary" class="panel-col surface">
              <div class="list-toolbar">
                <div class="search-box">
                  <Icon name="search" size={12} />
                  <input type="text" class="search-input" bind:value={traceListSearch} placeholder={$t('reLab.exectrace.searchSessions')} />
                </div>
              </div>

              <div class="list-scroll padded">
                {#if filteredTraceSessions.length === 0}
                  <EmptyState
                    icon="activity"
                    title={$t('reLab.exectrace.emptySessionsTitle')}
                    description={$t('reLab.exectrace.emptySessionsDesc')}
                    compact
                  />
                {:else}
                  {#each filteredTraceSessions as sess (sess.id)}
                    <button
                      type="button"
                      class="item-card"
                      class:active={selectedTraceId === sess.id}
                      on:click={() => selectTraceSession(sess.id)}
                    >
                      <div class="ic-top">
                        <Badge variant={engineVariant(sess.source)} size="xs" mono>{sess.source || 'trace'}</Badge>
                        {#if sess.arch}
                          <Badge variant="neutral" size="xs" mono>{sess.arch}</Badge>
                        {/if}
                        <span class="ic-origin mono tabular-nums">{sess.total_events || 0} ev</span>
                        <span
                          class="ic-del"
                          role="button"
                          tabindex="0"
                          title={$t('common.actions.delete')}
                          on:click={(ev) => deleteTraceSession(sess, ev)}
                          on:keydown={(ev) => { if (ev.key === 'Enter') deleteTraceSession(sess, ev) }}
                        >
                          <Icon name="trash" size={11} />
                        </span>
                      </div>
                      <div class="ic-name truncate">{sess.name || sess.id}</div>
                      <div class="ic-meta mono truncate">
                        {sess.target_module || '—'} · {sess.insn_count || 0} insns · {sess.unique_pcs || 0} PCs
                      </div>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- RIGHT: Multi-View Analysis (Overview | Events | Taint | Diff) -->
            <div slot="secondary" class="panel-col">
              <div class="inner-tabs">
                {#each ['overview', 'events', 'taint', 'diff'] as tab (tab)}
                  <button
                    type="button"
                    class="itab"
                    class:active={traceViewTab === tab}
                    on:click={() => (traceViewTab = tab)}
                  >
                    <span>{$t(`reLab.exectrace.views.${tab}`)}</span>
                    {#if tab === 'overview' && traceSummary?.crypto_hits?.length > 0}
                      <Badge variant="warning" size="xs" mono>{traceSummary.crypto_hits.length}</Badge>
                    {:else if tab === 'taint' && taintResult?.tainted_steps?.length > 0}
                      <Badge variant="accent" size="xs" mono>{taintResult.tainted_steps.length}</Badge>
                    {/if}
                  </button>
                {/each}
              </div>

              {#if traceViewTab === 'diff'}
                <!-- VIEW 4: ASLR-Normalized Trace Diff -->
                <div class="scroll-workspace">
                  {#if traceSessions.length < 2}
                    <EmptyState
                      icon="diff"
                      title={$t('reLab.exectrace.diff.emptyTitle')}
                      description={$t('reLab.exectrace.diff.needTwoSessions')}
                    />
                  {:else}
                    <div class="section-card cap-card">
                      <div class="drawer-grid four-col">
                        <label class="d-field">
                          <span>{$t('reLab.exectrace.diff.sessionA')}</span>
                          <select class="cap-input mono" bind:value={diffSessionA}>
                            {#each traceSessions as s (s.id)}
                              <option value={s.id}>{s.name || s.id} ({s.insn_count} insns)</option>
                            {/each}
                          </select>
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.exectrace.diff.sessionB')}</span>
                          <select class="cap-input mono" bind:value={diffSessionB}>
                            {#each traceSessions as s (s.id)}
                              <option value={s.id}>{s.name || s.id} ({s.insn_count} insns)</option>
                            {/each}
                          </select>
                        </label>
                        <label class="d-field">
                          <span>{$t('reLab.exectrace.diff.maxDiv')}</span>
                          <input type="number" class="cap-input mono" bind:value={diffMaxDivergences} min="1" max="500" />
                        </label>
                        <div class="d-field align-end">
                          <Button variant="primary" size="sm" icon="diff" loading={runningDiff} disabled={!diffSessionA || !diffSessionB} on:click={runTraceDiff}>
                            {runningDiff ? $t('reLab.exectrace.diff.running') : $t('reLab.exectrace.diff.runBtn')}
                          </Button>
                        </div>
                      </div>
                    </div>

                    {#if diffResult}
                      <div class="kpi-grid four-col">
                        <div class="kpi-card cap-card">
                          <div class="kpi-val mono tabular-nums">{diffResult.total_insns_a || 0}</div>
                          <div class="kpi-lbl">{$t('reLab.exectrace.diff.insnsA')}</div>
                        </div>
                        <div class="kpi-card cap-card">
                          <div class="kpi-val mono tabular-nums">{diffResult.total_insns_b || 0}</div>
                          <div class="kpi-lbl">{$t('reLab.exectrace.diff.insnsB')}</div>
                        </div>
                        <div class="kpi-card cap-card">
                          <div class="kpi-val mono tabular-nums success-txt">{diffResult.common_prefix_len || 0}</div>
                          <div class="kpi-lbl">{$t('reLab.exectrace.diff.prefixLen')}</div>
                        </div>
                        <div class="kpi-card cap-card">
                          <div class="kpi-val mono tabular-nums danger-txt">{diffResult.divergence_points?.length || 0}</div>
                          <div class="kpi-lbl">{$t('reLab.exectrace.diff.divergences')}</div>
                        </div>
                      </div>

                      {#if diffResult.summary}
                        <div class="summary-banner cap-card">{diffResult.summary}</div>
                      {/if}

                      {#if diffResult.first_divergence}
                        {@const fd = diffResult.first_divergence}
                        <div class="section-card cap-card first-div-card">
                          <div class="card-head">
                            <Icon name="alert-triangle" size={13} />
                            <span>{$t('reLab.exectrace.diff.firstDivTitle')}</span>
                            <Badge variant="danger" size="xs" mono>Index #{fd.index}</Badge>
                          </div>
                          <div class="div-compare mono">
                            <div class="div-side">
                              <div class="div-side-lbl">Session A · Seq #{fd.seq_a}</div>
                              <div class="accent-txt">{fd.module_a ? `${fd.module_a}+` : ''}{formatHex(fd.offset_a || fd.address_a)} <span class="meta-text">({formatHex(fd.address_a)})</span></div>
                              <div class="div-insn">{fd.insn_a || '—'}</div>
                            </div>
                            <div class="div-side">
                              <div class="div-side-lbl">Session B · Seq #{fd.seq_b}</div>
                              <div class="danger-txt">{fd.module_b ? `${fd.module_b}+` : ''}{formatHex(fd.offset_b || fd.address_b)} <span class="meta-text">({formatHex(fd.address_b)})</span></div>
                              <div class="div-insn">{fd.insn_b || '—'}</div>
                            </div>
                          </div>
                          {#if fd.reason}
                            <div class="fi-note">{fd.reason}</div>
                          {/if}
                          {#if fd.reg_diffs?.length}
                            <div class="reg-diff-block">
                              <span class="strip-label">{$t('reLab.exectrace.diff.regDiffs')}:</span>
                              <div class="chip-wrap">
                                {#each fd.reg_diffs as rd, j (j)}
                                  <Badge variant="warning" size="xs" mono>{rd}</Badge>
                                {/each}
                              </div>
                            </div>
                          {/if}
                        </div>
                      {/if}

                      {#if diffResult.divergence_points?.length > 1}
                        <div class="section-card cap-card">
                          <div class="card-head">
                            <span>{$t('reLab.exectrace.diff.allDivTitle', { count: diffResult.divergence_points.length })}</span>
                          </div>
                          <div class="table-wrap">
                            <table class="data-table mono">
                              <thead>
                                <tr>
                                  <th>#</th>
                                  <th>Seq A / B</th>
                                  <th>PC A (Norm)</th>
                                  <th>PC B (Norm)</th>
                                  <th>Insn A</th>
                                  <th>Insn B</th>
                                  <th>Reason</th>
                                </tr>
                              </thead>
                              <tbody>
                                {#each diffResult.divergence_points as dp, idx (`dp:${dp.index}:${idx}`)}
                                  <tr>
                                    <td class="tabular-nums">{dp.index}</td>
                                    <td class="tabular-nums">{dp.seq_a} / {dp.seq_b}</td>
                                    <td class="accent-txt">{formatHex(dp.offset_a || dp.address_a)}</td>
                                    <td class="danger-txt">{formatHex(dp.offset_b || dp.address_b)}</td>
                                    <td>{dp.insn_a || '—'}</td>
                                    <td>{dp.insn_b || '—'}</td>
                                    <td>{dp.reason || '—'}</td>
                                  </tr>
                                {/each}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      {/if}

                      <div class="findings-grid">
                        <div class="section-card cap-card">
                          <div class="card-head">{$t('reLab.exectrace.diff.onlyInA', { count: diffResult.only_in_a?.length || 0 })}</div>
                          <div class="chip-wrap">
                            {#each (diffResult.only_in_a || []).slice(0, 80) as pc, idx (idx)}
                              <span class="mono-chip">{pc}</span>
                            {/each}
                          </div>
                        </div>
                        <div class="section-card cap-card">
                          <div class="card-head">{$t('reLab.exectrace.diff.onlyInB', { count: diffResult.only_in_b?.length || 0 })}</div>
                          <div class="chip-wrap">
                            {#each (diffResult.only_in_b || []).slice(0, 80) as pc, idx (idx)}
                              <span class="mono-chip">{pc}</span>
                            {/each}
                          </div>
                        </div>
                      </div>
                    {:else}
                      <EmptyState
                        icon="diff"
                        title={$t('reLab.exectrace.diff.emptyTitle')}
                        description={$t('reLab.exectrace.diff.emptyDesc')}
                        compact
                      />
                    {/if}
                  {/if}
                </div>

              {:else if !activeTrace}
                <EmptyState
                  icon="activity"
                  title={$t('reLab.exectrace.selectSessionTitle')}
                  description={$t('reLab.exectrace.selectSessionDesc')}
                />

              {:else if traceViewTab === 'overview'}
                <!-- VIEW 1: Overview (KPIs, Crypto Hits, Memory Heatmap, Hot Functions & Loops) -->
                <div class="scroll-workspace">
                  <div class="kpi-grid five-col">
                    <div class="kpi-card cap-card">
                      <div class="kpi-val mono tabular-nums">{(activeTrace.total_events || 0).toLocaleString()}</div>
                      <div class="kpi-lbl">{$t('reLab.exectrace.overview.kpis.totalEvents')}</div>
                    </div>
                    <div class="kpi-card cap-card">
                      <div class="kpi-val mono tabular-nums accent-txt">{(activeTrace.insn_count || 0).toLocaleString()}</div>
                      <div class="kpi-lbl">{$t('reLab.exectrace.overview.kpis.insns')}</div>
                    </div>
                    <div class="kpi-card cap-card">
                      <div class="kpi-val mono tabular-nums warn-txt">{(activeTrace.mem_op_count || 0).toLocaleString()}</div>
                      <div class="kpi-lbl">{$t('reLab.exectrace.overview.kpis.memOps')}</div>
                    </div>
                    <div class="kpi-card cap-card">
                      <div class="kpi-val mono tabular-nums purple-txt">{(activeTrace.call_count || 0).toLocaleString()}</div>
                      <div class="kpi-lbl">{$t('reLab.exectrace.overview.kpis.calls')}</div>
                    </div>
                    <div class="kpi-card cap-card">
                      <div class="kpi-val mono tabular-nums success-txt">{(activeTrace.unique_pcs || 0).toLocaleString()}</div>
                      <div class="kpi-lbl">{$t('reLab.exectrace.overview.kpis.uniquePcs')}</div>
                    </div>
                  </div>

                  {#if traceSummary?.summary_text}
                    <div class="summary-banner cap-card">
                      <span>{traceSummary.summary_text}</span>
                      {#if activeTrace.module_base}
                        <Badge variant="neutral" size="xs" mono>Base {formatHex(activeTrace.module_base)}</Badge>
                      {/if}
                    </div>
                  {/if}

                  <!-- Crypto Constants & S-Box Hits -->
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="key" size={13} />
                      <span>{$t('reLab.exectrace.overview.cryptoTitle')}</span>
                      <Badge variant={traceSummary?.crypto_hits?.length ? 'warning' : 'neutral'} size="xs" mono>
                        {traceSummary?.crypto_hits?.length || 0}
                      </Badge>
                    </div>
                    {#if !traceSummary?.crypto_hits?.length}
                      <div class="card-empty">{$t('reLab.exectrace.overview.noCrypto')}</div>
                    {:else}
                      <div class="crypto-grid">
                        {#each traceSummary.crypto_hits as hit, idx (`${hit.algorithm}:${hit.seq}:${idx}`)}
                          <div class="crypto-card">
                            <div class="fi-top">
                              <Badge variant="warning" size="xs" mono>{hit.algorithm}</Badge>
                              <Badge variant="neutral" size="xs" mono>{Math.round((hit.confidence || 0) * 100)}%</Badge>
                              <span class="meta-text mono">Seq #{hit.seq}</span>
                              <div class="strip-spacer"></div>
                              <Button
                                variant="ghost"
                                size="xs"
                                on:click={() => seedTaintFromCryptoHit(hit)}
                              >
                                {$t('reLab.exectrace.overview.seedTaintBtn')}
                              </Button>
                            </div>
                            <div class="mono accent-txt">{formatHex(hit.address)}{hit.offset ? ` (+${formatHex(hit.offset)})` : ''}</div>
                            <div class="fi-note">{hit.evidence}</div>
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>

                  <!-- Memory Region Buffer Heatmap -->
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="database" size={13} />
                      <span>{$t('reLab.exectrace.overview.memHeatmapTitle')}</span>
                      <Badge variant="neutral" size="xs" mono>{traceSummary?.memory_regions?.length || 0}</Badge>
                    </div>
                    {#if !traceSummary?.memory_regions?.length}
                      <div class="card-empty">{$t('reLab.exectrace.overview.noMemRegions')}</div>
                    {:else}
                      <div class="heatmap-list">
                        {#each traceSummary.memory_regions as mr, idx (`mr:${mr.base_addr}:${idx}`)}
                          {@const total = (mr.read_count || 0) + (mr.write_count || 0)}
                          {@const readPct = Math.round(((mr.read_count || 0) / maxMemOps) * 100)}
                          {@const writePct = Math.round(((mr.write_count || 0) / maxMemOps) * 100)}
                          <div class="heatmap-row">
                            <div class="hm-addr mono">
                              {mr.base_addr_hex || formatHex(mr.base_addr)}..{mr.end_addr_hex || formatHex(mr.end_addr)}
                            </div>
                            <Badge variant={roleVariant(mr.role_hint)} size="xs" mono>
                              {$t(`reLab.exectrace.overview.roles.${mr.role_hint}`)}
                            </Badge>
                            <div class="hm-bars">
                              <div class="hm-bar-track" title="Reads: {mr.read_count} · Writes: {mr.write_count}">
                                <div class="hm-read" style="width: {Math.max(2, readPct)}%;"></div>
                                <div class="hm-write" style="width: {writePct}%;"></div>
                              </div>
                              <span class="hm-counts mono tabular-nums">R:{mr.read_count} W:{mr.write_count} ({mr.unique_addrs} addrs)</span>
                            </div>
                            {#if mr.sample_hex}
                              <span class="hm-sample mono truncate" title={mr.sample_hex}>{mr.sample_hex}</span>
                            {/if}
                            <Button
                              variant="subtle"
                              size="xs"
                              on:click={() => seedTaintFromMemRegion(mr)}
                            >
                              {$t('reLab.exectrace.overview.seedTaintBtn')}
                            </Button>
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>

                  <!-- Hot Functions & Hot Loops -->
                  <div class="findings-grid">
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="flame" size={13} />
                        <span>{$t('reLab.exectrace.overview.hotFuncsTitle')}</span>
                      </div>
                      {#if !traceSummary?.hot_functions?.length}
                        <div class="card-empty">{$t('reLab.exectrace.overview.noHotFuncs')}</div>
                      {:else}
                        <div class="table-wrap">
                          <table class="data-table mono">
                            <thead>
                              <tr>
                                <th>Function</th>
                                <th>Hits</th>
                                <th>Insns</th>
                                <th>Children</th>
                              </tr>
                            </thead>
                            <tbody>
                              {#each traceSummary.hot_functions.slice(0, 25) as fn, idx (`hf:${fn.name}:${idx}`)}
                                <tr>
                                  <td class="bold truncate" title={fn.name}>{fn.name}</td>
                                  <td class="tabular-nums">{fn.hits}</td>
                                  <td class="tabular-nums">{fn.insn_count}</td>
                                  <td class="tabular-nums">{fn.child_calls}</td>
                                </tr>
                              {/each}
                            </tbody>
                          </table>
                        </div>
                      {/if}
                    </div>

                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="repeat" size={13} />
                        <span>{$t('reLab.exectrace.overview.hotLoopsTitle')}</span>
                      </div>
                      {#if !traceSummary?.hot_loops?.length}
                        <div class="card-empty">{$t('reLab.exectrace.overview.noHotLoops')}</div>
                      {:else}
                        <div class="table-wrap">
                          <table class="data-table mono">
                            <thead>
                              <tr>
                                <th>Range</th>
                                <th>Iter</th>
                                <th>Body</th>
                                <th>Crypto%</th>
                                <th>Hint</th>
                              </tr>
                            </thead>
                            <tbody>
                              {#each traceSummary.hot_loops.slice(0, 20) as lp, idx (`lp:${lp.start_addr}:${idx}`)}
                                <tr>
                                  <td class="accent-txt">{formatHex(lp.start_offset || lp.start_addr)}..{formatHex(lp.end_offset || lp.end_addr)}</td>
                                  <td class="tabular-nums bold">{lp.iterations}x</td>
                                  <td class="tabular-nums">{lp.body_insns}</td>
                                  <td>
                                    <Badge variant={lp.crypto_ratio >= 0.35 ? 'warning' : 'neutral'} size="xs" mono>
                                      {Math.round((lp.crypto_ratio || 0) * 100)}%
                                    </Badge>
                                  </td>
                                  <td>{lp.hint || '—'}</td>
                                </tr>
                              {/each}
                            </tbody>
                          </table>
                        </div>
                      {/if}
                    </div>
                  </div>

                  <!-- Call Tree & Syscalls (shown when present) -->
                  {#if flatCallTree.length > 0}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="git-branch" size={13} />
                        <span>{$t('reLab.exectrace.overview.callTreeTitle')}</span>
                      </div>
                      <div class="calltree-list mono">
                        {#each flatCallTree.slice(0, 200) as item (`ct:${item.node.id}:${item.node.enter_seq}`)}
                          <div class="ct-row" style="padding-left: {8 + item.depth * 16}px;">
                            {#if item.hasChildren}
                              <button type="button" class="mini-icon-btn" on:click={() => toggleCallNode(item.node.id)}>
                                <Icon name={item.isCollapsed ? 'chevron-right' : 'chevron-down'} size={11} />
                              </button>
                            {:else}
                              <span class="ct-leaf">·</span>
                            {/if}
                            <span class="bold">{item.node.name}</span>
                            <span class="meta-text">seq {item.node.enter_seq}..{item.node.exit_seq || '?'} ({item.node.insn_count} insns)</span>
                            {#if item.node.ret_val}
                              <Badge variant="success" size="xs" mono>→ {item.node.ret_val}</Badge>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}

                  {#if traceSummary?.syscalls?.length > 0}
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="terminal" size={13} />
                        <span>{$t('reLab.exectrace.overview.syscallsTitle')}</span>
                      </div>
                      <div class="chip-wrap">
                        {#each traceSummary.syscalls as sc, idx (`sc:${sc.name}:${idx}`)}
                          <Badge variant="danger" size="xs" mono>{sc.name} ×{sc.count}</Badge>
                        {/each}
                      </div>
                    </div>
                  {/if}
                </div>

              {:else if traceViewTab === 'events'}
                <!-- VIEW 2: Paginated Events Table + Click to Seed Taint -->
                <div class="panel-col">
                  <div class="events-filter-bar">
                    <select class="cap-input mono compact-sel" bind:value={eventFilterKind} on:change={() => queryTraceEvents(0)}>
                      <option value="">{$t('reLab.exectrace.events.kindAll')}</option>
                      <option value="insn">insn</option>
                      <option value="call">call</option>
                      <option value="ret">ret</option>
                      <option value="mem_read">mem_read</option>
                      <option value="mem_write">mem_write</option>
                      <option value="jni">jni</option>
                      <option value="java_enter">java_enter</option>
                      <option value="java_exit">java_exit</option>
                      <option value="syscall">syscall</option>
                    </select>
                    <input
                      type="text"
                      class="cap-input mono addr-filter"
                      bind:value={eventFilterAddr}
                      placeholder={$t('reLab.exectrace.events.addrPlaceholder')}
                      on:keydown={(e) => { if (e.key === 'Enter') queryTraceEvents(0) }}
                    />
                    <input
                      type="text"
                      class="cap-input flex-1"
                      bind:value={eventFilterSearch}
                      placeholder={$t('reLab.exectrace.events.searchPlaceholder')}
                      on:keydown={(e) => { if (e.key === 'Enter') queryTraceEvents(0) }}
                    />
                    <Button variant="primary" size="xs" icon="filter" loading={loadingEvents} on:click={() => queryTraceEvents(0)}>
                      {$t('reLab.exectrace.events.applyBtn')}
                    </Button>
                  </div>

                  <!-- Selected Row Quick Taint Seeder Strip -->
                  {#if selectedEventRow}
                    <div class="seed-strip">
                      <Badge variant="accent" size="xs" mono>{$t('reLab.exectrace.events.selectedSeq', { seq: selectedEventRow.seq })}</Badge>
                      <span class="meta-text">{$t('reLab.exectrace.events.seedFromReg')}</span>
                      {#each Object.entries(selectedEventRow.regs_after || selectedEventRow.regs_before || {}) as [reg, val] (reg)}
                        <button
                          type="button"
                          class="seed-chip mono"
                          on:click={() => seedTaintFromEvent(selectedEventRow, 'backward', reg, '')}
                          title="Backward taint {reg}={formatHex(val)}"
                        >
                          {reg}={formatHex(val)}
                        </button>
                      {/each}
                      {#if selectedEventRow.mem_addr}
                        <button
                          type="button"
                          class="seed-chip mem mono"
                          on:click={() => seedTaintFromEvent(selectedEventRow, 'backward', '', formatHex(selectedEventRow.mem_addr))}
                        >
                          mem@{formatHex(selectedEventRow.mem_addr)}
                        </button>
                      {/if}
                      <div class="strip-spacer"></div>
                      <Button variant="subtle" size="xs" icon="arrow-right" on:click={() => seedTaintFromEvent(selectedEventRow, 'forward')}>
                        {$t('reLab.exectrace.events.seedForward')}
                      </Button>
                      <Button variant="primary" size="xs" icon="target" on:click={() => seedTaintFromEvent(selectedEventRow, 'backward')}>
                        {$t('reLab.exectrace.events.seedBackward')}
                      </Button>
                    </div>
                  {/if}

                  <div class="events-table-scroll">
                    {#if !eventPage?.events?.length}
                      <EmptyState icon="list" title={$t('reLab.native.emptyFilterTitle')} compact />
                    {:else}
                      <table class="data-table mono clickable-rows">
                        <thead>
                          <tr>
                            <th>{$t('reLab.exectrace.events.cols.seq')}</th>
                            <th>{$t('reLab.exectrace.events.cols.kind')}</th>
                            <th>{$t('reLab.exectrace.events.cols.addr')}</th>
                            <th>{$t('reLab.exectrace.events.cols.disasm')}</th>
                            <th>{$t('reLab.exectrace.events.cols.mem')}</th>
                            <th>{$t('reLab.exectrace.events.cols.regs')}</th>
                            <th>{$t('reLab.exectrace.events.cols.act')}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each eventPage.events as ev (ev.seq)}
                            <tr
                              class:selected={selectedEventRow?.seq === ev.seq}
                              on:click={() => (selectedEventRow = ev)}
                            >
                              <td class="tabular-nums meta-text">#{ev.seq}</td>
                              <td><Badge variant={eventKindVariant(ev.kind)} size="xs" mono>{ev.kind}</Badge></td>
                              <td class="tabular-nums accent-txt">
                                {ev.offset ? `+${formatHex(ev.offset)}` : formatHex(ev.address)}
                              </td>
                              <td>
                                {#if ev.mnemonic}
                                  <span class="bold">{ev.mnemonic}</span> {ev.operands || ''}
                                {:else if ev.symbol}
                                  <span class="purple-txt">{ev.symbol}</span>
                                {:else}
                                  {ev.raw || '—'}
                                {/if}
                              </td>
                              <td class="truncate-cell">
                                {#if ev.mem_addr}
                                  {formatHex(ev.mem_addr)}{ev.mem_value_hex ? ` = ${ev.mem_value_hex}` : ''}
                                {:else if ev.args?.length}
                                  ({ev.args.join(', ')})
                                {:else}
                                  —
                                {/if}
                              </td>
                              <td class="truncate-cell">
                                {#if ev.ret_val}
                                  → {ev.ret_val}
                                {:else if ev.regs_after && Object.keys(ev.regs_after).length > 0}
                                  {Object.entries(ev.regs_after).slice(0, 3).map(([k, v]) => `${k}=${formatHex(v)}`).join(' ')}
                                {:else}
                                  —
                                {/if}
                              </td>
                              <td>
                                <button
                                  type="button"
                                  class="taint-row-btn"
                                  title={$t('reLab.exectrace.events.seedBackward')}
                                  on:click|stopPropagation={() => seedTaintFromEvent(ev, 'backward')}
                                >
                                  <Icon name="target" size={12} />
                                </button>
                              </td>
                            </tr>
                          {/each}
                        </tbody>
                      </table>
                    {/if}
                  </div>

                  <!-- Pagination Bar -->
                  <div class="pagination-bar">
                    <span class="meta-text mono tabular-nums">
                      {#if eventPage && eventPage.total > 0}
                        {$t('reLab.exectrace.events.showing', {
                          start: eventPage.offset + 1,
                          end: Math.min(eventPage.offset + eventPage.events.length, eventPage.total),
                          total: eventPage.total,
                        })}
                      {:else}
                        {$t('reLab.exectrace.events.clickHint')}
                      {/if}
                    </span>
                    <div class="strip-spacer"></div>
                    <Button variant="secondary" size="xs" disabled={!eventPage || eventOffset <= 0} on:click={() => queryTraceEvents(Math.max(0, eventOffset - eventPageSize))}>
                      {$t('reLab.exectrace.events.prevBtn')}
                    </Button>
                    <Button variant="secondary" size="xs" disabled={!eventPage?.has_more} on:click={() => queryTraceEvents(eventOffset + eventPageSize)}>
                      {$t('reLab.exectrace.events.nextBtn')}
                    </Button>
                  </div>
                </div>

              {:else if traceViewTab === 'taint'}
                <!-- VIEW 3: Forward / Backward Taint Analysis -->
                <div class="scroll-workspace">
                  <div class="section-card cap-card">
                    <div class="drawer-grid four-col">
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.direction')}</span>
                        <select class="cap-input" bind:value={taintDirection}>
                          <option value="backward">{$t('reLab.exectrace.taint.backward')}</option>
                          <option value="forward">{$t('reLab.exectrace.taint.forward')}</option>
                        </select>
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.startSeq')}</span>
                        <input type="number" class="cap-input mono" bind:value={taintStartSeq} min="1" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.seedReg')}</span>
                        <input type="text" class="cap-input mono" bind:value={taintSeedReg} placeholder={$t('reLab.exectrace.taint.seedRegPlaceholder')} />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.seedMemAddr')}</span>
                        <input type="text" class="cap-input mono" bind:value={taintSeedMemAddr} placeholder={$t('reLab.exectrace.taint.seedMemPlaceholder')} />
                      </label>
                    </div>
                    <div class="drawer-grid three-col">
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.seedValueHex')}</span>
                        <input type="text" class="cap-input mono" bind:value={taintSeedValueHex} placeholder="deadbeef" />
                      </label>
                      <label class="d-field">
                        <span>{$t('reLab.exectrace.taint.maxSteps')}</span>
                        <input type="number" class="cap-input mono" bind:value={taintMaxSteps} min="10" max="100000" />
                      </label>
                      <div class="d-field align-end">
                        <Button
                          variant="primary"
                          size="sm"
                          icon="target"
                          loading={runningTaint}
                          disabled={!taintSeedReg.trim() && !taintSeedMemAddr.trim() && !taintSeedValueHex.trim()}
                          on:click={runTaintAnalysis}
                        >
                          {runningTaint ? $t('reLab.exectrace.taint.running') : $t('reLab.exectrace.taint.runBtn')}
                        </Button>
                      </div>
                    </div>
                  </div>

                  {#if !taintResult}
                    <EmptyState
                      icon="target"
                      title={$t('reLab.exectrace.taint.emptyTitle')}
                      description={$t('reLab.exectrace.taint.emptyDesc')}
                      compact
                    />
                  {:else}
                    <div class="summary-banner cap-card">
                      <Badge variant="accent" size="xs" mono>{taintResult.direction.toUpperCase()} · {taintResult.seed}</Badge>
                      <span>{taintResult.summary}</span>
                      <Badge variant="success" size="xs" mono>{$t('reLab.exectrace.taint.stepsCount', { count: taintResult.tainted_steps?.length || 0 })}</Badge>
                    </div>

                    <div class="findings-grid three-col-grid">
                      <div class="section-card cap-card">
                        <div class="card-head">{$t('reLab.exectrace.taint.sourcesSinksTitle')}</div>
                        <div class="chip-wrap">
                          {#each taintResult.sources_or_sinks || [] as ss, idx (idx)}
                            <Badge variant="danger" size="xs" mono>{ss}</Badge>
                          {:else}
                            <span class="meta-text">—</span>
                          {/each}
                        </div>
                      </div>
                      <div class="section-card cap-card">
                        <div class="card-head">{$t('reLab.exectrace.taint.regsTitle')}</div>
                        <div class="chip-wrap">
                          {#each taintResult.tainted_regs || [] as r, idx (idx)}
                            <Badge variant="accent" size="xs" mono>{r}</Badge>
                          {:else}
                            <span class="meta-text">—</span>
                          {/each}
                        </div>
                      </div>
                      <div class="section-card cap-card">
                        <div class="card-head">{$t('reLab.exectrace.taint.memTitle')}</div>
                        <div class="chip-wrap">
                          {#each taintResult.tainted_mem_addrs || [] as ma, idx (idx)}
                            <Badge variant="warning" size="xs" mono>{ma}</Badge>
                          {:else}
                            <span class="meta-text">—</span>
                          {/each}
                        </div>
                      </div>
                    </div>

                    <!-- Minimal Contributing Instruction Chain -->
                    <div class="section-card cap-card">
                      <div class="card-head">
                        <Icon name="layers" size={13} />
                        <span>{$t('reLab.exectrace.taint.chainTitle')}</span>
                        <Badge variant="accent" size="xs" mono>{taintResult.tainted_steps?.length || 0}</Badge>
                      </div>
                      <div class="table-wrap">
                        <table class="data-table mono">
                          <thead>
                            <tr>
                              <th>Seq</th>
                              <th>Addr / Offset</th>
                              <th>Instruction</th>
                              <th>Flow (Src → Dst)</th>
                              <th>Mem</th>
                              <th>Reason</th>
                            </tr>
                          </thead>
                          <tbody>
                            {#each taintResult.tainted_steps || [] as step, idx (`ts:${step.seq}:${idx}`)}
                              <tr class="taint-step-row">
                                <td class="tabular-nums meta-text">#{step.seq}</td>
                                <td class="accent-txt tabular-nums">
                                  {step.offset ? `+${formatHex(step.offset)}` : formatHex(step.address)}
                                </td>
                                <td><span class="bold">{step.mnemonic}</span> {step.operands}</td>
                                <td>
                                  {#if step.src_regs?.length || step.dst_regs?.length}
                                    <span class="meta-text">{(step.src_regs || []).join(',')}</span>
                                    <span> → </span>
                                    <span class="success-txt">{(step.dst_regs || []).join(',')}</span>
                                  {:else}
                                    —
                                  {/if}
                                </td>
                                <td>
                                  {#if step.mem_addr}
                                    <Badge variant={step.mem_op === 'write' ? 'warning' : 'info'} size="xs" mono>
                                      {step.mem_op || 'mem'} {formatHex(step.mem_addr)}
                                    </Badge>
                                  {:else}
                                    —
                                  {/if}
                                </td>
                                <td><span class="fi-note">{step.reason}</span></td>
                              </tr>
                            {/each}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          </SplitPane>
        </div>
      </div>

    <!-- ======================================================================
         SUB-TAB 6: CRYPTOLAB (PIPELINE · PROTOBUF · WHITE-BOX AES DFA)
         ====================================================================== -->
    {:else if subTab === 'cryptolab'}
      <div class="subtab-pane">
        <!-- Inner Mode Switcher -->
        <section class="action-bar">
          <div class="seg-toggle">
            <button type="button" class="seg-btn" class:active={cryptoMode === 'pipeline'} on:click={() => (cryptoMode = 'pipeline')}>
              {$t('reLab.cryptolab.modes.pipeline')}
            </button>
            <button type="button" class="seg-btn" class:active={cryptoMode === 'protobuf'} on:click={() => (cryptoMode = 'protobuf')}>
              {$t('reLab.cryptolab.modes.protobuf')}
            </button>
            <button type="button" class="seg-btn" class:active={cryptoMode === 'dfa'} on:click={() => (cryptoMode = 'dfa')}>
              {$t('reLab.cryptolab.modes.dfa')}
            </button>
          </div>
          <div class="strip-spacer"></div>
          {#if cryptoMode === 'pipeline'}
            <Button variant="secondary" size="sm" icon="sparkles" loading={identifyingCrypto} disabled={!cryptoInput.trim()} on:click={identifyCryptoPayload}>
              {identifyingCrypto ? $t('reLab.cryptolab.pipeline.identifying') : $t('reLab.cryptolab.pipeline.autoIdentifyBtn')}
            </Button>
            <Button variant="primary" size="sm" icon="play" loading={runningCrypto} on:click={runCryptoPipeline}>
              {runningCrypto ? $t('reLab.cryptolab.pipeline.running') : $t('reLab.cryptolab.pipeline.runBtn')}
            </Button>
          {/if}
        </section>

        <!-- MODE 1: CyberChef-Style Composable Crypto Pipeline -->
        {#if cryptoMode === 'pipeline'}
          <div class="pane-fill">
            <SplitPane direction="horizontal" initialSize={40} minPrimary={28} minSecondary={42} storageKey="cap.relab.crypto.hsplit">
              <!-- LEFT: Operations Catalog + Interactive Step Stack -->
              <div slot="primary" class="panel-col surface">
                <SplitPane direction="vertical" initialSize={44} minPrimary={26} minSecondary={32} storageKey="cap.relab.crypto.vsplit">
                  <!-- TOP: Operations Catalog -->
                  <div slot="primary" class="panel-col surface">
                    <div class="pane-header compact">
                      <span class="ph-title">{$t('reLab.cryptolab.pipeline.opsTitle')}</span>
                      <Badge variant="neutral" size="xs" mono>{filteredCryptoOps.length}</Badge>
                    </div>
                    <div class="list-toolbar">
                      <div class="search-box">
                        <Icon name="search" size={12} />
                        <input type="text" class="search-input" bind:value={cryptoOpSearch} placeholder={$t('reLab.cryptolab.pipeline.opSearchPlaceholder')} />
                      </div>
                    </div>
                    <div class="cat-pills">
                      {#each cryptoOpCategories as cat (cat)}
                        <button
                          type="button"
                          class="cat-pill"
                          class:active={cryptoOpCategory === cat}
                          on:click={() => (cryptoOpCategory = cat)}
                        >
                          {cat === 'all' ? $t('reLab.cryptolab.pipeline.catAll') : cat}
                        </button>
                      {/each}
                    </div>
                    <div class="list-scroll padded">
                      {#each filteredCryptoOps as op (op.name)}
                        <button type="button" class="op-catalog-row" on:click={() => addCryptoStep(op)}>
                          <div class="op-row-top">
                            <span class="bold truncate">{op.label}</span>
                            <Badge variant="neutral" size="xs" mono>{op.category}</Badge>
                            <Icon name="plus" size={11} />
                          </div>
                          <div class="fi-note truncate">{op.description}</div>
                        </button>
                      {/each}
                    </div>
                  </div>

                  <!-- BOTTOM: Active Recipe Step Stack -->
                  <div slot="secondary" class="panel-col">
                    <div class="pane-header compact">
                      <div class="ph-left">
                        <Icon name="layers" size={13} />
                        <span class="ph-title">{$t('reLab.cryptolab.pipeline.recipeTitle', { count: cryptoSteps.length })}</span>
                      </div>
                      <Button variant="ghost" size="xs" icon="trash" disabled={cryptoSteps.length === 0} on:click={() => (cryptoSteps = [])}>
                        {$t('reLab.cryptolab.pipeline.clearRecipe')}
                      </Button>
                    </div>
                    <div class="list-scroll padded">
                      {#if cryptoSteps.length === 0}
                        <div class="card-empty">{$t('reLab.cryptolab.pipeline.emptyRecipe')}</div>
                      {:else}
                        {#each cryptoSteps as step, idx (step.uid || `${step.op}:${idx}`)}
                          {@const spec = cryptoOpByName[step.op]}
                          <div class="step-card cap-card" class:step-disabled={step.disabled}>
                            <div class="step-card-head">
                              <Badge variant="accent" size="xs" mono>#{idx + 1}</Badge>
                              <strong class="truncate flex-1">{spec?.label || step.op}</strong>
                              {#if step.disabled}
                                <Badge variant="neutral" size="xs">{$t('reLab.cryptolab.pipeline.stepDisabled')}</Badge>
                              {/if}
                              <button type="button" class="mini-icon-btn" title="Move Up" aria-label="Move Up" disabled={idx === 0} on:click={() => moveCryptoStep(idx, -1)}>
                                <Icon name="arrow-up" size={11} />
                              </button>
                              <button type="button" class="mini-icon-btn" title="Move Down" aria-label="Move Down" disabled={idx === cryptoSteps.length - 1} on:click={() => moveCryptoStep(idx, 1)}>
                                <Icon name="arrow-down" size={11} />
                              </button>
                              <button type="button" class="mini-icon-btn" title={step.disabled ? $t('common.actions.enable') : $t('common.actions.disable')} aria-label="Toggle step" on:click={() => toggleCryptoStep(idx)}>
                                <Icon name={step.disabled ? 'eye-off' : 'eye'} size={11} />
                              </button>
                              <button type="button" class="mini-icon-btn" title={$t('common.actions.delete')} aria-label="Remove step" on:click={() => removeCryptoStep(idx)}>
                                <Icon name="x" size={11} />
                              </button>
                            </div>
                            {#if spec?.params?.length > 0}
                              <div class="step-params-grid">
                                {#each spec.params as param (param.name)}
                                  {#if param.type === 'boolean'}
                                    <label class="check-opt compact">
                                      <input
                                        type="checkbox"
                                        checked={String(step.params?.[param.name] ?? param.default) === 'true'}
                                        on:change={(e) => updateCryptoStepParam(idx, param.name, e.currentTarget.checked ? 'true' : 'false')}
                                      />
                                      <span>{param.label}</span>
                                    </label>
                                  {:else if param.type === 'select'}
                                    <label class="d-field">
                                      <span>{param.label}</span>
                                      <select
                                        class="cap-input mono"
                                        value={step.params?.[param.name] ?? param.default ?? ''}
                                        on:change={(e) => updateCryptoStepParam(idx, param.name, e.currentTarget.value)}
                                      >
                                        {#each param.options || [] as opt (opt)}
                                          <option value={opt}>{opt}</option>
                                        {/each}
                                      </select>
                                    </label>
                                  {:else}
                                    <label class="d-field">
                                      <span>{param.label}{param.required ? ' *' : ''}</span>
                                      <input
                                        type="text"
                                        class="cap-input mono"
                                        value={step.params?.[param.name] ?? ''}
                                        placeholder={param.placeholder || param.default || ''}
                                        on:input={(e) => updateCryptoStepParam(idx, param.name, e.currentTarget.value)}
                                      />
                                    </label>
                                  {/if}
                                {/each}
                              </div>
                            {/if}
                          </div>
                        {/each}
                      {/if}
                    </div>
                  </div>
                </SplitPane>
              </div>

              <!-- RIGHT: Input + Auto-Identify + Final Output & Expandable Step Trace -->
              <div slot="secondary" class="scroll-workspace">
                <!-- Input Card -->
                <div class="section-card cap-card">
                  <div class="card-head">
                    <Icon name="file-text" size={13} />
                    <span>{$t('reLab.cryptolab.pipeline.inputTitle')}</span>
                    <div class="strip-spacer"></div>
                    <div class="seg-toggle">
                      {#each ['utf8', 'hex', 'base64'] as enc (enc)}
                        <button type="button" class="seg-btn mono" class:active={cryptoInputEncoding === enc} on:click={() => (cryptoInputEncoding = enc)}>
                          {enc}
                        </button>
                      {/each}
                    </div>
                    {#if cryptoResult}
                      <Button variant="ghost" size="xs" icon="repeat" on:click={swapCryptoOutputToInput}>
                        {$t('reLab.cryptolab.pipeline.swapBtn')}
                      </Button>
                    {/if}
                  </div>
                  <textarea
                    class="cap-textarea mono"
                    rows="5"
                    bind:value={cryptoInput}
                    placeholder={$t('reLab.cryptolab.pipeline.inputPlaceholder')}
                  ></textarea>
                </div>

                <!-- Auto-Identify Panel -->
                {#if cryptoIdentify}
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="sparkles" size={13} />
                      <span>{$t('reLab.cryptolab.pipeline.identifyTitle')}</span>
                      <Badge variant="info" size="xs" mono>
                        {$t('reLab.cryptolab.pipeline.entropyLabel', {
                          val: (cryptoIdentify.entropy || 0).toFixed(2),
                          cls: cryptoIdentify.entropy_class || '',
                        })}
                      </Badge>
                      <Badge variant="neutral" size="xs" mono>{cryptoIdentify.decoded_byte_len} B</Badge>
                    </div>

                    {#if cryptoIdentify.candidates?.length > 0}
                      <div class="finding-list">
                        {#each cryptoIdentify.candidates as cand, idx (`cand:${cand.format}:${idx}`)}
                          <div class="finding-item">
                            <div class="fi-top">
                              <Badge variant="accent" size="xs" mono>{cand.label || cand.format}</Badge>
                              <Badge variant="success" size="xs" mono>{Math.round((cand.confidence || 0) * 100)}%</Badge>
                              {#if cand.details}<span class="meta-text">{cand.details}</span>{/if}
                            </div>
                            {#if cand.preview}
                              <div class="mono fi-pattern truncate">{cand.preview}</div>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    {/if}

                    {#if cryptoIdentify.jwt}
                      <div class="finding-item">
                        <div class="fi-top">
                          <Badge variant="purple" size="xs" mono>{$t('reLab.cryptolab.pipeline.jwtTitle')}</Badge>
                          {#if cryptoIdentify.jwt.algorithm}
                            <Badge variant="accent" size="xs" mono>{cryptoIdentify.jwt.algorithm}</Badge>
                          {/if}
                        </div>
                        <div class="findings-grid">
                          <pre class="collector-code mono">{cryptoIdentify.jwt.header_json}</pre>
                          <pre class="collector-code mono">{cryptoIdentify.jwt.payload_json}</pre>
                        </div>
                      </div>
                    {/if}

                    {#if cryptoIdentify.recipes?.length > 0}
                      <div class="chip-wrap">
                        {#each cryptoIdentify.recipes as rec, idx (`rec:${rec.name}:${idx}`)}
                          <Button variant="secondary" size="xs" icon="play" on:click={() => applyCryptoRecipe(rec)}>
                            {$t('reLab.cryptolab.pipeline.applyRecipe')}: {rec.name}
                          </Button>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}

                <!-- Pipeline Output & Expandable Step Trace -->
                {#if cryptoResult}
                  <div class="section-card cap-card">
                    <div class="card-head">
                      <Icon name="terminal" size={13} />
                      <span>{$t('reLab.cryptolab.pipeline.outputTitle')}</span>
                      <Badge variant={cryptoResult.success ? 'success' : 'danger'} size="xs" mono>
                        {cryptoResult.success
                          ? `${cryptoResult.byte_len} B · ${cryptoResult.total_elapsed_us} µs`
                          : (cryptoResult.failed_step >= 0
                              ? $t('reLab.cryptolab.pipeline.stepFailed', { idx: cryptoResult.failed_step + 1 })
                              : $t('reLab.cryptolab.pipeline.inputDecodeFailed'))}
                      </Badge>
                      <div class="strip-spacer"></div>
                      <div class="seg-toggle">
                        <button type="button" class="seg-btn mono" class:active={cryptoOutputTab === 'utf8'} on:click={() => (cryptoOutputTab = 'utf8')}>UTF-8</button>
                        <button type="button" class="seg-btn mono" class:active={cryptoOutputTab === 'hex'} on:click={() => (cryptoOutputTab = 'hex')}>Hex</button>
                        <button type="button" class="seg-btn mono" class:active={cryptoOutputTab === 'base64'} on:click={() => (cryptoOutputTab = 'base64')}>Base64</button>
                      </div>
                      <Button
                        variant="ghost"
                        size="xs"
                        icon="copy"
                        on:click={() =>
                          copyToClipboard(
                            cryptoOutputTab === 'hex'
                              ? cryptoResult.output_hex
                              : cryptoOutputTab === 'base64'
                                ? cryptoResult.output_base64
                                : cryptoResult.output_utf8,
                            translate('reLab.toast.copied')
                          )}
                      >
                        {$t('common.actions.copy')}
                      </Button>
                    </div>

                    {#if cryptoResult.error}
                      <div class="danger-txt mono fi-note">{cryptoResult.error}</div>
                    {/if}
                    <pre class="collector-code mono crypto-out-pre">{cryptoOutputTab === 'hex'
                      ? (cryptoResult.output_hex || '')
                      : cryptoOutputTab === 'base64'
                        ? (cryptoResult.output_base64 || '')
                        : (cryptoResult.output_utf8 || '')}</pre>

                    {#if cryptoResult.steps?.length > 0}
                      <div class="form-section-label">{$t('reLab.cryptolab.pipeline.traceTitle', { count: cryptoResult.steps.length })}</div>
                      <div class="finding-list">
                        {#each cryptoResult.steps as st (st.index)}
                          {@const isExp = expandedCryptoSteps.has(st.index)}
                          <div class="finding-item">
                            <button type="button" class="trace-step-btn" on:click={() => toggleCryptoStepTrace(st.index)}>
                              <Icon name={isExp ? 'chevron-down' : 'chevron-right'} size={12} />
                              <Badge variant={st.error ? 'danger' : st.disabled ? 'neutral' : 'accent'} size="xs" mono>#{st.index + 1} {st.op}</Badge>
                              <span class="meta-text mono tabular-nums">{st.byte_len} B · {st.elapsed_us} µs</span>
                              <span class="mono truncate flex-1">{st.error || st.output_utf8 || st.output_hex}</span>
                            </button>
                            {#if isExp}
                              <div class="trace-step-body mono">
                                {#if st.error}
                                  <div class="danger-txt">{st.error}</div>
                                {:else}
                                  <div><span class="meta-text">UTF-8:</span> {st.output_utf8}</div>
                                  <div class="fi-pattern"><span class="meta-text">HEX:</span> {st.output_hex}</div>
                                {/if}
                              </div>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </SplitPane>
          </div>

        <!-- MODE 2: Schema-less Protobuf Wire Inspector & Editor -->
        {:else if cryptoMode === 'protobuf'}
          <div class="scroll-workspace">
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="database" size={13} />
                <span>{$t('reLab.cryptolab.protobuf.title')}</span>
              </div>
              <p class="sub-copy">{$t('reLab.cryptolab.protobuf.subtitle')}</p>
              <textarea
                class="cap-textarea mono"
                rows="3"
                bind:value={protoInput}
                placeholder={$t('reLab.cryptolab.protobuf.inputPlaceholder')}
              ></textarea>
              <div class="drawer-foot">
                <Button variant="secondary" size="xs" icon="plus" on:click={() => addProtoField(null)}>
                  {$t('reLab.cryptolab.protobuf.addFieldBtn')}
                </Button>
                <div class="strip-spacer"></div>
                <Button variant="secondary" size="xs" icon="code" loading={encodingProto} disabled={!protoTree} on:click={encodeProtobuf}>
                  {encodingProto ? $t('reLab.cryptolab.protobuf.encoding') : $t('reLab.cryptolab.protobuf.encodeBtn')}
                </Button>
                <Button variant="primary" size="xs" icon="search" loading={decodingProto} disabled={!protoInput.trim()} on:click={decodeProtobuf}>
                  {decodingProto ? $t('reLab.cryptolab.protobuf.decoding') : $t('reLab.cryptolab.protobuf.decodeBtn')}
                </Button>
              </div>
            </div>

            {#if protoEncodedHex}
              <div class="section-card cap-card">
                <div class="card-head">
                  <Icon name="check-circle" size={13} />
                  <span>{$t('reLab.cryptolab.protobuf.encodedOutput', { bytes: Math.floor(protoEncodedHex.length / 2) })}</span>
                  <div class="strip-spacer"></div>
                  <Button variant="ghost" size="xs" icon="repeat" on:click={() => { protoInput = protoEncodedHex; decodeProtobuf() }}>
                    {$t('reLab.cryptolab.protobuf.useAsInput')}
                  </Button>
                  <Button variant="secondary" size="xs" icon="copy" on:click={() => copyToClipboard(protoEncodedHex, translate('reLab.toast.copied'))}>
                    {$t('common.actions.copy')}
                  </Button>
                </div>
                <pre class="collector-code mono">{protoEncodedHex}</pre>
              </div>
            {/if}

            {#if !protoTree}
              <EmptyState icon="database" title={$t('reLab.cryptolab.protobuf.emptyTitle')} description={$t('reLab.cryptolab.protobuf.emptyDesc')} compact />
            {:else}
              {#if protoTree.warnings?.length > 0}
                <div class="issues-box">
                  {#each protoTree.warnings as w, idx (idx)}
                    <div class="issue-line"><Icon name="alert-triangle" size={12} /><span>{w}</span></div>
                  {/each}
                </div>
              {/if}

              <div class="section-card cap-card">
                <div class="proto-tree-list">
                  {#each flatProtoRows as row (row.pathKey)}
                    <div class="proto-row" style="padding-left: {8 + row.depth * 22}px;">
                      {#if row.hasNested}
                        <button type="button" class="mini-icon-btn" title="Toggle nested" aria-label="Toggle nested" on:click={() => toggleProtoCollapse(row.pathKey)}>
                          <Icon name={row.isCollapsed ? 'chevron-right' : 'chevron-down'} size={12} />
                        </button>
                      {:else}
                        <span class="ct-leaf">·</span>
                      {/if}

                      <label class="proto-num-lbl mono">
                        <span>#</span>
                        <input
                          type="number"
                          class="cap-input mono proto-num-inp"
                          min="1"
                          value={row.field.field_number}
                          on:input={(e) => {
                            const n = Number.parseInt(e.currentTarget.value, 10)
                            if (Number.isFinite(n) && n > 0) {
                              row.field.field_number = n
                              protoTree = protoTree
                            }
                          }}
                        />
                      </label>

                      <Badge variant="neutral" size="xs" mono>{row.field.wire_type_name || `wt${row.field.wire_type}`}</Badge>

                      <select
                        class="cap-input mono proto-kind-sel"
                        value={row.field.kind}
                        on:change={(e) => updateProtoFieldKind(row.field, e.currentTarget.value)}
                      >
                        {#if row.field.wire_type === 0}
                          <option value="varint">uint64</option>
                          <option value="int64">int64</option>
                          <option value="sint64">sint64</option>
                        {:else if row.field.wire_type === 1}
                          <option value="fixed64">fixed64</option>
                          <option value="sfixed64">sfixed64</option>
                          <option value="double">double</option>
                        {:else if row.field.wire_type === 5}
                          <option value="fixed32">fixed32</option>
                          <option value="sfixed32">sfixed32</option>
                          <option value="float">float</option>
                        {:else}
                          <option value="string">string</option>
                          <option value="bytes">bytes (hex)</option>
                          <option value="message">message (nested)</option>
                        {/if}
                      </select>

                      {#if row.field.kind === 'message'}
                        <Badge variant="purple" size="xs" mono>{row.field.nested?.fields?.length || 0} fields</Badge>
                        <Button variant="subtle" size="xs" icon="plus" on:click={() => addProtoField(row.field.nested)}>
                          {$t('reLab.cryptolab.protobuf.addChildBtn')}
                        </Button>
                        <div class="strip-spacer"></div>
                      {:else}
                        <input
                          type="text"
                          class="cap-input mono flex-1"
                          value={protoFieldDisplayValue(row.field)}
                          placeholder={$t('reLab.cryptolab.protobuf.valuePlaceholder')}
                          on:input={(e) => updateProtoFieldValue(row.field, e.currentTarget.value)}
                        />
                        {#if row.field.wire_type === 0 && row.field.varint_s64 !== undefined}
                          <span class="meta-text mono">sint64={row.field.varint_s64}</span>
                        {/if}
                      {/if}

                      <button type="button" class="mini-icon-btn" title={$t('common.actions.delete')} aria-label="Delete field" on:click={() => removeProtoField(row.parentMsg, row.indexInParent)}>
                        <Icon name="trash" size={12} />
                      </button>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
          </div>

        <!-- MODE 3: White-Box AES-128 Round-9 DFA Solver & Fault Script Generator -->
        {:else}
          <div class="scroll-workspace">
            <!-- Solver Form -->
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="key" size={13} />
                <span>{$t('reLab.cryptolab.dfa.solverTitle')}</span>
              </div>
              <p class="sub-copy">{$t('reLab.cryptolab.dfa.solverSubtitle')}</p>

              <div class="form-grid two-col">
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.validCtLabel')}</span>
                  <input type="text" class="cap-input mono" bind:value={dfaValidHex} placeholder="3925841d02dc09fbdc118597196a0b32" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.plaintextLabel')}</span>
                  <input type="text" class="cap-input mono" bind:value={dfaPlaintextHex} placeholder="3243f6a8885a308d313198a2e0370734" />
                </label>
              </div>

              <label class="d-field">
                <span>{$t('reLab.cryptolab.dfa.faultsLabel', { count: dfaFaultLines.length })}</span>
                <textarea
                  class="cap-textarea mono"
                  rows="5"
                  bind:value={dfaFaultsText}
                  placeholder={$t('reLab.cryptolab.dfa.faultsPlaceholder')}
                ></textarea>
              </label>

              <div class="drawer-foot">
                <div class="strip-spacer"></div>
                <Button variant="primary" size="sm" icon="zap" loading={solvingDfa} disabled={!dfaValidHex.trim() || dfaFaultLines.length === 0} on:click={solveAes128Dfa}>
                  {solvingDfa ? $t('reLab.cryptolab.dfa.solving') : $t('reLab.cryptolab.dfa.solveBtn')}
                </Button>
              </div>
            </div>

            <!-- Recovery Result & 4-Column Convergence -->
            {#if dfaResult}
              <div class="section-card cap-card">
                <div class="card-head">
                  <Badge variant={dfaResult.solved ? 'success' : 'warning'} size="sm" solid={dfaResult.solved}>
                    {dfaResult.solved ? $t('reLab.cryptolab.dfa.solvedBadge') : $t('reLab.cryptolab.dfa.unsolvedBadge')}
                  </Badge>
                  {#if dfaResult.verified_with_plaintext}
                    <Badge variant="accent" size="xs" dot>{$t('reLab.cryptolab.dfa.verifiedBadge')}</Badge>
                  {/if}
                  <span class="meta-text mono tabular-nums">
                    {$t('reLab.cryptolab.dfa.usableStats', {
                      usable: dfaResult.usable_faults || 0,
                      total: dfaResult.total_faults_input || 0,
                      ignored: dfaResult.ignored_faults || 0,
                      us: dfaResult.elapsed_us || 0,
                    })}
                  </span>
                </div>

                {#if dfaResult.master_key_hex || dfaResult.round10_key_hex}
                  <div class="findings-grid">
                    <div class="finding-item dfa-key-card">
                      <div class="fi-top">
                        <span class="meta-text">{$t('reLab.cryptolab.dfa.masterKeyLabel')}</span>
                        <div class="strip-spacer"></div>
                        <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(dfaResult.master_key_hex, translate('reLab.toast.copied'))}>
                          {$t('common.actions.copy')}
                        </Button>
                      </div>
                      <div class="dfa-key-val mono success-txt">{dfaResult.master_key_hex || '—'}</div>
                    </div>
                    <div class="finding-item dfa-key-card">
                      <div class="fi-top">
                        <span class="meta-text">{$t('reLab.cryptolab.dfa.round10KeyLabel')}</span>
                        <div class="strip-spacer"></div>
                        <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(dfaResult.round10_key_hex, translate('reLab.toast.copied'))}>
                          {$t('common.actions.copy')}
                        </Button>
                      </div>
                      <div class="dfa-key-val mono accent-txt">{dfaResult.round10_key_hex || '—'}</div>
                    </div>
                  </div>
                {/if}

                <!-- 4-Column Convergence Progress -->
                <div class="kpi-grid four-col">
                  {#each dfaResult.columns || [] as col (col.group_index)}
                    <div class="finding-item" class:dfa-col-solved={col.solved}>
                      <div class="fi-top">
                        <strong>{$t('reLab.cryptolab.dfa.colTitle', { idx: col.group_index })}</strong>
                        <div class="strip-spacer"></div>
                        <Badge variant={col.solved ? 'success' : 'warning'} size="xs" mono>
                          {col.solved ? $t('reLab.cryptolab.dfa.colSolved') : $t('reLab.cryptolab.dfa.colCandidates', { count: col.candidate_count })}
                        </Badge>
                      </div>
                      <div class="meta-text mono">
                        {$t('reLab.cryptolab.dfa.colBytes', { bytes: (col.byte_indices || []).join(', ') })} · {$t('reLab.cryptolab.dfa.colFaults', { count: col.fault_count })}
                      </div>
                      {#if col.subkey_bytes_hex}
                        <div class="mono bold success-txt">K10: {col.subkey_bytes_hex}</div>
                      {/if}
                    </div>
                  {/each}
                </div>

                {#if dfaResult.notes?.length > 0}
                  <ul class="rec-list">
                    {#each dfaResult.notes as note, idx (idx)}
                      <li>{note}</li>
                    {/each}
                  </ul>
                {/if}
              </div>
            {/if}

            <!-- Fault-Injection Script Generator -->
            <div class="section-card cap-card">
              <div class="card-head">
                <Icon name="code" size={13} />
                <span>{$t('reLab.cryptolab.dfa.scriptTitle')}</span>
                <div class="strip-spacer"></div>
                <div class="seg-toggle">
                  <button type="button" class="seg-btn mono" class:active={dfaScriptEngine === 'unidbg'} on:click={() => (dfaScriptEngine = 'unidbg')}>Unidbg (Java)</button>
                  <button type="button" class="seg-btn mono" class:active={dfaScriptEngine === 'qiling'} on:click={() => (dfaScriptEngine = 'qiling')}>Qiling (Python)</button>
                </div>
              </div>

              <div class="drawer-grid four-col">
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.fields.binaryPath')}</span>
                  <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.binary_path} placeholder="/path/to/libwbaes.so" />
                </label>
                {#if dfaScriptEngine === 'unidbg'}
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.apkPath')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.apk_path} placeholder="/path/to/app.apk" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.targetClass')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.target_class} placeholder="com/example/Whitebox" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.targetMethod')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.target_method} placeholder="encrypt" />
                  </label>
                {:else}
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.rootfs')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.rootfs} placeholder="./rootfs/arm64_linux" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.targetSymbol')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.target_symbol} placeholder="wb_aes_encrypt" />
                  </label>
                  <label class="d-field">
                    <span>{$t('reLab.cryptolab.dfa.fields.targetAddr')}</span>
                    <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.target_addr} placeholder="0x1000" />
                  </label>
                {/if}
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.fields.faultHookAddr')}</span>
                  <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.fault_hook_addr} placeholder="0x12a40" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.fields.stateBufReg')}</span>
                  <input type="text" class="cap-input mono" bind:value={dfaScriptCfg.state_buf_reg} placeholder="x0" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.fields.faultXor')}</span>
                  <input type="number" class="cap-input mono" bind:value={dfaScriptCfg.fault_xor} min="1" max="255" />
                </label>
                <label class="d-field">
                  <span>{$t('reLab.cryptolab.dfa.fields.faultsPerByte')}</span>
                  <input type="number" class="cap-input mono" bind:value={dfaScriptCfg.faults_per_byte} min="1" max="32" />
                </label>
              </div>

              <div class="drawer-foot">
                <div class="strip-spacer"></div>
                {#if dfaGeneratedScript}
                  <Button variant="secondary" size="xs" icon="copy" on:click={() => copyToClipboard(dfaGeneratedScript.code, translate('reLab.toast.copied'))}>
                    {$t('common.actions.copy')}
                  </Button>
                  <Button variant="success" size="xs" icon="play" on:click={loadDfaScriptIntoEmulation}>
                    {$t('reLab.cryptolab.dfa.loadEmuBtn')}
                  </Button>
                {/if}
                <Button variant="primary" size="xs" icon="sparkles" loading={generatingDfaScript} on:click={generateDfaScript}>
                  {$t('reLab.cryptolab.dfa.generateBtn')}
                </Button>
              </div>

              {#if dfaGeneratedScript}
                <div class="collector-preview">
                  <div class="cp-head">
                    <strong class="mono">{dfaGeneratedScript.title}</strong>
                    <Badge variant={engineVariant(dfaGeneratedScript.engine)} size="xs" mono>{dfaGeneratedScript.engine}</Badge>
                    <Badge variant="neutral" size="xs" mono>{dfaGeneratedScript.file_name}</Badge>
                  </div>
                  <pre class="collector-code mono">{dfaGeneratedScript.code}</pre>
                  {#if dfaGeneratedScript.notes?.length}
                    <div class="cp-steps">
                      {#each dfaGeneratedScript.notes as n, idx (idx)}
                        <div>• {n}</div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .relab-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
    overflow: hidden;
  }

  /* ==================== Top Strip & Toolchain Pills ==================== */
  .top-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 14px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .subtab-nav {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    padding: 2px;
    border-radius: var(--radius-md);
    background: var(--bg-subtle);
    border: 1px solid var(--border-default);
  }

  .subtab-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 11px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .subtab-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .subtab-btn.active {
    background: var(--bg-elevated);
    border-color: var(--accent-border);
    color: var(--accent);
    box-shadow: var(--shadow-sm);
  }

  .live-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-success);
    animation: cap-pulse 1.6s ease-in-out infinite;
  }

  .tab-cnt {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-secondary);
  }

  .strip-spacer {
    flex: 1;
  }

  .strip-label {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }

  .toolchain-strip {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .tc-pills {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .tc-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    padding: 0 7px;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-muted);
    font-size: 10.5px;
    cursor: pointer;
    transition: border-color var(--transition-fast), color var(--transition-fast);
  }

  .tc-pill:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .tc-pill.ready {
    color: var(--text-primary);
    border-color: var(--status-success-border);
    background: var(--status-success-bg);
  }

  .tc-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--text-faint);
  }

  .tc-pill.ready .tc-dot {
    background: var(--status-success);
  }

  /* ==================== Drawers ==================== */
  .drawer-panel {
    margin: 10px 14px 0;
    padding: 12px 14px;
    background: var(--bg-surface);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex-shrink: 0;
    max-height: 55vh;
    overflow-y: auto;
  }

  .drawer-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .drawer-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .drawer-sub {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: 2px;
  }

  .drawer-grid {
    display: grid;
    gap: 10px;
  }

  .drawer-grid.three-col {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .drawer-grid.four-col {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }

  .d-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    min-width: 0;
  }

  .d-field.center-v {
    justify-content: center;
  }

  .d-field.align-end {
    justify-content: flex-end;
  }

  .d-field.narrow-med {
    width: 220px;
  }

  .tc-detail-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }

  .tc-stat-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 260px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .issues-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    color: var(--status-warning);
    font-size: var(--text-xs);
  }

  .issue-line {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .drawer-foot {
    display: flex;
    align-items: center;
    gap: 10px;
    padding-top: 8px;
    border-top: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }

  .hint-muted {
    font-size: 11px;
    color: var(--text-muted);
  }

  /* ==================== Body & Common Structural Layouts ==================== */
  .relab-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .subtab-pane {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .pane-fill {
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  .panel-col {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    min-width: 0;
    background: var(--bg-app);
  }

  .panel-col.surface {
    background: var(--bg-surface);
  }

  .action-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .input-with-icon {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-muted);
  }

  .input-with-icon.wide {
    flex: 1;
    min-width: 240px;
  }

  .flex-1 {
    flex: 1;
    min-width: 0;
  }

  .v-sep {
    width: 1px;
    height: 18px;
    background: var(--border-default);
    flex-shrink: 0;
  }

  /* ==================== Sub-Tab 1: Native / r2 ==================== */
  .mitigation-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 14px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .mit-group {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .file-tag {
    font-size: var(--text-xs);
    color: var(--text-primary);
  }

  .meta-text {
    font-size: 11px;
    color: var(--text-muted);
  }

  .inner-tabs {
    display: flex;
    border-bottom: 1px solid var(--border-default);
    background: var(--bg-panel);
    flex-shrink: 0;
    overflow-x: auto;
  }

  .itab {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    height: 33px;
    padding: 0 11px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
  }

  .itab:hover {
    color: var(--text-primary);
  }

  .itab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    background: var(--bg-surface);
  }

  .itab-cnt {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .list-toolbar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 7px 8px;
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .search-box {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-muted);
    min-width: 0;
  }

  .search-box.small {
    flex: 0 0 140px;
    height: 22px;
  }

  .search-input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    outline: none;
  }

  .filter-chip {
    height: 26px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }

  .filter-chip.active {
    border-color: var(--status-purple-border);
    background: var(--status-purple-bg);
    color: var(--status-purple);
  }

  .list-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .list-scroll.padded {
    padding: 8px;
    gap: 6px;
  }

  .sym-row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-primary);
    font-size: 11.5px;
    text-align: left;
    cursor: pointer;
  }

  .sym-row:hover {
    background: var(--bg-hover);
  }

  .sym-row.active {
    background: var(--accent-soft);
  }

  .sym-addr {
    font-size: 11px;
    color: var(--accent);
    flex-shrink: 0;
  }

  .sym-name {
    flex: 1;
    min-width: 0;
  }

  .sym-meta {
    font-size: 10.5px;
    color: var(--text-muted);
    max-width: 90px;
    flex-shrink: 0;
  }

  .xref-row {
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }

  .xref-line {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    flex-wrap: wrap;
  }

  .xref-op {
    font-size: 10.5px;
    color: var(--text-muted);
    width: 100%;
  }

  .pane-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .pane-header.compact {
    padding: 5px 10px;
  }

  .ph-left,
  .ph-right {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    flex-wrap: wrap;
  }

  .ph-title {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .fn-title {
    font-size: var(--text-xs);
    max-width: 240px;
  }

  .emulate-lbl {
    font-size: 11px;
    color: var(--text-muted);
  }

  .seg-toggle {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--radius-sm);
    background: var(--bg-subtle);
    border: 1px solid var(--border-default);
  }

  .seg-btn {
    height: 22px;
    padding: 0 9px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
  }

  .seg-btn.active {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }

  .seg-btn:disabled {
    opacity: 0.42;
    cursor: not-allowed;
  }

  .code-viewer-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    background: var(--bg-input);
  }

  .center-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    padding: 24px;
  }

  .disasm-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    line-height: 1.5;
  }

  .disasm-table tr:hover {
    background: var(--bg-hover);
  }

  .disasm-table td {
    padding: 2px 8px;
    vertical-align: top;
    white-space: pre;
  }

  .d-addr {
    color: var(--text-muted);
    width: 1%;
    user-select: all;
  }

  .d-bytes {
    color: var(--text-faint);
    width: 1%;
  }

  .d-insn {
    color: var(--text-primary);
  }

  .d-cmt {
    color: var(--text-muted);
  }

  .jump-link {
    border: none;
    background: transparent;
    color: var(--accent);
    cursor: pointer;
    font-size: 11.5px;
    padding: 0 4px 0 0;
  }

  .jump-link:hover {
    text-decoration: underline;
  }

  .raw-code {
    padding: 12px 14px;
    font-size: 12px;
    line-height: 1.55;
    color: var(--text-primary);
    white-space: pre;
    margin: 0;
  }

  .xrefs-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    padding: 10px;
  }

  .xref-card {
    overflow: hidden;
  }

  .preset-chips {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  .preset-chip {
    height: 20px;
    padding: 0 6px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 10.5px;
    cursor: pointer;
  }

  .preset-chip:hover {
    border-color: var(--accent-border);
    color: var(--accent);
    background: var(--accent-soft);
  }

  .r2-input-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .r2-prompt {
    font-size: 11.5px;
    font-weight: 700;
    color: var(--accent);
  }

  .r2-output-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding: 8px 10px;
    background: var(--bg-input);
    font-size: 11.5px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .r2-empty {
    color: var(--text-faint);
    font-family: var(--font-sans);
    font-size: var(--text-xs);
  }

  .r2-entry-cmd {
    display: flex;
    justify-content: space-between;
    color: var(--accent);
    font-weight: 600;
    margin-bottom: 3px;
  }

  .r2-out {
    margin: 0;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.45;
  }

  .r2-err {
    margin: 0;
    color: var(--status-danger);
    white-space: pre-wrap;
  }

  /* ==================== Sub-Tab 2: Emulation & Symbolic ==================== */
  .left-action-banner {
    padding: 0 8px 7px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .cat-pills {
    display: flex;
    gap: 4px;
    padding: 6px 8px;
    overflow-x: auto;
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .cat-pill {
    height: 20px;
    padding: 0 8px;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-default);
    background: transparent;
    color: var(--text-muted);
    font-size: 10.5px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
  }

  .cat-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .item-card {
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 100%;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    text-align: left;
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .item-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .item-card.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .ic-top {
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .ic-origin {
    font-size: 10px;
    color: var(--text-muted);
    margin-left: auto;
  }

  .ic-del {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--radius-xs);
    color: var(--text-muted);
  }

  .ic-del:hover {
    color: var(--status-danger);
    background: var(--status-danger-bg);
  }

  .ic-name {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .ic-desc {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.38;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }

  .ic-meta {
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .editor-header {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 6px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .ed-name {
    width: 220px;
    height: 26px;
    font-size: var(--text-xs);
    font-weight: 600;
  }

  .ed-cat {
    height: 26px;
    font-size: var(--text-xs);
  }

  .config-strip {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 7px;
    padding: 8px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .c-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 10.5px;
    color: var(--text-muted);
    min-width: 0;
  }

  .c-field .cap-input {
    height: 26px;
    font-size: 11.5px;
  }

  .editor-host {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .console-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 5px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .c-tabs,
  .c-tools {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }

  .c-tab {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 22px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
  }

  .c-tab:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .c-tab.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .cap-re-results {
    padding: 8px 10px;
    background: var(--status-success-bg);
    border-bottom: 1px solid var(--status-success-border);
    display: flex;
    flex-direction: column;
    gap: 6px;
    flex-shrink: 0;
    max-height: 150px;
    overflow-y: auto;
  }

  .res-strip-head {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 700;
    color: var(--status-success);
  }

  .res-cards {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .res-card {
    background: var(--bg-surface);
    border: 1px solid var(--status-success-border);
    border-radius: var(--radius-sm);
    padding: 6px 8px;
  }

  .res-card-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .res-summary {
    flex: 1;
    font-size: 11.5px;
    color: var(--text-primary);
  }

  .res-payload {
    margin: 5px 0 0;
    padding: 5px 7px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    font-size: 11px;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
  }

  .console-stream {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 6px 10px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .ev-row {
    border-radius: var(--radius-xs);
    border-left: 2px solid transparent;
    background: var(--bg-elevated);
  }

  .ev-row.lvl-result {
    border-left-color: var(--status-success);
    background: var(--status-success-bg);
  }

  .ev-row.lvl-error,
  .ev-row.lvl-stderr {
    border-left-color: var(--status-danger);
    background: var(--status-danger-bg);
  }

  .ev-row.lvl-system {
    border-left-color: var(--status-info);
    background: transparent;
  }

  .ev-head {
    display: flex;
    align-items: center;
    gap: 7px;
    width: 100%;
    padding: 4px 8px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    text-align: left;
    font-size: 11.5px;
  }

  .ev-head.clickable {
    cursor: pointer;
  }

  .ev-head.clickable:hover {
    background: var(--bg-hover);
  }

  .ev-time {
    font-size: 10.5px;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .ev-msg {
    flex: 1;
    min-width: 0;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .ev-detail-pre {
    margin: 0;
    padding: 6px 10px 8px 22px;
    border-top: 1px solid var(--border-subtle);
    font-size: 11px;
    color: var(--text-secondary);
    white-space: pre-wrap;
  }

  /* ==================== Sub-Tab 3: Deobf / Anti-Debug / VMP ==================== */
  .scroll-workspace {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .risk-banner {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 14px 16px;
  }

  .risk-gauge {
    position: relative;
    width: 76px;
    height: 76px;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .gauge-svg {
    width: 76px;
    height: 76px;
    transform: rotate(-90deg);
  }

  .gauge-track {
    fill: none;
    stroke: var(--bg-subtle);
    stroke-width: 7;
  }

  .gauge-fill {
    fill: none;
    stroke-width: 7;
    stroke-linecap: round;
    transition: stroke-dashoffset 320ms ease;
  }

  .gauge-val {
    position: absolute;
    font-size: 20px;
    font-weight: 700;
  }

  .risk-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .risk-top {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .target-path-lbl {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .risk-summary {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: 1.45;
  }

  .quick-gen-bar {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .section-card {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .card-head {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-xs);
    font-weight: 700;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .card-empty {
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 6px 2px;
  }

  .rec-list {
    padding-left: 18px;
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    line-height: 1.45;
  }

  .findings-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .findings-grid.three-col-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .finding-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .finding-item {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .fi-top {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    font-size: var(--text-xs);
  }

  .fi-pattern {
    font-size: 11px;
    color: var(--text-primary);
    word-break: break-all;
  }

  .fi-note {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.4;
  }

  .chip-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .mono-chip {
    font-family: var(--font-mono);
    font-size: 10.5px;
    padding: 1px 6px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
  }

  /* Tables */
  .table-wrap {
    overflow-x: auto;
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11.5px;
  }

  .data-table th {
    text-align: left;
    padding: 6px 8px;
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-default);
    white-space: nowrap;
  }

  .data-table td {
    padding: 6px 8px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    vertical-align: middle;
  }

  .data-table.clickable-rows tbody tr {
    cursor: pointer;
  }

  .data-table.clickable-rows tbody tr:hover {
    background: var(--bg-hover);
  }

  .data-table.clickable-rows tbody tr.selected {
    background: var(--accent-soft);
  }

  .truncate-cell {
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .entropy-cell {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .mini-bar {
    width: 52px;
    height: 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    overflow: hidden;
  }

  .mini-bar-fill {
    height: 100%;
    border-radius: var(--radius-full);
  }

  /* Script Generators */
  .gen-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .gen-list {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .gen-card {
    display: flex;
    flex-direction: column;
    gap: 3px;
    width: 100%;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    text-align: left;
    cursor: pointer;
  }

  .gen-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .gen-card.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .gc-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .gc-title {
    flex: 1;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .gc-sub {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.35;
  }

  .gen-form {
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 9px;
    background: var(--bg-panel);
  }

  .form-grid.two-col {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px;
  }

  .form-section-label {
    font-size: 10.5px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .check-col {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .check-opt {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .check-opt.compact {
    font-size: 11px;
    gap: 4px;
  }

  .gen-meta-strip {
    padding: 7px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 5px;
    flex-shrink: 0;
  }

  .meta-desc {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .gen-footer {
    padding: 8px 10px;
    background: var(--bg-panel);
    border-top: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .gf-line {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .gf-lbl {
    font-weight: 600;
    color: var(--text-secondary);
  }

  /* VMP Trace Analyzer & Textarea */
  .sub-copy {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .vmp-input-bar {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    flex-wrap: wrap;
  }

  .cap-textarea {
    width: 100%;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 11.5px;
    line-height: 1.5;
    resize: vertical;
    outline: none;
  }

  .cap-textarea:focus {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  /* KPI Grid */
  .kpi-grid {
    display: grid;
    gap: 10px;
  }

  .kpi-grid.four-col {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }

  .kpi-grid.five-col {
    grid-template-columns: repeat(5, minmax(0, 1fr));
  }

  .kpi-grid.six-col {
    grid-template-columns: repeat(6, minmax(0, 1fr));
  }

  .kpi-card {
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .kpi-val {
    font-size: 18px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .kpi-lbl {
    font-size: 10.5px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }

  .summary-banner {
    padding: 9px 12px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  /* ==================== Sub-Tab 4: ExecTrace & Taint ==================== */
  .collector-preview {
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    overflow: hidden;
  }

  .cp-head {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-subtle);
    font-size: var(--text-xs);
  }

  .collector-code {
    margin: 0;
    padding: 8px 10px;
    max-height: 180px;
    overflow: auto;
    font-size: 11px;
    line-height: 1.45;
    color: var(--text-primary);
  }

  .cp-steps {
    padding: 6px 10px;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-surface);
    font-size: 11px;
    color: var(--text-muted);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .crypto-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 8px;
  }

  .crypto-card {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--status-warning-border);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11.5px;
  }

  .heatmap-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .heatmap-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }

  .hm-addr {
    font-size: 11.5px;
    font-weight: 600;
    min-width: 190px;
    color: var(--text-primary);
  }

  .hm-bars {
    flex: 1;
    min-width: 160px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .hm-bar-track {
    height: 7px;
    border-radius: var(--radius-full);
    background: var(--bg-input);
    display: flex;
    overflow: hidden;
  }

  .hm-read {
    background: var(--status-info);
    height: 100%;
  }

  .hm-write {
    background: var(--status-warning);
    height: 100%;
  }

  .hm-counts {
    font-size: 10.5px;
    color: var(--text-muted);
  }

  .hm-sample {
    max-width: 160px;
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .calltree-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-height: 280px;
    overflow-y: auto;
    font-size: 11.5px;
  }

  .ct-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 3px 6px;
    border-radius: var(--radius-xs);
  }

  .ct-row:hover {
    background: var(--bg-hover);
  }

  .ct-leaf {
    color: var(--text-faint);
    width: 14px;
    text-align: center;
  }

  /* Events Tab */
  .events-filter-bar {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 8px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .compact-sel {
    width: 130px;
    height: 28px;
    font-size: var(--text-xs);
  }

  .addr-filter {
    width: 140px;
    height: 28px;
    font-size: var(--text-xs);
  }

  .seed-strip {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    background: var(--accent-soft);
    border-bottom: 1px solid var(--accent-border);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .seed-chip {
    height: 20px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--accent-border);
    background: var(--bg-surface);
    color: var(--accent);
    font-size: 10.5px;
    cursor: pointer;
  }

  .seed-chip:hover {
    background: var(--accent);
    color: var(--text-inverse);
  }

  .seed-chip.mem {
    border-color: var(--status-warning-border);
    color: var(--status-warning);
  }

  .events-table-scroll {
    flex: 1;
    min-height: 0;
    overflow: auto;
    background: var(--bg-app);
  }

  .taint-row-btn {
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    border-radius: var(--radius-xs);
    width: 22px;
    height: 22px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }

  .taint-row-btn:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
  }

  .pagination-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-panel);
    border-top: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .taint-step-row {
    background: color-mix(in srgb, var(--accent) 4%, transparent);
  }

  /* Trace Diff */
  .first-div-card {
    border-color: var(--status-danger-border);
    background: color-mix(in srgb, var(--status-danger) 5%, var(--bg-surface));
  }

  .div-compare {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .div-side {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11.5px;
  }

  .div-side-lbl {
    font-size: 10.5px;
    color: var(--text-muted);
    font-family: var(--font-sans);
    font-weight: 600;
  }

  .div-insn {
    font-weight: 600;
    color: var(--text-primary);
  }

  .reg-diff-block {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  /* Semantic Text Utilities */
  .bold { font-weight: 600; }
  .accent-txt { color: var(--accent); }
  .purple-txt { color: var(--status-purple); }
  .success-txt { color: var(--status-success); }
  .warn-txt { color: var(--status-warning); }
  .danger-txt { color: var(--status-danger); }

  .mini-icon-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .mini-icon-btn:hover {
    color: var(--text-primary);
  }

  /* ==================== Wave C Pro Upgrades ==================== */
  .inline-action-row {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .inline-field {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
  }

  .compact-input {
    width: 190px;
    height: 24px;
    font-size: 11px;
  }

  .compact-table-box {
    max-height: 180px;
    overflow-y: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .plist-kv-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px 14px;
    font-size: 11.5px;
  }

  .jadx-src-search {
    flex: 0 1 240px;
  }

  .jadx-cls-row {
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
  }

  .jadx-cls-main {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    min-width: 0;
  }

  .jadx-reg-box {
    padding: 6px 10px;
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-panel);
    flex-shrink: 0;
  }

  .inline-pills {
    padding: 0;
    border-bottom: none;
  }

  .ja3-box {
    padding: 6px 8px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    font-size: 11px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .tls-editor-box {
    height: 230px;
    display: flex;
    flex-direction: column;
  }

  .op-catalog-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
    width: 100%;
    padding: 7px 9px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    color: var(--text-primary);
    text-align: left;
    font-size: var(--text-xs);
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .op-catalog-row:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .op-row-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .step-card {
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .step-card.step-disabled {
    opacity: 0.58;
  }

  .step-card-head {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
  }

  .step-params-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px 8px;
  }

  .crypto-out-pre {
    max-height: 200px;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .trace-step-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 11px;
    text-align: left;
    cursor: pointer;
    padding: 0;
  }

  .trace-step-body {
    padding-top: 5px;
    border-top: 1px solid var(--border-subtle);
    font-size: 11px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .proto-tree-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .proto-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }

  .proto-num-lbl {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .proto-num-inp {
    width: 58px;
    height: 24px;
    font-size: 11px;
    padding: 0 5px;
  }

  .proto-kind-sel {
    width: 118px;
    height: 24px;
    font-size: 11px;
  }

  .dfa-key-card {
    gap: 4px;
  }

  .dfa-key-val {
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 0.04em;
    word-break: break-all;
  }

  .dfa-col-solved {
    border-color: var(--status-success-border);
    background: var(--status-success-bg);
  }
</style>
