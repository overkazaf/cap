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
    qiling_rootfs: '',
  }

  // ==================== Sub-Tab 1: Native Binary & Radare2 ====================
  let binaryPath = S.binaryPath || ''
  let binaryAnalysis = S.binaryAnalysis || null
  let analyzingBinary = false
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

  // ==================== Sub-Tab 3: Deobf · Anti-Debug · VMP ====================
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

  // Subscriptions
  let unsubs = []
  let unsubHandoff = null
  let unregisterCmds = null

  // ==================== State Persistence ====================
  $: {
    S.subTab = subTab
    S.binaryPath = binaryPath
    S.binaryAnalysis = binaryAnalysis
    S.nativeLeftTab = nativeLeftTab
    S.nativeSearch = nativeSearch
    S.nativeJniOnly = nativeJniOnly
    S.selectedFuncKey = selectedFuncKey
    S.functionDetail = functionDetail
    S.funcViewTab = funcViewTab
    S.r2Cmd = r2Cmd
    S.r2History = r2History

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
          keywords: 'radare2 r2 elf disasm binary native',
          run: () => (subTab = 'native'),
        },
        {
          id: 'relab:emulate',
          label: `RE Lab: ${_t('reLab.tabs.emulate')}`,
          category: 'RE Lab',
          icon: 'play',
          keywords: 'unidbg qiling angr emulate symbolic',
          run: () => (subTab = 'emulate'),
        },
        {
          id: 'relab:deobf',
          label: `RE Lab: ${_t('reLab.tabs.deobf')}`,
          category: 'RE Lab',
          icon: 'shield',
          keywords: 'deobf ollvm antidebug vmp packer stealth',
          run: () => (subTab = 'deobf'),
        },
        {
          id: 'relab:exectrace',
          label: `RE Lab: ${_t('reLab.tabs.exectrace')}`,
          category: 'RE Lab',
          icon: 'activity',
          keywords: 'exectrace taint diff stalker tenet crypto',
          run: () => (subTab = 'exectrace'),
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

  // ==================== Events, Handoff & Lifecycle ====================
  function applyHandoff(h) {
    if (!h) return
    if (h.subTab) subTab = h.subTab
    if (h.binaryPath) {
      binaryPath = h.binaryPath
      projBinaryPath = h.binaryPath
      if (!genSoPath) genSoPath = h.binaryPath
    }
    if (h.apkPath) {
      projAPKPath = h.apkPath
      if (!genApkPath) genApkPath = h.apkPath
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
      app?.GetREJobState?.().then((st) => { if (st) applyJobStatus(st) }).catch(() => {}),
    ])
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
        aria-selected={subTab === 'deobf'}
        class="subtab-btn"
        class:active={subTab === 'deobf'}
        on:click={() => (subTab = 'deobf')}
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
          <span>{$t('reLab.toolchain.qilingRootfs')}</span>
          <input type="text" class="cap-input mono" bind:value={tcForm.qiling_rootfs} placeholder={toolchain?.qiling_rootfs || $t('reLab.toolchain.qilingPlaceholder')} />
        </label>
      </div>

      <div class="tc-detail-row">
        {#each toolchainPills as pill (pill.key)}
          <div class="tc-stat-chip">
            <Badge variant={pill.ready ? 'success' : 'neutral'} size="xs" dot>{pill.label}</Badge>
            <span class="mono truncate">{pill.info?.version || pill.info?.issue || '—'}</span>
          </div>
        {/each}
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
          javac: {toolchain?.javac_path || '—'} · python: {toolchain?.python?.version || '—'}
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
          <Button variant="primary" size="sm" icon="search" loading={analyzingBinary} on:click={analyzeBinary}>
            {analyzingBinary ? $t('reLab.native.analyzing') : $t('reLab.native.analyzeBtn')}
          </Button>
          {#if binaryAnalysis}
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
         SUB-TAB 3: DEOBF · ANTI-DEBUG · VMP
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
        {:else}
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
        {/if}
      </div>

    <!-- ======================================================================
         SUB-TAB 4: EXECTRACE & TAINT
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
</style>
