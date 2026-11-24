<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/frida.js'
  import { t, translate } from '../lib/i18n.js'
  import { fridaState as S, fridaHandoff } from '../lib/fridaState.js'
  import { navigate } from '../lib/navigation.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard } from '../lib/format.js'
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

  // Device & Server state
  let devices = []
  let selectedDevice = S.selectedDevice
  let serverStatus = null
  let toolchain = null
  let refreshingEnv = false
  let serverBusy = false

  // Inline Deploy & Runtime Config panels
  let showDeployPanel = false
  let deployVersion = ''
  let deployArch = ''
  let deployRemoteName = 'frida-server'
  let deployPort = S.port || 27042
  let deployLocalBin = ''
  let deployAutoStart = true
  let deployForwardPort = true
  let deploying = false
  let deployProgress = null

  let showRuntimePanel = false
  let customPythonPath = ''
  let customFridaCLIPath = ''
  let savingRuntime = false

  // Target & Processes
  let target = S.target
  let mode = S.mode || 'attach'
  let noPause = S.noPause ?? true
  let processes = []
  let loadingProcs = false
  let showProcPicker = false
  let procFilter = ''

  // Script Library & Editor
  let scripts = []
  let scriptDir = ''
  let leftTab = S.leftTab || 'scripts'
  let scriptCategoryFilter = S.scriptCategoryFilter || 'all'
  let scriptSearch = S.scriptSearch || ''

  let scriptId = S.scriptId
  let scriptName = S.scriptName
  let scriptCategory = S.scriptCategory
  let scriptDescription = S.scriptDescription
  let scriptCode = S.scriptCode
  let scriptBuiltin = S.scriptBuiltin
  let dirty = S.dirty
  let savingScript = false
  let editorRef = null

  // CodeShare
  let codeshareQuery = S.codeshareQuery
  let codeshareResults = S.codeshareResults
  let codeshareLoading = false
  let fingerprintLoading = false
  let fingerprintResult = S.fingerprintResult

  // From DeepTrace
  let traceState = null
  let traceGenOpts = { ...S.traceGenOpts }
  let generatingHook = false
  let lastGeneratedHook = S.lastGeneratedHook

  // Active Session & Live Console
  let session = null
  let sessionStarting = false
  let reloadingScript = false
  let consoleFilter = S.consoleFilter || 'all'
  let consoleSearch = S.consoleSearch || ''
  let autoScroll = S.autoScroll ?? true
  let expandedEvents = new Set()
  let consoleEl = null
  let elapsedTick = Date.now()
  let clockTimer = null

  let unsubs = []
  let unsubHandoff = null
  let unregisterCmds = null

  const CATEGORIES = ['all', 'unpin', 'anti-detect', 'network', 'crypto', 'native', 'trace', 'codeshare', 'custom']
  const EDIT_CATEGORIES = ['custom', 'unpin', 'anti-detect', 'network', 'crypto', 'native', 'trace', 'codeshare']

  const SNIPPETS = [
    {
      key: 'javaPerform',
      code: `Java.perform(function () {\n    // your Java hooks\n});\n`,
    },
    {
      key: 'hookMethod',
      code: `Java.perform(function () {\n    const Cls = Java.use('com.example.TargetClass');\n    Cls.targetMethod.overloads.forEach(function (ov) {\n        ov.implementation = function () {\n            const ret = ov.apply(this, arguments);\n            send({ cap_cat: 'trace', hook: 'TargetClass.targetMethod', args: Array.from(arguments).map(String), retval: String(ret) });\n            return ret;\n        };\n    });\n});\n`,
    },
    {
      key: 'interceptor',
      code: `const addr = Module.findExportByName('libtarget.so', 'target_func');\nif (addr) {\n    Interceptor.attach(addr, {\n        onEnter(args) {\n            this.arg0 = args[0].readUtf8String();\n        },\n        onLeave(retval) {\n            send({ cap_cat: 'native', hook: 'libtarget.so!target_func', arg0: this.arg0, retval: retval.toString() });\n        }\n    });\n}\n`,
    },
    {
      key: 'sendEvent',
      code: `send({ cap_cat: 'trace', hook: 'myHook', detail: 'triggered' });\n`,
    },
    {
      key: 'stackTrace',
      code: `const stack = Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());\nconsole.log(stack);\n`,
    },
    {
      key: 'hexdump',
      code: `console.log(hexdump(args[0], { offset: 0, length: 64, header: true, ansi: false }));\n`,
    },
  ]

  // Persist lightweight state across route changes
  $: {
    S.selectedDevice = selectedDevice
    S.target = target
    S.mode = mode
    S.noPause = noPause
    S.port = deployPort
    S.scriptId = scriptId
    S.scriptName = scriptName
    S.scriptCategory = scriptCategory
    S.scriptDescription = scriptDescription
    S.scriptCode = scriptCode
    S.scriptBuiltin = scriptBuiltin
    S.dirty = dirty
    S.leftTab = leftTab
    S.scriptCategoryFilter = scriptCategoryFilter
    S.scriptSearch = scriptSearch
    S.consoleFilter = consoleFilter
    S.consoleSearch = consoleSearch
    S.autoScroll = autoScroll
    S.codeshareQuery = codeshareQuery
    S.codeshareResults = codeshareResults
    S.fingerprintResult = fingerprintResult
    S.traceGenOpts = traceGenOpts
    S.lastGeneratedHook = lastGeneratedHook
  }

  $: isSessionRunning = Boolean(session?.running)
  $: canHotReload = Boolean(isSessionRunning && session?.can_hot_reload)
  $: events = session?.events || []
  $: liveElapsedMs = isSessionRunning && session?.started_at_ms
    ? Math.max(0, elapsedTick - session.started_at_ms)
    : (session?.elapsed_ms || 0)

  $: filteredScripts = scripts.filter((sc) => {
    if (scriptCategoryFilter !== 'all' && sc.category !== scriptCategoryFilter) return false
    const q = scriptSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (sc.name || '').toLowerCase().includes(q) ||
      (sc.description || '').toLowerCase().includes(q) ||
      (sc.tags || []).some((tag) => tag.toLowerCase().includes(q))
    )
  })

  $: filteredProcs = processes.filter((p) => {
    const q = procFilter.trim().toLowerCase()
    if (!q) return true
    return (
      (p.name || '').toLowerCase().includes(q) ||
      (p.identifier || '').toLowerCase().includes(q) ||
      String(p.pid || '').includes(q)
    )
  })

  $: eventCounts = {
    all: events.length,
    hook: events.filter((e) => e.level === 'hook' || e.level === 'send').length,
    console: events.filter((e) => e.level === 'console' || e.level === 'info' || e.level === 'warn').length,
    error: events.filter((e) => e.level === 'error').length,
    system: events.filter((e) => e.level === 'system').length,
  }

  $: filteredEvents = events.filter((ev) => {
    if (consoleFilter === 'hook' && ev.level !== 'hook' && ev.level !== 'send') return false
    if (consoleFilter === 'console' && ev.level !== 'console' && ev.level !== 'info' && ev.level !== 'warn') return false
    if (consoleFilter === 'error' && ev.level !== 'error') return false
    if (consoleFilter === 'system' && ev.level !== 'system') return false
    const q = consoleSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (ev.message || '').toLowerCase().includes(q) ||
      (ev.category || '').toLowerCase().includes(q) ||
      (ev.raw || '').toLowerCase().includes(q)
    )
  })

  $: serverBadgeVariant = serverStatus?.running
    ? 'success'
    : serverStatus?.binary_path
      ? 'warning'
      : 'neutral'

  $: runtimeBadgeVariant = toolchain?.driver === 'python-bridge'
    ? 'success'
    : toolchain?.driver === 'frida-cli'
      ? 'warning'
      : 'danger'

  // Register Command Palette shortcuts
  $: {
    const _t = $t
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      unregisterCmds = registerCommands([
        {
          id: 'frida:run',
          label: `Frida: ${_t('frida.targetBar.runHook')}`,
          category: 'Frida',
          icon: 'zap',
          keywords: 'frida inject spawn attach hook',
          run: startSession,
        },
        {
          id: 'frida:deploy',
          label: `Frida: ${_t('frida.deploy.title')}`,
          category: 'Frida',
          icon: 'download',
          keywords: 'frida server deploy push download',
          run: () => {
            showDeployPanel = true
            showRuntimePanel = false
          },
        },
      ])
    }
  }

  function formatClock(ms) {
    const safe = Math.max(0, Number(ms) || 0)
    const totalSec = Math.floor(safe / 1000)
    const mins = Math.floor(totalSec / 60)
    const secs = totalSec % 60
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
  }

  function formatEventTime(tsMs) {
    if (!tsMs) return ''
    try {
      return new Date(tsMs).toLocaleTimeString('en-US', { hour12: false })
    } catch (_) {
      return ''
    }
  }

  function categoryVariant(cat) {
    switch (cat) {
      case 'unpin':
      case 'ssl':
        return 'success'
      case 'anti-detect':
        return 'purple'
      case 'network':
      case 'http':
        return 'info'
      case 'crypto':
        return 'warning'
      case 'native':
      case 'jni':
        return 'danger'
      case 'trace':
        return 'accent'
      default:
        return 'neutral'
    }
  }

  async function scrollConsole() {
    if (!autoScroll) return
    await tick()
    if (consoleEl) {
      consoleEl.scrollTop = consoleEl.scrollHeight
    }
  }

  function toggleEventExpand(seq) {
    const next = new Set(expandedEvents)
    if (next.has(seq)) next.delete(seq)
    else next.add(seq)
    expandedEvents = next
  }

  function payloadEntries(payload) {
    if (!payload || typeof payload !== 'object') return []
    return Object.entries(payload).filter(([k]) => k !== 'cap_cat' && k !== 'stack')
  }

  function formatPayloadValue(val) {
    if (val === null || val === undefined) return String(val)
    if (typeof val === 'string') return val
    try {
      return JSON.stringify(val, null, 2)
    } catch (_) {
      return String(val)
    }
  }

  // ==================== Backend Loading ====================

  async function loadEnvironment(forceToolchain = false) {
    const app = api()
    if (!app) return
    refreshingEnv = true
    try {
      const [tc, devs, settings] = await Promise.all([
        app.GetFridaToolchain?.(forceToolchain).catch(() => null),
        app.ListDevices?.().catch(() => []),
        app.GetSettings?.().catch(() => null),
      ])
      if (tc) toolchain = tc
      if (settings) {
        customPythonPath = settings.frida_python_path || ''
        customFridaCLIPath = settings.frida_cli_path || ''
        if (settings.frida_default_port && !deployPort) {
          deployPort = Number(settings.frida_default_port) || 27042
        }
      }
      devices = Array.isArray(devs) ? devs : []
      if (devices.length > 0 && !devices.some((d) => d.serial === selectedDevice)) {
        const ready = devices.find((d) => d.state === 'device') || devices[0]
        selectedDevice = ready.serial
      }
      if (selectedDevice) {
        await refreshServerStatus()
      } else {
        serverStatus = null
      }
    } finally {
      refreshingEnv = false
    }
  }

  async function refreshServerStatus() {
    const app = api()
    if (!app?.GetFridaServerStatus || !selectedDevice) {
      serverStatus = null
      return
    }
    try {
      serverStatus = await app.GetFridaServerStatus(selectedDevice, Number(deployPort) || 27042)
      if (serverStatus?.port) {
        deployPort = serverStatus.port
      }
    } catch (_) {}
  }

  async function loadScripts() {
    const app = api()
    if (!app?.ListFridaScripts) return
    try {
      const [list, dir] = await Promise.all([
        app.ListFridaScripts(),
        app.GetFridaScriptDir?.().catch(() => ''),
      ])
      scripts = Array.isArray(list) ? list : []
      scriptDir = dir || ''
      if (!scriptCode && scripts.length > 0) {
        selectScript(scripts[0], false)
      }
    } catch (_) {}
  }

  async function reloadScriptsFromDisk() {
    const app = api()
    if (!app?.ReloadFridaScripts) return
    try {
      const list = await app.ReloadFridaScripts()
      scripts = Array.isArray(list) ? list : []
      toast.info(translate('frida.toast.scriptsReloaded', { count: scripts.length }))
    } catch (_) {}
  }

  async function restoreSessionAndTrace() {
    const app = api()
    if (!app) return
    try {
      const [sess, tr] = await Promise.all([
        app.GetFridaSessionState?.().catch(() => null),
        app.GetDeepTraceState?.().catch(() => null),
      ])
      if (sess) {
        session = sess
        if (sess.running && sess.target && !target) {
          target = sess.target
        }
      }
      if (tr) {
        traceState = tr
      }
    } catch (_) {}
  }

  // ==================== Server Actions ====================

  async function handleStartServer() {
    const app = api()
    if (!app?.StartFridaServer || !selectedDevice || serverBusy) return
    serverBusy = true
    try {
      serverStatus = await app.StartFridaServer({
        serial: selectedDevice,
        binary_path: serverStatus?.binary_path || '',
        port: Number(deployPort) || 27042,
        listen_host: '0.0.0.0',
        forward_port: true,
      })
      toast.success(translate('frida.toast.serverStarted', { serial: selectedDevice }))
    } catch (e) {
      toast.error(translate('frida.toast.serverFailed', { err: e?.message || e }))
    } finally {
      serverBusy = false
    }
  }

  async function handleStopServer() {
    const app = api()
    if (!app?.StopFridaServer || !selectedDevice || serverBusy) return
    serverBusy = true
    try {
      serverStatus = await app.StopFridaServer(
        selectedDevice,
        serverStatus?.binary_name || '',
        Number(deployPort) || 27042
      )
      toast.info(translate('frida.toast.serverStopped'))
    } catch (e) {
      toast.error(translate('frida.toast.serverFailed', { err: e?.message || e }))
    } finally {
      serverBusy = false
    }
  }

  async function handleDeployServer() {
    const app = api()
    if (!app?.DeployFridaServer || !selectedDevice || deploying) return
    deploying = true
    deployProgress = { stage: 'resolve', detail: 'Preparing deployment…', percent: 5 }
    try {
      const res = await app.DeployFridaServer({
        serial: selectedDevice,
        version: deployVersion.trim(),
        arch: deployArch.trim(),
        local_binary_path: deployLocalBin.trim(),
        remote_name: deployRemoteName.trim() || 'frida-server',
        port: Number(deployPort) || 27042,
        auto_start: deployAutoStart,
        forward_port: deployForwardPort,
      })
      if (res?.status) {
        serverStatus = res.status
      } else {
        await refreshServerStatus()
      }
      toast.success(translate('frida.toast.deployDone', { msg: res?.message || 'OK' }))
      showDeployPanel = false
    } catch (e) {
      toast.error(translate('frida.toast.deployFailed', { err: e?.message || e }))
    } finally {
      deploying = false
    }
  }

  async function saveRuntimeConfig() {
    const app = api()
    if (!app?.UpdateFridaToolchainConfig) return
    savingRuntime = true
    try {
      toolchain = await app.UpdateFridaToolchainConfig(customPythonPath.trim(), customFridaCLIPath.trim())
      toast.success(translate('frida.toast.runtimeUpdated', { driver: toolchain?.driver || 'none' }))
      await refreshServerStatus()
    } catch (e) {
      toast.error(translate('frida.toast.serverFailed', { err: e?.message || e }))
    } finally {
      savingRuntime = false
    }
  }

  // ==================== Process Picker ====================

  async function loadProcesses() {
    const app = api()
    if (!app?.ListFridaProcesses || loadingProcs) return
    loadingProcs = true
    try {
      const remoteHost = serverStatus?.forwarded ? serverStatus.remote_endpoint : ''
      const list = await app.ListFridaProcesses(selectedDevice, remoteHost)
      processes = Array.isArray(list) ? list : []
      showProcPicker = true
    } catch (e) {
      toast.error(e?.message || String(e))
    } finally {
      loadingProcs = false
    }
  }

  function pickProcess(p) {
    target = p.identifier || (p.pid > 0 ? String(p.pid) : p.name)
    if (p.running && p.pid > 0) {
      mode = 'attach'
    } else {
      mode = 'spawn'
    }
    showProcPicker = false
  }

  // ==================== Script Management ====================

  function selectScript(sc, resetEd = true) {
    if (!sc) return
    scriptId = sc.id || ''
    scriptName = sc.name || 'Untitled'
    scriptCategory = sc.category || 'custom'
    scriptDescription = sc.description || ''
    scriptCode = sc.code || ''
    scriptBuiltin = Boolean(sc.builtin)
    dirty = false
    if (resetEd && editorRef?.resetHistory) {
      editorRef.resetHistory(scriptCode)
    }
  }

  function createNewScript() {
    scriptId = ''
    scriptName = 'Custom Hook'
    scriptCategory = 'custom'
    scriptDescription = ''
    scriptCode = `'use strict';\n\nJava.perform(function () {\n    send({ cap_cat: 'trace', hook: 'init', detail: 'Custom Frida hook active' });\n});\n`
    scriptBuiltin = false
    dirty = true
    editorRef?.resetHistory?.(scriptCode)
  }

  async function saveCurrentScript() {
    const app = api()
    if (!app?.SaveFridaScript || savingScript) return
    savingScript = true
    try {
      const nameToSave = scriptName.trim() || 'Untitled Script'
      const saved = await app.SaveFridaScript({
        id: scriptBuiltin ? '' : scriptId,
        name: scriptBuiltin ? `${nameToSave} (Custom)` : nameToSave,
        description: scriptDescription,
        category: scriptCategory || 'custom',
        code: scriptCode,
        target_package: target.trim(),
      })
      if (saved) {
        scriptId = saved.id
        scriptName = saved.name
        scriptBuiltin = false
        dirty = false
      }
      await loadScripts()
      toast.success(translate('frida.toast.scriptSaved', { name: saved?.name || nameToSave }))
    } catch (e) {
      toast.error(translate('frida.toast.scriptSaveFailed', { err: e?.message || e }))
    } finally {
      savingScript = false
    }
  }

  async function deleteCustomScript(sc, ev) {
    ev?.stopPropagation?.()
    if (!sc || sc.builtin) return
    const app = api()
    if (!app?.DeleteFridaScript) return
    try {
      await app.DeleteFridaScript(sc.id)
      if (scriptId === sc.id) {
        scriptId = ''
      }
      await loadScripts()
      toast.info(translate('frida.toast.scriptDeleted', { name: sc.name }))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  function insertSnippet(snippet) {
    if (editorRef?.insertAtCursor) {
      editorRef.insertAtCursor(snippet.code)
      dirty = true
    } else {
      scriptCode = (scriptCode ? scriptCode + '\n' : '') + snippet.code
      dirty = true
    }
  }

  // ==================== Session Controls ====================

  async function startSession() {
    const app = api()
    if (!app?.StartFridaSession || sessionStarting) return
    const tTarget = target.trim()
    if (!tTarget) {
      toast.warning(translate('frida.toast.selectTargetFirst'))
      return
    }
    sessionStarting = true
    try {
      const portNum = Number(deployPort) || 27042
      const remoteHost = serverStatus?.forwarded && portNum !== 27042 ? `127.0.0.1:${portNum}` : ''
      session = await app.StartFridaSession({
        serial: selectedDevice,
        target: tTarget,
        mode,
        script_code: scriptCode,
        script_id: scriptId,
        script_name: scriptName || 'Untitled Script',
        port: portNum,
        remote_host: remoteHost,
        no_pause: noPause,
      })
      toast.success(translate('frida.toast.sessionStarted', { target: tTarget }))
    } catch (e) {
      toast.error(translate('frida.toast.sessionStartFailed', { err: e?.message || e }))
    } finally {
      sessionStarting = false
    }
  }

  async function stopSession() {
    const app = api()
    if (!app?.StopFridaSession) return
    try {
      await app.StopFridaSession()
      toast.info(translate('frida.toast.sessionStopped'))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  async function hotReloadScript() {
    const app = api()
    if (!app?.ReloadFridaSessionScript || !canHotReload || reloadingScript) return
    reloadingScript = true
    try {
      await app.ReloadFridaSessionScript(scriptCode)
      toast.success(translate('frida.toast.hotReloaded'))
    } catch (e) {
      toast.error(translate('frida.toast.hotReloadFailed', { err: e?.message || e }))
    } finally {
      reloadingScript = false
    }
  }

  async function resumeSpawnedProcess() {
    const app = api()
    if (!app?.ResumeFridaSession) return
    try {
      await app.ResumeFridaSession()
      toast.success(translate('frida.toast.resumed'))
    } catch (e) {
      toast.error(e?.message || String(e))
    }
  }

  function clearConsole() {
    api()?.ClearFridaSessionLogs?.()
    if (session) {
      session = { ...session, events: [], event_count: 0, hook_count: 0, error_count: 0 }
    }
    expandedEvents = new Set()
  }

  function copyConsole() {
    const text = filteredEvents
      .map((ev) => `[${formatEventTime(ev.timestamp_ms)}] [${ev.level.toUpperCase()}] [${ev.category}] ${ev.message}`)
      .join('\n')
    copyToClipboard(text, translate('frida.toast.copiedConsole'))
  }

  function exportConsoleJsonl() {
    const lines = filteredEvents.map((ev) => JSON.stringify(ev)).join('\n')
    const blob = new Blob([lines], { type: 'application/x-ndjson;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `frida-${(target || 'session').replace(/[^a-zA-Z0-9._-]+/g, '_')}.jsonl`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success(translate('frida.toast.exportedJsonl', { count: filteredEvents.length }))
  }

  // ==================== CodeShare & Fingerprint ====================

  async function searchCodeShare(popular = false) {
    const app = api()
    if (!app?.SearchFridaCodeShare) return
    codeshareLoading = true
    try {
      const list = popular
        ? await app.BrowseFridaCodeShare(1)
        : await app.SearchFridaCodeShare(codeshareQuery.trim())
      codeshareResults = Array.isArray(list) ? list : []
    } catch (e) {
      toast.error(translate('frida.toast.codeshareFailed', { err: e?.message || e }))
    } finally {
      codeshareLoading = false
    }
  }

  async function runAppFingerprint() {
    const app = api()
    if (!app?.FingerprintDeviceApp) return
    const pkg = target.trim()
    if (!pkg) {
      toast.warning(translate('frida.toast.selectTargetFirst'))
      return
    }
    fingerprintLoading = true
    try {
      const bundle = await app.FingerprintDeviceApp(selectedDevice, pkg, true)
      fingerprintResult = bundle?.fingerprint || null
      if (Array.isArray(bundle?.scripts) && bundle.scripts.length > 0) {
        codeshareResults = bundle.scripts
      }
      toast.success(translate('frida.toast.fingerprintDone', { pkg, count: bundle?.scripts?.length || 0 }))
    } catch (e) {
      toast.error(translate('frida.toast.fingerprintFailed', { err: e?.message || e }))
    } finally {
      fingerprintLoading = false
    }
  }

  async function fetchCodeShareEntry(entry, saveLocally = false) {
    const app = api()
    if (!app?.FetchFridaCodeShareScript || !entry?.slug) return
    codeshareLoading = true
    try {
      const fetched = await app.FetchFridaCodeShareScript(entry.slug)
      if (!fetched?.source) return
      scriptId = ''
      scriptName = fetched.title || entry.title || entry.slug
      scriptCategory = 'codeshare'
      scriptDescription = entry.description || `CodeShare ${entry.slug}`
      scriptCode = fetched.source
      scriptBuiltin = false
      dirty = !saveLocally
      editorRef?.resetHistory?.(scriptCode)
      if (saveLocally) {
        await saveCurrentScript()
      } else {
        toast.success(translate('frida.toast.codeshareLoaded', { title: scriptName }))
      }
    } catch (e) {
      toast.error(translate('frida.toast.codeshareFailed', { err: e?.message || e }))
    } finally {
      codeshareLoading = false
    }
  }

  // ==================== DeepTrace -> Frida Hook Generator ====================

  async function generateFromTrace() {
    const app = api()
    if (!app?.GenerateFridaHookFromTrace || generatingHook) return
    generatingHook = true
    try {
      const gen = await app.GenerateFridaHookFromTrace({
        ...traceGenOpts,
        target_package: target.trim() || traceState?.package || '',
      })
      if (gen) {
        lastGeneratedHook = gen
        if (gen.target_package && !target.trim()) {
          target = gen.target_package
        }
        scriptId = ''
        scriptName = gen.script_name || 'DeepTrace Hook'
        scriptCategory = 'trace'
        scriptDescription = gen.summary || ''
        scriptCode = gen.code || ''
        scriptBuiltin = false
        dirty = true
        editorRef?.resetHistory?.(scriptCode)
        toast.success(
          translate('frida.toast.traceHookGenerated', {
            java: gen.java_targets?.length || 0,
            native: gen.native_targets?.length || 0,
          })
        )
      }
    } catch (e) {
      toast.error(translate('frida.toast.traceHookFailed', { err: e?.message || e }))
    } finally {
      generatingHook = false
    }
  }

  // ==================== Events & Shortcuts ====================

  function applyHandoff(h) {
    if (!h) return
    if (h.serial) selectedDevice = h.serial
    if (h.target) target = h.target
    if (h.mode === 'spawn' || h.mode === 'attach') mode = h.mode
    if (h.leftTab) leftTab = h.leftTab
    if (h.scriptCode) {
      scriptId = ''
      scriptName = h.scriptName || 'DeepTrace Hook'
      scriptCategory = h.scriptCategory || 'trace'
      scriptDescription = h.scriptDescription || ''
      scriptCode = h.scriptCode
      scriptBuiltin = false
      dirty = true
      editorRef?.resetHistory?.(scriptCode)
    }
    if (h.generatedHook) {
      lastGeneratedHook = h.generatedHook
    }
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return
    const on = (name, fn) => {
      const off = rt.EventsOn(name, fn)
      if (typeof off === 'function') unsubs.push(off)
    }
    on('frida:log', (ev) => {
      if (!ev) return
      if (!session) {
        session = { id: ev.session_id, status: 'running', running: true, events: [ev], event_count: 1, hook_count: 0, error_count: 0 }
      } else {
        const nextEvents = [...(session.events || []), ev].slice(-1000)
        session = {
          ...session,
          events: nextEvents,
          event_count: (session.event_count || 0) + 1,
          hook_count: (session.hook_count || 0) + (ev.level === 'hook' || ev.level === 'send' ? 1 : 0),
          error_count: (session.error_count || 0) + (ev.level === 'error' ? 1 : 0),
        }
      }
      scrollConsole()
    })
    on('frida:status', (st) => {
      if (!st) return
      session = {
        ...st,
        events: Array.isArray(st.events) && st.events.length >= (session?.events?.length || 0)
          ? st.events
          : (session?.events || []),
      }
    })
    on('frida:deploy_progress', (ev) => {
      if (ev) deployProgress = ev
    })
  }

  function handleKeydown(e) {
    if (!hasPrimaryMod(e)) return
    const k = e.key.toLowerCase()
    if (k === 's') {
      e.preventDefault()
      saveCurrentScript()
    } else if (k === 'enter') {
      e.preventDefault()
      if (isSessionRunning && canHotReload) {
        hotReloadScript()
      } else if (!isSessionRunning) {
        startSession()
      }
    } else if (k === 'r' && canHotReload) {
      e.preventDefault()
      hotReloadScript()
    }
  }

  onMount(async () => {
    subscribeEvents()
    unsubHandoff = fridaHandoff.subscribe((h) => {
      if (h) applyHandoff(h)
    })
    await Promise.all([loadEnvironment(false), loadScripts(), restoreSessionAndTrace()])
    if (scriptCode && editorRef?.resetHistory) {
      editorRef.resetHistory(scriptCode)
    }
    clockTimer = setInterval(() => {
      if (isSessionRunning) elapsedTick = Date.now()
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

<div class="frida-page">
  <!-- 1. Top Control Strip: Device + frida-server Lifecycle + Host Toolchain -->
  <section class="env-strip">
    <div class="env-group">
      <span class="strip-label">
        <Icon name="smartphone" size={13} />
        <span>{$t('frida.topbar.device')}</span>
      </span>
      <select
        class="cap-input device-select mono"
        bind:value={selectedDevice}
        on:change={refreshServerStatus}
      >
        {#if devices.length === 0}
          <option value="">{$t('frida.topbar.noDevices')}</option>
        {:else}
          {#each devices as d (d.serial)}
            <option value={d.serial}>{d.serial} ({d.state})</option>
          {/each}
        {/if}
      </select>
      <Button
        variant="ghost"
        size="xs"
        icon="refresh"
        iconOnly
        loading={refreshingEnv}
        title={$t('frida.topbar.refreshDevices')}
        on:click={() => loadEnvironment(true)}
      />
    </div>

    <span class="v-sep"></span>

    <!-- Server Status & Controls -->
    <div class="env-group">
      <span class="strip-label">
        <Icon name="shield" size={13} />
        <span>{$t('frida.topbar.server')}</span>
      </span>

      <Badge variant={serverBadgeVariant} size="xs" dot pulse={Boolean(serverStatus?.running)}>
        {#if serverStatus?.running}
          {$t('frida.topbar.running')}{serverStatus.pid ? ` #${serverStatus.pid}` : ''}
        {:else if serverStatus?.binary_path}
          {$t('frida.topbar.stopped')}
        {:else}
          {$t('frida.topbar.missing')}
        {/if}
      </Badge>

      {#if serverStatus?.frida_arch}
        <Badge variant="neutral" size="xs" mono>{serverStatus.frida_arch}</Badge>
      {/if}
      {#if serverStatus?.server_version}
        <Badge
          variant={serverStatus.version_match === 'major_mismatch'
            ? 'danger'
            : serverStatus.version_match === 'minor_diff'
              ? 'warning'
              : 'info'}
          size="xs"
          mono
        >
          v{serverStatus.server_version}
        </Badge>
      {/if}
      {#if serverStatus?.running && serverStatus?.port}
        <Badge variant="neutral" size="xs" mono>:{serverStatus.port}</Badge>
      {/if}

      {#if serverStatus?.running}
        <Button variant="danger" size="xs" icon="square" loading={serverBusy} on:click={handleStopServer}>
          {$t('frida.topbar.stopServer')}
        </Button>
      {:else if serverStatus?.binary_path}
        <Button variant="success" size="xs" icon="play" loading={serverBusy} on:click={handleStartServer}>
          {$t('frida.topbar.startServer')}
        </Button>
      {/if}

      <Button
        variant="secondary"
        size="xs"
        icon="download"
        active={showDeployPanel}
        disabled={!selectedDevice}
        on:click={() => {
          showDeployPanel = !showDeployPanel
          if (showDeployPanel) showRuntimePanel = false
        }}
      >
        {$t('frida.topbar.deployServer')}
      </Button>
    </div>

    <div class="env-spacer"></div>

    <!-- Host Toolchain Readiness Pill -->
    <button
      type="button"
      class="runtime-pill"
      class:active={showRuntimePanel}
      title={$t('frida.topbar.configureRuntime')}
      on:click={() => {
        showRuntimePanel = !showRuntimePanel
        if (showRuntimePanel) showDeployPanel = false
      }}
    >
      <Badge variant={runtimeBadgeVariant} size="xs" dot>
        {#if toolchain?.driver === 'python-bridge'}
          {$t('frida.topbar.bridgeReady')} v{toolchain.frida_version}
        {:else if toolchain?.driver === 'frida-cli'}
          {$t('frida.topbar.cliFallback')}
        {:else}
          {$t('frida.topbar.runtimeMissing')}
        {/if}
      </Badge>
      <Icon name="settings" size={12} />
    </button>
  </section>

  <!-- Optional Collapsible: Deploy frida-server Panel -->
  {#if showDeployPanel}
    <section class="drawer-panel cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('frida.deploy.title')}</div>
          <div class="drawer-sub">{$t('frida.deploy.subtitle')}</div>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (showDeployPanel = false)}>
          {$t('frida.deploy.close')}
        </Button>
      </div>

      <div class="drawer-grid">
        <label class="d-field">
          <span>{$t('frida.deploy.versionLabel')}</span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={deployVersion}
            placeholder={toolchain?.frida_version || $t('frida.deploy.versionPlaceholder')}
          />
        </label>
        <label class="d-field">
          <span>{$t('frida.deploy.archLabel')}</span>
          <select class="cap-input mono" bind:value={deployArch}>
            <option value="">{$t('frida.deploy.archAuto')} {serverStatus?.frida_arch ? `(${serverStatus.frida_arch})` : ''}</option>
            <option value="arm64">arm64</option>
            <option value="arm">arm</option>
            <option value="x86_64">x86_64</option>
            <option value="x86">x86</option>
          </select>
        </label>
        <label class="d-field">
          <span>{$t('frida.deploy.remoteNameLabel')}</span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={deployRemoteName}
            placeholder="frida-server"
            title={$t('frida.deploy.remoteNameHint')}
          />
        </label>
        <label class="d-field narrow">
          <span>{$t('frida.deploy.portLabel')}</span>
          <input type="number" class="cap-input mono" bind:value={deployPort} min="1024" max="65535" />
        </label>
      </div>

      <div class="drawer-row">
        <label class="d-field wide">
          <span>{$t('frida.deploy.localBinLabel')}</span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={deployLocalBin}
            placeholder={$t('frida.deploy.localBinPlaceholder')}
          />
        </label>
      </div>

      <div class="drawer-foot">
        <label class="check-opt">
          <input type="checkbox" bind:checked={deployAutoStart} />
          <span>{$t('frida.deploy.autoStart')}</span>
        </label>
        <label class="check-opt">
          <input type="checkbox" bind:checked={deployForwardPort} />
          <span>{$t('frida.deploy.forwardPort')}</span>
        </label>
        <div class="env-spacer"></div>
        {#if deployProgress}
          <span class="deploy-status mono">
            [{deployProgress.percent}%] {deployProgress.detail}
          </span>
        {/if}
        <Button variant="primary" size="sm" icon="download" loading={deploying} on:click={handleDeployServer}>
          {deploying ? $t('frida.deploy.deploying') : $t('frida.deploy.deployBtn')}
        </Button>
      </div>
    </section>
  {/if}

  <!-- Optional Collapsible: Host Runtime Config Panel -->
  {#if showRuntimePanel}
    <section class="drawer-panel cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('frida.runtimeConfig.title')}</div>
          <div class="drawer-sub">{$t('frida.runtimeConfig.subtitle')}</div>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (showRuntimePanel = false)}>
          {$t('frida.deploy.close')}
        </Button>
      </div>

      <div class="drawer-grid two-col">
        <label class="d-field">
          <span>{$t('frida.runtimeConfig.pythonLabel')}</span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={customPythonPath}
            placeholder={$t('frida.runtimeConfig.pythonPlaceholder')}
          />
        </label>
        <label class="d-field">
          <span>{$t('frida.runtimeConfig.cliLabel')}</span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={customFridaCLIPath}
            placeholder={$t('frida.runtimeConfig.cliPlaceholder')}
          />
        </label>
      </div>

      {#if toolchain?.issues?.length > 0}
        <div class="issues-box">
          {#each toolchain.issues as iss}
            <div class="issue-line">
              <Icon name="alert-triangle" size={12} />
              <span>{iss}</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="drawer-foot">
        <span class="mono hint-muted">
          {$t('frida.runtimeConfig.detectedPython')}: {toolchain?.python_path || '—'} · {$t('frida.runtimeConfig.detectedFrida')}: {toolchain?.frida_version || '—'}
        </span>
        <div class="env-spacer"></div>
        <Button variant="primary" size="sm" icon="check" loading={savingRuntime} on:click={saveRuntimeConfig}>
          {$t('frida.runtimeConfig.saveProbe')}
        </Button>
      </div>
    </section>
  {/if}

  <!-- 2. Target & Session Action Bar -->
  <section class="target-bar">
    <div class="target-picker-wrap">
      <div class="target-input-group">
        <Icon name="target" size={13} />
        <input
          type="text"
          class="cap-input target-input mono"
          bind:value={target}
          disabled={isSessionRunning}
          placeholder={$t('frida.targetBar.targetPlaceholder')}
          on:keydown={(e) => {
            if (e.key === 'Enter' && !isSessionRunning) startSession()
          }}
        />
        <Button
          variant="secondary"
          size="xs"
          icon="list"
          loading={loadingProcs}
          disabled={!selectedDevice}
          on:click={() => {
            if (showProcPicker) showProcPicker = false
            else loadProcesses()
          }}
        >
          {loadingProcs ? $t('frida.targetBar.loadingProcesses') : $t('frida.targetBar.pickProcess')}
        </Button>
      </div>

      {#if showProcPicker}
        <div class="proc-dropdown">
          <div class="proc-head">
            <Icon name="search" size={12} />
            <input
              type="text"
              class="proc-search"
              bind:value={procFilter}
              placeholder={$t('frida.targetBar.processSearch')}
            />
            <button type="button" class="mini-icon-btn" on:click={() => (showProcPicker = false)}>
              <Icon name="x" size={12} />
            </button>
          </div>
          <div class="proc-list">
            {#each filteredProcs.slice(0, 120) as p (p.pid + ':' + p.identifier + ':' + p.name)}
              <button type="button" class="proc-item" on:click={() => pickProcess(p)}>
                <span class="proc-dot" class:running={p.running}></span>
                <span class="proc-ident mono truncate">{p.identifier || p.name}</span>
                {#if p.name && p.identifier && p.name !== p.identifier}
                  <span class="proc-name truncate">{p.name}</span>
                {/if}
                <span class="proc-pid mono tabular-nums">{p.pid > 0 ? `#${p.pid}` : '—'}</span>
              </button>
            {/each}
          </div>
        </div>
      {/if}
    </div>

    <!-- Mode Segmented Toggle -->
    <div class="seg-toggle" role="group">
      <button
        type="button"
        class="seg-btn"
        class:active={mode === 'spawn'}
        disabled={isSessionRunning}
        on:click={() => (mode = 'spawn')}
      >
        {$t('frida.targetBar.modeSpawn')}
      </button>
      <button
        type="button"
        class="seg-btn"
        class:active={mode === 'attach'}
        disabled={isSessionRunning}
        on:click={() => (mode = 'attach')}
      >
        {$t('frida.targetBar.modeAttach')}
      </button>
    </div>

    {#if mode === 'spawn' && !isSessionRunning}
      <label class="check-opt compact">
        <input type="checkbox" bind:checked={noPause} />
        <span>{$t('frida.targetBar.noPause')}</span>
      </label>
    {/if}

    <!-- Primary Session Buttons -->
    <div class="session-actions">
      {#if !isSessionRunning}
        <Button
          variant="primary"
          size="sm"
          icon="zap"
          loading={sessionStarting}
          disabled={!target.trim() || !scriptCode.trim()}
          on:click={startSession}
        >
          {sessionStarting ? $t('frida.targetBar.starting') : $t('frida.targetBar.runHook')}
        </Button>
      {:else}
        {#if canHotReload}
          <Button
            variant="secondary"
            size="sm"
            icon="refresh"
            loading={reloadingScript}
            on:click={hotReloadScript}
          >
            {reloadingScript ? $t('frida.targetBar.reloading') : $t('frida.targetBar.hotReload')}
          </Button>
        {/if}
        {#if session?.paused}
          <Button variant="success" size="sm" icon="play" on:click={resumeSpawnedProcess}>
            {$t('frida.targetBar.resume')}
          </Button>
        {/if}
        <Button variant="danger" size="sm" icon="square" on:click={stopSession}>
          {$t('frida.targetBar.stopDetach')}
        </Button>
      {/if}
    </div>

    <div class="env-spacer"></div>

    <!-- Live Session Telemetry -->
    {#if session && session.status !== 'idle'}
      <div class="session-telemetry mono tabular-nums">
        <Badge
          variant={isSessionRunning ? 'success' : session.status === 'error' ? 'danger' : 'neutral'}
          size="xs"
          dot
          pulse={isSessionRunning}
        >
          {session.status.toUpperCase()}{session.pid ? ` · PID ${session.pid}` : ''}
        </Badge>
        <span class="tele-item">{formatClock(liveElapsedMs)}</span>
        <span class="tele-item accent">{$t('frida.targetBar.hooksCount', { count: session.hook_count || 0 })}</span>
        {#if session.reload_count > 0}
          <span class="tele-item">{$t('frida.targetBar.reloadsCount', { count: session.reload_count })}</span>
        {/if}
        {#if session.error_count > 0}
          <span class="tele-item danger">{$t('frida.targetBar.errorsCount', { count: session.error_count })}</span>
        {/if}
      </div>
    {/if}
  </section>

  <!-- 3. Main Split Workspace: Left Library/CodeShare/Trace | Right Editor + Console -->
  <div class="frida-body">
    <SplitPane direction="horizontal" initialSize={27} minPrimary={20} minSecondary={52} storageKey="cap.frida.hsplit">
      <!-- LEFT PANE -->
      <div slot="primary" class="left-pane">
        <div class="left-tabs" role="tablist">
          <button
            type="button"
            class="ltab"
            class:active={leftTab === 'scripts'}
            on:click={() => (leftTab = 'scripts')}
          >
            <Icon name="file-code" size={13} />
            <span>{$t('frida.leftTabs.scripts')}</span>
            <span class="ltab-cnt mono">{scripts.length}</span>
          </button>
          <button
            type="button"
            class="ltab"
            class:active={leftTab === 'codeshare'}
            on:click={() => (leftTab = 'codeshare')}
          >
            <Icon name="globe" size={13} />
            <span>{$t('frida.leftTabs.codeshare')}</span>
          </button>
          <button
            type="button"
            class="ltab"
            class:active={leftTab === 'trace'}
            on:click={() => {
              leftTab = 'trace'
              restoreSessionAndTrace()
            }}
          >
            <Icon name="git-branch" size={13} />
            <span>{$t('frida.leftTabs.trace')}</span>
          </button>
        </div>

        <!-- Tab 1: Script Library -->
        {#if leftTab === 'scripts'}
          <div class="left-toolbar">
            <div class="search-box">
              <Icon name="search" size={12} />
              <input
                type="text"
                class="search-input"
                bind:value={scriptSearch}
                placeholder={$t('frida.scripts.searchPlaceholder')}
              />
            </div>
            <Button variant="secondary" size="xs" icon="plus" on:click={createNewScript}>
              {$t('frida.scripts.newScript')}
            </Button>
            <Button
              variant="ghost"
              size="xs"
              icon="refresh"
              iconOnly
              title={$t('frida.scripts.openDirTitle', { dir: scriptDir })}
              on:click={reloadScriptsFromDisk}
            />
          </div>

          <div class="cat-pills">
            {#each CATEGORIES as cat}
              <button
                type="button"
                class="cat-pill"
                class:active={scriptCategoryFilter === cat}
                on:click={() => (scriptCategoryFilter = cat)}
              >
                {cat === 'all' ? $t('frida.scripts.allCategories') : $t(`frida.scripts.categories.${cat}`)}
              </button>
            {/each}
          </div>

          <div class="left-scroll">
            {#if filteredScripts.length === 0}
              <EmptyState
                icon="file-code"
                title={$t('frida.scripts.emptyTitle')}
                description={$t('frida.scripts.emptyDesc')}
                compact
              />
            {:else}
              {#each filteredScripts as sc (sc.id)}
                <button
                  type="button"
                  class="script-card"
                  class:active={scriptId === sc.id}
                  on:click={() => selectScript(sc)}
                >
                  <div class="sc-top">
                    <Badge variant={categoryVariant(sc.category)} size="xs">
                      {$t(`frida.scripts.categories.${sc.category}`)}
                    </Badge>
                    <span class="sc-origin">
                      {sc.builtin ? $t('frida.scripts.builtin') : $t('frida.scripts.custom')}
                    </span>
                    {#if !sc.builtin}
                      <span
                        class="sc-del"
                        role="button"
                        tabindex="0"
                        title={$t('common.actions.delete')}
                        on:click={(ev) => deleteCustomScript(sc, ev)}
                        on:keydown={(ev) => { if (ev.key === 'Enter') deleteCustomScript(sc, ev) }}
                      >
                        <Icon name="trash" size={11} />
                      </span>
                    {/if}
                  </div>
                  <div class="sc-name truncate">{sc.name}</div>
                  {#if sc.description}
                    <div class="sc-desc">{sc.description}</div>
                  {/if}
                </button>
              {/each}
            {/if}
          </div>

        <!-- Tab 2: CodeShare Explorer & App Fingerprint -->
        {:else if leftTab === 'codeshare'}
          <div class="cs-controls">
            <div class="cs-search-row">
              <input
                type="text"
                class="cap-input cs-input"
                bind:value={codeshareQuery}
                placeholder={$t('frida.codeshare.searchPlaceholder')}
                on:keydown={(e) => { if (e.key === 'Enter') searchCodeShare(false) }}
              />
              <Button variant="primary" size="xs" icon="search" loading={codeshareLoading} on:click={() => searchCodeShare(false)}>
                {$t('frida.codeshare.searchBtn')}
              </Button>
            </div>
            <div class="cs-action-row">
              <Button variant="secondary" size="xs" icon="flame" loading={codeshareLoading} on:click={() => searchCodeShare(true)}>
                {$t('frida.codeshare.browsePopular')}
              </Button>
              <Button
                variant="secondary"
                size="xs"
                icon="radar"
                loading={fingerprintLoading}
                disabled={!selectedDevice || !target.trim()}
                on:click={runAppFingerprint}
              >
                {fingerprintLoading ? $t('frida.codeshare.fingerprinting') : $t('frida.codeshare.fingerprintBtn')}
              </Button>
            </div>

            {#if fingerprintResult}
              <div class="fp-card">
                <div class="fp-pkg mono truncate">{fingerprintResult.package}</div>
                <div class="fp-chips">
                  {#each fingerprintResult.frameworks || [] as fw}
                    <Badge variant="info" size="xs" mono>{fw}</Badge>
                  {/each}
                  {#each fingerprintResult.pinning || [] as pin}
                    <Badge variant="warning" size="xs" mono>{pin}</Badge>
                  {/each}
                  {#each fingerprintResult.security || [] as sec}
                    <Badge variant="danger" size="xs" mono>{sec}</Badge>
                  {/each}
                </div>
              </div>
            {/if}
          </div>

          <div class="left-scroll">
            {#if codeshareResults.length === 0}
              <EmptyState
                icon="globe"
                title={$t('frida.codeshare.emptyTitle')}
                description={$t('frida.codeshare.emptyDesc')}
                compact
              />
            {:else}
              {#each codeshareResults as entry (entry.slug)}
                <div class="cs-card">
                  <div class="cs-title truncate">{entry.title}</div>
                  <div class="cs-meta mono">
                    <span>{entry.author || entry.slug}</span>
                    {#if entry.likes}<span>♥ {entry.likes}</span>{/if}
                    {#if entry.views}<span>👁 {entry.views}</span>{/if}
                  </div>
                  {#if entry.description}
                    <div class="sc-desc">{entry.description}</div>
                  {/if}
                  <div class="cs-btns">
                    <Button variant="secondary" size="xs" icon="code" on:click={() => fetchCodeShareEntry(entry, false)}>
                      {$t('frida.codeshare.loadToEditor')}
                    </Button>
                    <Button variant="ghost" size="xs" icon="save" on:click={() => fetchCodeShareEntry(entry, true)}>
                      {$t('frida.codeshare.saveLocal')}
                    </Button>
                  </div>
                </div>
              {/each}
            {/if}
          </div>

        <!-- Tab 3: From DeepTrace -->
        {:else if leftTab === 'trace'}
          <div class="left-scroll trace-panel">
            {#if traceState?.result}
              <div class="trace-head-box">
                <div class="trace-title">{$t('frida.fromTrace.title')}</div>
                <div class="trace-sub">{$t('frida.fromTrace.subtitle')}</div>
                <div class="trace-meta mono">
                  <div><span>{$t('frida.fromTrace.sourcePkg')}:</span> {traceState.result.package || traceState.package}</div>
                  <div><span>{$t('frida.fromTrace.sourceFlow')}:</span> {traceState.result.method} {traceState.result.url}</div>
                </div>
              </div>

              <div class="trace-opts">
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_java} /><span>{$t('frida.fromTrace.includeJava')} ({traceState.result.java_trace?.length || 0})</span></label>
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_dex_xrefs} /><span>{$t('frida.fromTrace.includeDex')} ({traceState.result.dex_xrefs?.length || 0})</span></label>
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_native} /><span>{$t('frida.fromTrace.includeNative')} ({traceState.result.native_trace?.length || 0})</span></label>
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_crypto} /><span>{$t('frida.fromTrace.includeCrypto')}</span></label>
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_ssl_unpin} /><span>{$t('frida.fromTrace.includeUnpin')}</span></label>
                <label class="check-opt"><input type="checkbox" bind:checked={traceGenOpts.include_backtrace} /><span>{$t('frida.fromTrace.includeBacktrace')}</span></label>
              </div>

              <Button variant="primary" size="sm" icon="zap" fullWidth loading={generatingHook} on:click={generateFromTrace}>
                {$t('frida.fromTrace.generateBtn')}
              </Button>

              {#if lastGeneratedHook}
                <div class="gen-summary">
                  <Badge variant="success" size="xs" dot>{$t('frida.fromTrace.lastGenerated', { summary: lastGeneratedHook.summary })}</Badge>
                </div>
              {/if}
            {:else}
              <EmptyState
                icon="git-branch"
                title={$t('frida.fromTrace.noTraceTitle')}
                description={$t('frida.fromTrace.noTraceDesc')}
                compact
              >
                <Button variant="secondary" size="xs" icon="arrow-right" on:click={() => navigate('trace')}>
                  {$t('frida.fromTrace.openDeepTrace')}
                </Button>
              </EmptyState>
            {/if}
          </div>
        {/if}
      </div>

      <!-- RIGHT PANE: Editor (Top) + Live Structured Console (Bottom) -->
      <div slot="secondary" class="right-pane">
        <SplitPane direction="vertical" initialSize={56} minPrimary={25} minSecondary={24} storageKey="cap.frida.vsplit">
          <!-- TOP: JS Script Editor -->
          <div slot="primary" class="editor-pane">
            <div class="editor-header">
              <input
                type="text"
                class="cap-input ed-name"
                bind:value={scriptName}
                placeholder={$t('frida.editor.namePlaceholder')}
                on:input={() => (dirty = true)}
              />
              <select class="cap-input ed-cat" bind:value={scriptCategory} on:change={() => (dirty = true)}>
                {#each EDIT_CATEGORIES as cat}
                  <option value={cat}>{$t(`frida.scripts.categories.${cat}`)}</option>
                {/each}
              </select>
              {#if dirty}
                <Badge variant="warning" size="xs">●</Badge>
              {/if}
              <div class="env-spacer"></div>
              <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(scriptCode, translate('frida.toast.copiedJs'))}>
                {$t('frida.editor.copyJs')}
              </Button>
              <Button variant="secondary" size="xs" icon="save" loading={savingScript} on:click={saveCurrentScript}>
                {scriptBuiltin ? $t('frida.editor.forkSave') : $t('frida.editor.save')}
              </Button>
            </div>

            <div class="snippet-strip">
              <span class="snip-label">{$t('frida.editor.snippetsLabel')}</span>
              {#each SNIPPETS as sn}
                <button type="button" class="snip-chip mono" on:click={() => insertSnippet(sn)}>
                  + {$t(`frida.editor.snippets.${sn.key}`)}
                </button>
              {/each}
            </div>

            <div class="editor-host">
              <CodeEditor
                bind:this={editorRef}
                bind:value={scriptCode}
                runtime="node"
                minHeight="140px"
                placeholder={$t('frida.editor.placeholder')}
                shortcutHint={$t('frida.editor.shortcutHint', { mod: MOD_LABEL })}
                on:input={() => (dirty = true)}
                on:save={saveCurrentScript}
                on:run={() => (isSessionRunning && canHotReload ? hotReloadScript() : startSession())}
              />
            </div>
          </div>

          <!-- BOTTOM: Live Hook & Structured Event Console -->
          <div slot="secondary" class="console-pane">
            <div class="console-bar">
              <div class="c-tabs">
                <button type="button" class="c-tab" class:active={consoleFilter === 'all'} on:click={() => (consoleFilter = 'all')}>
                  {$t('frida.console.filterAll')} <span class="mono">{eventCounts.all}</span>
                </button>
                <button type="button" class="c-tab" class:active={consoleFilter === 'hook'} on:click={() => (consoleFilter = 'hook')}>
                  {$t('frida.console.filterHook')} <span class="mono">{eventCounts.hook}</span>
                </button>
                <button type="button" class="c-tab" class:active={consoleFilter === 'console'} on:click={() => (consoleFilter = 'console')}>
                  {$t('frida.console.filterConsole')} <span class="mono">{eventCounts.console}</span>
                </button>
                <button type="button" class="c-tab" class:active={consoleFilter === 'error'} on:click={() => (consoleFilter = 'error')}>
                  {$t('frida.console.filterError')} <span class="mono">{eventCounts.error}</span>
                </button>
                <button type="button" class="c-tab" class:active={consoleFilter === 'system'} on:click={() => (consoleFilter = 'system')}>
                  {$t('frida.console.filterSystem')} <span class="mono">{eventCounts.system}</span>
                </button>
              </div>

              <div class="c-tools">
                <div class="search-box small">
                  <Icon name="search" size={11} />
                  <input
                    type="text"
                    class="search-input"
                    bind:value={consoleSearch}
                    placeholder={$t('frida.console.searchPlaceholder')}
                  />
                </div>
                <label class="check-opt compact">
                  <input type="checkbox" bind:checked={autoScroll} />
                  <span>{$t('frida.console.autoScroll')}</span>
                </label>
                <Button variant="ghost" size="xs" icon="download" disabled={filteredEvents.length === 0} on:click={exportConsoleJsonl}>
                  {$t('frida.console.exportJsonl')}
                </Button>
                <Button variant="ghost" size="xs" icon="copy" disabled={filteredEvents.length === 0} on:click={copyConsole}>
                  {$t('frida.console.copyAll')}
                </Button>
                <Button variant="ghost" size="xs" icon="trash" disabled={events.length === 0} on:click={clearConsole}>
                  {$t('frida.console.clear')}
                </Button>
              </div>
            </div>

            <div class="console-stream" bind:this={consoleEl}>
              {#if filteredEvents.length === 0}
                <EmptyState
                  icon="zap"
                  title={$t('frida.console.emptyTitle')}
                  description={$t('frida.console.emptyDesc')}
                  compact
                />
              {:else}
                {#each filteredEvents as ev (ev.seq)}
                  {@const hasDetails = Boolean(ev.payload || ev.data_hex)}
                  {@const isExpanded = expandedEvents.has(ev.seq)}
                  <div class="ev-row lvl-{ev.level}">
                    <button
                      type="button"
                      class="ev-head"
                      class:clickable={hasDetails}
                      on:click={() => hasDetails && toggleEventExpand(ev.seq)}
                    >
                      <span class="ev-time mono tabular-nums">{formatEventTime(ev.timestamp_ms)}</span>
                      <Badge variant={ev.level === 'error' ? 'danger' : categoryVariant(ev.category)} size="xs" mono>
                        {ev.category || ev.level}
                      </Badge>
                      <span class="ev-msg mono">{ev.message}</span>
                      {#if hasDetails}
                        <span class="ev-chevron">
                          <Icon name={isExpanded ? 'chevron-down' : 'chevron-right'} size={12} />
                        </span>
                      {/if}
                    </button>

                    {#if hasDetails && isExpanded}
                      <div class="ev-detail mono">
                        {#each payloadEntries(ev.payload) as [k, v]}
                          <div class="kv-row">
                            <span class="kv-k">{k}</span>
                            <pre class="kv-v">{formatPayloadValue(v)}</pre>
                          </div>
                        {/each}
                        {#if ev.data_hex}
                          <div class="kv-row">
                            <span class="kv-k">{$t('frida.console.binaryData')}</span>
                            <pre class="kv-v">{ev.data_hex}</pre>
                          </div>
                        {/if}
                        {#if ev.payload?.stack}
                          <div class="kv-row">
                            <span class="kv-k">{$t('frida.console.stackTrace')}</span>
                            <pre class="kv-v stack">{ev.payload.stack}</pre>
                          </div>
                        {/if}
                      </div>
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

<style>
  .frida-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
    overflow: hidden;
  }

  /* ==================== Top Environment & Server Strip ==================== */
  .env-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 14px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .env-group {
    display: flex;
    align-items: center;
    gap: 7px;
  }

  .strip-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .v-sep {
    width: 1px;
    height: 18px;
    background: var(--border-default);
  }

  .env-spacer {
    flex: 1;
  }

  .device-select {
    height: 26px;
    min-width: 170px;
    max-width: 240px;
    font-size: var(--text-xs);
  }

  .runtime-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .runtime-pill:hover,
  .runtime-pill.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--text-primary);
  }

  /* ==================== Collapsible Drawer Panels ==================== */
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
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }

  .drawer-grid.two-col {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .drawer-row {
    display: flex;
    gap: 10px;
  }

  .d-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .d-field.wide {
    flex: 1;
  }

  .drawer-foot {
    display: flex;
    align-items: center;
    gap: 14px;
    padding-top: 6px;
    border-top: 1px solid var(--border-subtle);
  }

  .deploy-status {
    font-size: var(--text-xs);
    color: var(--accent);
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

  .hint-muted {
    font-size: 11px;
    color: var(--text-muted);
  }

  /* ==================== Target & Session Bar ==================== */
  .target-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 14px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .target-picker-wrap {
    position: relative;
  }

  .target-input-group {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text-muted);
  }

  .target-input {
    width: 250px;
    height: 28px;
    font-size: var(--text-xs);
  }

  .proc-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    width: 390px;
    max-height: 320px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    z-index: 40;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .proc-head {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-muted);
  }

  .proc-search {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    outline: none;
  }

  .proc-list {
    overflow-y: auto;
    max-height: 270px;
  }

  .proc-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 10px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    text-align: left;
    cursor: pointer;
  }

  .proc-item:hover {
    background: var(--bg-hover);
  }

  .proc-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--border-strong);
    flex-shrink: 0;
  }

  .proc-dot.running {
    background: var(--status-success);
  }

  .proc-ident {
    flex: 1;
    font-size: 11px;
  }

  .proc-name {
    max-width: 110px;
    color: var(--text-muted);
    font-size: 11px;
  }

  .proc-pid {
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
    border-radius: calc(var(--radius-sm) - 2px);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
  }

  .seg-btn.active {
    background: var(--bg-elevated);
    color: var(--text-primary);
    box-shadow: var(--shadow-xs);
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
    gap: 4px;
    font-size: 11px;
  }

  .session-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .session-telemetry {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .tele-item.accent {
    color: var(--accent);
    font-weight: 600;
  }

  .tele-item.danger {
    color: var(--status-danger);
    font-weight: 600;
  }

  /* ==================== Main Split Body ==================== */
  .frida-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  .left-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--bg-surface);
  }

  .left-tabs {
    display: flex;
    border-bottom: 1px solid var(--border-default);
    background: var(--bg-panel);
    flex-shrink: 0;
  }

  .ltab {
    flex: 1;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    height: 34px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
  }

  .ltab:hover {
    color: var(--text-primary);
  }

  .ltab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    background: var(--bg-surface);
  }

  .ltab-cnt {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: 99px;
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .left-toolbar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px;
    border-bottom: 1px solid var(--border-subtle);
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
  }

  .search-box.small {
    flex: 0 0 150px;
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
    padding: 0 7px;
    border-radius: 99px;
    border: 1px solid var(--border-default);
    background: transparent;
    color: var(--text-muted);
    font-size: 10px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
  }

  .cat-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .left-scroll {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .script-card,
  .cs-card {
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

  .script-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .script-card.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .sc-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .sc-origin {
    font-size: 10px;
    color: var(--text-muted);
    margin-left: auto;
  }

  .sc-del {
    display: inline-flex;
    align-items: center;
    padding: 2px;
    border-radius: var(--radius-xs);
    color: var(--text-muted);
  }

  .sc-del:hover {
    color: var(--status-danger);
    background: var(--status-danger-bg);
  }

  .sc-name,
  .cs-title {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .sc-desc {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.4;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }

  /* CodeShare */
  .cs-controls {
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .cs-search-row,
  .cs-action-row {
    display: flex;
    gap: 6px;
  }

  .cs-input {
    flex: 1;
    height: 26px;
    font-size: var(--text-xs);
  }

  .cs-card {
    cursor: default;
  }

  .cs-meta {
    display: flex;
    gap: 10px;
    font-size: 10px;
    color: var(--text-muted);
  }

  .cs-btns {
    display: flex;
    gap: 6px;
    margin-top: 4px;
  }

  .fp-card {
    padding: 7px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .fp-pkg {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .fp-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  /* From DeepTrace */
  .trace-panel {
    gap: 10px;
  }

  .trace-head-box {
    padding: 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }

  .trace-title {
    font-size: var(--text-xs);
    font-weight: 700;
    color: var(--text-primary);
  }

  .trace-sub {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 3px;
    line-height: 1.4;
  }

  .trace-meta {
    margin-top: 8px;
    padding-top: 6px;
    border-top: 1px solid var(--border-subtle);
    font-size: 11px;
    color: var(--text-secondary);
    display: flex;
    flex-direction: column;
    gap: 2px;
    word-break: break-all;
  }

  .trace-meta span {
    color: var(--text-muted);
  }

  .trace-opts {
    display: flex;
    flex-direction: column;
    gap: 7px;
    padding: 6px 4px;
  }

  .gen-summary {
    display: flex;
    flex-wrap: wrap;
  }

  /* ==================== Right Pane: Editor + Console ==================== */
  .right-pane {
    height: 100%;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .editor-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  .editor-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .ed-name {
    width: 240px;
    height: 26px;
    font-size: var(--text-xs);
    font-weight: 600;
  }

  .ed-cat {
    height: 26px;
    font-size: var(--text-xs);
  }

  .snippet-strip {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 5px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    overflow-x: auto;
    flex-shrink: 0;
  }

  .snip-label {
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .snip-chip {
    height: 20px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
    cursor: pointer;
  }

  .snip-chip:hover {
    border-color: var(--accent-border);
    color: var(--accent);
    background: var(--accent-soft);
  }

  .editor-host {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ==================== Live Console ==================== */
  .console-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-surface);
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

  .c-tabs {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .c-tab {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    padding: 0 8px;
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

  .c-tools {
    display: flex;
    align-items: center;
    gap: 6px;
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

  .ev-row.lvl-hook,
  .ev-row.lvl-send {
    border-left-color: var(--accent);
  }

  .ev-row.lvl-error {
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
    line-height: 1.4;
  }

  .ev-chevron {
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .ev-detail {
    padding: 6px 10px 8px 24px;
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
  }

  .kv-row {
    display: grid;
    grid-template-columns: 110px minmax(0, 1fr);
    gap: 8px;
    align-items: start;
  }

  .kv-k {
    color: var(--text-muted);
    font-weight: 600;
    word-break: break-word;
  }

  .kv-v {
    margin: 0;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.4;
  }

  .kv-v.stack {
    color: var(--text-secondary);
    font-size: 10.5px;
  }

  .mini-icon-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px;
    display: inline-flex;
  }

  .mini-icon-btn:hover {
    color: var(--text-primary);
  }
</style>
