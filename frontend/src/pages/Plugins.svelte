<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate } from '../lib/i18n.js'
  import { MOD_LABEL } from '../lib/shortcuts.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import CodeEditor from '../components/CodeEditor.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration, formatTime } from '../lib/format.js'
  import { openAIHealModal } from '../lib/aiState.js'

  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  const httpMethods = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE']
  const runtimeOptions = ['builtin', 'python3', 'node', 'sh']

  let pluginDir = '~/.cap/plugins'
  let reloading = false
  let plugins = []
  let examples = []
  let recentFlows = []
  let selectedPlugin = null

  // Editor fields (including extended runtime & auto-run fields)
  let editName = ''
  let editDesc = ''
  let editType = 'analyzer'
  let editRuntime = 'builtin'
  let editAutoRun = false
  let editMethod = ''
  let editHostPattern = ''
  let editPathPattern = ''
  let editTimeoutSec = 10
  let editCode = ''
  let editEnabled = true
  let isNew = false
  let dirty = false

  let searchQuery = ''
  let typeFilter = 'all'
  let confirmDelete = false
  let saving = false
  let running = false

  // Bottom drawer state: Test Runner + Live Execution Log
  let drawerTab = 'runner' // 'runner' | 'logs'
  let runOutput = ''
  let runError = false
  let runDurationMs = null
  let runFlowId = ''
  let flowFilterQuery = ''
  let editorRef = null

  // Flow Variables & stdin JSON Inspector
  let inspectorMode = 'vars' // 'vars' | 'json' | 'off'
  let flowPayloadRaw = ''
  let flowPayloadObj = null
  let loadingPayload = false
  let payloadFetchSeq = 0

  let execLogs = []
  let logsOnlyCurrent = false
  let expandedLogIds = new Set()
  let unsubs = []
  let flowMatchState = null // null | true | false
  let matchCheckSeq = 0
  let matchCheckTimer = null

  const coreFlowFields = [
    'id',
    'method',
    'url',
    'scheme',
    'host',
    'path',
    'query',
    'status',
    'latency_ms',
    'req_headers',
    'resp_headers',
    'req_body',
    'resp_body',
    'sign_params',
  ]

  const pluginTypeStyles = {
    analyzer: { variant: 'accent', icon: 'radar' },
    request_filter: { variant: 'info', icon: 'filter' },
    response_modifier: { variant: 'purple', icon: 'edit' },
  }

  function normalizeRuntime(rt) {
    return runtimeOptions.includes(rt) ? rt : 'builtin'
  }

  function getTypeMeta(type, tr = translate) {
    const style = pluginTypeStyles[type] || { variant: 'neutral', icon: 'puzzle' }
    const labelKey = pluginTypeStyles[type] ? `tools.plugins.types.${type}` : 'tools.plugins.types.fallback'
    return { ...style, label: tr(labelKey) }
  }

  function runtimeLabel(rt, tr = translate) {
    const norm = normalizeRuntime(rt)
    return tr(`tools.plugins.runtimes.${norm}`)
  }

  function runtimeBadgeVariant(rt) {
    switch (normalizeRuntime(rt)) {
      case 'python3':
        return 'info'
      case 'node':
        return 'success'
      case 'sh':
        return 'warning'
      default:
        return 'neutral'
    }
  }

  function starterCodeFor(type, rt) {
    const norm = normalizeRuntime(rt)
    if (norm === 'python3') {
      return `import json, sys\n\nflow = json.load(sys.stdin)\nprint(f"[{flow.get('id')}] {flow.get('method')} {flow.get('url')} -> {flow.get('status')}")\n`
    }
    if (norm === 'node') {
      return `const fs = require('fs');\nconst flow = JSON.parse(fs.readFileSync(0, 'utf8'));\nconsole.log(\`[\${flow.id}] \${flow.method} \${flow.url} -> \${flow.status}\`);\n`
    }
    if (norm === 'sh') {
      return `# Reads flow JSON from stdin\ncat | head -c 500\necho ""\n`
    }
    if (type === 'request_filter') {
      return `// Request filter plugin\n// Inspects outgoing HTTP requests\n\nfunction onRequest(flow) {\n  return {\n    flow_id: flow.id,\n    method: flow.method,\n    url: flow.url,\n  };\n}\n`
    }
    if (type === 'response_modifier') {
      return `// Response hook plugin\n// Inspects or annotates HTTP responses\n\nfunction onResponse(flow) {\n  return {\n    flow_id: flow.id,\n    status: flow.status,\n    latency_ms: flow.latency_ms,\n  };\n}\n`
    }
    return `// Analyzer plugin\n// Runs security & signature analysis on captured flows\n\nfunction analyze(flow) {\n  return {\n    flow_id: flow.id,\n    method: flow.method,\n    url: flow.url,\n    result: "your analysis here"\n  };\n}\n`
  }

  function formatUpdated(ts) {
    if (!ts) return ''
    const d = new Date(ts)
    if (Number.isNaN(d.getTime())) return ''
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  }

  async function loadPluginDir() {
    const app = api()
    if (!app?.GetPluginDir) return
    try {
      const dir = await app.GetPluginDir()
      if (dir) pluginDir = dir
    } catch (_) {}
  }

  async function loadPlugins(notify = false) {
    const app = api()
    if (!app?.ListPlugins) return
    try {
      plugins = (await app.ListPlugins()) || []
      syncSelectedAfterRefresh()
      if (notify) toast.info(translate('tools.plugins.toast.reloaded', { count: plugins.length }))
    } catch (e) {
      if (notify) toast.error(translate('tools.plugins.toast.loadFailed', { error: e?.message || e }))
    }
  }

  async function reloadPluginsFromDisk(notify = true) {
    const app = api()
    if (!app) return
    reloading = true
    try {
      if (app.ReloadPlugins) {
        plugins = (await app.ReloadPlugins()) || []
      } else if (app.ListPlugins) {
        plugins = (await app.ListPlugins()) || []
      }
      syncSelectedAfterRefresh()
      if (notify) toast.info(translate('tools.plugins.toast.reloaded', { count: plugins.length }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.loadFailed', { error: e?.message || e }))
    } finally {
      reloading = false
    }
  }

  function syncSelectedAfterRefresh() {
    if (!selectedPlugin) return
    const refreshed = plugins.find((p) => p.name === selectedPlugin.name)
    if (refreshed) {
      selectedPlugin = refreshed
      editEnabled = Boolean(refreshed.enabled)
      if (!dirty) {
        editDesc = refreshed.description || ''
        editType = refreshed.type || 'analyzer'
        editRuntime = normalizeRuntime(refreshed.runtime)
        editAutoRun = Boolean(refreshed.auto_run)
        editMethod = refreshed.method || ''
        editHostPattern = refreshed.host_pattern || ''
        editPathPattern = refreshed.path_pattern || ''
        editTimeoutSec = Number(refreshed.timeout_sec) || 10
        editCode = refreshed.code || ''
      }
    }
  }

  async function loadExamples() {
    const app = api()
    if (!app?.GetExamplePlugins) return
    try {
      examples = (await app.GetExamplePlugins()) || []
    } catch (_) {
      examples = []
    }
  }

  async function loadRecentFlows() {
    const app = api()
    if (!app?.GetFlows) return
    try {
      recentFlows = (await app.GetFlows('', '', '', 50)) || []
      if (!runFlowId && recentFlows.length > 0) {
        runFlowId = recentFlows[0].id
      }
    } catch (_) {}
  }

  async function loadLogs() {
    const app = api()
    if (!app?.GetPluginLogs) return
    try {
      const list = await app.GetPluginLogs(100)
      execLogs = Array.isArray(list) ? list : []
      if (execLogs.length > 0 && expandedLogIds.size === 0) {
        expandedLogIds = new Set([execLogs[0].id])
      }
    } catch (_) {}
  }

  async function clearLogs() {
    const app = api()
    if (!app?.ClearPluginLogs) return
    try {
      await app.ClearPluginLogs()
      execLogs = []
      expandedLogIds = new Set()
      toast.info(translate('tools.plugins.toast.logsCleared'))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.logsClearFailed', { error: e?.message || e }))
    }
  }

  function handlePluginExecuted(rec) {
    if (!rec) return
    const id = rec.id || `local-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const normalized = { ...rec, id }
    const deduped = execLogs.filter((item) => item.id !== id)
    execLogs = [normalized, ...deduped].slice(0, 200)
    const nextExpanded = new Set(expandedLogIds)
    nextExpanded.add(id)
    expandedLogIds = nextExpanded
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }

  function matchSinglePattern(pattern, target, isPath = false) {
    const p = String(pattern || '').trim()
    if (!p) return true
    const val = String(target || '')
    if (p.length >= 2 && p.startsWith('/') && p.endsWith('/')) {
      try {
        return new RegExp(p.slice(1, -1), 'i').test(val)
      } catch (_) {
        return false
      }
    }
    if (p.includes('*')) {
      const escaped = p.split('*').map(escapeRegex).join('.*')
      const prefix = isPath && !p.startsWith('/') && !p.startsWith('*') ? '^/?' : '^'
      try {
        return new RegExp(`${prefix}${escaped}$`, 'i').test(val)
      } catch (_) {
        return false
      }
    }
    return val.toLowerCase().includes(p.toLowerCase())
  }

  function matchesFlowLocal(flow) {
    if (!flow) return null
    const m = editMethod.trim().toUpperCase()
    if (m && m !== 'ANY' && String(flow.method || '').toUpperCase() !== m) {
      return false
    }
    let parsedUrl = null
    try {
      if (flow.url) parsedUrl = new URL(flow.url)
    } catch (_) {}

    if (editHostPattern.trim()) {
      const rawHost = flow.host || parsedUrl?.host || ''
      const hostNoPort = parsedUrl?.hostname || rawHost.replace(/:\d+$/, '')
      if (
        !matchSinglePattern(editHostPattern, rawHost, false) &&
        !matchSinglePattern(editHostPattern, hostNoPort, false)
      ) {
        return false
      }
    }

    if (editPathPattern.trim()) {
      const pathOnly = parsedUrl?.pathname || flow.path || ''
      const pathWithQuery = parsedUrl
        ? `${parsedUrl.pathname}${parsedUrl.search || ''}`
        : flow.path || ''
      if (
        !matchSinglePattern(editPathPattern, pathOnly, true) &&
        !matchSinglePattern(editPathPattern, pathWithQuery, true)
      ) {
        return false
      }
    }
    return true
  }

  function scheduleMatchCheck(flowId, method, hostPat, pathPat, flowsList) {
    if (matchCheckTimer) clearTimeout(matchCheckTimer)
    const fid = String(flowId || '').trim()
    if (!fid) {
      flowMatchState = null
      return
    }
    const localFlow = flowsList.find((f) => f.id === fid) || null
    if (localFlow) {
      flowMatchState = matchesFlowLocal(localFlow)
    }
    const app = api()
    if (!app?.TestPluginMatch) {
      if (!localFlow) flowMatchState = null
      return
    }
    const seq = ++matchCheckSeq
    matchCheckTimer = setTimeout(async () => {
      try {
        const matched = await app.TestPluginMatch(
          {
            name: editName.trim() || 'preview',
            description: editDesc.trim(),
            type: editType,
            runtime: normalizeRuntime(editRuntime),
            auto_run: Boolean(editAutoRun),
            host_pattern: String(hostPat || '').trim(),
            path_pattern: String(pathPat || '').trim(),
            method: String(method || '').trim().toUpperCase(),
            timeout_sec: Math.max(1, Math.min(60, Number(editTimeoutSec) || 10)),
            code: editCode,
            enabled: true,
          },
          fid
        )
        if (seq === matchCheckSeq) {
          flowMatchState = Boolean(matched)
        }
      } catch (_) {
        if (seq === matchCheckSeq && !localFlow) {
          flowMatchState = null
        }
      }
    }, 120)
  }

  function toggleLogExpand(id) {
    const next = new Set(expandedLogIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    expandedLogIds = next
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return
    const off = rt.EventsOn('plugin:executed', handlePluginExecuted)
    if (typeof off === 'function') unsubs.push(off)
  }

  async function selectPlugin(p) {
    selectedPlugin = p
    editName = p.name || ''
    editDesc = p.description || ''
    editType = p.type || 'analyzer'
    editRuntime = normalizeRuntime(p.runtime)
    editAutoRun = Boolean(p.auto_run)
    editMethod = p.method || ''
    editHostPattern = p.host_pattern || ''
    editPathPattern = p.path_pattern || ''
    editTimeoutSec = Number(p.timeout_sec) || 10
    const nextCode = p.code || ''
    editCode = nextCode
    editEnabled = Boolean(p.enabled)
    isNew = false
    dirty = false
    confirmDelete = false
    runOutput = ''
    runError = false
    runDurationMs = null
    await tick()
    editorRef?.resetHistory(nextCode)
  }

  async function newPlugin(defaultType = 'analyzer', defaultRuntime = 'builtin') {
    selectedPlugin = null
    editName = ''
    editDesc = ''
    editType = defaultType
    editRuntime = normalizeRuntime(defaultRuntime)
    editAutoRun = defaultRuntime !== 'builtin'
    editMethod = ''
    editHostPattern = ''
    editPathPattern = ''
    editTimeoutSec = 10
    editEnabled = true
    const nextCode = starterCodeFor(defaultType, editRuntime)
    editCode = nextCode
    isNew = true
    dirty = true
    confirmDelete = false
    runOutput = ''
    runError = false
    runDurationMs = null
    await tick()
    editorRef?.resetHistory(nextCode)
  }

  async function loadExample(idx) {
    const app = api()
    if (!app?.GetExamplePlugins) return
    try {
      const list = examples.length ? examples : (await app.GetExamplePlugins()) || []
      const ex = list[idx]
      if (!ex) return
      selectedPlugin = null
      editName = ex.name
      editDesc = ex.description || ''
      editType = ex.type || 'analyzer'
      editRuntime = normalizeRuntime(ex.runtime)
      editAutoRun = Boolean(ex.auto_run)
      editMethod = ex.method || ''
      editHostPattern = ex.host_pattern || ''
      editPathPattern = ex.path_pattern || ''
      editTimeoutSec = Number(ex.timeout_sec) || 10
      const nextCode = ex.code || ''
      editCode = nextCode
      editEnabled = true
      isNew = true
      dirty = false
      confirmDelete = false
      await tick()
      editorRef?.resetHistory(nextCode)
      await savePlugin(true)
      toast.success(translate('tools.plugins.toast.installedExample', { name: ex.name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.exampleFailed', { error: e?.message || e }))
    }
  }

  async function savePlugin(silent = false) {
    const name = editName.trim()
    if (!name) {
      toast.warning(translate('tools.plugins.toast.nameRequired'))
      return false
    }
    const app = api()
    if (!app?.SavePlugin) return false
    saving = true
    const clampedTimeout = Math.max(1, Math.min(60, Number(editTimeoutSec) || 10))
    editTimeoutSec = clampedTimeout
    try {
      await app.SavePlugin({
        name,
        description: editDesc.trim(),
        type: editType,
        runtime: normalizeRuntime(editRuntime),
        auto_run: Boolean(editAutoRun),
        host_pattern: editHostPattern.trim(),
        path_pattern: editPathPattern.trim(),
        method: editMethod.trim().toUpperCase(),
        timeout_sec: clampedTimeout,
        code: editCode,
        enabled: editEnabled,
      })
      isNew = false
      dirty = false
      await loadPlugins()
      selectedPlugin = plugins.find((p) => p.name === name) || selectedPlugin
      if (!silent) toast.success(translate('tools.plugins.toast.saved', { name }))
      return true
    } catch (e) {
      const msg = e?.message || String(e)
      runOutput = translate('tools.plugins.toast.saveFailed', { error: msg })
      runError = true
      toast.error(translate('tools.plugins.toast.saveFailed', { error: msg }))
      return false
    } finally {
      saving = false
    }
  }

  async function deletePlugin(name) {
    const app = api()
    if (!app?.DeletePlugin) return
    try {
      await app.DeletePlugin(name)
      selectedPlugin = null
      editName = ''
      editDesc = ''
      editCode = ''
      isNew = false
      dirty = false
      confirmDelete = false
      runOutput = ''
      runError = false
      await loadPlugins()
      toast.info(translate('tools.plugins.toast.deleted', { name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.deleteFailed', { error: e?.message || e }))
    }
  }

  async function togglePlugin(p) {
    const app = api()
    if (!app?.TogglePlugin) return
    try {
      await app.TogglePlugin(p.name)
      await loadPlugins()
      const updated = plugins.find((x) => x.name === p.name)
      const key = updated?.enabled ? 'tools.plugins.toast.enabled' : 'tools.plugins.toast.disabled'
      toast.info(translate(key, { name: p.name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.toggleFailed', { error: e?.message || e }))
    }
  }

  function buildDraftPlugin() {
    return {
      name: editName.trim() || 'draft-plugin',
      description: editDesc.trim(),
      type: editType,
      runtime: normalizeRuntime(editRuntime),
      auto_run: Boolean(editAutoRun),
      host_pattern: editHostPattern.trim(),
      path_pattern: editPathPattern.trim(),
      method: editMethod.trim().toUpperCase(),
      timeout_sec: Math.max(1, Math.min(60, Number(editTimeoutSec) || 10)),
      code: editCode,
      enabled: editEnabled,
    }
  }

  async function loadFlowPayload(flowId) {
    const fid = String(flowId || '').trim()
    const seq = ++payloadFetchSeq
    if (!fid) {
      flowPayloadRaw = ''
      flowPayloadObj = null
      loadingPayload = false
      return
    }
    const app = api()
    if (!app?.GetPluginFlowPayload) {
      const local = recentFlows.find((f) => f.id === fid) || null
      if (local) {
        let query = ''
        const query_params = {}
        try {
          if (local.url) {
            const u = new URL(local.url)
            query = u.search.replace(/^\?/, '')
            u.searchParams.forEach((v, k) => {
              if (!(k in query_params)) query_params[k] = v
            })
          }
        } catch (_) {}
        flowPayloadObj = { ...local, query, query_params }
        flowPayloadRaw = JSON.stringify(flowPayloadObj, null, 2)
      } else {
        flowPayloadObj = null
        flowPayloadRaw = ''
      }
      return
    }
    loadingPayload = true
    try {
      const raw = await app.GetPluginFlowPayload(fid)
      if (seq !== payloadFetchSeq) return
      flowPayloadRaw = String(raw || '')
      try {
        flowPayloadObj = flowPayloadRaw ? JSON.parse(flowPayloadRaw) : null
      } catch (_) {
        flowPayloadObj = null
      }
    } catch (_) {
      if (seq === payloadFetchSeq) {
        flowPayloadRaw = ''
        flowPayloadObj = null
      }
    } finally {
      if (seq === payloadFetchSeq) loadingPayload = false
    }
  }

  function snippetForField(field, runtime, isQueryParam = false) {
    const rt = normalizeRuntime(runtime)
    if (isQueryParam) {
      const qk = JSON.stringify(field)
      if (rt === 'python3') return `flow.get("query_params", {}).get(${qk}, "")`
      if (rt === 'sh') return `jq -r '.query_params[${qk}] // ""'`
      return `flow.query_params?.[${qk}]`
    }
    if (rt === 'python3') {
      if (field === 'req_headers' || field === 'resp_headers' || field === 'query_params') {
        return `flow.get("${field}", {})`
      }
      if (field === 'sign_params') return `flow.get("${field}", [])`
      if (field === 'status' || field === 'latency_ms') return `flow.get("${field}", 0)`
      return `flow.get("${field}", "")`
    }
    if (rt === 'sh') {
      return `jq -r '.${field} // ""'`
    }
    return `flow.${field}`
  }

  function formatSampleValue(val) {
    if (val === undefined || val === null) return '—'
    if (typeof val === 'string') {
      if (!val) return '""'
      const clean = val.replace(/\s+/g, ' ').trim()
      return clean.length > 26 ? `${clean.slice(0, 26)}…` : clean
    }
    if (Array.isArray(val)) return `[${val.length}]`
    if (typeof val === 'object') return `{${Object.keys(val).length}}`
    return String(val)
  }

  function insertSnippetAtCursor(snippet) {
    if (!snippet) return
    if (editorRef?.insertAtCursor) {
      editorRef.insertAtCursor(snippet)
      dirty = true
      return
    }
    editCode = editCode ? `${editCode}\n${snippet}` : snippet
    dirty = true
  }

  function fillTriggerFromFlow() {
    const f = selectedTestFlow
    if (!f && !flowPayloadObj) return
    const src = flowPayloadObj || f
    editMethod = String(src.method || '').toUpperCase()
    let parsed = null
    try {
      if (src.url) parsed = new URL(src.url)
    } catch (_) {}
    const rawHost = src.host || parsed?.host || ''
    editHostPattern = parsed?.hostname || rawHost.replace(/:\d+$/, '')
    const basePath = parsed?.pathname || src.path || ''
    const qParams = flowPayloadObj?.query_params || {}
    const qKeys = Object.keys(qParams)
    if (qKeys.length > 0) {
      editPathPattern = `${basePath}?${qKeys[0]}=*`
    } else if (parsed?.search) {
      editPathPattern = `${basePath}${parsed.search}`
    } else {
      editPathPattern = basePath
    }
    dirty = true
    toast.info(translate('tools.plugins.toast.filledFromFlow', { id: src.id || runFlowId }))
  }

  async function runPlugin() {
    if (!runFlowId.trim()) {
      toast.warning(translate('tools.plugins.toast.flowIdRequired'))
      return
    }
    const app = api()
    if (!app?.RunPluginDraft && !app?.RunPlugin) return

    drawerTab = 'runner'
    running = true
    const t0 = performance.now()
    try {
      let result
      if (app.RunPluginDraft) {
        result = await app.RunPluginDraft(buildDraftPlugin(), runFlowId.trim())
      } else {
        if (!editName.trim()) {
          toast.warning(translate('tools.plugins.toast.nameBeforeRun'))
          return
        }
        if (isNew || dirty) {
          const ok = await savePlugin(true)
          if (!ok) return
        }
        result = await app.RunPlugin(editName.trim(), runFlowId.trim())
      }
      runDurationMs = Math.round(performance.now() - t0)
      if (result?.error) {
        runOutput = result.error
        runError = true
        toast.error(translate('tools.plugins.toast.pluginError', { error: result.error }))
      } else {
        runOutput = result?.output || translate('tools.plugins.noOutput')
        runError = false
      }
    } catch (e) {
      runDurationMs = Math.round(performance.now() - t0)
      runOutput = e?.message || String(e)
      runError = true
      toast.error(translate('tools.plugins.toast.runFailed', { error: runOutput }))
    } finally {
      running = false
      loadLogs()
    }
  }

  function insertRuntimeStarter() {
    const nextCode = starterCodeFor(editType, editRuntime)
    if (editorRef?.replaceValue) {
      editorRef.replaceValue(nextCode, { undoable: true })
    } else {
      editCode = nextCode
    }
    dirty = true
  }

  function pluginRuntimeToLanguage(rt) {
    switch (String(rt || '').toLowerCase()) {
      case 'python3':
        return 'python'
      case 'node':
        return 'javascript'
      case 'sh':
        return 'bash'
      default:
        return 'text'
    }
  }

  function applyPatchedPluginCode(patchedCode) {
    if (typeof patchedCode !== 'string') return
    if (editorRef?.replaceValue) {
      editorRef.replaceValue(patchedCode, { undoable: true })
    } else {
      editCode = patchedCode
    }
    dirty = true
  }

  function openPluginAIHeal() {
    openAIHealModal({
      scope: 'plugin',
      title: `${editName.trim() || 'Plugin Draft'} — ${translate('tools.plugins.aiFixBtn')}`,
      code: editCode,
      language: pluginRuntimeToLanguage(editRuntime),
      errorText: runOutput || '',
      logs: runOutput || '',
      metadata: {
        runtime: editRuntime || 'builtin',
        plugin_type: editType || 'analyzer',
        flow_id: runFlowId.trim(),
      },
      undoKey: `plugin:${editName.trim() || 'draft'}`,
      onApplyPatch: (patchedCode) => {
        applyPatchedPluginCode(patchedCode)
      },
      onApplyAndRerun: async (patchedCode) => {
        applyPatchedPluginCode(patchedCode)
        await tick()
        if (runFlowId.trim()) {
          await runPlugin()
        }
      },
    })
  }

  function summarizeScope(p) {
    const parts = []
    if (p.method) parts.push(p.method)
    if (p.host_pattern || p.path_pattern) {
      parts.push(`${p.host_pattern || '*'}${p.path_pattern || ''}`)
    }
    return parts.join(' ')
  }

  $: filteredPlugins = plugins.filter((p) => {
    if (typeFilter === 'auto' && !p.auto_run) return false
    else if (typeFilter !== 'all' && typeFilter !== 'auto' && p.type !== typeFilter) return false
    const q = searchQuery.trim().toLowerCase()
    if (!q) return true
    return (
      (p.name || '').toLowerCase().includes(q) ||
      (p.description || '').toLowerCase().includes(q) ||
      (p.type || '').toLowerCase().includes(q) ||
      (p.runtime || '').toLowerCase().includes(q) ||
      (p.host_pattern || '').toLowerCase().includes(q) ||
      (p.path_pattern || '').toLowerCase().includes(q)
    )
  })

  $: visibleLogs =
    logsOnlyCurrent && editName.trim()
      ? execLogs.filter((rec) => rec.plugin_name === editName.trim())
      : execLogs

  $: enabledCount = plugins.filter((p) => p.enabled).length
  $: selectedTestFlow = recentFlows.find((f) => f.id === runFlowId.trim()) || null
  $: filteredTestFlows = recentFlows.filter((f) => {
    const q = flowFilterQuery.trim().toLowerCase()
    if (!q) return true
    return (
      (f.id || '').toLowerCase().includes(q) ||
      (f.method || '').toLowerCase().includes(q) ||
      (f.host || '').toLowerCase().includes(q) ||
      (f.path || '').toLowerCase().includes(q) ||
      (f.url || '').toLowerCase().includes(q)
    )
  })
  $: queryParamEntries = Object.entries(flowPayloadObj?.query_params || {})
  $: if (editCode || isNew) {
    scheduleMatchCheck(runFlowId, editMethod, editHostPattern, editPathPattern, recentFlows)
  } else {
    flowMatchState = null
  }
  $: if ((editCode || isNew) && inspectorMode !== 'off') {
    loadFlowPayload(runFlowId)
  }

  onMount(() => {
    subscribeEvents()
    loadPluginDir()
    loadPlugins()
    loadExamples()
    loadRecentFlows()
    loadLogs()
  })

  onDestroy(() => {
    if (matchCheckTimer) clearTimeout(matchCheckTimer)
    for (const off of unsubs) {
      try {
        off()
      } catch (_) {}
    }
    unsubs = []
  })
</script>

<div class="plugins-page">
  <SplitPane direction="horizontal" initialSize={31} minPrimary={23} minSecondary={45} storageKey="cap.plugins.split">
    <!-- Left Extension Directory -->
    <div slot="primary" class="sidebar-pane">
      <div class="list-toolbar">
        <div class="list-title-group">
          <span class="pane-title">{$t('tools.plugins.title')}</span>
          <Badge variant="neutral" size="xs" mono>{enabledCount}/{plugins.length}</Badge>
        </div>
        <div class="toolbar-btns">
          <Button
            variant="ghost"
            size="xs"
            icon="refresh"
            iconOnly
            loading={reloading}
            title={$t('tools.plugins.reloadTitle')}
            on:click={() => reloadPluginsFromDisk(true)}
          />
          <Button variant="primary" size="xs" icon="plus" on:click={() => newPlugin()}>{$t('tools.plugins.newBtn')}</Button>
        </div>
      </div>

      <!-- Local Plugins Folder Header -->
      <div class="local-dir-bar">
        <span class="dir-icon"><Icon name="folder" size={12} /></span>
        <span class="dir-path mono truncate" title={pluginDir}>{pluginDir}</span>
        <div class="dir-actions">
          <button
            type="button"
            class="dir-btn"
            title={$t('tools.plugins.copyPathTitle')}
            on:click={() => copyToClipboard(pluginDir, translate('tools.plugins.toast.dirCopied'))}
          >
            <Icon name="copy" size={11} />
          </button>
          <button
            type="button"
            class="dir-btn"
            disabled={reloading}
            title={$t('tools.plugins.reloadDiskTitle')}
            on:click={() => reloadPluginsFromDisk(true)}
          >
            <Icon name="refresh" size={11} />
          </button>
        </div>
      </div>

      <!-- Search & Filter -->
      <div class="list-filters">
        <div class="search-wrap">
          <Icon name="search" size={13} />
          <input type="text" class="search-input" bind:value={searchQuery} placeholder={$t('tools.plugins.searchPlaceholder')} />
          {#if searchQuery}
            <button type="button" class="icon-clear" title={$t('common.actions.clear')} on:click={() => (searchQuery = '')}>
              <Icon name="x" size={12} />
            </button>
          {/if}
        </div>
        <div class="filter-pills">
          {#each ['all', 'auto', 'analyzer', 'request_filter', 'response_modifier'] as val}
            <button type="button" class="f-pill" class:active={typeFilter === val} on:click={() => (typeFilter = val)}>
              {$t(`tools.plugins.filters.${val}`)}
            </button>
          {/each}
        </div>
      </div>

      <!-- Installed Plugins -->
      <div class="plugin-list">
        {#each filteredPlugins as p (p.name)}
          {@const meta = getTypeMeta(p.type, $t)}
          {@const rt = normalizeRuntime(p.runtime)}
          {@const scope = summarizeScope(p)}
          <div class="plugin-card" class:selected={selectedPlugin?.name === p.name} class:disabled={!p.enabled}>
            <button type="button" class="plugin-select" on:click={() => selectPlugin(p)}>
              <div class="plugin-top">
                <span class="plugin-name truncate">{p.name}</span>
                <div class="plugin-badges">
                  {#if p.auto_run}
                    <Badge variant={p.enabled ? 'success' : 'neutral'} size="xs" dot={p.enabled}>
                      {$t('tools.plugins.autoBadge')}
                    </Badge>
                  {/if}
                  {#if rt !== 'builtin'}
                    <Badge variant={runtimeBadgeVariant(rt)} size="xs" mono>{rt}</Badge>
                  {:else}
                    <Badge variant={meta.variant} size="xs">{meta.label}</Badge>
                  {/if}
                </div>
              </div>
              {#if p.description}
                <div class="plugin-desc truncate">{p.description}</div>
              {/if}
              <div class="plugin-foot">
                {#if scope}
                  <span class="plugin-scope mono truncate" title={scope}>{scope}</span>
                {/if}
                {#if p.updated_at}
                  <span class="plugin-meta">{$t('tools.plugins.updatedAt', { date: formatUpdated(p.updated_at) })}</span>
                {/if}
              </div>
            </button>

            <label class="switch" title={p.enabled ? $t('tools.plugins.disableTitle') : $t('tools.plugins.enableTitle')}>
              <input type="checkbox" checked={p.enabled} on:change={() => togglePlugin(p)} />
              <span class="switch-track"></span>
            </label>
          </div>
        {/each}

        {#if filteredPlugins.length === 0}
          <EmptyState
            icon="puzzle"
            title={plugins.length === 0 ? $t('tools.plugins.empty.noPluginsTitle') : $t('tools.plugins.empty.filteredTitle')}
            description={plugins.length === 0 ? $t('tools.plugins.empty.noPluginsDesc') : $t('tools.plugins.empty.filteredDesc')}
            compact
          />
        {/if}
      </div>

      <!-- Built-in Templates -->
      <div class="examples-box">
        <div class="examples-head">
          <Icon name="sparkles" size={12} />
          <span>{$t('tools.plugins.starterTemplates')}</span>
        </div>
        <div class="examples-list">
          {#if examples.length > 0}
            {#each examples as ex, idx (ex.name)}
              <button type="button" class="example-chip" on:click={() => loadExample(idx)} title={ex.description}>
                <Icon name="plus" size={11} />
                <span class="mono">{ex.name}</span>
              </button>
            {/each}
          {:else}
            {#each ['log-requests', 'detect-keys', 'sign-validator'] as label, idx}
              <button type="button" class="example-chip" on:click={() => loadExample(idx)}>
                <Icon name="plus" size={11} />
                <span class="mono">{label}</span>
              </button>
            {/each}
          {/if}
        </div>
      </div>
    </div>

    <!-- Right Code Editor + Output / Live Logs Drawer -->
    <div slot="secondary" class="studio-pane">
      {#if editCode || isNew}
        <!-- Metadata & Action Toolbar -->
        <div class="studio-toolbar">
          <div class="meta-inputs">
            <input
              type="text"
              class="cap-input name-input mono"
              placeholder={$t('tools.plugins.namePlaceholder')}
              bind:value={editName}
              on:input={() => (dirty = true)}
            />
            <input
              type="text"
              class="cap-input desc-input"
              placeholder={$t('tools.plugins.descPlaceholder')}
              bind:value={editDesc}
              on:input={() => (dirty = true)}
            />
            <select
              class="cap-input type-select"
              bind:value={editType}
              on:change={() => (dirty = true)}
            >
              <option value="analyzer">{$t('tools.plugins.types.analyzer')}</option>
              <option value="request_filter">{$t('tools.plugins.types.request_filter')}</option>
              <option value="response_modifier">{$t('tools.plugins.types.response_modifier')}</option>
            </select>
          </div>

          <div class="toolbar-actions">
            {#if dirty}
              <Badge variant="warning" size="xs" dot>{$t('tools.plugins.unsaved')}</Badge>
            {/if}
            <Button
              variant="ghost"
              size="xs"
              icon="copy"
              title={$t('tools.plugins.copyCodeTitle')}
              on:click={() => copyToClipboard(editCode, translate('tools.plugins.toast.codeCopied'))}
            >
              {$t('common.actions.copy')}
            </Button>
            {#if selectedPlugin}
              {#if confirmDelete}
                <Button variant="danger" size="xs" icon="trash" on:click={() => deletePlugin(selectedPlugin.name)}>
                  {$t('common.actions.confirm')}
                </Button>
                <Button variant="ghost" size="xs" on:click={() => (confirmDelete = false)}>{$t('common.actions.cancel')}</Button>
              {:else}
                <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDelete = true)}>
                  {$t('common.actions.delete')}
                </Button>
              {/if}
            {/if}
            <Button variant="primary" size="xs" icon="save" loading={saving} on:click={() => savePlugin()}>
              {$t('common.actions.save')}
            </Button>
          </div>
        </div>

        <!-- Compact Runtime & Auto-Run Trigger Config Bar -->
        <div class="trigger-config-bar">
          <div class="cfg-row">
            <label class="cfg-item">
              <span class="cfg-k">{$t('tools.plugins.config.runtime')}</span>
              <select
                class="cap-input cfg-select"
                bind:value={editRuntime}
                on:change={() => (dirty = true)}
              >
                {#each runtimeOptions as rt}
                  <option value={rt}>{$t(`tools.plugins.runtimes.${rt}`)}</option>
                {/each}
              </select>
            </label>

            <label class="cfg-toggle" title={$t('tools.plugins.config.autoRunHint')}>
              <span class="switch">
                <input
                  type="checkbox"
                  bind:checked={editAutoRun}
                  on:change={() => (dirty = true)}
                />
                <span class="switch-track"></span>
              </span>
              <span class="cfg-toggle-label">{$t('tools.plugins.config.autoRun')}</span>
            </label>

            <label class="cfg-item">
              <span class="cfg-k">{$t('tools.plugins.config.method')}</span>
              <select
                class="cap-input cfg-method mono"
                bind:value={editMethod}
                on:change={() => (dirty = true)}
              >
                {#each httpMethods as m}
                  <option value={m}>{m || $t('tools.plugins.config.anyMethod')}</option>
                {/each}
              </select>
            </label>

            <label class="cfg-item cfg-grow">
              <span class="cfg-k">{$t('tools.plugins.config.hostPattern')}</span>
              <input
                type="text"
                class="cap-input cfg-pattern mono"
                bind:value={editHostPattern}
                on:input={() => (dirty = true)}
                placeholder={$t('tools.plugins.config.hostPlaceholder')}
              />
            </label>

            <label class="cfg-item cfg-grow" title={$t('tools.plugins.config.pathPatternTooltip')}>
              <span class="cfg-k">{$t('tools.plugins.config.pathPattern')}</span>
              <input
                type="text"
                class="cap-input cfg-pattern mono"
                bind:value={editPathPattern}
                on:input={() => (dirty = true)}
                placeholder={$t('tools.plugins.config.pathPlaceholder')}
              />
            </label>

            <label class="cfg-item">
              <span class="cfg-k">{$t('tools.plugins.config.timeoutSec')}</span>
              <input
                type="number"
                min="1"
                max="60"
                class="cap-input cfg-timeout mono tabular-nums"
                bind:value={editTimeoutSec}
                on:input={() => (dirty = true)}
              />
            </label>

            <Button
              variant="subtle"
              size="xs"
              icon="sparkles"
              disabled={!selectedTestFlow && !flowPayloadObj}
              title={$t('tools.plugins.config.fromFlowTitle')}
              on:click={fillTriggerFromFlow}
            >
              {$t('tools.plugins.config.fromFlowBtn')}
            </Button>
          </div>

          <div class="inspector-bar">
            <div class="inspector-tabs" role="tablist">
              <span class="inspector-label">{$t('tools.plugins.inspector.label')}</span>
              <button
                type="button"
                role="tab"
                aria-selected={inspectorMode === 'vars'}
                class="f-pill"
                class:active={inspectorMode === 'vars'}
                on:click={() => (inspectorMode = 'vars')}
              >
                {$t('tools.plugins.inspector.varsTab')}
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={inspectorMode === 'json'}
                class="f-pill"
                class:active={inspectorMode === 'json'}
                on:click={() => (inspectorMode = 'json')}
              >
                {$t('tools.plugins.inspector.jsonTab')}
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={inspectorMode === 'off'}
                class="f-pill"
                class:active={inspectorMode === 'off'}
                on:click={() => (inspectorMode = 'off')}
              >
                {$t('tools.plugins.inspector.offTab')}
              </button>
            </div>

            {#if editRuntime !== 'builtin'}
              <button type="button" class="inline-starter" on:click={insertRuntimeStarter}>
                {$t('tools.plugins.config.insertTemplate')}
              </button>
            {/if}
          </div>

          {#if inspectorMode === 'vars'}
            <div class="vars-panel">
              <div class="vars-hint">
                <Icon name="code" size={11} />
                <span>{$t('tools.plugins.inspector.clickHint', { runtime: runtimeLabel(editRuntime, $t) })}</span>
                {#if !runFlowId.trim()}
                  <span class="vars-warn">— {$t('tools.plugins.inspector.noFlowSelected')}</span>
                {/if}
              </div>

              {#if queryParamEntries.length > 0}
                <div class="vars-group">
                  <span class="vars-group-label">{$t('tools.plugins.inspector.queryParamsGroup')}</span>
                  <div class="vars-chips">
                    {#each queryParamEntries as [qk, qv]}
                      {@const snip = snippetForField(qk, editRuntime, true)}
                      <button
                        type="button"
                        class="var-chip is-qp mono"
                        title={$t('tools.plugins.inspector.insertTooltip', { snippet: snip })}
                        on:click={() => insertSnippetAtCursor(snip)}
                      >
                        <span class="var-k">query_params.{qk}</span>
                        <span class="var-v">{formatSampleValue(qv)}</span>
                      </button>
                    {/each}
                  </div>
                </div>
              {/if}

              <div class="vars-group">
                <span class="vars-group-label">{$t('tools.plugins.inspector.flowFieldsGroup')}</span>
                <div class="vars-chips">
                  {#each coreFlowFields as field}
                    {@const snip = snippetForField(field, editRuntime, false)}
                    <button
                      type="button"
                      class="var-chip mono"
                      title={$t('tools.plugins.inspector.insertTooltip', { snippet: snip })}
                      on:click={() => insertSnippetAtCursor(snip)}
                    >
                      <span class="var-k">{field}</span>
                      {#if flowPayloadObj}
                        <span class="var-v">{formatSampleValue(flowPayloadObj[field])}</span>
                      {/if}
                    </button>
                  {/each}
                </div>
              </div>
            </div>
          {:else if inspectorMode === 'json'}
            <div class="json-panel">
              <div class="json-panel-head">
                <span class="vars-hint">
                  <Icon name="file-code" size={11} />
                  <span>{$t('tools.plugins.config.stdinHint')}</span>
                </span>
                <div class="json-actions">
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="refresh"
                    iconOnly
                    loading={loadingPayload}
                    title={$t('tools.plugins.inspector.refreshPayload')}
                    on:click={() => loadFlowPayload(runFlowId)}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    disabled={!flowPayloadRaw}
                    on:click={() => copyToClipboard(flowPayloadRaw, translate('tools.plugins.toast.payloadCopied'))}
                  >
                    {$t('tools.plugins.inspector.copyJson')}
                  </Button>
                </div>
              </div>
              <pre class="json-pre mono">{loadingPayload
                  ? $t('tools.plugins.inspector.loadingPayload')
                  : flowPayloadRaw || $t('tools.plugins.inspector.noFlowSelected')}</pre>
            </div>
          {/if}
        </div>

        <!-- Vertical Split: Code Editor + Test Runner / Live Execution Log Drawer -->
        <div class="studio-split-wrap">
          <SplitPane direction="vertical" initialSize={58} minPrimary={25} minSecondary={22} storageKey="cap.plugins.drawer">
            <div slot="primary" class="code-pane">
              <CodeEditor
                bind:this={editorRef}
                bind:value={editCode}
                runtime={editRuntime}
                placeholder={$t('tools.plugins.codePlaceholder')}
                shortcutHint={$t('tools.plugins.editorHint', { mod: MOD_LABEL })}
                on:change={() => (dirty = true)}
                on:save={() => savePlugin()}
                on:run={() => {
                  if (!running) runPlugin()
                }}
              />
            </div>

            <div slot="secondary" class="drawer-pane">
              <div class="drawer-bar">
                <!-- Drawer Tabs -->
                <div class="drawer-tabs" role="tablist">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={drawerTab === 'runner'}
                    class="d-tab"
                    class:active={drawerTab === 'runner'}
                    on:click={() => (drawerTab = 'runner')}
                  >
                    <Icon name="play" size={12} />
                    <span>{$t('tools.plugins.testRunner')}</span>
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={drawerTab === 'logs'}
                    class="d-tab"
                    class:active={drawerTab === 'logs'}
                    on:click={() => (drawerTab = 'logs')}
                  >
                    <Icon name="activity" size={12} />
                    <span>{$t('tools.plugins.liveLogs')}</span>
                    <span class="d-count mono tabular-nums">{execLogs.length}</span>
                  </button>
                </div>

                {#if drawerTab === 'runner'}
                  <div class="drawer-controls">
                    {#if flowMatchState !== null}
                      <span
                        title={flowMatchState
                          ? $t('tools.plugins.config.matchesFlowTooltip')
                          : $t('tools.plugins.config.noMatchFlowTooltip')}
                      >
                        <Badge variant={flowMatchState ? 'success' : 'warning'} size="xs" dot>
                          {flowMatchState ? $t('tools.plugins.config.matchesFlow') : $t('tools.plugins.config.noMatchFlow')}
                        </Badge>
                      </span>
                    {/if}
                    {#if runDurationMs !== null}
                      <Badge variant={runError ? 'danger' : 'success'} size="xs" mono>
                        {runError ? $t('tools.plugins.statusError') : $t('tools.plugins.statusOk')} · {formatDuration(runDurationMs)}
                      </Badge>
                    {/if}
                    {#if recentFlows.length > 0}
                      <input
                        type="text"
                        class="cap-input flow-filter-input"
                        bind:value={flowFilterQuery}
                        placeholder={$t('tools.plugins.flowFilterPlaceholder')}
                      />
                      <select class="cap-input flow-select mono" bind:value={runFlowId} title={$t('tools.plugins.pickFlowTitle')}>
                        {#each filteredTestFlows as f (f.id)}
                          <option value={f.id}>
                            {f.id} — {f.method} {f.url || `${f.host}${f.path}`}
                          </option>
                        {/each}
                      </select>
                    {/if}
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="refresh"
                      iconOnly
                      title={$t('tools.plugins.refreshFlowsTitle')}
                      on:click={loadRecentFlows}
                    />
                    <input
                      type="text"
                      class="cap-input flow-id-input mono"
                      placeholder={$t('tools.plugins.flowIdPlaceholder')}
                      bind:value={runFlowId}
                      on:keydown={(e) => {
                        if (e.key === 'Enter') runPlugin()
                      }}
                    />
                    <Button
                      variant="primary"
                      size="xs"
                      icon="play"
                      loading={running}
                      title={$t('tools.plugins.runDraftTitle', { mod: MOD_LABEL })}
                      on:click={runPlugin}
                    >
                      {dirty || isNew ? $t('tools.plugins.runDraft') : $t('tools.plugins.run')}
                    </Button>
                    {#if runError && runOutput}
                      <Button
                        variant="secondary"
                        size="xs"
                        icon="sparkles"
                        title={$t('tools.plugins.aiFixTitle')}
                        on:click={openPluginAIHeal}
                      >
                        {$t('tools.plugins.aiFixBtn')}
                      </Button>
                    {/if}
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="copy"
                      iconOnly
                      disabled={!runOutput}
                      title={$t('tools.plugins.copyOutputTitle')}
                      on:click={() => copyToClipboard(runOutput, translate('tools.plugins.toast.outputCopied'))}
                    />
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="x"
                      iconOnly
                      disabled={!runOutput}
                      title={$t('tools.plugins.clearOutputTitle')}
                      on:click={() => {
                        runOutput = ''
                        runError = false
                        runDurationMs = null
                      }}
                    />
                  </div>
                {:else}
                  <div class="drawer-controls">
                    <button
                      type="button"
                      class="f-pill"
                      class:active={logsOnlyCurrent}
                      on:click={() => (logsOnlyCurrent = !logsOnlyCurrent)}
                    >
                      {logsOnlyCurrent
                        ? `${$t('tools.plugins.logsFilterCurrent')} (${visibleLogs.length}/${execLogs.length})`
                        : `${$t('tools.plugins.logsFilterAll')} (${execLogs.length})`}
                    </button>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="refresh"
                      iconOnly
                      title={$t('tools.plugins.logsRefreshTitle')}
                      on:click={loadLogs}
                    />
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="trash"
                      iconOnly
                      disabled={execLogs.length === 0}
                      title={$t('tools.plugins.logsClearTitle')}
                      on:click={clearLogs}
                    />
                  </div>
                {/if}
              </div>

              {#if drawerTab === 'runner'}
                <pre class="drawer-output mono" class:is-error={runError}>{runOutput || $t('tools.plugins.outputPlaceholder')}</pre>
              {:else}
                <div class="logs-viewport">
                  {#if visibleLogs.length === 0}
                    <EmptyState
                      icon="activity"
                      title={$t('tools.plugins.logsEmptyTitle')}
                      description={$t('tools.plugins.logsEmptyDesc')}
                      compact
                    />
                  {:else}
                    {#each visibleLogs as rec (rec.id)}
                      {@const hasErr = Boolean(rec.error)}
                      {@const isOpen = expandedLogIds.has(rec.id)}
                      <div class="log-entry" class:has-error={hasErr}>
                        <div class="log-row">
                          <button type="button" class="log-expand" on:click={() => toggleLogExpand(rec.id)}>
                            <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={12} />
                            <Badge variant={hasErr ? 'danger' : 'success'} size="xs" mono>
                              {hasErr ? $t('tools.plugins.statusError') : $t('tools.plugins.statusOk')}
                            </Badge>
                            <span class="log-plugin mono">{rec.plugin_name}</span>
                            <Badge variant={runtimeBadgeVariant(rec.runtime)} size="xs" mono>
                              {normalizeRuntime(rec.runtime)}
                            </Badge>
                            <Badge variant={rec.trigger === 'auto' ? 'accent' : 'neutral'} size="xs">
                              {rec.trigger === 'auto' ? $t('tools.plugins.triggerAuto') : $t('tools.plugins.triggerManual')}
                            </Badge>
                            {#if rec.method}
                              <Badge variant="method" method={rec.method} size="xs" />
                            {/if}
                            {#if rec.flow_id}
                              <span class="log-flow mono">{rec.flow_id}</span>
                            {/if}
                            <span class="log-url mono truncate" title={rec.url}>{rec.url}</span>
                            <span class="log-dur mono tabular-nums">{formatDuration(rec.duration_ms)}</span>
                            <span class="log-ts mono tabular-nums">{formatTime(rec.timestamp)}</span>
                          </button>
                          <button
                            type="button"
                            class="log-copy-btn"
                            title={$t('tools.plugins.copyOutputTitle')}
                            on:click={() =>
                              copyToClipboard(rec.error || rec.output || '', translate('tools.plugins.toast.outputCopied'))}
                          >
                            <Icon name="copy" size={11} />
                          </button>
                        </div>
                        {#if isOpen}
                          <pre class="log-body mono" class:is-error={hasErr}>{rec.error ? `${rec.error}${rec.output ? `\n\n${rec.output}` : ''}` : rec.output || $t('tools.plugins.noOutput')}</pre>
                        {/if}
                      </div>
                    {/each}
                  {/if}
                </div>
              {/if}
            </div>
          </SplitPane>
        </div>
      {:else}
        <EmptyState
          icon="puzzle"
          title={$t('tools.plugins.empty.studioTitle')}
          description={$t('tools.plugins.empty.studioDesc')}
        >
          <Button variant="primary" size="sm" icon="plus" on:click={() => newPlugin('analyzer', 'builtin')}>
            {$t('tools.plugins.empty.newAnalyzer')}
          </Button>
          <Button variant="secondary" size="sm" icon="code" on:click={() => newPlugin('analyzer', 'python3')}>
            {$t('tools.plugins.empty.newPythonScript')}
          </Button>
          <Button variant="secondary" size="sm" icon="filter" on:click={() => newPlugin('request_filter', 'builtin')}>
            {$t('tools.plugins.empty.newRequestFilter')}
          </Button>
          <Button variant="secondary" size="sm" icon="sparkles" on:click={() => loadExample(0)}>
            {$t('tools.plugins.empty.installExample')}
          </Button>
        </EmptyState>
      {/if}
    </div>
  </SplitPane>
</div>

<style>
  .plugins-page {
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Left Sidebar */
  .sidebar-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: var(--bg-header);
    min-height: 0;
  }

  .list-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .list-title-group {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pane-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .toolbar-btns {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /* Local Plugins Directory Bar */
  .local-dir-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px 6px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
    min-width: 0;
  }

  .dir-icon {
    color: var(--text-faint);
    display: flex;
    flex-shrink: 0;
  }

  .dir-path {
    flex: 1;
    min-width: 0;
    font-size: 10.5px;
    color: var(--text-muted);
  }

  .dir-actions {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }

  .dir-btn {
    width: 20px;
    height: 20px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .dir-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dir-btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  .list-filters {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 7px;
    flex-shrink: 0;
  }

  .search-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 8px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
  }

  .search-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .search-input {
    border: none;
    background: transparent;
    outline: none;
    flex: 1;
    min-width: 0;
    font-size: var(--text-xs);
    color: var(--text-primary);
  }

  .icon-clear {
    border: none;
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    display: flex;
    padding: 2px;
  }

  .filter-pills {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  .f-pill {
    padding: 2px 7px;
    height: 21px;
    font-size: 10.5px;
    font-weight: 500;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .f-pill:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .f-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .plugin-list {
    flex: 1;
    overflow-y: auto;
    min-height: 0;
  }

  .plugin-card {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    border-bottom: 1px solid var(--border-subtle);
    border-left: 2px solid transparent;
    transition: background var(--transition-fast);
  }

  .plugin-card:hover {
    background: var(--bg-hover);
  }

  .plugin-card.selected {
    background: var(--bg-active);
    border-left-color: var(--accent);
  }

  .plugin-card.disabled .plugin-name,
  .plugin-card.disabled .plugin-desc {
    opacity: 0.55;
  }

  .plugin-select {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 0;
  }

  .plugin-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }

  .plugin-badges {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .plugin-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .plugin-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .plugin-foot {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .plugin-scope {
    font-size: 10px;
    color: var(--accent);
    opacity: 0.85;
  }

  .plugin-meta {
    font-size: 10px;
    color: var(--text-faint);
    margin-left: auto;
    flex-shrink: 0;
  }

  /* Toggle Switch */
  .switch {
    position: relative;
    display: inline-block;
    width: 30px;
    height: 17px;
    flex-shrink: 0;
    cursor: pointer;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
    position: absolute;
  }

  .switch-track {
    position: absolute;
    inset: 0;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .switch-track::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 11px;
    height: 11px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: transform var(--transition-fast), background var(--transition-fast);
  }

  .switch input:checked + .switch-track {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .switch input:checked + .switch-track::after {
    transform: translateX(13px);
    background: var(--status-success);
  }

  /* Examples Footer */
  .examples-box {
    padding: 10px 12px;
    border-top: 1px solid var(--border-default);
    background: var(--bg-surface);
    display: flex;
    flex-direction: column;
    gap: 7px;
    flex-shrink: 0;
  }

  .examples-head {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
  }

  .examples-list {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }

  .example-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 8px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .example-chip:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
  }

  /* Right Studio */
  .studio-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-app);
  }

  .studio-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .meta-inputs {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 260px;
  }

  .name-input {
    width: 150px;
    height: 28px;
  }

  .desc-input {
    flex: 1;
    min-width: 110px;
    height: 28px;
  }

  .type-select {
    width: 135px;
    height: 28px;
    cursor: pointer;
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  /* Trigger & Runtime Config Bar */
  .trigger-config-bar {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 7px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .cfg-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .cfg-item {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    min-width: 0;
  }

  .cfg-grow {
    flex: 1;
    min-width: 145px;
  }

  .cfg-k {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .cfg-select {
    height: 25px;
    font-size: var(--text-xs);
    padding: 0 7px;
    cursor: pointer;
  }

  .cfg-method {
    height: 25px;
    width: 78px;
    font-size: var(--text-xs);
    padding: 0 6px;
    cursor: pointer;
  }

  .cfg-pattern {
    height: 25px;
    flex: 1;
    min-width: 100px;
    font-size: var(--text-xs);
    padding: 0 7px;
  }

  .cfg-timeout {
    height: 25px;
    width: 56px;
    font-size: var(--text-xs);
    padding: 0 6px;
  }

  .cfg-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    user-select: none;
  }

  .cfg-toggle-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .inline-starter {
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
    padding: 0;
  }

  .inline-starter:hover {
    text-decoration: underline;
  }

  .studio-split-wrap {
    flex: 1;
    min-height: 0;
  }

  .code-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  /* Bottom Drawer */
  .drawer-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-surface);
  }

  .drawer-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 0 10px 0 6px;
    min-height: 34px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .drawer-tabs {
    display: flex;
    align-items: center;
    gap: 2px;
  }

  .d-tab {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 34px;
    padding: 0 10px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .d-tab:hover {
    color: var(--text-primary);
  }

  .d-tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .d-count {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .d-tab.active .d-count {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .drawer-controls {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 0;
    flex-wrap: wrap;
  }

  .flow-select {
    height: 25px;
    max-width: 220px;
    font-size: var(--text-xs);
  }

  .flow-id-input {
    height: 25px;
    width: 104px;
    font-size: var(--text-xs);
  }

  .drawer-output {
    flex: 1;
    overflow-y: auto;
    padding: 12px 14px;
    margin: 0;
    font-size: var(--text-xs);
    line-height: 1.6;
    color: var(--text-secondary);
    background: var(--bg-input);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .drawer-output.is-error {
    color: var(--status-danger);
  }

  /* Live Execution Log Viewport */
  .logs-viewport {
    flex: 1;
    overflow-y: auto;
    background: var(--bg-input);
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-height: 0;
  }

  .log-entry {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    overflow: hidden;
  }

  .log-entry.has-error {
    border-color: var(--status-danger-border);
  }

  .log-row {
    display: flex;
    align-items: center;
    gap: 4px;
    padding-right: 6px;
  }

  .log-expand {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-xs);
    cursor: pointer;
    text-align: left;
  }

  .log-expand:hover {
    background: var(--bg-hover);
  }

  .log-plugin {
    font-weight: 600;
    color: var(--text-primary);
    flex-shrink: 0;
  }

  .log-flow {
    font-size: 10.5px;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .log-url {
    flex: 1;
    min-width: 0;
    font-size: 11px;
    color: var(--text-muted);
  }

  .log-dur,
  .log-ts {
    font-size: 10.5px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .log-copy-btn {
    width: 22px;
    height: 22px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-faint);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
  }

  .log-copy-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .log-body {
    margin: 0;
    padding: 8px 10px;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-input);
    color: var(--text-secondary);
    font-size: 11.5px;
    line-height: 1.55;
    max-height: 180px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .log-body.is-error {
    color: var(--status-danger);
  }

  /* Interactive Flow Variables & stdin JSON Inspector */
  .inspector-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-top: 4px;
    border-top: 1px solid var(--border-subtle);
  }

  .inspector-tabs {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }

  .inspector-label {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-faint);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 2px;
  }

  .vars-panel {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 7px 9px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    max-height: 132px;
    overflow-y: auto;
  }

  .vars-hint {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 10.5px;
    color: var(--text-muted);
    flex-wrap: wrap;
  }

  .vars-warn {
    color: var(--status-warning);
  }

  .vars-group {
    display: flex;
    align-items: flex-start;
    gap: 6px;
  }

  .vars-group-label {
    font-size: 10px;
    font-weight: 600;
    color: var(--text-faint);
    text-transform: uppercase;
    padding-top: 4px;
    white-space: nowrap;
    min-width: 72px;
  }

  .vars-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    flex: 1;
    min-width: 0;
  }

  .var-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-surface);
    font-size: 10.5px;
    cursor: pointer;
    max-width: 240px;
    transition: all var(--transition-fast);
  }

  .var-chip:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .var-chip.is-qp {
    border-color: var(--status-info-border);
    background: var(--status-info-bg);
  }

  .var-k {
    color: var(--accent);
    font-weight: 600;
    white-space: nowrap;
  }

  .var-chip.is-qp .var-k {
    color: var(--status-info);
  }

  .var-v {
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .json-panel {
    display: flex;
    flex-direction: column;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    overflow: hidden;
  }

  .json-panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 4px 8px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
  }

  .json-actions {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .json-pre {
    margin: 0;
    padding: 8px 10px;
    max-height: 140px;
    overflow: auto;
    font-size: 11px;
    line-height: 1.5;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .flow-filter-input {
    height: 25px;
    width: 110px;
    font-size: var(--text-xs);
  }
</style>
