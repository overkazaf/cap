<script>
  import { onMount, onDestroy, createEventDispatcher, tick } from 'svelte'
  import '../lib/locales/pluginWorkbench.js'
  import { t, translate } from '../lib/i18n.js'
  import { hasPrimaryMod, MOD_LABEL } from '../lib/shortcuts.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatBytes, formatDuration, formatTime } from '../lib/format.js'

  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'
  import EmptyState from './EmptyState.svelte'
  import SplitPane from './SplitPane.svelte'

  /**
   * Currently selected flow from Flows.svelte (FlowSummary or FlowDetail).
   * @type {Record<string, any> | null}
   */
  export let selectedFlow = null
  export let compact = true

  const dispatch = createEventDispatcher()
  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  const RUNTIME_OPTIONS = ['python3', 'node', 'sh', 'builtin']
  const HTTP_METHODS = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

  // Plugin list & active draft state
  let plugins = []
  let selectedPluginName = ''
  let isNew = false
  let dirty = false
  let reloading = false
  let saving = false
  let running = false

  let editName = ''
  let editDesc = ''
  let editType = 'analyzer'
  let editRuntime = 'python3'
  let editAutoRun = true
  let editEnabled = true
  let editMethod = ''
  let editHostPattern = ''
  let editPathPattern = ''
  let editTimeoutSec = 10
  let editCode = ''

  // Schema / Variable inspector state
  let schemaTab = 'variables' // 'variables' | 'stdin' | 'hide'
  let varFilter = ''
  let payloadJson = ''
  let payloadObj = null
  let payloadLoading = false
  let payloadFlowId = ''
  let payloadSeq = 0

  // Real-time flow match check
  let flowMatchState = null // null | true | false
  let matchCheckSeq = 0
  let matchCheckTimer = null

  // Editor ref & cursor info
  let editorEl = null
  let cursorLine = 1
  let cursorCol = 1

  // Output & Live Logs
  let bottomTab = 'output' // 'output' | 'logs'
  let runOutput = ''
  let runError = false
  let runDurationMs = null
  let runWasDraft = true
  let execLogs = []
  let logsOnlyCurrent = false
  let expandedLogIds = new Set()

  let unsubs = []

  function normalizeRuntime(rt) {
    return RUNTIME_OPTIONS.includes(rt) ? rt : 'builtin'
  }

  function buildDraftPlugin() {
    return {
      name: (editName || '').trim() || 'draft-plugin',
      description: editDesc || '',
      type: editType || 'analyzer',
      runtime: normalizeRuntime(editRuntime),
      auto_run: Boolean(editAutoRun),
      enabled: Boolean(editEnabled),
      method: editMethod || '',
      host_pattern: (editHostPattern || '').trim(),
      path_pattern: (editPathPattern || '').trim(),
      timeout_sec: Math.max(1, Math.min(60, Number(editTimeoutSec) || 10)),
      code: editCode || '',
    }
  }

  function parseUrlParts(flow) {
    const out = {
      scheme: flow?.scheme || '',
      host: flow?.host || '',
      path: flow?.path || '',
      query: flow?.query || '',
      query_params: {},
    }
    if (flow?.url) {
      try {
        const u = new URL(flow.url)
        out.scheme = out.scheme || u.protocol.replace(/:$/, '')
        out.host = out.host || u.host
        out.path = out.path || u.pathname
        out.query = u.search ? u.search.slice(1) : ''
        for (const [k, v] of u.searchParams.entries()) {
          if (!(k in out.query_params)) out.query_params[k] = v
        }
      } catch (_) {
        const qIdx = String(flow.url).indexOf('?')
        if (qIdx >= 0) {
          out.query = String(flow.url).slice(qIdx + 1)
          try {
            const sp = new URLSearchParams(out.query)
            for (const [k, v] of sp.entries()) {
              if (!(k in out.query_params)) out.query_params[k] = v
            }
          } catch (_) {}
        }
      }
    }
    return out
  }

  function synthesizeFallbackPayload(flow) {
    if (!flow) return null
    const parts = parseUrlParts(flow)
    return {
      id: flow.id || '',
      method: flow.method || '',
      url: flow.url || '',
      scheme: parts.scheme,
      host: parts.host,
      path: parts.path,
      query: parts.query,
      query_params: parts.query_params,
      status: flow.status ?? 0,
      latency_ms: flow.latency_ms ?? 0,
      req_headers: flow.req_headers || {},
      resp_headers: flow.resp_headers || {},
      req_body: flow.req_body || '',
      resp_body: flow.resp_body || '',
      sign_params: Array.isArray(flow.sign_params) ? flow.sign_params : [],
    }
  }

  function makeStarterCode(rt, flow = null) {
    const norm = normalizeRuntime(rt)
    const parts = flow ? parseUrlParts(flow) : null
    const firstQueryKey = parts ? Object.keys(parts.query_params)[0] : ''

    if (norm === 'python3') {
      const qLine = firstQueryKey
        ? `q_val = flow.get("query_params", {}).get(${JSON.stringify(firstQueryKey)}, "")\nprint(f"query[{firstQueryKey}] = {q_val}")\n`
        : ''
      return `import json, sys\n\nflow = json.load(sys.stdin)\nprint(f"[{flow.get('method')}] {flow.get('host')}{flow.get('path')} -> {flow.get('status')}")\n${qLine}`
    }
    if (norm === 'node') {
      const qLine = firstQueryKey
        ? `const qVal = flow.query_params?.[${JSON.stringify(firstQueryKey)}] ?? "";\nconsole.log("query[${firstQueryKey}] =", qVal);\n`
        : ''
      return `const fs = require("fs");\nconst flow = JSON.parse(fs.readFileSync(0, "utf8"));\nconsole.log(\`[\${flow.method}] \${flow.host}\${flow.path} -> \${flow.status}\`);\n${qLine}`
    }
    if (norm === 'sh') {
      const qLine = firstQueryKey
        ? `echo "$FLOW" | jq -r '.query_params[${JSON.stringify(firstQueryKey)}] // empty'\n`
        : ''
      return `FLOW=$(cat)\necho "$FLOW" | jq -r '"[" + .method + "] " + .host + .path + " -> " + (.status|tostring)'\n${qLine}`
    }
    return `// Built-in analyzer plugin\nfunction analyze(flow) {\n  return {\n    id: flow.id,\n    method: flow.method,\n    url: flow.url,\n    status: flow.status\n  };\n}\n`
  }

  function suggestPatternFromFlow(flow) {
    const parts = parseUrlParts(flow)
    const host = (parts.host || '').replace(/:\d+$/, '')
    const queryKeys = Object.keys(parts.query_params)
    let pathPattern = parts.path || '/'
    if (queryKeys.length > 0) {
      pathPattern = `${pathPattern}?${queryKeys[0]}=*`
    }
    const slugHost = host.split('.')[0] || 'api'
    const slugSeg = (parts.path || '')
      .split('/')
      .filter(Boolean)
      .slice(-1)[0]
      ?.replace(/[^a-zA-Z0-9_-]/g, '') || 'hook'
    const suggestedName = `${slugHost}-${slugSeg}`.toLowerCase().slice(0, 36)
    return { host, pathPattern, method: flow.method || '', suggestedName }
  }

  function applyPluginToEditor(p) {
    if (!p) return
    isNew = false
    selectedPluginName = p.name || ''
    editName = p.name || ''
    editDesc = p.description || ''
    editType = p.type || 'analyzer'
    editRuntime = normalizeRuntime(p.runtime)
    editAutoRun = Boolean(p.auto_run)
    editEnabled = p.enabled !== false
    editMethod = p.method || ''
    editHostPattern = p.host_pattern || ''
    editPathPattern = p.path_pattern || ''
    editTimeoutSec = p.timeout_sec || 10
    editCode = p.code || ''
    dirty = false
    scheduleMatchCheck()
  }

  function createNewFromFlow() {
    const flow = selectedFlow
    isNew = true
    selectedPluginName = '__new__'
    editType = 'analyzer'
    editRuntime = 'python3'
    editAutoRun = true
    editEnabled = true
    editTimeoutSec = 10
    if (flow) {
      const s = suggestPatternFromFlow(flow)
      editName = s.suggestedName
      editDesc = `${flow.method || 'HTTP'} ${s.host}${s.pathPattern}`
      editMethod = s.method
      editHostPattern = s.host
      editPathPattern = s.pathPattern
      editCode = makeStarterCode('python3', flow)
      toast.info(translate('pluginBench.toast.createdFromFlow', { host: s.host || flow.url }))
    } else {
      editName = `plugin-${Date.now().toString().slice(-4)}`
      editDesc = ''
      editMethod = ''
      editHostPattern = ''
      editPathPattern = ''
      editCode = makeStarterCode('python3', null)
    }
    dirty = true
    scheduleMatchCheck()
  }

  function fillTriggersFromFlow() {
    if (!selectedFlow) {
      toast.warning(translate('pluginBench.toast.needFlow'))
      return
    }
    const s = suggestPatternFromFlow(selectedFlow)
    editMethod = s.method
    editHostPattern = s.host
    editPathPattern = s.pathPattern
    dirty = true
    scheduleMatchCheck()
    toast.info(translate('pluginBench.toast.filledFromFlow'))
  }

  function handlePluginSelect(e) {
    const val = e.target.value
    if (val === '__new__') return
    const found = plugins.find((p) => p.name === val)
    if (found) applyPluginToEditor(found)
  }

  function markDirty() {
    dirty = true
  }

  function handleRuntimeChange() {
    dirty = true
    if (isNew && !editCode.trim()) {
      editCode = makeStarterCode(editRuntime, selectedFlow)
    }
  }

  async function loadPlugins(notify = false) {
    const app = api()
    if (!app) return
    reloading = true
    try {
      const list = notify && app.ReloadPlugins
        ? await app.ReloadPlugins()
        : await app.ListPlugins?.()
      plugins = Array.isArray(list) ? list : []
      if (!isNew) {
        const current = plugins.find((p) => p.name === selectedPluginName)
        if (current && !dirty) {
          applyPluginToEditor(current)
        } else if (!selectedPluginName && plugins.length > 0) {
          applyPluginToEditor(plugins[0])
        } else if (plugins.length === 0 && !editCode) {
          createNewFromFlow()
        }
      }
      if (notify) {
        toast.info(translate('pluginBench.toast.reloaded', { count: plugins.length }))
      }
    } catch (e) {
      if (notify) {
        toast.error(translate('pluginBench.toast.loadFailed', { error: e?.message || e }))
      }
    } finally {
      reloading = false
    }
  }

  async function saveCurrentPlugin() {
    const app = api()
    if (!app?.SavePlugin || saving) return
    const name = (editName || '').trim()
    if (!name) {
      toast.warning(translate('pluginBench.toast.needName'))
      return
    }
    saving = true
    try {
      const draft = { ...buildDraftPlugin(), name }
      await app.SavePlugin(draft)
      isNew = false
      selectedPluginName = name
      dirty = false
      await loadPlugins(false)
      toast.success(translate('pluginBench.toast.saved', { name }))
    } catch (e) {
      toast.error(translate('pluginBench.toast.saveFailed', { error: e?.message || e }))
    } finally {
      saving = false
    }
  }

  async function runDraft() {
    if (!selectedFlow?.id) {
      toast.warning(translate('pluginBench.toast.needFlow'))
      return
    }
    const app = api()
    if (!app || running) return
    running = true
    bottomTab = 'output'
    runWasDraft = dirty || isNew
    const t0 = performance.now()
    try {
      const draft = buildDraftPlugin()
      let res = null
      if (app.RunPluginDraft) {
        res = await app.RunPluginDraft(draft, selectedFlow.id)
      } else if (app.RunPlugin && !isNew && !dirty && selectedPluginName) {
        res = await app.RunPlugin(selectedPluginName, selectedFlow.id)
      } else {
        throw new Error('RunPluginDraft binding unavailable')
      }
      runDurationMs = Math.round(performance.now() - t0)
      if (res?.error) {
        runError = true
        runOutput = res.output ? `${res.output}\n\n[error] ${res.error}` : res.error
        toast.error(translate('pluginBench.toast.runError', { error: res.error }))
      } else {
        runError = false
        runOutput = res?.output ?? ''
        toast.success(translate('pluginBench.toast.runSuccess', { ms: runDurationMs }))
      }
    } catch (e) {
      runDurationMs = Math.round(performance.now() - t0)
      runError = true
      runOutput = String(e?.message || e)
      toast.error(translate('pluginBench.toast.runError', { error: runOutput }))
    } finally {
      running = false
      loadLogs()
    }
  }

  // ==================== Live Flow Payload & Variables ====================
  async function loadFlowPayload(flow) {
    if (!flow?.id) {
      payloadFlowId = ''
      payloadJson = ''
      payloadObj = null
      return
    }
    const seq = ++payloadSeq
    payloadFlowId = flow.id
    const fallback = synthesizeFallbackPayload(flow)
    payloadObj = fallback
    payloadJson = JSON.stringify(fallback, null, 2)

    const app = api()
    if (!app?.GetPluginFlowPayload) return
    payloadLoading = true
    try {
      const raw = await app.GetPluginFlowPayload(flow.id)
      if (seq !== payloadSeq) return
      if (raw && typeof raw === 'string') {
        payloadJson = raw
        try {
          payloadObj = JSON.parse(raw)
        } catch (_) {}
      }
    } catch (_) {
      // Keep fallback synthesized payload on error
    } finally {
      if (seq === payloadSeq) payloadLoading = false
    }
  }

  $: if (selectedFlow?.id !== payloadFlowId) {
    loadFlowPayload(selectedFlow)
    scheduleMatchCheck(0)
  }

  // ==================== Live Match Check ====================
  function matchPatternClient(pattern, target, isPath) {
    const p = (pattern || '').trim()
    if (!p || p === '*') return true
    if (p.length >= 2 && p.startsWith('/') && p.endsWith('/')) {
      try {
        return new RegExp(p.slice(1, -1)).test(target || '')
      } catch (_) {
        return false
      }
    }
    if (p.includes('*')) {
      const escaped = p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
      const prefix = isPath && !p.startsWith('/') && !p.startsWith('*') ? '/?' : ''
      return new RegExp(`^${prefix}${escaped}$`, 'i').test(target || '')
    }
    return String(target || '').toLowerCase().includes(p.toLowerCase())
  }

  function clientFallbackMatch(draft, flow) {
    if (!flow) return null
    if (draft.method && draft.method.toUpperCase() !== String(flow.method || '').toUpperCase()) {
      return false
    }
    const parts = parseUrlParts(flow)
    const rawHost = parts.host || ''
    const hostNoPort = rawHost.replace(/:\d+$/, '')
    if (draft.host_pattern) {
      const okHost =
        matchPatternClient(draft.host_pattern, rawHost, false) ||
        matchPatternClient(draft.host_pattern, hostNoPort, false)
      if (!okHost) return false
    }
    if (draft.path_pattern) {
      const pathWithQuery = parts.query ? `${parts.path}?${parts.query}` : parts.path
      const okPath =
        matchPatternClient(draft.path_pattern, parts.path, true) ||
        matchPatternClient(draft.path_pattern, pathWithQuery, true)
      if (!okPath) return false
    }
    return true
  }

  function scheduleMatchCheck(delay = 140) {
    if (matchCheckTimer) clearTimeout(matchCheckTimer)
    if (!selectedFlow?.id) {
      flowMatchState = null
      return
    }
    matchCheckTimer = setTimeout(runMatchCheck, delay)
  }

  async function runMatchCheck() {
    if (!selectedFlow?.id) {
      flowMatchState = null
      return
    }
    const seq = ++matchCheckSeq
    const draft = buildDraftPlugin()
    const app = api()
    if (app?.TestPluginMatch) {
      try {
        const matched = await app.TestPluginMatch(draft, selectedFlow.id)
        if (seq === matchCheckSeq) flowMatchState = Boolean(matched)
        return
      } catch (_) {}
    }
    if (seq === matchCheckSeq) {
      flowMatchState = clientFallbackMatch(draft, selectedFlow)
    }
  }

  // ==================== Variable Catalog & Runtime-Aware Snippets ====================
  function truncatePreview(val, max = 38) {
    if (val === undefined || val === null || val === '') return translate('pluginBench.schema.emptyValue')
    const s = typeof val === 'string' ? val : JSON.stringify(val)
    const oneLine = s.replace(/\s+/g, ' ').trim()
    if (!oneLine) return translate('pluginBench.schema.emptyValue')
    return oneLine.length > max ? `${oneLine.slice(0, max - 1)}…` : oneLine
  }

  function snippetFor(kind, key, rt) {
    const norm = normalizeRuntime(rt)
    const jqKey = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key) ? `.${key}` : `[${JSON.stringify(key)}]`

    if (kind === 'query_param') {
      if (norm === 'python3') return `flow.get("query_params", {}).get(${JSON.stringify(key)}, "")`
      if (norm === 'node') return `flow.query_params?.[${JSON.stringify(key)}] ?? ""`
      if (norm === 'sh') return `jq -r '.query_params${jqKey} // empty'`
      return `flow.query_params[${JSON.stringify(key)}]`
    }
    if (kind === 'req_header') {
      if (norm === 'python3') return `flow.get("req_headers", {}).get(${JSON.stringify(key)}, "")`
      if (norm === 'node') return `flow.req_headers?.[${JSON.stringify(key)}] ?? ""`
      if (norm === 'sh') return `jq -r '.req_headers[${JSON.stringify(key)}] // empty'`
      return `flow.req_headers[${JSON.stringify(key)}]`
    }
    if (kind === 'resp_header') {
      if (norm === 'python3') return `flow.get("resp_headers", {}).get(${JSON.stringify(key)}, "")`
      if (norm === 'node') return `flow.resp_headers?.[${JSON.stringify(key)}] ?? ""`
      if (norm === 'sh') return `jq -r '.resp_headers[${JSON.stringify(key)}] // empty'`
      return `flow.resp_headers[${JSON.stringify(key)}]`
    }
    if (kind === 'resp_json') {
      if (norm === 'python3') return `json.loads(flow.get("resp_body") or "{}")`
      if (norm === 'node') return `JSON.parse(flow.resp_body || "{}")`
      if (norm === 'sh') return `jq -r '.resp_body | fromjson'`
      return `JSON.parse(flow.resp_body || "{}")`
    }
    if (kind === 'req_json') {
      if (norm === 'python3') return `json.loads(flow.get("req_body") or "{}")`
      if (norm === 'node') return `JSON.parse(flow.req_body || "{}")`
      if (norm === 'sh') return `jq -r '.req_body | fromjson'`
      return `JSON.parse(flow.req_body || "{}")`
    }
    // Top-level field
    if (norm === 'python3') return `flow.get(${JSON.stringify(key)})`
    if (norm === 'node') return `flow.${key}`
    if (norm === 'sh') return `jq -r '.${key} // empty'`
    return `flow.${key}`
  }

  function buildVariableGroups(payload, filterStr) {
    const p = payload || {}
    const q = (filterStr || '').trim().toLowerCase()

    const core = [
      { id: 'id', label: 'id', kind: 'field', key: 'id', type: 'str', preview: truncatePreview(p.id, 18) },
      { id: 'method', label: 'method', kind: 'field', key: 'method', type: 'str', preview: truncatePreview(p.method, 10) },
      { id: 'status', label: 'status', kind: 'field', key: 'status', type: 'int', preview: p.status !== undefined ? String(p.status) : '—' },
      { id: 'latency_ms', label: 'latency_ms', kind: 'field', key: 'latency_ms', type: 'int', preview: p.latency_ms !== undefined ? `${p.latency_ms}ms` : '—' },
      { id: 'scheme', label: 'scheme', kind: 'field', key: 'scheme', type: 'str', preview: truncatePreview(p.scheme, 10) },
      { id: 'host', label: 'host', kind: 'field', key: 'host', type: 'str', preview: truncatePreview(p.host, 28) },
      { id: 'path', label: 'path', kind: 'field', key: 'path', type: 'str', preview: truncatePreview(p.path, 30) },
      { id: 'url', label: 'url', kind: 'field', key: 'url', type: 'str', preview: truncatePreview(p.url, 34) },
      { id: 'query', label: 'query', kind: 'field', key: 'query', type: 'str', preview: truncatePreview(p.query, 28) },
    ]

    const qParamsObj = p.query_params && typeof p.query_params === 'object' ? p.query_params : {}
    const queryEntries = Object.entries(qParamsObj)
    const queryItems = [
      {
        id: 'query_params',
        label: 'query_params',
        kind: 'field',
        key: 'query_params',
        type: 'map',
        preview: `${queryEntries.length} key${queryEntries.length === 1 ? '' : 's'}`,
      },
      ...queryEntries.map(([k, v]) => ({
        id: `qp:${k}`,
        label: `query_params.${k}`,
        kind: 'query_param',
        key: k,
        type: 'str',
        preview: truncatePreview(v, 28),
      })),
    ]

    const reqHeaders = p.req_headers && typeof p.req_headers === 'object' ? p.req_headers : {}
    const respHeaders = p.resp_headers && typeof p.resp_headers === 'object' ? p.resp_headers : {}
    const priorityReq = ['Authorization', 'Cookie', 'Content-Type', 'User-Agent', 'X-Sign', 'X-Token']
    const reqHeaderKeys = [
      ...priorityReq.filter((k) => Object.keys(reqHeaders).some((rk) => rk.toLowerCase() === k.toLowerCase())).map((k) =>
        Object.keys(reqHeaders).find((rk) => rk.toLowerCase() === k.toLowerCase()),
      ),
      ...Object.keys(reqHeaders),
    ]
    const uniqueReqKeys = [...new Set(reqHeaderKeys)].slice(0, 6)
    const uniqueRespKeys = Object.keys(respHeaders).slice(0, 4)

    const headerItems = [
      {
        id: 'req_headers',
        label: 'req_headers',
        kind: 'field',
        key: 'req_headers',
        type: 'map',
        preview: `${Object.keys(reqHeaders).length}`,
      },
      ...uniqueReqKeys.map((k) => ({
        id: `reqh:${k}`,
        label: `req_headers.${k}`,
        kind: 'req_header',
        key: k,
        type: 'str',
        preview: truncatePreview(reqHeaders[k], 24),
      })),
      {
        id: 'resp_headers',
        label: 'resp_headers',
        kind: 'field',
        key: 'resp_headers',
        type: 'map',
        preview: `${Object.keys(respHeaders).length}`,
      },
      ...uniqueRespKeys.map((k) => ({
        id: `resph:${k}`,
        label: `resp_headers.${k}`,
        kind: 'resp_header',
        key: k,
        type: 'str',
        preview: truncatePreview(respHeaders[k], 24),
      })),
    ]

    const bodyItems = [
      { id: 'req_body', label: 'req_body', kind: 'field', key: 'req_body', type: 'str', preview: truncatePreview(p.req_body, 26) },
      { id: 'req_json', label: 'req_body (JSON)', kind: 'req_json', key: 'req_body', type: 'json', preview: 'parse' },
      { id: 'resp_body', label: 'resp_body', kind: 'field', key: 'resp_body', type: 'str', preview: truncatePreview(p.resp_body, 26) },
      { id: 'resp_json', label: 'resp_body (JSON)', kind: 'resp_json', key: 'resp_body', type: 'json', preview: 'parse' },
      {
        id: 'sign_params',
        label: 'sign_params',
        kind: 'field',
        key: 'sign_params',
        type: 'list',
        preview: Array.isArray(p.sign_params) && p.sign_params.length ? p.sign_params.join(', ') : '[]',
      },
    ]

    const groups = [
      { id: 'query', titleKey: 'pluginBench.schema.groupQuery', items: queryItems },
      { id: 'core', titleKey: 'pluginBench.schema.groupCore', items: core },
      { id: 'body', titleKey: 'pluginBench.schema.groupBody', items: bodyItems },
      { id: 'headers', titleKey: 'pluginBench.schema.groupHeaders', items: headerItems },
    ]

    if (!q) return groups
    return groups
      .map((g) => ({
        ...g,
        items: g.items.filter(
          (item) =>
            item.label.toLowerCase().includes(q) ||
            String(item.preview || '').toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.items.length > 0)
  }

  $: variableGroups = buildVariableGroups(payloadObj, varFilter)

  async function insertVariableChip(item) {
    const snippet = snippetFor(item.kind, item.key, editRuntime)
    if (!editorEl) {
      editCode = editCode ? `${editCode}\n${snippet}` : snippet
      dirty = true
      toast.info(translate('pluginBench.toast.insertedVar', { name: item.label }))
      return
    }
    const start = editorEl.selectionStart ?? editCode.length
    const end = editorEl.selectionEnd ?? editCode.length
    editCode = editCode.slice(0, start) + snippet + editCode.slice(end)
    dirty = true
    await tick()
    editorEl.focus()
    const nextPos = start + snippet.length
    editorEl.setSelectionRange(nextPos, nextPos)
    updateCursorPos()
    toast.info(translate('pluginBench.toast.insertedVar', { name: item.label }))
  }

  function updateCursorPos() {
    if (!editorEl) return
    const pos = editorEl.selectionStart ?? 0
    const before = editCode.slice(0, pos)
    const lines = before.split('\n')
    cursorLine = lines.length
    cursorCol = lines[lines.length - 1].length + 1
  }

  function handleEditorKeydown(e) {
    if (e.key === 'Tab') {
      e.preventDefault()
      const start = editorEl.selectionStart
      const end = editorEl.selectionEnd
      editCode = editCode.slice(0, start) + '  ' + editCode.slice(end)
      dirty = true
      tick().then(() => {
        editorEl.setSelectionRange(start + 2, start + 2)
        updateCursorPos()
      })
      return
    }
    if (hasPrimaryMod(e) && e.key.toLowerCase() === 's') {
      e.preventDefault()
      saveCurrentPlugin()
      return
    }
    if (hasPrimaryMod(e) && e.key === 'Enter') {
      e.preventDefault()
      runDraft()
    }
  }

  // ==================== Live Execution Logs ====================
  async function loadLogs() {
    const app = api()
    if (!app?.GetPluginLogs) return
    try {
      const list = await app.GetPluginLogs(100)
      if (Array.isArray(list)) execLogs = list
    } catch (_) {}
  }

  async function clearLogs() {
    const app = api()
    try {
      await app?.ClearPluginLogs?.()
      execLogs = []
      expandedLogIds = new Set()
      toast.info(translate('pluginBench.toast.logsCleared'))
    } catch (_) {}
  }

  function handlePluginExecuted(rec) {
    if (!rec || typeof rec !== 'object') return
    const safeRec = rec.id
      ? rec
      : { ...rec, id: `local-${Date.now()}-${Math.random().toString(36).slice(2, 7)}` }
    const filtered = execLogs.filter((x) => x.id !== safeRec.id)
    execLogs = [safeRec, ...filtered].slice(0, 120)
  }

  function toggleLogExpand(id) {
    const next = new Set(expandedLogIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    expandedLogIds = next
  }

  function handleSelectLogFlow(flowId) {
    if (!flowId) return
    dispatch('selectFlow', { flowId })
  }

  $: visibleLogs = logsOnlyCurrent && editName
    ? execLogs.filter((r) => r.plugin_name === editName.trim())
    : execLogs

  $: runtimeDisplay = $t(`pluginBench.runtimes.${normalizeRuntime(editRuntime)}`)

  onMount(async () => {
    await loadPlugins(false)
    await loadLogs()
    if (selectedFlow) {
      loadFlowPayload(selectedFlow)
      scheduleMatchCheck(0)
    }
    const rt = runtimeApi()
    if (rt?.EventsOn) {
      const off = rt.EventsOn('plugin:executed', handlePluginExecuted)
      if (typeof off === 'function') unsubs.push(off)
    }
  })

  onDestroy(() => {
    if (matchCheckTimer) clearTimeout(matchCheckTimer)
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
  })
</script>

<div class="plugin-workbench" class:compact>
  <!-- 1. Compact Plugin Selector & Action Bar -->
  <div class="wb-toolbar">
    <div class="wb-toolbar-left">
      <div class="select-wrap">
        <Icon name="puzzle" size={13} className="select-icon" />
        <select
          class="plugin-select"
          aria-label={$t('pluginBench.header.pluginSelectAria')}
          value={isNew ? '__new__' : selectedPluginName}
          on:change={handlePluginSelect}
        >
          {#if isNew}
            <option value="__new__">★ {editName || $t('pluginBench.header.newDraftOption')}</option>
          {/if}
          {#if plugins.length === 0 && !isNew}
            <option value="">{$t('pluginBench.header.noPluginsOption')}</option>
          {/if}
          {#each plugins as p (p.name)}
            <option value={p.name}>
              {p.enabled ? '●' : '○'} {p.name} ({p.runtime || 'builtin'}){p.auto_run ? ' ⚡' : ''}
            </option>
          {/each}
        </select>
      </div>

      {#if isNew}
        <input
          type="text"
          class="cap-input name-input mono"
          bind:value={editName}
          on:input={markDirty}
          placeholder={$t('pluginBench.header.namePlaceholder')}
          spellcheck="false"
        />
      {/if}

      {#if dirty || isNew}
        <Badge variant="warning" size="xs">{$t('pluginBench.header.unsavedBadge')}</Badge>
      {/if}
    </div>

    <div class="wb-toolbar-right">
      <Button
        variant="subtle"
        size="xs"
        icon="sparkles"
        title={$t('pluginBench.header.newFromFlowTooltip')}
        on:click={createNewFromFlow}
      >
        {$t('pluginBench.header.newFromFlow')}
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon="target"
        disabled={!selectedFlow}
        title={$t('pluginBench.header.fillFromFlowTooltip')}
        on:click={fillTriggersFromFlow}
      >
        {$t('pluginBench.header.fillFromFlow')}
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon="refresh"
        iconOnly
        loading={reloading}
        title={$t('pluginBench.header.reloadTooltip')}
        on:click={() => loadPlugins(true)}
      />
      <Button
        variant="secondary"
        size="xs"
        icon="save"
        loading={saving}
        disabled={!editName.trim()}
        title={$t('pluginBench.header.saveTooltip', { mod: MOD_LABEL })}
        on:click={saveCurrentPlugin}
      >
        {$t('pluginBench.header.save')}
      </Button>
      <Button
        variant="primary"
        size="xs"
        icon="play"
        loading={running}
        disabled={!selectedFlow}
        title={$t('pluginBench.header.runTooltip', { mod: MOD_LABEL })}
        on:click={runDraft}
      >
        {dirty || isNew ? $t('pluginBench.header.runDraft') : $t('pluginBench.header.run')}
      </Button>
    </div>
  </div>

  <!-- 2. Trigger & Runtime Strip -->
  <div class="trigger-strip">
    <div class="trigger-row">
      <label class="field-inline">
        <span class="field-lbl">{$t('pluginBench.trigger.runtime')}</span>
        <select
          class="mini-select mono"
          bind:value={editRuntime}
          on:change={handleRuntimeChange}
        >
          {#each RUNTIME_OPTIONS as rt}
            <option value={rt}>{$t(`pluginBench.runtimes.${rt}`)}</option>
          {/each}
        </select>
      </label>

      <label class="field-inline">
        <span class="field-lbl">{$t('pluginBench.trigger.method')}</span>
        <select
          class="mini-select mono"
          bind:value={editMethod}
          on:change={() => { markDirty(); scheduleMatchCheck(0) }}
        >
          {#each HTTP_METHODS as m}
            <option value={m}>{m || $t('pluginBench.trigger.anyMethod')}</option>
          {/each}
        </select>
      </label>

      <label class="toggle-chip" class:on={editAutoRun}>
        <input type="checkbox" bind:checked={editAutoRun} on:change={markDirty} />
        <Icon name="zap" size={11} />
        <span>{$t('pluginBench.trigger.autoRun')}</span>
      </label>

      <label class="toggle-chip" class:on={editEnabled}>
        <input type="checkbox" bind:checked={editEnabled} on:change={markDirty} />
        <span>{$t('pluginBench.trigger.enabled')}</span>
      </label>

      <label class="field-inline timeout-field">
        <span class="field-lbl">{$t('pluginBench.trigger.timeout')}</span>
        <input
          type="number"
          min="1"
          max="60"
          class="mini-input mono tabular-nums"
          bind:value={editTimeoutSec}
          on:input={markDirty}
        />
        <span class="unit">{$t('pluginBench.trigger.timeoutUnit')}</span>
      </label>

      <div class="match-pill-wrap">
        {#if !selectedFlow}
          <Badge variant="neutral" size="xs" dot>{$t('pluginBench.trigger.matchNone')}</Badge>
        {:else if flowMatchState === true}
          <Badge variant="success" size="xs" dot>{$t('pluginBench.trigger.matchYes')}</Badge>
        {:else if flowMatchState === false}
          <Badge variant="warning" size="xs" dot>{$t('pluginBench.trigger.matchNo')}</Badge>
        {/if}
      </div>
    </div>

    <div class="trigger-row patterns-row">
      <label class="pattern-field">
        <span class="field-lbl">{$t('pluginBench.trigger.host')}</span>
        <input
          type="text"
          class="cap-input pattern-input mono"
          bind:value={editHostPattern}
          on:input={() => { markDirty(); scheduleMatchCheck() }}
          placeholder={$t('pluginBench.trigger.hostPlaceholder')}
          spellcheck="false"
        />
      </label>
      <label class="pattern-field pattern-path">
        <span class="field-lbl">{$t('pluginBench.trigger.path')}</span>
        <input
          type="text"
          class="cap-input pattern-input mono"
          bind:value={editPathPattern}
          on:input={() => { markDirty(); scheduleMatchCheck() }}
          placeholder={$t('pluginBench.trigger.pathPlaceholder')}
          title={$t('pluginBench.trigger.pathTitle')}
          spellcheck="false"
        />
      </label>
    </div>
  </div>

  <!-- 3. Interactive Flow Variables & stdin JSON Schema Helper -->
  <div class="schema-panel" class:collapsed={schemaTab === 'hide'}>
    <div class="schema-bar">
      <div class="schema-tabs">
        <button
          class="seg-tab"
          class:active={schemaTab === 'variables'}
          on:click={() => (schemaTab = 'variables')}
        >
          <Icon name="code" size={12} />
          <span>{$t('pluginBench.schema.tabVariables')}</span>
        </button>
        <button
          class="seg-tab"
          class:active={schemaTab === 'stdin'}
          on:click={() => (schemaTab = 'stdin')}
        >
          <Icon name="file-code" size={12} />
          <span>{$t('pluginBench.schema.tabStdin')}</span>
        </button>
        <button
          class="seg-tab"
          class:active={schemaTab === 'hide'}
          on:click={() => (schemaTab = 'hide')}
        >
          <Icon name="chevron-up" size={12} />
          <span>{$t('pluginBench.schema.tabHide')}</span>
        </button>
      </div>

      <div class="schema-tools">
        {#if schemaTab === 'variables'}
          <span class="insert-hint truncate">{$t('pluginBench.schema.insertHint', { runtime: runtimeDisplay })}</span>
          <input
            type="text"
            class="var-filter-input"
            bind:value={varFilter}
            placeholder={$t('pluginBench.schema.filterPlaceholder')}
            spellcheck="false"
          />
        {:else if schemaTab === 'stdin' && payloadJson}
          <span class="stdin-meta mono tabular-nums">{formatBytes(payloadJson.length)}</span>
          <Button
            variant="ghost"
            size="xs"
            icon="copy"
            on:click={() => copyToClipboard(payloadJson, translate('pluginBench.schema.copiedJson'))}
          >
            {$t('pluginBench.schema.copyJson')}
          </Button>
        {/if}
      </div>
    </div>

    {#if schemaTab === 'variables'}
      <div class="schema-body vars-body">
        {#if !selectedFlow}
          <div class="schema-empty">{$t('pluginBench.schema.noFlowHint')}</div>
        {:else}
          {#each variableGroups as group (group.id)}
            <div class="var-group">
              <div class="var-group-title">{$t(group.titleKey)}</div>
              <div class="var-chips">
                {#each group.items as item (item.id)}
                  <button
                    class="var-chip"
                    title="{snippetFor(item.kind, item.key, editRuntime)}"
                    on:click={() => insertVariableChip(item)}
                  >
                    <span class="var-name mono">{item.label}</span>
                    <span class="var-type mono">{item.type}</span>
                    <span class="var-val mono truncate">{item.preview}</span>
                  </button>
                {/each}
              </div>
            </div>
          {/each}
        {/if}
      </div>
    {:else if schemaTab === 'stdin'}
      <div class="schema-body stdin-body">
        {#if !selectedFlow}
          <div class="schema-empty">{$t('pluginBench.schema.noFlowHint')}</div>
        {:else if payloadLoading && !payloadJson}
          <div class="schema-empty">{$t('pluginBench.schema.loadingPayload')}</div>
        {:else}
          <pre class="stdin-pre mono">{payloadJson}</pre>
        {/if}
      </div>
    {/if}
  </div>

  <!-- 4. Code Editor + Output / Live Log Split -->
  <div class="editor-split-wrap">
    <SplitPane
      direction="vertical"
      initialSize={58}
      minPrimary={28}
      minSecondary={22}
      storageKey="cap.pluginWorkbench.split"
    >
      <div slot="primary" class="editor-pane">
        <textarea
          bind:this={editorEl}
          bind:value={editCode}
          class="code-editor mono"
          placeholder={$t('pluginBench.editor.placeholder')}
          spellcheck="false"
          autocomplete="off"
          autocapitalize="off"
          on:input={() => { markDirty(); updateCursorPos() }}
          on:click={updateCursorPos}
          on:keyup={updateCursorPos}
          on:keydown={handleEditorKeydown}
        ></textarea>
        <div class="editor-foot">
          <span class="foot-hint">{$t('pluginBench.editor.shortcutHint', { mod: MOD_LABEL })}</span>
          <span class="foot-pos mono tabular-nums">{$t('pluginBench.editor.lineCol', { line: cursorLine, col: cursorCol })}</span>
        </div>
      </div>

      <div slot="secondary" class="bottom-pane">
        <div class="bottom-bar">
          <div class="bottom-tabs">
            <button
              class="seg-tab"
              class:active={bottomTab === 'output'}
              on:click={() => (bottomTab = 'output')}
            >
              <Icon name="terminal" size={12} />
              <span>{$t('pluginBench.output.tabOutput')}</span>
              {#if runDurationMs !== null}
                <Badge variant={runError ? 'danger' : 'success'} size="xs">
                  {runError ? $t('pluginBench.output.statusError') : $t('pluginBench.output.statusOk')}
                </Badge>
              {/if}
            </button>
            <button
              class="seg-tab"
              class:active={bottomTab === 'logs'}
              on:click={() => { bottomTab = 'logs'; loadLogs() }}
            >
              <Icon name="list" size={12} />
              <span>{$t('pluginBench.output.tabLogs')}</span>
              {#if visibleLogs.length > 0}
                <span class="count-pill mono tabular-nums">{visibleLogs.length}/{execLogs.length}</span>
              {/if}
            </button>
          </div>

          <div class="bottom-actions">
            {#if bottomTab === 'output'}
              {#if runDurationMs !== null}
                <Badge variant="neutral" size="xs">
                  {runWasDraft ? $t('pluginBench.output.draftTag') : $t('pluginBench.output.savedTag')}
                </Badge>
                <span class="dur-text mono tabular-nums">{formatDuration(runDurationMs)}</span>
              {/if}
              {#if runOutput}
                <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(runOutput)}>
                  {$t('pluginBench.output.copyOutput')}
                </Button>
                <Button variant="ghost" size="xs" icon="x" on:click={() => { runOutput = ''; runDurationMs = null; runError = false }}>
                  {$t('pluginBench.output.clearOutput')}
                </Button>
              {/if}
            {:else}
              <button
                class="filter-pill"
                class:active={!logsOnlyCurrent}
                on:click={() => (logsOnlyCurrent = false)}
              >
                {$t('pluginBench.logs.filterAll')}
              </button>
              <button
                class="filter-pill"
                class:active={logsOnlyCurrent}
                on:click={() => (logsOnlyCurrent = true)}
              >
                {$t('pluginBench.logs.filterCurrent')}
              </button>
              <Button variant="ghost" size="xs" icon="refresh" iconOnly title={$t('pluginBench.logs.refreshTooltip')} on:click={loadLogs} />
              <Button variant="ghost" size="xs" icon="trash" iconOnly title={$t('pluginBench.logs.clearTooltip')} on:click={clearLogs} />
            {/if}
          </div>
        </div>

        <div class="bottom-body">
          {#if bottomTab === 'output'}
            {#if runDurationMs === null && !runOutput}
              <EmptyState
                compact
                icon="play"
                title={$t('pluginBench.output.emptyTitle')}
                description={selectedFlow
                  ? $t('pluginBench.output.emptyDesc', { mod: MOD_LABEL })
                  : $t('pluginBench.output.noFlowSelected')}
              />
            {:else}
              <pre class="output-pre mono" class:is-error={runError}>{runOutput || $t('pluginBench.output.noOutput')}</pre>
            {/if}
          {:else}
            {#if visibleLogs.length === 0}
              <EmptyState
                compact
                icon="list"
                title={$t('pluginBench.logs.emptyTitle')}
                description={$t('pluginBench.logs.emptyDesc')}
              />
            {:else}
              <div class="logs-list">
                {#each visibleLogs as rec (rec.id)}
                  {@const expanded = expandedLogIds.has(rec.id)}
                  <div class="log-entry" class:has-error={Boolean(rec.error)}>
                    <div class="log-row">
                      <button class="log-expand" on:click={() => toggleLogExpand(rec.id)} aria-label="Toggle output">
                        <Icon name={expanded ? 'chevron-down' : 'chevron-right'} size={12} />
                      </button>
                      <span class="log-time mono tabular-nums">{formatTime(rec.timestamp)}</span>
                      <Badge variant={rec.error ? 'danger' : 'success'} size="xs">
                        {rec.error ? $t('pluginBench.output.statusError') : $t('pluginBench.output.statusOk')}
                      </Badge>
                      <span class="log-plugin mono truncate">{rec.plugin_name}</span>
                      <span class="log-trigger">{rec.trigger === 'auto' ? $t('pluginBench.logs.triggerAuto') : $t('pluginBench.logs.triggerManual')}</span>
                      {#if rec.flow_id}
                        <button
                          class="log-flow-link mono"
                          title={$t('pluginBench.logs.selectFlowTooltip', { id: rec.flow_id })}
                          on:click={() => handleSelectLogFlow(rec.flow_id)}
                        >
                          {rec.method || 'HTTP'} #{String(rec.flow_id).slice(0, 8)}
                        </button>
                      {/if}
                      <span class="log-dur mono tabular-nums">{formatDuration(rec.duration_ms)}</span>
                    </div>
                    {#if expanded}
                      <pre class="log-detail mono" class:is-error={Boolean(rec.error)}>{rec.error ? `${rec.output ? rec.output + '\n' : ''}[error] ${rec.error}` : (rec.output || $t('pluginBench.output.noOutput'))}</pre>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          {/if}
        </div>
      </div>
    </SplitPane>
  </div>
</div>

<style>
  .plugin-workbench {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    min-width: 0;
    min-height: 0;
    background: var(--bg-app);
    overflow: hidden;
  }

  /* ==================== 1. Top Toolbar ==================== */
  .wb-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 7px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .wb-toolbar-left,
  .wb-toolbar-right {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
    flex-wrap: wrap;
  }

  .select-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
    color: var(--accent);
  }

  .select-wrap :global(.select-icon) {
    position: absolute;
    left: 8px;
    pointer-events: none;
  }

  .plugin-select {
    height: 26px;
    max-width: 210px;
    padding: 0 22px 0 26px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: var(--text-xs);
    font-weight: 500;
    outline: none;
    cursor: pointer;
  }

  .plugin-select:focus {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .name-input {
    height: 26px;
    width: 136px;
    font-size: var(--text-xs);
    padding: 0 8px;
  }

  /* ==================== 2. Trigger & Runtime Strip ==================== */
  .trigger-strip {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 7px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .trigger-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .field-inline {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .field-lbl {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .mini-select {
    height: 24px;
    padding: 0 6px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 11px;
    outline: none;
  }

  .mini-input {
    width: 44px;
    height: 24px;
    padding: 0 5px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 11px;
    text-align: center;
    outline: none;
  }

  .unit {
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .toggle-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 24px;
    padding: 0 8px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-subtle);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    user-select: none;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .toggle-chip input {
    display: none;
  }

  .toggle-chip.on {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .match-pill-wrap {
    margin-left: auto;
    display: flex;
    align-items: center;
  }

  .patterns-row {
    gap: 8px;
  }

  .pattern-field {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1 1 160px;
    min-width: 0;
  }

  .pattern-path {
    flex: 1.4 1 200px;
  }

  .pattern-input {
    flex: 1;
    height: 25px;
    font-size: 11.5px;
    padding: 0 8px;
    min-width: 0;
  }

  /* ==================== 3. Interactive Schema / Variables ==================== */
  .schema-panel {
    display: flex;
    flex-direction: column;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .schema-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 4px 10px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .schema-panel.collapsed .schema-bar {
    border-bottom: none;
  }

  .schema-tabs,
  .bottom-tabs {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }

  .seg-tab {
    height: 24px;
    padding: 0 8px;
    border: 1px solid transparent;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .seg-tab:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .seg-tab.active {
    background: var(--bg-active);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .schema-tools {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .insert-hint {
    font-size: 10.5px;
    color: var(--text-faint);
    max-width: 240px;
  }

  .var-filter-input {
    width: 110px;
    height: 22px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 11px;
    outline: none;
  }

  .var-filter-input:focus {
    border-color: var(--accent);
  }

  .stdin-meta {
    font-size: 10.5px;
    color: var(--text-muted);
  }

  .schema-body {
    max-height: 148px;
    overflow-y: auto;
    padding: 7px 10px;
  }

  .schema-empty {
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 8px 2px;
  }

  .vars-body {
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .var-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .var-group-title {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-faint);
  }

  .var-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }

  .var-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    max-width: 260px;
    height: 23px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-surface);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast), color var(--transition-fast);
  }

  .var-chip:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--text-primary);
  }

  .var-name {
    color: var(--accent);
    font-weight: 600;
    flex-shrink: 0;
  }

  .var-type {
    font-size: 9.5px;
    color: var(--text-faint);
    padding: 0 3px;
    border-radius: 3px;
    background: var(--bg-subtle);
    flex-shrink: 0;
  }

  .var-val {
    font-size: 10.5px;
    color: var(--text-muted);
    min-width: 0;
  }

  .stdin-pre {
    margin: 0;
    font-size: 11px;
    line-height: 1.45;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
  }

  /* ==================== 4. Editor + Output Split ==================== */
  .editor-split-wrap {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .editor-pane {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    min-height: 0;
    background: var(--bg-input);
  }

  .code-editor {
    flex: 1;
    width: 100%;
    min-height: 0;
    padding: 10px 12px;
    border: none;
    resize: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 12px;
    line-height: 1.55;
    tab-size: 2;
    outline: none;
  }

  .code-editor:focus-visible {
    box-shadow: none;
  }

  .editor-foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 3px 10px;
    background: var(--bg-header);
    border-top: 1px solid var(--border-subtle);
    font-size: 10.5px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .bottom-pane {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    min-height: 0;
    background: var(--bg-surface);
  }

  .bottom-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 4px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .bottom-actions {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .count-pill {
    font-size: 10px;
    padding: 0 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .dur-text {
    font-size: 10.5px;
    color: var(--text-muted);
  }

  .filter-pill {
    height: 22px;
    padding: 0 7px;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 10.5px;
    cursor: pointer;
  }

  .filter-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
    font-weight: 600;
  }

  .bottom-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 8px 10px;
  }

  .output-pre {
    margin: 0;
    font-size: 11.5px;
    line-height: 1.5;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .output-pre.is-error,
  .log-detail.is-error {
    color: var(--status-danger);
  }

  .logs-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .log-entry {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs);
    background: var(--bg-app);
  }

  .log-entry.has-error {
    border-color: var(--status-danger-border);
  }

  .log-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 7px;
    font-size: 11px;
    min-width: 0;
  }

  .log-expand {
    width: 18px;
    height: 18px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
  }

  .log-expand:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .log-time {
    font-size: 10.5px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .log-plugin {
    font-weight: 600;
    color: var(--text-primary);
    max-width: 130px;
  }

  .log-trigger {
    font-size: 10px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .log-flow-link {
    border: 1px solid var(--accent-border);
    border-radius: var(--radius-xs);
    background: var(--accent-soft);
    color: var(--accent);
    padding: 1px 6px;
    font-size: 10.5px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .log-flow-link:hover {
    filter: brightness(1.1);
  }

  .log-dur {
    margin-left: auto;
    font-size: 10.5px;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .log-detail {
    margin: 0;
    padding: 6px 10px 8px 28px;
    border-top: 1px solid var(--border-subtle);
    font-size: 11px;
    line-height: 1.45;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
    background: var(--bg-input);
  }
</style>
