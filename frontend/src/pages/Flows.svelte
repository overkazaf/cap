<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/core.js'
  import { t, translate } from '../lib/i18n.js'
  import { flowsState as FS } from '../lib/captureState.js'
  import { formatBytes, formatDuration, copyToClipboard } from '../lib/format.js'
  import { isEditableTarget } from '../lib/shortcuts.js'
  import { navigate } from '../lib/navigation.js'
  import { openGatewayPublishFlow } from '../lib/gatewayState.js'
  import { openRecon } from '../lib/reconState.js'
  import { toast } from '../lib/toast.js'
  import { registerCommands } from '../lib/commandPalette.js'

  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Kbd from '../components/Kbd.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import PluginWorkbench from '../components/PluginWorkbench.svelte'

  const appApi = () => window?.go?.wailsgui?.App

  function extractFlowReconHost(flow) {
    if (!flow) return ''
    if (flow.url) {
      try {
        const u = new URL(flow.url)
        if (u.hostname) return u.hostname.replace(/^\[|\]$/g, '')
      } catch (_) {}
    }
    const raw = String(flow.host || '').trim()
    if (!raw) return ''
    if (raw.startsWith('[')) {
      const end = raw.indexOf(']')
      if (end > 1) return raw.slice(1, end)
    }
    return raw.replace(/:\d+$/, '')
  }

  function openFlowInRecon(flow) {
    const host = extractFlowReconHost(flow)
    if (!host) return
    openRecon({ target: host, tab: 'domain', autoRun: true })
  }

  // Flow data & filters
  let flows = []
  let selectedFlow = null
  let detailLoading = false
  let filterHost = FS.filterHost
  let filterMethod = FS.filterMethod
  let filterStatus = FS.filterStatus
  let filterType = FS.filterType
  let filterSearch = FS.filterSearch

  // Workspace layout & modes
  let viewMode = FS.viewMode || 'list' // 'list' | 'grouped'
  let splitDirection = FS.splitDirection || 'horizontal' // 'horizontal' | 'vertical'
  let liveFollow = FS.liveFollow ?? true
  let rightPanel = FS.rightPanel || 'detail' // 'detail' | 'device'
  let activeTab = FS.activeTab || 'params'
  let wordWrap = FS.wordWrap ?? true

  // Inspector sub-states
  let bodyFormat = 'auto' // 'auto' | 'json' | 'xml' | 'proto' | 'hex' | 'raw'
  let bodySearch = ''
  let headerSearch = ''
  let reqHex = ''
  let respHex = ''
  let reqProto = ''
  let respProto = ''
  let hexCache = {}
  let protoCache = {}

  // Export
  let languages = ['curl', 'python', 'go', 'java', 'js']
  let exportLang = FS.exportLang || 'curl'
  let exportCode = ''
  let exportLoading = false

  // Sign analysis
  let signResults = []
  let signLoading = false

  // Replay
  let showReplayEditor = false
  let replayURL = ''
  let replayMethod = ''
  let replayBody = ''
  let replayHeaders = ''
  let replayResult = null
  let replaying = false

  // Compare / Diff
  let compareBaseId = FS.compareBaseId || ''
  let compareBaseLabel = FS.compareBaseLabel || ''
  let compareResult = null
  let compareLoading = false

  // HAR Import & Plugin Output modal
  let showHarImport = false
  let harPath = ''
  let harImporting = false
  let pluginModal = null // { name, output, error }

  // API Groups
  let apiGroups = []

  // Device screen mirror (native MJPEG stream) & shell
  let screenSrc = ''
  let streamUrl = ''
  let screenActive = false
  let screenStarting = false
  let screenInterrupted = false
  let screenError = ''
  let screenStartSeq = 0
  let screenSize = [1080, 2400]
  let deviceSerial = ''
  let screenQuality = 70 // 35 = Low 320p, 70 = Balanced 540p, 90 = HD 720p
  let screenEngine = 'auto' // 'auto' | 'scrcpy' | 'fast'
  let activeScreenEngine = '' // 'scrcpy' | 'fast' | ''
  let screenFallbackReason = ''
  let scrcpyReady = false
  let scrcpyDeploying = false
  let streamStats = { active: false, engine: '', fps: 0, latency_ms: 0, frames: 0, errors: 0 }
  let statsTimer = null
  let statsInFlight = false
  let fallbackTimer = null
  let fallbackInFlight = false
  let qualityDebounceTimer = null
  let screenImgEl = null
  let screenBoxEl = null
  let pointerGesture = null // { pointerId, startX, startY, curX, curY, startTime, devX1, devY1, devX2, devY2, isDrag }
  let tapRipple = null // { x, y, id }
  let tapRippleTimer = null
  let shellTabs = []
  let activeShellTab = null
  let shellTabCounter = 0

  // Capture pause & events
  let capturePaused = false
  let unsubs = []
  let flowRefreshTimer = null
  let searchDebounceTimer = null
  let pollInterval = null
  let unregisterCmds = null

  function debouncedLoadFlows() {
    clearTimeout(searchDebounceTimer)
    searchDebounceTimer = setTimeout(loadFlows, 120)
  }

  // Context menu & Rules/Plugins
  let ctxMenu = null // { x, y, flow }
  let pluginList = []
  let activeRules = []

  // DOM refs
  let searchInputEl = null
  let listBodyEl = null

  // Persist lightweight UI state across route switches
  $: {
    FS.filterHost = filterHost
    FS.filterMethod = filterMethod
    FS.filterStatus = filterStatus
    FS.filterType = filterType
    FS.filterSearch = filterSearch
    FS.viewMode = viewMode
    FS.splitDirection = splitDirection
    FS.liveFollow = liveFollow
    FS.rightPanel = rightPanel
    FS.activeTab = activeTab
    FS.exportLang = exportLang
    FS.wordWrap = wordWrap
    FS.compareBaseId = compareBaseId
    FS.compareBaseLabel = compareBaseLabel
  }

  const METHODS = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
  $: STATUS_CLASSES = [
    { id: '', label: $t('core.flows.facetAll') },
    { id: '2xx', label: '2xx' },
    { id: '3xx', label: '3xx' },
    { id: '4xx', label: '4xx' },
    { id: '5xx', label: '5xx' },
  ]
  $: CONTENT_TYPES = [
    { id: '', label: $t('core.flows.facetAllTypes') },
    { id: 'json', label: $t('core.flows.facetJson') },
    { id: 'html', label: $t('core.flows.facetHtml') },
    { id: 'xml', label: $t('core.flows.facetXml') },
    { id: 'form', label: $t('core.flows.facetForm') },
    { id: 'text', label: $t('core.flows.facetText') },
    { id: 'media', label: $t('core.flows.facetMedia') },
  ]

  function classifyContentType(bodyType) {
    const bt = String(bodyType || '').toLowerCase()
    if (!bt) return 'other'
    if (bt.includes('json')) return 'json'
    if (bt.includes('html')) return 'html'
    if (bt.includes('xml')) return 'xml'
    if (bt.includes('form') || bt.includes('urlencoded') || bt.includes('multipart')) return 'form'
    if (bt.includes('image') || bt.includes('video') || bt.includes('audio') || bt.includes('font')) return 'media'
    if (bt.includes('text') || bt.includes('javascript') || bt.includes('css')) return 'text'
    return 'other'
  }

  function shortContentType(bodyType) {
    const bt = String(bodyType || '').toLowerCase()
    if (!bt) return '—'
    if (bt.includes('json')) return 'json'
    if (bt.includes('html')) return 'html'
    if (bt.includes('xml')) return 'xml'
    if (bt.includes('form') || bt.includes('urlencoded')) return 'form'
    if (bt.includes('javascript')) return 'js'
    if (bt.includes('css')) return 'css'
    if (bt.includes('protobuf') || bt.includes('grpc')) return 'proto'
    if (bt.includes('image')) return 'img'
    if (bt.includes('octet-stream')) return 'bin'
    if (bt.includes('text/plain')) return 'txt'
    const slash = bt.indexOf('/')
    if (slash >= 0) {
      return bt.slice(slash + 1).split(';')[0].slice(0, 6)
    }
    return bt.slice(0, 6)
  }

  function matchStatusFilter(status, facet) {
    if (!facet) return true
    const s = Number(status) || 0
    if (facet === '2xx') return s >= 200 && s < 300
    if (facet === '3xx') return s >= 300 && s < 400
    if (facet === '4xx') return s >= 400 && s < 500
    if (facet === '5xx') return s >= 500
    return true
  }

  function splitPathQuery(f) {
    try {
      const u = new URL(f.url)
      return { path: u.pathname || f.path || '/', query: u.search || '' }
    } catch (_) {
      const raw = String(f.path || '/')
      const qIdx = raw.indexOf('?')
      if (qIdx >= 0) return { path: raw.slice(0, qIdx), query: raw.slice(qIdx) }
      return { path: raw, query: '' }
    }
  }

  // Distinct hosts for quick filter dropdown/chips
  $: distinctHosts = Array.from(new Set(flows.map((f) => f.host).filter(Boolean))).slice(0, 20)

  // Client-side facet filtering on top of backend GetFlows results
  $: filteredFlows = flows.filter((f) => {
    if (!matchStatusFilter(f.status, filterStatus)) return false
    if (filterType && classifyContentType(f.body_type) !== filterType) return false
    return true
  })

  $: maxLatency = filteredFlows.reduce((max, f) => Math.max(max, Number(f.latency_ms) || 0), 1)
  $: hasActiveFilters = Boolean(filterHost || filterMethod || filterStatus || filterType || filterSearch)

  function latencyTone(ms) {
    const n = Number(ms) || 0
    if (n >= 1000) return 'slow'
    if (n >= 300) return 'med'
    return 'fast'
  }

  function resetFilters() {
    filterHost = ''
    filterMethod = ''
    filterStatus = ''
    filterType = ''
    filterSearch = ''
    loadFlows()
  }

  // ==================== Backend Calls ====================

  async function loadFlows() {
    const api = appApi()
    if (!api?.GetFlows) return
    try {
      const prevTopId = flows[0]?.id
      const res = (await api.GetFlows(filterHost, filterMethod, filterSearch, 0)) || []
      flows = res
      if (liveFollow && listBodyEl && res.length > 0 && res[0]?.id !== prevTopId) {
        await tick()
        listBodyEl.scrollTop = 0
      }
    } catch (e) {
      console.error(e)
    }
  }

  function queueFlowRefresh() {
    clearTimeout(flowRefreshTimer)
    flowRefreshTimer = setTimeout(() => {
      loadFlows()
      if (viewMode === 'grouped') loadGroups()
    }, 100)
  }

  async function loadPlugins() {
    try {
      pluginList = (await appApi()?.ListPlugins?.()) || []
    } catch (_) {}
  }

  async function loadActiveRules() {
    try {
      activeRules = (await appApi()?.ListRules?.()) || []
    } catch (_) {}
  }

  async function loadLanguages() {
    try {
      const langs = await appApi()?.GetLanguages?.()
      if (Array.isArray(langs) && langs.length > 0) languages = langs
    } catch (_) {}
  }

  async function toggleCapturePause() {
    const api = appApi()
    if (!api) return
    try {
      if (capturePaused) {
        await api.ResumeCapture()
        capturePaused = false
        toast.info(translate('core.flows.toast.captureResumed'))
      } else {
        await api.PauseCapture()
        capturePaused = true
        toast.warning(translate('core.flows.toast.capturePaused'))
      }
    } catch (e) {
      toast.error(translate('core.flows.toast.captureToggleFailed', { err: e }))
    }
  }

  async function clearFlows() {
    const api = appApi()
    if (!api?.ClearFlows) return
    try {
      await api.ClearFlows()
      flows = []
      apiGroups = []
      selectedFlow = null
      exportCode = ''
      signResults = []
      replayResult = null
      compareResult = null
      hexCache = {}
      protoCache = {}
      toast.success(translate('core.flows.toast.clearedFlows'))
    } catch (e) {
      toast.error(translate('core.flows.toast.clearFailed', { err: e }))
    }
  }

  async function selectFlow(f, opts = {}) {
    if (!f) return
    const api = appApi()
    if (!api?.GetFlowDetail) return
    detailLoading = true
    try {
      selectedFlow = await api.GetFlowDetail(f.id)
      if (opts.openPlugins) {
        if (screenActive || screenStarting) stopScreen()
        rightPanel = 'plugins'
      } else if (opts.forceDetail || rightPanel !== 'plugins') {
        if (screenActive || screenStarting) stopScreen()
        rightPanel = 'detail'
      }
      bodyFormat = 'auto'
      bodySearch = ''
      headerSearch = ''
      signResults = []
      replayResult = null
      showReplayEditor = false
      compareResult = null
      reqHex = ''
      respHex = ''
      reqProto = ''
      respProto = ''
      if (activeTab === 'export') {
        generateExport()
      }
    } catch (e) {
      toast.error(translate('core.flows.toast.loadDetailFailed', { id: f.id, err: e }))
    }
    detailLoading = false
  }

  async function selectFlowById(flowId) {
    if (!flowId) return
    const match = flows.find((item) => item.id === flowId) || { id: flowId }
    await selectFlow(match)
    await tick()
    const row = listBodyEl?.querySelector(`[data-flow-id="${CSS.escape(String(flowId))}"]`)
    row?.scrollIntoView({ block: 'nearest' })
  }

  async function generateExport() {
    if (!selectedFlow) return
    const api = appApi()
    if (!api?.ExportCode) return
    exportLoading = true
    try {
      if (exportLang === 'jsonl') {
        exportCode = await api.ExportAgent()
      } else {
        exportCode = await api.ExportCode(selectedFlow.id, exportLang)
      }
    } catch (e) {
      exportCode = `Error: ${e}`
    }
    exportLoading = false
  }

  async function exportAgentJSONL() {
    const api = appApi()
    if (!api?.ExportAgent) return
    exportLoading = true
    try {
      const code = await api.ExportAgent()
      exportLang = 'jsonl'
      exportCode = code
      if (selectedFlow) {
        activeTab = 'export'
        rightPanel = 'detail'
      } else {
        await copyToClipboard(code, translate('core.flows.toast.copiedJsonl'))
      }
    } catch (e) {
      toast.error(translate('core.flows.toast.exportJsonlFailed', { err: e }))
    }
    exportLoading = false
  }

  async function copyAsCurl(flowId) {
    const api = appApi()
    if (!api?.ExportCode) return
    try {
      const code = await api.ExportCode(flowId, 'curl')
      await copyToClipboard(code, translate('core.flows.toast.copiedCurl'))
    } catch (e) {
      toast.error(translate('core.flows.toast.curlFailed', { err: e }))
    }
  }

  async function importHar() {
    const api = appApi()
    if (!api?.ImportHARFile || !harPath.trim()) return
    harImporting = true
    try {
      const count = await api.ImportHARFile(harPath.trim())
      toast.success(translate('core.flows.toast.harImported', { count }))
      showHarImport = false
      harPath = ''
      await loadFlows()
    } catch (e) {
      toast.error(translate('core.flows.toast.harFailed', { err: e }))
    }
    harImporting = false
  }

  async function analyzeSign() {
    if (!selectedFlow) return
    const api = appApi()
    if (!api?.AnalyzeSign) return
    signLoading = true
    try {
      signResults = (await api.AnalyzeSign(selectedFlow.id)) || []
      if (signResults.length === 0) {
        toast.info(translate('core.flows.toast.noSignDetected'))
      }
    } catch (e) {
      signResults = [{ param_name: 'error', value: String(e), encoding: '', possible_algs: [], confidence: 0 }]
    }
    signLoading = false
  }

  async function replayFlow(flowId = null) {
    const id = flowId || selectedFlow?.id
    if (!id) return
    const api = appApi()
    if (!api?.ReplayFlow) return
    replaying = true
    try {
      replayResult = await api.ReplayFlow(id)
      toast.success(translate('core.flows.toast.replayed', { status: replayResult.status, ms: replayResult.latency_ms }))
    } catch (e) {
      replayResult = { error: String(e) }
      toast.error(translate('core.flows.toast.replayFailed', { err: e }))
    }
    replaying = false
  }

  async function replayModified() {
    if (!selectedFlow) return
    const api = appApi()
    if (!api?.ReplayModified) return
    replaying = true
    let setHeaders = {}
    if (replayHeaders.trim()) {
      for (const line of replayHeaders.split('\n')) {
        const idx = line.indexOf(':')
        if (idx > 0) setHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
      }
    }
    try {
      replayResult = await api.ReplayModified({
        flow_id: selectedFlow.id,
        url: replayURL || '',
        method: replayMethod || '',
        set_headers: setHeaders,
        del_headers: [],
        body: replayBody || '',
      })
      toast.success(translate('core.flows.toast.modifiedReplayed', { status: replayResult.status, ms: replayResult.latency_ms }))
    } catch (e) {
      replayResult = { error: String(e) }
      toast.error(translate('core.flows.toast.replayFailed', { err: e }))
    }
    replaying = false
  }

  function openReplayEditor() {
    if (!selectedFlow) return
    replayURL = selectedFlow.url
    replayMethod = selectedFlow.method
    replayBody = selectedFlow.req_body || ''
    replayHeaders = Object.entries(selectedFlow.req_headers || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n')
    replayResult = null
    showReplayEditor = !showReplayEditor
  }

  // ==================== Flow Compare / Diff ====================

  function pinCompareBase(f) {
    if (!f) return
    compareBaseId = f.id
    compareBaseLabel = `#${f.id} ${f.method} ${f.path}`
    toast.info(translate('core.flows.toast.pinnedCompare', { id: f.id }))
  }

  function clearCompareBase() {
    compareBaseId = ''
    compareBaseLabel = ''
    compareResult = null
  }

  async function runCompareWith(targetFlow) {
    if (!compareBaseId || !targetFlow) return
    const api = appApi()
    if (!api?.CompareFlows) return
    compareLoading = true
    try {
      compareResult = await api.CompareFlows(compareBaseId, targetFlow.id)
      rightPanel = 'detail'
    } catch (e) {
      toast.error(translate('core.flows.toast.compareFailed', { err: e }))
    }
    compareLoading = false
  }

  // ==================== Rules & Context Menu ====================

  function matchingRule(f) {
    return activeRules.find(
      (r) =>
        r.enabled &&
        (!r.match?.method || r.match.method === f.method) &&
        (!r.match?.host || f.host.includes(r.match.host)) &&
        (!r.match?.path || f.path.includes(r.match.path))
    )
  }

  function ruleIconName(rule) {
    if (!rule) return ''
    switch (rule.action?.type) {
      case 'breakpoint': return 'pause'
      case 'mock': return 'layers'
      case 'modify_request':
      case 'modify_response': return 'edit'
      case 'drop': return 'ban'
      default: return 'target'
    }
  }

  function showContextMenu(e, f) {
    e.preventDefault()
    const menuW = 240
    const menuH = 320
    const x = Math.min(e.clientX, window.innerWidth - menuW - 8)
    const y = Math.min(e.clientY, window.innerHeight - menuH - 8)
    ctxMenu = { x: Math.max(8, x), y: Math.max(8, y), flow: f }
  }

  function hideContextMenu() {
    ctxMenu = null
  }

  async function ctxAddRule(type, name, action) {
    if (!ctxMenu) return
    const f = ctxMenu.flow
    try {
      await appApi().AddRule({
        id: 'r-' + Date.now(),
        name,
        enabled: true,
        priority: type === 'breakpoint' ? 5 : 10,
        match: { method: f.method, host: f.host, path: f.path },
        action,
      })
      await loadActiveRules()
      hideContextMenu()
      toast.success(translate('core.flows.toast.ruleCreated', { name }), {
        action: { label: translate('core.flows.toast.openRules'), onClick: () => navigate('rules') },
      })
    } catch (e) {
      toast.error(translate('core.flows.toast.addRuleFailed', { err: e }))
    }
  }

  function ctxAddBreakpoint() {
    const f = ctxMenu?.flow
    if (!f) return
    ctxAddRule('breakpoint', `Break ${f.method} ${f.path}`, { type: 'breakpoint', break_on_req: true, break_on_resp: false })
  }

  function ctxAddMockRule() {
    const f = ctxMenu?.flow
    if (!f) return
    ctxAddRule('mock', `Mock ${f.method} ${f.path}`, { type: 'mock', mock_status: 200, mock_body: '', mock_headers: {} })
  }

  function ctxAddModifyRule() {
    const f = ctxMenu?.flow
    if (!f) return
    ctxAddRule('modify', `Modify ${f.method} ${f.path}`, { type: 'modify_request', set_headers: {}, del_headers: [] })
  }

  function ctxAddDropRule() {
    const f = ctxMenu?.flow
    if (!f) return
    ctxAddRule('drop', `Block ${f.host}${f.path}`, { type: 'drop' })
  }

  async function ctxRunPlugin(pluginName) {
    if (!ctxMenu) return
    const flowId = ctxMenu.flow.id
    hideContextMenu()
    try {
      const result = await appApi().RunPlugin(pluginName, flowId)
      pluginModal = {
        name: pluginName,
        flowId,
        output: result?.output || '',
        error: result?.error || '',
      }
    } catch (e) {
      toast.error(translate('core.flows.toast.pluginError', { name: pluginName, err: e }))
    }
  }

  // ==================== Body Parsing, Formatting & Syntax Highlighting ====================

  function parseParams(flow) {
    if (!flow) return []
    const params = []
    try {
      const url = new URL(flow.url)
      for (const [k, v] of url.searchParams) {
        params.push({ source: 'query', key: k, value: v })
      }
    } catch (_) {}

    const reqCT =
      Object.entries(flow.req_headers || {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1] || ''

    if (flow.req_body && (reqCT.includes('form') || (flow.body_type && flow.body_type.includes('form')))) {
      try {
        for (const pair of flow.req_body.split('&')) {
          if (!pair) continue
          const [k, ...rest] = pair.split('=')
          params.push({
            source: 'form',
            key: decodeURIComponent(k || ''),
            value: decodeURIComponent(rest.join('=') || ''),
          })
        }
      } catch (_) {}
    }

    if (flow.req_body) {
      try {
        const obj = JSON.parse(flow.req_body)
        if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
          for (const [k, v] of Object.entries(obj)) {
            params.push({
              source: 'json',
              key: k,
              value: typeof v === 'object' ? JSON.stringify(v) : String(v),
            })
          }
        }
      } catch (_) {}
    }
    return params
  }

  function isSignParam(key, flow) {
    const sp = flow?.sign_params || []
    return sp.some((p) => p.toLowerCase() === String(key).toLowerCase())
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  }

  function formatXmlPretty(xml) {
    try {
      const reg = /(>)(<)(\/*)/g
      const formatted = xml.replace(reg, '$1\n$2$3')
      let pad = 0
      return formatted
        .split('\n')
        .map((line) => {
          let indent = 0
          if (line.match(/.+<\/\w[^>]*>$/)) indent = 0
          else if (line.match(/^<\/\w/)) {
            if (pad > 0) pad -= 1
          } else if (line.match(/^<\w([^>]*[^/])?>.*$/)) indent = 1
          const out = '  '.repeat(pad) + line
          pad += indent
          return out
        })
        .join('\n')
    } catch (_) {
      return xml
    }
  }

  function detectFormat(body, contentType) {
    if (!body) return 'raw'
    const ct = String(contentType || '').toLowerCase()
    const trimmed = body.trim()
    if (ct.includes('json') || ((trimmed.startsWith('{') || trimmed.startsWith('[')) && trimmed.length < 400000)) {
      try {
        JSON.parse(body)
        return 'json'
      } catch (_) {}
    }
    if (ct.includes('xml') || ct.includes('html') || trimmed.startsWith('<')) {
      return 'xml'
    }
    return 'raw'
  }

  function getFormattedBodyText(body, contentType, fmt) {
    if (!body) return ''
    if (fmt === 'raw') return body
    const effective = fmt === 'auto' ? detectFormat(body, contentType) : fmt
    if (effective === 'json') {
      try {
        return JSON.stringify(JSON.parse(body), null, 2)
      } catch (_) {
        return body
      }
    }
    if (effective === 'xml') {
      return formatXmlPretty(body)
    }
    return body
  }

  function highlightJson(text) {
    const escaped = escapeHtml(text)
    return escaped.replace(
      /(&quot;(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\&]|&(?!quot;))*&quot;(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (match, _g1, isKey) => {
        if (match.startsWith('&quot;')) {
          if (isKey) return `<span class="hl-key">${match}</span>`
          return `<span class="hl-str">${match}</span>`
        }
        if (match === 'true' || match === 'false') return `<span class="hl-bool">${match}</span>`
        if (match === 'null') return `<span class="hl-null">${match}</span>`
        return `<span class="hl-num">${match}</span>`
      }
    )
  }

  function highlightXml(text) {
    const escaped = escapeHtml(text)
    return escaped.replace(
      /(&lt;\/?)([\w:-]+)([^&]*?)(\/?&gt;)/g,
      (_m, open, tag, attrs, close) => {
        const hlAttrs = attrs.replace(
          /([\w:-]+)(=)(&quot;[^&]*?&quot;)/g,
          '<span class="hl-key">$1</span>$2<span class="hl-str">$3</span>'
        )
        return `<span class="hl-punct">${open}</span><span class="hl-tag">${tag}</span>${hlAttrs}<span class="hl-punct">${close}</span>`
      }
    )
  }

  function applySearchHighlight(escapedOrPlain, query, isPlain) {
    const q = query.trim()
    if (!q) return { html: isPlain ? escapeHtml(escapedOrPlain) : escapedOrPlain, matches: 0 }
    const safeQ = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const re = new RegExp(safeQ, 'gi')
    let count = 0
    if (isPlain) {
      const parts = String(escapedOrPlain).split(re)
      const matches = String(escapedOrPlain).match(re) || []
      count = matches.length
      let out = ''
      for (let i = 0; i < parts.length; i++) {
        out += escapeHtml(parts[i])
        if (i < matches.length) {
          out += `<mark class="hl-match">${escapeHtml(matches[i])}</mark>`
        }
      }
      return { html: out, matches: count }
    }
    return { html: escapedOrPlain, matches: 0 }
  }

  function renderHighlightedBody(body, contentType, fmt, query) {
    if (!body) return { html: '', matches: 0, effective: 'raw' }
    if (fmt === 'hex' || fmt === 'proto') {
      const res = applySearchHighlight(body, query, true)
      return { ...res, effective: fmt }
    }
    const formatted = getFormattedBodyText(body, contentType, fmt)
    const effective = fmt === 'auto' ? detectFormat(body, contentType) : fmt
    if (query.trim()) {
      const res = applySearchHighlight(formatted, query, true)
      return { ...res, effective }
    }
    // Performance guard for huge payloads (>250KB)
    if (formatted.length > 250000) {
      return { html: escapeHtml(formatted), matches: 0, effective: 'raw' }
    }
    if (effective === 'json') {
      return { html: highlightJson(formatted), matches: 0, effective }
    }
    if (effective === 'xml') {
      return { html: highlightXml(formatted), matches: 0, effective }
    }
    return { html: escapeHtml(formatted), matches: 0, effective }
  }

  function formatHex(hexStr) {
    if (!hexStr || hexStr === '(empty)') return hexStr || ''
    const lines = []
    for (let i = 0; i < hexStr.length; i += 32) {
      const chunk = hexStr.slice(i, i + 32)
      const offset = (i / 2).toString(16).padStart(8, '0')
      const pairs = chunk.match(/.{1,2}/g) || []
      const ascii = pairs
        .map((h) => {
          const c = parseInt(h, 16)
          return c >= 32 && c < 127 ? String.fromCharCode(c) : '.'
        })
        .join('')
      lines.push(`${offset}  ${pairs.join(' ').padEnd(48)}  ${ascii}`)
    }
    return lines.join('\n')
  }

  async function loadHexFor(isReq) {
    if (!selectedFlow) return ''
    const key = `${selectedFlow.id}-${isReq}`
    if (!hexCache[key]) {
      try {
        hexCache[key] = await appApi().GetBodyHex(selectedFlow.id, isReq)
      } catch (e) {
        hexCache[key] = `Error: ${e}`
      }
    }
    return formatHex(hexCache[key])
  }

  async function loadProtoFor(isReq) {
    if (!selectedFlow) return ''
    const key = `${selectedFlow.id}-${isReq}`
    if (!protoCache[key]) {
      try {
        protoCache[key] = await appApi().DecodeProtobuf(selectedFlow.id, isReq)
      } catch (e) {
        protoCache[key] = `Error: ${e}`
      }
    }
    return protoCache[key]
  }

  async function switchBodyFormat(fmt) {
    bodyFormat = fmt
    if (!selectedFlow) return
    if (fmt === 'hex') {
      reqHex = await loadHexFor(true)
      respHex = await loadHexFor(false)
    } else if (fmt === 'proto') {
      reqProto = await loadProtoFor(true)
      respProto = await loadProtoFor(false)
    }
  }

  function buildRawRequest(flow) {
    if (!flow) return ''
    const { path, query } = splitPathQuery(flow)
    const lines = [`${flow.method} ${path}${query} HTTP/1.1`, `Host: ${flow.host}`]
    for (const [k, v] of Object.entries(flow.req_headers || {})) {
      if (k.toLowerCase() !== 'host') lines.push(`${k}: ${v}`)
    }
    lines.push('')
    if (flow.req_body) lines.push(flow.req_body)
    return lines.join('\n')
  }

  function buildRawResponse(flow) {
    if (!flow) return ''
    const lines = [`HTTP/1.1 ${flow.status}`]
    for (const [k, v] of Object.entries(flow.resp_headers || {})) {
      lines.push(`${k}: ${v}`)
    }
    lines.push('')
    if (flow.resp_body) lines.push(flow.resp_body)
    return lines.join('\n')
  }

  function filterHeaderEntries(headersObj, q) {
    const entries = Object.entries(headersObj || {}).sort(([a], [b]) => a.localeCompare(b))
    const term = q.trim().toLowerCase()
    if (!term) return entries
    return entries.filter(([k, v]) => k.toLowerCase().includes(term) || String(v).toLowerCase().includes(term))
  }

  function byteLength(str) {
    if (!str) return 0
    return new Blob([str]).size
  }

  function headersByteLength(obj) {
    return Object.entries(obj || {}).reduce((acc, [k, v]) => acc + k.length + String(v).length + 4, 0)
  }

  // Reactive inspector derived views
  $: selectedParams = selectedFlow ? parseParams(selectedFlow) : []
  $: reqHeaderCount = Object.keys(selectedFlow?.req_headers || {}).length
  $: respHeaderCount = Object.keys(selectedFlow?.resp_headers || {}).length
  $: reqBodySize = byteLength(selectedFlow?.req_body)
  $: respBodySize = byteLength(selectedFlow?.resp_body)
  $: reqContentType =
    Object.entries(selectedFlow?.req_headers || {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1] || ''
  $: respContentType =
    selectedFlow?.body_type ||
    Object.entries(selectedFlow?.resp_headers || {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1] ||
    ''

  $: reqBodyView =
    activeTab === 'req-body' && selectedFlow
      ? renderHighlightedBody(
          bodyFormat === 'hex' ? reqHex : bodyFormat === 'proto' ? reqProto : selectedFlow.req_body,
          reqContentType,
          bodyFormat,
          bodySearch
        )
      : { html: '', matches: 0, effective: 'raw' }

  $: respBodyView =
    activeTab === 'resp-body' && selectedFlow
      ? renderHighlightedBody(
          bodyFormat === 'hex' ? respHex : bodyFormat === 'proto' ? respProto : selectedFlow.resp_body,
          respContentType,
          bodyFormat,
          bodySearch
        )
      : { html: '', matches: 0, effective: 'raw' }

  $: filteredReqHeaders = filterHeaderEntries(selectedFlow?.req_headers, headerSearch)
  $: filteredRespHeaders = filterHeaderEntries(selectedFlow?.resp_headers, headerSearch)

  function switchTab(tabId) {
    activeTab = tabId
    if (tabId === 'export' && selectedFlow) {
      generateExport()
    }
  }

  // ==================== API Groups ====================

  async function loadGroups() {
    try {
      apiGroups = (await appApi()?.GetAPIGroups?.()) || []
    } catch (e) {
      console.error(e)
    }
  }

  function setViewMode(mode) {
    viewMode = mode
    if (mode === 'grouped') loadGroups()
  }

  // ==================== Device Screen Mirror (Native MJPEG) & Shell ====================

  const QUALITY_PRESETS = [
    { value: 35, labelKey: 'core.flows.devQualityLow' },
    { value: 70, labelKey: 'core.flows.devQualityBalanced' },
    { value: 90, labelKey: 'core.flows.devQualityHd' },
  ]

  function clearStreamTimers() {
    if (statsTimer) {
      clearInterval(statsTimer)
      statsTimer = null
    }
    if (fallbackTimer) {
      clearTimeout(fallbackTimer)
      fallbackTimer = null
    }
    if (qualityDebounceTimer) {
      clearTimeout(qualityDebounceTimer)
      qualityDebounceTimer = null
    }
    if (tapRippleTimer) {
      clearTimeout(tapRippleTimer)
      tapRippleTimer = null
    }
  }

  async function pollStreamStats() {
    if (!screenActive || statsInFlight) return
    const api = appApi()
    if (!api?.GetScreenStreamStats) return
    statsInFlight = true
    try {
      const st = await api.GetScreenStreamStats()
      if (st && screenActive) {
        streamStats = st
        if (st.engine) activeScreenEngine = st.engine
        if (st.width > 0 && st.height > 0) screenSize = [st.width, st.height]
      }
    } catch (_) {}
    statsInFlight = false
  }

  async function startScreen() {
    const api = appApi()
    if (!api) return
    const seq = ++screenStartSeq
    clearStreamTimers()
    screenStarting = true
    screenInterrupted = false
    screenError = ''
    screenFallbackReason = ''
    streamUrl = ''
    screenSrc = ''

    try {
      const devs = await api.ListDevices?.()
      if (seq !== screenStartSeq) return
      if (devs && devs.length > 0) {
        if (!devs.some((d) => d.serial === deviceSerial)) {
          deviceSerial = devs[0].serial
        }
      } else {
        deviceSerial = ''
        screenActive = false
        screenStarting = false
        return
      }
    } catch (e) {
      if (seq !== screenStartSeq) return
      screenError = String(e)
      screenActive = false
      screenStarting = false
      return
    }

    if (shellTabs.length === 0) addShellTab()

    // Prefer native loopback HTTP MJPEG stream (WebKit C++ off-main-thread decode)
    if (api.StartScreenStream) {
      try {
        const targetFps = screenEngine === 'fast' ? 15 : 30
        const info = await api.StartScreenStream(deviceSerial, screenEngine, screenQuality, targetFps)
        if (seq !== screenStartSeq) {
          api.StopScreenStream?.().catch(() => {})
          return
        }
        streamUrl = info?.url || ''
        activeScreenEngine = info?.engine || (screenEngine === 'auto' ? 'fast' : screenEngine)
        scrcpyReady = Boolean(info?.scrcpy_ready)
        screenFallbackReason = info?.fallback_reason || ''
        if (info?.width > 0 && info?.height > 0) {
          screenSize = [info.width, info.height]
        }
        screenActive = true
        screenStarting = false
        streamStats = {
          active: true,
          engine: activeScreenEngine,
          fps: 0,
          latency_ms: 0,
          frames: 0,
          errors: 0,
        }
        pollStreamStats()
        statsTimer = setInterval(pollStreamStats, 1500)
        return
      } catch (e) {
        if (seq !== screenStartSeq) return
        screenError = String(e)
        screenActive = false
        screenStarting = false
        toast.error(translate('core.flows.devStreamError', { err: e }))
        return
      }
    }

    // Legacy single-flight guarded fallback (only if StartScreenStream is unavailable)
    try {
      const sz = await api.GetScreenSize?.(deviceSerial)
      if (Array.isArray(sz) && sz.length === 2) screenSize = sz
      scrcpyReady = Boolean(await api.IsScrcpyReady?.(deviceSerial))
    } catch (_) {}
    if (seq !== screenStartSeq) return
    activeScreenEngine = screenEngine === 'scrcpy' && scrcpyReady ? 'scrcpy' : 'fast'
    screenActive = true
    screenStarting = false
    captureFrameFallback(seq)
  }

  function stopScreen() {
    screenStartSeq += 1
    screenActive = false
    screenStarting = false
    screenInterrupted = false
    pointerGesture = null
    clearStreamTimers()
    streamUrl = ''
    screenSrc = ''
    streamStats = { active: false, engine: '', fps: 0, latency_ms: 0, frames: 0, errors: 0 }
    if (screenImgEl) {
      try {
        screenImgEl.src = ''
      } catch (_) {}
    }
    appApi()?.StopScreenStream?.().catch(() => {})
  }

  async function captureFrameFallback(seq) {
    if (!screenActive || seq !== screenStartSeq || fallbackInFlight) return
    const api = appApi()
    if (!api) return
    fallbackInFlight = true
    try {
      if (activeScreenEngine === 'scrcpy' && api.CaptureScrcpy) {
        screenSrc = await api.CaptureScrcpy(deviceSerial)
      } else if (api.CaptureScreenScaled) {
        screenSrc = await api.CaptureScreenScaled(deviceSerial, screenQuality)
      }
    } catch (_) {
      /* skip frame */
    }
    fallbackInFlight = false
    if (screenActive && seq === screenStartSeq && !streamUrl) {
      const delay = activeScreenEngine === 'scrcpy' ? 60 : 250
      fallbackTimer = setTimeout(() => captureFrameFallback(seq), delay)
    }
  }

  function handleStreamError() {
    if (!screenActive || !streamUrl) return
    screenInterrupted = true
  }

  function handleStreamLoad() {
    screenInterrupted = false
    screenError = ''
  }

  async function switchEngine(engine) {
    if (screenEngine === engine && screenActive) return
    screenEngine = engine
    if (screenActive || rightPanel === 'device') {
      await startScreen()
    }
  }

  function selectQuality(q) {
    if (screenQuality === q) return
    screenQuality = q
    if (screenActive) {
      clearTimeout(qualityDebounceTimer)
      qualityDebounceTimer = setTimeout(() => {
        if (screenActive) startScreen()
      }, 180)
    }
  }

  async function deployScrcpy() {
    const api = appApi()
    if (!api?.DeployScrcpy) return
    scrcpyDeploying = true
    try {
      const msg = await api.DeployScrcpy(deviceSerial)
      scrcpyReady = true
      toast.success(msg || translate('core.flows.toast.scrcpyDeployed'))
      if (screenActive) {
        screenEngine = 'auto'
        await startScreen()
      }
    } catch (e) {
      toast.error(translate('core.flows.toast.scrcpyDeployFailed', { err: e }))
    }
    scrcpyDeploying = false
  }

  function mapClientToDevice(clientX, clientY) {
    if (!screenImgEl) return null
    const rect = screenImgEl.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null

    // Account for object-fit: contain letterboxing inside the img element
    const natW = screenImgEl.naturalWidth || screenSize[0] || 1080
    const natH = screenImgEl.naturalHeight || screenSize[1] || 2400
    const boxAspect = rect.width / rect.height
    const imgAspect = natW / natH

    let renderW = rect.width
    let renderH = rect.height
    let offsetX = 0
    let offsetY = 0

    if (boxAspect > imgAspect) {
      renderW = rect.height * imgAspect
      offsetX = (rect.width - renderW) / 2
    } else if (boxAspect < imgAspect) {
      renderH = rect.width / imgAspect
      offsetY = (rect.height - renderH) / 2
    }

    const relX = clientX - rect.left - offsetX
    const relY = clientY - rect.top - offsetY
    const nx = Math.max(0, Math.min(1, relX / renderW))
    const ny = Math.max(0, Math.min(1, relY / renderH))

    const boxRect = screenBoxEl ? screenBoxEl.getBoundingClientRect() : rect
    return {
      devX: Math.round(nx * (screenSize[0] || natW)),
      devY: Math.round(ny * (screenSize[1] || natH)),
      uiX: clientX - boxRect.left,
      uiY: clientY - boxRect.top,
    }
  }

  function handleScreenPointerDown(e) {
    if (e.button !== 0 || !deviceSerial) return
    const pt = mapClientToDevice(e.clientX, e.clientY)
    if (!pt) return
    e.preventDefault()
    try {
      e.currentTarget.setPointerCapture(e.pointerId)
    } catch (_) {}
    pointerGesture = {
      pointerId: e.pointerId,
      startX: pt.uiX,
      startY: pt.uiY,
      curX: pt.uiX,
      curY: pt.uiY,
      startTime: performance.now(),
      devX1: pt.devX,
      devY1: pt.devY,
      devX2: pt.devX,
      devY2: pt.devY,
      isDrag: false,
    }
  }

  function handleScreenPointerMove(e) {
    if (!pointerGesture || e.pointerId !== pointerGesture.pointerId) return
    const pt = mapClientToDevice(e.clientX, e.clientY)
    if (!pt) return
    const dist = Math.hypot(pt.uiX - pointerGesture.startX, pt.uiY - pointerGesture.startY)
    pointerGesture = {
      ...pointerGesture,
      curX: pt.uiX,
      curY: pt.uiY,
      devX2: pt.devX,
      devY2: pt.devY,
      isDrag: pointerGesture.isDrag || dist > 8,
    }
  }

  async function handleScreenPointerUp(e) {
    if (!pointerGesture || e.pointerId !== pointerGesture.pointerId) return
    const g = pointerGesture
    pointerGesture = null
    try {
      e.currentTarget.releasePointerCapture(e.pointerId)
    } catch (_) {}

    const api = appApi()
    if (!api || !deviceSerial) return

    if (g.isDrag && api.DeviceSwipe) {
      const duration = Math.max(80, Math.min(800, Math.round(performance.now() - g.startTime)))
      try {
        await api.DeviceSwipe(deviceSerial, g.devX1, g.devY1, g.devX2, g.devY2, duration)
      } catch (err) {
        console.error(err)
      }
    } else if (api.DeviceTap) {
      tapRipple = { x: g.startX, y: g.startY, id: Date.now() }
      clearTimeout(tapRippleTimer)
      tapRippleTimer = setTimeout(() => {
        tapRipple = null
      }, 380)
      try {
        await api.DeviceTap(deviceSerial, g.devX1, g.devY1)
      } catch (err) {
        console.error(err)
      }
    }
  }

  function handleScreenPointerCancel() {
    pointerGesture = null
  }

  async function deviceBack() {
    if (!deviceSerial) return
    await appApi()?.DeviceBack?.(deviceSerial)
  }

  async function deviceHome() {
    if (!deviceSerial) return
    await appApi()?.DeviceHome?.(deviceSerial)
  }

  async function deviceRecent() {
    if (!deviceSerial) return
    await appApi()?.DeviceKeyEvent?.(deviceSerial, 187)
  }

  function toggleRightPanel(panel) {
    rightPanel = panel
    if (panel === 'device') {
      if (!screenActive && !screenStarting) startScreen()
    } else if (screenActive || screenStarting) {
      stopScreen()
    }
  }

  function addShellTab() {
    shellTabCounter++
    const tab = {
      id: `sh-${shellTabCounter}`,
      label: `sh-${shellTabCounter}`,
      content: '$ ',
      inputStart: 2,
      history: [],
      histIdx: -1,
    }
    shellTabs = [...shellTabs, tab]
    activeShellTab = tab.id
  }

  function closeShellTab(id) {
    shellTabs = shellTabs.filter((t) => t.id !== id)
    if (activeShellTab === id) {
      activeShellTab = shellTabs.length > 0 ? shellTabs[shellTabs.length - 1].id : null
    }
  }

  function getShellTab(id) {
    return shellTabs.find((t) => t.id === id)
  }

  async function handleShellKey(e, tabId) {
    const tab = getShellTab(tabId)
    if (!tab) return

    if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      tab.content = '$ '
      tab.inputStart = 2
      shellTabs = shellTabs
      return
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 't') {
      e.preventDefault()
      addShellTab()
      return
    }
    if (e.key === 'Enter') {
      e.preventDefault()
      const input = tab.content.slice(tab.inputStart).trim()
      if (input) {
        tab.history = [...tab.history, input]
        tab.histIdx = -1
      }
      tab.content += '\n'
      if (input === 'clear' || input === 'cls') {
        tab.content = ''
      } else if (input) {
        try {
          const r = await appApi().ExecCommand(input)
          if (r) tab.content += r + '\n'
        } catch (err) {
          tab.content += `error: ${err}\n`
        }
      }
      tab.content += '$ '
      tab.inputStart = tab.content.length
      shellTabs = shellTabs
      await tick()
      const el = e.target
      if (el) {
        el.scrollTop = el.scrollHeight
        el.setSelectionRange(tab.content.length, tab.content.length)
      }
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (tab.history.length > 0) {
        if (tab.histIdx < 0) tab.histIdx = tab.history.length
        tab.histIdx = Math.max(0, tab.histIdx - 1)
        tab.content = tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        shellTabs = shellTabs
      }
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (tab.histIdx >= 0) {
        tab.histIdx++
        tab.content =
          tab.histIdx >= tab.history.length
            ? tab.content.slice(0, tab.inputStart)
            : tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        if (tab.histIdx >= tab.history.length) tab.histIdx = -1
        shellTabs = shellTabs
      }
      return
    }
    if (e.target.selectionStart < tab.inputStart && (e.key === 'Backspace' || e.key.length === 1)) {
      e.preventDefault()
      e.target.setSelectionRange(tab.content.length, tab.content.length)
    }
  }

  function handleShellInput(e, tabId) {
    const tab = getShellTab(tabId)
    if (!tab) return
    if (e.target.value.length < tab.inputStart) {
      e.target.value = tab.content
      e.target.setSelectionRange(tab.content.length, tab.content.length)
    } else {
      tab.content = e.target.value
    }
    shellTabs = shellTabs
  }

  // ==================== Keyboard Navigation ====================

  async function stepSelection(delta) {
    if (viewMode !== 'list' || filteredFlows.length === 0) return
    const currentIdx = selectedFlow ? filteredFlows.findIndex((f) => f.id === selectedFlow.id) : -1
    let nextIdx
    if (currentIdx === -1) {
      nextIdx = delta > 0 ? 0 : filteredFlows.length - 1
    } else {
      nextIdx = Math.max(0, Math.min(filteredFlows.length - 1, currentIdx + delta))
    }
    const target = filteredFlows[nextIdx]
    if (target && target.id !== selectedFlow?.id) {
      await selectFlow(target)
      await tick()
      const row = listBodyEl?.querySelector(`[data-flow-id="${CSS.escape(String(target.id))}"]`)
      row?.scrollIntoView({ block: 'nearest' })
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Escape') {
      if (ctxMenu) {
        ctxMenu = null
        return
      }
      if (pluginModal) {
        pluginModal = null
        return
      }
      if (showHarImport) {
        showHarImport = false
        return
      }
      if (compareResult) {
        compareResult = null
        return
      }
      if (selectedFlow && !isEditableTarget(e.target)) {
        selectedFlow = null
        return
      }
      return
    }

    if (isEditableTarget(e.target)) return
    if (e.metaKey || e.ctrlKey || e.altKey) return

    if (e.key === '/') {
      e.preventDefault()
      searchInputEl?.focus()
      searchInputEl?.select()
      return
    }
    if (e.key === 'ArrowDown' || e.key === 'j') {
      e.preventDefault()
      stepSelection(1)
      return
    }
    if (e.key === 'ArrowUp' || e.key === 'k') {
      e.preventDefault()
      stepSelection(-1)
      return
    }
  }

  // ==================== Lifecycle ====================

  // Re-register command palette items reactively when locale changes
  $: {
    const _t = $t
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      const cat = _t('nav.flows.title') !== 'nav.flows.title' ? _t('nav.flows.title') : 'Traffic Inspector'
      unregisterCmds = registerCommands([
        {
          id: 'flows:toggle-layout',
          label: _t('core.flows.cmd.toggleLayout'),
          category: cat,
          icon: 'columns',
          run: () => (splitDirection = splitDirection === 'horizontal' ? 'vertical' : 'horizontal'),
        },
        {
          id: 'flows:toggle-grouping',
          label: _t('core.flows.cmd.toggleGrouping'),
          category: cat,
          icon: 'layers',
          run: () => setViewMode(viewMode === 'list' ? 'grouped' : 'list'),
        },
        {
          id: 'flows:open-plugin-workbench',
          label: _t('core.flows.cmd.openPluginWorkbench'),
          category: cat,
          icon: 'puzzle',
          run: () => toggleRightPanel('plugins'),
        },
        {
          id: 'flows:import-har',
          label: _t('core.flows.cmd.importHar'),
          category: cat,
          icon: 'upload',
          run: () => (showHarImport = true),
        },
        {
          id: 'flows:export-jsonl',
          label: _t('core.flows.cmd.exportJsonl'),
          category: cat,
          icon: 'download',
          run: exportAgentJSONL,
        },
      ])
    }
  }

  onMount(async () => {
    loadFlows()
    loadPlugins()
    loadActiveRules()
    loadLanguages()

    try {
      capturePaused = Boolean(await appApi()?.IsPaused?.())
    } catch (_) {}

    if (rightPanel === 'device') {
      startScreen()
    }

    if (window.runtime?.EventsOn) {
      const offFlow = window.runtime.EventsOn('proxy:flow', queueFlowRefresh)
      if (typeof offFlow === 'function') unsubs.push(offFlow)

      const offCap = window.runtime.EventsOn('proxy:capture', (ev) => {
        if (typeof ev?.paused === 'boolean') capturePaused = ev.paused
      })
      if (typeof offCap === 'function') unsubs.push(offCap)
    }

    pollInterval = setInterval(() => {
      loadFlows()
      loadActiveRules()
    }, 2000)
  })

  onDestroy(() => {
    clearInterval(pollInterval)
    clearTimeout(flowRefreshTimer)
    clearTimeout(searchDebounceTimer)
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
    if (unregisterCmds) unregisterCmds()
    stopScreen()
  })
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="flows-page">
  <!-- Tier 1: Primary Search & Action Toolbar -->
  <header class="toolbar-primary">
    <div class="search-box">
      <Icon name="search" size={14} className="search-ico" />
      <input
        bind:this={searchInputEl}
        type="text"
        bind:value={filterSearch}
        on:input={debouncedLoadFlows}
        placeholder={$t('core.flows.searchPlaceholder')}
        aria-label={$t('core.flows.searchAria')}
      />
      {#if filterSearch}
        <button class="clear-x" type="button" title={$t('core.flows.clearSearch')} on:click={() => { filterSearch = ''; loadFlows() }}>
          <Icon name="x" size={12} />
        </button>
      {:else}
        <Kbd keys="/" size="xs" />
      {/if}
    </div>

    <div class="host-box">
      <Icon name="globe" size={13} />
      <input
        type="text"
        list="cap-host-suggestions"
        bind:value={filterHost}
        on:input={debouncedLoadFlows}
        placeholder={$t('core.flows.hostPlaceholder')}
        aria-label={$t('core.flows.hostAria')}
      />
      {#if filterHost}
        <button class="clear-x" type="button" title={$t('core.flows.clearHost')} on:click={() => { filterHost = ''; loadFlows() }}>
          <Icon name="x" size={12} />
        </button>
      {/if}
      <datalist id="cap-host-suggestions">
        {#each distinctHosts as h}
          <option value={h} />
        {/each}
      </datalist>
    </div>

    <div class="toolbar-count mono tabular-nums" title={$t('core.flows.countTitle')}>
      {#if filteredFlows.length !== flows.length}
        <span class="cnt-hi">{filteredFlows.length}</span><span class="cnt-sep">/</span>{flows.length}
      {:else}
        <span class="cnt-hi">{flows.length}</span>
      {/if}
      <span class="cnt-label">{$t('core.flows.flowsUnit')}</span>
    </div>

    <div class="toolbar-actions">
      <div class="seg-group" role="group" aria-label={$t('core.flows.viewModeAria')}>
        <button
          class="seg-btn"
          class:active={viewMode === 'list'}
          type="button"
          title={$t('core.flows.viewFlatTitle')}
          on:click={() => setViewMode('list')}
        >
          <Icon name="list" size={13} />
        </button>
        <button
          class="seg-btn"
          class:active={viewMode === 'grouped'}
          type="button"
          title={$t('core.flows.viewGroupedTitle')}
          on:click={() => setViewMode('grouped')}
        >
          <Icon name="layers" size={13} />
        </button>
      </div>

      <div class="seg-group" role="group" aria-label={$t('core.flows.splitLayoutAria')}>
        <button
          class="seg-btn"
          class:active={splitDirection === 'horizontal'}
          type="button"
          title={$t('core.flows.splitHorizontalTitle')}
          on:click={() => (splitDirection = 'horizontal')}
        >
          <Icon name="columns" size={13} />
        </button>
        <button
          class="seg-btn"
          class:active={splitDirection === 'vertical'}
          type="button"
          title={$t('core.flows.splitVerticalTitle')}
          on:click={() => (splitDirection = 'vertical')}
        >
          <Icon name="rows" size={13} />
        </button>
      </div>

      <Button
        variant="secondary"
        size="xs"
        icon="arrow-down"
        active={liveFollow}
        title={$t('core.flows.followTitle')}
        on:click={() => (liveFollow = !liveFollow)}
      >
        {$t('core.flows.follow')}
      </Button>

      <Button
        variant={capturePaused ? 'success' : 'secondary'}
        size="xs"
        icon={capturePaused ? 'play' : 'pause'}
        title={capturePaused ? $t('core.flows.resumeTitle') : $t('core.flows.pauseTitle')}
        on:click={toggleCapturePause}
      >
        {capturePaused ? $t('core.flows.resume') : $t('core.flows.pause')}
      </Button>

      <Button
        variant="ghost"
        size="xs"
        icon="upload"
        title={$t('core.flows.harTitle')}
        on:click={() => (showHarImport = !showHarImport)}
      >
        {$t('core.flows.harBtn')}
      </Button>

      <Button
        variant="ghost"
        size="xs"
        icon="download"
        title={$t('core.flows.jsonlTitle')}
        on:click={exportAgentJSONL}
      >
        {$t('core.flows.jsonlBtn')}
      </Button>

      <Button
        variant="ghost"
        size="xs"
        icon="trash"
        iconOnly
        title={$t('core.flows.clearAllTitle')}
        on:click={clearFlows}
      />
    </div>
  </header>

  <!-- Tier 2: Quick Facet Filter Pills -->
  <div class="toolbar-facets">
    <div class="facet-group">
      {#each METHODS as m}
        <button
          class="facet-pill method-pill"
          class:active={filterMethod === m}
          data-method={m || 'ALL'}
          type="button"
          on:click={() => { filterMethod = m; loadFlows() }}
        >
          {m || $t('core.flows.facetAll')}
        </button>
      {/each}
    </div>

    <span class="facet-divider"></span>

    <div class="facet-group">
      {#each STATUS_CLASSES as st}
        <button
          class="facet-pill status-pill"
          class:active={filterStatus === st.id}
          data-status={st.id || 'all'}
          type="button"
          on:click={() => (filterStatus = st.id)}
        >
          {st.label}
        </button>
      {/each}
    </div>

    <span class="facet-divider"></span>

    <div class="facet-group">
      {#each CONTENT_TYPES as ct}
        <button
          class="facet-pill"
          class:active={filterType === ct.id}
          type="button"
          on:click={() => (filterType = ct.id)}
        >
          {ct.label}
        </button>
      {/each}
    </div>

    {#if hasActiveFilters}
      <button class="facet-reset" type="button" on:click={resetFilters}>
        <Icon name="x" size={11} />
        <span>{$t('core.flows.resetFilters')}</span>
      </button>
    {/if}

    {#if compareBaseId}
      <div class="compare-chip">
        <Icon name="diff" size={12} />
        <span class="mono truncate">{$t('core.flows.compareBase', { label: compareBaseLabel })}</span>
        <button type="button" title={$t('core.flows.clearCompareBase')} on:click={clearCompareBase}>
          <Icon name="x" size={11} />
        </button>
      </div>
    {/if}
  </div>

  <!-- Collapsible HAR Import Bar -->
  {#if showHarImport}
    <div class="har-bar">
      <Icon name="upload" size={14} />
      <span class="har-label">{$t('core.flows.harLabel')}</span>
      <input
        type="text"
        class="cap-input mono har-input"
        bind:value={harPath}
        placeholder={$t('core.flows.harPlaceholder')}
        on:keydown={(e) => e.key === 'Enter' && importHar()}
      />
      <Button variant="primary" size="xs" loading={harImporting} on:click={importHar}>{$t('core.flows.harImportBtn')}</Button>
      <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.harCloseTitle')} on:click={() => (showHarImport = false)} />
    </div>
  {/if}

  <!-- Main Resizable Split Workspace -->
  <div class="workspace">
    <SplitPane
      direction={splitDirection}
      initialSize={46}
      minPrimary={24}
      minSecondary={26}
      storageKey="cap.flows.splitSize"
    >
      <!-- PRIMARY PANE: Flow List / API Groups -->
      <div slot="primary" class="list-pane">
        {#if viewMode === 'list'}
          <div class="table-head mono">
            <span class="c-rule" title={$t('core.flows.colRuleTitle')}></span>
            <span class="c-id">#</span>
            <span class="c-method">{$t('core.flows.colMethod')}</span>
            <span class="c-status">{$t('core.flows.colStatus')}</span>
            <span class="c-endpoint">{$t('core.flows.colEndpoint')}</span>
            <span class="c-type">{$t('core.flows.colType')}</span>
            <span class="c-lat">{$t('core.flows.colLatency')}</span>
            <span class="c-time">{$t('core.flows.colTime')}</span>
          </div>
        {/if}

        <div class="list-scroll" bind:this={listBodyEl}>
          {#if viewMode === 'grouped'}
            {#if apiGroups.length === 0}
              <EmptyState
                icon="layers"
                title={$t('core.flows.emptyGroupsTitle')}
                description={$t('core.flows.emptyGroupsDesc')}
                compact
              >
                <Button variant="secondary" size="xs" icon="list" on:click={() => setViewMode('list')}>
                  {$t('core.flows.flatListBtn')}
                </Button>
              </EmptyState>
            {:else}
              {#each apiGroups as group}
                <div class="group-section">
                  <div class="group-head">
                    <Icon name="globe" size={12} />
                    <span class="group-host mono">{group.host}</span>
                    <span class="group-prefix mono truncate">{group.prefix}</span>
                    <Badge variant="neutral" size="xs" mono>{group.count}</Badge>
                  </div>
                  {#each group.endpoints || [] as ep}
                    <button
                      class="group-ep-row"
                      type="button"
                      on:click={() => {
                        filterHost = group.host
                        filterSearch = ep.path
                        viewMode = 'list'
                        loadFlows()
                      }}
                    >
                      <Badge method={ep.method} size="xs" />
                      <span class="ep-path mono truncate">{ep.path}</span>
                      <span class="ep-lat mono tabular-nums">{formatDuration(ep.avg_ms)}</span>
                      <span class="ep-hits mono tabular-nums">×{ep.count}</span>
                    </button>
                  {/each}
                </div>
              {/each}
            {/if}
          {:else if filteredFlows.length === 0}
            <EmptyState
              icon={hasActiveFilters ? 'filter' : 'radar'}
              title={hasActiveFilters ? $t('core.flows.emptyFilterTitle') : $t('core.flows.emptyTrafficTitle')}
              description={hasActiveFilters
                ? $t('core.flows.emptyFilterDesc')
                : $t('core.flows.emptyTrafficDesc')}
            >
              {#if hasActiveFilters}
                <Button variant="secondary" size="sm" icon="x" on:click={resetFilters}>
                  {$t('core.flows.resetFiltersBtn')}
                </Button>
              {:else}
                <Button variant="primary" size="sm" icon="radio" on:click={() => navigate('capture')}>
                  {$t('core.flows.openCaptureBtn')}
                </Button>
              {/if}
            </EmptyState>
          {:else}
            {#each filteredFlows as f (f.id)}
              {@const rule = matchingRule(f)}
              {@const parts = splitPathQuery(f)}
              {@const latPct = Math.min(100, Math.max(4, Math.round(((Number(f.latency_ms) || 0) / maxLatency) * 100)))}
              <button
                class="flow-row"
                class:selected={selectedFlow && selectedFlow.id === f.id}
                class:has-rule={Boolean(rule)}
                class:is-base={compareBaseId === f.id}
                data-flow-id={f.id}
                type="button"
                on:click={() => selectFlow(f)}
                on:contextmenu={(e) => showContextMenu(e, f)}
              >
                <span class="c-rule" title={rule ? $t('core.flows.ruleTooltip', { name: rule.name }) : ''}>
                  {#if rule}
                    <Icon name={ruleIconName(rule)} size={11} />
                  {/if}
                </span>
                <span class="c-id mono tabular-nums">{f.id}</span>
                <span class="c-method">
                  <Badge method={f.method} size="xs" />
                </span>
                <span class="c-status">
                  <Badge status={f.status} size="xs" />
                </span>
                <span class="c-endpoint mono" title={f.url}>
                  <span class="ep-host">{f.host}</span><span class="ep-p">{parts.path}</span>{#if parts.query}<span class="ep-q">{parts.query}</span>{/if}
                </span>
                <span class="c-type mono">{shortContentType(f.body_type)}</span>
                <span class="c-lat mono tabular-nums lat-{latencyTone(f.latency_ms)}">
                  <span class="lat-val">{formatDuration(f.latency_ms)}</span>
                  <span class="lat-track"><span class="lat-fill" style="width:{latPct}%"></span></span>
                </span>
                <span class="c-time mono tabular-nums">{f.time}</span>
              </button>
            {/each}
          {/if}
        </div>
      </div>

      <!-- SECONDARY PANE: Inspector / Device Mirror -->
      <div slot="secondary" class="inspector-pane">
        <!-- Secondary Mode Bar -->
        <div class="pane-mode-bar">
          <div class="mode-tabs">
            <button
              class="mode-tab"
              class:active={rightPanel === 'detail'}
              type="button"
              on:click={() => toggleRightPanel('detail')}
            >
              <Icon name="activity" size={13} />
              <span>{$t('core.flows.modeInspector')}</span>
              {#if selectedFlow}
                <span class="mode-pill mono">#{selectedFlow.id}</span>
              {/if}
            </button>
            <button
              class="mode-tab"
              class:active={rightPanel === 'device'}
              type="button"
              on:click={() => toggleRightPanel('device')}
            >
              <Icon name="smartphone" size={13} />
              <span>{$t('core.flows.modeDevice')}</span>
              {#if screenActive}
                <span class="live-dot"></span>
              {/if}
            </button>
            <button
              class="mode-tab"
              class:active={rightPanel === 'plugins'}
              type="button"
              on:click={() => toggleRightPanel('plugins')}
            >
              <Icon name="puzzle" size={13} />
              <span>{$t('core.flows.modePlugins')}</span>
            </button>
          </div>

          <div class="pane-mode-right">
            {#if rightPanel === 'detail' && selectedFlow}
              {#if compareBaseId && compareBaseId !== selectedFlow.id}
                <Button
                  variant="subtle"
                  size="xs"
                  icon="diff"
                  loading={compareLoading}
                  on:click={() => runCompareWith(selectedFlow)}
                >
                  {$t('core.flows.diffVs', { id: compareBaseId })}
                </Button>
              {:else}
                <Button
                  variant="ghost"
                  size="xs"
                  icon="diff"
                  title={$t('core.flows.comparePinTitle')}
                  on:click={() => pinCompareBase(selectedFlow)}
                >
                  {$t('core.flows.compareBtn')}
                </Button>
              {/if}
              <Button
                variant="ghost"
                size="xs"
                icon="x"
                iconOnly
                title={$t('core.flows.closeInspectorTitle')}
                on:click={() => { selectedFlow = null; compareResult = null }}
              />
            {/if}
          </div>
        </div>

        {#if rightPanel === 'plugins'}
          <!-- Single-Page Plugin Debug Workbench -->
          <div class="plugins-panel">
            <PluginWorkbench
              {selectedFlow}
              compact={true}
              on:selectFlow={(e) => selectFlowById(e.detail?.flowId)}
            />
          </div>
        {:else if rightPanel === 'device'}
          <!-- Device Screen Mirror (Native MJPEG) + Multi-Tab Shell -->
          <div class="device-panel">
            <SplitPane direction="vertical" initialSize={66} minPrimary={28} minSecondary={18} storageKey="cap.flows.deviceSplit">
              <div slot="primary" class="device-stage">
                <!-- Live Stream Telemetry Bar -->
                <div class="device-telemetry-bar">
                  <div class="telemetry-left">
                    {#if activeScreenEngine}
                      <Badge variant={activeScreenEngine === 'scrcpy' ? 'success' : 'info'} size="xs" dot={screenActive && !screenInterrupted} pulse={screenActive && !screenInterrupted} mono>
                        {activeScreenEngine === 'scrcpy' ? $t('core.flows.devScrcpy') : $t('core.flows.devFast')}
                      </Badge>
                    {/if}
                    {#if screenActive}
                      <span class="telemetry-metric mono tabular-nums">
                        {$t('core.flows.devTelemetryFps', { fps: (streamStats?.fps || 0).toFixed(1) })}
                      </span>
                      <span class="telemetry-sep">·</span>
                      <span class="telemetry-metric mono tabular-nums">
                        {$t('core.flows.devTelemetryLatency', { ms: Math.round(streamStats?.latency_ms || 0) })}
                      </span>
                    {/if}
                    {#if deviceSerial}
                      <span class="telemetry-serial mono truncate" title={deviceSerial}>{deviceSerial}</span>
                    {/if}
                  </div>
                  <span class="telemetry-hint">{$t('core.flows.devSwipeHint')}</span>
                </div>

                {#if screenActive && activeScreenEngine === 'fast' && !scrcpyReady}
                  <div class="device-fallback-bar">
                    <Icon name="zap" size={12} />
                    <span class="truncate">
                      {screenFallbackReason
                        ? $t('core.flows.devFallbackHint', { reason: screenFallbackReason })
                        : $t('core.flows.devFallbackShort')}
                    </span>
                    <Button variant="subtle" size="xs" icon="download" loading={scrcpyDeploying} on:click={deployScrcpy}>
                      {$t('core.flows.devDeploy')}
                    </Button>
                  </div>
                {/if}

                <div class="device-viewport">
                  <div
                    bind:this={screenBoxEl}
                    class="device-screen-box"
                    style="aspect-ratio: {screenSize[0]} / {screenSize[1]}"
                  >
                    {#if (streamUrl || screenSrc) && !screenInterrupted}
                      <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
                      <img
                        bind:this={screenImgEl}
                        class="device-img"
                        src={streamUrl || screenSrc}
                        alt={$t('core.flows.deviceAlt')}
                        draggable="false"
                        on:load={handleStreamLoad}
                        on:error={handleStreamError}
                        on:pointerdown={handleScreenPointerDown}
                        on:pointermove={handleScreenPointerMove}
                        on:pointerup={handleScreenPointerUp}
                        on:pointercancel={handleScreenPointerCancel}
                      />

                      <!-- Subtle Touch / Swipe Visual Feedback Overlay -->
                      {#if pointerGesture?.isDrag || tapRipple}
                        <svg class="gesture-overlay" aria-hidden="true">
                          {#if pointerGesture?.isDrag}
                            <line
                              x1={pointerGesture.startX}
                              y1={pointerGesture.startY}
                              x2={pointerGesture.curX}
                              y2={pointerGesture.curY}
                              class="swipe-line"
                            />
                            <circle cx={pointerGesture.startX} cy={pointerGesture.startY} r="4" class="swipe-start" />
                            <circle cx={pointerGesture.curX} cy={pointerGesture.curY} r="6" class="swipe-end" />
                          {/if}
                          {#if tapRipple}
                            <circle cx={tapRipple.x} cy={tapRipple.y} r="14" class="tap-ring" />
                          {/if}
                        </svg>
                      {/if}
                    {:else}
                      <div class="device-connecting">
                        <Icon name={screenInterrupted || screenError ? 'alert-triangle' : 'smartphone'} size={24} />
                        <span>
                          {#if screenStarting}
                            {$t('core.flows.devConnecting')}
                          {:else if screenInterrupted}
                            {$t('core.flows.devReconnecting')}
                          {:else if screenError}
                            {$t('core.flows.devStreamError', { err: screenError })}
                          {:else if deviceSerial}
                            {$t('core.flows.deviceStreaming', { serial: deviceSerial })}
                          {:else}
                            {$t('core.flows.devNoDevice')}
                          {/if}
                        </span>
                        {#if !screenStarting}
                          <Button variant="secondary" size="xs" icon="refresh" on:click={startScreen}>
                            {$t('core.flows.devRefresh')}
                          </Button>
                        {/if}
                      </div>
                    {/if}
                  </div>
                </div>

                <div class="device-toolbar">
                  <div class="dev-nav-btns">
                    <Button variant="secondary" size="xs" icon="chevron-left" iconOnly title={$t('core.flows.devBack')} disabled={!deviceSerial} on:click={deviceBack} />
                    <Button variant="secondary" size="xs" icon="square" iconOnly title={$t('core.flows.devHome')} disabled={!deviceSerial} on:click={deviceHome} />
                    <Button variant="secondary" size="xs" icon="layers" iconOnly title={$t('core.flows.devRecent')} disabled={!deviceSerial} on:click={deviceRecent} />
                    <Button variant="secondary" size="xs" icon="refresh" iconOnly title={$t('core.flows.devRefresh')} loading={screenStarting} on:click={startScreen} />
                  </div>

                  <div class="seg-group">
                    <button
                      class="seg-btn"
                      class:active={screenEngine === 'auto'}
                      type="button"
                      on:click={() => switchEngine('auto')}
                    >
                      {$t('core.flows.devAuto')}
                    </button>
                    <button
                      class="seg-btn"
                      class:active={screenEngine === 'scrcpy'}
                      disabled={!scrcpyReady}
                      type="button"
                      on:click={() => switchEngine('scrcpy')}
                    >
                      {$t('core.flows.devScrcpy')}
                    </button>
                    <button
                      class="seg-btn"
                      class:active={screenEngine === 'fast'}
                      type="button"
                      on:click={() => switchEngine('fast')}
                    >
                      {$t('core.flows.devFast')}
                    </button>
                  </div>

                  <div class="seg-group">
                    {#each QUALITY_PRESETS as preset}
                      <button
                        class="seg-btn"
                        class:active={screenQuality === preset.value}
                        type="button"
                        on:click={() => selectQuality(preset.value)}
                      >
                        {$t(preset.labelKey)}
                      </button>
                    {/each}
                  </div>
                </div>
              </div>

              <div slot="secondary" class="device-shell">
                <div class="shell-tabs">
                  {#each shellTabs as st}
                    <div class="sh-tab" class:active={st.id === activeShellTab}>
                      <button class="sh-tab-btn mono" type="button" on:click={() => (activeShellTab = st.id)}>
                        <Icon name="terminal" size={11} />
                        <span>{st.label}</span>
                      </button>
                      <button class="sh-tab-x" type="button" on:click={() => closeShellTab(st.id)}>
                        <Icon name="x" size={10} />
                      </button>
                    </div>
                  {/each}
                  <button class="sh-add" type="button" title={$t('core.flows.newShellTab')} on:click={addShellTab}>
                    <Icon name="plus" size={12} />
                  </button>
                </div>
                {#each shellTabs as st}
                  {#if st.id === activeShellTab}
                    <textarea
                      class="shell-textarea mono"
                      bind:value={st.content}
                      on:keydown={(e) => handleShellKey(e, st.id)}
                      on:input={(e) => handleShellInput(e, st.id)}
                      spellcheck="false"
                    ></textarea>
                  {/if}
                {/each}
              </div>
            </SplitPane>
          </div>
        {:else if selectedFlow}
          <!-- Flow Detail Inspector -->
          <div class="detail-shell" class:is-loading={detailLoading}>
            <!-- Request Summary Header -->
            <div class="detail-summary">
              <div class="summary-top">
                <Badge method={selectedFlow.method} size="sm" />
                <Badge status={selectedFlow.status} size="sm" />
                <span class="summary-url mono truncate" title={selectedFlow.url}>{selectedFlow.url}</span>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  iconOnly
                  title={$t('core.flows.copyUrlTitle')}
                  on:click={() => copyToClipboard(selectedFlow.url, translate('core.flows.copiedUrl'))}
                />
              </div>

              <div class="summary-meta-bar">
                <div class="meta-pills mono tabular-nums">
                  <span class="meta-item"><Icon name="clock" size={11} /> {formatDuration(selectedFlow.latency_ms)}</span>
                  <span class="meta-item">{selectedFlow.time}</span>
                  <span class="meta-item">{$t('core.flows.reqLabel', { size: formatBytes(reqBodySize) })}</span>
                  <span class="meta-item">{$t('core.flows.respLabel', { size: formatBytes(respBodySize) })}</span>
                  {#if selectedFlow.sign_params?.length > 0}
                    <Badge variant="warning" size="xs">
                      <Icon name="key" size={10} /> {$t('core.flows.signCount', { count: selectedFlow.sign_params.length })}
                    </Badge>
                  {/if}
                </div>

                <div class="summary-actions">
                  <Button variant="secondary" size="xs" icon="play" loading={replaying} on:click={() => replayFlow()}>
                    {$t('core.flows.replayBtn')}
                  </Button>
                  <Button variant="secondary" size="xs" icon="edit" active={showReplayEditor} on:click={openReplayEditor}>
                    {$t('core.flows.modifyBtn')}
                  </Button>
                  <Button variant="subtle" size="xs" icon="key" loading={signLoading} on:click={analyzeSign}>
                    {$t('core.flows.signBtn')}
                  </Button>
                  <Button variant="subtle" size="xs" icon="globe" on:click={() => openGatewayPublishFlow(selectedFlow)}>
                    {$t('core.flows.publishGatewayBtn')}
                  </Button>
                  <Button variant="subtle" size="xs" on:click={() => openFlowInRecon(selectedFlow)}>
                    <Icon name="radar" size={13} />
                    <span>{$t('core.flows.reconBtn')}</span>
                  </Button>
                  <Button variant="ghost" size="xs" icon="code" active={activeTab === 'export'} on:click={() => switchTab('export')}>
                    {$t('core.flows.codeBtn')}
                  </Button>
                </div>
              </div>
            </div>

            <!-- Collapsible Modify & Replay Drawer -->
            {#if showReplayEditor}
              <div class="drawer-panel replay-drawer">
                <div class="drawer-head">
                  <span class="drawer-title"><Icon name="edit" size={12} /> {$t('core.flows.replayDrawerTitle')}</span>
                  <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.closeEditorTitle')} on:click={() => (showReplayEditor = false)} />
                </div>
                <div class="replay-form">
                  <div class="rf-row">
                    <select class="cap-input mono rf-method" bind:value={replayMethod}>
                      {#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as m}
                        <option value={m}>{m}</option>
                      {/each}
                    </select>
                    <input type="text" class="cap-input mono flex-1" bind:value={replayURL} placeholder={$t('core.flows.replayUrlPlaceholder')} />
                  </div>
                  <div class="rf-grid">
                    <div class="rf-col">
                      <label class="rf-label" for="replay-hdrs">{$t('core.flows.replayHeadersLabel')}</label>
                      <textarea id="replay-hdrs" class="cap-textarea mono" bind:value={replayHeaders} placeholder="Authorization: Bearer ..."></textarea>
                    </div>
                    <div class="rf-col">
                      <label class="rf-label" for="replay-body">{$t('core.flows.replayBodyLabel')}</label>
                      <textarea id="replay-body" class="cap-textarea mono" bind:value={replayBody}></textarea>
                    </div>
                  </div>
                  <div class="rf-actions">
                    <Button variant="primary" size="xs" icon="send" loading={replaying} on:click={replayModified}>
                      {$t('core.flows.sendModifiedBtn')}
                    </Button>
                  </div>
                </div>
              </div>
            {/if}

            <!-- Replay Result Card -->
            {#if replayResult}
              <div class="drawer-panel replay-result">
                <div class="drawer-head">
                  <div class="rr-left">
                    <span class="drawer-title"><Icon name="repeat" size={12} /> {$t('core.flows.replayRespTitle')}</span>
                    {#if replayResult.error}
                      <Badge variant="danger" size="xs">{replayResult.error}</Badge>
                    {:else}
                      <Badge status={replayResult.status} size="xs" />
                      <span class="mono tabular-nums rr-lat">{formatDuration(replayResult.latency_ms)}</span>
                      {#if replayResult.status_diff}
                        <Badge variant="warning" size="xs">{replayResult.status_diff}</Badge>
                      {/if}
                    {/if}
                  </div>
                  <div class="rr-right">
                    {#if replayResult.body}
                      <Button variant="ghost" size="xs" icon="copy" iconOnly title={$t('core.flows.copyReplayBodyTitle')} on:click={() => copyToClipboard(replayResult.body, translate('core.flows.copiedReplayBody'))} />
                    {/if}
                    <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.dismissReplayTitle')} on:click={() => (replayResult = null)} />
                  </div>
                </div>
                {#if replayResult.body}
                  <pre class="rr-body mono">{getFormattedBodyText(replayResult.body, 'application/json', 'auto')}</pre>
                {/if}
              </div>
            {/if}

            <!-- Compare / Diff Drawer -->
            {#if compareResult}
              <div class="drawer-panel compare-drawer">
                <div class="drawer-head">
                  <div class="rr-left">
                    <span class="drawer-title"><Icon name="diff" size={12} /> {$t('core.flows.diffTitle', { a: compareResult.flow_a, b: compareResult.flow_b })}</span>
                    <Badge variant="info" size="xs">{compareResult.summary || $t('core.flows.diffCompared')}</Badge>
                  </div>
                  <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.closeDiffTitle')} on:click={() => (compareResult = null)} />
                </div>
                <div class="compare-body mono">
                  <div class="cmp-meta">
                    <span>{$t('core.flows.diffStatus')}: <b>{compareResult.status?.a}</b> -> <b>{compareResult.status?.b}</b></span>
                    <span>{$t('core.flows.diffLatency')}: <b>{compareResult.latency?.a}ms</b> -> <b>{compareResult.latency?.b}ms</b> ({compareResult.latency?.percent})</span>
                    <span>{$t('core.flows.diffHeaders')}: +{compareResult.headers?.added?.length || 0} / -{compareResult.headers?.removed?.length || 0} / ~{compareResult.headers?.changed?.length || 0}</span>
                  </div>
                  {#if compareResult.headers?.changed?.length > 0 || compareResult.headers?.added?.length > 0 || compareResult.headers?.removed?.length > 0}
                    <div class="cmp-section">
                      <div class="cmp-sec-title">{$t('core.flows.diffHeaderChanges')}</div>
                      {#each compareResult.headers.added || [] as h}
                        <div class="cmp-line add">+ {h.key}: {h.value}</div>
                      {/each}
                      {#each compareResult.headers.removed || [] as h}
                        <div class="cmp-line rem">- {h.key}: {h.value}</div>
                      {/each}
                      {#each compareResult.headers.changed || [] as h}
                        <div class="cmp-line chg">~ {h.key}: {h.value_a} -> {h.value_b}</div>
                      {/each}
                    </div>
                  {/if}
                  {#if compareResult.resp_body && compareResult.resp_body.type !== 'identical'}
                    <div class="cmp-section">
                      <div class="cmp-sec-title">{$t('core.flows.diffRespBody', { type: compareResult.resp_body.type, sizeA: formatBytes(compareResult.resp_body.size_a), sizeB: formatBytes(compareResult.resp_body.size_b) })}</div>
                      {#if compareResult.resp_body.json_diff}
                        {#each compareResult.resp_body.json_diff.added || [] as p}
                          <div class="cmp-line add">+ {p}</div>
                        {/each}
                        {#each compareResult.resp_body.json_diff.removed || [] as p}
                          <div class="cmp-line rem">- {p}</div>
                        {/each}
                        {#each compareResult.resp_body.json_diff.changed || [] as c}
                          <div class="cmp-line chg">~ {c.path}: {c.value_a} -> {c.value_b}</div>
                        {/each}
                      {:else if compareResult.resp_body.text_diff}
                        <pre class="cmp-pre">{compareResult.resp_body.text_diff}</pre>
                      {/if}
                    </div>
                  {/if}
                </div>
              </div>
            {/if}

            <!-- Sign Analysis Drawer -->
            {#if signResults.length > 0}
              <div class="drawer-panel sign-drawer">
                <div class="drawer-head">
                  <span class="drawer-title"><Icon name="key" size={12} /> {$t('core.flows.signDrawerTitle', { count: signResults.length })}</span>
                  <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.closeSignTitle')} on:click={() => (signResults = [])} />
                </div>
                <div class="sign-list">
                  {#each signResults as sr}
                    <div class="sign-row mono">
                      <span class="sr-param">{sr.param_name}</span>
                      {#if sr.encoding}<Badge variant="neutral" size="xs">{sr.encoding}</Badge>{/if}
                      <span class="sr-algs">{(sr.possible_algs || []).join(', ') || $t('core.flows.signUnknown')}</span>
                      <Badge variant={sr.confidence >= 0.7 ? 'success' : 'warning'} size="xs" mono>{Math.round((sr.confidence || 0) * 100)}%</Badge>
                      {#if sr.input_guess}<span class="sr-guess truncate" title={sr.input_guess}>{sr.input_guess}</span>{/if}
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Inspector Tab Bar -->
            <div class="inspector-tabs" role="tablist">
              {#each [
                { id: 'params', label: $t('core.flows.tabs.params'), count: selectedParams.length },
                { id: 'req-headers', label: $t('core.flows.tabs.reqHeaders'), count: reqHeaderCount },
                { id: 'req-body', label: $t('core.flows.tabs.reqBody'), size: reqBodySize },
                { id: 'resp-headers', label: $t('core.flows.tabs.respHeaders'), count: respHeaderCount },
                { id: 'resp-body', label: $t('core.flows.tabs.respBody'), size: respBodySize },
                { id: 'raw', label: $t('core.flows.tabs.raw') },
                { id: 'timing', label: $t('core.flows.tabs.timing') },
                { id: 'export', label: $t('core.flows.tabs.export') },
              ] as tab}
                <button
                  class="itab"
                  class:active={activeTab === tab.id}
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  type="button"
                  on:click={() => switchTab(tab.id)}
                >
                  <span>{tab.label}</span>
                  {#if tab.count > 0}
                    <span class="itab-badge mono tabular-nums">{tab.count}</span>
                  {:else if tab.size > 0}
                    <span class="itab-badge mono tabular-nums">{formatBytes(tab.size)}</span>
                  {/if}
                </button>
              {/each}
            </div>

            <!-- Inspector Tab Content -->
            <div class="inspector-content">
              {#if activeTab === 'params'}
                {#if selectedParams.length > 0}
                  <div class="sub-toolbar">
                    <span class="sub-tb-info">{$t('core.flows.paramsSummary', { count: selectedParams.length })}</span>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="copy"
                      on:click={() => copyToClipboard(selectedParams.map((p) => `${p.key}=${p.value}`).join('\n'), translate('core.flows.copiedAllParams'))}
                    >
                      {$t('core.flows.copyAll')}
                    </Button>
                  </div>
                  <div class="kv-table">
                    <div class="kv-head params-grid mono">
                      <span>{$t('core.flows.colSource')}</span>
                      <span>{$t('core.flows.colKey')}</span>
                      <span>{$t('core.flows.colValue')}</span>
                      <span></span>
                    </div>
                    {#each selectedParams as p}
                      {@const signed = isSignParam(p.key, selectedFlow)}
                      <div class="kv-row params-grid" class:row-signed={signed}>
                        <span>
                          <Badge
                            variant={p.source === 'query' ? 'info' : p.source === 'form' ? 'purple' : 'success'}
                            size="xs"
                          >
                            {p.source}
                          </Badge>
                        </span>
                        <span class="kv-key mono" class:is-sign={signed}>
                          {p.key}
                          {#if signed}<Badge variant="warning" size="xs">{$t('core.flows.signTag')}</Badge>{/if}
                        </span>
                        <span class="kv-val mono">{p.value}</span>
                        <button class="kv-copy" type="button" title={$t('core.flows.copyValTitle')} on:click={() => copyToClipboard(p.value, translate('core.flows.copiedKey', { key: p.key }))}>
                          <Icon name="copy" size={12} />
                        </button>
                      </div>
                    {/each}
                  </div>
                {:else}
                  <EmptyState icon="sliders" title={$t('core.flows.noParamsTitle')} description={$t('core.flows.noParamsDesc')} compact />
                {/if}

              {:else if activeTab === 'req-headers' || activeTab === 'resp-headers'}
                {@const isReq = activeTab === 'req-headers'}
                {@const hdrList = isReq ? filteredReqHeaders : filteredRespHeaders}
                <div class="sub-toolbar">
                  <div class="inline-search">
                    <Icon name="search" size={12} />
                    <input type="text" bind:value={headerSearch} placeholder={$t('core.flows.filterHeadersPlaceholder')} />
                    {#if headerSearch}
                      <button type="button" class="clear-x" on:click={() => (headerSearch = '')}><Icon name="x" size={11} /></button>
                    {/if}
                  </div>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    on:click={() =>
                      copyToClipboard(
                        hdrList.map(([k, v]) => `${k}: ${v}`).join('\n'),
                        translate(isReq ? 'core.flows.copiedReqHeaders' : 'core.flows.copiedRespHeaders')
                      )}
                  >
                    {$t('core.flows.copyAll')}
                  </Button>
                </div>
                {#if hdrList.length === 0}
                  <EmptyState icon="file-text" title={$t('core.flows.noHeadersTitle')} description={$t('core.flows.noHeadersDesc')} compact />
                {:else}
                  <div class="kv-table">
                    {#each hdrList as [k, v]}
                      <div class="kv-row hdr-grid">
                        <span class="kv-key mono">{k}</span>
                        <span class="kv-val mono">{v}</span>
                        <button class="kv-copy" type="button" title={$t('core.flows.copyHeaderValTitle')} on:click={() => copyToClipboard(v, translate('core.flows.copiedKey', { key: k }))}>
                          <Icon name="copy" size={12} />
                        </button>
                      </div>
                    {/each}
                  </div>
                {/if}

              {:else if activeTab === 'req-body' || activeTab === 'resp-body'}
                {@const isReq = activeTab === 'req-body'}
                {@const rawBody = isReq ? selectedFlow.req_body : selectedFlow.resp_body}
                {@const ct = isReq ? reqContentType : respContentType}
                {@const view = isReq ? reqBodyView : respBodyView}
                <div class="sub-toolbar body-tb">
                  <div class="fmt-pills">
                    {#each ['auto', 'json', 'xml', 'proto', 'hex', 'raw'] as fmt}
                      <button
                        class="fmt-pill"
                        class:active={bodyFormat === fmt}
                        type="button"
                        on:click={() => switchBodyFormat(fmt)}
                      >
                        {fmt}
                      </button>
                    {/each}
                  </div>

                  <div class="inline-search">
                    <Icon name="search" size={12} />
                    <input type="text" bind:value={bodySearch} placeholder={$t('core.flows.findInBodyPlaceholder')} />
                    {#if bodySearch}
                      <span class="match-cnt mono tabular-nums">{view.matches}</span>
                      <button type="button" class="clear-x" on:click={() => (bodySearch = '')}><Icon name="x" size={11} /></button>
                    {/if}
                  </div>

                  <div class="tb-right">
                    <Button variant="ghost" size="xs" active={wordWrap} title={$t('core.flows.wrapTitle')} on:click={() => (wordWrap = !wordWrap)}>
                      {$t('core.flows.wrapBtn')}
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="copy"
                      disabled={!rawBody}
                      on:click={() => copyToClipboard(getFormattedBodyText(rawBody, ct, bodyFormat), translate('core.flows.copiedBody'))}
                    >
                      {$t('core.flows.copyBtn')}
                    </Button>
                  </div>
                </div>

                {#if !rawBody}
                  <EmptyState icon="file-code" title={$t('core.flows.emptyBodyTitle')} description={isReq ? $t('core.flows.emptyReqBodyDesc') : $t('core.flows.emptyRespBodyDesc')} compact />
                {:else}
                  <pre class="code-viewer mono" class:wrap={wordWrap}>{@html view.html}</pre>
                {/if}

              {:else if activeTab === 'raw'}
                <div class="raw-split">
                  <div class="raw-block">
                    <div class="sub-toolbar">
                      <span class="sub-tb-info">{$t('core.flows.rawRequestTitle')}</span>
                      <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(buildRawRequest(selectedFlow), translate('core.flows.copiedRawReq'))}>
                        {$t('core.flows.copyBtn')}
                      </Button>
                    </div>
                    <pre class="code-viewer mono wrap">{buildRawRequest(selectedFlow)}</pre>
                  </div>
                  <div class="raw-block">
                    <div class="sub-toolbar">
                      <span class="sub-tb-info">{$t('core.flows.rawResponseTitle')}</span>
                      <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(buildRawResponse(selectedFlow), translate('core.flows.copiedRawResp'))}>
                        {$t('core.flows.copyBtn')}
                      </Button>
                    </div>
                    <pre class="code-viewer mono wrap">{buildRawResponse(selectedFlow)}</pre>
                  </div>
                </div>

              {:else if activeTab === 'timing'}
                {@const reqHdrSz = headersByteLength(selectedFlow.req_headers)}
                {@const respHdrSz = headersByteLength(selectedFlow.resp_headers)}
                {@const totalSz = Math.max(1, reqHdrSz + reqBodySize + respHdrSz + respBodySize)}
                <div class="timing-view">
                  <div class="timing-card">
                    <div class="timing-head">
                      <span>{$t('core.flows.timingTotalLatency')}</span>
                      <span class="mono tabular-nums timing-big">{formatDuration(selectedFlow.latency_ms)}</span>
                    </div>
                    <div class="timing-bar">
                      <div class="timing-bar-fill lat-{latencyTone(selectedFlow.latency_ms)}" style="width: {Math.min(100, Math.max(8, (Number(selectedFlow.latency_ms) || 0) / 10))}%"></div>
                    </div>
                    <div class="timing-meta mono">
                      <span>{$t('core.flows.timingCapturedAt', { time: selectedFlow.time })}</span>
                      <span>{$t('core.flows.timingFlowId', { id: selectedFlow.id })}</span>
                    </div>
                  </div>

                  <div class="timing-grid">
                    <div class="timing-card">
                      <div class="timing-subhead">{$t('core.flows.timingReqPayload')}</div>
                      <div class="timing-kv"><span>{$t('core.flows.timingHeadersCount', { count: reqHeaderCount })}</span><span class="mono tabular-nums">{formatBytes(reqHdrSz)}</span></div>
                      <div class="timing-kv"><span>{$t('core.flows.timingBody')}</span><span class="mono tabular-nums">{formatBytes(reqBodySize)}</span></div>
                      <div class="timing-kv total"><span>{$t('core.flows.timingTotalSent')}</span><span class="mono tabular-nums">{formatBytes(reqHdrSz + reqBodySize)}</span></div>
                    </div>

                    <div class="timing-card">
                      <div class="timing-subhead">{$t('core.flows.timingRespPayload')}</div>
                      <div class="timing-kv"><span>{$t('core.flows.timingHeadersCount', { count: respHeaderCount })}</span><span class="mono tabular-nums">{formatBytes(respHdrSz)}</span></div>
                      <div class="timing-kv"><span>{$t('core.flows.timingBody')}</span><span class="mono tabular-nums">{formatBytes(respBodySize)}</span></div>
                      <div class="timing-kv total"><span>{$t('core.flows.timingTotalReceived')}</span><span class="mono tabular-nums">{formatBytes(respHdrSz + respBodySize)}</span></div>
                    </div>
                  </div>

                  <div class="timing-card">
                    <div class="timing-subhead">{$t('core.flows.timingComposition', { total: formatBytes(totalSz) })}</div>
                    <div class="size-stack">
                      <div class="ss-req" style="width: {((reqHdrSz + reqBodySize) / totalSz) * 100}%"></div>
                      <div class="ss-resp" style="width: {((respHdrSz + respBodySize) / totalSz) * 100}%"></div>
                    </div>
                    <div class="size-legend">
                      <span><i class="dot-req"></i> {$t('core.flows.timingReqPct', { pct: Math.round(((reqHdrSz + reqBodySize) / totalSz) * 100) })}</span>
                      <span><i class="dot-resp"></i> {$t('core.flows.timingRespPct', { pct: Math.round(((respHdrSz + respBodySize) / totalSz) * 100) })}</span>
                    </div>
                  </div>

                  {#if selectedFlow.tags?.length > 0 || selectedFlow.source_ref}
                    <div class="timing-card">
                      <div class="timing-subhead">{$t('core.flows.timingMetadata')}</div>
                      {#if selectedFlow.tags?.length > 0}
                        <div class="tag-row">
                          {#each selectedFlow.tags as tag}
                            <Badge variant="accent" size="xs">{tag}</Badge>
                          {/each}
                        </div>
                      {/if}
                      {#if selectedFlow.source_ref}
                        <div class="mono source-ref">
                          {selectedFlow.source_ref.file}:{selectedFlow.source_ref.line} {selectedFlow.source_ref.function || ''}
                        </div>
                      {/if}
                    </div>
                  {/if}
                </div>

              {:else if activeTab === 'export'}
                <div class="sub-toolbar">
                  <div class="fmt-pills">
                    {#each languages as lang}
                      <button
                        class="fmt-pill"
                        class:active={exportLang === lang}
                        type="button"
                        on:click={() => { exportLang = lang; generateExport() }}
                      >
                        {lang}
                      </button>
                    {/each}
                    <button
                      class="fmt-pill"
                      class:active={exportLang === 'jsonl'}
                      type="button"
                      on:click={() => { exportLang = 'jsonl'; generateExport() }}
                    >
                      JSONL
                    </button>
                  </div>
                  <Button variant="primary" size="xs" icon="copy" disabled={!exportCode} on:click={() => copyToClipboard(exportCode, translate('core.flows.copiedSnippet', { lang: exportLang }))}>
                    {$t('core.flows.copyCodeBtn')}
                  </Button>
                </div>
                <pre class="code-viewer mono wrap">{exportLoading ? $t('core.flows.generatingSnippet') : exportCode}</pre>
              {/if}
            </div>
          </div>
        {:else}
          <EmptyState
            icon="activity"
            title={$t('core.flows.selectFlowTitle')}
            description={$t('core.flows.selectFlowDesc')}
          >
            <div class="shortcut-hints">
              <span class="hint"><Kbd keys={['↑', '↓']} size="xs" /> {$t('core.flows.hintNavigate')}</span>
              <span class="hint"><Kbd keys="/" size="xs" /> {$t('core.flows.hintSearch')}</span>
              <span class="hint"><Kbd keys="Esc" size="xs" /> {$t('core.flows.hintClose')}</span>
            </div>
          </EmptyState>
        {/if}
      </div>
    </SplitPane>
  </div>
</div>

<!-- Right-click Context Menu -->
{#if ctxMenu}
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="ctx-backdrop" on:click={hideContextMenu}></div>
  <div class="ctx-menu" style="left:{ctxMenu.x}px; top:{ctxMenu.y}px" role="menu">
    <div class="ctx-title mono truncate">{ctxMenu.flow.method} {ctxMenu.flow.host}{ctxMenu.flow.path}</div>

    <button class="ctx-item" type="button" on:click={() => { copyToClipboard(ctxMenu.flow.url, translate('core.flows.copiedUrl')); hideContextMenu() }}>
      <Icon name="copy" size={13} /> <span>{$t('core.flows.ctx.copyUrl')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={() => { copyAsCurl(ctxMenu.flow.id); hideContextMenu() }}>
      <Icon name="code" size={13} /> <span>{$t('core.flows.ctx.copyCurl')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={() => { replayFlow(ctxMenu.flow.id); hideContextMenu() }}>
      <Icon name="play" size={13} /> <span>{$t('core.flows.ctx.replay')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={() => { const f = ctxMenu.flow; hideContextMenu(); selectFlow(f, { openPlugins: true }) }}>
      <Icon name="puzzle" size={13} /> <span>{$t('core.flows.ctx.debugInPlugins')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={() => { const f = ctxMenu.flow; hideContextMenu(); openGatewayPublishFlow(f) }}>
      <Icon name="globe" size={13} /> <span>{$t('core.flows.ctx.publishGateway')}</span>
    </button>

    <div class="ctx-sep"></div>

    <button class="ctx-item" type="button" on:click={() => { pinCompareBase(ctxMenu.flow); hideContextMenu() }}>
      <Icon name="pin" size={13} /> <span>{$t('core.flows.ctx.pinCompare')}</span>
    </button>
    {#if compareBaseId && compareBaseId !== ctxMenu.flow.id}
      <button class="ctx-item" type="button" on:click={() => { const f = ctxMenu.flow; hideContextMenu(); selectFlow(f).then(() => runCompareWith(f)) }}>
        <Icon name="diff" size={13} /> <span>{$t('core.flows.ctx.compareVs', { id: compareBaseId })}</span>
      </button>
    {/if}

    <div class="ctx-sep"></div>

    <button class="ctx-item" type="button" on:click={ctxAddBreakpoint}>
      <Icon name="pause" size={13} /> <span>{$t('core.flows.ctx.addBreakpoint')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={ctxAddMockRule}>
      <Icon name="layers" size={13} /> <span>{$t('core.flows.ctx.addMock')}</span>
    </button>
    <button class="ctx-item" type="button" on:click={ctxAddModifyRule}>
      <Icon name="edit" size={13} /> <span>{$t('core.flows.ctx.addModify')}</span>
    </button>
    <button class="ctx-item danger" type="button" on:click={ctxAddDropRule}>
      <Icon name="ban" size={13} /> <span>{$t('core.flows.ctx.addBlock')}</span>
    </button>

    {#if pluginList.length > 0}
      <div class="ctx-sep"></div>
      <div class="ctx-group-label">{$t('core.flows.ctx.runPluginGroup')}</div>
      {#each pluginList as p}
        <button class="ctx-item" type="button" on:click={() => ctxRunPlugin(p.name)}>
          <Icon name="puzzle" size={13} /> <span>{p.name}</span>
        </button>
      {/each}
    {/if}
  </div>
{/if}

<!-- Plugin Execution Output Modal -->
{#if pluginModal}
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="modal-backdrop" on:click={() => (pluginModal = null)}>
    <div class="modal-card cap-card" on:click|stopPropagation>
      <div class="modal-head">
        <div class="modal-title">
          <Icon name="puzzle" size={14} />
          <span>{$t('core.flows.pluginTitle', { name: pluginModal.name })}</span>
          <Badge variant="neutral" size="xs" mono>#{pluginModal.flowId}</Badge>
        </div>
        <Button variant="ghost" size="xs" icon="x" iconOnly title={$t('core.flows.closeModalTitle')} on:click={() => (pluginModal = null)} />
      </div>
      <div class="modal-body">
        {#if pluginModal.error}
          <pre class="modal-pre error mono">{pluginModal.error}</pre>
        {:else}
          <pre class="modal-pre mono">{pluginModal.output || $t('core.flows.noOutput')}</pre>
        {/if}
      </div>
      <div class="modal-foot">
        <Button
          variant="secondary"
          size="xs"
          icon="copy"
          on:click={() => copyToClipboard(pluginModal.output || pluginModal.error, translate('core.flows.copiedPluginOutput'))}
        >
          {$t('core.flows.copyOutput')}
        </Button>
        <Button variant="primary" size="xs" on:click={() => (pluginModal = null)}>{$t('core.flows.closeBtn')}</Button>
      </div>
    </div>
  </div>
{/if}

<style>
  .flows-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Primary Toolbar */
  .toolbar-primary {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .search-box,
  .host-box {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 8px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .search-box {
    flex: 1 1 200px;
    min-width: 160px;
  }

  .host-box {
    flex: 0 1 175px;
    min-width: 120px;
  }

  .search-box:focus-within,
  .host-box:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .search-box input,
  .host-box input {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-sm);
    outline: none;
  }

  .search-box input::placeholder,
  .host-box input::placeholder {
    color: var(--text-faint);
  }

  .clear-x {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    padding: 2px;
    border-radius: var(--radius-xs);
  }

  .clear-x:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .toolbar-count {
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 0 6px;
    white-space: nowrap;
  }

  .cnt-hi {
    color: var(--text-primary);
    font-weight: 600;
  }

  .cnt-sep {
    margin: 0 2px;
    color: var(--text-faint);
  }

  .cnt-label {
    margin-left: 3px;
    color: var(--text-faint);
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }

  .seg-group {
    display: inline-flex;
    align-items: center;
    padding: 2px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    gap: 1px;
  }

  .seg-btn {
    height: 20px;
    padding: 0 7px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-2xs);
    font-weight: 500;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: all var(--transition-fast);
  }

  .seg-btn:hover:not(:disabled) {
    color: var(--text-primary);
  }

  .seg-btn.active {
    background: var(--bg-elevated);
    color: var(--accent);
    box-shadow: var(--shadow-sm);
  }

  .seg-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  /* Tier 2: Facets Strip */
  .toolbar-facets {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    overflow-x: auto;
    scrollbar-width: none;
  }

  .toolbar-facets::-webkit-scrollbar {
    display: none;
  }

  .facet-group {
    display: flex;
    align-items: center;
    gap: 3px;
    flex-shrink: 0;
  }

  .facet-divider {
    width: 1px;
    height: 14px;
    background: var(--border-default);
    flex-shrink: 0;
  }

  .facet-pill {
    height: 21px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: all var(--transition-fast);
  }

  .facet-pill:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .facet-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
    font-weight: 600;
  }

  .method-pill.active[data-method='GET'] { color: var(--method-get); border-color: color-mix(in srgb, var(--method-get) 40%, transparent); background: color-mix(in srgb, var(--method-get) 14%, transparent); }
  .method-pill.active[data-method='POST'] { color: var(--method-post); border-color: color-mix(in srgb, var(--method-post) 40%, transparent); background: color-mix(in srgb, var(--method-post) 14%, transparent); }
  .method-pill.active[data-method='PUT'] { color: var(--method-put); border-color: color-mix(in srgb, var(--method-put) 40%, transparent); background: color-mix(in srgb, var(--method-put) 14%, transparent); }
  .method-pill.active[data-method='PATCH'] { color: var(--method-patch); border-color: color-mix(in srgb, var(--method-patch) 40%, transparent); background: color-mix(in srgb, var(--method-patch) 14%, transparent); }
  .method-pill.active[data-method='DELETE'] { color: var(--method-delete); border-color: color-mix(in srgb, var(--method-delete) 40%, transparent); background: color-mix(in srgb, var(--method-delete) 14%, transparent); }

  .status-pill.active[data-status='2xx'] { color: var(--status-success); background: var(--status-success-bg); border-color: var(--status-success-border); }
  .status-pill.active[data-status='3xx'] { color: var(--status-info); background: var(--status-info-bg); border-color: var(--status-info-border); }
  .status-pill.active[data-status='4xx'] { color: var(--status-warning); background: var(--status-warning-bg); border-color: var(--status-warning-border); }
  .status-pill.active[data-status='5xx'] { color: var(--status-danger); background: var(--status-danger-bg); border-color: var(--status-danger-border); }

  .facet-reset {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    height: 21px;
    padding: 0 7px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    flex-shrink: 0;
  }

  .facet-reset:hover {
    color: var(--status-danger);
    border-color: var(--status-danger-border);
  }

  .compare-chip {
    margin-left: auto;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 21px;
    max-width: 220px;
    padding: 0 7px;
    border-radius: var(--radius-full);
    background: var(--status-purple-bg);
    border: 1px solid var(--status-purple-border);
    color: var(--status-purple);
    font-size: 10.5px;
    flex-shrink: 0;
  }

  .compare-chip button {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    display: flex;
    align-items: center;
  }

  /* HAR Import Bar */
  .har-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 12px;
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-default);
    color: var(--text-secondary);
    font-size: var(--text-xs);
    flex-shrink: 0;
  }

  .har-label {
    font-weight: 600;
    color: var(--text-primary);
  }

  .har-input {
    flex: 1;
    max-width: 440px;
    height: 26px;
  }

  /* Split Workspace */
  .workspace {
    flex: 1;
    min-height: 0;
    display: flex;
  }

  /* Primary Flow List Pane */
  .list-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  .table-head {
    display: grid;
    grid-template-columns: 16px 38px 58px 44px minmax(120px, 1fr) 44px 66px 70px;
    gap: 6px;
    align-items: center;
    padding: 6px 10px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .list-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  .flow-row {
    display: grid;
    grid-template-columns: 16px 38px 58px 44px minmax(120px, 1fr) 44px 66px 70px;
    gap: 6px;
    align-items: center;
    width: 100%;
    padding: 5px 10px;
    border: none;
    border-bottom: 1px solid var(--border-subtle);
    border-left: 2px solid transparent;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    text-align: left;
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .flow-row:hover {
    background: var(--bg-hover);
  }

  .flow-row.has-rule {
    border-left-color: var(--status-warning);
  }

  .flow-row.is-base {
    border-left-color: var(--status-purple);
  }

  .flow-row.selected {
    background: var(--bg-active);
    border-left-color: var(--accent);
  }

  .c-rule {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--status-warning);
  }

  .c-id {
    font-size: 10.5px;
    color: var(--text-faint);
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .c-method,
  .c-status {
    display: flex;
    align-items: center;
  }

  .c-endpoint {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 11.5px;
  }

  .ep-host {
    color: var(--text-muted);
    margin-right: 1px;
  }

  .ep-p {
    color: var(--text-primary);
    font-weight: 500;
  }

  .ep-q {
    color: var(--accent);
    opacity: 0.85;
  }

  .c-type {
    font-size: 10px;
    color: var(--text-faint);
    text-align: center;
    text-transform: uppercase;
  }

  .c-lat {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 2px;
    font-size: 10.5px;
  }

  .lat-fast .lat-val { color: var(--text-secondary); }
  .lat-med .lat-val { color: var(--status-warning); }
  .lat-slow .lat-val { color: var(--status-danger); font-weight: 600; }

  .lat-track {
    width: 100%;
    height: 2px;
    background: var(--bg-subtle);
    border-radius: 2px;
    overflow: hidden;
  }

  .lat-fill {
    display: block;
    height: 100%;
    border-radius: 2px;
    background: var(--accent);
  }

  .lat-med .lat-fill { background: var(--status-warning); }
  .lat-slow .lat-fill { background: var(--status-danger); }

  .c-time {
    font-size: 10.5px;
    color: var(--text-faint);
    text-align: right;
  }

  /* API Groups View */
  .group-section {
    border-bottom: 1px solid var(--border-subtle);
  }

  .group-head {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 7px 12px;
    background: var(--bg-header);
    color: var(--text-muted);
    font-size: var(--text-xs);
    position: sticky;
    top: 0;
  }

  .group-host {
    color: var(--accent);
    font-weight: 600;
  }

  .group-prefix {
    flex: 1;
    color: var(--text-secondary);
  }

  .group-ep-row {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 12px 6px 24px;
    border: none;
    border-top: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    text-align: left;
    cursor: pointer;
  }

  .group-ep-row:hover {
    background: var(--bg-hover);
  }

  .ep-path {
    flex: 1;
    color: var(--text-primary);
  }

  .ep-lat,
  .ep-hits {
    font-size: 11px;
    color: var(--text-muted);
  }

  /* Secondary Inspector Pane */
  .inspector-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-surface);
  }

  .pane-mode-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 34px;
    padding: 0 8px 0 6px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .mode-tabs {
    display: flex;
    align-items: center;
    height: 100%;
    gap: 2px;
  }

  .mode-tab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 100%;
    padding: 0 10px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
  }

  .mode-tab:hover {
    color: var(--text-primary);
  }

  .mode-tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 600;
  }

  .mode-pill {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-xs);
    background: var(--bg-subtle);
    color: var(--text-secondary);
  }

  .live-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-success);
    animation: cap-pulse 1.8s ease-in-out infinite;
  }

  .pane-mode-right {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /* Detail Shell */
  .detail-shell {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    transition: opacity var(--transition-fast);
  }

  .detail-shell.is-loading {
    opacity: 0.72;
  }

  .detail-summary {
    display: flex;
    flex-direction: column;
    gap: 7px;
    padding: 10px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .summary-top {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
  }

  .summary-url {
    flex: 1;
    font-size: var(--text-sm);
    color: var(--text-primary);
    user-select: text;
  }

  .summary-meta-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }

  .meta-pills {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
    color: var(--text-muted);
    flex-wrap: wrap;
  }

  .meta-item {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .summary-actions {
    display: flex;
    align-items: center;
    gap: 5px;
  }

  /* Drawers (Replay, Compare, Sign) */
  .drawer-panel {
    background: var(--bg-app);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .drawer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
  }

  .drawer-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .replay-form {
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .rf-row {
    display: flex;
    gap: 6px;
  }

  .rf-method {
    width: 88px;
  }

  .flex-1 {
    flex: 1;
    min-width: 0;
  }

  .rf-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }

  .rf-col {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .rf-label {
    font-size: 10px;
    color: var(--text-muted);
    font-weight: 500;
  }

  .cap-textarea {
    width: 100%;
    min-height: 58px;
    max-height: 120px;
    padding: 6px 8px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 11.5px;
    resize: vertical;
    outline: none;
  }

  .cap-textarea:focus {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .rf-actions {
    display: flex;
    justify-content: flex-end;
  }

  .rr-left,
  .rr-right {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .rr-lat {
    font-size: 11px;
    color: var(--text-muted);
  }

  .rr-body {
    max-height: 130px;
    overflow: auto;
    margin: 0;
    padding: 8px 12px;
    font-size: 11.5px;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-all;
  }

  /* Compare Drawer */
  .compare-body {
    max-height: 190px;
    overflow-y: auto;
    padding: 8px 12px;
    font-size: 11px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .cmp-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    color: var(--text-secondary);
  }

  .cmp-sec-title {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    margin-bottom: 4px;
  }

  .cmp-line {
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    word-break: break-all;
  }

  .cmp-line.add { color: var(--status-success); background: var(--status-success-bg); }
  .cmp-line.rem { color: var(--status-danger); background: var(--status-danger-bg); }
  .cmp-line.chg { color: var(--status-warning); background: var(--status-warning-bg); }

  .cmp-pre {
    margin: 0;
    padding: 6px 8px;
    background: var(--bg-surface);
    border-radius: var(--radius-xs);
    color: var(--text-secondary);
    white-space: pre-wrap;
  }

  /* Sign Results */
  .sign-list {
    padding: 6px 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: 130px;
    overflow-y: auto;
  }

  .sign-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11.5px;
    padding: 3px 0;
  }

  .sr-param {
    color: var(--accent);
    font-weight: 600;
    min-width: 72px;
  }

  .sr-algs {
    color: var(--status-success);
    font-weight: 500;
  }

  .sr-guess {
    color: var(--text-muted);
    font-style: italic;
    margin-left: auto;
    max-width: 240px;
  }

  /* Inspector Tabs */
  .inspector-tabs {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 0 8px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    overflow-x: auto;
    scrollbar-width: none;
    flex-shrink: 0;
  }

  .inspector-tabs::-webkit-scrollbar {
    display: none;
  }

  .itab {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 32px;
    padding: 0 9px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .itab:hover {
    color: var(--text-primary);
  }

  .itab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 600;
  }

  .itab-badge {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .inspector-content {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .sub-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .sub-tb-info {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .inline-search {
    display: flex;
    align-items: center;
    gap: 5px;
    height: 24px;
    padding: 0 7px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    color: var(--text-faint);
    min-width: 150px;
  }

  .inline-search:focus-within {
    border-color: var(--accent);
  }

  .inline-search input {
    width: 120px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 11px;
    outline: none;
  }

  .match-cnt {
    font-size: 10px;
    color: var(--accent);
    padding: 0 4px;
  }

  .fmt-pills {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 2px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
  }

  .fmt-pill {
    height: 20px;
    padding: 0 7px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 10.5px;
    font-weight: 500;
    text-transform: uppercase;
    cursor: pointer;
  }

  .fmt-pill:hover {
    color: var(--text-primary);
  }

  .fmt-pill.active {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 600;
  }

  .tb-right {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  /* KV Tables (Params & Headers) */
  .kv-table {
    flex: 1;
    overflow-y: auto;
  }

  .kv-head {
    padding: 6px 12px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    position: sticky;
    top: 0;
  }

  .params-grid {
    display: grid;
    grid-template-columns: 62px minmax(110px, 180px) minmax(0, 1fr) 26px;
    gap: 8px;
    align-items: center;
  }

  .hdr-grid {
    display: grid;
    grid-template-columns: minmax(120px, 200px) minmax(0, 1fr) 26px;
    gap: 8px;
    align-items: start;
  }

  .kv-row {
    padding: 6px 12px;
    border-bottom: 1px solid var(--border-subtle);
    font-size: 12px;
  }

  .kv-row:hover {
    background: var(--bg-hover);
  }

  .kv-row.row-signed {
    background: color-mix(in srgb, var(--status-warning-bg) 45%, transparent);
  }

  .kv-key {
    color: var(--accent);
    font-weight: 500;
    word-break: break-word;
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }

  .kv-key.is-sign {
    color: var(--status-warning);
  }

  .kv-val {
    color: var(--text-secondary);
    word-break: break-all;
    user-select: text;
  }

  .kv-copy {
    width: 22px;
    height: 22px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    transition: opacity var(--transition-fast), color var(--transition-fast);
  }

  .kv-row:hover .kv-copy,
  .kv-copy:focus-visible {
    opacity: 1;
  }

  .kv-copy:hover {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }

  /* Syntax-Highlighted Body / Code Viewer */
  .code-viewer {
    flex: 1;
    min-height: 0;
    overflow: auto;
    margin: 0;
    padding: 10px 14px;
    background: var(--bg-app);
    color: var(--text-primary);
    font-size: 12px;
    line-height: 1.55;
    white-space: pre;
    user-select: text;
  }

  .code-viewer.wrap {
    white-space: pre-wrap;
    word-break: break-word;
  }

  .code-viewer :global(.hl-key) { color: var(--accent); }
  .code-viewer :global(.hl-str) { color: var(--status-success); }
  .code-viewer :global(.hl-num) { color: var(--status-warning); }
  .code-viewer :global(.hl-bool) { color: var(--status-purple); font-weight: 600; }
  .code-viewer :global(.hl-null) { color: var(--text-faint); font-style: italic; }
  .code-viewer :global(.hl-tag) { color: var(--status-info); font-weight: 600; }
  .code-viewer :global(.hl-punct) { color: var(--text-faint); }
  .code-viewer :global(.hl-match) {
    background: var(--status-warning-bg);
    color: var(--status-warning);
    border-radius: 2px;
    padding: 0 1px;
    outline: 1px solid var(--status-warning-border);
  }

  /* Raw Dual View */
  .raw-split {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-rows: 1fr 1fr;
  }

  .raw-block {
    display: flex;
    flex-direction: column;
    min-height: 0;
    border-bottom: 1px solid var(--border-default);
  }

  .raw-block:last-child {
    border-bottom: none;
  }

  /* Timing View */
  .timing-view {
    flex: 1;
    overflow-y: auto;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .timing-card {
    padding: 12px 14px;
    border-radius: var(--radius-md);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .timing-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .timing-big {
    font-size: var(--text-lg);
    font-weight: 700;
    color: var(--text-primary);
  }

  .timing-bar {
    height: 8px;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    overflow: hidden;
  }

  .timing-bar-fill {
    height: 100%;
    border-radius: var(--radius-full);
    background: var(--status-success);
  }

  .timing-bar-fill.lat-med { background: var(--status-warning); }
  .timing-bar-fill.lat-slow { background: var(--status-danger); }

  .timing-meta {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    color: var(--text-faint);
  }

  .timing-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  .timing-subhead {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
  }

  .timing-kv {
    display: flex;
    justify-content: space-between;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .timing-kv.total {
    padding-top: 6px;
    border-top: 1px solid var(--border-subtle);
    color: var(--text-primary);
    font-weight: 600;
  }

  .size-stack {
    display: flex;
    height: 8px;
    border-radius: var(--radius-full);
    overflow: hidden;
    background: var(--bg-elevated);
  }

  .ss-req { background: var(--accent); }
  .ss-resp { background: var(--status-success); }

  .size-legend {
    display: flex;
    gap: 14px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .size-legend i {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 4px;
  }

  .dot-req { background: var(--accent); }
  .dot-resp { background: var(--status-success); }

  .tag-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .source-ref {
    font-size: 11.5px;
    color: var(--text-secondary);
  }

  /* Plugin Workbench & Device Mirror Panels */
  .plugins-panel,
  .device-panel {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .device-stage {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  .device-telemetry-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 5px 10px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    font-size: 11px;
    flex-shrink: 0;
  }

  .telemetry-left {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .telemetry-metric {
    color: var(--text-primary);
    font-weight: 600;
    font-size: 11px;
  }

  .telemetry-sep {
    color: var(--text-faint);
  }

  .telemetry-serial {
    color: var(--text-muted);
    font-size: 10.5px;
    max-width: 140px;
  }

  .telemetry-hint {
    color: var(--text-faint);
    font-size: 10.5px;
    white-space: nowrap;
  }

  .device-fallback-bar {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 4px 10px;
    background: var(--status-info-bg);
    border-bottom: 1px solid var(--status-info-border);
    color: var(--status-info);
    font-size: 11px;
    flex-shrink: 0;
  }

  .device-fallback-bar span {
    flex: 1;
    min-width: 0;
  }

  .device-viewport {
    flex: 1;
    min-height: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 8px;
    overflow: hidden;
  }

  .device-screen-box {
    position: relative;
    height: 100%;
    max-width: 100%;
    border-radius: var(--radius-lg);
    overflow: hidden;
    border: 1px solid var(--border-strong);
    background: var(--terminal-bg);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .device-img {
    width: 100%;
    height: 100%;
    object-fit: contain;
    cursor: crosshair;
    display: block;
    user-select: none;
    touch-action: none;
    -webkit-user-drag: none;
  }

  .gesture-overlay {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    overflow: visible;
  }

  .swipe-line {
    stroke: var(--accent);
    stroke-width: 2.5;
    stroke-linecap: round;
    stroke-dasharray: 4 3;
  }

  .swipe-start {
    fill: var(--accent);
    opacity: 0.85;
  }

  .swipe-end {
    fill: var(--accent-soft);
    stroke: var(--accent);
    stroke-width: 2;
  }

  .tap-ring {
    fill: var(--accent-soft);
    stroke: var(--accent);
    stroke-width: 2;
    animation: tap-pulse 360ms ease-out forwards;
  }

  @keyframes tap-pulse {
    from {
      opacity: 0.95;
    }
    to {
      opacity: 0;
    }
  }

  .device-connecting {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 24px;
    color: var(--text-muted);
    font-size: var(--text-xs);
    text-align: center;
  }

  .device-toolbar {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-header);
    border-top: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }

  .dev-nav-btns {
    display: flex;
    gap: 4px;
  }

  .device-shell {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--terminal-bg);
  }

  .shell-tabs {
    display: flex;
    align-items: center;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    padding: 0 4px;
    flex-shrink: 0;
  }

  .sh-tab {
    display: inline-flex;
    align-items: center;
    border-bottom: 2px solid transparent;
    color: var(--text-muted);
  }

  .sh-tab.active {
    color: var(--status-success);
    border-bottom-color: var(--status-success);
  }

  .sh-tab-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 7px;
    border: none;
    background: transparent;
    color: inherit;
    font-size: 11px;
    cursor: pointer;
  }

  .sh-tab-x,
  .sh-add {
    border: none;
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    padding: 4px 6px;
    display: flex;
    align-items: center;
  }

  .sh-tab-x:hover { color: var(--status-danger); }
  .sh-add:hover { color: var(--status-success); }

  .shell-textarea {
    flex: 1;
    width: 100%;
    resize: none;
    border: none;
    outline: none;
    background: var(--terminal-bg);
    color: var(--terminal-fg);
    font-size: 12px;
    line-height: 1.5;
    padding: 8px 10px;
    caret-color: var(--terminal-fg);
  }

  /* Shortcut hints in EmptyState */
  .shortcut-hints {
    display: flex;
    align-items: center;
    gap: 14px;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .hint {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  /* Context Menu */
  .ctx-backdrop {
    position: fixed;
    inset: 0;
    z-index: var(--z-dropdown);
  }

  .ctx-menu {
    position: fixed;
    z-index: calc(var(--z-dropdown) + 1);
    width: 236px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    padding: 4px;
    box-shadow: var(--shadow-lg);
  }

  .ctx-title {
    padding: 6px 8px;
    font-size: 10.5px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-subtle);
    margin-bottom: 3px;
  }

  .ctx-group-label {
    padding: 4px 8px 2px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
  }

  .ctx-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 6px 8px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    cursor: pointer;
    text-align: left;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .ctx-item:hover {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .ctx-item.danger:hover {
    background: var(--status-danger-bg);
    color: var(--status-danger);
  }

  .ctx-sep {
    height: 1px;
    background: var(--border-subtle);
    margin: 4px 0;
  }

  /* Plugin Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }

  .modal-card {
    width: min(640px, 100%);
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: var(--shadow-lg);
  }

  .modal-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
  }

  .modal-title {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .modal-body {
    flex: 1;
    overflow: auto;
    padding: 12px 14px;
    background: var(--bg-app);
  }

  .modal-pre {
    margin: 0;
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .modal-pre.error {
    color: var(--status-danger);
  }

  .modal-foot {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding: 10px 14px;
    background: var(--bg-surface);
    border-top: 1px solid var(--border-subtle);
  }

  /* Responsive polish at 900x650 */
  @media (max-width: 1020px) {
    .table-head,
    .flow-row {
      grid-template-columns: 14px 34px 54px 40px minmax(100px, 1fr) 58px;
    }

    .c-type,
    .c-time {
      display: none;
    }

    .rf-grid,
    .timing-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
