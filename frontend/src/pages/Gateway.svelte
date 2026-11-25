<script>
  import { onMount, onDestroy } from 'svelte'
  import '../lib/locales/gateway.js'
  import { t, translate } from '../lib/i18n.js'
  import { gatewayState as S, gatewayHandoff } from '../lib/gatewayState.js'
  import { openAIHealModal } from '../lib/aiState.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration, formatTime } from '../lib/format.js'
  import { hasPrimaryMod } from '../lib/shortcuts.js'
  import { registerCommands } from '../lib/commandPalette.js'

  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import CodeEditor from '../components/CodeEditor.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
  const PROXY_STRATEGIES = ['round_robin', 'random', 'least_latency', 'sticky_device']
  const ACCOUNT_STRATEGIES = ['round_robin', 'least_used', 'sticky_device']
  const ACCOUNT_STATUSES = ['active', 'expired', 'challenged', 'disabled']
  const WORKER_KINDS = ['unidbg_http', 'qiling_http', 'script_http', 'custom']
  const SIGNER_KINDS = ['builtin_hmac', 'script', 'http', 'unidbg_http', 'frida_rpc']
  const HMAC_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'hmac-md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512']
  const SCRIPT_RUNTIMES = ['python3', 'node', 'sh']
  const INJECT_TARGETS = ['query', 'header', 'body_json']
  const TEMPLATE_VARS = [
    '{{input.keyword}}',
    '{{device.oaid}}',
    '{{device.user_agent}}',
    '{{device.device_id}}',
    '{{device.android_id}}',
    '{{timestamp}}',
    '{{timestamp_ms}}',
    '{{nonce}}',
    '{{uuid}}',
  ]
  const ACCOUNT_TEMPLATE_VARS = [
    '{{account.token}}',
    '{{account.cookie}}',
    '{{account.username}}',
  ]
  const FALLBACK_TLS_PROFILES = [
    { id: 'go_default', name: 'Go Default (crypto/tls)', platform: 'generic' },
    { id: 'chrome_131', name: 'Chrome 131 (Desktop)', platform: 'desktop' },
    { id: 'safari_17', name: 'Safari 17 (macOS / WebKit)', platform: 'desktop' },
    { id: 'firefox_132', name: 'Firefox 132 (Desktop)', platform: 'desktop' },
    { id: 'okhttp_android', name: 'OkHttp (Android)', platform: 'android' },
    { id: 'ios_cfnetwork', name: 'CFNetwork (iOS)', platform: 'ios' },
  ]

  const STARTER_SCRIPTS = {
    python3: `import hashlib, json, sys

req = json.load(sys.stdin)
q = req.get("query") or {}
ts = str(req.get("timestamp") or "")
nonce = str(req.get("nonce") or "")
canonical = "&".join(f"{k}={q[k]}" for k in sorted(q.keys()))
sig = hashlib.sha256(f"{canonical}|{ts}|{nonce}".encode()).hexdigest()

json.dump({
    "sign": sig,
    "params": {"ts": ts, "nonce": nonce},
    "headers": {"X-Sign": sig}
}, sys.stdout)
`,
    node: `const crypto = require('crypto');
const fs = require('fs');

const req = JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
const q = req.query || {};
const canonical = Object.keys(q).sort().map((k) => \`\${k}=\${q[k]}\`).join('&');
const sig = crypto.createHash('sha256').update(\`\${canonical}|\${req.timestamp || ''}|\${req.nonce || ''}\`).digest('hex');

process.stdout.write(JSON.stringify({
  sign: sig,
  params: { ts: String(req.timestamp || ''), nonce: String(req.nonce || '') },
  headers: { 'X-Sign': sig }
}));
`,
    sh: `#!/bin/sh
# Reads SignerInput JSON from stdin and outputs SignerOutput JSON
INPUT=$(cat)
SIG=$(printf "%s" "$INPUT" | shasum -a 256 | awk '{print $1}')
printf '{"sign":"%s"}\n' "$SIG"
`,
  }

  function buildFridaStarterScript(exportName = 'sign') {
    const fn = String(exportName || 'sign').trim() || 'sign'
    const keyExpr = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(fn) ? fn : JSON.stringify(fn)
    return `'use strict';

rpc.exports = {
  ${keyExpr}: function (payload) {
    let result = '';
    Java.perform(function () {
      // Example: invoke target app's Java/JNI signing routine
      // const Signer = Java.use('com.example.app.Signer');
      // result = Signer.sign(payload.url || '', JSON.stringify(payload.query || {}));
      result = 'frida-' + String(payload.timestamp || Date.now());
    });
    return {
      sign: result,
      headers: { 'X-Sign': result }
    };
  }
};
`
  }

  function isUnmodifiedStarterScript(code) {
    const trimmed = String(code || '').trim()
    if (!trimmed) return true
    if (Object.values(STARTER_SCRIPTS).some((tpl) => tpl.trim() === trimmed)) return true
    if (trimmed === buildFridaStarterScript(sFridaExport).trim() || trimmed === buildFridaStarterScript('sign').trim()) {
      return true
    }
    return false
  }

  // ==================== Global Gateway State ====================
  let activeTab = S.activeTab || 'routes'
  let stats = {
    running: false,
    listen_addr: S.listenAddr || '127.0.0.1:9090',
    started_at: '',
    total_requests: 0,
    success_requests: 0,
    error_requests: 0,
    rate_limited: 0,
    auth_failures: 0,
    avg_latency_ms: 0,
    proxy_total: 0,
    proxy_healthy: 0,
    device_total: 0,
    device_enabled: 0,
    signer_total: 0,
    route_total: 0,
    route_enabled: 0,
    total_accounts: 0,
    active_accounts: 0,
    total_workers: 0,
    healthy_workers: 0,
    cache_hits: 0,
    cache_misses: 0,
    open_circuits: 0,
  }
  let listenAddr = S.listenAddr || '127.0.0.1:9090'
  let gwConfig = {
    listen_addr: '127.0.0.1:9090',
    require_auth: false,
    api_keys: [],
    cors_origins: ['*'],
    max_logs: 500,
  }
  let serverBusy = false
  let refreshingAll = false

  // Config, OpenAPI, Prometheus & Docker Drawers
  let showConfigDrawer = false
  let cfgRequireAuth = false
  let cfgApiKeys = []
  let cfgNewKey = ''
  let cfgRevealKeys = false
  let cfgCorsText = '*'
  let cfgMaxLogs = 500
  let savingConfig = false

  let showOpenApiDrawer = false
  let openApiSpec = ''
  let loadingOpenApi = false

  let showPromDrawer = false
  let promMetrics = ''
  let loadingProm = false

  let showDockerDrawer = false
  let dockerBundle = null
  let dockerTab = 'dockerfile' // 'dockerfile' | 'compose'
  let loadingDocker = false

  // ==================== Sub-tab 1: Routes & Live Tester ====================
  let routes = []
  let tlsProfiles = []
  let ja3Cache = {}
  let loadingJa3 = false
  let circuitStates = {}
  let routeSearch = S.routeSearch || ''
  let selectedRoute = null
  let isNewRoute = false
  let confirmDeleteRouteId = null
  let savingRoute = false

  // Route Editor fields
  let rId = ''
  let rSlug = ''
  let rName = ''
  let rDescription = ''
  let rEnabled = true
  let rMethod = 'GET'
  let rUpstreamUrl = ''
  let rStaticHeaders = []
  let rStaticQuery = []
  let rBodyTemplate = ''
  let rSignerId = ''
  let rDeviceTags = ''
  let rProxyTags = ''
  let rRequireDevice = false
  let rRequireProxy = false
  let rRateLimitRps = 0
  let rTimeoutSec = 15
  let rSourceFlowId = ''
  // Route Production Controls fields
  let openTlsSection = true
  let openAccountSection = true
  let openResilienceSection = true
  let rTlsProfile = 'go_default'
  let rMtlsCertPath = ''
  let rMtlsKeyPath = ''
  let mtlsValidation = null
  let validatingMtls = false
  let mtlsValidateSeq = 0
  let rAccountTags = ''
  let rRequireAccount = false
  let rAutoRefresh = false
  let rRefreshRouteSlug = ''
  let rRefreshOnStatuses = ''
  let rRefreshOnBodySubstr = ''
  let rChallengeWebhookUrl = ''
  let rCacheTtlSec = 0
  let rCacheKeyFields = ''
  let rCacheMaxEntries = 512
  let rCircuitFailThreshold = 0
  let rCircuitCooldownSec = 30
  let clearingCache = false
  let resettingCircuit = false
  let templateTarget = 'url' // 'url' | 'body'
  let urlInputEl = null
  let bodyInputEl = null

  // Publish from Captured Flow picker
  let showFlowPicker = false
  let capturedFlows = []
  let loadingFlows = false
  let flowSearch = ''
  let selectedFlowId = ''
  let publishSlug = ''
  let publishName = ''
  let publishingFlow = false

  // Live Route Test Console
  let testInputTab = 'input' // 'input' | 'body' | 'headers'
  let testRespTab = 'body' // 'body' | 'headers' | 'signed'
  let testInputJson = S.testInputJson || '{\n  "keyword": "cap"\n}'
  let testOverrideBody = S.testBody || ''
  let testExtraHeaders = ''
  let testDeviceId = S.testDeviceId || ''
  let testProxyId = S.testProxyId || ''
  let testAccountId = S.testAccountId || ''
  let testBypassCache = Boolean(S.testBypassCache)
  let testRaw = Boolean(S.testRaw)
  let testingRoute = false
  let testResult = S.lastTestResult || null
  let testPreviewCache = new Map() // key: `${slug}:${ts}` or latest per slug

  // ==================== Sub-tab 2: Proxy IP Pool ====================
  let proxies = []
  let proxyConfig = {
    strategy: 'round_robin',
    provider_url: '',
    provider_format: 'lines',
    provider_json_path: '',
    refresh_interval_sec: 0,
    health_check_url: 'http://connectivitycheck.gstatic.com/generate_204',
    failover_retries: 2,
  }
  let savingProxyCfg = false
  let checkingProxies = false
  let fetchingProxies = false
  let proxySearch = S.proxySearch || ''
  let proxyStatusFilter = S.proxyStatusFilter || 'all'

  // Add / Bulk Import Proxy Drawer
  let showProxyDrawer = false
  let proxyDrawerTab = 'single' // 'single' | 'bulk'
  let pEditId = ''
  let pName = ''
  let pUrl = ''
  let pUsername = ''
  let pPassword = ''
  let pRegion = ''
  let pTags = ''
  let pEnabled = true
  let savingProxy = false

  let bulkRawLines = ''
  let bulkDefaultScheme = 'http'
  let bulkRegion = ''
  let bulkTags = ''
  let importingProxies = false

  // ==================== Sub-tab 3: Device Pool ====================
  let devices = []
  let devicePresets = []
  let deviceSearch = S.deviceSearch || ''
  let deviceKindFilter = S.deviceKindFilter || 'all'
  let selectedDevice = null
  let isNewDevice = false
  let confirmDeleteDeviceId = null
  let savingDevice = false
  let syncingAdb = false

  let showPresetMenu = false
  let selectedPresetId = ''
  let presetCustomName = ''
  let creatingPreset = false

  // Device Editor fields
  let dId = ''
  let dName = ''
  let dKind = 'virtual'
  let dAdbSerial = ''
  let dEnabled = true
  let dTags = ''
  let dStickyProxyId = ''
  let dProxyRegion = ''
  let dModel = ''
  let dBrand = ''
  let dOsVersion = ''
  let dSdk = 34
  let dUserAgent = ''
  let dDeviceId = ''
  let dAndroidId = ''
  let dOaid = ''
  let dLocale = 'zh_CN'
  let dTimezone = 'Asia/Shanghai'
  let dScreen = '1080x2400'
  let dExtraHeaders = []
  let dCookies = []
  let dAuthHeaders = []
  let dTokens = []

  // ==================== Sub-tab 4: Signer Providers ====================
  let signers = []
  let signerSearch = S.signerSearch || ''
  let selectedSigner = null
  let isNewSigner = false
  let confirmDeleteSignerId = null
  let savingSigner = false
  let signerEditorRef = null

  // Signer Editor fields
  let sId = ''
  let sName = ''
  let sKind = 'builtin_hmac'
  let sEnabled = true
  let sDescription = ''
  let sRuntime = 'python3'
  let sScriptCode = ''
  let sEndpointUrl = ''
  let sWorkerPoolId = ''
  let sHttpMethod = 'POST'
  let sTimeoutSec = 10
  let sHeaders = []
  let sHmacAlgo = 'hmac-sha256'
  let sHmacSecret = ''
  let sShowSecret = false
  let sFridaSerial = ''
  let sFridaPackage = ''
  let sFridaExport = ''
  let sInjectTarget = 'query'
  let sInjectField = 'sign'
  let sOutputMapping = []

  // Inline Signer Tester
  let sTestMethod = 'GET'
  let sTestUrl = 'https://api.example.com/v1/search'
  let sTestQueryJson = '{\n  "keyword": "cap",\n  "page": "1"\n}'
  let sTestBody = ''
  let testingSigner = false
  let signerTestResult = null
  let signerTestError = ''

  // ==================== Sub-tab 5: Live Gateway Logs ====================
  let logs = []
  let logRouteFilter = S.logRouteFilter || 'all'
  let logStatusFilter = S.logStatusFilter || 'all'
  let logSearch = S.logSearch || ''
  let expandedLogIds = new Set()
  let loadingLogs = false

  // ==================== Sub-tab 6: Account / Session Pool ====================
  let accounts = []
  let accountPoolConfig = {
    strategy: 'round_robin',
    refresh: {
      refresh_route_slug: '',
      refresh_on_statuses: [],
      refresh_on_body_substr: '',
      challenge_webhook_url: '',
      max_refresh_attempts: 1,
    },
  }
  let savingAccountCfg = false
  let accountSearch = S.accountSearch || ''
  let accountStatusFilter = S.accountStatusFilter || 'all'
  let selectedAccount = null
  let isNewAccount = false
  let confirmDeleteAccountId = null
  let savingAccount = false
  let markingAccountId = ''

  // Account Editor fields
  let aId = ''
  let aName = ''
  let aUsername = ''
  let aEnabled = true
  let aStatus = 'active'
  let aTags = ''
  let aStickyDeviceId = ''
  let aStickyProxyId = ''
  let aExpiresAt = ''
  let aNotes = ''
  let aToken = ''
  let aRefreshToken = ''
  let aCookie = ''
  let aCookies = []
  let aAuthHeaders = []
  let aTokens = []
  let aShowSecrets = false

  // ==================== Sub-tab 7: Managed Signer Workers ====================
  let workers = []
  let workerStatuses = []
  let loadingWorkers = false
  let workerSearch = S.workerSearch || ''
  let selectedWorker = null
  let isNewWorker = false
  let confirmDeleteWorkerId = null
  let savingWorker = false
  let workerActionBusyId = ''
  let expandedInstanceKeys = new Set()
  let workerPollTimer = null
  let workerPollInFlight = false
  let destroyed = false

  // Worker Pool Editor fields
  let wId = ''
  let wName = ''
  let wKind = 'unidbg_http'
  let wEnabled = true
  let wDescription = ''
  let wCommand = ''
  let wArgsText = ''
  let wWorkDir = ''
  let wEnv = []
  let wBasePort = 18080
  let wInstances = 2
  let wHealthPath = '/health'
  let wSignPath = '/sign'
  let wAutoRestart = true
  let wMaxRestarts = 5
  let wRestartBackoffMs = 500

  let unsubs = []
  let unsubHandoff = null
  let unregisterCmds = null

  // ==================== Persist State Across Route Switches ====================
  $: {
    S.activeTab = activeTab
    S.listenAddr = listenAddr
    S.selectedRouteId = selectedRoute?.id || ''
    S.selectedDeviceId = selectedDevice?.id || ''
    S.selectedSignerId = selectedSigner?.id || ''
    S.selectedAccountId = selectedAccount?.id || ''
    S.selectedWorkerId = selectedWorker?.id || ''
    S.routeSearch = routeSearch
    S.proxySearch = proxySearch
    S.proxyStatusFilter = proxyStatusFilter
    S.deviceSearch = deviceSearch
    S.deviceKindFilter = deviceKindFilter
    S.signerSearch = signerSearch
    S.accountSearch = accountSearch
    S.accountStatusFilter = accountStatusFilter
    S.workerSearch = workerSearch
    S.logRouteFilter = logRouteFilter
    S.logStatusFilter = logStatusFilter
    S.logSearch = logSearch
    S.testInputJson = testInputJson
    S.testBody = testOverrideBody
    S.testDeviceId = testDeviceId
    S.testProxyId = testProxyId
    S.testAccountId = testAccountId
    S.testBypassCache = testBypassCache
    S.testRaw = testRaw
    S.lastTestResult = testResult
  }

  // ==================== Derived & Computed Values ====================
  $: enabledProxyCount = proxies.filter((p) => p.enabled).length
  $: healthyProxyCount = proxies.filter((p) => p.enabled && p.healthy).length
  $: displayHealthyProxies = proxies.length > 0 ? healthyProxyCount : (stats.proxy_healthy || 0)
  $: displayActiveProxies = proxies.length > 0 ? enabledProxyCount : (stats.proxy_total || 0)
  $: successRateVal = stats.total_requests > 0
    ? (stats.success_requests / stats.total_requests) * 100
    : null
  $: successRateText = successRateVal === null ? '—' : `${successRateVal.toFixed(1)}%`
  $: successRateClass = successRateVal === null
    ? ''
    : successRateVal >= 95
      ? 'kpi-good'
      : successRateVal >= 80
        ? 'kpi-warn'
        : 'kpi-bad'

  $: activeBaseUrl = normalizeBaseUrl(stats.running ? (stats.listen_addr || listenAddr) : listenAddr)

  $: signerNameById = Object.fromEntries(signers.map((s) => [s.id, s.name || s.id]))
  $: proxyNameById = Object.fromEntries(proxies.map((p) => [p.id, p.name || redactProxyURL(p.url) || p.id]))
  $: deviceNameById = Object.fromEntries(devices.map((d) => [d.id, d.name || d.id]))
  $: workerNameById = Object.fromEntries(workers.map((w) => [w.id, w.name || w.id]))
  $: workerStatusById = Object.fromEntries(
    workerStatuses
      .filter((st) => st?.spec?.id)
      .map((st) => [st.spec.id, st])
  )

  $: localActiveAccounts = accounts.filter((a) => {
    if (!a.enabled || (a.status && a.status !== 'active')) return false
    if (a.expires_at) {
      const exp = Date.parse(a.expires_at)
      if (Number.isFinite(exp) && exp <= Date.now()) return false
    }
    return true
  }).length
  $: displayTotalAccounts = accounts.length > 0 ? accounts.length : (stats.total_accounts || 0)
  $: displayActiveAccounts = accounts.length > 0 ? localActiveAccounts : (stats.active_accounts || 0)

  $: localTotalWorkers = workerStatuses.length > 0
    ? workerStatuses.reduce((acc, st) => acc + (st.total_instances ?? st.total_count ?? st.spec?.instances ?? 0), 0)
    : workers.reduce((acc, w) => acc + (Number(w.instances) || 1), 0)
  $: localHealthyWorkers = workerStatuses.reduce((acc, st) => acc + (st.healthy_instances ?? st.healthy_count ?? 0), 0)
  $: displayTotalWorkers = (workerStatuses.length > 0 || workers.length > 0) ? localTotalWorkers : (stats.total_workers || 0)
  $: displayHealthyWorkers = workerStatuses.length > 0 ? localHealthyWorkers : (stats.healthy_workers || 0)

  $: localOpenCircuits = Object.values(circuitStates || {}).filter((c) => c?.state === 'open').length
  $: displayOpenCircuits = Object.keys(circuitStates || {}).length > 0 ? localOpenCircuits : (stats.open_circuits || 0)

  $: effectiveTlsProfiles = tlsProfiles.length > 0 ? tlsProfiles : FALLBACK_TLS_PROFILES
  $: selectedTlsProfileSpec = effectiveTlsProfiles.find((p) => p.id === rTlsProfile) || effectiveTlsProfiles[0] || null
  $: currentJa3 = ja3Cache[rTlsProfile] || selectedTlsProfileSpec?.ja3 || null
  $: activeRouteSlugKey = (selectedRoute?.slug || rSlug || '').trim()
  $: currentRouteCircuit = activeRouteSlugKey ? (circuitStates[activeRouteSlugKey] || null) : null
  $: refreshRouteCandidates = routes.filter((r) => r.slug && r.slug !== activeRouteSlugKey)
  $: selectedWorkerStatus = selectedWorker?.id ? (workerStatusById[selectedWorker.id] || null) : null

  $: filteredRoutes = routes.filter((r) => {
    const q = routeSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (r.name || '').toLowerCase().includes(q) ||
      (r.slug || '').toLowerCase().includes(q) ||
      (r.upstream_url || '').toLowerCase().includes(q) ||
      (r.upstream_method || '').toLowerCase().includes(q)
    )
  })

  $: filteredFlows = capturedFlows.filter((f) => {
    const q = flowSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (f.url || '').toLowerCase().includes(q) ||
      (f.host || '').toLowerCase().includes(q) ||
      (f.path || '').toLowerCase().includes(q) ||
      (f.method || '').toLowerCase().includes(q)
    )
  })

  $: filteredProxies = proxies.filter((n) => {
    if (proxyStatusFilter === 'healthy' && !(n.enabled && n.healthy)) return false
    if (proxyStatusFilter === 'unhealthy' && !(n.enabled && !n.healthy)) return false
    if (proxyStatusFilter === 'disabled' && n.enabled) return false
    const q = proxySearch.trim().toLowerCase()
    if (!q) return true
    return (
      (n.name || '').toLowerCase().includes(q) ||
      (n.url || '').toLowerCase().includes(q) ||
      (n.region || '').toLowerCase().includes(q) ||
      (n.tags || []).some((tg) => tg.toLowerCase().includes(q)) ||
      (n.last_error || '').toLowerCase().includes(q)
    )
  })

  $: filteredDevices = devices.filter((d) => {
    if (deviceKindFilter !== 'all' && d.kind !== deviceKindFilter) return false
    const q = deviceSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (d.name || '').toLowerCase().includes(q) ||
      (d.adb_serial || '').toLowerCase().includes(q) ||
      (d.fingerprint?.model || '').toLowerCase().includes(q) ||
      (d.fingerprint?.brand || '').toLowerCase().includes(q) ||
      (d.fingerprint?.oaid || '').toLowerCase().includes(q) ||
      (d.tags || []).some((tg) => tg.toLowerCase().includes(q))
    )
  })

  $: filteredSigners = signers.filter((s) => {
    const q = signerSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (s.name || '').toLowerCase().includes(q) ||
      (s.kind || '').toLowerCase().includes(q) ||
      (s.description || '').toLowerCase().includes(q) ||
      (s.endpoint_url || '').toLowerCase().includes(q) ||
      (s.worker_pool_id || '').toLowerCase().includes(q)
    )
  })

  $: filteredAccounts = accounts.filter((a) => {
    const st = a.status || (a.enabled ? 'active' : 'disabled')
    if (accountStatusFilter !== 'all' && st !== accountStatusFilter) return false
    const q = accountSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (a.name || '').toLowerCase().includes(q) ||
      (a.username || '').toLowerCase().includes(q) ||
      (a.notes || '').toLowerCase().includes(q) ||
      (a.tags || []).some((tg) => tg.toLowerCase().includes(q))
    )
  })

  $: filteredWorkers = workers.filter((w) => {
    const q = workerSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (w.name || '').toLowerCase().includes(q) ||
      (w.kind || '').toLowerCase().includes(q) ||
      (w.command || '').toLowerCase().includes(q) ||
      (w.description || '').toLowerCase().includes(q)
    )
  })

  $: logRouteSlugs = Array.from(
    new Set([
      ...routes.map((r) => r.slug).filter(Boolean),
      ...logs.map((l) => l.route_slug).filter(Boolean),
    ])
  ).sort()

  $: filteredLogs = logs.filter((l) => {
    if (logRouteFilter !== 'all' && l.route_slug !== logRouteFilter) return false
    if (logStatusFilter === 'ok' && !(l.ok && l.status_code >= 200 && l.status_code < 300)) return false
    if (logStatusFilter === '4xx' && !(l.status_code >= 400 && l.status_code < 500)) return false
    if (logStatusFilter === 'error' && (l.ok && l.status_code < 500 && !l.error)) return false
    const q = logSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (l.route_slug || '').toLowerCase().includes(q) ||
      (l.upstream_url || '').toLowerCase().includes(q) ||
      (l.proxy_name || '').toLowerCase().includes(q) ||
      (l.device_name || '').toLowerCase().includes(q) ||
      (l.account_name || '').toLowerCase().includes(q) ||
      (l.tls_profile || '').toLowerCase().includes(q) ||
      (l.error || '').toLowerCase().includes(q) ||
      (l.client_ip || '').toLowerCase().includes(q) ||
      String(l.status_code || '').includes(q)
    )
  })

  $: logErrorCount = logs.filter((l) => !l.ok || Boolean(l.error)).length
  $: isRunning = Boolean(stats.running)

  // Command Palette integration (depends only on isRunning + $t, not live traffic stats)
  $: {
    const _t = $t
    const running = isRunning
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      unregisterCmds = registerCommands([
        {
          id: 'gateway:toggle',
          label: `${_t('gateway.topbar.title')}: ${running ? _t('gateway.topbar.stop') : _t('gateway.topbar.start')}`,
          category: _t('gateway.topbar.title'),
          icon: running ? 'square' : 'play',
          keywords: 'gateway api server start stop 网关 启动 停止',
          run: toggleGatewayServer,
        },
        {
          id: 'gateway:openapi',
          label: `${_t('gateway.topbar.title')}: ${_t('gateway.topbar.openApi')}`,
          category: _t('gateway.topbar.title'),
          icon: 'file-code',
          keywords: 'gateway openapi swagger spec json',
          run: () => openOpenApiDrawer(),
        },
        {
          id: 'gateway:prometheus',
          label: `${_t('gateway.topbar.title')}: ${_t('gateway.topbar.prometheus')}`,
          category: _t('gateway.topbar.title'),
          icon: 'radar',
          keywords: 'gateway prometheus metrics telemetry grafana 监控 指标',
          run: () => openPromDrawer(true),
        },
        {
          id: 'gateway:docker',
          label: `${_t('gateway.topbar.title')}: ${_t('gateway.topbar.docker')}`,
          category: _t('gateway.topbar.title'),
          icon: 'box',
          keywords: 'gateway docker compose headless container deploy 部署 容器',
          run: () => openDockerDrawer(true),
        },
        {
          id: 'gateway:check-proxies',
          label: `${_t('gateway.topbar.title')}: ${_t('gateway.proxies.checkAll')}`,
          category: _t('gateway.topbar.title'),
          icon: 'shield-check',
          keywords: 'gateway proxy health check ip pool',
          run: () => {
            activeTab = 'proxies'
            handleCheckAllProxies()
          },
        },
      ])
    }
  }

  // ==================== Helpers ====================
  function normalizeBaseUrl(addr) {
    let s = String(addr || '127.0.0.1:9090').trim()
    if (!s) s = '127.0.0.1:9090'
    if (s.startsWith('http://') || s.startsWith('https://')) return s.replace(/\/+$/, '')
    if (s.startsWith(':')) s = `127.0.0.1${s}`
    s = s.replace(/^0\.0\.0\.0:/, '127.0.0.1:')
    return `http://${s}`
  }

  function redactProxyURL(raw) {
    const s = String(raw || '').trim()
    if (!s) return ''
    return s.replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s@]+)@/, '$1REDACTED@')
  }

  function mapToRows(obj) {
    if (!obj || typeof obj !== 'object') return []
    return Object.entries(obj).map(([key, value]) => ({ key, value: String(value ?? '') }))
  }

  function rowsToMap(rows) {
    const out = {}
    for (const row of rows || []) {
      const k = String(row?.key || '').trim()
      if (k) out[k] = String(row?.value ?? '')
    }
    return out
  }

  function parseTagsInput(raw) {
    return String(raw || '')
      .split(/[,，\n]/)
      .map((s) => s.trim())
      .filter(Boolean)
  }

  function formatTagsInput(arr) {
    return Array.isArray(arr) ? arr.join(', ') : ''
  }

  function parseHeadersTextarea(text) {
    const h = {}
    for (const line of String(text || '').split('\n')) {
      const idx = line.indexOf(':')
      if (idx > 0) {
        const k = line.slice(0, idx).trim()
        const v = line.slice(idx + 1).trim()
        if (k) h[k] = v
      }
    }
    return h
  }

  function randomHex(byteLen = 8) {
    const bytes = new Uint8Array(byteLen)
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes)
    } else {
      for (let i = 0; i < byteLen; i++) bytes[i] = Math.floor(Math.random() * 256)
    }
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  }

  function randomUuid() {
    const h = randomHex(16)
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`
  }

  function signerKindVariant(kind) {
    switch (kind) {
      case 'builtin_hmac': return 'success'
      case 'script': return 'info'
      case 'http': return 'accent'
      case 'unidbg_http': return 'purple'
      case 'frida_rpc': return 'warning'
      default: return 'neutral'
    }
  }

  function formatPrettyBody(body, data) {
    if (data !== undefined && data !== null) {
      try {
        return JSON.stringify(data, null, 2)
      } catch (_) {}
    }
    const raw = String(body || '')
    const trimmed = raw.trim()
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        return JSON.stringify(JSON.parse(trimmed), null, 2)
      } catch (_) {}
    }
    return raw
  }

  function maskKey(k) {
    const s = String(k || '')
    if (cfgRevealKeys || s.length <= 10) return s
    return `${s.slice(0, 6)}••••••${s.slice(-4)}`
  }

  function parseStatusCodesInput(raw) {
    return Array.from(
      new Set(
        String(raw || '')
          .split(/[,，\s]+/)
          .map((s) => Number(s.trim()))
          .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599)
      )
    )
  }

  function formatStatusCodesInput(arr) {
    return Array.isArray(arr) ? arr.join(', ') : ''
  }

  function parseArgsLines(raw) {
    return String(raw || '')
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
  }

  function formatArgsLines(arr) {
    return Array.isArray(arr) ? arr.join('\n') : ''
  }

  function accountStatusVariant(status) {
    switch (status) {
      case 'active': return 'success'
      case 'expired': return 'warning'
      case 'challenged': return 'danger'
      case 'disabled': return 'neutral'
      default: return 'neutral'
    }
  }

  function workerKindVariant(kind) {
    switch (kind) {
      case 'unidbg_http': return 'purple'
      case 'qiling_http': return 'info'
      case 'script_http': return 'accent'
      default: return 'neutral'
    }
  }

  function circuitStateVariant(state) {
    switch (state) {
      case 'open': return 'danger'
      case 'half_open': return 'warning'
      default: return 'success'
    }
  }

  function downloadTextFile(filename, content, mime = 'text/plain;charset=utf-8') {
    if (!content) return
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

  function shellSingleQuote(str) {
    return `'${String(str ?? '').replace(/'/g, `'\\''`)}'`
  }

  // ==================== Backend Data Loading ====================
  async function loadAllData() {
    const app = api()
    if (!app) return
    refreshingAll = true
    try {
      const [
        st,
        cfg,
        rList,
        pList,
        pCfg,
        dList,
        presets,
        sList,
        lList,
        tlsList,
        cStates,
        aList,
        aCfg,
        wList,
        wStatuses,
      ] = await Promise.all([
        app.GetGatewayStatus?.().catch(() => null),
        app.GetGatewayConfig?.().catch(() => null),
        app.ListGatewayRoutes?.().catch(() => []),
        app.ListGatewayProxies?.().catch(() => []),
        app.GetProxyPoolConfig?.().catch(() => null),
        app.ListGatewayDevices?.().catch(() => []),
        app.ListGatewayDevicePresets?.().catch(() => []),
        app.ListGatewaySigners?.().catch(() => []),
        app.ListGatewayLogs?.(200).catch(() => []),
        app.ListTLSProfiles?.().catch(() => []),
        app.GetGatewayCircuitStates?.().catch(() => ({})),
        app.ListGatewayAccounts?.().catch(() => []),
        app.GetAccountPoolConfig?.().catch(() => null),
        app.ListGatewayWorkers?.().catch(() => []),
        app.ListGatewayWorkerStatuses?.().catch(() => []),
      ])
      if (destroyed) return
      if (st) {
        stats = { ...stats, ...st }
        if (st.listen_addr) listenAddr = st.listen_addr
      }
      if (cfg) {
        gwConfig = {
          listen_addr: cfg.listen_addr || '127.0.0.1:9090',
          require_auth: Boolean(cfg.require_auth),
          api_keys: Array.isArray(cfg.api_keys) ? cfg.api_keys : [],
          cors_origins: Array.isArray(cfg.cors_origins) ? cfg.cors_origins : [],
          max_logs: Number(cfg.max_logs) || 500,
        }
        if (!stats.running && cfg.listen_addr) {
          listenAddr = cfg.listen_addr
        }
        syncConfigDrawerDraft()
      }
      routes = Array.isArray(rList) ? rList : []
      proxies = Array.isArray(pList) ? pList : []
      if (pCfg) {
        proxyConfig = {
          strategy: pCfg.strategy || 'round_robin',
          provider_url: pCfg.provider_url || '',
          provider_format: pCfg.provider_format || 'lines',
          provider_json_path: pCfg.provider_json_path || '',
          refresh_interval_sec: Number(pCfg.refresh_interval_sec) || 0,
          health_check_url: pCfg.health_check_url || 'http://connectivitycheck.gstatic.com/generate_204',
          failover_retries: Number(pCfg.failover_retries ?? 2),
        }
      }
      devices = Array.isArray(dList) ? dList : []
      devicePresets = Array.isArray(presets) ? presets : []
      if (devicePresets.length > 0 && !selectedPresetId) {
        selectedPresetId = devicePresets[0].id
      }
      signers = Array.isArray(sList) ? sList : []
      logs = Array.isArray(lList) ? lList : []
      tlsProfiles = Array.isArray(tlsList) ? tlsList : []
      if (tlsProfiles.length > 0) {
        const nextJa3 = { ...ja3Cache }
        for (const p of tlsProfiles) {
          if (p?.id && p?.ja3) nextJa3[p.id] = p.ja3
        }
        ja3Cache = nextJa3
      }
      circuitStates = cStates && typeof cStates === 'object' ? cStates : {}
      accounts = Array.isArray(aList) ? aList : []
      if (aCfg) {
        accountPoolConfig = {
          strategy: aCfg.strategy || 'round_robin',
          refresh: aCfg.refresh || {},
        }
      }
      workers = Array.isArray(wList) ? wList : []
      workerStatuses = Array.isArray(wStatuses) ? wStatuses : []

      // Restore selections cleanly
      if (!isNewRoute) {
        const targetRoute = routes.find((r) => r.id === (selectedRoute?.id || S.selectedRouteId)) || routes[0]
        if (targetRoute) selectRoute(targetRoute)
      }
      if (!isNewDevice) {
        const targetDev = devices.find((d) => d.id === (selectedDevice?.id || S.selectedDeviceId)) || devices[0]
        if (targetDev) selectDevice(targetDev)
      }
      if (!isNewSigner) {
        const targetSigner = signers.find((s) => s.id === (selectedSigner?.id || S.selectedSignerId)) || signers[0]
        if (targetSigner) selectSigner(targetSigner)
      }
      if (!isNewAccount) {
        const targetAcc = accounts.find((a) => a.id === (selectedAccount?.id || S.selectedAccountId)) || accounts[0]
        if (targetAcc) selectAccount(targetAcc)
      }
      if (!isNewWorker) {
        const targetWorker = workers.find((w) => w.id === (selectedWorker?.id || S.selectedWorkerId)) || workers[0]
        if (targetWorker) selectWorker(targetWorker)
      }
    } finally {
      refreshingAll = false
    }
  }

  async function refreshStatus() {
    const app = api()
    if (!app?.GetGatewayStatus) return
    try {
      const st = await app.GetGatewayStatus()
      if (st) stats = { ...stats, ...st }
    } catch (_) {}
  }

  // ==================== Gateway Lifecycle, Auth Config & OpenAPI ====================
  async function toggleGatewayServer() {
    const app = api()
    if (!app || serverBusy) return
    serverBusy = true
    try {
      if (stats.running) {
        const st = await app.StopGateway?.()
        if (st) stats = { ...stats, ...st }
        toast.info(translate('gateway.toast.stopped'))
      } else {
        const addr = listenAddr.trim() || '127.0.0.1:9090'
        const st = await app.StartGateway?.(addr)
        if (st) {
          stats = { ...stats, ...st }
          if (st.listen_addr) listenAddr = st.listen_addr
        }
        toast.success(translate('gateway.toast.started', { addr: stats.listen_addr || addr }))
      }
    } catch (e) {
      const key = stats.running ? 'gateway.toast.stopFailed' : 'gateway.toast.startFailed'
      toast.error(translate(key, { err: e?.message || e }))
    } finally {
      serverBusy = false
    }
  }

  function syncConfigDrawerDraft() {
    cfgRequireAuth = Boolean(gwConfig.require_auth)
    cfgApiKeys = [...(gwConfig.api_keys || [])]
    cfgCorsText = (gwConfig.cors_origins || []).join('\n')
    cfgMaxLogs = Number(gwConfig.max_logs) || 500
  }

  function toggleConfigDrawer() {
    showConfigDrawer = !showConfigDrawer
    if (showConfigDrawer) {
      showOpenApiDrawer = false
      showPromDrawer = false
      showDockerDrawer = false
      syncConfigDrawerDraft()
    }
  }

  function addApiKey() {
    const clean = cfgNewKey.trim()
    if (!clean) return
    if (!cfgApiKeys.includes(clean)) {
      cfgApiKeys = [...cfgApiKeys, clean]
    }
    cfgNewKey = ''
  }

  function generateApiKey() {
    const generated = `cap_gw_${randomHex(16)}`
    cfgApiKeys = [...cfgApiKeys, generated]
    cfgRequireAuth = true
    copyToClipboard(generated)
  }

  function removeApiKey(key) {
    cfgApiKeys = cfgApiKeys.filter((k) => k !== key)
  }

  async function saveGatewayConfig() {
    const app = api()
    if (!app?.UpdateGatewayConfig || savingConfig) return
    savingConfig = true
    try {
      const cors = String(cfgCorsText || '')
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean)
      const payload = {
        listen_addr: listenAddr.trim() || gwConfig.listen_addr || '127.0.0.1:9090',
        require_auth: cfgRequireAuth,
        api_keys: cfgApiKeys,
        cors_origins: cors,
        max_logs: Math.max(50, Number(cfgMaxLogs) || 500),
      }
      const updated = await app.UpdateGatewayConfig(payload)
      if (updated) {
        gwConfig = {
          listen_addr: updated.listen_addr || payload.listen_addr,
          require_auth: Boolean(updated.require_auth),
          api_keys: Array.isArray(updated.api_keys) ? updated.api_keys : [],
          cors_origins: Array.isArray(updated.cors_origins) ? updated.cors_origins : [],
          max_logs: Number(updated.max_logs) || 500,
        }
        syncConfigDrawerDraft()
      }
      toast.success(translate('gateway.toast.configSaved'))
      showConfigDrawer = false
    } catch (e) {
      toast.error(translate('gateway.toast.configFailed', { err: e?.message || e }))
    } finally {
      savingConfig = false
    }
  }

  async function openOpenApiDrawer(forceOpen = true) {
    if (!forceOpen && showOpenApiDrawer) {
      showOpenApiDrawer = false
      return
    }
    showOpenApiDrawer = true
    showConfigDrawer = false
    showPromDrawer = false
    showDockerDrawer = false
    await loadOpenApiSpec()
  }

  async function loadOpenApiSpec() {
    const app = api()
    if (!app?.GetGatewayOpenAPI) return
    loadingOpenApi = true
    try {
      const spec = await app.GetGatewayOpenAPI()
      openApiSpec = typeof spec === 'string' ? spec : JSON.stringify(spec, null, 2)
    } catch (e) {
      toast.error(translate('gateway.toast.openApiFailed', { err: e?.message || e }))
    } finally {
      loadingOpenApi = false
    }
  }

  function downloadOpenApiSpec() {
    if (!openApiSpec) return
    downloadTextFile('cap-gateway-openapi.json', openApiSpec, 'application/json;charset=utf-8')
    toast.success(translate('gateway.toast.openApiDownloaded'))
  }

  async function openPromDrawer(forceOpen = true) {
    if (!forceOpen && showPromDrawer) {
      showPromDrawer = false
      return
    }
    showPromDrawer = true
    showConfigDrawer = false
    showOpenApiDrawer = false
    showDockerDrawer = false
    await loadPromMetrics()
  }

  async function loadPromMetrics() {
    const app = api()
    if (!app?.GetGatewayPrometheusMetrics) return
    loadingProm = true
    try {
      const txt = await app.GetGatewayPrometheusMetrics()
      promMetrics = typeof txt === 'string' ? txt : String(txt ?? '')
    } catch (e) {
      toast.error(translate('gateway.toast.promFailed', { err: e?.message || e }))
    } finally {
      loadingProm = false
    }
  }

  function downloadPromMetrics() {
    if (!promMetrics) return
    downloadTextFile('cap-gateway-metrics.prom', promMetrics, 'text/plain;charset=utf-8')
    toast.success(translate('gateway.toast.promDownloaded'))
  }

  async function openDockerDrawer(forceOpen = true) {
    if (!forceOpen && showDockerDrawer) {
      showDockerDrawer = false
      return
    }
    showDockerDrawer = true
    showConfigDrawer = false
    showOpenApiDrawer = false
    showPromDrawer = false
    await loadDockerBundle()
  }

  async function loadDockerBundle() {
    const app = api()
    if (!app?.ExportGatewayDockerBundle) return
    loadingDocker = true
    try {
      const addr = (stats.running ? stats.listen_addr : listenAddr) || listenAddr || '127.0.0.1:9090'
      const bundle = await app.ExportGatewayDockerBundle(addr)
      dockerBundle = bundle || null
    } catch (e) {
      toast.error(translate('gateway.toast.dockerFailed', { err: e?.message || e }))
    } finally {
      loadingDocker = false
    }
  }

  $: activeDockerFilename = dockerTab === 'compose' ? 'docker-compose.yml' : 'Dockerfile'
  $: activeDockerContent = !dockerBundle
    ? ''
    : (dockerTab === 'compose' ? (dockerBundle.docker_compose || '') : (dockerBundle.dockerfile || ''))

  function copyActiveDockerFile() {
    if (!activeDockerContent) return
    copyToClipboard(activeDockerContent, translate('gateway.toast.dockerCopied', { file: activeDockerFilename }))
  }

  function downloadActiveDockerFile() {
    if (!activeDockerContent) return
    const file = activeDockerFilename
    downloadTextFile(file, activeDockerContent, 'text/plain;charset=utf-8')
    toast.success(translate('gateway.toast.dockerDownloaded', { file }))
  }

  // ==================== Sub-tab 1: Service Routes & Live Tester ====================
  function selectRoute(r) {
    if (!r) return
    const prevId = selectedRoute?.id || S.selectedRouteId
    if (prevId && prevId !== r.id) {
      testResult = null
    }
    selectedRoute = r
    isNewRoute = false
    confirmDeleteRouteId = null
    rId = r.id || ''
    rSlug = r.slug || ''
    rName = r.name || ''
    rDescription = r.description || ''
    rEnabled = Boolean(r.enabled)
    rMethod = r.upstream_method || 'GET'
    rUpstreamUrl = r.upstream_url || ''
    rStaticHeaders = mapToRows(r.static_headers)
    rStaticQuery = mapToRows(r.static_query)
    rBodyTemplate = r.body_template || ''
    rSignerId = r.signer_id || ''
    rDeviceTags = formatTagsInput(r.device_tags)
    rProxyTags = formatTagsInput(r.proxy_tags)
    rRequireDevice = Boolean(r.require_device)
    rRequireProxy = Boolean(r.require_proxy)
    rRateLimitRps = Number(r.rate_limit_rps) || 0
    rTimeoutSec = Number(r.timeout_sec) || 15
    rSourceFlowId = r.source_flow_id || ''

    // Pro Controls fields
    rTlsProfile = r.tls_profile || 'go_default'
    rMtlsCertPath = r.mtls_cert_path || ''
    rMtlsKeyPath = r.mtls_key_path || ''
    mtlsValidateSeq++
    mtlsValidation = null
    validatingMtls = false
    rAccountTags = formatTagsInput(r.account_tags)
    rRequireAccount = Boolean(r.require_account)
    rAutoRefresh = Boolean(r.auto_refresh)
    rRefreshRouteSlug = r.refresh_route_slug || ''
    rRefreshOnStatuses = formatStatusCodesInput(r.refresh_on_statuses)
    rRefreshOnBodySubstr = r.refresh_on_body_substr || ''
    rChallengeWebhookUrl = r.challenge_webhook_url || ''
    rCacheTtlSec = Number(r.cache_ttl_sec) || 0
    rCacheKeyFields = formatTagsInput(r.cache_key_fields)
    rCacheMaxEntries = Number(r.cache_max_entries) || 512
    rCircuitFailThreshold = Number(r.circuit_fail_threshold) || 0
    rCircuitCooldownSec = Number(r.circuit_cooldown_sec) || 30

    loadJa3ForProfile(rTlsProfile)
  }

  function createNewRoute() {
    selectedRoute = null
    isNewRoute = true
    confirmDeleteRouteId = null
    rId = ''
    rSlug = ''
    rName = ''
    rDescription = ''
    rEnabled = true
    rMethod = 'GET'
    rUpstreamUrl = 'https://api.example.com/v1/search?q={{input.keyword}}'
    rStaticHeaders = [{ key: 'Accept', value: 'application/json' }]
    rStaticQuery = []
    rBodyTemplate = ''
    rSignerId = ''
    rDeviceTags = ''
    rProxyTags = ''
    rRequireDevice = false
    rRequireProxy = false
    rRateLimitRps = 0
    rTimeoutSec = 15
    rSourceFlowId = ''

    rTlsProfile = 'go_default'
    rMtlsCertPath = ''
    rMtlsKeyPath = ''
    mtlsValidateSeq++
    mtlsValidation = null
    validatingMtls = false
    rAccountTags = ''
    rRequireAccount = false
    rAutoRefresh = false
    rRefreshRouteSlug = ''
    rRefreshOnStatuses = '401, 403'
    rRefreshOnBodySubstr = ''
    rChallengeWebhookUrl = ''
    rCacheTtlSec = 0
    rCacheKeyFields = ''
    rCacheMaxEntries = 512
    rCircuitFailThreshold = 0
    rCircuitCooldownSec = 30
    testResult = null

    loadJa3ForProfile(rTlsProfile)
  }

  async function loadJa3ForProfile(profileId) {
    const id = String(profileId || 'go_default').trim() || 'go_default'
    if (ja3Cache[id]) return
    const app = api()
    if (!app?.ComputeTLSProfileJA3) return
    loadingJa3 = true
    try {
      const summary = await app.ComputeTLSProfileJA3(id)
      if (summary) {
        ja3Cache = { ...ja3Cache, [id]: summary }
      }
    } catch (_) {
    } finally {
      loadingJa3 = false
    }
  }

  async function handleValidateMtlsPair() {
    const app = api()
    if (!app?.ValidateMTLSKeyPair || validatingMtls) return
    const seq = ++mtlsValidateSeq
    const certPath = rMtlsCertPath.trim()
    const keyPath = rMtlsKeyPath.trim()
    validatingMtls = true
    mtlsValidation = null
    try {
      const res = await app.ValidateMTLSKeyPair(certPath, keyPath)
      if (destroyed || seq !== mtlsValidateSeq) return
      mtlsValidation = res || null
      if (res?.valid) {
        toast.success(translate('gateway.toast.mtlsValidated'))
      } else if (res?.error) {
        toast.warning(translate('gateway.toast.mtlsValidationFailed', { err: res.error }))
      }
    } catch (e) {
      if (destroyed || seq !== mtlsValidateSeq) return
      mtlsValidation = { valid: false, error: e?.message || String(e) }
      toast.error(translate('gateway.toast.mtlsValidationFailed', { err: e?.message || e }))
    } finally {
      if (seq === mtlsValidateSeq) {
        validatingMtls = false
      }
    }
  }

  async function refreshCircuitStates() {
    const app = api()
    if (!app?.GetGatewayCircuitStates) return
    try {
      const map = await app.GetGatewayCircuitStates()
      circuitStates = map && typeof map === 'object' ? map : {}
    } catch (_) {}
  }

  async function handleClearRouteCache() {
    const app = api()
    const slug = (selectedRoute?.slug || rSlug || '').trim()
    if (!app?.ClearGatewayRouteCache || !slug || clearingCache) return
    clearingCache = true
    try {
      await app.ClearGatewayRouteCache(slug)
      toast.success(translate('gateway.toast.cacheCleared', { slug }))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.actionFailed', { err: e?.message || e }))
    } finally {
      clearingCache = false
    }
  }

  async function handleResetRouteCircuit() {
    const app = api()
    const slug = (selectedRoute?.slug || rSlug || '').trim()
    if (!app?.ResetGatewayCircuit || !slug || resettingCircuit) return
    resettingCircuit = true
    try {
      await app.ResetGatewayCircuit(slug)
      toast.success(translate('gateway.toast.circuitReset', { slug }))
      await Promise.all([refreshCircuitStates(), refreshStatus()])
    } catch (e) {
      toast.error(translate('gateway.toast.actionFailed', { err: e?.message || e }))
    } finally {
      resettingCircuit = false
    }
  }

  function insertTemplateVar(token) {
    if (templateTarget === 'body') {
      const el = bodyInputEl
      if (el && typeof el.selectionStart === 'number') {
        const start = el.selectionStart
        const end = el.selectionEnd
        rBodyTemplate = rBodyTemplate.slice(0, start) + token + rBodyTemplate.slice(end)
        requestAnimationFrame(() => {
          el.focus()
          el.setSelectionRange(start + token.length, start + token.length)
        })
      } else {
        rBodyTemplate = (rBodyTemplate || '') + token
      }
    } else {
      const el = urlInputEl
      if (el && typeof el.selectionStart === 'number') {
        const start = el.selectionStart
        const end = el.selectionEnd
        rUpstreamUrl = rUpstreamUrl.slice(0, start) + token + rUpstreamUrl.slice(end)
        requestAnimationFrame(() => {
          el.focus()
          el.setSelectionRange(start + token.length, start + token.length)
        })
      } else {
        rUpstreamUrl = (rUpstreamUrl || '') + token
      }
    }
  }

  function formatRouteBodyJson() {
    try {
      rBodyTemplate = JSON.stringify(JSON.parse(rBodyTemplate), null, 2)
    } catch (e) {
      toast.warning(translate('gateway.toast.invalidJson', { err: e?.message || e }))
    }
  }

  async function saveCurrentRoute() {
    const app = api()
    if (!app?.SaveGatewayRoute || savingRoute) return
    savingRoute = true
    try {
      const payload = {
        id: isNewRoute ? '' : rId,
        slug: rSlug.trim(),
        name: rName.trim(),
        description: rDescription.trim(),
        enabled: rEnabled,
        upstream_method: rMethod || 'GET',
        upstream_url: rUpstreamUrl.trim(),
        static_headers: rowsToMap(rStaticHeaders),
        static_query: rowsToMap(rStaticQuery),
        body_template: rBodyTemplate,
        signer_id: rSignerId || '',
        device_tags: parseTagsInput(rDeviceTags),
        proxy_tags: parseTagsInput(rProxyTags),
        require_device: rRequireDevice,
        require_proxy: rRequireProxy,
        account_tags: parseTagsInput(rAccountTags),
        require_account: rRequireAccount,
        auto_refresh: rAutoRefresh,
        refresh_route_slug: rRefreshRouteSlug.trim(),
        refresh_on_statuses: parseStatusCodesInput(rRefreshOnStatuses),
        refresh_on_body_substr: rRefreshOnBodySubstr.trim(),
        challenge_webhook_url: rChallengeWebhookUrl.trim(),
        tls_profile: rTlsProfile || 'go_default',
        mtls_cert_path: rMtlsCertPath.trim(),
        mtls_key_path: rMtlsKeyPath.trim(),
        cache_ttl_sec: Math.max(0, Number(rCacheTtlSec) || 0),
        cache_key_fields: parseTagsInput(rCacheKeyFields),
        cache_max_entries: Math.max(0, Number(rCacheMaxEntries) || 0),
        circuit_fail_threshold: Math.max(0, Number(rCircuitFailThreshold) || 0),
        circuit_cooldown_sec: Math.max(0, Number(rCircuitCooldownSec) || 0),
        rate_limit_rps: Number(rRateLimitRps) || 0,
        timeout_sec: Math.max(1, Number(rTimeoutSec) || 15),
        source_flow_id: rSourceFlowId || '',
      }
      const saved = await app.SaveGatewayRoute(payload)
      const list = await app.ListGatewayRoutes?.()
      routes = Array.isArray(list) ? list : routes
      if (saved) {
        selectRoute(routes.find((x) => x.id === saved.id) || saved)
        toast.success(translate('gateway.toast.routeSaved', { slug: saved.slug }))
      }
      await Promise.all([refreshCircuitStates(), refreshStatus()])
    } catch (e) {
      toast.error(translate('gateway.toast.routeSaveFailed', { err: e?.message || e }))
    } finally {
      savingRoute = false
    }
  }

  async function deleteCurrentRoute(id) {
    const app = api()
    if (!app?.DeleteGatewayRoute || !id) return
    try {
      await app.DeleteGatewayRoute(id)
      confirmDeleteRouteId = null
      const list = await app.ListGatewayRoutes?.()
      routes = Array.isArray(list) ? list : []
      if (selectedRoute?.id === id) {
        selectedRoute = null
        isNewRoute = false
        if (routes.length > 0) selectRoute(routes[0])
      }
      toast.info(translate('gateway.toast.routeDeleted'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.actionFailed', { err: e?.message || e }))
    }
  }

  // Publish from Captured Flow
  async function openFlowPicker(prefill = null) {
    showFlowPicker = true
    if (prefill) {
      if (prefill.flowId) selectedFlowId = prefill.flowId
      if (prefill.slug) publishSlug = prefill.slug
      if (prefill.name) publishName = prefill.name
    }
    await loadRecentFlows()
  }

  async function loadRecentFlows() {
    const app = api()
    if (!app?.GetFlows) return
    loadingFlows = true
    try {
      const list = await app.GetFlows('', '', '', 50)
      capturedFlows = Array.isArray(list) ? list : []
      if (selectedFlowId && !publishSlug) {
        const hit = capturedFlows.find((f) => f.id === selectedFlowId)
        if (hit) pickFlowForPublish(hit)
      }
    } catch (_) {
      capturedFlows = []
    } finally {
      loadingFlows = false
    }
  }

  function pickFlowForPublish(flow) {
    if (!flow) return
    selectedFlowId = flow.id
    const pathClean = String(flow.path || '').replace(/^\/+|\/+$/g, '').replace(/\//g, '-')
    const slugBase = (pathClean || flow.host || 'api')
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, '-')
      .replace(/^[-._]+|[-._]+$/g, '')
    publishSlug = slugBase || 'api-route'
    publishName = `${String(flow.method || 'GET').toUpperCase()} ${flow.path || '/'}`
  }

  async function handlePublishFlow() {
    const app = api()
    if (!app?.PublishFlowToGateway || publishingFlow) return
    if (!selectedFlowId) {
      toast.warning(translate('gateway.routes.publishFlow.selectFlowFirst'))
      return
    }
    publishingFlow = true
    try {
      const created = await app.PublishFlowToGateway(selectedFlowId, publishSlug.trim(), publishName.trim())
      const list = await app.ListGatewayRoutes?.()
      routes = Array.isArray(list) ? list : routes
      if (created) {
        selectRoute(routes.find((x) => x.id === created.id) || created)
        toast.success(translate('gateway.toast.flowPublished', { slug: created.slug }))
      }
      showFlowPicker = false
      selectedFlowId = ''
      publishSlug = ''
      publishName = ''
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.flowPublishFailed', { err: e?.message || e }))
    } finally {
      publishingFlow = false
    }
  }

  // Live Route Tester
  async function runRouteTest() {
    const app = api()
    const slug = (selectedRoute?.slug || rSlug || '').trim()
    if (!app?.TestGatewayRoute || !slug || testingRoute) return

    let inputMap = {}
    if (testInputJson.trim()) {
      try {
        const parsed = JSON.parse(testInputJson)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          for (const [k, v] of Object.entries(parsed)) {
            inputMap[k] = typeof v === 'string' ? v : JSON.stringify(v)
          }
        }
      } catch (e) {
        toast.error(translate('gateway.toast.invalidJson', { err: e?.message || e }))
        return
      }
    }

    const extraHdrs = parseHeadersTextarea(testExtraHeaders)
    const reqPayload = {
      route_slug: slug,
      method: rMethod || 'GET',
      input: inputMap,
      query: {},
      headers: extraHdrs,
      body: testOverrideBody || '',
      device_id: testDeviceId || '',
      proxy_id: testProxyId || '',
      account_id: testAccountId || '',
      bypass_cache: testBypassCache,
      raw: testRaw,
    }

    testingRoute = true
    try {
      const res = await app.TestGatewayRoute(slug, reqPayload)
      testResult = res || null
      if (res) {
        // Cache latest preview per route slug so Live Logs can display rich req/resp previews
        testPreviewCache.set(slug, {
          ts: Date.now(),
          request: reqPayload,
          response: res,
        })
        testPreviewCache = testPreviewCache
      }
      await Promise.all([refreshCircuitStates(), refreshStatus()])
    } catch (e) {
      testResult = {
        ok: false,
        status: 0,
        latency_ms: 0,
        error: e?.message || String(e),
      }
      toast.error(translate('gateway.toast.testFailed', { err: e?.message || e }))
    } finally {
      testingRoute = false
    }
  }

  function copyRouteCurl() {
    const slug = (selectedRoute?.slug || rSlug || '').trim()
    if (!slug) return
    const method = (rMethod || 'GET').toUpperCase()
    let parsedInput = {}
    try {
      if (testInputJson.trim()) parsedInput = JSON.parse(testInputJson)
    } catch (_) {}

    let urlObj
    try {
      urlObj = new URL(`${activeBaseUrl}/gw/${encodeURIComponent(slug)}`)
    } catch (_) {
      urlObj = new URL(`http://127.0.0.1:9090/gw/${encodeURIComponent(slug)}`)
    }
    const sendBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || Boolean(testOverrideBody.trim())
    if (!sendBody && parsedInput && typeof parsedInput === 'object') {
      for (const [k, v] of Object.entries(parsedInput)) {
        urlObj.searchParams.set(k, typeof v === 'string' ? v : JSON.stringify(v))
      }
    }
    if (testRaw) urlObj.searchParams.set('raw', '1')

    const parts = [`curl -X ${method} ${shellSingleQuote(urlObj.toString())}`]
    if (gwConfig.require_auth) {
      const key = gwConfig.api_keys?.[0] || '<YOUR_API_KEY>'
      parts.push(`-H ${shellSingleQuote(`X-API-Key: ${key}`)}`)
    }
    if (testDeviceId) {
      parts.push(`-H ${shellSingleQuote(`X-Cap-Device-ID: ${testDeviceId}`)}`)
    }
    if (testProxyId) {
      parts.push(`-H ${shellSingleQuote(`X-Cap-Proxy-ID: ${testProxyId}`)}`)
    }
    if (testAccountId) {
      parts.push(`-H ${shellSingleQuote(`X-Cap-Account-ID: ${testAccountId}`)}`)
    }
    if (testBypassCache) {
      parts.push(`-H 'Cache-Control: no-cache'`)
    }
    const extra = parseHeadersTextarea(testExtraHeaders)
    for (const [k, v] of Object.entries(extra)) {
      parts.push(`-H ${shellSingleQuote(`${k}: ${v}`)}`)
    }
    if (sendBody) {
      parts.push(`-H 'Content-Type: application/json'`)
      const bodyStr = testOverrideBody.trim() || JSON.stringify(parsedInput)
      parts.push(`-d ${shellSingleQuote(bodyStr)}`)
    }
    copyToClipboard(parts.join(' \\\n  '), translate('gateway.toast.curlCopied'))
  }

  // ==================== Sub-tab 2: Proxy IP Pool ====================
  async function saveProxyPoolConfig() {
    const app = api()
    if (!app?.UpdateProxyPoolConfig || savingProxyCfg) return
    savingProxyCfg = true
    try {
      await app.UpdateProxyPoolConfig({
        strategy: proxyConfig.strategy || 'round_robin',
        provider_url: String(proxyConfig.provider_url || '').trim(),
        provider_format: proxyConfig.provider_format || 'lines',
        provider_json_path: String(proxyConfig.provider_json_path || '').trim(),
        refresh_interval_sec: Math.max(0, Number(proxyConfig.refresh_interval_sec) || 0),
        health_check_url: String(proxyConfig.health_check_url || '').trim(),
        failover_retries: Math.max(0, Number(proxyConfig.failover_retries) || 0),
      })
      toast.success(translate('gateway.toast.proxyConfigSaved'))
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    } finally {
      savingProxyCfg = false
    }
  }

  async function handleFetchProxiesFromProvider() {
    const app = api()
    if (!app?.FetchGatewayProxiesFromProvider || fetchingProxies) return
    const url = String(proxyConfig.provider_url || '').trim()
    if (!url) return
    fetchingProxies = true
    try {
      const added = await app.FetchGatewayProxiesFromProvider(
        url,
        proxyConfig.provider_format || 'lines',
        String(proxyConfig.provider_json_path || '').trim()
      )
      const list = await app.ListGatewayProxies?.()
      proxies = Array.isArray(list) ? list : proxies
      toast.success(translate('gateway.toast.proxiesFetched', { count: Number(added) || 0 }))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    } finally {
      fetchingProxies = false
    }
  }

  async function handleCheckAllProxies() {
    const app = api()
    if (!app?.CheckGatewayProxies || checkingProxies) return
    checkingProxies = true
    try {
      const list = await app.CheckGatewayProxies()
      if (Array.isArray(list)) {
        proxies = list
      }
      const healthy = proxies.filter((n) => n.enabled && n.healthy).length
      toast.success(translate('gateway.toast.proxiesChecked', { total: proxies.length, healthy }))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    } finally {
      checkingProxies = false
    }
  }

  function openAddProxyDrawer(tab = 'single') {
    proxyDrawerTab = tab
    pEditId = ''
    pName = ''
    pUrl = ''
    pUsername = ''
    pPassword = ''
    pRegion = ''
    pTags = ''
    pEnabled = true
    showProxyDrawer = true
  }

  function editProxyNode(node) {
    proxyDrawerTab = 'single'
    pEditId = node.id || ''
    pName = node.name || ''
    pUrl = node.url || ''
    pUsername = node.username || ''
    pPassword = node.password || ''
    pRegion = node.region || ''
    pTags = formatTagsInput(node.tags)
    pEnabled = Boolean(node.enabled)
    showProxyDrawer = true
  }

  async function handleSaveSingleProxy() {
    const app = api()
    if (!app?.SaveGatewayProxy || savingProxy) return
    savingProxy = true
    try {
      const existing = proxies.find((n) => n.id === pEditId)
      const payload = {
        ...(existing || {}),
        id: pEditId || '',
        name: pName.trim(),
        url: pUrl.trim(),
        username: pUsername.trim(),
        password: pPassword,
        region: pRegion.trim(),
        tags: parseTagsInput(pTags),
        enabled: pEnabled,
      }
      await app.SaveGatewayProxy(payload)
      const list = await app.ListGatewayProxies?.()
      proxies = Array.isArray(list) ? list : proxies
      showProxyDrawer = false
      toast.success(translate('gateway.toast.proxySaved'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    } finally {
      savingProxy = false
    }
  }

  async function handleBulkImportProxies() {
    const app = api()
    if (!app?.BulkImportGatewayProxies || importingProxies) return
    if (!bulkRawLines.trim()) return
    importingProxies = true
    try {
      const count = await app.BulkImportGatewayProxies(
        bulkRawLines,
        bulkDefaultScheme || 'http',
        bulkRegion.trim(),
        parseTagsInput(bulkTags)
      )
      const list = await app.ListGatewayProxies?.()
      proxies = Array.isArray(list) ? list : proxies
      bulkRawLines = ''
      showProxyDrawer = false
      toast.success(translate('gateway.toast.proxiesImported', { count: Number(count) || 0 }))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    } finally {
      importingProxies = false
    }
  }

  async function toggleProxyEnabled(node) {
    const app = api()
    if (!app?.SaveGatewayProxy) return
    try {
      await app.SaveGatewayProxy({ ...node, enabled: !node.enabled })
      const list = await app.ListGatewayProxies?.()
      proxies = Array.isArray(list) ? list : proxies
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    }
  }

  async function deleteProxyNode(id) {
    const app = api()
    if (!app?.DeleteGatewayProxy || !id) return
    try {
      await app.DeleteGatewayProxy(id)
      const list = await app.ListGatewayProxies?.()
      proxies = Array.isArray(list) ? list : []
      toast.info(translate('gateway.toast.proxyDeleted'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.proxyOpFailed', { err: e?.message || e }))
    }
  }

  function proxyHealthMeta(n) {
    if (n.healthy) return { variant: 'success', label: translate('gateway.proxies.statusHealthy') }
    if (!n.last_checked && !n.fail_count && !n.last_error) {
      return { variant: 'neutral', label: translate('gateway.proxies.statusUnchecked') }
    }
    return { variant: 'danger', label: translate('gateway.proxies.statusUnhealthy') }
  }

  // ==================== Sub-tab 3: Device Pool ====================
  function selectDevice(dev) {
    if (!dev) return
    selectedDevice = dev
    isNewDevice = false
    confirmDeleteDeviceId = null
    dId = dev.id || ''
    dName = dev.name || ''
    dKind = dev.kind || 'virtual'
    dAdbSerial = dev.adb_serial || ''
    dEnabled = Boolean(dev.enabled)
    dTags = formatTagsInput(dev.tags)
    dStickyProxyId = dev.sticky_proxy_id || ''
    dProxyRegion = dev.proxy_region || ''

    const fp = dev.fingerprint || {}
    dModel = fp.model || ''
    dBrand = fp.brand || ''
    dOsVersion = fp.os_version || ''
    dSdk = Number(fp.sdk) || 34
    dUserAgent = fp.user_agent || ''
    dDeviceId = fp.device_id || ''
    dAndroidId = fp.android_id || ''
    dOaid = fp.oaid || ''
    dLocale = fp.locale || ''
    dTimezone = fp.timezone || ''
    dScreen = fp.screen || ''
    dExtraHeaders = mapToRows(fp.extra_headers)
    dCookies = mapToRows(dev.cookies)
    dAuthHeaders = mapToRows(dev.auth_headers)
    dTokens = mapToRows(dev.tokens)
  }

  function createNewVirtualDevice() {
    selectedDevice = null
    isNewDevice = true
    confirmDeleteDeviceId = null
    dId = ''
    dName = 'Virtual Android #1'
    dKind = 'virtual'
    dAdbSerial = ''
    dEnabled = true
    dTags = 'virtual, android14'
    dStickyProxyId = ''
    dProxyRegion = ''
    dModel = 'Pixel 8 Pro'
    dBrand = 'Google'
    dOsVersion = '14'
    dSdk = 34
    dUserAgent = 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/AP2A.240805.005) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36'
    dDeviceId = randomHex(8)
    dAndroidId = randomHex(8)
    dOaid = randomUuid()
    dLocale = 'en_US'
    dTimezone = 'America/Los_Angeles'
    dScreen = '1344x2992'
    dExtraHeaders = []
    dCookies = []
    dAuthHeaders = []
    dTokens = []
  }

  function randomizeDeviceIds() {
    dDeviceId = randomHex(8)
    dAndroidId = randomHex(8)
    dOaid = randomUuid()
  }

  async function handleCreateDeviceFromPreset() {
    const app = api()
    if (!app?.CreateGatewayDeviceFromPreset || !selectedPresetId || creatingPreset) return
    creatingPreset = true
    try {
      const created = await app.CreateGatewayDeviceFromPreset(selectedPresetId, presetCustomName.trim())
      const list = await app.ListGatewayDevices?.()
      devices = Array.isArray(list) ? list : devices
      if (created) {
        selectDevice(devices.find((d) => d.id === created.id) || created)
        toast.success(translate('gateway.toast.deviceCreatedPreset', { name: created.name }))
      }
      presetCustomName = ''
      showPresetMenu = false
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.deviceOpFailed', { err: e?.message || e }))
    } finally {
      creatingPreset = false
    }
  }

  async function handleSyncAdbDevices() {
    const app = api()
    if (!app?.SyncGatewayADBDevices || syncingAdb) return
    syncingAdb = true
    try {
      const synced = await app.SyncGatewayADBDevices()
      const list = await app.ListGatewayDevices?.()
      devices = Array.isArray(list) ? list : devices
      const count = Array.isArray(synced) ? synced.length : 0
      toast.success(translate('gateway.toast.adbSynced', { count }))
      if (count > 0 && synced[0]) {
        selectDevice(devices.find((d) => d.id === synced[0].id) || synced[0])
      }
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.deviceOpFailed', { err: e?.message || e }))
    } finally {
      syncingAdb = false
    }
  }

  async function saveCurrentDevice() {
    const app = api()
    if (!app?.SaveGatewayDevice || savingDevice) return
    savingDevice = true
    try {
      const payload = {
        id: isNewDevice ? '' : dId,
        name: dName.trim(),
        kind: dKind || 'virtual',
        adb_serial: dAdbSerial.trim(),
        enabled: dEnabled,
        tags: parseTagsInput(dTags),
        sticky_proxy_id: dStickyProxyId || '',
        proxy_region: dProxyRegion.trim(),
        fingerprint: {
          model: dModel.trim(),
          brand: dBrand.trim(),
          os_version: dOsVersion.trim(),
          sdk: Number(dSdk) || 0,
          user_agent: dUserAgent.trim(),
          device_id: dDeviceId.trim(),
          android_id: dAndroidId.trim(),
          oaid: dOaid.trim(),
          locale: dLocale.trim(),
          timezone: dTimezone.trim(),
          screen: dScreen.trim(),
          extra_headers: rowsToMap(dExtraHeaders),
        },
        cookies: rowsToMap(dCookies),
        auth_headers: rowsToMap(dAuthHeaders),
        tokens: rowsToMap(dTokens),
      }
      const saved = await app.SaveGatewayDevice(payload)
      const list = await app.ListGatewayDevices?.()
      devices = Array.isArray(list) ? list : devices
      if (saved) {
        selectDevice(devices.find((d) => d.id === saved.id) || saved)
        toast.success(translate('gateway.toast.deviceSaved', { name: saved.name }))
      }
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.deviceOpFailed', { err: e?.message || e }))
    } finally {
      savingDevice = false
    }
  }

  async function deleteCurrentDevice(id) {
    const app = api()
    if (!app?.DeleteGatewayDevice || !id) return
    try {
      await app.DeleteGatewayDevice(id)
      confirmDeleteDeviceId = null
      const list = await app.ListGatewayDevices?.()
      devices = Array.isArray(list) ? list : []
      if (selectedDevice?.id === id) {
        selectedDevice = null
        isNewDevice = false
        if (devices.length > 0) selectDevice(devices[0])
      }
      toast.info(translate('gateway.toast.deviceDeleted'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.deviceOpFailed', { err: e?.message || e }))
    }
  }

  // ==================== Sub-tab 4: Signer Providers ====================
  function selectSigner(sg) {
    if (!sg) return
    selectedSigner = sg
    isNewSigner = false
    confirmDeleteSignerId = null
    signerTestResult = null
    signerTestError = ''

    sId = sg.id || ''
    sName = sg.name || ''
    sKind = sg.kind || 'builtin_hmac'
    sEnabled = Boolean(sg.enabled)
    sDescription = sg.description || ''
    sRuntime = sg.runtime || 'python3'
    sScriptCode = sg.script_code || ''
    sEndpointUrl = sg.endpoint_url || ''
    sWorkerPoolId = sg.worker_pool_id || ''
    sHttpMethod = sg.http_method || 'POST'
    sTimeoutSec = Number(sg.timeout_sec) || 10
    sHeaders = mapToRows(sg.headers)
    sHmacAlgo = sg.hmac_algorithm || 'hmac-sha256'
    sHmacSecret = sg.hmac_secret || ''
    sFridaSerial = sg.frida_serial || ''
    sFridaPackage = sg.frida_package || ''
    sFridaExport = sg.frida_export || ''
    sInjectTarget = sg.inject_target || 'query'
    sInjectField = sg.inject_field || 'sign'
    sOutputMapping = mapToRows(sg.output_mapping)
    if (signerEditorRef?.resetHistory) {
      signerEditorRef.resetHistory(sScriptCode)
    }
  }

  function createNewSigner() {
    selectedSigner = null
    isNewSigner = true
    confirmDeleteSignerId = null
    signerTestResult = null
    signerTestError = ''

    sId = ''
    sName = 'HMAC-SHA256 Signer'
    sKind = 'builtin_hmac'
    sEnabled = true
    sDescription = ''
    sRuntime = 'python3'
    sScriptCode = ''
    sEndpointUrl = 'http://127.0.0.1:8899/sign'
    sWorkerPoolId = ''
    sHttpMethod = 'POST'
    sTimeoutSec = 10
    sHeaders = []
    sHmacAlgo = 'hmac-sha256'
    sHmacSecret = ''
    sFridaSerial = ''
    sFridaPackage = ''
    sFridaExport = 'sign'
    sInjectTarget = 'query'
    sInjectField = 'sign'
    sOutputMapping = []
  }

  function selectSignerKind(nextKind) {
    const prevKind = sKind
    sKind = nextKind
    if (nextKind === 'script') {
      if (!sScriptCode.trim() || (prevKind !== 'script' && isUnmodifiedStarterScript(sScriptCode))) {
        sScriptCode = STARTER_SCRIPTS[sRuntime] || STARTER_SCRIPTS.python3
        signerEditorRef?.resetHistory?.(sScriptCode)
      }
    } else if (nextKind === 'frida_rpc') {
      if (!sScriptCode.trim() || (prevKind !== 'frida_rpc' && isUnmodifiedStarterScript(sScriptCode))) {
        sScriptCode = buildFridaStarterScript(sFridaExport)
        signerEditorRef?.resetHistory?.(sScriptCode)
      }
    }
  }

  function loadStarterScript() {
    const code = STARTER_SCRIPTS[sRuntime] || STARTER_SCRIPTS.python3
    sScriptCode = code
    if (signerEditorRef?.replaceValue) {
      signerEditorRef.replaceValue(code, { undoable: true })
    }
  }

  function loadFridaStarterScript() {
    const code = buildFridaStarterScript(sFridaExport)
    sScriptCode = code
    if (signerEditorRef?.replaceValue) {
      signerEditorRef.replaceValue(code, { undoable: true })
    }
  }

  function buildSignerDraft(forceEnabled = false) {
    const base = {
      id: isNewSigner ? '' : sId,
      name: sName.trim() || 'Unnamed Signer',
      kind: sKind,
      enabled: forceEnabled ? true : sEnabled,
      description: sDescription.trim(),
      timeout_sec: Math.max(1, Number(sTimeoutSec) || 10),
      inject_target: sInjectTarget || 'query',
      inject_field: sInjectField.trim() || (sInjectTarget === 'header' ? 'X-Sign' : 'sign'),
    }
    if (sKind === 'builtin_hmac') {
      base.hmac_algorithm = sHmacAlgo || 'hmac-sha256'
      base.hmac_secret = sHmacSecret
    } else if (sKind === 'script') {
      base.runtime = sRuntime || 'python3'
      base.script_code = sScriptCode
      base.output_mapping = rowsToMap(sOutputMapping)
    } else if (sKind === 'http' || sKind === 'unidbg_http') {
      base.endpoint_url = sEndpointUrl.trim()
      base.worker_pool_id = sWorkerPoolId || ''
      base.http_method = sHttpMethod || 'POST'
      base.headers = rowsToMap(sHeaders)
      base.output_mapping = rowsToMap(sOutputMapping)
    } else if (sKind === 'frida_rpc') {
      base.frida_serial = sFridaSerial.trim()
      base.frida_package = sFridaPackage.trim()
      base.frida_export = sFridaExport.trim()
      base.script_code = sScriptCode
      base.output_mapping = rowsToMap(sOutputMapping)
    }
    return base
  }

  async function saveCurrentSigner() {
    const app = api()
    if (!app?.SaveGatewaySigner || savingSigner) return
    savingSigner = true
    try {
      const saved = await app.SaveGatewaySigner(buildSignerDraft(false))
      const list = await app.ListGatewaySigners?.()
      signers = Array.isArray(list) ? list : signers
      if (saved) {
        selectSigner(signers.find((x) => x.id === saved.id) || saved)
        toast.success(translate('gateway.toast.signerSaved', { name: saved.name }))
      }
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.signerOpFailed', { err: e?.message || e }))
    } finally {
      savingSigner = false
    }
  }

  async function deleteCurrentSigner(id) {
    const app = api()
    if (!app?.DeleteGatewaySigner || !id) return
    try {
      await app.DeleteGatewaySigner(id)
      confirmDeleteSignerId = null
      const list = await app.ListGatewaySigners?.()
      signers = Array.isArray(list) ? list : []
      if (selectedSigner?.id === id) {
        selectedSigner = null
        isNewSigner = false
        if (signers.length > 0) selectSigner(signers[0])
      }
      toast.info(translate('gateway.toast.signerDeleted'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.signerOpFailed', { err: e?.message || e }))
    }
  }

  function signerLanguageForAI() {
    if (sKind === 'frida_rpc') return 'javascript'
    if (sKind === 'script') {
      if (sRuntime === 'python3') return 'python'
      if (sRuntime === 'node') return 'javascript'
      if (sRuntime === 'sh') return 'bash'
    }
    return 'text'
  }

  function applyPatchedSignerCode(patchedCode) {
    if (typeof patchedCode !== 'string') return
    if (signerEditorRef?.replaceValue) {
      signerEditorRef.replaceValue(patchedCode, { undoable: true })
    } else {
      sScriptCode = patchedCode
    }
  }

  function openSignerAIHeal() {
    const canEditScript = sKind === 'script' || sKind === 'frida_rpc'
    openAIHealModal({
      scope: 'signer',
      title: `${sName.trim() || 'Signer'} — ${translate('gateway.signers.tester.aiFixBtn')}`,
      code: canEditScript ? (sScriptCode || '') : '',
      language: signerLanguageForAI(),
      errorText: signerTestError || '',
      logs: signerTestError || '',
      metadata: {
        kind: sKind || '',
        runtime: sKind === 'script' ? sRuntime : '',
        test_method: sTestMethod || 'GET',
        test_url: sTestUrl || '',
      },
      undoKey: `signer:${selectedSignerId || sName.trim() || 'draft'}`,
      onApplyPatch: canEditScript
        ? (patchedCode) => {
            applyPatchedSignerCode(patchedCode)
          }
        : null,
      onApplyAndRerun: canEditScript
        ? async (patchedCode) => {
            applyPatchedSignerCode(patchedCode)
            await handleTestSigner()
          }
        : null,
    })
  }

  async function handleTestSigner() {
    const app = api()
    if (!app?.TestGatewaySigner || testingSigner) return

    let queryObj = {}
    if (sTestQueryJson.trim()) {
      try {
        const parsed = JSON.parse(sTestQueryJson)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          for (const [k, v] of Object.entries(parsed)) {
            queryObj[k] = typeof v === 'string' ? v : JSON.stringify(v)
          }
        }
      } catch (e) {
        toast.error(translate('gateway.toast.invalidJson', { err: e?.message || e }))
        return
      }
    }

    let pathStr = '/'
    try {
      pathStr = new URL(sTestUrl).pathname || '/'
    } catch (_) {}

    const sampleInput = {
      method: sTestMethod || 'GET',
      url: sTestUrl.trim() || 'https://api.example.com/v1/search',
      path: pathStr,
      query: queryObj,
      headers: {},
      body: sTestBody || '',
      timestamp: Math.floor(Date.now() / 1000),
      nonce: randomHex(8),
      input: queryObj,
    }

    testingSigner = true
    signerTestError = ''
    try {
      const out = await app.TestGatewaySigner(buildSignerDraft(true), sampleInput)
      signerTestResult = out || null
      toast.success(translate('gateway.toast.signerTestOk', { ms: out?.latency_ms ?? 0 }))
    } catch (e) {
      signerTestResult = null
      signerTestError = e?.message || String(e)
      toast.error(translate('gateway.toast.signerOpFailed', { err: signerTestError }))
    } finally {
      testingSigner = false
    }
  }

  // ==================== Sub-tab 5: Live Gateway Logs ====================
  async function loadGatewayLogs() {
    const app = api()
    if (!app?.ListGatewayLogs) return
    loadingLogs = true
    try {
      const list = await app.ListGatewayLogs(200)
      logs = Array.isArray(list) ? list : []
    } finally {
      loadingLogs = false
    }
  }

  async function handleClearLogs() {
    const app = api()
    if (!app?.ClearGatewayLogs) return
    try {
      await app.ClearGatewayLogs()
      logs = []
      expandedLogIds = new Set()
      toast.info(translate('gateway.toast.logsCleared'))
    } catch (e) {
      toast.error(translate('gateway.toast.actionFailed', { err: e?.message || e }))
    }
  }

  function toggleLogExpand(id) {
    const next = new Set(expandedLogIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    expandedLogIds = next
  }

  function openRouteFromLog(rec) {
    const target = routes.find((r) => r.id === rec.route_id || r.slug === rec.route_slug)
    if (target) {
      selectRoute(target)
    }
    activeTab = 'routes'
  }

  function getCachedPreviewForLog(rec) {
    if (!rec?.route_slug) return null
    const cached = testPreviewCache.get(rec.route_slug)
    if (!cached) return null
    const logMs = new Date(rec.timestamp).getTime()
    if (Number.isFinite(logMs) && Math.abs(cached.ts - logMs) < 120000) {
      return cached
    }
    return null
  }

  // ==================== Sub-tab 6: Account / Session Pool ====================
  function selectAccount(acc) {
    if (!acc) return
    selectedAccount = acc
    isNewAccount = false
    confirmDeleteAccountId = null
    aShowSecrets = false
    aId = acc.id || ''
    aName = acc.name || ''
    aUsername = acc.username || ''
    aEnabled = Boolean(acc.enabled)
    aStatus = acc.status || (acc.enabled ? 'active' : 'disabled')
    aTags = formatTagsInput(acc.tags)
    aStickyDeviceId = acc.sticky_device_id || ''
    aStickyProxyId = acc.sticky_proxy_id || ''
    aExpiresAt = acc.expires_at || ''
    aNotes = acc.notes || ''
    aToken = acc.token || ''
    aRefreshToken = acc.refresh_token || ''
    aCookie = acc.cookie || ''
    aCookies = mapToRows(acc.cookies)
    aAuthHeaders = mapToRows(acc.auth_headers)
    aTokens = mapToRows(acc.tokens)
  }

  function createNewAccount() {
    selectedAccount = null
    isNewAccount = true
    confirmDeleteAccountId = null
    aShowSecrets = false
    aId = ''
    aName = 'Account #1'
    aUsername = ''
    aEnabled = true
    aStatus = 'active'
    aTags = ''
    aStickyDeviceId = ''
    aStickyProxyId = ''
    aExpiresAt = ''
    aNotes = ''
    aToken = ''
    aRefreshToken = ''
    aCookie = ''
    aCookies = []
    aAuthHeaders = []
    aTokens = []
  }

  function setAccountExpiryPreset(hours) {
    if (!hours) {
      aExpiresAt = ''
      return
    }
    const target = new Date(Date.now() + hours * 3600 * 1000)
    aExpiresAt = target.toISOString().replace(/\.\d{3}Z$/, 'Z')
  }

  async function saveAccountPoolConfig() {
    const app = api()
    if (!app?.UpdateAccountPoolConfig || savingAccountCfg) return
    savingAccountCfg = true
    try {
      await app.UpdateAccountPoolConfig({
        strategy: accountPoolConfig.strategy || 'round_robin',
        refresh: accountPoolConfig.refresh || {},
      })
      toast.success(translate('gateway.toast.accountConfigSaved'))
    } catch (e) {
      toast.error(translate('gateway.toast.accountOpFailed', { err: e?.message || e }))
      try {
        const fresh = await app.GetAccountPoolConfig?.()
        if (fresh && !destroyed) {
          accountPoolConfig = {
            strategy: fresh.strategy || 'round_robin',
            refresh: fresh.refresh || {},
          }
        }
      } catch (_) {}
    } finally {
      savingAccountCfg = false
    }
  }

  async function saveCurrentAccount() {
    const app = api()
    if (!app?.SaveGatewayAccount || savingAccount) return
    savingAccount = true
    try {
      const payload = {
        ...(selectedAccount && !isNewAccount ? selectedAccount : {}),
        id: isNewAccount ? '' : aId,
        name: aName.trim(),
        username: aUsername.trim(),
        enabled: aEnabled,
        status: aStatus || (aEnabled ? 'active' : 'disabled'),
        tags: parseTagsInput(aTags),
        sticky_device_id: aStickyDeviceId || '',
        sticky_proxy_id: aStickyProxyId || '',
        expires_at: aExpiresAt.trim(),
        notes: aNotes.trim(),
        token: aToken,
        refresh_token: aRefreshToken,
        cookie: aCookie,
        cookies: rowsToMap(aCookies),
        auth_headers: rowsToMap(aAuthHeaders),
        tokens: rowsToMap(aTokens),
      }
      const saved = await app.SaveGatewayAccount(payload)
      const list = await app.ListGatewayAccounts?.()
      accounts = Array.isArray(list) ? list : accounts
      if (saved) {
        selectAccount(accounts.find((x) => x.id === saved.id) || saved)
        toast.success(translate('gateway.toast.accountSaved', { name: saved.name || saved.username || saved.id }))
      }
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.accountOpFailed', { err: e?.message || e }))
    } finally {
      savingAccount = false
    }
  }

  async function deleteCurrentAccount(id) {
    const app = api()
    if (!app?.DeleteGatewayAccount || !id) return
    try {
      await app.DeleteGatewayAccount(id)
      confirmDeleteAccountId = null
      const list = await app.ListGatewayAccounts?.()
      accounts = Array.isArray(list) ? list : []
      if (selectedAccount?.id === id) {
        selectedAccount = null
        isNewAccount = false
        if (accounts.length > 0) selectAccount(accounts[0])
      }
      toast.info(translate('gateway.toast.accountDeleted'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.accountOpFailed', { err: e?.message || e }))
    }
  }

  async function handleMarkAccountHealthy(id) {
    const app = api()
    if (!app?.MarkGatewayAccountHealthy || !id || markingAccountId) return
    markingAccountId = id
    try {
      await app.MarkGatewayAccountHealthy(id)
      const list = await app.ListGatewayAccounts?.()
      accounts = Array.isArray(list) ? list : accounts
      if (selectedAccount?.id === id) {
        const refreshed = accounts.find((x) => x.id === id)
        if (refreshed) selectAccount(refreshed)
      }
      toast.success(translate('gateway.toast.accountMarkedHealthy'))
      await refreshStatus()
    } catch (e) {
      toast.error(translate('gateway.toast.accountOpFailed', { err: e?.message || e }))
    } finally {
      markingAccountId = ''
    }
  }

  // ==================== Sub-tab 7: Managed Signer Workers ====================
  async function loadWorkersAndStatuses(quiet = false) {
    const app = api()
    if (!app || destroyed) return
    if (quiet && workerPollInFlight) return
    if (quiet) workerPollInFlight = true
    else loadingWorkers = true
    try {
      const [wList, wStatuses] = await Promise.all([
        app.ListGatewayWorkers?.().catch(() => null),
        app.ListGatewayWorkerStatuses?.().catch(() => null),
      ])
      if (destroyed) return
      if (Array.isArray(wList)) workers = wList
      if (Array.isArray(wStatuses)) workerStatuses = wStatuses
      if (!isNewWorker && selectedWorker?.id) {
        const updated = workers.find((x) => x.id === selectedWorker.id)
        if (updated) selectedWorker = updated
      }
      if (!quiet) await refreshStatus()
    } finally {
      if (quiet) workerPollInFlight = false
      else loadingWorkers = false
    }
  }

  function selectWorker(w) {
    if (!w) return
    selectedWorker = w
    isNewWorker = false
    confirmDeleteWorkerId = null
    wId = w.id || ''
    wName = w.name || ''
    wKind = w.kind || 'unidbg_http'
    wEnabled = Boolean(w.enabled)
    wDescription = w.description || ''
    wCommand = w.command || ''
    wArgsText = formatArgsLines(w.args)
    wWorkDir = w.work_dir || ''
    wEnv = mapToRows(w.env)
    wBasePort = Number(w.base_port) || 18080
    wInstances = Math.min(8, Math.max(1, Number(w.instances) || 1))
    wHealthPath = w.health_path || '/health'
    wSignPath = w.sign_path || '/sign'
    wAutoRestart = Boolean(w.auto_restart)
    wMaxRestarts = Number(w.max_restarts) || 5
    wRestartBackoffMs = Number(w.restart_backoff_ms) || 500
  }

  function createNewWorker() {
    selectedWorker = null
    isNewWorker = true
    confirmDeleteWorkerId = null
    wId = ''
    wName = 'Unidbg Signer Pool'
    wKind = 'unidbg_http'
    wEnabled = true
    wDescription = ''
    wCommand = 'java'
    wArgsText = '-jar\nunidbg-signer.jar'
    wWorkDir = ''
    wEnv = []
    wBasePort = 18080
    wInstances = 2
    wHealthPath = '/health'
    wSignPath = '/sign'
    wAutoRestart = true
    wMaxRestarts = 5
    wRestartBackoffMs = 500
  }

  async function saveCurrentWorker() {
    const app = api()
    if (!app?.SaveGatewayWorker || savingWorker) return
    savingWorker = true
    try {
      const payload = {
        id: isNewWorker ? '' : wId,
        name: wName.trim(),
        kind: wKind || 'custom',
        enabled: wEnabled,
        description: wDescription.trim(),
        command: wCommand.trim(),
        args: parseArgsLines(wArgsText),
        work_dir: wWorkDir.trim(),
        env: rowsToMap(wEnv),
        base_port: Math.min(65535, Math.max(1, Number(wBasePort) || 18080)),
        instances: Math.min(8, Math.max(1, Number(wInstances) || 1)),
        health_path: wHealthPath.trim() || '/health',
        sign_path: wSignPath.trim() || '/sign',
        auto_restart: wAutoRestart,
        max_restarts: Math.max(0, Number(wMaxRestarts) || 0),
        restart_backoff_ms: Math.max(50, Number(wRestartBackoffMs) || 500),
      }
      const saved = await app.SaveGatewayWorker(payload)
      await loadWorkersAndStatuses()
      if (saved) {
        selectWorker(workers.find((x) => x.id === saved.id) || saved)
        toast.success(translate('gateway.toast.workerSaved', { name: saved.name }))
      }
    } catch (e) {
      toast.error(translate('gateway.toast.workerOpFailed', { err: e?.message || e }))
    } finally {
      savingWorker = false
    }
  }

  async function deleteCurrentWorker(id) {
    const app = api()
    if (!app?.DeleteGatewayWorker || !id) return
    try {
      await app.DeleteGatewayWorker(id)
      confirmDeleteWorkerId = null
      await loadWorkersAndStatuses()
      if (selectedWorker?.id === id) {
        selectedWorker = null
        isNewWorker = false
        if (workers.length > 0) selectWorker(workers[0])
      }
      toast.info(translate('gateway.toast.workerDeleted'))
    } catch (e) {
      toast.error(translate('gateway.toast.workerOpFailed', { err: e?.message || e }))
    }
  }

  async function handleStartWorker(id) {
    const app = api()
    if (!app?.StartGatewayWorker || !id || workerActionBusyId) return
    workerActionBusyId = id
    try {
      await app.StartGatewayWorker(id)
      toast.success(translate('gateway.toast.workerStarted'))
      await loadWorkersAndStatuses()
    } catch (e) {
      toast.error(translate('gateway.toast.workerOpFailed', { err: e?.message || e }))
    } finally {
      workerActionBusyId = ''
    }
  }

  async function handleStopWorker(id) {
    const app = api()
    if (!app?.StopGatewayWorker || !id || workerActionBusyId) return
    workerActionBusyId = id
    try {
      await app.StopGatewayWorker(id)
      toast.info(translate('gateway.toast.workerStopped'))
      await loadWorkersAndStatuses()
    } catch (e) {
      toast.error(translate('gateway.toast.workerOpFailed', { err: e?.message || e }))
    } finally {
      workerActionBusyId = ''
    }
  }

  async function handleRestartWorker(id) {
    const app = api()
    if (!app?.RestartGatewayWorker || !id || workerActionBusyId) return
    workerActionBusyId = id
    try {
      await app.RestartGatewayWorker(id)
      toast.success(translate('gateway.toast.workerRestarted'))
      await loadWorkersAndStatuses()
    } catch (e) {
      toast.error(translate('gateway.toast.workerOpFailed', { err: e?.message || e }))
    } finally {
      workerActionBusyId = ''
    }
  }

  function toggleInstanceExpand(workerId, idx) {
    const key = `${workerId}:${idx}`
    const next = new Set(expandedInstanceKeys)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    expandedInstanceKeys = next
  }

  // ==================== Events, Handoff & Shortcuts ====================
  function applyHandoff(h) {
    if (!h) return
    S.pendingPublishFlow = null
    gatewayHandoff.set(null)
    if (h.type === 'publish_flow' || h.flowId) {
      activeTab = 'routes'
      openFlowPicker(h)
    }
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return
    const on = (name, fn) => {
      const off = rt.EventsOn(name, fn)
      if (typeof off === 'function') unsubs.push(off)
    }

    on('gateway:invoke', (rec) => {
      if (!rec) return
      const isDup = Boolean(rec.id) && logs.some((x) => x.id === rec.id)
      const maxLogs = Math.max(200, Number(gwConfig.max_logs) || 500)
      logs = [rec, ...logs.filter((x) => x.id !== rec.id)].slice(0, maxLogs)
      if (!isDup) {
        const prevTotal = Number(stats.total_requests) || 0
        const nextTotal = prevTotal + 1
        const prevAvg = Number(stats.avg_latency_ms) || 0
        const nextAvg = ((prevAvg * prevTotal) + (Number(rec.latency_ms) || 0)) / nextTotal
        stats = {
          ...stats,
          total_requests: nextTotal,
          success_requests: (Number(stats.success_requests) || 0) + (rec.ok ? 1 : 0),
          error_requests: (Number(stats.error_requests) || 0) + (rec.ok ? 0 : 1),
          cache_hits: (Number(stats.cache_hits) || 0) + (rec.cache_hit ? 1 : 0),
          avg_latency_ms: nextAvg,
        }
        if (rec.circuit_tripped) {
          refreshCircuitStates()
        }
      }
    })

    on('gateway:status', (st) => {
      if (!st) return
      const running = Boolean(st.running)
      stats = {
        ...stats,
        running,
        listen_addr: st.listen_addr || stats.listen_addr,
        started_at: running ? (st.started_at || stats.started_at) : '',
      }
      if (st.listen_addr) listenAddr = st.listen_addr
      if (st.error) {
        toast.error(st.error)
      }
    })
  }

  function handleKeydown(e) {
    if (!hasPrimaryMod(e)) return
    if (e.key.toLowerCase() === 's') {
      if (activeTab === 'routes' && (selectedRoute || isNewRoute)) {
        e.preventDefault()
        saveCurrentRoute()
      } else if (activeTab === 'devices' && (selectedDevice || isNewDevice)) {
        e.preventDefault()
        saveCurrentDevice()
      } else if (activeTab === 'signers' && (selectedSigner || isNewSigner)) {
        e.preventDefault()
        saveCurrentSigner()
      } else if (activeTab === 'accounts' && (selectedAccount || isNewAccount)) {
        e.preventDefault()
        saveCurrentAccount()
      } else if (activeTab === 'workers' && (selectedWorker || isNewWorker)) {
        e.preventDefault()
        saveCurrentWorker()
      }
    }
  }

  onMount(async () => {
    subscribeEvents()
    await loadAllData()
    if (destroyed) return
    workerPollTimer = setInterval(() => {
      if (!destroyed && activeTab === 'workers') {
        loadWorkersAndStatuses(true)
      }
    }, 3000)
    let consumedInitialHandoff = false
    unsubHandoff = gatewayHandoff.subscribe((h) => {
      if (h && !destroyed) {
        consumedInitialHandoff = true
        applyHandoff(h)
      }
    })
    if (!destroyed && !consumedInitialHandoff && S.pendingPublishFlow) {
      applyHandoff(S.pendingPublishFlow)
    }
  })

  onDestroy(() => {
    destroyed = true
    if (workerPollTimer) {
      clearInterval(workerPollTimer)
      workerPollTimer = null
    }
    if (unsubHandoff) {
      unsubHandoff()
      unsubHandoff = null
    }
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
  })
</script>

<svelte:window on:keydown={handleKeydown} />

<div class="gw-page">
  <!-- 1. Top Control Strip -->
  <section class="control-strip">
    <div class="ctrl-left">
      <Badge variant={stats.running ? 'success' : 'neutral'} size="md" dot pulse={stats.running}>
        {stats.running ? $t('gateway.topbar.listening') : $t('gateway.topbar.stopped')}
      </Badge>

      <div class="addr-group">
        <Icon name="globe" size={13} />
        <input
          type="text"
          class="cap-input addr-input mono"
          bind:value={listenAddr}
          disabled={stats.running || serverBusy}
          placeholder={$t('gateway.topbar.listenPlaceholder')}
          aria-label={$t('gateway.topbar.listenAddr')}
          on:keydown={(e) => {
            if (e.key === 'Enter' && !stats.running) toggleGatewayServer()
          }}
        />
        <Button
          variant="ghost"
          size="xs"
          icon="copy"
          iconOnly
          title={$t('gateway.topbar.copyBaseUrl')}
          on:click={() => copyToClipboard(activeBaseUrl)}
        />
      </div>

      <Button
        variant={stats.running ? 'danger' : 'success'}
        size="sm"
        icon={stats.running ? 'square' : 'play'}
        loading={serverBusy}
        on:click={toggleGatewayServer}
      >
        {#if serverBusy}
          {stats.running ? $t('gateway.topbar.stopping') : $t('gateway.topbar.starting')}
        {:else}
          {stats.running ? $t('gateway.topbar.stop') : $t('gateway.topbar.start')}
        {/if}
      </Button>
    </div>

    <div class="ctrl-spacer"></div>

    <div class="ctrl-right">
      <Button
        variant="secondary"
        size="sm"
        icon={gwConfig.require_auth ? 'lock' : 'unlock'}
        active={showConfigDrawer}
        on:click={toggleConfigDrawer}
      >
        <span>{$t('gateway.topbar.apiAuth')}</span>
        <Badge variant={gwConfig.require_auth ? 'warning' : 'neutral'} size="xs">
          {gwConfig.require_auth ? $t('gateway.topbar.authOn') : $t('gateway.topbar.authOpen')}
        </Badge>
      </Button>

      <Button
        variant="secondary"
        size="sm"
        icon="file-code"
        active={showOpenApiDrawer}
        on:click={() => openOpenApiDrawer(false)}
      >
        {$t('gateway.topbar.openApi')}
      </Button>

      <Button
        variant="secondary"
        size="sm"
        icon="radar"
        active={showPromDrawer}
        on:click={() => openPromDrawer(false)}
      >
        {$t('gateway.topbar.prometheus')}
      </Button>

      <Button
        variant="secondary"
        size="sm"
        icon="box"
        active={showDockerDrawer}
        on:click={() => openDockerDrawer(false)}
      >
        {$t('gateway.topbar.docker')}
      </Button>

      <Button
        variant="ghost"
        size="sm"
        icon="refresh"
        iconOnly
        loading={refreshingAll}
        title={$t('gateway.topbar.refreshAll')}
        on:click={loadAllData}
      />
    </div>
  </section>

  <!-- Collapsible Drawer: API Key Auth & Gateway Config -->
  {#if showConfigDrawer}
    <section class="top-drawer cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('gateway.configDrawer.title')}</div>
          <div class="drawer-sub">{$t('gateway.configDrawer.subtitle')}</div>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (showConfigDrawer = false)}>
          {$t('gateway.configDrawer.close')}
        </Button>
      </div>

      <div class="cfg-drawer-grid">
        <div class="cfg-col">
          <div class="switch-row">
            <div>
              <div class="f-label">{$t('gateway.configDrawer.requireAuth')}</div>
              <div class="f-hint">{$t('gateway.configDrawer.requireAuthHint')}</div>
            </div>
            <label class="switch">
              <input type="checkbox" bind:checked={cfgRequireAuth} />
              <span class="switch-track"></span>
            </label>
          </div>

          <div class="f-block">
            <div class="label-row">
              <span class="f-label">{$t('gateway.configDrawer.apiKeys')}</span>
              <div class="inline-actions">
                <Button variant="ghost" size="xs" icon={cfgRevealKeys ? 'eye-off' : 'eye'} on:click={() => (cfgRevealKeys = !cfgRevealKeys)} />
                <Button variant="secondary" size="xs" icon="key" on:click={generateApiKey}>
                  {$t('gateway.configDrawer.generateKey')}
                </Button>
              </div>
            </div>

            <div class="key-add-row">
              <input
                type="text"
                class="cap-input mono flex-1"
                bind:value={cfgNewKey}
                placeholder={$t('gateway.configDrawer.addKeyPlaceholder')}
                on:keydown={(e) => { if (e.key === 'Enter') addApiKey() }}
              />
              <Button variant="secondary" size="xs" icon="plus" on:click={addApiKey}>
                {$t('gateway.configDrawer.addKey')}
              </Button>
            </div>

            {#if cfgApiKeys.length === 0}
              <div class="empty-inline">{$t('gateway.configDrawer.noKeys')}</div>
            {:else}
              <div class="key-list">
                {#each cfgApiKeys as k (k)}
                  <div class="key-chip mono">
                    <span class="truncate">{maskKey(k)}</span>
                    <button type="button" class="chip-icon-btn" on:click={() => copyToClipboard(k)} title="Copy">
                      <Icon name="copy" size={11} />
                    </button>
                    <button type="button" class="chip-icon-btn danger" on:click={() => removeApiKey(k)} title="Remove">
                      <Icon name="x" size={11} />
                    </button>
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        </div>

        <div class="cfg-col">
          <label class="f-block">
            <span class="f-label">{$t('gateway.configDrawer.corsOrigins')}</span>
            <textarea
              class="cap-textarea mono"
              rows="3"
              bind:value={cfgCorsText}
              placeholder={$t('gateway.configDrawer.corsPlaceholder')}
            ></textarea>
          </label>

          <label class="f-block narrow-field">
            <span class="f-label">{$t('gateway.configDrawer.maxLogs')}</span>
            <input type="number" min="50" max="10000" class="cap-input mono tabular-nums" bind:value={cfgMaxLogs} />
          </label>
        </div>
      </div>

      <div class="drawer-foot">
        <div class="ctrl-spacer"></div>
        <Button variant="primary" size="sm" icon="save" loading={savingConfig} on:click={saveGatewayConfig}>
          {$t('gateway.configDrawer.save')}
        </Button>
      </div>
    </section>
  {/if}

  <!-- Collapsible Drawer: OpenAPI 3.0 Spec -->
  {#if showOpenApiDrawer}
    <section class="top-drawer cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('gateway.openApiDrawer.title')}</div>
          <div class="drawer-sub">{$t('gateway.openApiDrawer.subtitle')}</div>
        </div>
        <div class="inline-actions">
          <Button variant="ghost" size="xs" icon="refresh" loading={loadingOpenApi} on:click={loadOpenApiSpec}>
            {$t('gateway.openApiDrawer.refresh')}
          </Button>
          <Button variant="secondary" size="xs" icon="copy" disabled={!openApiSpec} on:click={() => copyToClipboard(openApiSpec, translate('gateway.toast.openApiCopied'))}>
            {$t('gateway.openApiDrawer.copyJson')}
          </Button>
          <Button variant="primary" size="xs" icon="download" disabled={!openApiSpec} on:click={downloadOpenApiSpec}>
            {$t('gateway.openApiDrawer.downloadJson')}
          </Button>
          <Button variant="ghost" size="xs" icon="x" iconOnly on:click={() => (showOpenApiDrawer = false)} />
        </div>
      </div>

      <div class="openapi-meta mono">
        <span>{$t('gateway.openApiDrawer.liveEndpoint')}</span>
        <span class="accent-text">{activeBaseUrl}/openapi.json</span>
      </div>

      <pre class="openapi-pre mono">{loadingOpenApi ? $t('gateway.openApiDrawer.loading') : (openApiSpec || $t('gateway.openApiDrawer.empty'))}</pre>
    </section>
  {/if}

  <!-- Collapsible Drawer: Prometheus Metrics -->
  {#if showPromDrawer}
    <section class="top-drawer cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('gateway.promDrawer.title')}</div>
          <div class="drawer-sub">{$t('gateway.promDrawer.subtitle')}</div>
        </div>
        <div class="inline-actions">
          <Button variant="ghost" size="xs" icon="refresh" loading={loadingProm} on:click={loadPromMetrics}>
            {$t('gateway.promDrawer.refresh')}
          </Button>
          <Button variant="secondary" size="xs" icon="copy" disabled={!promMetrics} on:click={() => copyToClipboard(promMetrics, translate('gateway.toast.promCopied'))}>
            {$t('gateway.promDrawer.copy')}
          </Button>
          <Button variant="primary" size="xs" icon="download" disabled={!promMetrics} on:click={downloadPromMetrics}>
            {$t('gateway.promDrawer.download')}
          </Button>
          <Button variant="ghost" size="xs" icon="x" iconOnly on:click={() => (showPromDrawer = false)} />
        </div>
      </div>

      <div class="openapi-meta mono">
        <span>{$t('gateway.promDrawer.liveEndpoint')}</span>
        <span class="accent-text">{activeBaseUrl}/metrics/prometheus</span>
      </div>

      <pre class="openapi-pre mono">{loadingProm ? $t('gateway.promDrawer.loading') : (promMetrics || $t('gateway.promDrawer.empty'))}</pre>
    </section>
  {/if}

  <!-- Collapsible Drawer: Docker / Headless Deployment Bundle -->
  {#if showDockerDrawer}
    <section class="top-drawer cap-card">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('gateway.dockerDrawer.title')}</div>
          <div class="drawer-sub">{$t('gateway.dockerDrawer.subtitle')}</div>
        </div>
        <div class="inline-actions">
          <Button variant="ghost" size="xs" icon="refresh" loading={loadingDocker} on:click={loadDockerBundle}>
            {$t('gateway.dockerDrawer.regenerate')}
          </Button>
          <Button variant="secondary" size="xs" icon="copy" disabled={!activeDockerContent} on:click={copyActiveDockerFile}>
            {$t('gateway.dockerDrawer.copyFile', { file: activeDockerFilename })}
          </Button>
          <Button variant="primary" size="xs" icon="download" disabled={!activeDockerContent} on:click={downloadActiveDockerFile}>
            {$t('gateway.dockerDrawer.downloadFile', { file: activeDockerFilename })}
          </Button>
          <Button variant="ghost" size="xs" icon="x" iconOnly on:click={() => (showDockerDrawer = false)} />
        </div>
      </div>

      <div class="docker-bar">
        <div class="seg-mini">
          <button type="button" class="seg-mini-btn mono" class:active={dockerTab === 'dockerfile'} on:click={() => (dockerTab = 'dockerfile')}>
            {$t('gateway.dockerDrawer.dockerfileTab')}
          </button>
          <button type="button" class="seg-mini-btn mono" class:active={dockerTab === 'compose'} on:click={() => (dockerTab = 'compose')}>
            {$t('gateway.dockerDrawer.composeTab')}
          </button>
        </div>
        <div class="openapi-meta mono">
          <span>{$t('gateway.dockerDrawer.listenMeta')}</span>
          <span class="accent-text">{dockerBundle?.listen_addr || listenAddr}</span>
          <span class="kpi-sep">·</span>
          <span>{$t('gateway.dockerDrawer.headlessHint')}</span>
          <span class="accent-text">cap gateway serve --addr {dockerBundle?.listen_addr || listenAddr}</span>
        </div>
      </div>

      <pre class="openapi-pre mono">{loadingDocker ? $t('gateway.dockerDrawer.loading') : (activeDockerContent || $t('gateway.dockerDrawer.empty'))}</pre>
    </section>
  {/if}

  <!-- 2. 5-KPI Telemetry Strip + Pro Telemetry Badges -->
  <section class="kpi-strip">
    <div class="kpi-card">
      <div class="kpi-head">
        <span class="kpi-label">{$t('gateway.kpi.totalRequests')}</span>
        <Icon name="activity" size={13} />
      </div>
      <div class="kpi-val mono tabular-nums">{(stats.total_requests || 0).toLocaleString()}</div>
      <div class="kpi-sub mono tabular-nums">
        {$t('gateway.kpi.rateLimitedMeta', { rl: stats.rate_limited || 0, auth: stats.auth_failures || 0 })}
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-head">
        <span class="kpi-label">{$t('gateway.kpi.successRate')}</span>
        <Icon name="check-circle" size={13} />
      </div>
      <div class="kpi-val mono tabular-nums {successRateClass}">{successRateText}</div>
      <div class="kpi-sub mono tabular-nums">
        {$t('gateway.kpi.okErrMeta', { ok: stats.success_requests || 0, err: stats.error_requests || 0 })}
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-head">
        <span class="kpi-label">{$t('gateway.kpi.avgLatency')}</span>
        <Icon name="clock" size={13} />
      </div>
      <div class="kpi-val mono tabular-nums">
        {stats.total_requests > 0 ? formatDuration(stats.avg_latency_ms) : '—'}
      </div>
      <div class="kpi-sub">{$t('gateway.kpi.signerPipeline')}</div>
    </div>

    <div class="kpi-card">
      <div class="kpi-head">
        <span class="kpi-label">{$t('gateway.kpi.healthyProxies')}</span>
        <Icon name="globe" size={13} />
      </div>
      <div class="kpi-val mono tabular-nums">
        <span class:kpi-good={displayHealthyProxies > 0}>{displayHealthyProxies}</span><span class="kpi-slash">/{displayActiveProxies}</span>
      </div>
      <div class="kpi-sub mono tabular-nums">
        {$t('gateway.kpi.activeNodesMeta', { enabled: displayActiveProxies, total: stats.proxy_total || proxies.length })}
      </div>
    </div>

    <div class="kpi-card">
      <div class="kpi-head">
        <span class="kpi-label">{$t('gateway.kpi.devicesRoutes')}</span>
        <Icon name="layers" size={13} />
      </div>
      <div class="kpi-val mono tabular-nums">
        {stats.device_enabled || 0}<span class="kpi-slash">/{stats.device_total || devices.length}</span>
        <span class="kpi-sep">·</span>
        {stats.route_enabled || 0}<span class="kpi-slash">/{stats.route_total || routes.length}</span>
      </div>
      <div class="kpi-sub mono tabular-nums">
        {$t('gateway.kpi.devicesRoutesMeta', {
          devices: stats.device_total || devices.length,
          routes: stats.route_total || routes.length,
          signers: stats.signer_total || signers.length,
        })}
      </div>
    </div>
  </section>

  <!-- Compact Pro Live Badges Strip -->
  <section class="pro-kpi-strip">
    <button type="button" class="pro-kpi-pill" on:click={() => (activeTab = 'accounts')}>
      <Icon name="shield" size={12} />
      <span class="pk-label">{$t('gateway.kpi.activeAccounts')}</span>
      <Badge variant={displayActiveAccounts > 0 ? 'success' : 'neutral'} size="xs" mono>
        {displayActiveAccounts}/{displayTotalAccounts}
      </Badge>
    </button>

    <button type="button" class="pro-kpi-pill" on:click={() => { activeTab = 'workers'; loadWorkersAndStatuses() }}>
      <Icon name="cpu" size={12} />
      <span class="pk-label">{$t('gateway.kpi.healthyWorkers')}</span>
      <Badge variant={displayHealthyWorkers > 0 ? 'success' : (displayTotalWorkers > 0 ? 'warning' : 'neutral')} size="xs" mono>
        {displayHealthyWorkers}/{displayTotalWorkers}
      </Badge>
    </button>

    <div class="pro-kpi-pill static">
      <Icon name="database" size={12} />
      <span class="pk-label">{$t('gateway.kpi.cacheHits')}</span>
      <Badge variant={(stats.cache_hits || 0) > 0 ? 'info' : 'neutral'} size="xs" mono>
        {$t('gateway.kpi.cacheRatio', { hits: stats.cache_hits || 0, misses: stats.cache_misses || 0 })}
      </Badge>
    </div>

    <div class="pro-kpi-pill static">
      <Icon name="alert-triangle" size={12} />
      <span class="pk-label">{$t('gateway.kpi.openCircuits')}</span>
      <Badge variant={displayOpenCircuits > 0 ? 'danger' : 'success'} size="xs" dot={displayOpenCircuits > 0} mono>
        {displayOpenCircuits}
      </Badge>
    </div>
  </section>

  <!-- 3. Sub-tab Switcher Bar -->
  <div class="subtab-bar" role="tablist">
    <button type="button" role="tab" aria-selected={activeTab === 'routes'} class="subtab-btn" class:active={activeTab === 'routes'} on:click={() => (activeTab = 'routes')}>
      <Icon name="link" size={13} />
      <span>{$t('gateway.tabs.routes')}</span>
      <span class="tab-cnt mono tabular-nums">{routes.length}</span>
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'proxies'} class="subtab-btn" class:active={activeTab === 'proxies'} on:click={() => (activeTab = 'proxies')}>
      <Icon name="globe" size={13} />
      <span>{$t('gateway.tabs.proxies')}</span>
      <span class="tab-cnt mono tabular-nums">{displayHealthyProxies}/{proxies.length}</span>
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'devices'} class="subtab-btn" class:active={activeTab === 'devices'} on:click={() => (activeTab = 'devices')}>
      <Icon name="smartphone" size={13} />
      <span>{$t('gateway.tabs.devices')}</span>
      <span class="tab-cnt mono tabular-nums">{devices.length}</span>
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'signers'} class="subtab-btn" class:active={activeTab === 'signers'} on:click={() => (activeTab = 'signers')}>
      <Icon name="key" size={13} />
      <span>{$t('gateway.tabs.signers')}</span>
      <span class="tab-cnt mono tabular-nums">{signers.length}</span>
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'logs'} class="subtab-btn" class:active={activeTab === 'logs'} on:click={() => { activeTab = 'logs'; loadGatewayLogs() }}>
      <Icon name="terminal" size={13} />
      <span>{$t('gateway.tabs.logs')}</span>
      <span class="tab-cnt mono tabular-nums">{logs.length}</span>
      {#if logErrorCount > 0}
        <span class="tab-err-dot"></span>
      {/if}
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'accounts'} class="subtab-btn" class:active={activeTab === 'accounts'} on:click={() => (activeTab = 'accounts')}>
      <Icon name="shield" size={13} />
      <span>{$t('gateway.tabs.accounts')}</span>
      <span class="tab-cnt mono tabular-nums">{displayActiveAccounts}/{accounts.length}</span>
    </button>
    <button type="button" role="tab" aria-selected={activeTab === 'workers'} class="subtab-btn" class:active={activeTab === 'workers'} on:click={() => { activeTab = 'workers'; loadWorkersAndStatuses() }}>
      <Icon name="cpu" size={13} />
      <span>{$t('gateway.tabs.workers')}</span>
      <span class="tab-cnt mono tabular-nums">{displayHealthyWorkers}/{displayTotalWorkers}</span>
    </button>
  </div>

  <!-- 4. Active Sub-tab Workspace -->
  <div class="gw-body">
    <!-- ==================== SUB-TAB 1: SERVICE ROUTES & LIVE TESTER ==================== -->
    {#if activeTab === 'routes'}
      <SplitPane direction="horizontal" initialSize={30} minPrimary={22} minSecondary={52} storageKey="cap.gateway.routes.hsplit">
        <!-- Left: Published Routes + Flow Picker -->
        <div slot="primary" class="list-pane">
          <div class="pane-toolbar">
            <div class="search-box">
              <Icon name="search" size={12} />
              <input
                type="text"
                class="search-input"
                bind:value={routeSearch}
                placeholder={$t('gateway.routes.searchPlaceholder')}
              />
              {#if routeSearch}
                <button type="button" class="clear-btn" on:click={() => (routeSearch = '')}>
                  <Icon name="x" size={11} />
                </button>
              {/if}
            </div>
            <Button variant="primary" size="xs" icon="plus" on:click={createNewRoute}>
              {$t('gateway.routes.newRoute')}
            </Button>
            <Button
              variant="secondary"
              size="xs"
              icon="activity"
              active={showFlowPicker}
              on:click={() => {
                if (showFlowPicker) showFlowPicker = false
                else openFlowPicker()
              }}
            >
              {$t('gateway.routes.fromFlow')}
            </Button>
          </div>

          <!-- Inline Publish from Captured Flow Picker -->
          {#if showFlowPicker}
            <div class="flow-picker-panel">
              <div class="fp-head">
                <div>
                  <div class="fp-title">{$t('gateway.routes.publishFlow.title')}</div>
                  <div class="fp-sub">{$t('gateway.routes.publishFlow.subtitle')}</div>
                </div>
                <div class="inline-actions">
                  <Button variant="ghost" size="xs" icon="refresh" iconOnly loading={loadingFlows} title={$t('gateway.routes.publishFlow.refresh')} on:click={loadRecentFlows} />
                  <Button variant="ghost" size="xs" icon="x" iconOnly on:click={() => (showFlowPicker = false)} />
                </div>
              </div>

              <div class="search-box compact">
                <Icon name="search" size={11} />
                <input
                  type="text"
                  class="search-input"
                  bind:value={flowSearch}
                  placeholder={$t('gateway.routes.publishFlow.searchPlaceholder')}
                />
              </div>

              <div class="flow-list">
                {#if filteredFlows.length === 0}
                  <div class="empty-inline">{$t('gateway.routes.publishFlow.empty')}</div>
                {:else}
                  {#each filteredFlows as fl (fl.id)}
                    <button
                      type="button"
                      class="flow-pick-row"
                      class:active={selectedFlowId === fl.id}
                      on:click={() => pickFlowForPublish(fl)}
                    >
                      <Badge variant="method" method={fl.method} size="xs" />
                      <span class="fp-url mono truncate" title={fl.url}>{fl.host}{fl.path}</span>
                      {#if fl.status}
                        <Badge status={fl.status} size="xs" />
                      {/if}
                    </button>
                  {/each}
                {/if}
              </div>

              <div class="fp-inputs">
                <label class="f-block">
                  <span class="f-label">{$t('gateway.routes.publishFlow.slugLabel')}</span>
                  <input type="text" class="cap-input mono" bind:value={publishSlug} placeholder={$t('gateway.routes.publishFlow.slugPlaceholder')} />
                </label>
                <label class="f-block">
                  <span class="f-label">{$t('gateway.routes.publishFlow.nameLabel')}</span>
                  <input type="text" class="cap-input" bind:value={publishName} placeholder={$t('gateway.routes.publishFlow.namePlaceholder')} />
                </label>
              </div>

              <div class="fp-foot">
                <Button
                  variant="primary"
                  size="xs"
                  icon="upload"
                  fullWidth
                  loading={publishingFlow}
                  disabled={!selectedFlowId}
                  on:click={handlePublishFlow}
                >
                  {publishingFlow ? $t('gateway.routes.publishFlow.publishing') : $t('gateway.routes.publishFlow.publishBtn')}
                </Button>
              </div>
            </div>
          {/if}

          <div class="list-scroll">
            {#if filteredRoutes.length === 0}
              <EmptyState
                icon="link"
                title={$t('gateway.routes.emptyTitle')}
                description={$t('gateway.routes.emptyDesc')}
                compact
              >
                <Button variant="primary" size="xs" icon="plus" on:click={createNewRoute}>
                  {$t('gateway.routes.newRoute')}
                </Button>
                <Button variant="secondary" size="xs" icon="activity" on:click={() => openFlowPicker()}>
                  {$t('gateway.routes.fromFlow')}
                </Button>
              </EmptyState>
            {:else}
              {#each filteredRoutes as r (r.id)}
                <button
                  type="button"
                  class="entity-card"
                  class:active={selectedRoute?.id === r.id && !isNewRoute}
                  class:disabled-card={!r.enabled}
                  on:click={() => selectRoute(r)}
                >
                  <div class="ec-top">
                    <span class="status-dot" class:on={r.enabled}></span>
                    <Badge variant="method" method={r.upstream_method || 'GET'} size="xs" />
                    <span class="ec-slug mono truncate">/gw/{r.slug}</span>
                  </div>
                  <div class="ec-name truncate">{r.name || r.slug}</div>
                  <div class="ec-url mono truncate" title={r.upstream_url}>{r.upstream_url}</div>
                  <div class="ec-chips">
                    {#if r.signer_id}
                      <Badge variant="purple" size="xs" mono>
                        {$t('gateway.routes.badges.signer')}: {signerNameById[r.signer_id] || r.signer_id}
                      </Badge>
                    {/if}
                    {#if r.require_proxy || r.proxy_tags?.length}
                      <Badge variant="info" size="xs">
                        {$t('gateway.routes.badges.proxy')}{r.proxy_tags?.length ? ` (${r.proxy_tags.join(',')})` : ''}
                      </Badge>
                    {/if}
                    {#if r.require_device || r.device_tags?.length}
                      <Badge variant="accent" size="xs">
                        {$t('gateway.routes.badges.device')}{r.device_tags?.length ? ` (${r.device_tags.join(',')})` : ''}
                      </Badge>
                    {/if}
                    {#if r.require_account || r.account_tags?.length}
                      <Badge variant="success" size="xs">
                        {$t('gateway.routes.badges.account')}{r.account_tags?.length ? ` (${r.account_tags.join(',')})` : ''}
                      </Badge>
                    {/if}
                    {#if r.tls_profile && r.tls_profile !== 'go_default'}
                      <Badge variant="neutral" size="xs" mono>{r.tls_profile}</Badge>
                    {/if}
                    {#if r.cache_ttl_sec > 0}
                      <Badge variant="info" size="xs" mono>
                        {$t('gateway.routes.badges.cache', { sec: r.cache_ttl_sec })}
                      </Badge>
                    {/if}
                    {#if circuitStates[r.slug]?.state === 'open'}
                      <Badge variant="danger" size="xs" dot mono>{$t('gateway.routes.badges.circuitOpen')}</Badge>
                    {:else if circuitStates[r.slug]?.state === 'half_open'}
                      <Badge variant="warning" size="xs" dot mono>{$t('gateway.routes.badges.circuitHalfOpen')}</Badge>
                    {/if}
                    {#if r.rate_limit_rps > 0}
                      <Badge variant="warning" size="xs" mono>
                        {$t('gateway.routes.badges.rps', { rps: r.rate_limit_rps })}
                      </Badge>
                    {/if}
                  </div>
                </button>
              {/each}
            {/if}
          </div>
        </div>

        <!-- Right: Route Editor + Live Test Console -->
        <div slot="secondary" class="detail-pane">
          {#if selectedRoute || isNewRoute}
            <SplitPane direction="vertical" initialSize={58} minPrimary={30} minSecondary={24} storageKey="cap.gateway.routeTest.vsplit">
              <!-- Top: Route Editor -->
              <div slot="primary" class="editor-shell">
                <div class="editor-topbar">
                  <div class="editor-head-left">
                    <Badge variant="method" method={rMethod} size="sm" />
                    <span class="editor-title mono truncate">
                      {isNewRoute ? $t('gateway.routes.editor.newTitle') : `/gw/${rSlug || selectedRoute?.slug || ''}`}
                    </span>
                    {#if !isNewRoute && rSlug}
                      <Button
                        variant="ghost"
                        size="xs"
                        icon="copy"
                        iconOnly
                        title={$t('gateway.routes.editor.copyEndpoint', { slug: rSlug })}
                        on:click={() => copyToClipboard(`${activeBaseUrl}/gw/${rSlug}`)}
                      />
                    {/if}
                    {#if rSourceFlowId}
                      <Badge variant="neutral" size="xs" mono>{$t('gateway.routes.editor.sourceFlow')}: {rSourceFlowId.slice(0, 8)}</Badge>
                    {/if}
                  </div>
                  <div class="editor-head-actions">
                    <label class="inline-switch">
                      <span>{rEnabled ? $t('gateway.routes.editor.enabled') : $t('gateway.routes.editor.disabled')}</span>
                      <span class="switch">
                        <input type="checkbox" bind:checked={rEnabled} />
                        <span class="switch-track"></span>
                      </span>
                    </label>
                    {#if selectedRoute && !isNewRoute}
                      {#if confirmDeleteRouteId === selectedRoute.id}
                        <Button variant="danger" size="xs" icon="trash" on:click={() => deleteCurrentRoute(selectedRoute.id)}>
                          {$t('gateway.routes.editor.confirmDelete')}
                        </Button>
                        <Button variant="ghost" size="xs" on:click={() => (confirmDeleteRouteId = null)}>
                          <Icon name="x" size={12} />
                        </Button>
                      {:else}
                        <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDeleteRouteId = selectedRoute.id)}>
                          {$t('gateway.routes.editor.delete')}
                        </Button>
                      {/if}
                    {/if}
                    <Button variant="primary" size="xs" icon="save" loading={savingRoute} on:click={saveCurrentRoute}>
                      {$t('gateway.routes.editor.save')}
                    </Button>
                  </div>
                </div>

                <div class="editor-scroll">
                  <!-- Core Endpoint & Template Card -->
                  <div class="form-card cap-card">
                    <div class="card-head">
                      <span class="card-title">{$t('gateway.routes.editor.sectionCore')}</span>
                      <span class="card-hint mono">{activeBaseUrl}/gw/{rSlug || 'slug'}</span>
                    </div>

                    <div class="grid-3">
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.slug')}</span>
                        <input type="text" class="cap-input mono" bind:value={rSlug} placeholder="search-items" />
                      </label>
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.name')}</span>
                        <input type="text" class="cap-input" bind:value={rName} placeholder={$t('gateway.routes.editor.namePlaceholder')} />
                      </label>
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.description')}</span>
                        <input type="text" class="cap-input" bind:value={rDescription} placeholder={$t('gateway.routes.editor.descriptionPlaceholder')} />
                      </label>
                    </div>

                    <div class="method-url-row">
                      <label class="f-block method-col">
                        <span class="f-label">{$t('gateway.routes.editor.method')}</span>
                        <select class="cap-input mono" bind:value={rMethod}>
                          {#each HTTP_METHODS as m}
                            <option value={m}>{m}</option>
                          {/each}
                        </select>
                      </label>
                      <label class="f-block flex-1">
                        <span class="f-label">{$t('gateway.routes.editor.upstreamUrl')}</span>
                        <input
                          bind:this={urlInputEl}
                          type="text"
                          class="cap-input mono"
                          bind:value={rUpstreamUrl}
                          on:focus={() => (templateTarget = 'url')}
                          placeholder={$t('gateway.routes.editor.upstreamUrlPlaceholder')}
                        />
                      </label>
                    </div>

                    <!-- Clickable Template Variable Chips -->
                    <div class="tpl-bar">
                      <span class="tpl-label">{$t('gateway.routes.editor.templateChips')}</span>
                      <div class="seg-mini">
                        <button type="button" class="seg-mini-btn" class:active={templateTarget === 'url'} on:click={() => (templateTarget = 'url')}>
                          {$t('gateway.routes.editor.targetUrl')}
                        </button>
                        <button type="button" class="seg-mini-btn" class:active={templateTarget === 'body'} on:click={() => (templateTarget = 'body')}>
                          {$t('gateway.routes.editor.targetBody')}
                        </button>
                      </div>
                      <div class="tpl-chips">
                        {#each TEMPLATE_VARS as tv}
                          <button type="button" class="tpl-chip mono" on:click={() => insertTemplateVar(tv)}>
                            {tv}
                          </button>
                        {/each}
                      </div>
                    </div>

                    <!-- Static Headers & Static Query KV Editors -->
                    <div class="grid-2">
                      <div class="kv-section">
                        <div class="label-row">
                          <span class="f-label">{$t('gateway.routes.editor.staticHeaders')}</span>
                          <button type="button" class="mini-link" on:click={() => (rStaticHeaders = [...rStaticHeaders, { key: '', value: '' }])}>
                            + {$t('gateway.routes.editor.addPair')}
                          </button>
                        </div>
                        {#each rStaticHeaders as row, idx (idx)}
                          <div class="kv-edit-row">
                            <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder={$t('gateway.routes.editor.keyPlaceholder')} />
                            <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder={$t('gateway.routes.editor.valPlaceholder')} />
                            <button type="button" class="row-del" on:click={() => (rStaticHeaders = rStaticHeaders.filter((_, i) => i !== idx))}>
                              <Icon name="x" size={12} />
                            </button>
                          </div>
                        {/each}
                      </div>

                      <div class="kv-section">
                        <div class="label-row">
                          <span class="f-label">{$t('gateway.routes.editor.staticQuery')}</span>
                          <button type="button" class="mini-link" on:click={() => (rStaticQuery = [...rStaticQuery, { key: '', value: '' }])}>
                            + {$t('gateway.routes.editor.addPair')}
                          </button>
                        </div>
                        {#each rStaticQuery as row, idx (idx)}
                          <div class="kv-edit-row">
                            <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder={$t('gateway.routes.editor.keyPlaceholder')} />
                            <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder={$t('gateway.routes.editor.valPlaceholder')} />
                            <button type="button" class="row-del" on:click={() => (rStaticQuery = rStaticQuery.filter((_, i) => i !== idx))}>
                              <Icon name="x" size={12} />
                            </button>
                          </div>
                        {/each}
                      </div>
                    </div>

                    <div class="f-block">
                      <div class="label-row">
                        <span class="f-label">{$t('gateway.routes.editor.bodyTemplate')}</span>
                        <button type="button" class="mini-link" on:click={formatRouteBodyJson}>
                          {$t('gateway.routes.editor.formatJson')}
                        </button>
                      </div>
                      <textarea
                        bind:this={bodyInputEl}
                        class="cap-textarea mono"
                        rows="3"
                        bind:value={rBodyTemplate}
                        on:focus={() => (templateTarget = 'body')}
                        placeholder={$t('gateway.routes.editor.bodyPlaceholder')}
                      ></textarea>
                    </div>
                  </div>

                  <!-- Pipeline Integration Card -->
                  <div class="form-card cap-card">
                    <div class="card-head">
                      <span class="card-title">{$t('gateway.routes.editor.sectionPipeline')}</span>
                    </div>

                    <div class="grid-3">
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.signer')}</span>
                        <select class="cap-input" bind:value={rSignerId}>
                          <option value="">{$t('gateway.routes.editor.signerNone')}</option>
                          {#each signers as sg (sg.id)}
                            <option value={sg.id}>[{sg.kind}] {sg.name}</option>
                          {/each}
                        </select>
                      </label>

                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.rateLimitRps')}</span>
                        <input type="number" min="0" step="0.5" class="cap-input mono tabular-nums" bind:value={rRateLimitRps} title={$t('gateway.routes.editor.rateLimitHint')} />
                      </label>

                      <label class="f-block">
                        <span class="f-label">{$t('gateway.routes.editor.timeoutSec')}</span>
                        <input type="number" min="1" max="120" class="cap-input mono tabular-nums" bind:value={rTimeoutSec} />
                      </label>
                    </div>

                    <div class="grid-2">
                      <div class="pool-bind-box">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.routes.editor.deviceTags')}</span>
                          <input type="text" class="cap-input mono" bind:value={rDeviceTags} placeholder={$t('gateway.routes.editor.tagsPlaceholder')} />
                        </label>
                        <label class="check-opt">
                          <input type="checkbox" bind:checked={rRequireDevice} />
                          <span>{$t('gateway.routes.editor.requireDevice')}</span>
                        </label>
                      </div>

                      <div class="pool-bind-box">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.routes.editor.proxyTags')}</span>
                          <input type="text" class="cap-input mono" bind:value={rProxyTags} placeholder={$t('gateway.routes.editor.tagsPlaceholder')} />
                        </label>
                        <label class="check-opt">
                          <input type="checkbox" bind:checked={rRequireProxy} />
                          <span>{$t('gateway.routes.editor.requireProxy')}</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  <!-- Production Controls: TLS Fingerprint & mTLS -->
                  <div class="form-card cap-card prod-card">
                    <button type="button" class="prod-head-btn" on:click={() => (openTlsSection = !openTlsSection)}>
                      <span class="prod-head-left">
                        <Icon name={openTlsSection ? 'chevron-down' : 'chevron-right'} size={13} />
                        <Icon name="shield-check" size={13} />
                        <span class="card-title">{$t('gateway.routes.editor.tlsSection')}</span>
                      </span>
                      <span class="prod-head-badges">
                        <Badge variant={rTlsProfile && rTlsProfile !== 'go_default' ? 'accent' : 'neutral'} size="xs" mono>
                          {rTlsProfile || 'go_default'}
                        </Badge>
                        {#if rMtlsCertPath.trim() && rMtlsKeyPath.trim()}
                          <Badge variant="info" size="xs" mono>mTLS</Badge>
                        {/if}
                      </span>
                    </button>

                    {#if openTlsSection}
                      <div class="prod-body">
                        <div class="grid-2">
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.tlsProfile')}</span>
                            <select
                              class="cap-input mono"
                              bind:value={rTlsProfile}
                              on:change={() => loadJa3ForProfile(rTlsProfile)}
                            >
                              {#each effectiveTlsProfiles as tp (tp.id)}
                                <option value={tp.id}>{tp.name} ({tp.id})</option>
                              {/each}
                            </select>
                          </label>

                          <div class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.ja3Summary')}</span>
                            <div class="ja3-bar mono">
                              {#if loadingJa3 && !currentJa3}
                                <span class="muted">…</span>
                              {:else if currentJa3}
                                <Badge variant="purple" size="xs" mono>JA3</Badge>
                                <span class="ja3-hash truncate" title={currentJa3.ja3_string || currentJa3.ja3_hash}>
                                  {currentJa3.ja3_hash || '—'}
                                </span>
                                <span class="ja3-meta">
                                  {$t('gateway.routes.editor.ja3CiphersCurves', {
                                    ciphers: currentJa3.cipher_count || 0,
                                    curves: currentJa3.curve_count || 0,
                                  })}
                                </span>
                                {#if currentJa3.ja3_hash}
                                  <button
                                    type="button"
                                    class="chip-icon-btn"
                                    title={$t('gateway.routes.editor.copyJa3')}
                                    on:click={() => copyToClipboard(currentJa3.ja3_hash)}
                                  >
                                    <Icon name="copy" size={11} />
                                  </button>
                                {/if}
                              {:else}
                                <span class="muted">—</span>
                              {/if}
                            </div>
                          </div>
                        </div>

                        <div class="mtls-row">
                          <label class="f-block flex-1">
                            <span class="f-label">{$t('gateway.routes.editor.mtlsCertPath')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rMtlsCertPath}
                              on:input={() => { mtlsValidateSeq++; mtlsValidation = null; validatingMtls = false }}
                              placeholder={$t('gateway.routes.editor.mtlsCertPlaceholder')}
                            />
                          </label>
                          <label class="f-block flex-1">
                            <span class="f-label">{$t('gateway.routes.editor.mtlsKeyPath')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rMtlsKeyPath}
                              on:input={() => { mtlsValidateSeq++; mtlsValidation = null; validatingMtls = false }}
                              placeholder={$t('gateway.routes.editor.mtlsKeyPlaceholder')}
                            />
                          </label>
                          <Button
                            variant="secondary"
                            size="sm"
                            icon="shield-check"
                            loading={validatingMtls}
                            disabled={!rMtlsCertPath.trim() || !rMtlsKeyPath.trim()}
                            on:click={handleValidateMtlsPair}
                          >
                            {validatingMtls ? $t('gateway.routes.editor.validatingPair') : $t('gateway.routes.editor.validatePair')}
                          </Button>
                        </div>

                        {#if mtlsValidation}
                          <div class="mtls-result" class:ok={mtlsValidation.valid} class:fail={!mtlsValidation.valid}>
                            <div class="mtls-res-head">
                              <Badge variant={mtlsValidation.valid ? 'success' : 'danger'} size="xs" dot>
                                {mtlsValidation.valid ? $t('gateway.routes.editor.mtlsValid') : $t('gateway.routes.editor.mtlsInvalid')}
                              </Badge>
                              <Badge variant={mtlsValidation.key_pair_match ? 'success' : 'danger'} size="xs">
                                {mtlsValidation.key_pair_match ? $t('gateway.routes.editor.mtlsMatchOk') : $t('gateway.routes.editor.mtlsMatchFail')}
                              </Badge>
                              {#if mtlsValidation.leaf}
                                <span class="mono truncate">{mtlsValidation.leaf.common_name || mtlsValidation.leaf.subject}</span>
                              {/if}
                              {#if mtlsValidation.expired}
                                <Badge variant="danger" size="xs">{$t('gateway.routes.editor.mtlsExpired')}</Badge>
                              {:else if mtlsValidation.valid && Number.isFinite(mtlsValidation.expires_in_days)}
                                <Badge variant="neutral" size="xs" mono>
                                  {$t('gateway.routes.editor.mtlsExpiresDays', { days: mtlsValidation.expires_in_days })}
                                </Badge>
                              {/if}
                              {#if mtlsValidation.has_client_auth_eku}
                                <Badge variant="info" size="xs">{$t('gateway.routes.editor.mtlsClientAuthEku')}</Badge>
                              {/if}
                              {#if mtlsValidation.chain_length > 0}
                                <Badge variant="neutral" size="xs" mono>
                                  {$t('gateway.routes.editor.mtlsChainLen', { len: mtlsValidation.chain_length })}
                                </Badge>
                              {/if}
                            </div>
                            {#if mtlsValidation.error}
                              <div class="mtls-msg mono">{mtlsValidation.error}</div>
                            {/if}
                            {#if mtlsValidation.warnings?.length}
                              <div class="mtls-warn mono">{mtlsValidation.warnings.join(' · ')}</div>
                            {/if}
                          </div>
                        {/if}
                      </div>
                    {/if}
                  </div>

                  <!-- Production Controls: Account Pool & Auto-Refresh -->
                  <div class="form-card cap-card prod-card">
                    <button type="button" class="prod-head-btn" on:click={() => (openAccountSection = !openAccountSection)}>
                      <span class="prod-head-left">
                        <Icon name={openAccountSection ? 'chevron-down' : 'chevron-right'} size={13} />
                        <Icon name="repeat" size={13} />
                        <span class="card-title">{$t('gateway.routes.editor.accountSection')}</span>
                      </span>
                      <span class="prod-head-badges">
                        {#if rRequireAccount}
                          <Badge variant="success" size="xs">{$t('gateway.routes.badges.account')}</Badge>
                        {/if}
                        {#if rAutoRefresh}
                          <Badge variant="warning" size="xs">AUTO-REFRESH</Badge>
                        {/if}
                      </span>
                    </button>

                    {#if openAccountSection}
                      <div class="prod-body">
                        <div class="grid-2">
                          <div class="pool-bind-box">
                            <label class="f-block">
                              <span class="f-label">{$t('gateway.routes.editor.accountTags')}</span>
                              <input type="text" class="cap-input mono" bind:value={rAccountTags} placeholder={$t('gateway.routes.editor.accountTagsPlaceholder')} />
                            </label>
                            <label class="check-opt">
                              <input type="checkbox" bind:checked={rRequireAccount} />
                              <span>{$t('gateway.routes.editor.requireAccount')}</span>
                            </label>
                          </div>

                          <div class="pool-bind-box">
                            <label class="f-block">
                              <span class="f-label">{$t('gateway.routes.editor.refreshRouteSlug')}</span>
                              <select class="cap-input mono" bind:value={rRefreshRouteSlug}>
                                <option value="">{$t('gateway.routes.editor.refreshRouteNone')}</option>
                                {#each refreshRouteCandidates as cand (cand.id)}
                                  <option value={cand.slug}>/gw/{cand.slug} — {cand.name || cand.slug}</option>
                                {/each}
                              </select>
                            </label>
                            <label class="check-opt">
                              <input type="checkbox" bind:checked={rAutoRefresh} />
                              <span>{$t('gateway.routes.editor.autoRefresh')}</span>
                            </label>
                          </div>
                        </div>

                        <!-- Clickable Account Template Variable Chips -->
                        <div class="tpl-bar">
                          <span class="tpl-label">{$t('gateway.routes.editor.accountVars')}</span>
                          <div class="seg-mini">
                            <button type="button" class="seg-mini-btn" class:active={templateTarget === 'url'} on:click={() => (templateTarget = 'url')}>
                              {$t('gateway.routes.editor.targetUrl')}
                            </button>
                            <button type="button" class="seg-mini-btn" class:active={templateTarget === 'body'} on:click={() => (templateTarget = 'body')}>
                              {$t('gateway.routes.editor.targetBody')}
                            </button>
                          </div>
                          <div class="tpl-chips">
                            {#each ACCOUNT_TEMPLATE_VARS as av}
                              <button type="button" class="tpl-chip mono" on:click={() => insertTemplateVar(av)}>
                                {av}
                              </button>
                            {/each}
                          </div>
                        </div>

                        <div class="grid-3">
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.refreshOnStatuses')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rRefreshOnStatuses}
                              placeholder={$t('gateway.routes.editor.refreshOnStatusesPlaceholder')}
                            />
                          </label>
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.refreshOnBodySubstr')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rRefreshOnBodySubstr}
                              placeholder={$t('gateway.routes.editor.refreshOnBodyPlaceholder')}
                            />
                          </label>
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.challengeWebhookUrl')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rChallengeWebhookUrl}
                              placeholder={$t('gateway.routes.editor.challengeWebhookPlaceholder')}
                            />
                          </label>
                        </div>
                      </div>
                    {/if}
                  </div>

                  <!-- Production Controls: TTL Cache & Circuit Breaker -->
                  <div class="form-card cap-card prod-card">
                    <button type="button" class="prod-head-btn" on:click={() => (openResilienceSection = !openResilienceSection)}>
                      <span class="prod-head-left">
                        <Icon name={openResilienceSection ? 'chevron-down' : 'chevron-right'} size={13} />
                        <Icon name="database" size={13} />
                        <span class="card-title">{$t('gateway.routes.editor.resilienceSection')}</span>
                      </span>
                      <span class="prod-head-badges">
                        {#if rCacheTtlSec > 0}
                          <Badge variant="info" size="xs" mono>
                            {$t('gateway.routes.badges.cache', { sec: rCacheTtlSec })}
                          </Badge>
                        {/if}
                        {#if currentRouteCircuit}
                          <Badge variant={circuitStateVariant(currentRouteCircuit.state)} size="xs" dot mono>
                            {$t(`gateway.routes.editor.circuitStates.${currentRouteCircuit.state || 'closed'}`)}
                          </Badge>
                        {/if}
                      </span>
                    </button>

                    {#if openResilienceSection}
                      <div class="prod-body">
                        <div class="grid-3">
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.cacheTtlSec')}</span>
                            <input
                              type="number"
                              min="0"
                              max="86400"
                              class="cap-input mono tabular-nums"
                              bind:value={rCacheTtlSec}
                              title={$t('gateway.routes.editor.cacheTtlHint')}
                            />
                          </label>
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.cacheKeyFields')}</span>
                            <input
                              type="text"
                              class="cap-input mono"
                              bind:value={rCacheKeyFields}
                              placeholder={$t('gateway.routes.editor.cacheKeyFieldsPlaceholder')}
                            />
                          </label>
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.cacheMaxEntries')}</span>
                            <input type="number" min="0" max="100000" class="cap-input mono tabular-nums" bind:value={rCacheMaxEntries} />
                          </label>
                        </div>

                        <div class="grid-3">
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.circuitFailThreshold')}</span>
                            <input
                              type="number"
                              min="0"
                              max="100"
                              class="cap-input mono tabular-nums"
                              bind:value={rCircuitFailThreshold}
                              title={$t('gateway.routes.editor.circuitFailHint')}
                            />
                          </label>
                          <label class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.circuitCooldownSec')}</span>
                            <input type="number" min="1" max="3600" class="cap-input mono tabular-nums" bind:value={rCircuitCooldownSec} />
                          </label>
                          <div class="f-block">
                            <span class="f-label">{$t('gateway.routes.editor.circuitStateLabel')}</span>
                            <div class="circuit-bar">
                              <Badge
                                variant={circuitStateVariant(currentRouteCircuit?.state || 'closed')}
                                size="xs"
                                dot
                                mono
                              >
                                {$t(`gateway.routes.editor.circuitStates.${currentRouteCircuit?.state || 'closed'}`)}
                              </Badge>
                              {#if currentRouteCircuit}
                                <span class="circuit-meta mono tabular-nums">
                                  {$t('gateway.routes.editor.circuitMeta', {
                                    fails: currentRouteCircuit.consecutive_failures || 0,
                                    trips: currentRouteCircuit.trip_count || 0,
                                  })}
                                </span>
                              {/if}
                            </div>
                          </div>
                        </div>

                        <div class="resilience-actions">
                          <Button
                            variant="secondary"
                            size="xs"
                            icon="trash"
                            loading={clearingCache}
                            disabled={isNewRoute || !activeRouteSlugKey}
                            on:click={handleClearRouteCache}
                          >
                            {$t('gateway.routes.editor.clearCache')}
                          </Button>
                          <Button
                            variant="secondary"
                            size="xs"
                            icon="refresh"
                            loading={resettingCircuit}
                            disabled={isNewRoute || !activeRouteSlugKey}
                            on:click={handleResetRouteCircuit}
                          >
                            {$t('gateway.routes.editor.resetCircuit')}
                          </Button>
                        </div>
                      </div>
                    {/if}
                  </div>
                </div>
              </div>

              <!-- Bottom: Live Test Console -->
              <div slot="secondary" class="tester-pane">
                <div class="tester-bar">
                  <div class="tester-bar-left">
                    <Icon name="zap" size={13} />
                    <span class="tester-title">{$t('gateway.routes.tester.title')}</span>
                    <select class="cap-input mini-select" bind:value={testDeviceId}>
                      <option value="">{$t('gateway.routes.tester.deviceOverride')}</option>
                      {#each devices as dev (dev.id)}
                        <option value={dev.id}>{dev.name} ({dev.kind})</option>
                      {/each}
                    </select>
                    <select class="cap-input mini-select" bind:value={testProxyId}>
                      <option value="">{$t('gateway.routes.tester.proxyOverride')}</option>
                      {#each proxies as p (p.id)}
                        <option value={p.id}>{p.name}{p.region ? ` [${p.region}]` : ''}</option>
                      {/each}
                    </select>
                    <select class="cap-input mini-select" bind:value={testAccountId}>
                      <option value="">{$t('gateway.routes.tester.accountOverride')}</option>
                      {#each accounts as acc (acc.id)}
                        <option value={acc.id}>{acc.name}{acc.username ? ` (${acc.username})` : ''}</option>
                      {/each}
                    </select>
                    <label class="check-opt compact">
                      <input type="checkbox" bind:checked={testBypassCache} />
                      <span>{$t('gateway.routes.tester.bypassCache')}</span>
                    </label>
                    <label class="check-opt compact">
                      <input type="checkbox" bind:checked={testRaw} />
                      <span>{$t('gateway.routes.tester.rawToggle')}</span>
                    </label>
                  </div>

                  <div class="tester-bar-right">
                    <Button variant="secondary" size="xs" icon="copy" disabled={!selectedRoute?.slug && !rSlug.trim()} on:click={copyRouteCurl}>
                      {$t('gateway.routes.tester.copyCurl')}
                    </Button>
                    <Button
                      variant="primary"
                      size="xs"
                      icon="send"
                      loading={testingRoute}
                      disabled={isNewRoute || !selectedRoute?.slug}
                      title={isNewRoute ? $t('gateway.routes.tester.saveFirstHint') : ''}
                      on:click={runRouteTest}
                    >
                      {testingRoute ? $t('gateway.routes.tester.running') : $t('gateway.routes.tester.runTest')}
                    </Button>
                  </div>
                </div>

                <div class="tester-split">
                  <!-- Test Request Inputs -->
                  <div class="tester-col">
                    <div class="mini-tabs">
                      <button type="button" class="mtab" class:active={testInputTab === 'input'} on:click={() => (testInputTab = 'input')}>
                        {$t('gateway.routes.tester.inputTab')}
                      </button>
                      <button type="button" class="mtab" class:active={testInputTab === 'body'} on:click={() => (testInputTab = 'body')}>
                        {$t('gateway.routes.tester.bodyTab')}
                      </button>
                      <button type="button" class="mtab" class:active={testInputTab === 'headers'} on:click={() => (testInputTab = 'headers')}>
                        {$t('gateway.routes.tester.headersTab')}
                      </button>
                    </div>
                    <div class="tester-area">
                      {#if testInputTab === 'input'}
                        <textarea class="code-box mono" bind:value={testInputJson} placeholder={$t('gateway.routes.tester.inputPlaceholder')}></textarea>
                      {:else if testInputTab === 'body'}
                        <textarea class="code-box mono" bind:value={testOverrideBody} placeholder={$t('gateway.routes.tester.bodyOverridePlaceholder')}></textarea>
                      {:else}
                        <textarea class="code-box mono" bind:value={testExtraHeaders} placeholder={$t('gateway.routes.tester.headersOverridePlaceholder')}></textarea>
                      {/if}
                    </div>
                  </div>

                  <!-- Live Test Output -->
                  <div class="tester-col border-l">
                    <div class="mini-tabs between">
                      <div class="inline-actions">
                        <button type="button" class="mtab" class:active={testRespTab === 'body'} on:click={() => (testRespTab = 'body')}>
                          {$t('gateway.routes.tester.respBodyTab')}
                        </button>
                        <button type="button" class="mtab" class:active={testRespTab === 'headers'} on:click={() => (testRespTab = 'headers')}>
                          {$t('gateway.routes.tester.respHeadersTab')}
                          {#if testResult?.headers}
                            <span class="tab-cnt mono">{Object.keys(testResult.headers).length}</span>
                          {/if}
                        </button>
                        <button type="button" class="mtab" class:active={testRespTab === 'signed'} on:click={() => (testRespTab = 'signed')}>
                          {$t('gateway.routes.tester.respSignedTab')}
                        </button>
                      </div>
                      {#if testResult?.body}
                        <button type="button" class="mini-link" on:click={() => copyToClipboard(testResult.body)}>
                          {$t('gateway.routes.tester.copyBody')}
                        </button>
                      {/if}
                    </div>

                    {#if testResult}
                      <div class="test-meta-strip mono tabular-nums">
                        <Badge status={testResult.status || 0} size="xs">{testResult.status || 'ERR'}</Badge>
                        <span>{$t('gateway.routes.tester.totalMs')}: <strong>{formatDuration(testResult.latency_ms)}</strong></span>
                        {#if testResult.signer_ms > 0}
                          <span class="accent-text">{$t('gateway.routes.tester.signerMs')}: {formatDuration(testResult.signer_ms)}</span>
                        {/if}
                        <span>{$t('gateway.routes.tester.proxyUsed')}: <strong>{testResult.proxy || $t('gateway.routes.tester.direct')}</strong></span>
                        <span>{$t('gateway.routes.tester.deviceUsed')}: <strong>{testResult.device || $t('gateway.routes.tester.none')}</strong></span>
                        {#if testResult.account}
                          <span>{$t('gateway.routes.tester.accountUsed')}: <strong>{testResult.account}</strong></span>
                        {/if}
                        {#if testResult.tls_profile}
                          <span>{$t('gateway.routes.tester.tlsUsed')}: <strong>{testResult.tls_profile}</strong></span>
                        {/if}
                        {#if testResult.cache_hit}
                          <Badge variant="info" size="xs" mono>{$t('gateway.logs.badges.hit')}</Badge>
                        {/if}
                        {#if testResult.circuit_tripped}
                          <Badge variant="danger" size="xs" mono>{$t('gateway.logs.badges.circuit')}</Badge>
                        {/if}
                        {#if testResult.refresh_triggered}
                          <Badge variant="warning" size="xs" mono>{$t('gateway.logs.badges.refresh')}</Badge>
                        {/if}
                        {#if testResult.retries > 0}
                          <Badge variant="warning" size="xs">{$t('gateway.routes.tester.retries', { count: testResult.retries })}</Badge>
                        {/if}
                      </div>

                      {#if testResult.error}
                        <div class="error-banner mono">
                          <Icon name="alert-circle" size={12} />
                          <span>{testResult.error}</span>
                        </div>
                      {/if}

                      <div class="tester-area scroll">
                        {#if testRespTab === 'body'}
                          <pre class="resp-pre mono">{formatPrettyBody(testResult.body, testResult.data)}</pre>
                        {:else if testRespTab === 'headers'}
                          <div class="kv-readout mono">
                            {#each Object.entries(testResult.headers || {}) as [hk, hv] (hk)}
                              <div class="kv-line">
                                <span class="kv-rk">{hk}</span>
                                <span class="kv-rv">{hv}</span>
                              </div>
                            {/each}
                          </div>
                        {:else}
                          <div class="signed-readout mono">
                            {#if testResult.upstream_url}
                              <div class="sr-block">
                                <div class="sr-title">{$t('gateway.routes.tester.upstreamUrl')}</div>
                                <div class="sr-val">{testResult.upstream_url}</div>
                              </div>
                            {/if}
                            {#if testResult.signed_params && Object.keys(testResult.signed_params).length > 0}
                              <div class="sr-block">
                                <div class="sr-title">{$t('gateway.routes.tester.signedParams')}</div>
                                {#each Object.entries(testResult.signed_params) as [pk, pv]}
                                  <div class="kv-line"><span class="kv-rk">{pk}</span><span class="kv-rv">{pv}</span></div>
                                {/each}
                              </div>
                            {/if}
                            {#if testResult.signed_headers && Object.keys(testResult.signed_headers).length > 0}
                              <div class="sr-block">
                                <div class="sr-title">{$t('gateway.routes.tester.signedHeaders')}</div>
                                {#each Object.entries(testResult.signed_headers) as [hk, hv]}
                                  <div class="kv-line"><span class="kv-rk">{hk}</span><span class="kv-rv">{hv}</span></div>
                                {/each}
                              </div>
                            {/if}
                            {#if !testResult.signed_params && !testResult.signed_headers}
                              <div class="empty-inline">{$t('gateway.routes.tester.noSignedFields')}</div>
                            {/if}
                          </div>
                        {/if}
                      </div>
                    {:else}
                      <div class="tester-empty">{$t('gateway.routes.tester.emptyResult')}</div>
                    {/if}
                  </div>
                </div>
              </div>
            </SplitPane>
          {:else}
            <EmptyState
              icon="link"
              title={$t('gateway.routes.noSelectionTitle')}
              description={$t('gateway.routes.noSelectionDesc')}
            >
              <Button variant="primary" size="sm" icon="plus" on:click={createNewRoute}>
                {$t('gateway.routes.newRoute')}
              </Button>
              <Button variant="secondary" size="sm" icon="activity" on:click={() => openFlowPicker()}>
                {$t('gateway.routes.fromFlow')}
              </Button>
            </EmptyState>
          {/if}
        </div>
      </SplitPane>

    <!-- ==================== SUB-TAB 2: PROXY IP POOL ==================== -->
    {:else if activeTab === 'proxies'}
      <div class="full-tab-shell">
        <!-- Policy & Dynamic Provider Strip -->
        <div class="pool-bars">
          <div class="pool-bar-row">
            <label class="inline-field">
              <span>{$t('gateway.proxies.strategy')}</span>
              <select class="cap-input" bind:value={proxyConfig.strategy}>
                {#each PROXY_STRATEGIES as st}
                  <option value={st}>{$t(`gateway.proxies.strategies.${st}`)}</option>
                {/each}
              </select>
            </label>

            <label class="inline-field flex-1">
              <span>{$t('gateway.proxies.healthCheckUrl')}</span>
              <input
                type="text"
                class="cap-input mono flex-1"
                bind:value={proxyConfig.health_check_url}
                placeholder={$t('gateway.proxies.healthCheckPlaceholder')}
              />
            </label>

            <label class="inline-field narrow-inline">
              <span>{$t('gateway.proxies.failoverRetries')}</span>
              <input type="number" min="0" max="10" class="cap-input mono tabular-nums" bind:value={proxyConfig.failover_retries} />
            </label>

            <label class="inline-field narrow-inline">
              <span>{$t('gateway.proxies.refreshSec')}</span>
              <input type="number" min="0" max="3600" class="cap-input mono tabular-nums" bind:value={proxyConfig.refresh_interval_sec} />
            </label>

            <Button variant="secondary" size="sm" icon="save" loading={savingProxyCfg} on:click={saveProxyPoolConfig}>
              {$t('gateway.proxies.saveConfig')}
            </Button>

            <Button variant="secondary" size="sm" icon="shield-check" loading={checkingProxies} on:click={handleCheckAllProxies}>
              {checkingProxies ? $t('gateway.proxies.checking') : $t('gateway.proxies.checkAll')}
            </Button>

            <Button
              variant="primary"
              size="sm"
              icon="plus"
              active={showProxyDrawer}
              on:click={() => {
                if (showProxyDrawer) showProxyDrawer = false
                else openAddProxyDrawer('single')
              }}
            >
              {$t('gateway.proxies.addBulk')}
            </Button>
          </div>

          <!-- Dynamic IP Provider Fetch Bar -->
          <div class="pool-bar-row provider-row">
            <span class="strip-tag">
              <Icon name="download" size={12} />
              <span>{$t('gateway.proxies.providerLabel')}</span>
            </span>
            <input
              type="text"
              class="cap-input mono flex-1"
              bind:value={proxyConfig.provider_url}
              placeholder={$t('gateway.proxies.providerUrlPlaceholder')}
            />
            <select class="cap-input format-select" bind:value={proxyConfig.provider_format}>
              <option value="lines">{$t('gateway.proxies.formatLines')}</option>
              <option value="json">{$t('gateway.proxies.formatJson')}</option>
            </select>
            {#if proxyConfig.provider_format === 'json'}
              <input
                type="text"
                class="cap-input mono path-input"
                bind:value={proxyConfig.provider_json_path}
                placeholder={$t('gateway.proxies.jsonPathPlaceholder')}
              />
            {/if}
            <Button
              variant="secondary"
              size="sm"
              icon="zap"
              loading={fetchingProxies}
              disabled={!proxyConfig.provider_url?.trim()}
              on:click={handleFetchProxiesFromProvider}
            >
              {fetchingProxies ? $t('gateway.proxies.fetching') : $t('gateway.proxies.fetchNow')}
            </Button>
          </div>
        </div>

        <!-- Collapsible Quick Add / Bulk Import Proxy Drawer -->
        {#if showProxyDrawer}
          <div class="inline-drawer cap-card">
            <div class="drawer-head">
              <div class="seg-mini">
                <button type="button" class="seg-mini-btn" class:active={proxyDrawerTab === 'single'} on:click={() => (proxyDrawerTab = 'single')}>
                  {$t('gateway.proxies.drawer.singleTab')}
                </button>
                <button type="button" class="seg-mini-btn" class:active={proxyDrawerTab === 'bulk'} on:click={() => (proxyDrawerTab = 'bulk')}>
                  {$t('gateway.proxies.drawer.bulkTab')}
                </button>
              </div>
              <Button variant="ghost" size="xs" icon="x" iconOnly on:click={() => (showProxyDrawer = false)} />
            </div>

            {#if proxyDrawerTab === 'single'}
              <div class="grid-3">
                <label class="f-block">
                  <span class="f-label">{$t('gateway.proxies.drawer.name')}</span>
                  <input type="text" class="cap-input" bind:value={pName} placeholder={$t('gateway.proxies.drawer.namePlaceholder')} />
                </label>
                <label class="f-block span-2">
                  <span class="f-label">{$t('gateway.proxies.drawer.url')}</span>
                  <input type="text" class="cap-input mono" bind:value={pUrl} placeholder={$t('gateway.proxies.drawer.urlPlaceholder')} />
                </label>
                <label class="f-block">
                  <span class="f-label">{$t('gateway.proxies.drawer.username')}</span>
                  <input type="text" class="cap-input mono" bind:value={pUsername} />
                </label>
                <label class="f-block">
                  <span class="f-label">{$t('gateway.proxies.drawer.password')}</span>
                  <input type="password" class="cap-input mono" bind:value={pPassword} />
                </label>
                <label class="f-block">
                  <span class="f-label">{$t('gateway.proxies.drawer.region')}</span>
                  <input type="text" class="cap-input mono" bind:value={pRegion} placeholder={$t('gateway.proxies.drawer.regionPlaceholder')} />
                </label>
                <label class="f-block span-2">
                  <span class="f-label">{$t('gateway.proxies.drawer.tags')}</span>
                  <input type="text" class="cap-input mono" bind:value={pTags} placeholder={$t('gateway.proxies.drawer.tagsPlaceholder')} />
                </label>
                <div class="drawer-inline-end">
                  <label class="check-opt">
                    <input type="checkbox" bind:checked={pEnabled} />
                    <span>{$t('gateway.proxies.drawer.enabled')}</span>
                  </label>
                  <Button variant="primary" size="sm" icon="save" loading={savingProxy} disabled={!pUrl.trim()} on:click={handleSaveSingleProxy}>
                    {pEditId ? $t('gateway.proxies.drawer.updateProxy') : $t('gateway.proxies.drawer.saveProxy')}
                  </Button>
                </div>
              </div>
            {:else}
              <div class="bulk-grid">
                <textarea
                  class="cap-textarea mono"
                  rows="5"
                  bind:value={bulkRawLines}
                  placeholder={$t('gateway.proxies.drawer.bulkPlaceholder')}
                ></textarea>
                <div class="bulk-opts">
                  <label class="f-block">
                    <span class="f-label">{$t('gateway.proxies.drawer.defaultScheme')}</span>
                    <select class="cap-input mono" bind:value={bulkDefaultScheme}>
                      <option value="http">http</option>
                      <option value="https">https</option>
                      <option value="socks5">socks5</option>
                      <option value="socks5h">socks5h</option>
                    </select>
                  </label>
                  <label class="f-block">
                    <span class="f-label">{$t('gateway.proxies.drawer.region')}</span>
                    <input type="text" class="cap-input mono" bind:value={bulkRegion} placeholder={$t('gateway.proxies.drawer.regionPlaceholder')} />
                  </label>
                  <label class="f-block">
                    <span class="f-label">{$t('gateway.proxies.drawer.tags')}</span>
                    <input type="text" class="cap-input mono" bind:value={bulkTags} placeholder={$t('gateway.proxies.drawer.tagsPlaceholder')} />
                  </label>
                  <Button variant="primary" size="sm" icon="upload" loading={importingProxies} disabled={!bulkRawLines.trim()} on:click={handleBulkImportProxies}>
                    {importingProxies ? $t('gateway.proxies.drawer.importing') : $t('gateway.proxies.drawer.bulkImportBtn')}
                  </Button>
                </div>
              </div>
            {/if}
          </div>
        {/if}

        <!-- Table Filter Bar -->
        <div class="table-filter-bar">
          <div class="search-box">
            <Icon name="search" size={12} />
            <input type="text" class="search-input" bind:value={proxySearch} placeholder={$t('gateway.proxies.filterSearch')} />
          </div>
          <div class="filter-pills">
            {#each ['all', 'healthy', 'unhealthy', 'disabled'] as pf}
              <button type="button" class="pill-btn" class:active={proxyStatusFilter === pf} on:click={() => (proxyStatusFilter = pf)}>
                {$t(`gateway.proxies.filter${pf.charAt(0).toUpperCase() + pf.slice(1)}`)}
              </button>
            {/each}
          </div>
        </div>

        <!-- Proxy Nodes Table -->
        <div class="table-wrap">
          {#if filteredProxies.length === 0}
            <EmptyState
              icon="globe"
              title={$t('gateway.proxies.emptyTitle')}
              description={$t('gateway.proxies.emptyDesc')}
            >
              <Button variant="primary" size="sm" icon="plus" on:click={() => openAddProxyDrawer('single')}>
                {$t('gateway.proxies.addBulk')}
              </Button>
            </EmptyState>
          {:else}
            <table class="data-table">
              <thead>
                <tr>
                  <th class="col-xs">{$t('gateway.proxies.cols.enabled')}</th>
                  <th>{$t('gateway.proxies.cols.endpoint')}</th>
                  <th>{$t('gateway.proxies.cols.region')}</th>
                  <th>{$t('gateway.proxies.cols.tags')}</th>
                  <th>{$t('gateway.proxies.cols.health')}</th>
                  <th class="num">{$t('gateway.proxies.cols.latency')}</th>
                  <th class="num">{$t('gateway.proxies.cols.stats')}</th>
                  <th>{$t('gateway.proxies.cols.lastError')}</th>
                  <th class="num">{$t('gateway.proxies.cols.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredProxies as n (n.id)}
                  {@const hm = proxyHealthMeta(n)}
                  <tr class:row-muted={!n.enabled}>
                    <td>
                      <label class="switch">
                        <input type="checkbox" checked={n.enabled} on:change={() => toggleProxyEnabled(n)} />
                        <span class="switch-track"></span>
                      </label>
                    </td>
                    <td>
                      <div class="proxy-ep">
                        <div class="proxy-name-row">
                          <span class="proxy-name">{n.name || n.id}</span>
                          {#if n.username}
                            <Badge variant="neutral" size="xs" mono>{$t('gateway.proxies.authTag')}</Badge>
                          {/if}
                        </div>
                        <div class="proxy-url mono truncate" title={redactProxyURL(n.url)}>{redactProxyURL(n.url)}</div>
                      </div>
                    </td>
                    <td>
                      {#if n.region}
                        <Badge variant="info" size="xs" mono>{n.region}</Badge>
                      {:else}
                        <span class="muted">—</span>
                      {/if}
                    </td>
                    <td>
                      <div class="tag-cell">
                        {#each n.tags || [] as tg}
                          <Badge variant="neutral" size="xs" mono>{tg}</Badge>
                        {/each}
                      </div>
                    </td>
                    <td>
                      <Badge variant={hm.variant} size="xs" dot>{hm.label}</Badge>
                    </td>
                    <td class="num mono tabular-nums">
                      {n.latency_ms > 0 ? `${n.latency_ms}ms` : '—'}
                    </td>
                    <td class="num mono tabular-nums">
                      <span class="ok-cnt">{n.success_count || 0}</span>
                      <span class="muted"> / </span>
                      <span class:err-cnt={n.fail_count > 0}>{n.fail_count || 0}</span>
                    </td>
                    <td>
                      {#if n.last_error}
                        <span class="err-text mono truncate" title={n.last_error}>{n.last_error}</span>
                      {:else}
                        <span class="muted">—</span>
                      {/if}
                    </td>
                    <td class="num">
                      <div class="row-actions">
                        <Button variant="ghost" size="xs" icon="edit" iconOnly on:click={() => editProxyNode(n)} />
                        <Button variant="ghost" size="xs" icon="trash" iconOnly on:click={() => deleteProxyNode(n.id)} />
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      </div>

    <!-- ==================== SUB-TAB 3: DEVICE POOL & FINGERPRINTS ==================== -->
    {:else if activeTab === 'devices'}
      <div class="full-tab-shell">
        <!-- Device Pool Top Bar -->
        <div class="pool-bar-row device-topbar">
          <div class="search-box">
            <Icon name="search" size={12} />
            <input type="text" class="search-input" bind:value={deviceSearch} placeholder={$t('gateway.devices.searchPlaceholder')} />
          </div>

          <div class="filter-pills">
            {#each ['all', 'virtual', 'physical'] as kf}
              <button type="button" class="pill-btn" class:active={deviceKindFilter === kf} on:click={() => (deviceKindFilter = kf)}>
                {kf === 'all' ? $t('gateway.devices.allKinds') : $t(`gateway.devices.${kf}`)}
              </button>
            {/each}
          </div>

          <div class="ctrl-spacer"></div>

          <!-- + From Preset Dropdown -->
          <div class="preset-wrap">
            <Button
              variant="secondary"
              size="sm"
              icon="sparkles"
              iconRight="chevron-down"
              active={showPresetMenu}
              on:click={() => (showPresetMenu = !showPresetMenu)}
            >
              + {$t('gateway.devices.fromPreset')}
            </Button>
            {#if showPresetMenu}
              <div class="preset-popover cap-card">
                <label class="f-block">
                  <span class="f-label">{$t('gateway.devices.choosePreset')}</span>
                  <select class="cap-input" bind:value={selectedPresetId}>
                    {#each devicePresets as pr (pr.id)}
                      <option value={pr.id}>{pr.name} ({pr.fingerprint?.model} · Android {pr.fingerprint?.os_version})</option>
                    {/each}
                  </select>
                </label>
                <label class="f-block">
                  <span class="f-label">{$t('gateway.devices.presetCustomName')}</span>
                  <input type="text" class="cap-input" bind:value={presetCustomName} placeholder={$t('gateway.devices.editor.namePlaceholder')} />
                </label>
                <div class="inline-actions end">
                  <Button variant="ghost" size="xs" on:click={() => (showPresetMenu = false)}>
                    <Icon name="x" size={12} />
                  </Button>
                  <Button variant="primary" size="xs" icon="plus" loading={creatingPreset} disabled={!selectedPresetId} on:click={handleCreateDeviceFromPreset}>
                    {$t('gateway.devices.createFromPreset')}
                  </Button>
                </div>
              </div>
            {/if}
          </div>

          <Button variant="secondary" size="sm" icon="usb" loading={syncingAdb} on:click={handleSyncAdbDevices}>
            {syncingAdb ? $t('gateway.devices.syncing') : $t('gateway.devices.syncAdb')}
          </Button>

          <Button variant="primary" size="sm" icon="plus" on:click={createNewVirtualDevice}>
            {$t('gateway.devices.newVirtual')}
          </Button>
        </div>

        <!-- Devices Horizontal SplitPane -->
        <div class="split-fill">
          <SplitPane direction="horizontal" initialSize={32} minPrimary={22} minSecondary={50} storageKey="cap.gateway.devices.hsplit">
            <div slot="primary" class="list-pane">
              <div class="list-scroll">
                {#if filteredDevices.length === 0}
                  <EmptyState
                    icon="smartphone"
                    title={$t('gateway.devices.emptyTitle')}
                    description={$t('gateway.devices.emptyDesc')}
                    compact
                  />
                {:else}
                  {#each filteredDevices as dev (dev.id)}
                    <button
                      type="button"
                      class="entity-card"
                      class:active={selectedDevice?.id === dev.id && !isNewDevice}
                      class:disabled-card={!dev.enabled}
                      on:click={() => selectDevice(dev)}
                    >
                      <div class="ec-top">
                        <span class="status-dot" class:on={dev.enabled}></span>
                        <Badge variant={dev.kind === 'physical' ? 'info' : 'purple'} size="xs">
                          {$t(`gateway.devices.${dev.kind === 'physical' ? 'physical' : 'virtual'}`)}
                        </Badge>
                        <span class="ec-usage mono tabular-nums">
                          {$t('gateway.devices.usesCount', { count: dev.in_use_count || 0 })}
                        </span>
                      </div>
                      <div class="ec-name truncate">{dev.name}</div>
                      <div class="ec-sub mono truncate">
                        {dev.fingerprint?.brand || ''} {dev.fingerprint?.model || 'Android'} · OS {dev.fingerprint?.os_version || '?'} / SDK {dev.fingerprint?.sdk || '?'}
                      </div>
                      <div class="ec-chips">
                        {#if dev.sticky_proxy_id}
                          <Badge variant="success" size="xs" mono>
                            {$t('gateway.devices.stickyBadge', { name: proxyNameById[dev.sticky_proxy_id] || dev.sticky_proxy_id })}
                          </Badge>
                        {/if}
                        {#if dev.adb_serial}
                          <Badge variant="neutral" size="xs" mono>{dev.adb_serial}</Badge>
                        {/if}
                        {#each dev.tags || [] as tg}
                          <Badge variant="neutral" size="xs" mono>{tg}</Badge>
                        {/each}
                      </div>
                    </button>
                  {/each}
                {/if}
              </div>
            </div>

            <div slot="secondary" class="detail-pane">
              {#if selectedDevice || isNewDevice}
                <div class="editor-shell">
                  <div class="editor-topbar">
                    <div class="editor-head-left">
                      <Badge variant={dKind === 'physical' ? 'info' : 'purple'} size="sm">
                        {$t(`gateway.devices.${dKind === 'physical' ? 'physical' : 'virtual'}`)}
                      </Badge>
                      <span class="editor-title truncate">{isNewDevice ? $t('gateway.devices.editor.newTitle') : dName || selectedDevice?.id}</span>
                    </div>
                    <div class="editor-head-actions">
                      <label class="inline-switch">
                        <span>{dEnabled ? $t('gateway.routes.editor.enabled') : $t('gateway.routes.editor.disabled')}</span>
                        <span class="switch">
                          <input type="checkbox" bind:checked={dEnabled} />
                          <span class="switch-track"></span>
                        </span>
                      </label>
                      {#if selectedDevice && !isNewDevice}
                        {#if confirmDeleteDeviceId === selectedDevice.id}
                          <Button variant="danger" size="xs" icon="trash" on:click={() => deleteCurrentDevice(selectedDevice.id)}>
                            {$t('gateway.devices.editor.confirmDelete')}
                          </Button>
                          <Button variant="ghost" size="xs" on:click={() => (confirmDeleteDeviceId = null)}>
                            <Icon name="x" size={12} />
                          </Button>
                        {:else}
                          <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDeleteDeviceId = selectedDevice.id)}>
                            {$t('gateway.devices.editor.delete')}
                          </Button>
                        {/if}
                      {/if}
                      <Button variant="primary" size="xs" icon="save" loading={savingDevice} on:click={saveCurrentDevice}>
                        {$t('gateway.devices.editor.save')}
                      </Button>
                    </div>
                  </div>

                  <div class="editor-scroll">
                    <!-- Identity & Proxy Affinity -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.devices.editor.sectionIdentity')}</span>
                        {#if selectedDevice && !isNewDevice}
                          <span class="card-hint mono">
                            {$t('gateway.devices.editor.metaUsage', {
                              count: selectedDevice.in_use_count || 0,
                              last: selectedDevice.last_used_at ? formatTime(selectedDevice.last_used_at) : '—',
                            })}
                          </span>
                        {/if}
                      </div>

                      <div class="grid-3">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.name')}</span>
                          <input type="text" class="cap-input" bind:value={dName} placeholder={$t('gateway.devices.editor.namePlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.kind')}</span>
                          <select class="cap-input" bind:value={dKind}>
                            <option value="virtual">{$t('gateway.devices.virtual')}</option>
                            <option value="physical">{$t('gateway.devices.physical')}</option>
                          </select>
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.adbSerial')}</span>
                          <input type="text" class="cap-input mono" bind:value={dAdbSerial} placeholder={$t('gateway.devices.editor.adbSerialPlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.tags')}</span>
                          <input type="text" class="cap-input mono" bind:value={dTags} placeholder={$t('gateway.devices.editor.tagsPlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.stickyProxy')}</span>
                          <select class="cap-input mono" bind:value={dStickyProxyId}>
                            <option value="">{$t('gateway.devices.editor.stickyProxyNone')}</option>
                            {#each proxies as p (p.id)}
                              <option value={p.id}>{p.name}{p.region ? ` [${p.region}]` : ''} ({redactProxyURL(p.url)})</option>
                            {/each}
                          </select>
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.proxyRegion')}</span>
                          <input type="text" class="cap-input mono" bind:value={dProxyRegion} placeholder={$t('gateway.devices.editor.proxyRegionPlaceholder')} />
                        </label>
                      </div>
                    </div>

                    <!-- Fingerprint Attributes -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.devices.editor.sectionFingerprint')}</span>
                        <Button variant="secondary" size="xs" icon="refresh" on:click={randomizeDeviceIds}>
                          {$t('gateway.devices.editor.randomizeIds')}
                        </Button>
                      </div>

                      <div class="grid-4">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.brand')}</span>
                          <input type="text" class="cap-input" bind:value={dBrand} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.model')}</span>
                          <input type="text" class="cap-input mono" bind:value={dModel} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.osVersion')}</span>
                          <input type="text" class="cap-input mono" bind:value={dOsVersion} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.sdk')}</span>
                          <input type="number" min="21" max="40" class="cap-input mono tabular-nums" bind:value={dSdk} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.screen')}</span>
                          <input type="text" class="cap-input mono" bind:value={dScreen} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.locale')}</span>
                          <input type="text" class="cap-input mono" bind:value={dLocale} />
                        </label>
                        <label class="f-block span-2">
                          <span class="f-label">{$t('gateway.devices.editor.timezone')}</span>
                          <input type="text" class="cap-input mono" bind:value={dTimezone} />
                        </label>
                      </div>

                      <div class="grid-3">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.deviceId')}</span>
                          <input type="text" class="cap-input mono" bind:value={dDeviceId} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.androidId')}</span>
                          <input type="text" class="cap-input mono" bind:value={dAndroidId} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.devices.editor.oaid')}</span>
                          <input type="text" class="cap-input mono" bind:value={dOaid} />
                        </label>
                      </div>

                      <label class="f-block">
                        <span class="f-label">{$t('gateway.devices.editor.userAgent')}</span>
                        <input type="text" class="cap-input mono" bind:value={dUserAgent} />
                      </label>

                      <div class="kv-section">
                        <div class="label-row">
                          <span class="f-label">{$t('gateway.devices.editor.extraHeaders')}</span>
                          <button type="button" class="mini-link" on:click={() => (dExtraHeaders = [...dExtraHeaders, { key: '', value: '' }])}>
                            + {$t('gateway.routes.editor.addPair')}
                          </button>
                        </div>
                        {#each dExtraHeaders as row, idx (idx)}
                          <div class="kv-edit-row">
                            <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="X-Device-Header" />
                            <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="value" />
                            <button type="button" class="row-del" on:click={() => (dExtraHeaders = dExtraHeaders.filter((_, i) => i !== idx))}>
                              <Icon name="x" size={12} />
                            </button>
                          </div>
                        {/each}
                      </div>
                    </div>

                    <!-- Session State KV Editors -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.devices.editor.sectionSession')}</span>
                      </div>

                      <div class="grid-3-stack">
                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.devices.editor.cookies')}</span>
                            <button type="button" class="mini-link" on:click={() => (dCookies = [...dCookies, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each dCookies as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="sessionid" />
                              <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="value" />
                              <button type="button" class="row-del" on:click={() => (dCookies = dCookies.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>

                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.devices.editor.authHeaders')}</span>
                            <button type="button" class="mini-link" on:click={() => (dAuthHeaders = [...dAuthHeaders, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each dAuthHeaders as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="Authorization" />
                              <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="Bearer ..." />
                              <button type="button" class="row-del" on:click={() => (dAuthHeaders = dAuthHeaders.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>

                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.devices.editor.tokens')}</span>
                            <button type="button" class="mini-link" on:click={() => (dTokens = [...dTokens, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each dTokens as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="access_token" />
                              <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="token value" />
                              <button type="button" class="row-del" on:click={() => (dTokens = dTokens.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              {:else}
                <EmptyState
                  icon="smartphone"
                  title={$t('gateway.devices.noSelectionTitle')}
                  description={$t('gateway.devices.noSelectionDesc')}
                >
                  <Button variant="primary" size="sm" icon="plus" on:click={createNewVirtualDevice}>
                    {$t('gateway.devices.newVirtual')}
                  </Button>
                </EmptyState>
              {/if}
            </div>
          </SplitPane>
        </div>
      </div>

    <!-- ==================== SUB-TAB 4: SIGNER PROVIDERS ==================== -->
    {:else if activeTab === 'signers'}
      <SplitPane direction="horizontal" initialSize={28} minPrimary={22} minSecondary={54} storageKey="cap.gateway.signers.hsplit">
        <!-- Left: Signers List -->
        <div slot="primary" class="list-pane">
          <div class="pane-toolbar">
            <div class="search-box">
              <Icon name="search" size={12} />
              <input type="text" class="search-input" bind:value={signerSearch} placeholder={$t('gateway.signers.searchPlaceholder')} />
            </div>
            <Button variant="primary" size="xs" icon="plus" on:click={createNewSigner}>
              {$t('gateway.signers.newSigner')}
            </Button>
          </div>

          <div class="list-scroll">
            {#if filteredSigners.length === 0}
              <EmptyState
                icon="key"
                title={$t('gateway.signers.emptyTitle')}
                description={$t('gateway.signers.emptyDesc')}
                compact
              >
                <Button variant="primary" size="xs" icon="plus" on:click={createNewSigner}>
                  {$t('gateway.signers.newSigner')}
                </Button>
              </EmptyState>
            {:else}
              {#each filteredSigners as sg (sg.id)}
                <button
                  type="button"
                  class="entity-card"
                  class:active={selectedSigner?.id === sg.id && !isNewSigner}
                  class:disabled-card={!sg.enabled}
                  on:click={() => selectSigner(sg)}
                >
                  <div class="ec-top">
                    <span class="status-dot" class:on={sg.enabled}></span>
                    <Badge variant={signerKindVariant(sg.kind)} size="xs" mono>{sg.kind}</Badge>
                    <span class="ec-usage mono">{sg.inject_target || 'query'}:{sg.inject_field || 'sign'}</span>
                  </div>
                  <div class="ec-name truncate">{sg.name}</div>
                  {#if sg.description}
                    <div class="ec-sub truncate">{sg.description}</div>
                  {/if}
                  {#if sg.worker_pool_id}
                    <div class="ec-chips">
                      <Badge variant="accent" size="xs" mono>
                        {$t('gateway.signers.editor.workerPoolBadge', { name: workerNameById[sg.worker_pool_id] || sg.worker_pool_id })}
                      </Badge>
                    </div>
                  {/if}
                </button>
              {/each}
            {/if}
          </div>
        </div>

        <!-- Right: Adaptive Signer Editor + Inline Test Runner -->
        <div slot="secondary" class="detail-pane">
          {#if selectedSigner || isNewSigner}
            <div class="editor-shell">
              <div class="editor-topbar">
                <div class="editor-head-left">
                  <Badge variant={signerKindVariant(sKind)} size="sm" mono>{sKind}</Badge>
                  <span class="editor-title truncate">{isNewSigner ? $t('gateway.signers.editor.newTitle') : sName || selectedSigner?.id}</span>
                </div>
                <div class="editor-head-actions">
                  <label class="inline-switch">
                    <span>{sEnabled ? $t('gateway.routes.editor.enabled') : $t('gateway.routes.editor.disabled')}</span>
                    <span class="switch">
                      <input type="checkbox" bind:checked={sEnabled} />
                      <span class="switch-track"></span>
                    </span>
                  </label>
                  {#if selectedSigner && !isNewSigner}
                    {#if confirmDeleteSignerId === selectedSigner.id}
                      <Button variant="danger" size="xs" icon="trash" on:click={() => deleteCurrentSigner(selectedSigner.id)}>
                        {$t('gateway.signers.editor.confirmDelete')}
                      </Button>
                      <Button variant="ghost" size="xs" on:click={() => (confirmDeleteSignerId = null)}>
                        <Icon name="x" size={12} />
                      </Button>
                    {:else}
                      <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDeleteSignerId = selectedSigner.id)}>
                        {$t('gateway.signers.editor.delete')}
                      </Button>
                    {/if}
                  {/if}
                  <Button variant="primary" size="xs" icon="save" loading={savingSigner} on:click={saveCurrentSigner}>
                    {$t('gateway.signers.editor.save')}
                  </Button>
                </div>
              </div>

              <div class="editor-scroll">
                <!-- Core & Kind Selector Card -->
                <div class="form-card cap-card">
                  <div class="grid-2">
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.editor.name')}</span>
                      <input type="text" class="cap-input" bind:value={sName} placeholder={$t('gateway.signers.editor.namePlaceholder')} />
                    </label>
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.editor.description')}</span>
                      <input type="text" class="cap-input" bind:value={sDescription} placeholder={$t('gateway.signers.editor.descriptionPlaceholder')} />
                    </label>
                  </div>

                  <div class="f-block">
                    <span class="f-label">{$t('gateway.signers.editor.kind')}</span>
                    <div class="kind-tiles">
                      {#each SIGNER_KINDS as k}
                        <button
                          type="button"
                          class="kind-tile"
                          class:active={sKind === k}
                          on:click={() => selectSignerKind(k)}
                        >
                          <span class="kt-title">{$t(`gateway.signers.kinds.${k}`)}</span>
                          <span class="kt-code mono">{k}</span>
                        </button>
                      {/each}
                    </div>
                  </div>

                  <!-- Adaptive Kind Configuration -->
                  {#if sKind === 'builtin_hmac'}
                    <div class="grid-2">
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.hmacAlgo')}</span>
                        <select class="cap-input mono" bind:value={sHmacAlgo}>
                          {#each HMAC_ALGORITHMS as alg}
                            <option value={alg}>{alg}</option>
                          {/each}
                        </select>
                      </label>
                      <div class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.hmacSecret')}</span>
                        <div class="secret-wrap">
                          {#if sShowSecret}
                            <input type="text" class="cap-input mono flex-1" bind:value={sHmacSecret} placeholder={$t('gateway.signers.editor.hmacSecretPlaceholder')} />
                          {:else}
                            <input type="password" class="cap-input mono flex-1" bind:value={sHmacSecret} placeholder={$t('gateway.signers.editor.hmacSecretPlaceholder')} />
                          {/if}
                          <Button variant="ghost" size="xs" icon={sShowSecret ? 'eye-off' : 'eye'} iconOnly on:click={() => (sShowSecret = !sShowSecret)} />
                        </div>
                      </div>
                    </div>

                  {:else if sKind === 'script'}
                    <div class="script-meta-row">
                      <label class="inline-field">
                        <span>{$t('gateway.signers.editor.runtime')}</span>
                        <select class="cap-input mono" bind:value={sRuntime}>
                          {#each SCRIPT_RUNTIMES as rt}
                            <option value={rt}>{rt}</option>
                          {/each}
                        </select>
                      </label>
                      <label class="inline-field narrow-inline">
                        <span>{$t('gateway.signers.editor.timeoutSec')}</span>
                        <input type="number" min="1" max="60" class="cap-input mono tabular-nums" bind:value={sTimeoutSec} />
                      </label>
                      <div class="ctrl-spacer"></div>
                      <Button variant="secondary" size="xs" icon="file-code" on:click={loadStarterScript}>
                        {$t('gateway.signers.editor.loadStarter')}
                      </Button>
                    </div>
                    <div class="f-hint">{$t('gateway.signers.editor.scriptHint')}</div>
                    <div class="signer-editor-host">
                      <CodeEditor
                        bind:this={signerEditorRef}
                        bind:value={sScriptCode}
                        runtime={sRuntime}
                        minHeight="210px"
                        on:save={saveCurrentSigner}
                        on:run={handleTestSigner}
                      />
                    </div>

                  {:else if sKind === 'http' || sKind === 'unidbg_http'}
                    <div class="pool-bind-box">
                      <div class="label-row">
                        <span class="f-label">{$t('gateway.signers.editor.workerPool')}</span>
                        <button type="button" class="mini-link" on:click={() => { activeTab = 'workers'; loadWorkersAndStatuses() }}>
                          {$t('gateway.signers.editor.manageWorkers')} →
                        </button>
                      </div>
                      <select class="cap-input mono" bind:value={sWorkerPoolId}>
                        <option value="">{$t('gateway.signers.editor.workerPoolNone')}</option>
                        {#each workers as w (w.id)}
                          {@const ws = workerStatusById[w.id]}
                          <option value={w.id}>
                            [{w.kind}] {w.name} ({ws?.healthy_instances ?? ws?.healthy_count ?? 0}/{ws?.total_instances ?? ws?.total_count ?? w.instances ?? 1})
                          </option>
                        {/each}
                      </select>
                      <div class="f-hint">{$t('gateway.signers.editor.workerPoolHint')}</div>
                    </div>

                    <div class="method-url-row">
                      <label class="f-block method-col">
                        <span class="f-label">{$t('gateway.signers.editor.httpMethod')}</span>
                        <select class="cap-input mono" bind:value={sHttpMethod}>
                          <option value="POST">POST</option>
                          <option value="GET">GET</option>
                          <option value="PUT">PUT</option>
                        </select>
                      </label>
                      <label class="f-block flex-1">
                        <span class="f-label">{$t('gateway.signers.editor.endpointUrl')}</span>
                        <input type="text" class="cap-input mono" bind:value={sEndpointUrl} placeholder={$t('gateway.signers.editor.endpointPlaceholder')} />
                      </label>
                      <label class="f-block narrow-col">
                        <span class="f-label">{$t('gateway.signers.editor.timeoutSec')}</span>
                        <input type="number" min="1" max="60" class="cap-input mono tabular-nums" bind:value={sTimeoutSec} />
                      </label>
                    </div>

                    <div class="kv-section">
                      <div class="label-row">
                        <span class="f-label">{$t('gateway.signers.editor.requestHeaders')}</span>
                        <button type="button" class="mini-link" on:click={() => (sHeaders = [...sHeaders, { key: '', value: '' }])}>
                          + {$t('gateway.routes.editor.addPair')}
                        </button>
                      </div>
                      {#each sHeaders as row, idx (idx)}
                        <div class="kv-edit-row">
                          <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="Authorization" />
                          <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="Bearer ..." />
                          <button type="button" class="row-del" on:click={() => (sHeaders = sHeaders.filter((_, i) => i !== idx))}>
                            <Icon name="x" size={12} />
                          </button>
                        </div>
                      {/each}
                    </div>

                  {:else if sKind === 'frida_rpc'}
                    <div class="grid-4">
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.fridaSerial')}</span>
                        <input
                          type="text"
                          list="gw-adb-serials"
                          class="cap-input mono"
                          bind:value={sFridaSerial}
                          placeholder={$t('gateway.signers.editor.fridaSerialPlaceholder')}
                        />
                        <datalist id="gw-adb-serials">
                          {#each devices.filter((d) => d.adb_serial) as dev (dev.id)}
                            <option value={dev.adb_serial}>{dev.name}</option>
                          {/each}
                        </datalist>
                      </label>
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.fridaPackage')}</span>
                        <input type="text" class="cap-input mono" bind:value={sFridaPackage} placeholder={$t('gateway.signers.editor.fridaPackagePlaceholder')} />
                      </label>
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.fridaExport')}</span>
                        <input type="text" class="cap-input mono" bind:value={sFridaExport} placeholder={$t('gateway.signers.editor.fridaExportPlaceholder')} />
                      </label>
                      <label class="f-block">
                        <span class="f-label">{$t('gateway.signers.editor.timeoutSec')}</span>
                        <input type="number" min="1" max="60" class="cap-input mono tabular-nums" bind:value={sTimeoutSec} />
                      </label>
                    </div>

                    <div class="script-meta-row">
                      <span class="f-label">{$t('gateway.signers.editor.fridaScriptLabel')}</span>
                      <div class="ctrl-spacer"></div>
                      <Button variant="secondary" size="xs" icon="file-code" on:click={loadFridaStarterScript}>
                        {$t('gateway.signers.editor.loadFridaStarter')}
                      </Button>
                    </div>
                    <div class="f-hint">{$t('gateway.signers.editor.fridaScriptHint')}</div>
                    <div class="signer-editor-host">
                      <CodeEditor
                        bind:this={signerEditorRef}
                        bind:value={sScriptCode}
                        runtime="node"
                        minHeight="210px"
                        on:save={saveCurrentSigner}
                        on:run={handleTestSigner}
                      />
                    </div>
                  {/if}
                </div>

                <!-- Injection & Output Mapping Card -->
                <div class="form-card cap-card">
                  <div class="card-head">
                    <span class="card-title">{$t('gateway.signers.editor.sectionInjection')}</span>
                  </div>

                  <div class="grid-2">
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.editor.injectTarget')}</span>
                      <select class="cap-input" bind:value={sInjectTarget}>
                        {#each INJECT_TARGETS as it}
                          <option value={it}>{$t(`gateway.signers.editor.injectTargets.${it}`)}</option>
                        {/each}
                      </select>
                    </label>
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.editor.injectField')}</span>
                      <input type="text" class="cap-input mono" bind:value={sInjectField} placeholder={$t('gateway.signers.editor.injectFieldPlaceholder')} />
                    </label>
                  </div>

                  {#if sKind !== 'builtin_hmac'}
                    <div class="kv-section">
                      <div class="label-row">
                        <div>
                          <span class="f-label">{$t('gateway.signers.editor.outputMapping')}</span>
                          <span class="f-hint inline-hint">{$t('gateway.signers.editor.outputMappingHint')}</span>
                        </div>
                        <button type="button" class="mini-link" on:click={() => (sOutputMapping = [...sOutputMapping, { key: '', value: '' }])}>
                          + {$t('gateway.routes.editor.addPair')}
                        </button>
                      </div>
                      {#each sOutputMapping as row, idx (idx)}
                        <div class="kv-edit-row">
                          <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder={$t('gateway.signers.editor.outputSrcPlaceholder')} />
                          <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder={$t('gateway.signers.editor.outputDestPlaceholder')} />
                          <button type="button" class="row-del" on:click={() => (sOutputMapping = sOutputMapping.filter((_, i) => i !== idx))}>
                            <Icon name="x" size={12} />
                          </button>
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>

                <!-- Inline Signer Test Runner -->
                <div class="form-card cap-card">
                  <div class="card-head">
                    <span class="card-title">{$t('gateway.signers.tester.title')}</span>
                    <Button variant="primary" size="xs" icon="play" loading={testingSigner} on:click={handleTestSigner}>
                      {testingSigner ? $t('gateway.signers.tester.running') : $t('gateway.signers.tester.run')}
                    </Button>
                  </div>

                  <div class="method-url-row">
                    <label class="f-block method-col">
                      <span class="f-label">{$t('gateway.signers.tester.method')}</span>
                      <select class="cap-input mono" bind:value={sTestMethod}>
                        {#each HTTP_METHODS as m}
                          <option value={m}>{m}</option>
                        {/each}
                      </select>
                    </label>
                    <label class="f-block flex-1">
                      <span class="f-label">{$t('gateway.signers.tester.url')}</span>
                      <input type="text" class="cap-input mono" bind:value={sTestUrl} />
                    </label>
                  </div>

                  <div class="grid-2">
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.tester.queryJson')}</span>
                      <textarea class="cap-textarea mono" rows="3" bind:value={sTestQueryJson}></textarea>
                    </label>
                    <label class="f-block">
                      <span class="f-label">{$t('gateway.signers.tester.body')}</span>
                      <textarea class="cap-textarea mono" rows="3" bind:value={sTestBody} placeholder={'{"keyword":"cap"}'}></textarea>
                    </label>
                  </div>

                  {#if signerTestError}
                    <div class="error-banner mono">
                      <Icon name="alert-circle" size={12} />
                      <span class="flex-1">{signerTestError}</span>
                      <Button
                        variant="secondary"
                        size="xs"
                        icon="sparkles"
                        title={$t('gateway.signers.tester.aiFixTitle')}
                        on:click={openSignerAIHeal}
                      >
                        {$t('gateway.signers.tester.aiFixBtn')}
                      </Button>
                    </div>
                  {/if}

                  {#if signerTestResult}
                    <div class="signer-result-box">
                      <div class="sr-head">
                        <span class="f-label">{$t('gateway.signers.tester.resultTitle')}</span>
                        <div class="inline-actions">
                          <Badge variant="success" size="xs" mono>{formatDuration(signerTestResult.latency_ms)}</Badge>
                          {#if signerTestResult.sign}
                            <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(signerTestResult.sign)}>
                              {$t('gateway.signers.tester.copySign')}
                            </Button>
                          {/if}
                        </div>
                      </div>

                      {#if signerTestResult.sign}
                        <div class="kv-line mono">
                          <span class="kv-rk">{$t('gateway.signers.tester.primarySign')}</span>
                          <span class="kv-rv accent-text">{signerTestResult.sign}</span>
                        </div>
                      {/if}
                      {#if signerTestResult.params && Object.keys(signerTestResult.params).length > 0}
                        <div class="kv-line mono">
                          <span class="kv-rk">{$t('gateway.signers.tester.params')}</span>
                          <span class="kv-rv">{JSON.stringify(signerTestResult.params)}</span>
                        </div>
                      {/if}
                      {#if signerTestResult.headers && Object.keys(signerTestResult.headers).length > 0}
                        <div class="kv-line mono">
                          <span class="kv-rk">{$t('gateway.signers.tester.headers')}</span>
                          <span class="kv-rv">{JSON.stringify(signerTestResult.headers)}</span>
                        </div>
                      {/if}
                      {#if signerTestResult.body_fields && Object.keys(signerTestResult.body_fields).length > 0}
                        <div class="kv-line mono">
                          <span class="kv-rk">{$t('gateway.signers.tester.bodyFields')}</span>
                          <span class="kv-rv">{JSON.stringify(signerTestResult.body_fields)}</span>
                        </div>
                      {/if}
                      {#if signerTestResult.raw}
                        <pre class="resp-pre compact mono">{JSON.stringify(signerTestResult.raw, null, 2)}</pre>
                      {/if}
                    </div>
                  {/if}
                </div>
              </div>
            </div>
          {:else}
            <EmptyState
              icon="key"
              title={$t('gateway.signers.noSelectionTitle')}
              description={$t('gateway.signers.noSelectionDesc')}
            >
              <Button variant="primary" size="sm" icon="plus" on:click={createNewSigner}>
                {$t('gateway.signers.newSigner')}
              </Button>
            </EmptyState>
          {/if}
        </div>
      </SplitPane>

    <!-- ==================== SUB-TAB 5: LIVE GATEWAY LOGS ==================== -->
    {:else if activeTab === 'logs'}
      <div class="full-tab-shell">
        <div class="table-filter-bar">
          <select class="cap-input route-filter-select mono" bind:value={logRouteFilter}>
            <option value="all">{$t('gateway.logs.allRoutes')}</option>
            {#each logRouteSlugs as sl (sl)}
              <option value={sl}>/gw/{sl}</option>
            {/each}
          </select>

          <div class="filter-pills">
            <button type="button" class="pill-btn" class:active={logStatusFilter === 'all'} on:click={() => (logStatusFilter = 'all')}>
              {$t('gateway.logs.allStatuses')}
            </button>
            <button type="button" class="pill-btn" class:active={logStatusFilter === 'ok'} on:click={() => (logStatusFilter = 'ok')}>
              {$t('gateway.logs.statusOk')}
            </button>
            <button type="button" class="pill-btn" class:active={logStatusFilter === '4xx'} on:click={() => (logStatusFilter = '4xx')}>
              {$t('gateway.logs.status4xx')}
            </button>
            <button type="button" class="pill-btn" class:active={logStatusFilter === 'error'} on:click={() => (logStatusFilter = 'error')}>
              {$t('gateway.logs.statusErr')}
            </button>
          </div>

          <div class="search-box">
            <Icon name="search" size={12} />
            <input type="text" class="search-input" bind:value={logSearch} placeholder={$t('gateway.logs.searchPlaceholder')} />
          </div>

          <Badge variant="success" size="xs" dot pulse={stats.running}>
            {$t('gateway.logs.liveBadge')}
          </Badge>

          <Button variant="ghost" size="xs" icon="refresh" loading={loadingLogs} on:click={loadGatewayLogs}>
            {$t('gateway.logs.refresh')}
          </Button>
          <Button variant="ghost" size="xs" icon="trash" disabled={logs.length === 0} on:click={handleClearLogs}>
            {$t('gateway.logs.clear')}
          </Button>
        </div>

        <div class="table-wrap">
          {#if filteredLogs.length === 0}
            <EmptyState
              icon="terminal"
              title={$t('gateway.logs.emptyTitle')}
              description={$t('gateway.logs.emptyDesc')}
            />
          {:else}
            <div class="log-list">
              <div class="log-head-row">
                <span></span>
                <span>{$t('gateway.logs.cols.time')}</span>
                <span>{$t('gateway.logs.cols.route')}</span>
                <span>{$t('gateway.logs.cols.status')}</span>
                <span>{$t('gateway.logs.cols.latency')}</span>
                <span>{$t('gateway.logs.cols.proxy')}</span>
                <span>{$t('gateway.logs.cols.device')}</span>
                <span>{$t('gateway.logs.cols.account')}</span>
                <span>{$t('gateway.logs.cols.result')}</span>
              </div>

              {#each filteredLogs as rec (rec.id)}
                {@const isOpen = expandedLogIds.has(rec.id)}
                {@const preview = isOpen ? getCachedPreviewForLog(rec) : null}
                <div class="log-item" class:log-err={!rec.ok || Boolean(rec.error)}>
                  <button type="button" class="log-row" on:click={() => toggleLogExpand(rec.id)}>
                    <span class="chev">
                      <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={12} />
                    </span>
                    <span class="mono tabular-nums muted">{formatTime(rec.timestamp)}</span>
                    <span class="log-route-cell">
                      <Badge variant="method" method={rec.method || 'GET'} size="xs" />
                      <span class="mono truncate">/gw/{rec.route_slug}</span>
                      {#if rec.tls_profile}
                        <Badge variant="neutral" size="xs" mono>{rec.tls_profile}</Badge>
                      {/if}
                    </span>
                    <span>
                      <Badge status={rec.status_code || 0} size="xs">{rec.status_code || 'ERR'}</Badge>
                    </span>
                    <span class="log-lat-cell mono tabular-nums">
                      <span>{formatDuration(rec.latency_ms)}</span>
                      {#if rec.signer_ms > 0}
                        <Badge variant="purple" size="xs" mono>{$t('gateway.logs.signerChip', { ms: rec.signer_ms })}</Badge>
                      {/if}
                    </span>
                    <span class="mono truncate muted">{rec.proxy_name || $t('gateway.logs.direct')}</span>
                    <span class="mono truncate muted">{rec.device_name || '—'}</span>
                    <span class="mono truncate muted">{rec.account_name || '—'}</span>
                    <span class="log-res-cell">
                      {#if rec.cache_hit}
                        <Badge variant="info" size="xs" mono>{$t('gateway.logs.badges.hit')}</Badge>
                      {/if}
                      {#if rec.circuit_tripped}
                        <Badge variant="danger" size="xs" mono>{$t('gateway.logs.badges.circuit')}</Badge>
                      {/if}
                      {#if rec.refresh_triggered}
                        <Badge variant="warning" size="xs" mono>{$t('gateway.logs.badges.refresh')}</Badge>
                      {/if}
                      {#if rec.error}
                        <Badge variant="danger" size="xs">{rec.error.slice(0, 28)}</Badge>
                      {:else if !rec.ok}
                        <Badge variant="warning" size="xs">HTTP {rec.status_code}</Badge>
                      {:else}
                        <Badge variant="success" size="xs">{$t('gateway.logs.ok')}</Badge>
                      {/if}
                    </span>
                  </button>

                  {#if isOpen}
                    <div class="log-detail">
                      <div class="ld-head">
                        <span class="f-label">{$t('gateway.logs.detail.requestSection')}</span>
                        <Button variant="secondary" size="xs" icon="external-link" on:click={() => openRouteFromLog(rec)}>
                          {$t('gateway.logs.detail.testRoute')}
                        </Button>
                      </div>

                      <div class="ld-grid mono">
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.upstreamUrl')}</span>
                          <span class="kv-rv">{rec.upstream_url || '—'}</span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.clientIp')}</span>
                          <span class="kv-rv">
                            {rec.client_ip || 'local'}
                            {#if rec.retries > 0}
                              · {$t('gateway.logs.retriesChip', { n: rec.retries })}
                            {/if}
                          </span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.signer')}</span>
                          <span class="kv-rv">
                            {rec.signer_id ? `${signerNameById[rec.signer_id] || rec.signer_id} (${formatDuration(rec.signer_ms)})` : '—'}
                          </span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.proxy')}</span>
                          <span class="kv-rv">{rec.proxy_name || $t('gateway.logs.direct')} {rec.proxy_id ? `(${rec.proxy_id})` : ''}</span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.device')}</span>
                          <span class="kv-rv">{rec.device_name || '—'} {rec.device_id ? `(${rec.device_id})` : ''}</span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.account')}</span>
                          <span class="kv-rv">{rec.account_name || '—'} {rec.account_id ? `(${rec.account_id})` : ''}</span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.tlsProfile')}</span>
                          <span class="kv-rv">{rec.tls_profile || 'go_default'}</span>
                        </div>
                        <div class="kv-line">
                          <span class="kv-rk">{$t('gateway.logs.detail.signals')}</span>
                          <span class="kv-rv log-signals-row">
                            {#if rec.cache_hit}
                              <Badge variant="info" size="xs" mono>{$t('gateway.logs.badges.hit')}</Badge>
                            {/if}
                            {#if rec.circuit_tripped}
                              <Badge variant="danger" size="xs" mono>{$t('gateway.logs.badges.circuit')}</Badge>
                            {/if}
                            {#if rec.refresh_triggered}
                              <Badge variant="warning" size="xs" mono>{$t('gateway.logs.badges.refresh')}</Badge>
                            {/if}
                            {#if !rec.cache_hit && !rec.circuit_tripped && !rec.refresh_triggered}
                              <span class="muted">{$t('gateway.logs.detail.noSignals')}</span>
                            {/if}
                          </span>
                        </div>
                      </div>

                      {#if rec.error}
                        <div class="error-banner mono">
                          <Icon name="alert-circle" size={12} />
                          <span>{rec.error}</span>
                        </div>
                      {/if}

                      <div class="ld-preview">
                        <div class="f-label">{$t('gateway.logs.detail.previewSection')}</div>
                        {#if preview || rec.req_body || rec.resp_body}
                          <div class="grid-2">
                            <div class="preview-box">
                              <div class="pb-title">{$t('gateway.logs.detail.reqPreview')}</div>
                              <pre class="resp-pre compact mono">{rec.req_body || JSON.stringify(preview?.request || {}, null, 2)}</pre>
                            </div>
                            <div class="preview-box">
                              <div class="pb-title">{$t('gateway.logs.detail.respPreview')}</div>
                              <pre class="resp-pre compact mono">{rec.resp_body || formatPrettyBody(preview?.response?.body, preview?.response?.data)}</pre>
                            </div>
                          </div>
                        {:else}
                          <div class="empty-inline">{$t('gateway.logs.detail.noPayloadHint')}</div>
                        {/if}
                      </div>
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </div>

    <!-- ==================== SUB-TAB 6: ACCOUNT / SESSION POOL ==================== -->
    {:else if activeTab === 'accounts'}
      <div class="full-tab-shell">
        <div class="pool-bar-row device-topbar">
          <div class="search-box">
            <Icon name="search" size={12} />
            <input type="text" class="search-input" bind:value={accountSearch} placeholder={$t('gateway.accounts.searchPlaceholder')} />
          </div>

          <div class="filter-pills">
            <button type="button" class="pill-btn" class:active={accountStatusFilter === 'all'} on:click={() => (accountStatusFilter = 'all')}>
              {$t('gateway.accounts.filterAll')}
            </button>
            {#each ACCOUNT_STATUSES as st}
              <button type="button" class="pill-btn" class:active={accountStatusFilter === st} on:click={() => (accountStatusFilter = st)}>
                {$t(`gateway.accounts.statuses.${st}`)}
              </button>
            {/each}
          </div>

          <div class="ctrl-spacer"></div>

          <label class="inline-field">
            <span>{$t('gateway.accounts.strategy')}</span>
            <select class="cap-input" bind:value={accountPoolConfig.strategy} disabled={savingAccountCfg} on:change={saveAccountPoolConfig}>
              {#each ACCOUNT_STRATEGIES as st}
                <option value={st}>{$t(`gateway.accounts.strategies.${st}`)}</option>
              {/each}
            </select>
          </label>

          <Button variant="primary" size="sm" icon="plus" on:click={createNewAccount}>
            + {$t('gateway.accounts.newAccount')}
          </Button>
        </div>

        <div class="split-fill">
          <SplitPane direction="horizontal" initialSize={32} minPrimary={22} minSecondary={50} storageKey="cap.gateway.accounts.hsplit">
            <!-- Left: Accounts List -->
            <div slot="primary" class="list-pane">
              <div class="list-scroll">
                {#if filteredAccounts.length === 0}
                  <EmptyState
                    icon="shield"
                    title={$t('gateway.accounts.emptyTitle')}
                    description={$t('gateway.accounts.emptyDesc')}
                    compact
                  >
                    <Button variant="primary" size="xs" icon="plus" on:click={createNewAccount}>
                      + {$t('gateway.accounts.newAccount')}
                    </Button>
                  </EmptyState>
                {:else}
                  {#each filteredAccounts as acc (acc.id)}
                    {@const accStatus = acc.status || (acc.enabled ? 'active' : 'disabled')}
                    <div
                      class="entity-card-wrap"
                      class:active={selectedAccount?.id === acc.id && !isNewAccount}
                      class:disabled-card={!acc.enabled || accStatus === 'disabled'}
                    >
                      <button type="button" class="entity-card-main" on:click={() => selectAccount(acc)}>
                        <div class="ec-top">
                          <span class="status-dot" class:on={acc.enabled && accStatus === 'active'}></span>
                          <Badge variant={accountStatusVariant(accStatus)} size="xs" dot>
                            {$t(`gateway.accounts.statuses.${accStatus}`)}
                          </Badge>
                          <span class="ec-usage mono tabular-nums">
                            {$t('gateway.accounts.usageMeta', { uses: acc.use_count || 0, fails: acc.fail_count || 0 })}
                          </span>
                        </div>
                        <div class="ec-name truncate">{acc.name || acc.username || acc.id}</div>
                        {#if acc.username && acc.username !== acc.name}
                          <div class="ec-sub mono truncate">{acc.username}</div>
                        {/if}
                        <div class="ec-chips">
                          {#if acc.sticky_device_id}
                            <Badge variant="accent" size="xs" mono>
                              {$t('gateway.accounts.stickyDeviceBadge', { name: deviceNameById[acc.sticky_device_id] || acc.sticky_device_id })}
                            </Badge>
                          {/if}
                          {#each acc.tags || [] as tg}
                            <Badge variant="neutral" size="xs" mono>{tg}</Badge>
                          {/each}
                        </div>
                      </button>

                      <div class="entity-card-actions">
                        <Button
                          variant="subtle"
                          size="xs"
                          icon="check-circle"
                          loading={markingAccountId === acc.id}
                          on:click={() => handleMarkAccountHealthy(acc.id)}
                        >
                          {$t('gateway.accounts.markHealthy')}
                        </Button>
                      </div>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- Right: Account Editor -->
            <div slot="secondary" class="detail-pane">
              {#if selectedAccount || isNewAccount}
                <div class="editor-shell">
                  <div class="editor-topbar">
                    <div class="editor-head-left">
                      <Badge variant={accountStatusVariant(aStatus)} size="sm" dot>
                        {$t(`gateway.accounts.statuses.${aStatus}`)}
                      </Badge>
                      <span class="editor-title truncate">
                        {isNewAccount ? $t('gateway.accounts.editor.newTitle') : (aName || aUsername || selectedAccount?.id)}
                      </span>
                    </div>
                    <div class="editor-head-actions">
                      {#if selectedAccount && !isNewAccount}
                        <Button
                          variant="secondary"
                          size="xs"
                          icon="check-circle"
                          loading={markingAccountId === selectedAccount.id}
                          on:click={() => handleMarkAccountHealthy(selectedAccount.id)}
                        >
                          {$t('gateway.accounts.markHealthy')}
                        </Button>
                      {/if}
                      <label class="inline-switch">
                        <span>{aEnabled ? $t('gateway.routes.editor.enabled') : $t('gateway.routes.editor.disabled')}</span>
                        <span class="switch">
                          <input type="checkbox" bind:checked={aEnabled} />
                          <span class="switch-track"></span>
                        </span>
                      </label>
                      {#if selectedAccount && !isNewAccount}
                        {#if confirmDeleteAccountId === selectedAccount.id}
                          <Button variant="danger" size="xs" icon="trash" on:click={() => deleteCurrentAccount(selectedAccount.id)}>
                            {$t('gateway.accounts.editor.confirmDelete')}
                          </Button>
                          <Button variant="ghost" size="xs" on:click={() => (confirmDeleteAccountId = null)}>
                            <Icon name="x" size={12} />
                          </Button>
                        {:else}
                          <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDeleteAccountId = selectedAccount.id)}>
                            {$t('gateway.accounts.editor.delete')}
                          </Button>
                        {/if}
                      {/if}
                      <Button variant="primary" size="xs" icon="save" loading={savingAccount} on:click={saveCurrentAccount}>
                        {$t('gateway.accounts.editor.save')}
                      </Button>
                    </div>
                  </div>

                  <div class="editor-scroll">
                    <!-- Account Identity & Lifecycle -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.accounts.editor.sectionIdentity')}</span>
                        {#if selectedAccount && !isNewAccount}
                          <span class="card-hint mono tabular-nums">
                            {$t('gateway.accounts.editor.metaTelemetry', {
                              uses: selectedAccount.use_count || 0,
                              fails: selectedAccount.fail_count || 0,
                              refreshes: selectedAccount.refresh_count || 0,
                              last: selectedAccount.last_used_at ? formatTime(selectedAccount.last_used_at) : '—',
                            })}
                          </span>
                        {/if}
                      </div>

                      <div class="grid-3">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.name')}</span>
                          <input type="text" class="cap-input" bind:value={aName} placeholder={$t('gateway.accounts.editor.namePlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.username')}</span>
                          <input type="text" class="cap-input mono" bind:value={aUsername} placeholder={$t('gateway.accounts.editor.usernamePlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.status')}</span>
                          <select class="cap-input" bind:value={aStatus}>
                            {#each ACCOUNT_STATUSES as st}
                              <option value={st}>{$t(`gateway.accounts.statuses.${st}`)}</option>
                            {/each}
                          </select>
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.tags')}</span>
                          <input type="text" class="cap-input mono" bind:value={aTags} placeholder={$t('gateway.accounts.editor.tagsPlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.stickyDevice')}</span>
                          <select class="cap-input" bind:value={aStickyDeviceId}>
                            <option value="">{$t('gateway.accounts.editor.stickyDeviceNone')}</option>
                            {#each devices as dev (dev.id)}
                              <option value={dev.id}>{dev.name} ({dev.kind})</option>
                            {/each}
                          </select>
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.stickyProxy')}</span>
                          <select class="cap-input mono" bind:value={aStickyProxyId}>
                            <option value="">{$t('gateway.accounts.editor.stickyProxyNone')}</option>
                            {#each proxies as p (p.id)}
                              <option value={p.id}>{p.name}{p.region ? ` [${p.region}]` : ''}</option>
                            {/each}
                          </select>
                        </label>
                      </div>

                      <div class="grid-2">
                        <div class="f-block">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.accounts.editor.expiresAt')}</span>
                            <div class="expiry-presets">
                              <button type="button" class="mini-link mono" on:click={() => setAccountExpiryPreset(24)}>
                                {$t('gateway.accounts.editor.preset24h')}
                              </button>
                              <button type="button" class="mini-link mono" on:click={() => setAccountExpiryPreset(24 * 7)}>
                                {$t('gateway.accounts.editor.preset7d')}
                              </button>
                              <button type="button" class="mini-link" on:click={() => setAccountExpiryPreset(0)}>
                                {$t('gateway.accounts.editor.clearExpiry')}
                              </button>
                            </div>
                          </div>
                          <input
                            type="text"
                            class="cap-input mono"
                            bind:value={aExpiresAt}
                            placeholder={$t('gateway.accounts.editor.expiresPlaceholder')}
                          />
                        </div>

                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.notes')}</span>
                          <input type="text" class="cap-input" bind:value={aNotes} placeholder={$t('gateway.accounts.editor.notesPlaceholder')} />
                        </label>
                      </div>

                      {#if selectedAccount?.last_error && !isNewAccount}
                        <div class="error-banner mono">
                          <Icon name="alert-circle" size={12} />
                          <span>{selectedAccount.last_error}</span>
                        </div>
                      {/if}
                    </div>

                    <!-- Credentials & Session KV Editors (with safe secret toggles) -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.accounts.editor.sectionCredentials')}</span>
                        <Button
                          variant="secondary"
                          size="xs"
                          icon={aShowSecrets ? 'eye-off' : 'eye'}
                          on:click={() => (aShowSecrets = !aShowSecrets)}
                        >
                          {aShowSecrets ? $t('gateway.accounts.editor.hideSecrets') : $t('gateway.accounts.editor.revealSecrets')}
                        </Button>
                      </div>

                      <div class="grid-2">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.primaryToken')}</span>
                          {#if aShowSecrets}
                            <input type="text" class="cap-input mono" bind:value={aToken} placeholder={$t('gateway.accounts.editor.primaryTokenPlaceholder')} />
                          {:else}
                            <input type="password" class="cap-input mono" bind:value={aToken} placeholder={$t('gateway.accounts.editor.primaryTokenPlaceholder')} />
                          {/if}
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.accounts.editor.refreshToken')}</span>
                          {#if aShowSecrets}
                            <input type="text" class="cap-input mono" bind:value={aRefreshToken} placeholder={$t('gateway.accounts.editor.refreshTokenPlaceholder')} />
                          {:else}
                            <input type="password" class="cap-input mono" bind:value={aRefreshToken} placeholder={$t('gateway.accounts.editor.refreshTokenPlaceholder')} />
                          {/if}
                        </label>
                      </div>

                      <label class="f-block">
                        <span class="f-label">{$t('gateway.accounts.editor.primaryCookie')}</span>
                        {#if aShowSecrets}
                          <input type="text" class="cap-input mono" bind:value={aCookie} placeholder={$t('gateway.accounts.editor.primaryCookiePlaceholder')} />
                        {:else}
                          <input type="password" class="cap-input mono" bind:value={aCookie} placeholder={$t('gateway.accounts.editor.primaryCookiePlaceholder')} />
                        {/if}
                      </label>

                      <div class="grid-3-stack">
                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.accounts.editor.cookies')}</span>
                            <button type="button" class="mini-link" on:click={() => (aCookies = [...aCookies, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each aCookies as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="sessionid" />
                              {#if aShowSecrets}
                                <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="value" />
                              {:else}
                                <input type="password" class="cap-input mono flex-1" bind:value={row.value} placeholder="••••••" />
                              {/if}
                              <button type="button" class="row-del" on:click={() => (aCookies = aCookies.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>

                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.accounts.editor.authHeaders')}</span>
                            <button type="button" class="mini-link" on:click={() => (aAuthHeaders = [...aAuthHeaders, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each aAuthHeaders as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="Authorization" />
                              {#if aShowSecrets}
                                <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="Bearer ..." />
                              {:else}
                                <input type="password" class="cap-input mono flex-1" bind:value={row.value} placeholder="••••••" />
                              {/if}
                              <button type="button" class="row-del" on:click={() => (aAuthHeaders = aAuthHeaders.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>

                        <div class="kv-section">
                          <div class="label-row">
                            <span class="f-label">{$t('gateway.accounts.editor.tokens')}</span>
                            <button type="button" class="mini-link" on:click={() => (aTokens = [...aTokens, { key: '', value: '' }])}>
                              + {$t('gateway.routes.editor.addPair')}
                            </button>
                          </div>
                          {#each aTokens as row, idx (idx)}
                            <div class="kv-edit-row">
                              <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="access_token" />
                              {#if aShowSecrets}
                                <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="token" />
                              {:else}
                                <input type="password" class="cap-input mono flex-1" bind:value={row.value} placeholder="••••••" />
                              {/if}
                              <button type="button" class="row-del" on:click={() => (aTokens = aTokens.filter((_, i) => i !== idx))}>
                                <Icon name="x" size={12} />
                              </button>
                            </div>
                          {/each}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              {:else}
                <EmptyState
                  icon="shield"
                  title={$t('gateway.accounts.noSelectionTitle')}
                  description={$t('gateway.accounts.noSelectionDesc')}
                >
                  <Button variant="primary" size="sm" icon="plus" on:click={createNewAccount}>
                    + {$t('gateway.accounts.newAccount')}
                  </Button>
                </EmptyState>
              {/if}
            </div>
          </SplitPane>
        </div>
      </div>

    <!-- ==================== SUB-TAB 7: MANAGED SIGNER WORKERS ==================== -->
    {:else if activeTab === 'workers'}
      <div class="full-tab-shell">
        <div class="pool-bar-row device-topbar">
          <div class="search-box">
            <Icon name="search" size={12} />
            <input type="text" class="search-input" bind:value={workerSearch} placeholder={$t('gateway.workers.searchPlaceholder')} />
          </div>

          <div class="ctrl-spacer"></div>

          <Button variant="secondary" size="sm" icon="refresh" loading={loadingWorkers} on:click={() => loadWorkersAndStatuses(false)}>
            {$t('gateway.workers.refreshStatus')}
          </Button>

          <Button variant="primary" size="sm" icon="plus" on:click={createNewWorker}>
            + {$t('gateway.workers.newWorker')}
          </Button>
        </div>

        <div class="split-fill">
          <SplitPane direction="horizontal" initialSize={32} minPrimary={22} minSecondary={50} storageKey="cap.gateway.workers.hsplit">
            <!-- Left: Worker Specs List -->
            <div slot="primary" class="list-pane">
              <div class="list-scroll">
                {#if filteredWorkers.length === 0}
                  <EmptyState
                    icon="cpu"
                    title={$t('gateway.workers.emptyTitle')}
                    description={$t('gateway.workers.emptyDesc')}
                    compact
                  >
                    <Button variant="primary" size="xs" icon="plus" on:click={createNewWorker}>
                      + {$t('gateway.workers.newWorker')}
                    </Button>
                  </EmptyState>
                {:else}
                  {#each filteredWorkers as w (w.id)}
                    {@const ws = workerStatusById[w.id]}
                    {@const healthyCnt = ws?.healthy_instances ?? ws?.healthy_count ?? 0}
                    {@const totalCnt = ws?.total_instances ?? ws?.total_count ?? w.instances ?? 1}
                    {@const wRunning = Boolean(ws?.running)}
                    <div
                      class="entity-card-wrap"
                      class:active={selectedWorker?.id === w.id && !isNewWorker}
                      class:disabled-card={!w.enabled}
                    >
                      <button type="button" class="entity-card-main" on:click={() => selectWorker(w)}>
                        <div class="ec-top">
                          <span class="status-dot" class:on={wRunning && healthyCnt > 0}></span>
                          <Badge variant={workerKindVariant(w.kind)} size="xs" mono>{w.kind}</Badge>
                          <Badge
                            variant={healthyCnt > 0 && healthyCnt === totalCnt ? 'success' : (wRunning ? 'warning' : 'neutral')}
                            size="xs"
                            mono
                          >
                            {healthyCnt}/{totalCnt}
                          </Badge>
                        </div>
                        <div class="ec-name truncate">{w.name}</div>
                        <div class="ec-sub mono truncate">
                          {w.command} · :{w.base_port}{w.instances > 1 ? `–${w.base_port + w.instances - 1}` : ''}
                        </div>
                      </button>

                      <div class="entity-card-actions">
                        {#if !wRunning}
                          <Button
                            variant="success"
                            size="xs"
                            icon="play"
                            iconOnly
                            title={$t('gateway.workers.start')}
                            loading={workerActionBusyId === w.id}
                            on:click={() => handleStartWorker(w.id)}
                          />
                        {:else}
                          <Button
                            variant="danger"
                            size="xs"
                            icon="square"
                            iconOnly
                            title={$t('gateway.workers.stop')}
                            loading={workerActionBusyId === w.id}
                            on:click={() => handleStopWorker(w.id)}
                          />
                        {/if}
                        <Button
                          variant="ghost"
                          size="xs"
                          icon="refresh"
                          iconOnly
                          title={$t('gateway.workers.restart')}
                          disabled={workerActionBusyId === w.id}
                          on:click={() => handleRestartWorker(w.id)}
                        />
                      </div>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>

            <!-- Right: Worker Pool Editor + Live Instance Health Table -->
            <div slot="secondary" class="detail-pane">
              {#if selectedWorker || isNewWorker}
                <div class="editor-shell">
                  <div class="editor-topbar">
                    <div class="editor-head-left">
                      <Badge variant={workerKindVariant(wKind)} size="sm" mono>{wKind}</Badge>
                      <span class="editor-title truncate">
                        {isNewWorker ? $t('gateway.workers.editor.newTitle') : (wName || selectedWorker?.id)}
                      </span>
                      {#if selectedWorker && !isNewWorker}
                        <Badge
                          variant={selectedWorkerStatus?.running ? 'success' : 'neutral'}
                          size="xs"
                          dot
                          pulse={Boolean(selectedWorkerStatus?.running)}
                        >
                          {selectedWorkerStatus?.running ? $t('gateway.workers.running') : $t('gateway.workers.stopped')}
                        </Badge>
                      {/if}
                    </div>
                    <div class="editor-head-actions">
                      {#if selectedWorker && !isNewWorker}
                        {#if !selectedWorkerStatus?.running}
                          <Button
                            variant="success"
                            size="xs"
                            icon="play"
                            loading={workerActionBusyId === selectedWorker.id}
                            on:click={() => handleStartWorker(selectedWorker.id)}
                          >
                            {$t('gateway.workers.start')}
                          </Button>
                        {:else}
                          <Button
                            variant="danger"
                            size="xs"
                            icon="square"
                            loading={workerActionBusyId === selectedWorker.id}
                            on:click={() => handleStopWorker(selectedWorker.id)}
                          >
                            {$t('gateway.workers.stop')}
                          </Button>
                        {/if}
                        <Button
                          variant="secondary"
                          size="xs"
                          icon="refresh"
                          disabled={workerActionBusyId === selectedWorker.id}
                          on:click={() => handleRestartWorker(selectedWorker.id)}
                        >
                          {$t('gateway.workers.restart')}
                        </Button>
                      {/if}
                      <label class="inline-switch">
                        <span>{wEnabled ? $t('gateway.routes.editor.enabled') : $t('gateway.routes.editor.disabled')}</span>
                        <span class="switch">
                          <input type="checkbox" bind:checked={wEnabled} />
                          <span class="switch-track"></span>
                        </span>
                      </label>
                      {#if selectedWorker && !isNewWorker}
                        {#if confirmDeleteWorkerId === selectedWorker.id}
                          <Button variant="danger" size="xs" icon="trash" on:click={() => deleteCurrentWorker(selectedWorker.id)}>
                            {$t('gateway.workers.editor.confirmDelete')}
                          </Button>
                          <Button variant="ghost" size="xs" on:click={() => (confirmDeleteWorkerId = null)}>
                            <Icon name="x" size={12} />
                          </Button>
                        {:else}
                          <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDeleteWorkerId = selectedWorker.id)}>
                            {$t('gateway.workers.editor.delete')}
                          </Button>
                        {/if}
                      {/if}
                      <Button variant="primary" size="xs" icon="save" loading={savingWorker} on:click={saveCurrentWorker}>
                        {$t('gateway.workers.editor.save')}
                      </Button>
                    </div>
                  </div>

                  <div class="editor-scroll">
                    <!-- Worker Spec Card -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <span class="card-title">{$t('gateway.workers.editor.sectionSpec')}</span>
                        <span class="card-hint mono">127.0.0.1:{wBasePort}–{Number(wBasePort) + Math.max(1, Number(wInstances) || 1) - 1}</span>
                      </div>

                      <div class="grid-3">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.name')}</span>
                          <input type="text" class="cap-input" bind:value={wName} placeholder={$t('gateway.workers.editor.namePlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.kind')}</span>
                          <select class="cap-input mono" bind:value={wKind}>
                            {#each WORKER_KINDS as wk}
                              <option value={wk}>{$t(`gateway.workers.kinds.${wk}`)} ({wk})</option>
                            {/each}
                          </select>
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.description')}</span>
                          <input type="text" class="cap-input" bind:value={wDescription} placeholder={$t('gateway.workers.editor.descriptionPlaceholder')} />
                        </label>
                      </div>

                      <div class="grid-2">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.command')}</span>
                          <input type="text" class="cap-input mono" bind:value={wCommand} placeholder={$t('gateway.workers.editor.commandPlaceholder')} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.workDir')}</span>
                          <input type="text" class="cap-input mono" bind:value={wWorkDir} placeholder={$t('gateway.workers.editor.workDirPlaceholder')} />
                        </label>
                      </div>

                      <label class="f-block">
                        <span class="f-label">{$t('gateway.workers.editor.args')}</span>
                        <textarea
                          class="cap-textarea mono"
                          rows="2"
                          bind:value={wArgsText}
                          placeholder={$t('gateway.workers.editor.argsPlaceholder')}
                        ></textarea>
                      </label>

                      <div class="grid-4">
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.basePort')}</span>
                          <input type="number" min="1" max="65535" class="cap-input mono tabular-nums" bind:value={wBasePort} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.instances')}</span>
                          <input type="number" min="1" max="8" class="cap-input mono tabular-nums" bind:value={wInstances} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.healthPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={wHealthPath} placeholder="/health" />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.signPath')}</span>
                          <input type="text" class="cap-input mono" bind:value={wSignPath} placeholder="/sign" />
                        </label>
                      </div>

                      <div class="grid-3">
                        <div class="pool-bind-box">
                          <label class="check-opt">
                            <input type="checkbox" bind:checked={wAutoRestart} />
                            <span>{$t('gateway.workers.editor.autoRestart')}</span>
                          </label>
                        </div>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.maxRestarts')}</span>
                          <input type="number" min="0" max="100" class="cap-input mono tabular-nums" bind:value={wMaxRestarts} />
                        </label>
                        <label class="f-block">
                          <span class="f-label">{$t('gateway.workers.editor.backoffMs')}</span>
                          <input type="number" min="50" max="30000" step="50" class="cap-input mono tabular-nums" bind:value={wRestartBackoffMs} />
                        </label>
                      </div>

                      <div class="kv-section">
                        <div class="label-row">
                          <div>
                            <span class="f-label">{$t('gateway.workers.editor.envVars')}</span>
                            <span class="f-hint inline-hint">{$t('gateway.workers.editor.envHint')}</span>
                          </div>
                          <button type="button" class="mini-link" on:click={() => (wEnv = [...wEnv, { key: '', value: '' }])}>
                            + {$t('gateway.routes.editor.addPair')}
                          </button>
                        </div>
                        {#each wEnv as row, idx (idx)}
                          <div class="kv-edit-row">
                            <input type="text" class="cap-input mono kv-key" bind:value={row.key} placeholder="JAVA_OPTS" />
                            <input type="text" class="cap-input mono flex-1" bind:value={row.value} placeholder="-Xmx512m" />
                            <button type="button" class="row-del" on:click={() => (wEnv = wEnv.filter((_, i) => i !== idx))}>
                              <Icon name="x" size={12} />
                            </button>
                          </div>
                        {/each}
                      </div>
                    </div>

                    <!-- Live Instance Health Table -->
                    <div class="form-card cap-card">
                      <div class="card-head">
                        <div class="inline-actions">
                          <span class="card-title">{$t('gateway.workers.health.title')}</span>
                          {#if selectedWorkerStatus}
                            {@const hCnt = selectedWorkerStatus.healthy_instances ?? selectedWorkerStatus.healthy_count ?? 0}
                            {@const tCnt = selectedWorkerStatus.total_instances ?? selectedWorkerStatus.total_count ?? 0}
                            <Badge variant={hCnt > 0 && hCnt === tCnt ? 'success' : (selectedWorkerStatus.running ? 'warning' : 'neutral')} size="xs" mono>
                              {$t('gateway.workers.healthyRatio', { healthy: hCnt, total: tCnt })}
                            </Badge>
                          {/if}
                        </div>
                        {#if selectedWorker && !isNewWorker}
                          <Button variant="ghost" size="xs" icon="refresh" loading={loadingWorkers} on:click={() => loadWorkersAndStatuses(false)}>
                            {$t('gateway.workers.refreshStatus')}
                          </Button>
                        {/if}
                      </div>

                      {#if isNewWorker || !selectedWorker}
                        <div class="empty-inline">{$t('gateway.workers.health.saveFirst')}</div>
                      {:else}
                        <div class="worker-table-wrap">
                          <table class="data-table worker-health-table">
                            <thead>
                              <tr>
                                <th class="col-chev"></th>
                                <th>{$t('gateway.workers.health.cols.index')}</th>
                                <th>{$t('gateway.workers.health.cols.port')}</th>
                                <th class="num">{$t('gateway.workers.health.cols.pid')}</th>
                                <th>{$t('gateway.workers.health.cols.state')}</th>
                                <th>{$t('gateway.workers.health.cols.healthy')}</th>
                                <th class="num">{$t('gateway.workers.health.cols.latency')}</th>
                                <th class="num">{$t('gateway.workers.health.cols.restarts')}</th>
                                <th>{$t('gateway.workers.health.cols.lastError')}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {#each selectedWorkerStatus?.instances || [] as inst (inst.index)}
                                {@const instKey = `${selectedWorker.id}:${inst.index}`}
                                {@const instOpen = expandedInstanceKeys.has(instKey)}
                                <tr>
                                  <td>
                                    <button
                                      type="button"
                                      class="chip-icon-btn"
                                      title={$t('gateway.workers.health.stderrTitle')}
                                      on:click={() => toggleInstanceExpand(selectedWorker.id, inst.index)}
                                    >
                                      <Icon name={instOpen ? 'chevron-down' : 'chevron-right'} size={12} />
                                    </button>
                                  </td>
                                  <td class="mono tabular-nums">#{inst.index}</td>
                                  <td class="mono tabular-nums" title={inst.sign_url || inst.endpoint}>:{inst.port}</td>
                                  <td class="num mono tabular-nums">{inst.pid || '—'}</td>
                                  <td>
                                    <Badge variant={inst.running ? 'info' : 'neutral'} size="xs" dot>
                                      {inst.running ? $t('gateway.workers.health.stateRunning') : $t('gateway.workers.health.stateStopped')}
                                    </Badge>
                                  </td>
                                  <td>
                                    {#if !inst.running}
                                      <Badge variant="neutral" size="xs">{$t('gateway.workers.health.healthIdle')}</Badge>
                                    {:else if inst.healthy}
                                      <Badge variant="success" size="xs" dot>{$t('gateway.workers.health.healthOk')}</Badge>
                                    {:else}
                                      <Badge variant="danger" size="xs" dot>{$t('gateway.workers.health.healthFail')}</Badge>
                                    {/if}
                                  </td>
                                  <td class="num mono tabular-nums">
                                    {inst.latency_ms > 0 ? `${inst.latency_ms}ms` : '—'}
                                  </td>
                                  <td class="num mono tabular-nums">{inst.restarts || 0}</td>
                                  <td>
                                    {#if inst.last_error}
                                      <span class="err-text mono truncate" title={inst.last_error}>{inst.last_error}</span>
                                    {:else}
                                      <span class="muted">—</span>
                                    {/if}
                                  </td>
                                </tr>
                                {#if instOpen}
                                  <tr class="stderr-row">
                                    <td colspan="9">
                                      <div class="stderr-panel">
                                        <div class="stderr-meta mono">
                                          <span>{$t('gateway.workers.health.signUrlLabel')}: <strong class="accent-text">{inst.sign_url || inst.endpoint}</strong></span>
                                          <span>{$t('gateway.workers.health.inFlightLabel')}: <strong>{inst.in_flight || 0}</strong></span>
                                          {#if inst.last_probe}
                                            <span>{$t('gateway.workers.health.lastProbeLabel')}: <strong>{formatTime(inst.last_probe)}</strong></span>
                                          {/if}
                                          <div class="ctrl-spacer"></div>
                                          {#if inst.stderr_tail}
                                            <Button variant="ghost" size="xs" icon="copy" on:click={() => copyToClipboard(inst.stderr_tail)}>
                                              {$t('gateway.workers.health.copyStderr')}
                                            </Button>
                                          {/if}
                                        </div>
                                        {#if inst.last_error}
                                          <div class="error-banner mono">
                                            <Icon name="alert-circle" size={12} />
                                            <span>{inst.last_error}</span>
                                          </div>
                                        {/if}
                                        <div class="pb-title">{$t('gateway.workers.health.stderrTitle')}</div>
                                        {#if inst.stderr_tail}
                                          <pre class="stderr-pre mono">{inst.stderr_tail}</pre>
                                        {:else}
                                          <div class="empty-inline">{$t('gateway.workers.health.stderrEmpty')}</div>
                                        {/if}
                                      </div>
                                    </td>
                                  </tr>
                                {/if}
                              {/each}
                            </tbody>
                          </table>
                        </div>
                      {/if}
                    </div>
                  </div>
                </div>
              {:else}
                <EmptyState
                  icon="cpu"
                  title={$t('gateway.workers.noSelectionTitle')}
                  description={$t('gateway.workers.noSelectionDesc')}
                >
                  <Button variant="primary" size="sm" icon="plus" on:click={createNewWorker}>
                    + {$t('gateway.workers.newWorker')}
                  </Button>
                </EmptyState>
              {/if}
            </div>
          </SplitPane>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .gw-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    width: 100%;
    min-height: 0;
    background: var(--bg-app);
    color: var(--text-primary);
    overflow: hidden;
  }

  /* ==================== Top Control Strip ==================== */
  .control-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 14px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .ctrl-left,
  .ctrl-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .ctrl-spacer {
    flex: 1;
    min-width: 8px;
  }

  .addr-group {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 0 4px 0 8px;
    height: 28px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    color: var(--text-muted);
  }

  .addr-input {
    width: 164px;
    height: 24px;
    border: none;
    background: transparent;
    padding: 0 4px;
    font-size: var(--text-xs);
  }

  .addr-input:focus {
    box-shadow: none;
  }

  /* ==================== Collapsible Top Drawers ==================== */
  .top-drawer,
  .inline-drawer {
    margin: 8px 14px 0;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex-shrink: 0;
    background: var(--bg-elevated);
    box-shadow: var(--shadow-sm);
  }

  .drawer-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
  }

  .drawer-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .drawer-sub {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: 2px;
  }

  .drawer-foot {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border-subtle);
  }

  .cfg-drawer-grid {
    display: grid;
    grid-template-columns: 1.3fr 1fr;
    gap: 16px;
  }

  .cfg-col {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .switch-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
  }

  .key-add-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .key-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 4px;
  }

  .key-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    max-width: 260px;
    padding: 3px 7px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    font-size: 11px;
    color: var(--text-primary);
  }

  .chip-icon-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    padding: 2px;
    display: inline-flex;
    border-radius: var(--radius-xs);
  }

  .chip-icon-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .chip-icon-btn.danger:hover {
    color: var(--status-danger);
    background: var(--status-danger-bg);
  }

  .openapi-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .openapi-pre {
    max-height: 240px;
    overflow: auto;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    font-size: 11px;
    line-height: 1.5;
    color: var(--text-secondary);
  }

  /* ==================== 5-KPI Telemetry Strip ==================== */
  .kpi-strip {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 8px;
    padding: 8px 14px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .kpi-card {
    padding: 8px 10px;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .kpi-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    color: var(--text-muted);
    font-size: 11px;
  }

  .kpi-label {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .kpi-val {
    font-size: 16px;
    font-weight: 700;
    line-height: 1.25;
    color: var(--text-primary);
  }

  .kpi-slash {
    font-size: 12px;
    font-weight: 500;
    color: var(--text-muted);
  }

  .kpi-sep {
    margin: 0 4px;
    color: var(--text-faint);
  }

  .kpi-sub {
    font-size: 10.5px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .kpi-good { color: var(--status-success); }
  .kpi-warn { color: var(--status-warning); }
  .kpi-bad { color: var(--status-danger); }

  /* ==================== Sub-tab Navigation ==================== */
  .subtab-bar {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 0 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    overflow-x: auto;
  }

  .subtab-btn {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 36px;
    padding: 0 12px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: color var(--transition-fast), border-color var(--transition-fast), background var(--transition-fast);
  }

  .subtab-btn:hover {
    color: var(--text-primary);
    background: var(--bg-subtle);
  }

  .subtab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .tab-cnt {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .subtab-btn.active .tab-cnt {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .tab-err-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-danger);
  }

  /* ==================== Main Workspace Body ==================== */
  .gw-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .full-tab-shell {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    overflow: hidden;
  }

  .split-fill {
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  .list-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-surface);
  }

  .pane-toolbar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px;
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .list-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .detail-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  .editor-shell {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
  }

  .editor-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 7px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .editor-head-left,
  .editor-head-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .editor-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .editor-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  /* ==================== Entity Cards ==================== */
  .entity-card {
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

  .entity-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .entity-card.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .entity-card.disabled-card {
    opacity: 0.62;
  }

  .ec-top {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--border-strong);
    flex-shrink: 0;
  }

  .status-dot.on {
    background: var(--status-success);
  }

  .ec-slug {
    font-size: 11px;
    color: var(--accent);
    font-weight: 600;
  }

  .ec-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .ec-url,
  .ec-sub {
    font-size: 11px;
    color: var(--text-muted);
  }

  .ec-usage {
    margin-left: auto;
    font-size: 10px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .ec-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 2px;
  }

  /* ==================== Flow Publish Picker ==================== */
  .flow-picker-panel {
    margin: 8px 8px 0;
    padding: 10px;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--accent-border);
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .fp-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
  }

  .fp-title {
    font-size: var(--text-sm);
    font-weight: 600;
  }

  .fp-sub {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 1px;
  }

  .flow-list {
    max-height: 150px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 3px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
  }

  .flow-pick-row {
    display: flex;
    align-items: center;
    gap: 6px;
    width: 100%;
    padding: 4px 6px;
    border-radius: var(--radius-xs);
    border: 1px solid transparent;
    background: transparent;
    text-align: left;
    cursor: pointer;
    font-size: 11px;
  }

  .flow-pick-row:hover {
    background: var(--bg-hover);
  }

  .flow-pick-row.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
  }

  .fp-url {
    flex: 1;
    min-width: 0;
    color: var(--text-primary);
  }

  .fp-inputs {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
  }

  /* ==================== Form Cards & Inputs ==================== */
  .form-card {
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .card-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .card-hint {
    font-size: 11px;
    color: var(--text-muted);
  }

  .f-block {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .f-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
  }

  .f-hint {
    font-size: 11px;
    color: var(--text-muted);
  }

  .inline-hint {
    margin-left: 8px;
    font-weight: 400;
  }

  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .cap-textarea {
    width: 100%;
    padding: 7px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 12px;
    line-height: 1.45;
    resize: vertical;
    outline: none;
  }

  .cap-textarea:focus {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .grid-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .grid-3 {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }

  .grid-4 {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }

  .grid-3-stack {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .span-2 {
    grid-column: span 2;
  }

  .flex-1 {
    flex: 1;
    min-width: 0;
  }

  .method-url-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
  }

  .method-col {
    width: 110px;
    flex-shrink: 0;
  }

  .narrow-col {
    width: 100px;
    flex-shrink: 0;
  }

  .narrow-field {
    max-width: 180px;
  }

  /* Template Variable Chips */
  .tpl-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }

  .tpl-label {
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .tpl-chips {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
  }

  .tpl-chip {
    height: 20px;
    padding: 0 6px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-surface);
    color: var(--accent);
    font-size: 10.5px;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .tpl-chip:hover {
    background: var(--accent-soft);
    border-color: var(--accent-border);
  }

  /* KV Editors */
  .kv-section {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .kv-edit-row {
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .kv-key {
    width: 38%;
    min-width: 85px;
  }

  .row-del {
    width: 24px;
    height: 24px;
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

  .row-del:hover {
    color: var(--status-danger);
    background: var(--status-danger-bg);
  }

  .mini-link {
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    padding: 1px 4px;
    border-radius: var(--radius-xs);
  }

  .mini-link:hover {
    background: var(--accent-soft);
  }

  .pool-bind-box {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  /* ==================== Live Test Console ==================== */
  .tester-pane {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-surface);
  }

  .tester-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .tester-bar-left,
  .tester-bar-right {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
  }

  .tester-title {
    font-size: var(--text-xs);
    font-weight: 700;
    color: var(--text-primary);
  }

  .mini-select {
    height: 24px;
    font-size: 11px;
    padding: 0 6px;
    max-width: 155px;
  }

  .tester-split {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: 38% 62%;
    overflow: hidden;
  }

  .tester-col {
    display: flex;
    flex-direction: column;
    min-height: 0;
    min-width: 0;
    overflow: hidden;
  }

  .border-l {
    border-left: 1px solid var(--border-default);
  }

  .mini-tabs {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 4px 8px;
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .mini-tabs.between {
    justify-content: space-between;
  }

  .mtab {
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
    font-weight: 600;
    cursor: pointer;
  }

  .mtab:hover {
    color: var(--text-primary);
  }

  .mtab.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .tester-area {
    flex: 1;
    min-height: 0;
    display: flex;
    flex-direction: column;
  }

  .tester-area.scroll {
    overflow: auto;
    padding: 8px 10px;
  }

  .code-box {
    flex: 1;
    width: 100%;
    height: 100%;
    padding: 8px 10px;
    border: none;
    resize: none;
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 11.5px;
    line-height: 1.5;
    outline: none;
  }

  .test-meta-strip {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    padding: 5px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    font-size: 11px;
    color: var(--text-secondary);
    flex-shrink: 0;
  }

  .tester-empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 20px;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .resp-pre {
    margin: 0;
    font-size: 11.5px;
    line-height: 1.5;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .resp-pre.compact {
    max-height: 160px;
    overflow: auto;
    padding: 8px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    font-size: 11px;
  }

  .kv-readout,
  .signed-readout {
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 11px;
  }

  .kv-line {
    display: grid;
    grid-template-columns: 140px minmax(0, 1fr);
    gap: 8px;
    align-items: baseline;
  }

  .kv-rk {
    color: var(--text-muted);
    font-weight: 600;
    word-break: break-word;
  }

  .kv-rv {
    color: var(--text-primary);
    word-break: break-all;
  }

  .sr-block {
    padding: 7px 9px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .sr-title {
    font-size: 10.5px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
  }

  .sr-val {
    color: var(--accent);
    word-break: break-all;
  }

  /* ==================== Proxy IP Pool & Tables ==================== */
  .pool-bars {
    display: flex;
    flex-direction: column;
    border-bottom: 1px solid var(--border-default);
    background: var(--bg-surface);
    flex-shrink: 0;
  }

  .pool-bar-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    flex-wrap: wrap;
  }

  .provider-row {
    padding-top: 6px;
    padding-bottom: 8px;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-header);
  }

  .device-topbar {
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .strip-tag {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-secondary);
    white-space: nowrap;
  }

  .inline-field {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
  }

  .narrow-inline input {
    width: 68px;
  }

  .format-select {
    width: 120px;
  }

  .path-input {
    width: 170px;
  }

  .bulk-grid {
    display: grid;
    grid-template-columns: 1.7fr 1fr;
    gap: 12px;
  }

  .bulk-opts {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .drawer-inline-end {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 8px;
  }

  .table-filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 14px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .table-wrap {
    flex: 1;
    min-height: 0;
    overflow: auto;
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-xs);
  }

  .data-table th {
    position: sticky;
    top: 0;
    z-index: 2;
    text-align: left;
    padding: 7px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
  }

  .data-table td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--border-subtle);
    vertical-align: middle;
  }

  .data-table tr:hover td {
    background: var(--bg-hover);
  }

  .data-table tr.row-muted td {
    opacity: 0.55;
  }

  .data-table .num {
    text-align: right;
  }

  .col-xs {
    width: 48px;
  }

  .proxy-ep {
    display: flex;
    flex-direction: column;
    gap: 2px;
    max-width: 320px;
  }

  .proxy-name-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .proxy-name {
    font-weight: 600;
    color: var(--text-primary);
  }

  .proxy-url {
    font-size: 11px;
    color: var(--text-muted);
  }

  .tag-cell {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .ok-cnt { color: var(--status-success); }
  .err-cnt { color: var(--status-danger); font-weight: 600; }

  .err-text {
    display: inline-block;
    max-width: 200px;
    font-size: 11px;
    color: var(--status-danger);
  }

  .row-actions {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }

  /* ==================== Preset Popover ==================== */
  .preset-wrap {
    position: relative;
  }

  .preset-popover {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    width: 320px;
    padding: 12px;
    background: var(--bg-elevated);
    box-shadow: var(--shadow-lg);
    z-index: var(--z-dropdown);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  /* ==================== Signer Editor ==================== */
  .kind-tiles {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 6px;
  }

  .kind-tile {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
    padding: 7px 9px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    cursor: pointer;
    text-align: left;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .kind-tile:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .kind-tile.active {
    border-color: var(--accent);
    background: var(--accent-soft);
  }

  .kt-title {
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .kt-code {
    font-size: 10px;
    color: var(--text-muted);
  }

  .kind-tile.active .kt-title,
  .kind-tile.active .kt-code {
    color: var(--accent);
  }

  .secret-wrap {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .script-meta-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }

  .signer-editor-host {
    height: 230px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    overflow: hidden;
  }

  .signer-result-box {
    padding: 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--status-success-border);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .sr-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  /* ==================== Live Gateway Logs ==================== */
  .route-filter-select {
    width: 170px;
  }

  .log-list {
    display: flex;
    flex-direction: column;
  }

  .log-head-row,
  .log-row {
    display: grid;
    grid-template-columns: 20px 72px minmax(165px, 1.35fr) 62px 124px minmax(84px, 0.78fr) minmax(84px, 0.78fr) minmax(84px, 0.78fr) minmax(135px, 1.15fr);
    gap: 8px;
    align-items: center;
    padding: 6px 12px;
    font-size: var(--text-xs);
  }

  .log-head-row {
    position: sticky;
    top: 0;
    z-index: 2;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
  }

  .log-item {
    border-bottom: 1px solid var(--border-subtle);
  }

  .log-item.log-err {
    background: color-mix(in srgb, var(--status-danger) 5%, transparent);
  }

  .log-row {
    width: 100%;
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
  }

  .log-row:hover {
    background: var(--bg-hover);
  }

  .chev {
    color: var(--text-muted);
    display: inline-flex;
  }

  .log-route-cell,
  .log-lat-cell,
  .log-res-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .log-detail {
    padding: 10px 16px 12px 38px;
    background: var(--bg-surface);
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .ld-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .ld-grid {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
  }

  .ld-preview {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .preview-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pb-title {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--text-muted);
  }

  /* ==================== Shared Micro-Widgets ==================== */
  .search-box {
    flex: 1;
    min-width: 140px;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-muted);
  }

  .search-box.compact {
    height: 24px;
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

  .clear-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: inline-flex;
    padding: 2px;
  }

  .filter-pills {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .pill-btn {
    height: 24px;
    padding: 0 9px;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-default);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
  }

  .pill-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .pill-btn.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .seg-mini {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--radius-sm);
    background: var(--bg-subtle);
    border: 1px solid var(--border-default);
  }

  .seg-mini-btn {
    height: 20px;
    padding: 0 8px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
  }

  .seg-mini-btn.active {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }

  .inline-actions {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .inline-actions.end {
    justify-content: flex-end;
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

  .inline-switch {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .switch {
    position: relative;
    display: inline-flex;
    width: 30px;
    height: 16px;
    flex-shrink: 0;
    cursor: pointer;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .switch-track {
    position: absolute;
    inset: 0;
    border-radius: 999px;
    background: var(--border-strong);
    transition: background var(--transition-fast);
  }

  .switch-track::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--text-primary);
    transition: transform var(--transition-fast);
  }

  .switch input:checked + .switch-track {
    background: var(--accent);
  }

  .switch input:checked + .switch-track::after {
    transform: translateX(14px);
    background: var(--text-inverse);
  }

  .error-banner {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--status-danger-bg);
    border: 1px solid var(--status-danger-border);
    color: var(--status-danger);
    font-size: 11px;
    word-break: break-word;
  }

  .empty-inline {
    padding: 8px 10px;
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg-subtle);
    border-radius: var(--radius-sm);
  }

  .accent-text {
    color: var(--accent);
  }

  .muted {
    color: var(--text-muted);
  }

  /* ==================== Wave C Pro Controls & Pools ==================== */
  .docker-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .pro-kpi-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    padding: 5px 14px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .pro-kpi-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 24px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .pro-kpi-pill:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .pro-kpi-pill.static {
    cursor: default;
  }

  .pro-kpi-pill.static:hover {
    border-color: var(--border-subtle);
    background: var(--bg-elevated);
  }

  .pk-label {
    font-weight: 500;
    color: var(--text-muted);
  }

  .prod-card {
    gap: 0;
    padding: 0;
    overflow: hidden;
  }

  .prod-head-btn {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    width: 100%;
    padding: 9px 12px;
    border: none;
    background: var(--bg-surface);
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
  }

  .prod-head-btn:hover {
    background: var(--bg-hover);
  }

  .prod-head-left,
  .prod-head-badges {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .prod-body {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 10px 12px 12px;
    border-top: 1px solid var(--border-subtle);
  }

  .ja3-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    min-height: 28px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    font-size: 11px;
    min-width: 0;
  }

  .ja3-hash {
    color: var(--text-primary);
    flex: 1;
    min-width: 0;
  }

  .ja3-meta {
    color: var(--text-muted);
    font-size: 10px;
    white-space: nowrap;
  }

  .mtls-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    flex-wrap: wrap;
  }

  .mtls-result {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
  }

  .mtls-result.ok {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .mtls-result.fail {
    background: var(--status-danger-bg);
    border-color: var(--status-danger-border);
  }

  .mtls-res-head {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }

  .mtls-msg {
    color: var(--status-danger);
    word-break: break-word;
  }

  .mtls-warn {
    color: var(--status-warning);
    word-break: break-word;
  }

  .circuit-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 28px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
  }

  .circuit-meta {
    font-size: 11px;
    color: var(--text-muted);
  }

  .resilience-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .log-signals-row {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
  }

  /* Entity cards with inline action buttons (valid HTML, no nested buttons) */
  .entity-card-wrap {
    display: flex;
    align-items: stretch;
    gap: 6px;
    width: 100%;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .entity-card-wrap:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .entity-card-wrap.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .entity-card-wrap.disabled-card {
    opacity: 0.62;
  }

  .entity-card-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 2px;
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
    color: inherit;
  }

  .entity-card-actions {
    display: flex;
    align-items: center;
    gap: 3px;
    flex-shrink: 0;
  }

  .expiry-presets {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .worker-table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .worker-health-table .col-chev {
    width: 28px;
    padding-right: 2px;
  }

  .stderr-row td {
    padding: 0;
    background: var(--bg-surface);
  }

  .stderr-row:hover td {
    background: var(--bg-surface);
  }

  .stderr-panel {
    padding: 8px 12px 10px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .stderr-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .stderr-pre {
    margin: 0;
    max-height: 180px;
    overflow: auto;
    padding: 8px 10px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    font-size: 11px;
    line-height: 1.45;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
  }
</style>
