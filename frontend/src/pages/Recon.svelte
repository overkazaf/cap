<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/recon.js'
  import { t, translate } from '../lib/i18n.js'
  import { reconState as S, reconHandoff } from '../lib/reconState.js'
  import { toast } from '../lib/toast.js'
  import {
    copyToClipboard,
    formatBytes,
    formatDuration,
    formatTime,
  } from '../lib/format.js'
  import { hasPrimaryMod } from '../lib/shortcuts.js'
  import { registerCommands } from '../lib/commandPalette.js'

  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  const HTTP_PORTS = new Set([
    80, 81, 443, 591, 3000, 4000, 5000, 5173, 8000, 8008,
    8080, 8081, 8088, 8090, 8443, 8880, 8888, 9000, 9090, 9443,
  ])
  const HTTPS_PORTS = new Set([443, 6443, 8443, 9443])

  const TECH_CATEGORY_ORDER = [
    'web-server',
    'server',
    'proxy',
    'cdn',
    'waf',
    'framework',
    'frontend',
    'language',
    'cms',
    'api',
    'other',
  ]

  const PORT_ENGINES = ['auto', 'nmap', 'native']
  const PORT_PRESETS = ['quick', 'top100', 'web', 'service', 'custom']
  const CONSOLE_FILTERS = ['all', 'progress', 'result', 'warn', 'error', 'system']
  const HISTORY_KINDS = ['all', 'domain', 'site', 'subdomain', 'portscan']

  // ==================== Persistent Workspace State ====================
  let activeTab = S.activeTab || 'domain'
  let target = S.target || ''

  // Toolchain & Paths Config Drawer
  let toolchain = S.toolchain || null
  let loadingToolchain = false
  let showToolchainDrawer = false
  let savingToolchain = false
  let cfgNmapPath = ''
  let cfgSubfinderPath = ''
  let cfgWhoisPath = ''
  let cfgDigPath = ''

  // Captured Hosts Quick-Picker
  let capturedHosts = []
  let loadingCaptured = false
  let showCapturedPicker = false
  let capturedSearch = ''

  // Tab 1: Domain Intel
  let domainReport = S.domainReport || null
  let domainLoading = false
  let tlsInspectPort = S.tlsInspectPort || 443
  let tlsInspectLoading = false
  let showWhoisRaw = S.showWhoisRaw || false
  let showTlsChain = S.showTlsChain || false

  // Tab 2: Site Probe
  let siteOpts = { ...S.siteOpts }
  let siteProfile = S.siteProfile || null
  let siteLoading = false
  let showSiteHeaders = S.showSiteHeaders || false

  // Tab 3: Subdomains
  let subdomainOpts = { ...S.subdomainOpts }
  let subdomainReport = S.subdomainReport || null
  let subdomainSearch = S.subdomainSearch || ''
  let subdomainSourceFilter = S.subdomainSourceFilter || 'all'

  // Tab 4: Ports & Nmap
  let portScanOpts = { ...S.portScanOpts }
  let portScanResult = S.portScanResult || null
  let portStateFilter = S.portStateFilter || 'all'
  let portSearch = S.portSearch || ''

  // Async Job & Live Console
  let jobState = S.jobState || null
  let startingJob = false
  let cancellingJob = false
  let consoleFilter = S.consoleFilter || 'all'
  let consoleAutoScroll = S.consoleAutoScroll ?? true
  let consoleCollapsed = S.consoleCollapsed || false
  let consoleEl = null
  let elapsedTick = Date.now()
  let clockTimer = null
  let lastNotifiedJobId = ''

  // Tab 5: Scan History
  let historyEntries = Array.isArray(S.historyEntries) ? S.historyEntries : []
  let historyLoading = false
  let historyKindFilter = S.historyKindFilter || 'all'
  let historySearch = S.historySearch || ''
  let selectedHistoryId = S.selectedHistoryId || ''
  let previewHistoryEntry = null
  let confirmClearHistory = false

  // Lifecycle guards
  let destroyed = false
  let unsubs = []
  let unsubHandoff = null
  let unregisterCmds = null

  // Persist workspace state across route switches
  $: {
    S.activeTab = activeTab
    S.target = target
    S.toolchain = toolchain
    S.domainReport = domainReport
    S.tlsInspectPort = tlsInspectPort
    S.showWhoisRaw = showWhoisRaw
    S.showTlsChain = showTlsChain
    S.siteOpts = siteOpts
    S.siteProfile = siteProfile
    S.showSiteHeaders = showSiteHeaders
    S.subdomainOpts = subdomainOpts
    S.subdomainReport = subdomainReport
    S.subdomainSearch = subdomainSearch
    S.subdomainSourceFilter = subdomainSourceFilter
    S.portScanOpts = portScanOpts
    S.portScanResult = portScanResult
    S.portStateFilter = portStateFilter
    S.portSearch = portSearch
    S.jobState = jobState
    S.consoleFilter = consoleFilter
    S.consoleAutoScroll = consoleAutoScroll
    S.consoleCollapsed = consoleCollapsed
    S.historyEntries = historyEntries
    S.historyKindFilter = historyKindFilter
    S.historySearch = historySearch
    S.selectedHistoryId = selectedHistoryId
  }

  // ==================== Reactive Computations ====================
  $: isJobRunning = Boolean(jobState?.running || jobState?.status === 'running')
  $: activeJobKind = jobState?.kind || ''
  $: liveJobElapsedMs = isJobRunning && jobState?.started_at_ms
    ? Math.max(0, elapsedTick - jobState.started_at_ms)
    : (jobState?.elapsed_ms || 0)

  $: toolchainItems = [
    { key: 'nmap', data: toolchain?.nmap || { name: 'nmap', ready: false } },
    { key: 'subfinder', data: toolchain?.subfinder || { name: 'subfinder', ready: false } },
    { key: 'whois', data: toolchain?.whois || { name: 'whois', ready: false } },
    { key: 'dig', data: toolchain?.dig || { name: 'dig', ready: false } },
  ]

  $: filteredCapturedHosts = capturedHosts.filter((item) => {
    const q = capturedSearch.trim().toLowerCase()
    if (!q) return true
    return (
      item.host.toLowerCase().includes(q) ||
      item.sampleUrl.toLowerCase().includes(q)
    )
  })

  $: targetPlaceholder =
    activeTab === 'site'
      ? $t('recon.targetBar.placeholderSite')
      : activeTab === 'subdomains'
        ? $t('recon.targetBar.placeholderSubdomains')
        : activeTab === 'ports'
          ? $t('recon.targetBar.placeholderPorts')
          : activeTab === 'history'
            ? $t('recon.targetBar.placeholderHistory')
            : $t('recon.targetBar.placeholderDomain')

  // Domain DNS flattened structured rows
  $: dnsRows = buildDnsRows(domainReport?.dns_records)

  // Site Tech grouped by category
  $: groupedTechnologies = groupTechnologies(siteProfile?.technologies)

  // Site Security audit summary + gauge geometry
  $: securityAuditStats = computeSecurityStats(siteProfile?.security_headers, siteProfile?.security_score)
  $: siteHeaderEntries = siteProfile?.headers
    ? Object.entries(siteProfile.headers).sort((a, b) => a[0].localeCompare(b[0]))
    : []
  $: siteDiscoveryEnabled = Boolean(
    siteOpts.probeRobots || siteOpts.probeSitemap || siteOpts.probeWellKnown || siteOpts.probeFavicon
  )

  // Subdomain filtering
  $: subdomainSources = buildSubdomainSources(subdomainReport)
  $: filteredSubdomains = (subdomainReport?.subdomains || []).filter((entry) => {
    if (
      subdomainSourceFilter !== 'all' &&
      !(entry.sources || []).includes(subdomainSourceFilter)
    ) {
      return false
    }
    const q = subdomainSearch.trim().toLowerCase()
    if (!q) return true
    return (
      (entry.hostname || '').toLowerCase().includes(q) ||
      (entry.cname || '').toLowerCase().includes(q) ||
      (entry.ips || []).some((ip) => ip.toLowerCase().includes(q)) ||
      (entry.sources || []).some((src) => src.toLowerCase().includes(q))
    )
  })

  // Port scan validation & filtering
  $: customPortsCheck = validatePortsSpec(portScanOpts.portsSpec)
  $: filteredPortHosts = filterPortHosts(portScanResult?.hosts, portStateFilter, portSearch)

  // Console events filtered for relevant job kind
  $: activeConsoleEvents = (jobState?.events || []).filter((ev) => {
    if (consoleFilter !== 'all' && ev.level !== consoleFilter) return false
    return true
  })

  // History filtering
  $: filteredHistory = historyEntries.filter((entry) => {
    if (historyKindFilter !== 'all' && entry.kind !== historyKindFilter) return false
    const q = historySearch.trim().toLowerCase()
    if (!q) return true
    return (
      (entry.target || '').toLowerCase().includes(q) ||
      (entry.summary || '').toLowerCase().includes(q) ||
      (entry.kind || '').toLowerCase().includes(q)
    )
  })

  // Register Command Palette entries
  $: {
    const _t = $t
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      unregisterCmds = registerCommands([
        {
          id: 'recon:domain',
          label: `Recon: ${_t('recon.tabs.domain')}`,
          category: 'Recon',
          icon: 'globe',
          keywords: 'recon domain dns whois tls cert',
          run: () => {
            activeTab = 'domain'
          },
        },
        {
          id: 'recon:site',
          label: `Recon: ${_t('recon.tabs.site')}`,
          category: 'Recon',
          icon: 'search',
          keywords: 'recon site probe fingerprint headers robots',
          run: () => {
            activeTab = 'site'
          },
        },
        {
          id: 'recon:subdomains',
          label: `Recon: ${_t('recon.tabs.subdomains')}`,
          category: 'Recon',
          icon: 'layers',
          keywords: 'recon subdomains subfinder crt.sh dns',
          run: () => {
            activeTab = 'subdomains'
          },
        },
        {
          id: 'recon:ports',
          label: `Recon: ${_t('recon.tabs.ports')}`,
          category: 'Recon',
          icon: 'radar',
          keywords: 'recon ports nmap tcp scan banner',
          run: () => {
            activeTab = 'ports'
          },
        },
      ])
    }
  }

  // ==================== Pure Helper Functions ====================

  function isTerminalStatus(st) {
    return st === 'done' || st === 'error' || st === 'cancelled'
  }

  function formatClock(ms) {
    const safe = Math.max(0, Number(ms) || 0)
    const totalSec = Math.floor(safe / 1000)
    const mins = Math.floor(totalSec / 60)
    const secs = totalSec % 60
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
  }

  function formatDateTime(iso) {
    if (!iso) return '—'
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return String(iso)
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  }

  function extractHost(raw) {
    const s = String(raw || '').trim()
    if (!s) return ''
    try {
      if (s.includes('://')) {
        const u = new URL(s)
        return u.hostname.replace(/^\[|\]$/g, '')
      }
      if (/^[0-9a-fA-F:]+$/.test(s) && s.includes(':')) {
        return s
      }
      const noPath = s.split(/[/?#]/)[0]
      if (noPath.startsWith('[')) {
        const end = noPath.indexOf(']')
        return end > 1 ? noPath.slice(1, end) : noPath
      }
      const parts = noPath.split(':')
      return parts[0].trim()
    } catch (_) {
      return s
    }
  }

  function formatSiteTarget(raw) {
    const s = String(raw || '').trim()
    if (!s) return ''
    if (/^https?:\/\//i.test(s)) return s
    return `https://${s}`
  }

  function cleanSanHost(san) {
    return String(san || '').trim().replace(/^\*\./, '')
  }

  function isHttpLikePort(p) {
    if (!p) return false
    if (HTTP_PORTS.has(Number(p.port))) return true
    const svc = String(p.service || '').toLowerCase()
    return svc.includes('http') || svc.includes('ssl') || svc.includes('www')
  }

  function isHttpsLikePort(p) {
    if (!p) return false
    if (HTTPS_PORTS.has(Number(p.port))) return true
    const svc = String(p.service || '').toLowerCase()
    return svc.includes('https') || svc.includes('ssl') || svc.includes('tls')
  }

  function buildPortProbeUrl(host, portObj) {
    const baseHost = (host?.hostname || host?.address || extractHost(target) || '').trim()
    if (!baseHost) return ''
    const needsBrackets = baseHost.includes(':') && !baseHost.startsWith('[')
    const formattedHost = needsBrackets ? `[${baseHost}]` : baseHost
    const useHttps = isHttpsLikePort(portObj)
    const scheme = useHttps ? 'https' : 'http'
    const portNum = Number(portObj?.port) || (useHttps ? 443 : 80)
    const isDefault = (useHttps && portNum === 443) || (!useHttps && portNum === 80)
    return isDefault ? `${scheme}://${formattedHost}` : `${scheme}://${formattedHost}:${portNum}`
  }

  function buildDnsRows(records) {
    if (!records) return []
    const rows = []
    for (const v of records.a || []) rows.push({ type: 'A', value: v, extra: '' })
    for (const v of records.aaaa || []) rows.push({ type: 'AAAA', value: v, extra: '' })
    if (records.cname) rows.push({ type: 'CNAME', value: records.cname, extra: '' })
    for (const mx of records.mx || []) {
      rows.push({
        type: 'MX',
        value: mx.host || '',
        extra: translate('recon.domain.dnsPref', { pref: mx.pref ?? 0 }),
      })
    }
    for (const v of records.ns || []) rows.push({ type: 'NS', value: v, extra: '' })
    for (const v of records.txt || []) rows.push({ type: 'TXT', value: v, extra: '' })
    for (const v of records.ptr || []) rows.push({ type: 'PTR', value: v, extra: '' })
    return rows
  }

  function dnsTypeVariant(type) {
    switch (type) {
      case 'A':
        return 'accent'
      case 'AAAA':
        return 'info'
      case 'CNAME':
        return 'purple'
      case 'MX':
        return 'warning'
      case 'NS':
        return 'success'
      default:
        return 'neutral'
    }
  }

  function groupTechnologies(list) {
    if (!Array.isArray(list) || list.length === 0) return []
    const map = new Map()
    for (const item of list) {
      const cat = String(item?.category || 'other').toLowerCase()
      if (!map.has(cat)) map.set(cat, [])
      map.get(cat).push(item)
    }
    const orderedKeys = [
      ...TECH_CATEGORY_ORDER.filter((k) => map.has(k)),
      ...Array.from(map.keys()).filter((k) => !TECH_CATEGORY_ORDER.includes(k)),
    ]
    return orderedKeys.map((category) => ({
      category,
      items: map.get(category),
    }))
  }

  function techCategoryVariant(cat) {
    switch (cat) {
      case 'waf':
        return 'warning'
      case 'cdn':
        return 'info'
      case 'web-server':
      case 'server':
      case 'proxy':
        return 'accent'
      case 'framework':
      case 'language':
        return 'purple'
      case 'cms':
      case 'api':
        return 'success'
      default:
        return 'neutral'
    }
  }

  function techCategoryLabel(cat, _t) {
    const key = TECH_CATEGORY_ORDER.includes(cat) ? cat : 'other'
    return _t(`recon.site.techCategories.${key}`)
  }

  function historyKindLabel(kind, _t) {
    const k = String(kind || '').toLowerCase()
    if (HISTORY_KINDS.includes(k)) {
      return _t(`recon.history.kinds.${k}`)
    }
    return kind || '—'
  }

  function computeSecurityStats(headers, rawScore) {
    const list = Array.isArray(headers) ? headers : []
    const score = Math.max(0, Math.min(100, Number(rawScore) || 0))
    let pass = 0
    let warn = 0
    let fail = 0
    for (const h of list) {
      if (h.status === 'pass') pass++
      else if (h.status === 'warn') warn++
      else fail++
    }
    const radius = 34
    const circumference = 2 * Math.PI * radius
    const dashOffset = circumference * (1 - score / 100)
    const tone = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'danger'
    return { score, pass, warn, fail, radius, circumference, dashOffset, tone }
  }

  function buildSubdomainSources(report) {
    if (!report) return []
    const set = new Set(report.sources_used || [])
    for (const entry of report.subdomains || []) {
      for (const s of entry.sources || []) set.add(s)
    }
    return Array.from(set)
  }

  function validatePortsSpec(spec) {
    const s = String(spec || '').trim()
    if (!s) return { valid: false, count: 0, errorKey: 'recon.ports.validation.empty' }
    if (s.startsWith('-')) return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalid' }
    const seen = new Set()
    const parts = s.split(',')
    for (const rawPart of parts) {
      const part = rawPart.trim()
      if (!part) return { valid: false, count: 0, errorKey: 'recon.ports.validation.emptyToken' }
      if (part.includes('-')) {
        const bounds = part.split('-')
        if (bounds.length !== 2) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalidRange' }
        }
        const a = bounds[0].trim()
        const b = bounds[1].trim()
        if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalidRange' }
        }
        const lo = Number(a)
        const hi = Number(b)
        if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo > hi) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalidRange' }
        }
        if (hi - lo + 1 > 4096) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.tooMany' }
        }
        for (let p = lo; p <= hi; p++) {
          seen.add(p)
          if (seen.size > 4096) {
            return { valid: false, count: 0, errorKey: 'recon.ports.validation.tooMany' }
          }
        }
      } else {
        if (!/^\d+$/.test(part)) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalidPort' }
        }
        const p = Number(part)
        if (p < 1 || p > 65535) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.invalidPort' }
        }
        seen.add(p)
        if (seen.size > 4096) {
          return { valid: false, count: 0, errorKey: 'recon.ports.validation.tooMany' }
        }
      }
    }
    return { valid: true, count: seen.size, errorKey: '' }
  }

  function filterPortHosts(hosts, stateFilter, query) {
    if (!Array.isArray(hosts)) return []
    const q = String(query || '').trim().toLowerCase()
    return hosts.map((h) => {
      const ports = (h.ports || []).filter((p) => {
        if (stateFilter === 'open' && p.state !== 'open') return false
        if (stateFilter === 'filtered' && p.state !== 'filtered') return false
        if (!q) return true
        return (
          String(p.port).includes(q) ||
          (p.protocol || '').toLowerCase().includes(q) ||
          (p.service || '').toLowerCase().includes(q) ||
          (p.product || '').toLowerCase().includes(q) ||
          (p.version || '').toLowerCase().includes(q) ||
          (p.banner || '').toLowerCase().includes(q)
        )
      })
      return { ...h, filteredPorts: ports }
    })
  }

  function portStateVariant(state) {
    if (state === 'open') return 'success'
    if (state === 'filtered') return 'warning'
    return 'neutral'
  }

  function tlsExpiryBadge(leaf) {
    if (!leaf) return { variant: 'neutral', text: '' }
    if (leaf.expired || leaf.days_until_expiry < 0) {
      return {
        variant: 'danger',
        text: translate('recon.domain.tlsExpired', {
          days: Math.abs(Number(leaf.days_until_expiry) || 0),
        }),
      }
    }
    if (leaf.days_until_expiry === 0) {
      return { variant: 'warning', text: translate('recon.domain.tlsExpiresToday') }
    }
    if (leaf.days_until_expiry <= 30) {
      return {
        variant: 'warning',
        text: translate('recon.domain.tlsExpiresIn', { days: leaf.days_until_expiry }),
      }
    }
    return {
      variant: 'success',
      text: translate('recon.domain.tlsExpiresIn', { days: leaf.days_until_expiry }),
    }
  }

  function jobStatusVariant(status) {
    switch (status) {
      case 'running':
        return 'accent'
      case 'done':
        return 'success'
      case 'error':
        return 'danger'
      case 'cancelled':
        return 'warning'
      default:
        return 'neutral'
    }
  }

  function jobStatusLabel(status) {
    switch (status) {
      case 'running':
        return translate('recon.console.statusRunning')
      case 'done':
        return translate('recon.console.statusDone')
      case 'error':
        return translate('recon.console.statusError')
      case 'cancelled':
        return translate('recon.console.statusCancelled')
      default:
        return translate('recon.console.statusIdle')
    }
  }

  function historyKindVariant(kind) {
    switch (kind) {
      case 'domain':
        return 'accent'
      case 'site':
        return 'info'
      case 'subdomain':
        return 'purple'
      case 'portscan':
        return 'warning'
      default:
        return 'neutral'
    }
  }

  function exportJsonReport(data, prefix, rawTarget) {
    if (!data) return
    try {
      const safeTarget = String(rawTarget || 'report')
        .replace(/^https?:\/\//i, '')
        .replace(/[^a-zA-Z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 64) || 'report'
      const filename = `cap-recon-${prefix}-${safeTarget}.json`
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success(translate('recon.toast.exportedJson', { filename }))
    } catch (e) {
      toast.error(String(e?.message || e))
    }
  }

  // ==================== Job State Reconciliation ====================

  function maxEventSeq(events) {
    if (!Array.isArray(events) || events.length === 0) return 0
    let max = 0
    for (const ev of events) {
      const n = Number(ev?.seq) || 0
      if (n > max) max = n
    }
    return max
  }

  function mergeJobEvents(existing, incoming) {
    const bySeq = new Map()
    const pushList = (list) => {
      if (!Array.isArray(list)) return
      for (const ev of list) {
        if (!ev) continue
        const key = ev.seq !== undefined && ev.seq !== null
          ? `s:${ev.seq}`
          : `t:${ev.timestamp_ms || 0}:${ev.message || ''}`
        bySeq.set(key, ev)
      }
    }
    pushList(existing)
    pushList(incoming)
    const sorted = Array.from(bySeq.values()).sort((a, b) => (Number(a.seq) || 0) - (Number(b.seq) || 0))
    return sorted.length > 1000 ? sorted.slice(sorted.length - 1000) : sorted
  }

  async function scrollConsoleToBottom() {
    if (!consoleAutoScroll || consoleCollapsed || !consoleEl) return
    await tick()
    if (consoleEl) {
      consoleEl.scrollTop = consoleEl.scrollHeight
    }
  }

  function applyJobLogEvent(ev) {
    if (!ev || destroyed) return
    const evSeq = Number(ev.seq) || 0
    if (!jobState || !jobState.id) {
      jobState = {
        id: ev.job_id || '',
        kind: ev.kind || '',
        target: target || '',
        status: 'running',
        running: true,
        started_at_ms: ev.timestamp_ms || Date.now(),
        event_count: 1,
        events: [ev],
      }
      scrollConsoleToBottom()
      return
    }

    if (ev.job_id && jobState.id && ev.job_id !== jobState.id) {
      const curMax = maxEventSeq(jobState.events)
      const isNewer = evSeq > curMax && (ev.timestamp_ms || 0) >= (jobState.started_at_ms || 0)
      if (!isNewer) return
      jobState = {
        id: ev.job_id,
        kind: ev.kind || '',
        target: '',
        status: 'running',
        running: true,
        started_at_ms: ev.timestamp_ms || Date.now(),
        event_count: 1,
        events: [ev],
      }
      scrollConsoleToBottom()
      return
    }

    const merged = mergeJobEvents(jobState.events, [ev])
    jobState = {
      ...jobState,
      events: merged,
      event_count: Math.max(Number(jobState.event_count) || 0, merged.length),
    }
    scrollConsoleToBottom()
  }

  function reconcileJobState(st, { fromRpc = false, notify = true } = {}) {
    if (!st || destroyed) return
    const prev = jobState
    const prevRunning = Boolean(prev?.running || prev?.status === 'running')

    // Ignore stale snapshots belonging to an older job ID
    if (prev?.id && st.id && st.id !== prev.id) {
      const prevStart = Number(prev.started_at_ms) || 0
      const nextStart = Number(st.started_at_ms) || 0
      const prevSeq = maxEventSeq(prev.events)
      const nextSeq = maxEventSeq(st.events)
      if (nextStart < prevStart && nextSeq <= prevSeq) {
        return
      }
    }

    // Same job ID: prevent terminal -> running regression from late RPC returns
    if (prev?.id && st.id && st.id === prev.id) {
      if (isTerminalStatus(prev.status) && (st.running || st.status === 'running')) {
        const merged = mergeJobEvents(prev.events, st.events)
        jobState = {
          ...prev,
          events: merged,
          event_count: Math.max(Number(prev.event_count) || 0, merged.length),
        }
        return
      }
    }

    let nextEvents
    if (prev?.id && st.id && st.id === prev.id) {
      const explicitClear =
        !fromRpc &&
        (Number(st.event_count) || 0) === 0 &&
        (!Array.isArray(st.events) || st.events.length === 0) &&
        (prev.events?.length || 0) > 0 &&
        st.status === prev.status
      nextEvents = explicitClear ? [] : mergeJobEvents(prev.events, st.events)
    } else {
      nextEvents = mergeJobEvents([], st.events)
    }

    jobState = {
      ...st,
      events: nextEvents,
      event_count:
        nextEvents.length === 0 && (Number(st.event_count) || 0) === 0
          ? 0
          : Math.max(Number(st.event_count) || 0, nextEvents.length),
    }

    // Hydrate matching tab results from job payload
    if (st.domain_report) domainReport = st.domain_report
    if (st.site_profile) siteProfile = st.site_profile
    if (st.subdomain_report) subdomainReport = st.subdomain_report
    if (st.port_scan_result) portScanResult = st.port_scan_result

    scrollConsoleToBottom()

    if (notify && st.id && isTerminalStatus(st.status) && prevRunning && lastNotifiedJobId !== st.id) {
      lastNotifiedJobId = st.id
      if (st.status === 'done') {
        toast.success(translate('recon.toast.jobDone', { kind: st.kind || '' }))
        loadHistory()
      } else if (st.status === 'cancelled') {
        toast.warning(translate('recon.toast.jobCancelled'))
      } else if (st.status === 'error') {
        toast.error(translate('recon.toast.jobError', { err: st.error || 'unknown error' }))
      }
    }
  }

  // ==================== Backend RPC Loaders & Actions ====================

  async function loadToolchain(forceRefresh = false) {
    const app = api()
    if (!app?.GetReconToolchain) return
    loadingToolchain = true
    try {
      const info = await app.GetReconToolchain(Boolean(forceRefresh))
      if (!destroyed && info) {
        toolchain = info
      }
    } catch (_) {
      // ignore initial probe error
    } finally {
      if (!destroyed) loadingToolchain = false
    }
  }

  async function loadToolchainSettings() {
    const app = api()
    if (!app?.GetSetting) return
    try {
      const [nmapP, subP, whoisP, digP] = await Promise.all([
        app.GetSetting('recon_nmap_path').catch(() => ''),
        app.GetSetting('recon_subfinder_path').catch(() => ''),
        app.GetSetting('recon_whois_path').catch(() => ''),
        app.GetSetting('recon_dig_path').catch(() => ''),
      ])
      if (destroyed) return
      cfgNmapPath = nmapP || ''
      cfgSubfinderPath = subP || ''
      cfgWhoisPath = whoisP || ''
      cfgDigPath = digP || ''
    } catch (_) {}
  }

  async function toggleToolchainDrawer() {
    showToolchainDrawer = !showToolchainDrawer
    if (showToolchainDrawer) {
      await loadToolchainSettings()
    }
  }

  async function saveToolchainConfig(resetToAuto = false) {
    const app = api()
    if (!app?.UpdateReconToolchainConfig) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    if (resetToAuto) {
      cfgNmapPath = ''
      cfgSubfinderPath = ''
      cfgWhoisPath = ''
      cfgDigPath = ''
    }
    savingToolchain = true
    try {
      const info = await app.UpdateReconToolchainConfig({
        nmap_path: cfgNmapPath.trim(),
        subfinder_path: cfgSubfinderPath.trim(),
        whois_path: cfgWhoisPath.trim(),
        dig_path: cfgDigPath.trim(),
      })
      if (destroyed) return
      if (info) toolchain = info
      toast.success(translate('recon.toast.toolchainSaved'))
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.toolchainError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) savingToolchain = false
    }
  }

  async function loadCapturedHosts() {
    const app = api()
    if (!app?.GetFlows) return
    loadingCaptured = true
    try {
      const flows = (await app.GetFlows('', '', '', 200)) || []
      if (destroyed) return
      const map = new Map()
      for (const f of flows) {
        const rawHost = String(f?.host || '').trim()
        let host = rawHost
        let scheme = 'https'
        let sampleUrl = String(f?.url || '').trim()
        if (sampleUrl) {
          try {
            const u = new URL(sampleUrl)
            scheme = u.protocol.replace(':', '') || 'https'
            if (!host) host = u.host
          } catch (_) {}
        }
        if (!host) continue
        const key = host.toLowerCase()
        const existing = map.get(key)
        if (existing) {
          existing.count += 1
        } else {
          map.set(key, {
            host,
            hostname: extractHost(host),
            scheme,
            origin: `${scheme}://${host}`,
            sampleUrl: sampleUrl || `${scheme}://${host}`,
            count: 1,
            lastStatus: f?.status || 0,
          })
        }
      }
      capturedHosts = Array.from(map.values()).sort((a, b) => b.count - a.count)
    } catch (_) {
      // ignore if proxy store not ready
    } finally {
      if (!destroyed) loadingCaptured = false
    }
  }

  function toggleCapturedPicker() {
    showCapturedPicker = !showCapturedPicker
    if (showCapturedPicker) {
      loadCapturedHosts()
    }
  }

  function selectCapturedHost(item) {
    if (!item) return
    target = activeTab === 'site' ? item.origin : item.hostname || item.host
    showCapturedPicker = false
  }

  async function loadHistory() {
    const app = api()
    if (!app?.ListReconHistory) return
    historyLoading = true
    try {
      const list = await app.ListReconHistory()
      if (!destroyed) {
        historyEntries = Array.isArray(list) ? list : []
      }
    } catch (_) {
      // ignore initial history load errors
    } finally {
      if (!destroyed) historyLoading = false
    }
  }

  async function restoreJobSnapshot() {
    const app = api()
    if (!app?.GetReconJobState) return
    try {
      const st = await app.GetReconJobState()
      if (!destroyed && st) {
        reconcileJobState(st, { fromRpc: true, notify: false })
      }
    } catch (_) {}
  }

  async function runDomainAnalysis(customTarget = '') {
    const app = api()
    if (!app?.AnalyzeReconDomain) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    const raw = String(customTarget || target).trim()
    if (!raw) {
      toast.warning(translate('recon.toast.enterTarget'))
      return
    }
    domainLoading = true
    try {
      const report = await app.AnalyzeReconDomain(raw)
      if (destroyed) return
      if (report) {
        domainReport = report
        if (report.tls?.port) {
          tlsInspectPort = report.tls.port
        }
        toast.success(translate('recon.toast.domainDone', { target: report.target || raw }))
        loadHistory()
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.domainError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) domainLoading = false
    }
  }

  async function runTlsInspect() {
    const app = api()
    if (!app?.InspectReconTLS) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    const host = extractHost(domainReport?.target || target)
    if (!host) {
      toast.warning(translate('recon.toast.enterTarget'))
      return
    }
    const port = Math.max(1, Math.min(65535, Number(tlsInspectPort) || 443))
    tlsInspectPort = port
    tlsInspectLoading = true
    try {
      const tlsReport = await app.InspectReconTLS(host, port)
      if (destroyed) return
      if (tlsReport) {
        if (domainReport) {
          domainReport = { ...domainReport, tls: tlsReport }
        } else {
          domainReport = {
            target: host,
            root_domain: host,
            ipv4: [],
            ipv6: [],
            dns_records: { a: [], aaaa: [], cname: '', mx: [], ns: [], txt: [], ptr: [] },
            cdn_providers: [],
            waf_hints: [],
            tls: tlsReport,
            elapsed_ms: tlsReport.elapsed_ms || 0,
            checked_at: tlsReport.checked_at || '',
          }
        }
        toast.success(translate('recon.toast.tlsDone', { host, port }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.tlsError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) tlsInspectLoading = false
    }
  }

  async function runSiteProbe(customTarget = '') {
    const app = api()
    if (!app?.ProbeReconSite) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    const raw = String(customTarget || target).trim()
    if (!raw) {
      toast.warning(translate('recon.toast.enterTarget'))
      return
    }
    const opts = {
      timeout_ms: Math.max(1000, Math.min(60000, Number(siteOpts.timeoutMs) || 10000)),
      no_redirects: Boolean(siteOpts.noRedirects),
      insecure_skip_verify: Boolean(siteOpts.insecureSkipVerify),
      skip_discovery: !siteDiscoveryEnabled,
    }
    siteLoading = true
    try {
      const profile = await app.ProbeReconSite(raw, opts)
      if (destroyed) return
      if (profile) {
        siteProfile = profile
        toast.success(
          translate('recon.toast.siteDone', {
            status: profile.status_code,
            score: profile.security_score,
          })
        )
        loadHistory()
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.siteError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) siteLoading = false
    }
  }

  async function startSubdomainJob(customTarget = '') {
    const app = api()
    if (!app?.StartReconJob) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    const raw = extractHost(customTarget || target)
    if (!raw) {
      toast.warning(translate('recon.toast.enterTarget'))
      return
    }
    startingJob = true
    consoleCollapsed = false
    try {
      const st = await app.StartReconJob({
        kind: 'subdomain',
        target: raw,
        subdomain: {
          domain: raw,
          use_subfinder: Boolean(subdomainOpts.useSubfinder),
          use_ct_log: Boolean(subdomainOpts.useCTLog),
          use_common_dns: Boolean(subdomainOpts.useCommonDNS),
          resolve_dns: Boolean(subdomainOpts.resolveDNS),
          timeout_sec: Math.max(5, Math.min(300, Number(subdomainOpts.timeoutSec) || 45)),
        },
        save_history: true,
      })
      if (destroyed) return
      if (st) {
        reconcileJobState(st, { fromRpc: true, notify: false })
        toast.info(translate('recon.toast.jobStarted', { kind: 'subdomain', target: st.target || raw }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.jobStartError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) startingJob = false
    }
  }

  async function startPortScanJob(customTarget = '') {
    const app = api()
    if (!app?.StartReconJob) {
      toast.error(translate('recon.toast.missingApi'))
      return
    }
    const raw = String(customTarget || target).trim()
    if (!raw) {
      toast.warning(translate('recon.toast.enterTarget'))
      return
    }
    const scanTarget = raw.includes('://') ? extractHost(raw) : raw
    if (portScanOpts.preset === 'custom' && !customPortsCheck.valid) {
      toast.warning(translate('recon.toast.invalidCustomPorts'))
      return
    }
    startingJob = true
    consoleCollapsed = false
    try {
      const st = await app.StartReconJob({
        kind: 'portscan',
        target: scanTarget,
        port_scan: {
          target: scanTarget,
          engine: portScanOpts.engine || 'auto',
          preset: portScanOpts.preset || 'quick',
          ports_spec: portScanOpts.preset === 'custom' ? portScanOpts.portsSpec.trim() : '',
          service_version: Boolean(portScanOpts.serviceVersion),
          skip_host_discovery: Boolean(portScanOpts.skipHostDiscovery),
          timeout_ms: Math.max(200, Math.min(10000, Number(portScanOpts.timeoutMs) || 1200)),
        },
        save_history: true,
      })
      if (destroyed) return
      if (st) {
        reconcileJobState(st, { fromRpc: true, notify: false })
        toast.info(translate('recon.toast.jobStarted', { kind: 'portscan', target: st.target || scanTarget }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.jobStartError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) startingJob = false
    }
  }

  async function cancelActiveJob() {
    const app = api()
    if (!app?.CancelReconJob) return
    cancellingJob = true
    try {
      await app.CancelReconJob()
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.cancelError', { err: e?.message || e }))
      }
    } finally {
      if (!destroyed) cancellingJob = false
    }
  }

  async function clearJobLogs() {
    const app = api()
    if (app?.ClearReconJobLogs) {
      try {
        await app.ClearReconJobLogs()
      } catch (_) {}
    }
    if (!destroyed && jobState) {
      jobState = { ...jobState, events: [], event_count: 0 }
    }
  }

  async function runPrimaryAction() {
    if (activeTab === 'domain') {
      await runDomainAnalysis()
    } else if (activeTab === 'site') {
      await runSiteProbe()
    } else if (activeTab === 'subdomains') {
      await startSubdomainJob()
    } else if (activeTab === 'ports') {
      await startPortScanJob()
    } else if (activeTab === 'history') {
      await loadHistory()
    }
  }

  // ==================== History Actions ====================

  async function openHistoryEntry(id, restoreToTab = true) {
    const app = api()
    if (!app?.GetReconHistory || !id) return
    try {
      const entry = await app.GetReconHistory(id)
      if (destroyed || !entry) return
      selectedHistoryId = entry.id
      previewHistoryEntry = entry

      if (restoreToTab) {
        if (entry.target) target = entry.target
        if (entry.kind === 'domain' && entry.domain_report) {
          domainReport = entry.domain_report
          activeTab = 'domain'
        } else if (entry.kind === 'site' && entry.site_profile) {
          siteProfile = entry.site_profile
          siteOpts = {
            ...siteOpts,
            probeRobots: true,
            probeSitemap: true,
            probeWellKnown: true,
            probeFavicon: true,
          }
          activeTab = 'site'
        } else if (entry.kind === 'subdomain' && entry.subdomain_report) {
          subdomainReport = entry.subdomain_report
          activeTab = 'subdomains'
        } else if (entry.kind === 'portscan' && entry.port_scan_result) {
          portScanResult = entry.port_scan_result
          activeTab = 'ports'
        }
        toast.success(
          translate('recon.toast.historyRestored', {
            kind: entry.kind,
            target: entry.target,
          })
        )
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.historyLoadError', { err: e?.message || e }))
      }
    }
  }

  async function copyHistoryJson(id) {
    const app = api()
    if (!app?.GetReconHistory || !id) return
    try {
      const entry = await app.GetReconHistory(id)
      if (!destroyed && entry) {
        await copyToClipboard(JSON.stringify(entry, null, 2))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.historyLoadError', { err: e?.message || e }))
      }
    }
  }

  async function exportHistoryJson(id) {
    const app = api()
    if (!app?.GetReconHistory || !id) return
    try {
      const entry = await app.GetReconHistory(id)
      if (!destroyed && entry) {
        exportJsonReport(entry, entry.kind || 'history', entry.target || entry.id)
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.historyLoadError', { err: e?.message || e }))
      }
    }
  }

  async function deleteHistoryEntry(id) {
    const app = api()
    if (!app?.DeleteReconHistory || !id) return
    try {
      await app.DeleteReconHistory(id)
      if (destroyed) return
      historyEntries = historyEntries.filter((h) => h.id !== id)
      if (selectedHistoryId === id) {
        selectedHistoryId = ''
        previewHistoryEntry = null
      }
      toast.success(translate('recon.toast.historyDeleted'))
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.historyError', { err: e?.message || e }))
      }
    }
  }

  async function clearAllHistory() {
    const app = api()
    if (!app?.ClearReconHistory) return
    try {
      await app.ClearReconHistory()
      if (destroyed) return
      historyEntries = []
      selectedHistoryId = ''
      previewHistoryEntry = null
      confirmClearHistory = false
      toast.success(translate('recon.toast.historyCleared'))
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('recon.toast.historyError', { err: e?.message || e }))
      }
    }
  }

  // ==================== Cross-Tab Pivot Actions ====================

  function pivotToSite(urlOrHost, autoRun = true) {
    const formatted = formatSiteTarget(cleanSanHost(urlOrHost))
    if (!formatted) return
    target = formatted
    activeTab = 'site'
    if (autoRun) runSiteProbe(formatted)
  }

  function pivotToSubdomains(host, autoRun = false) {
    const clean = extractHost(cleanSanHost(host))
    if (!clean) return
    target = clean
    activeTab = 'subdomains'
    if (autoRun) startSubdomainJob(clean)
  }

  function pivotToPorts(host, autoRun = false) {
    const clean = extractHost(cleanSanHost(host))
    if (!clean) return
    target = clean
    activeTab = 'ports'
    if (autoRun) startPortScanJob(clean)
  }

  function pivotToDomain(host, autoRun = true) {
    const clean = extractHost(cleanSanHost(host))
    if (!clean) return
    target = clean
    activeTab = 'domain'
    if (autoRun) runDomainAnalysis(clean)
  }

  function pivotToTls(host, port) {
    const clean = extractHost(cleanSanHost(host))
    if (!clean) return
    target = clean
    tlsInspectPort = Number(port) || 443
    activeTab = 'domain'
    runTlsInspect()
  }

  // ==================== Events, Handoff & Shortcuts ====================

  function applyHandoff(h) {
    if (!h || destroyed) return
    if (h.target) target = h.target
    if (h.tab) activeTab = h.tab
    S.pendingHandoff = null
    reconHandoff.set(null)
    if (h.autoRun && h.target) {
      runPrimaryAction()
    }
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return
    const on = (name, fn) => {
      const off = rt.EventsOn(name, fn)
      if (typeof off === 'function') unsubs.push(off)
    }
    on('recon:log', (ev) => applyJobLogEvent(ev))
    on('recon:status', (st) => reconcileJobState(st, { fromRpc: false, notify: true }))
  }

  function handleWindowClick(e) {
    if (showCapturedPicker && !e.target?.closest?.('.captured-picker-wrap')) {
      showCapturedPicker = false
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Escape') {
      if (showCapturedPicker) showCapturedPicker = false
      if (confirmClearHistory) confirmClearHistory = false
      return
    }
    if (!hasPrimaryMod(e)) return
    if (e.key === 'Enter') {
      e.preventDefault()
      runPrimaryAction()
    }
  }

  onMount(async () => {
    subscribeEvents()
    let consumedInitial = false
    unsubHandoff = reconHandoff.subscribe((h) => {
      if (h && !destroyed) {
        consumedInitial = true
        applyHandoff(h)
      }
    })
    if (!consumedInitial && S.pendingHandoff && !destroyed) {
      applyHandoff(S.pendingHandoff)
    }

    clockTimer = setInterval(() => {
      if (!destroyed && isJobRunning) {
        elapsedTick = Date.now()
      }
    }, 500)

    await Promise.all([
      loadToolchain(false),
      loadCapturedHosts(),
      loadHistory(),
      restoreJobSnapshot(),
    ])
    if (destroyed) return
  })

  onDestroy(() => {
    destroyed = true
    if (clockTimer) {
      clearInterval(clockTimer)
      clockTimer = null
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
      try {
        off()
      } catch (_) {}
    }
    unsubs = []
  })
</script>

<svelte:window on:keydown={handleKeydown} on:click={handleWindowClick} />

<div class="recon-page">
  <!-- 1. Single-Tier Top Strip: 5 Tabs + Host Toolchain Status -->
  <header class="top-strip">
    <nav class="tab-strip" aria-label="Recon tabs">
      <button
        type="button"
        class="tab-btn"
        class:active={activeTab === 'domain'}
        on:click={() => (activeTab = 'domain')}
      >
        <Icon name="globe" size={14} />
        <span>{$t('recon.tabs.domain')}</span>
        {#if domainLoading || (isJobRunning && activeJobKind === 'domain')}
          <span class="tab-pulse-dot" aria-hidden="true"></span>
        {/if}
      </button>

      <button
        type="button"
        class="tab-btn"
        class:active={activeTab === 'site'}
        on:click={() => (activeTab = 'site')}
      >
        <Icon name="search" size={14} />
        <span>{$t('recon.tabs.site')}</span>
        {#if siteLoading || (isJobRunning && activeJobKind === 'site')}
          <span class="tab-pulse-dot" aria-hidden="true"></span>
        {:else if siteProfile}
          <span class="tab-mini-tag mono">{siteProfile.status_code}</span>
        {/if}
      </button>

      <button
        type="button"
        class="tab-btn"
        class:active={activeTab === 'subdomains'}
        on:click={() => (activeTab = 'subdomains')}
      >
        <Icon name="layers" size={14} />
        <span>{$t('recon.tabs.subdomains')}</span>
        {#if isJobRunning && activeJobKind === 'subdomain'}
          <span class="tab-pulse-dot" aria-hidden="true"></span>
        {:else if subdomainReport}
          <span class="tab-count tabular-nums">{subdomainReport.total_count ?? 0}</span>
        {/if}
      </button>

      <button
        type="button"
        class="tab-btn"
        class:active={activeTab === 'ports'}
        on:click={() => (activeTab = 'ports')}
      >
        <Icon name="radar" size={14} />
        <span>{$t('recon.tabs.ports')}</span>
        {#if isJobRunning && activeJobKind === 'portscan'}
          <span class="tab-pulse-dot" aria-hidden="true"></span>
        {:else if portScanResult}
          <span class="tab-count tabular-nums">{portScanResult.open_count ?? 0}</span>
        {/if}
      </button>

      <button
        type="button"
        class="tab-btn"
        class:active={activeTab === 'history'}
        on:click={() => {
          activeTab = 'history'
          loadHistory()
        }}
      >
        <Icon name="clock" size={14} />
        <span>{$t('recon.tabs.history')}</span>
        {#if historyEntries.length > 0}
          <span class="tab-count tabular-nums">{historyEntries.length}</span>
        {/if}
      </button>
    </nav>

    <div class="strip-spacer"></div>

    <!-- Right Host Toolchain Status Pills -->
    <div class="toolchain-strip">
      {#each toolchainItems as tool (tool.key)}
        <button
          type="button"
          class="tool-pill"
          class:ready={tool.data.ready}
          class:active={showToolchainDrawer}
          title={tool.data.ready
            ? `${tool.data.name} ${tool.data.version || ''} (${tool.data.path || ''})`
            : (tool.data.issue || tool.data.install || tool.data.name)}
          on:click={toggleToolchainDrawer}
        >
          <span class="tool-dot" class:ready={tool.data.ready}></span>
          <span class="tool-name mono">{tool.data.name}</span>
          {#if tool.data.ready && tool.data.version}
            <span class="tool-ver mono">{tool.data.version}</span>
          {/if}
        </button>
      {/each}

      <Button
        variant="ghost"
        size="xs"
        icon="refresh"
        iconOnly
        loading={loadingToolchain}
        title={$t('recon.topbar.refreshToolchain')}
        on:click={() => loadToolchain(true)}
      />

      <Button
        variant="secondary"
        size="xs"
        icon="sliders"
        iconOnly
        active={showToolchainDrawer}
        title={$t('recon.topbar.configurePaths')}
        on:click={toggleToolchainDrawer}
      />
    </div>
  </header>

  <!-- Collapsible Paths Config Drawer -->
  {#if showToolchainDrawer}
    <section class="toolchain-drawer">
      <div class="drawer-head">
        <div>
          <div class="drawer-title">{$t('recon.toolchainDrawer.title')}</div>
          <div class="drawer-sub">{$t('recon.toolchainDrawer.subtitle')}</div>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (showToolchainDrawer = false)}>
          {$t('recon.toolchainDrawer.close')}
        </Button>
      </div>

      <div class="drawer-grid">
        <label class="d-field">
          <span class="d-field-head">
            <span>{$t('recon.toolchainDrawer.nmapLabel')}</span>
            <Badge variant={toolchain?.nmap?.ready ? 'success' : 'warning'} size="xs">
              {toolchain?.nmap?.ready ? (toolchain.nmap.version || $t('recon.topbar.ready')) : $t('recon.topbar.missing')}
            </Badge>
          </span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={cfgNmapPath}
            placeholder={$t('recon.toolchainDrawer.nmapPlaceholder')}
          />
          <span class="d-hint mono truncate" title={toolchain?.nmap?.path || toolchain?.nmap?.install || ''}>
            {#if toolchain?.nmap?.ready && toolchain?.nmap?.path}
              {$t('recon.toolchainDrawer.detectedPath', { path: toolchain.nmap.path })}
            {:else if toolchain?.nmap?.install}
              {$t('recon.toolchainDrawer.installHint', { cmd: toolchain.nmap.install })}
            {/if}
          </span>
        </label>

        <label class="d-field">
          <span class="d-field-head">
            <span>{$t('recon.toolchainDrawer.subfinderLabel')}</span>
            <Badge variant={toolchain?.subfinder?.ready ? 'success' : 'warning'} size="xs">
              {toolchain?.subfinder?.ready ? (toolchain.subfinder.version || $t('recon.topbar.ready')) : $t('recon.topbar.missing')}
            </Badge>
          </span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={cfgSubfinderPath}
            placeholder={$t('recon.toolchainDrawer.subfinderPlaceholder')}
          />
          <span class="d-hint mono truncate" title={toolchain?.subfinder?.path || toolchain?.subfinder?.install || ''}>
            {#if toolchain?.subfinder?.ready && toolchain?.subfinder?.path}
              {$t('recon.toolchainDrawer.detectedPath', { path: toolchain.subfinder.path })}
            {:else if toolchain?.subfinder?.install}
              {$t('recon.toolchainDrawer.installHint', { cmd: toolchain.subfinder.install })}
            {/if}
          </span>
        </label>

        <label class="d-field">
          <span class="d-field-head">
            <span>{$t('recon.toolchainDrawer.whoisLabel')}</span>
            <Badge variant={toolchain?.whois?.ready ? 'success' : 'warning'} size="xs">
              {toolchain?.whois?.ready ? (toolchain.whois.version || $t('recon.topbar.ready')) : $t('recon.topbar.missing')}
            </Badge>
          </span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={cfgWhoisPath}
            placeholder={$t('recon.toolchainDrawer.whoisPlaceholder')}
          />
          <span class="d-hint mono truncate" title={toolchain?.whois?.path || toolchain?.whois?.install || ''}>
            {#if toolchain?.whois?.ready && toolchain?.whois?.path}
              {$t('recon.toolchainDrawer.detectedPath', { path: toolchain.whois.path })}
            {:else if toolchain?.whois?.install}
              {$t('recon.toolchainDrawer.installHint', { cmd: toolchain.whois.install })}
            {/if}
          </span>
        </label>

        <label class="d-field">
          <span class="d-field-head">
            <span>{$t('recon.toolchainDrawer.digLabel')}</span>
            <Badge variant={toolchain?.dig?.ready ? 'success' : 'warning'} size="xs">
              {toolchain?.dig?.ready ? (toolchain.dig.version || $t('recon.topbar.ready')) : $t('recon.topbar.missing')}
            </Badge>
          </span>
          <input
            type="text"
            class="cap-input mono"
            bind:value={cfgDigPath}
            placeholder={$t('recon.toolchainDrawer.digPlaceholder')}
          />
          <span class="d-hint mono truncate" title={toolchain?.dig?.path || toolchain?.dig?.install || ''}>
            {#if toolchain?.dig?.ready && toolchain?.dig?.path}
              {$t('recon.toolchainDrawer.detectedPath', { path: toolchain.dig.path })}
            {:else if toolchain?.dig?.install}
              {$t('recon.toolchainDrawer.installHint', { cmd: toolchain.dig.install })}
            {/if}
          </span>
        </label>
      </div>

      {#if toolchain?.issues?.length}
        <div class="issues-box">
          {#each toolchain.issues as issue, i (i)}
            <div class="issue-line">
              <Icon name="info" size={12} />
              <span>{issue}</span>
            </div>
          {/each}
        </div>
      {/if}

      <div class="drawer-foot">
        <Button
          variant="primary"
          size="xs"
          icon="check"
          loading={savingToolchain}
          on:click={() => saveToolchainConfig(false)}
        >
          {savingToolchain ? $t('recon.toolchainDrawer.saving') : $t('recon.toolchainDrawer.saveProbe')}
        </Button>
        <Button
          variant="secondary"
          size="xs"
          icon="undo"
          disabled={savingToolchain}
          on:click={() => saveToolchainConfig(true)}
        >
          {$t('recon.toolchainDrawer.resetAuto')}
        </Button>
        <Button
          variant="ghost"
          size="xs"
          icon="refresh"
          loading={loadingToolchain}
          on:click={() => loadToolchain(true)}
        >
          {$t('recon.toolchainDrawer.reprobe')}
        </Button>
        <div class="strip-spacer"></div>
        {#if toolchain?.checked_at}
          <span class="hint-muted mono">
            {$t('recon.toolchainDrawer.checkedAt', { time: formatTime(toolchain.checked_at) })}
          </span>
        {/if}
      </div>
    </section>
  {/if}

  <!-- 2. Shared Smart Target Bar -->
  <section class="target-bar">
    <div class="target-input-wrap">
      <span class="target-icon">
        <Icon name="target" size={14} />
      </span>
      <input
        type="text"
        class="cap-input target-input mono"
        bind:value={target}
        placeholder={targetPlaceholder}
        aria-label={$t('recon.targetBar.label')}
        on:keydown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault()
            runPrimaryAction()
          }
        }}
      />
      {#if target}
        <button
          type="button"
          class="clear-target-btn"
          title={$t('recon.targetBar.clearTarget')}
          on:click={() => (target = '')}
        >
          <Icon name="x" size={12} />
        </button>
      {/if}
    </div>

    <!-- Captured Hosts Quick-Picker Dropdown -->
    <div class="captured-picker-wrap">
      <Button
        variant="secondary"
        size="sm"
        icon="activity"
        iconRight="chevron-down"
        active={showCapturedPicker}
        title={$t('recon.targetBar.capturedHostsTitle')}
        on:click={toggleCapturedPicker}
      >
        <span>{$t('recon.targetBar.capturedHosts')}</span>
        {#if capturedHosts.length > 0}
          <Badge variant="accent" size="xs" mono>{capturedHosts.length}</Badge>
        {/if}
      </Button>

      {#if showCapturedPicker}
        <div class="captured-dropdown">
          <div class="captured-head">
            <Icon name="search" size={13} />
            <input
              type="text"
              class="captured-search"
              bind:value={capturedSearch}
              placeholder={$t('recon.targetBar.capturedSearchPlaceholder')}
            />
            <Button
              variant="ghost"
              size="xs"
              icon="refresh"
              iconOnly
              loading={loadingCaptured}
              title={$t('recon.targetBar.capturedRefresh')}
              on:click={loadCapturedHosts}
            />
          </div>

          <div class="captured-list">
            {#if filteredCapturedHosts.length === 0}
              <div class="captured-empty">{$t('recon.targetBar.capturedEmpty')}</div>
            {:else}
              {#each filteredCapturedHosts as item (item.host)}
                <button
                  type="button"
                  class="captured-item"
                  on:click={() => selectCapturedHost(item)}
                >
                  <Badge variant={item.scheme === 'https' ? 'success' : 'info'} size="xs" mono>
                    {item.scheme.toUpperCase()}
                  </Badge>
                  <span class="captured-host mono truncate">{item.host}</span>
                  <span class="captured-count tabular-nums">
                    {$t('recon.targetBar.capturedRequests', { count: item.count })}
                  </span>
                </button>
              {/each}
            {/if}
          </div>
        </div>
      {/if}
    </div>

    <!-- Primary Tab Action -->
    {#if activeTab === 'domain'}
      <Button
        variant="primary"
        size="sm"
        icon="globe"
        loading={domainLoading}
        on:click={() => runDomainAnalysis()}
      >
        {domainLoading ? $t('recon.targetBar.runningDomain') : $t('recon.targetBar.runDomain')}
      </Button>
    {:else if activeTab === 'site'}
      <Button
        variant="primary"
        size="sm"
        icon="search"
        loading={siteLoading}
        on:click={() => runSiteProbe()}
      >
        {siteLoading ? $t('recon.targetBar.runningSite') : $t('recon.targetBar.runSite')}
      </Button>
    {:else if activeTab === 'subdomains'}
      <Button
        variant="primary"
        size="sm"
        icon="layers"
        loading={startingJob || (isJobRunning && activeJobKind === 'subdomain')}
        on:click={() => startSubdomainJob()}
      >
        {isJobRunning && activeJobKind === 'subdomain'
          ? $t('recon.targetBar.runningSubdomains')
          : $t('recon.targetBar.runSubdomains')}
      </Button>
    {:else if activeTab === 'ports'}
      <Button
        variant="primary"
        size="sm"
        icon="radar"
        loading={startingJob || (isJobRunning && activeJobKind === 'portscan')}
        disabled={portScanOpts.preset === 'custom' && !customPortsCheck.valid}
        on:click={() => startPortScanJob()}
      >
        {isJobRunning && activeJobKind === 'portscan'
          ? $t('recon.targetBar.runningPorts')
          : $t('recon.targetBar.runPorts')}
      </Button>
    {:else}
      <Button
        variant="secondary"
        size="sm"
        icon="refresh"
        loading={historyLoading}
        on:click={loadHistory}
      >
        {$t('recon.targetBar.refreshHistory')}
      </Button>
    {/if}

    <!-- Live Running Job Pill + Cancel Button -->
    {#if isJobRunning}
      <div class="active-job-group">
        <Badge variant="accent" size="md" dot pulse mono>
          {$t('recon.targetBar.activeJobBadge', {
            kind: activeJobKind,
            elapsed: formatClock(liveJobElapsedMs),
          })}
        </Badge>
        <Button
          variant="danger"
          size="sm"
          icon="square"
          loading={cancellingJob}
          on:click={cancelActiveJob}
        >
          {cancellingJob ? $t('recon.targetBar.cancelling') : $t('recon.targetBar.cancelJob')}
        </Button>
      </div>
    {/if}
  </section>

  <!-- 3. Main Scrollable Workspace Content -->
  <main class="workspace-body">
    <!-- ==================== TAB 1: DOMAIN INTEL ==================== -->
    {#if activeTab === 'domain'}
      {#if !domainReport}
        <EmptyState
          icon="globe"
          title={$t('recon.domain.emptyTitle')}
          description={$t('recon.domain.emptyDesc')}
        />
      {:else}
        <div class="tab-content">
          <!-- Domain Summary Hero -->
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="globe" size={16} />
                <h2 class="hero-target mono">{domainReport.target}</h2>
                {#if domainReport.root_domain && domainReport.root_domain !== domainReport.target}
                  <Badge variant="neutral" size="sm" mono>
                    {$t('recon.domain.rootDomain')}: {domainReport.root_domain}
                  </Badge>
                {/if}
                <Badge variant="neutral" size="xs" mono>
                  {formatDuration(domainReport.elapsed_ms)}
                </Badge>
              </div>
              <div class="card-actions">
                <Button
                  variant="secondary"
                  size="xs"
                  icon="search"
                  on:click={() => pivotToSite(domainReport.target, true)}
                >
                  {$t('recon.common.pivotSite')}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  icon="layers"
                  on:click={() => pivotToSubdomains(domainReport.root_domain || domainReport.target, false)}
                >
                  {$t('recon.common.pivotSubdomains')}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  icon="radar"
                  on:click={() => pivotToPorts(domainReport.target, false)}
                >
                  {$t('recon.common.pivotPorts')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  on:click={() => copyToClipboard(JSON.stringify(domainReport, null, 2))}
                >
                  {$t('recon.common.copyJson')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="download"
                  on:click={() => exportJsonReport(domainReport, 'domain', domainReport.target)}
                >
                  {$t('recon.common.exportJson')}
                </Button>
              </div>
            </div>

            <div class="meta-pill-grid">
              <div class="meta-group">
                <span class="meta-label">{$t('recon.domain.ipv4')}</span>
                <div class="pill-wrap">
                  {#if domainReport.ipv4?.length}
                    {#each domainReport.ipv4 as ip (ip)}
                      <button
                        type="button"
                        class="mono-chip"
                        title={$t('recon.common.copy')}
                        on:click={() => copyToClipboard(ip)}
                      >
                        <span>{ip}</span>
                        <Icon name="copy" size={10} />
                      </button>
                    {/each}
                  {:else}
                    <span class="muted-text">{$t('recon.common.none')}</span>
                  {/if}
                </div>
              </div>

              <div class="meta-group">
                <span class="meta-label">{$t('recon.domain.ipv6')}</span>
                <div class="pill-wrap">
                  {#if domainReport.ipv6?.length}
                    {#each domainReport.ipv6 as ip (ip)}
                      <button
                        type="button"
                        class="mono-chip"
                        title={$t('recon.common.copy')}
                        on:click={() => copyToClipboard(ip)}
                      >
                        <span>{ip}</span>
                        <Icon name="copy" size={10} />
                      </button>
                    {/each}
                  {:else}
                    <span class="muted-text">{$t('recon.common.none')}</span>
                  {/if}
                </div>
              </div>

              <div class="meta-group">
                <span class="meta-label">{$t('recon.domain.cdnProviders')} / {$t('recon.domain.wafHints')}</span>
                <div class="pill-wrap">
                  {#each domainReport.cdn_providers || [] as cdn (cdn)}
                    <Badge variant="info" size="sm">{cdn}</Badge>
                  {/each}
                  {#each domainReport.waf_hints || [] as waf (waf)}
                    <Badge variant="warning" size="sm" dot>{waf}</Badge>
                  {/each}
                  {#if !domainReport.cdn_providers?.length && !domainReport.waf_hints?.length}
                    <span class="muted-text">{$t('recon.domain.noInfraDetected')}</span>
                  {/if}
                </div>
              </div>
            </div>

            {#if domainReport.warnings?.length}
              <div class="warnings-banner">
                <Icon name="alert-triangle" size={13} />
                <div class="warnings-list">
                  {#each domainReport.warnings as w, idx (idx)}
                    <span>{w}</span>
                  {/each}
                </div>
              </div>
            {/if}
          </section>

          <!-- Structured DNS Table -->
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="list" size={15} />
                <h3 class="card-title">{$t('recon.domain.dnsTitle')}</h3>
                <Badge variant="neutral" size="xs" mono>{dnsRows.length}</Badge>
              </div>
            </div>

            {#if dnsRows.length === 0}
              <div class="card-empty">{$t('recon.domain.dnsEmpty')}</div>
            {:else}
              <div class="table-wrap">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th class="col-type">{$t('recon.domain.dnsType')}</th>
                      <th>{$t('recon.domain.dnsValue')}</th>
                      <th class="col-act"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each dnsRows as row, i (`${row.type}-${row.value}-${i}`)}
                      <tr>
                        <td>
                          <Badge variant={dnsTypeVariant(row.type)} size="xs" mono>{row.type}</Badge>
                        </td>
                        <td class="mono break-all">
                          {row.value}
                          {#if row.extra}
                            <span class="inline-meta">({row.extra})</span>
                          {/if}
                        </td>
                        <td class="col-act">
                          <Button
                            variant="ghost"
                            size="xs"
                            icon="copy"
                            iconOnly
                            title={$t('recon.common.copy')}
                            on:click={() => copyToClipboard(row.value)}
                          />
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>

          <!-- 2-Column Split: WHOIS Summary + TLS / SSL Cert & SANs -->
          <div class="two-col-grid">
            <!-- WHOIS Summary Card -->
            <section class="cap-card section-card">
              <div class="card-head">
                <div class="card-title-row">
                  <Icon name="file-text" size={15} />
                  <h3 class="card-title">{$t('recon.domain.whoisTitle')}</h3>
                </div>
                {#if domainReport.whois?.raw}
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={showWhoisRaw ? 'chevron-up' : 'chevron-down'}
                    on:click={() => (showWhoisRaw = !showWhoisRaw)}
                  >
                    {$t('recon.domain.whoisRawToggle')}
                  </Button>
                {/if}
              </div>

              {#if !domainReport.whois}
                <div class="card-empty">{$t('recon.domain.whoisUnavailable')}</div>
              {:else}
                <div class="kv-grid">
                  <div class="kv-row">
                    <span class="kv-k">{$t('recon.domain.whoisDomain')}</span>
                    <span class="kv-v mono">{domainReport.whois.domain || '—'}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-k">{$t('recon.domain.whoisRegistrar')}</span>
                    <span class="kv-v">{domainReport.whois.registrar || '—'}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-k">{$t('recon.domain.whoisCreated')}</span>
                    <span class="kv-v mono">{domainReport.whois.creation_date || '—'}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-k">{$t('recon.domain.whoisExpires')}</span>
                    <span class="kv-v mono">{domainReport.whois.expiry_date || '—'}</span>
                  </div>
                  <div class="kv-row">
                    <span class="kv-k">{$t('recon.domain.whoisUpdated')}</span>
                    <span class="kv-v mono">{domainReport.whois.updated_date || '—'}</span>
                  </div>
                </div>

                {#if domainReport.whois.name_servers?.length}
                  <div class="sub-block">
                    <div class="meta-label">{$t('recon.domain.whoisNameServers')}</div>
                    <div class="pill-wrap">
                      {#each domainReport.whois.name_servers as ns (ns)}
                        <Badge variant="neutral" size="xs" mono>{ns}</Badge>
                      {/each}
                    </div>
                  </div>
                {/if}

                {#if domainReport.whois.statuses?.length}
                  <div class="sub-block">
                    <div class="meta-label">{$t('recon.domain.whoisStatuses')}</div>
                    <div class="pill-wrap">
                      {#each domainReport.whois.statuses as st, i (`${st}-${i}`)}
                        <Badge variant="info" size="xs">{st}</Badge>
                      {/each}
                    </div>
                  </div>
                {/if}

                {#if showWhoisRaw && domainReport.whois.raw}
                  <div class="raw-block">
                    <div class="raw-head">
                      <span>
                        {$t('recon.domain.whoisRawToggle')}
                        {#if domainReport.whois.truncated}
                          <Badge variant="warning" size="xs">{$t('recon.domain.whoisTruncated')}</Badge>
                        {/if}
                      </span>
                      <Button
                        variant="ghost"
                        size="xs"
                        icon="copy"
                        on:click={() => copyToClipboard(domainReport.whois.raw)}
                      >
                        {$t('recon.common.copy')}
                      </Button>
                    </div>
                    <pre class="raw-pre mono">{domainReport.whois.raw}</pre>
                  </div>
                {/if}
              {/if}
            </section>

            <!-- TLS / SSL Certificate & SANs Card -->
            <section class="cap-card section-card">
              <div class="card-head">
                <div class="card-title-row">
                  <Icon name={domainReport.tls?.verified ? 'lock' : 'unlock'} size={15} />
                  <h3 class="card-title">{$t('recon.domain.tlsTitle')}</h3>
                </div>
                <div class="tls-port-probe">
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    class="cap-input tls-port-input mono"
                    bind:value={tlsInspectPort}
                    aria-label={$t('recon.domain.tlsPortPlaceholder')}
                    placeholder="443"
                  />
                  <Button
                    variant="secondary"
                    size="xs"
                    icon="lock"
                    loading={tlsInspectLoading}
                    on:click={runTlsInspect}
                  >
                    {tlsInspectLoading ? $t('recon.domain.tlsInspecting') : $t('recon.domain.tlsInspectBtn')}
                  </Button>
                </div>
              </div>

              {#if !domainReport.tls}
                <div class="card-empty">{$t('recon.domain.tlsUnavailable')}</div>
              {:else}
                {@const tls = domainReport.tls}
                {@const leaf = tls.leaf}
                {@const expiry = tlsExpiryBadge(leaf)}

                <div class="tls-badges">
                  {#if tls.host && tls.port}
                    <Badge variant="neutral" size="sm" mono>{tls.host}:{tls.port}</Badge>
                  {/if}
                  <Badge variant={tls.verified ? 'success' : 'warning'} size="sm" dot>
                    {tls.verified ? $t('recon.domain.tlsVerified') : $t('recon.domain.tlsUnverified')}
                  </Badge>
                  {#if tls.tls_version}
                    <Badge variant="accent" size="sm" mono>{tls.tls_version}</Badge>
                  {/if}
                  {#if tls.alpn}
                    <Badge variant="info" size="sm" mono>ALPN: {tls.alpn}</Badge>
                  {/if}
                  {#if leaf && expiry.text}
                    <Badge variant={expiry.variant} size="sm" mono>{expiry.text}</Badge>
                  {/if}
                  {#if leaf?.self_signed}
                    <Badge variant="warning" size="xs">{$t('recon.domain.tlsSelfSigned')}</Badge>
                  {/if}
                  {#if leaf?.is_ca}
                    <Badge variant="purple" size="xs">{$t('recon.domain.tlsIsCA')}</Badge>
                  {/if}
                </div>

                {#if tls.verify_error}
                  <div class="warnings-banner">
                    <Icon name="alert-circle" size={13} />
                    <span>{tls.verify_error}</span>
                  </div>
                {/if}

                {#if leaf}
                  <div class="kv-grid">
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsSubject')}</span>
                      <span class="kv-v mono break-all">{leaf.subject || leaf.common_name || '—'}</span>
                    </div>
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsIssuer')}</span>
                      <span class="kv-v mono break-all">{leaf.issuer || '—'}</span>
                    </div>
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsCipher')}</span>
                      <span class="kv-v mono break-all">{tls.cipher_suite || '—'}</span>
                    </div>
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsPublicKey')}</span>
                      <span class="kv-v mono">
                        {leaf.pub_key_algo || '—'}{#if leaf.pub_key_bits} ({leaf.pub_key_bits} bit){/if}
                        {#if leaf.signature_algo} · {leaf.signature_algo}{/if}
                      </span>
                    </div>
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsValidity')}</span>
                      <span class="kv-v mono">
                        {formatDateTime(leaf.not_before)} → {formatDateTime(leaf.not_after)}
                      </span>
                    </div>
                    <div class="kv-row">
                      <span class="kv-k">{$t('recon.domain.tlsFingerprint')}</span>
                      <span class="kv-v mono fingerprint-row">
                        <span class="truncate" title={leaf.sha256_fingerprint}>{leaf.sha256_fingerprint || '—'}</span>
                        {#if leaf.sha256_fingerprint}
                          <Button
                            variant="ghost"
                            size="xs"
                            icon="copy"
                            iconOnly
                            title={$t('recon.common.copy')}
                            on:click={() => copyToClipboard(leaf.sha256_fingerprint)}
                          />
                        {/if}
                      </span>
                    </div>
                  </div>

                  {#if leaf.sans?.length}
                    <div class="sub-block">
                      <div class="meta-label">
                        {$t('recon.domain.tlsSansTitle', { count: leaf.sans.length })}
                      </div>
                      <div class="hint-muted">{$t('recon.domain.tlsSansHint')}</div>
                      <div class="san-list">
                        {#each leaf.sans as san (san)}
                          <div class="san-pill">
                            <button
                              type="button"
                              class="san-main mono"
                              title={$t('recon.common.pivotSite')}
                              on:click={() => pivotToSite(san, true)}
                            >
                              <span>{san}</span>
                              <Icon name="arrow-right" size={10} />
                            </button>
                            <button
                              type="button"
                              class="san-sub-btn"
                              title={$t('recon.common.pivotSubdomains')}
                              on:click={() => pivotToSubdomains(san, false)}
                            >
                              <Icon name="layers" size={11} />
                            </button>
                          </div>
                        {/each}
                      </div>
                    </div>
                  {/if}
                {/if}

                {#if tls.chain?.length > 1}
                  <div class="sub-block">
                    <Button
                      variant="ghost"
                      size="xs"
                      icon={showTlsChain ? 'chevron-up' : 'chevron-down'}
                      on:click={() => (showTlsChain = !showTlsChain)}
                    >
                      {$t('recon.domain.tlsChainToggle', { count: tls.chain.length })}
                    </Button>
                    {#if showTlsChain}
                      <div class="chain-list">
                        {#each tls.chain as cert, idx (`${cert.serial || idx}-${idx}`)}
                          <div class="chain-item">
                            <Badge variant={cert.is_ca ? 'purple' : 'accent'} size="xs" mono>#{idx}</Badge>
                            <div class="chain-body">
                              <div class="mono chain-subj truncate">{cert.subject || cert.common_name}</div>
                              <div class="hint-muted mono truncate">
                                {cert.issuer} · {formatDateTime(cert.not_after)}
                              </div>
                            </div>
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}
              {/if}
            </section>
          </div>
        </div>
      {/if}

    <!-- ==================== TAB 2: SITE PROBE ==================== -->
    {:else if activeTab === 'site'}
      <div class="options-strip">
        <span class="opt-group-label">{$t('recon.site.optDiscovery')}:</span>
        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.probeRobots} />
          <span class="mono">{$t('recon.site.optRobots')}</span>
        </label>
        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.probeSitemap} />
          <span class="mono">{$t('recon.site.optSitemap')}</span>
        </label>
        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.probeWellKnown} />
          <span class="mono">{$t('recon.site.optWellKnown')}</span>
        </label>
        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.probeFavicon} />
          <span class="mono">{$t('recon.site.optFavicon')}</span>
        </label>

        <span class="v-sep"></span>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.insecureSkipVerify} />
          <span>{$t('recon.site.optSkipVerify')}</span>
        </label>
        <label class="chk-pill">
          <input type="checkbox" bind:checked={siteOpts.noRedirects} />
          <span>{$t('recon.site.optNoRedirects')}</span>
        </label>

        <label class="inline-num-field">
          <span>{$t('recon.site.optTimeout')}</span>
          <input
            type="number"
            min="1000"
            max="60000"
            step="1000"
            class="cap-input num-input mono"
            bind:value={siteOpts.timeoutMs}
          />
        </label>
      </div>

      {#if !siteProfile}
        <EmptyState
          icon="search"
          title={$t('recon.site.emptyTitle')}
          description={$t('recon.site.emptyDesc')}
        />
      {:else}
        <div class="tab-content">
          <!-- Site Hero Overview Card -->
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Badge status={siteProfile.status_code} size="md" />
                {#if siteProfile.protocol}
                  <Badge variant="neutral" size="sm" mono>{siteProfile.protocol}</Badge>
                {/if}
                <Badge variant="accent" size="sm" mono>
                  {formatDuration(siteProfile.elapsed_ms)}
                </Badge>
                {#if siteProfile.content_length > 0}
                  <Badge variant="neutral" size="sm" mono>
                    {formatBytes(siteProfile.content_length)}
                  </Badge>
                {/if}
                <h2 class="site-page-title truncate">
                  {siteProfile.title || $t('recon.site.noTitle')}
                </h2>
              </div>

              <div class="card-actions">
                <Button
                  variant="secondary"
                  size="xs"
                  icon="globe"
                  on:click={() => pivotToDomain(siteProfile.final_url || siteProfile.target_url, true)}
                >
                  {$t('recon.common.pivotDomain')}
                </Button>
                <Button
                  variant="secondary"
                  size="xs"
                  icon="radar"
                  on:click={() => pivotToPorts(siteProfile.final_url || siteProfile.target_url, false)}
                >
                  {$t('recon.common.pivotPorts')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  on:click={() => copyToClipboard(JSON.stringify(siteProfile, null, 2))}
                >
                  {$t('recon.common.copyJson')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="download"
                  on:click={() => exportJsonReport(siteProfile, 'site', siteProfile.final_url || siteProfile.target_url)}
                >
                  {$t('recon.common.exportJson')}
                </Button>
              </div>
            </div>

            <div class="site-meta-grid">
              <div class="kv-row">
                <span class="kv-k">{$t('recon.site.finalUrl')}</span>
                <span class="kv-v mono break-all">{siteProfile.final_url || siteProfile.target_url}</span>
              </div>
              <div class="kv-row">
                <span class="kv-k">{$t('recon.site.server')}</span>
                <span class="kv-v mono">{siteProfile.server || '—'}</span>
              </div>
              <div class="kv-row">
                <span class="kv-k">{$t('recon.site.contentType')}</span>
                <span class="kv-v mono">{siteProfile.content_type || '—'}</span>
              </div>
              {#if siteProfile.meta_generator}
                <div class="kv-row">
                  <span class="kv-k">{$t('recon.site.metaGenerator')}</span>
                  <span class="kv-v mono">{siteProfile.meta_generator}</span>
                </div>
              {/if}
              {#if siteOpts.probeFavicon && siteProfile.favicon_sha256}
                <div class="kv-row">
                  <span class="kv-k">{$t('recon.site.faviconHash')}</span>
                  <span class="kv-v mono fingerprint-row">
                    <span class="truncate" title={siteProfile.favicon_sha256}>{siteProfile.favicon_sha256}</span>
                    <Button
                      variant="ghost"
                      size="xs"
                      icon="copy"
                      iconOnly
                      title={$t('recon.common.copy')}
                      on:click={() => copyToClipboard(siteProfile.favicon_sha256)}
                    />
                  </span>
                </div>
              {/if}
            </div>

            <!-- Redirect Chain Breadcrumb -->
            {#if siteProfile.redirect_chain?.length}
              <div class="sub-block">
                <div class="meta-label">
                  {$t('recon.site.redirectsTitle', { count: siteProfile.redirect_chain.length })}
                </div>
                <div class="redirect-chain">
                  {#each siteProfile.redirect_chain as hop, idx (`${hop.url}-${idx}`)}
                    <div class="redirect-hop">
                      <Badge status={hop.status_code} size="xs" />
                      <span class="mono hop-url" title={hop.url}>{hop.url}</span>
                    </div>
                    <span class="hop-arrow">
                      <Icon name="arrow-right" size={12} />
                    </span>
                  {/each}
                  <div class="redirect-hop final">
                    <Badge status={siteProfile.status_code} size="xs" />
                    <span class="mono hop-url" title={siteProfile.final_url}>{siteProfile.final_url}</span>
                  </div>
                </div>
              </div>
            {/if}

            {#if siteProfile.warnings?.length}
              <div class="warnings-banner">
                <Icon name="alert-triangle" size={13} />
                <div class="warnings-list">
                  {#each siteProfile.warnings as w, idx (idx)}
                    <span>{w}</span>
                  {/each}
                </div>
              </div>
            {/if}
          </section>

          <!-- 2-Column Split: Tech Stack Fingerprints + Security Headers Audit -->
          <div class="two-col-grid site-split">
            <!-- Tech Stack Fingerprints -->
            <section class="cap-card section-card">
              <div class="card-head">
                <div class="card-title-row">
                  <Icon name="layers" size={15} />
                  <h3 class="card-title">
                    {$t('recon.site.techTitle', { count: siteProfile.technologies?.length || 0 })}
                  </h3>
                </div>
              </div>

              {#if siteProfile.cdn_providers?.length || siteProfile.waf_hints?.length}
                <div class="pill-wrap">
                  {#each siteProfile.cdn_providers || [] as cdn (cdn)}
                    <Badge variant="info" size="sm">CDN: {cdn}</Badge>
                  {/each}
                  {#each siteProfile.waf_hints || [] as waf (waf)}
                    <Badge variant="warning" size="sm" dot>WAF: {waf}</Badge>
                  {/each}
                </div>
              {/if}

              {#if groupedTechnologies.length === 0}
                <div class="card-empty">{$t('recon.site.techEmpty')}</div>
              {:else}
                <div class="tech-groups">
                  {#each groupedTechnologies as group (group.category)}
                    <div class="tech-group">
                      <div class="meta-label">
                        {techCategoryLabel(group.category, $t)}
                      </div>
                      <div class="pill-wrap">
                        {#each group.items as tech (`${tech.category}-${tech.name}`)}
                          <span
                            class="tech-chip"
                            title={`${tech.name}${tech.version ? ' ' + tech.version : ''} (${tech.confidence}) — ${tech.evidence || ''}`}
                          >
                            <Badge variant={techCategoryVariant(group.category)} size="sm">
                              {tech.name}{#if tech.version}&nbsp;{tech.version}{/if}
                            </Badge>
                            <span class="conf-dot conf-{tech.confidence || 'low'}"></span>
                          </span>
                        {/each}
                      </div>
                    </div>
                  {/each}
                </div>
              {/if}
            </section>

            <!-- Security Headers Audit with 0-100 Gauge -->
            <section class="cap-card section-card">
              <div class="card-head">
                <div class="card-title-row">
                  <Icon name="shield-check" size={15} />
                  <h3 class="card-title">{$t('recon.site.securityTitle')}</h3>
                </div>
                <span class="hint-muted tabular-nums">
                  {$t('recon.site.securitySummary', {
                    pass: securityAuditStats.pass,
                    warn: securityAuditStats.warn,
                    fail: securityAuditStats.fail,
                  })}
                </span>
              </div>

              <div class="sec-audit-top">
                <div class="score-gauge" aria-label={`${$t('recon.site.securityScore')}: ${securityAuditStats.score}/100`}>
                  <svg viewBox="0 0 84 84" width="84" height="84">
                    <circle
                      cx="42"
                      cy="42"
                      r={securityAuditStats.radius}
                      class="gauge-track"
                    />
                    <circle
                      cx="42"
                      cy="42"
                      r={securityAuditStats.radius}
                      class="gauge-fill tone-{securityAuditStats.tone}"
                      stroke-dasharray={securityAuditStats.circumference}
                      stroke-dashoffset={securityAuditStats.dashOffset}
                      transform="rotate(-90 42 42)"
                    />
                  </svg>
                  <div class="gauge-center">
                    <span class="gauge-num tabular-nums tone-{securityAuditStats.tone}">
                      {securityAuditStats.score}
                    </span>
                    <span class="gauge-sub">/100</span>
                  </div>
                </div>

                <div class="sec-table-wrap">
                  <table class="data-table compact-table">
                    <thead>
                      <tr>
                        <th>{$t('recon.site.secColHeader')}</th>
                        <th>{$t('recon.site.secColStatus')}</th>
                        <th>{$t('recon.site.secColScore')}</th>
                        <th>{$t('recon.site.secColValue')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {#each siteProfile.security_headers || [] as item (item.header)}
                        <tr>
                          <td class="mono fw-600">{item.header}</td>
                          <td>
                            <Badge
                              variant={item.status === 'pass' ? 'success' : item.status === 'warn' ? 'warning' : 'danger'}
                              size="xs"
                            >
                              {item.status === 'pass'
                                ? $t('recon.site.secStatusPass')
                                : item.status === 'warn'
                                  ? $t('recon.site.secStatusWarn')
                                  : $t('recon.site.secStatusFail')}
                            </Badge>
                          </td>
                          <td class="mono tabular-nums">{item.score}/{item.weight}</td>
                          <td class="sec-val-cell">
                            {#if item.value}
                              <div class="mono sec-val truncate" title={item.value}>{item.value}</div>
                            {:else}
                              <span class="muted-text">{$t('recon.site.secMissing')}</span>
                            {/if}
                            {#if item.recommendation}
                              <div class="sec-rec">{item.recommendation}</div>
                            {/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          </div>

          <!-- Discovery Artifacts: Robots.txt, Sitemap URLs, Well-Known Endpoints -->
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="link" size={15} />
                <h3 class="card-title">{$t('recon.site.discoveryTitle')}</h3>
              </div>
            </div>

            {#if !siteDiscoveryEnabled && !siteProfile.robots_rules && !siteProfile.sitemap_urls?.length && !siteProfile.well_known_paths?.length}
              <div class="card-empty">{$t('recon.site.discoverySkipped')}</div>
            {:else}
              <div class="discovery-grid">
                {#if siteOpts.probeRobots}
                  <div class="disc-panel">
                    <div class="disc-head">
                      <span class="disc-title mono">{$t('recon.site.robotsTitle')}</span>
                      {#if siteProfile.robots_rules?.found}
                        <Badge variant="success" size="xs">
                          {$t('recon.site.robotsFound', { lines: siteProfile.robots_rules.raw_lines || 0 })}
                        </Badge>
                      {:else}
                        <Badge variant="neutral" size="xs">{$t('recon.site.robotsNotFound')}</Badge>
                      {/if}
                    </div>
                    {#if siteProfile.robots_rules?.found}
                      {#if siteProfile.robots_rules.disallow?.length}
                        <div class="disc-sub">
                          <span class="meta-label">
                            {$t('recon.site.robotsDisallow', { count: siteProfile.robots_rules.disallow.length })}
                          </span>
                          <div class="disc-scroll-list mono">
                            {#each siteProfile.robots_rules.disallow as rule, idx (`d-${idx}`)}
                              <div class="disc-line disallow">{rule}</div>
                            {/each}
                          </div>
                        </div>
                      {/if}
                      {#if siteProfile.robots_rules.allow?.length}
                        <div class="disc-sub">
                          <span class="meta-label">
                            {$t('recon.site.robotsAllow', { count: siteProfile.robots_rules.allow.length })}
                          </span>
                          <div class="disc-scroll-list mono">
                            {#each siteProfile.robots_rules.allow as rule, idx (`a-${idx}`)}
                              <div class="disc-line allow">{rule}</div>
                            {/each}
                          </div>
                        </div>
                      {/if}
                      {#if siteProfile.robots_rules.sitemaps?.length}
                        <div class="disc-sub">
                          <span class="meta-label">
                            {$t('recon.site.robotsSitemaps', { count: siteProfile.robots_rules.sitemaps.length })}
                          </span>
                          <div class="disc-scroll-list mono">
                            {#each siteProfile.robots_rules.sitemaps as sm, idx (`sm-${idx}`)}
                              <div class="disc-line truncate" title={sm}>{sm}</div>
                            {/each}
                          </div>
                        </div>
                      {/if}
                    {/if}
                  </div>
                {/if}

                {#if siteOpts.probeSitemap}
                  <div class="disc-panel">
                    <div class="disc-head">
                      <span class="disc-title">
                        {$t('recon.site.sitemapTitle', { count: siteProfile.sitemap_urls?.length || 0 })}
                      </span>
                    </div>
                    {#if !siteProfile.sitemap_urls?.length}
                      <div class="muted-text">{$t('recon.site.sitemapEmpty')}</div>
                    {:else}
                      <div class="disc-scroll-list">
                        {#each siteProfile.sitemap_urls as loc (loc)}
                          <div class="sitemap-row">
                            <span class="mono truncate" title={loc}>{loc}</span>
                            <Button
                              variant="ghost"
                              size="xs"
                              icon="arrow-right"
                              iconOnly
                              title={$t('recon.common.pivotSite')}
                              on:click={() => pivotToSite(loc, true)}
                            />
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}

                {#if siteOpts.probeWellKnown}
                  <div class="disc-panel">
                    <div class="disc-head">
                      <span class="disc-title">
                        {$t('recon.site.wellKnownTitle', { count: siteProfile.well_known_paths?.length || 0 })}
                      </span>
                    </div>
                    {#if !siteProfile.well_known_paths?.length}
                      <div class="muted-text">{$t('recon.site.wellKnownEmpty')}</div>
                    {:else}
                      <div class="wk-list">
                        {#each siteProfile.well_known_paths as wk (wk.path)}
                          <div class="wk-item">
                            <div class="wk-item-head">
                              <span class="mono fw-600">{wk.path}</span>
                              <div class="wk-badges">
                                <Badge status={wk.status_code} size="xs" />
                                <Badge variant={wk.found ? 'success' : 'neutral'} size="xs">
                                  {wk.found ? $t('recon.site.wellKnownFound') : $t('recon.site.wellKnownMissing')}
                                </Badge>
                              </div>
                            </div>
                            {#if wk.found && wk.snippet}
                              <pre class="wk-snippet mono">{wk.snippet}</pre>
                            {/if}
                          </div>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            {/if}
          </section>

          <!-- Collapsible Raw Response Headers -->
          {#if siteHeaderEntries.length > 0}
            <section class="cap-card section-card">
              <div class="card-head">
                <div class="card-title-row">
                  <Icon name="file-code" size={15} />
                  <h3 class="card-title">
                    {$t('recon.site.headersTitle', { count: siteHeaderEntries.length })}
                  </h3>
                </div>
                <Button
                  variant="ghost"
                  size="xs"
                  icon={showSiteHeaders ? 'chevron-up' : 'chevron-down'}
                  on:click={() => (showSiteHeaders = !showSiteHeaders)}
                >
                  {showSiteHeaders ? $t('recon.common.collapse') : $t('recon.common.expand')}
                </Button>
              </div>
              {#if showSiteHeaders}
                <div class="table-wrap">
                  <table class="data-table compact-table">
                    <tbody>
                      {#each siteHeaderEntries as [k, v] (k)}
                        <tr>
                          <td class="mono fw-600 header-key-col">{k}</td>
                          <td class="mono break-all">{v}</td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </section>
          {/if}
        </div>
      {/if}

    <!-- ==================== TAB 3: SUBDOMAINS ==================== -->
    {:else if activeTab === 'subdomains'}
      <div class="options-strip">
        <label class="chk-pill">
          <input type="checkbox" bind:checked={subdomainOpts.useSubfinder} />
          <span>{$t('recon.subdomains.srcSubfinder')}</span>
          <Badge variant={toolchain?.subfinder?.ready ? 'success' : 'neutral'} size="xs">
            {toolchain?.subfinder?.ready ? $t('recon.topbar.ready') : $t('recon.topbar.missing')}
          </Badge>
        </label>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={subdomainOpts.useCTLog} />
          <span>{$t('recon.subdomains.srcCTLog')}</span>
        </label>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={subdomainOpts.useCommonDNS} />
          <span>{$t('recon.subdomains.srcCommonDNS')}</span>
        </label>

        <span class="v-sep"></span>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={subdomainOpts.resolveDNS} />
          <span>{$t('recon.subdomains.optResolveIPs')}</span>
        </label>

        <label class="inline-num-field">
          <span>{$t('recon.subdomains.optTimeoutSec')}</span>
          <input
            type="number"
            min="5"
            max="300"
            class="cap-input num-input mono"
            bind:value={subdomainOpts.timeoutSec}
          />
        </label>
      </div>

      <div class="tab-content">
        <!-- Live Console for Subdomain Jobs -->
        {#if jobState && (jobState.kind === 'subdomain' || (isJobRunning && activeJobKind === 'subdomain'))}
          <section class="cap-card console-card">
            <div class="console-head">
              <div class="card-title-row">
                <Icon name="terminal" size={14} />
                <span class="card-title">{$t('recon.console.title')}</span>
                <Badge variant={jobStatusVariant(jobState.status)} size="xs" dot pulse={isJobRunning}>
                  {jobStatusLabel(jobState.status)}
                </Badge>
                <span class="hint-muted mono tabular-nums">{formatClock(liveJobElapsedMs)}</span>
                <span class="hint-muted tabular-nums">
                  {$t('recon.console.eventsCount', { count: jobState.events?.length || 0 })}
                </span>
              </div>

              <div class="console-controls">
                <div class="seg-toggle">
                  {#each CONSOLE_FILTERS as f (f)}
                    <button
                      type="button"
                      class="seg-btn"
                      class:active={consoleFilter === f}
                      on:click={() => (consoleFilter = f)}
                    >
                      {$t(`recon.console.filters.${f}`)}
                    </button>
                  {/each}
                </div>
                <label class="chk-inline">
                  <input type="checkbox" bind:checked={consoleAutoScroll} />
                  <span>{$t('recon.console.autoScroll')}</span>
                </label>
                <Button variant="ghost" size="xs" icon="trash" on:click={clearJobLogs}>
                  {$t('recon.console.clearLogs')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon={consoleCollapsed ? 'chevron-down' : 'chevron-up'}
                  iconOnly
                  on:click={() => (consoleCollapsed = !consoleCollapsed)}
                />
              </div>
            </div>

            {#if !consoleCollapsed}
              <div class="console-body mono" bind:this={consoleEl}>
                {#if activeConsoleEvents.length === 0}
                  <div class="console-empty">{$t('recon.console.empty')}</div>
                {:else}
                  {#each activeConsoleEvents as ev (`${ev.job_id || ''}-${ev.seq}`)}
                    <div class="log-line lvl-{ev.level || 'info'}">
                      <span class="log-ts tabular-nums">{formatTime(ev.timestamp_ms)}</span>
                      <span class="log-lvl">{(ev.level || 'info').toUpperCase()}</span>
                      <span class="log-msg">{ev.message}</span>
                    </div>
                  {/each}
                {/if}
              </div>
            {/if}
          </section>
        {/if}

        {#if !subdomainReport}
          {#if !(isJobRunning && activeJobKind === 'subdomain')}
            <EmptyState
              icon="layers"
              title={$t('recon.subdomains.emptyTitle')}
              description={$t('recon.subdomains.emptyDesc')}
            />
          {/if}
        {:else}
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="layers" size={15} />
                <h2 class="hero-target mono">{subdomainReport.domain}</h2>
                <Badge variant="accent" size="sm" mono>
                  {$t('recon.subdomains.totalFound', { count: subdomainReport.total_count ?? subdomainReport.subdomains?.length ?? 0 })}
                </Badge>
                <Badge variant="neutral" size="xs" mono>
                  {formatDuration(subdomainReport.elapsed_ms)}
                </Badge>
                {#if subdomainReport.wildcard_detected}
                  <Badge variant="warning" size="sm" dot>
                    {$t('recon.subdomains.wildcardTitle')}
                  </Badge>
                {/if}
              </div>

              <div class="card-actions">
                <Button
                  variant="secondary"
                  size="xs"
                  icon="copy"
                  on:click={() => {
                    const hosts = filteredSubdomains.map((e) => e.hostname).join('\n')
                    copyToClipboard(
                      hosts,
                      translate('recon.toast.copiedHosts', { count: filteredSubdomains.length })
                    )
                  }}
                >
                  {$t('recon.subdomains.copyHosts')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="download"
                  on:click={() => exportJsonReport(subdomainReport, 'subdomains', subdomainReport.domain)}
                >
                  {$t('recon.common.exportJson')}
                </Button>
              </div>
            </div>

            {#if subdomainReport.wildcard_detected}
              <div class="warnings-banner">
                <Icon name="alert-triangle" size={14} />
                <span>
                  {$t('recon.subdomains.wildcardDesc', {
                    ips: (subdomainReport.wildcard_ips || []).join(', ') || '—',
                  })}
                </span>
              </div>
            {/if}

            {#if subdomainReport.warnings?.length}
              <div class="warnings-banner subtle">
                <Icon name="info" size={13} />
                <div class="warnings-list">
                  {#each subdomainReport.warnings as w, idx (idx)}
                    <span>{w}</span>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Search & Source Filter Bar -->
            <div class="filter-bar">
              <div class="search-box">
                <Icon name="search" size={13} />
                <input
                  type="text"
                  class="search-input"
                  bind:value={subdomainSearch}
                  placeholder={$t('recon.subdomains.searchPlaceholder')}
                />
              </div>

              <div class="seg-toggle">
                <button
                  type="button"
                  class="seg-btn"
                  class:active={subdomainSourceFilter === 'all'}
                  on:click={() => (subdomainSourceFilter = 'all')}
                >
                  {$t('recon.common.all')}
                </button>
                {#each subdomainSources as src (src)}
                  <button
                    type="button"
                    class="seg-btn mono"
                    class:active={subdomainSourceFilter === src}
                    on:click={() => (subdomainSourceFilter = src)}
                  >
                    {src}
                  </button>
                {/each}
              </div>
            </div>

            {#if filteredSubdomains.length === 0}
              <div class="card-empty">{$t('recon.subdomains.noMatches')}</div>
            {:else}
              <div class="table-wrap">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th class="col-idx">{$t('recon.subdomains.colIndex')}</th>
                      <th>{$t('recon.subdomains.colHostname')}</th>
                      <th>{$t('recon.subdomains.colSources')}</th>
                      <th>{$t('recon.subdomains.colIPs')}</th>
                      <th>{$t('recon.subdomains.colCNAME')}</th>
                      <th class="col-pivots">{$t('recon.subdomains.colActions')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each filteredSubdomains as entry, idx (entry.hostname)}
                      <tr>
                        <td class="col-idx mono tabular-nums muted-text">{idx + 1}</td>
                        <td class="mono fw-600">
                          <button
                            type="button"
                            class="inline-copy-btn mono"
                            title={$t('recon.common.copy')}
                            on:click={() => copyToClipboard(entry.hostname)}
                          >
                            {entry.hostname}
                          </button>
                        </td>
                        <td>
                          <div class="pill-wrap">
                            {#each entry.sources || [] as src (src)}
                              <Badge
                                variant={src === 'subfinder' ? 'accent' : src === 'crt.sh' ? 'purple' : 'info'}
                                size="xs"
                                mono
                              >
                                {src}
                              </Badge>
                            {/each}
                          </div>
                        </td>
                        <td>
                          <div class="pill-wrap">
                            {#if entry.ips?.length}
                              {#each entry.ips as ip (ip)}
                                <Badge variant="neutral" size="xs" mono>{ip}</Badge>
                              {/each}
                            {:else}
                              <span class="muted-text">—</span>
                            {/if}
                          </div>
                        </td>
                        <td class="mono muted-text">{entry.cname || '—'}</td>
                        <td class="col-pivots">
                          <div class="pivot-btns">
                            <Button
                              variant="secondary"
                              size="xs"
                              icon="search"
                              iconRight="arrow-right"
                              on:click={() => pivotToSite(entry.hostname, true)}
                            >
                              {$t('recon.common.pivotSite')}
                            </Button>
                            <Button
                              variant="subtle"
                              size="xs"
                              icon="radar"
                              iconRight="arrow-right"
                              on:click={() => pivotToPorts(entry.hostname, false)}
                            >
                              {$t('recon.common.pivotPorts')}
                            </Button>
                          </div>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>
        {/if}
      </div>

    <!-- ==================== TAB 4: PORTS & NMAP ==================== -->
    {:else if activeTab === 'ports'}
      <div class="options-strip ports-options">
        <div class="opt-cluster">
          <span class="opt-group-label">{$t('recon.ports.engineLabel')}</span>
          <div class="seg-toggle">
            {#each PORT_ENGINES as eng (eng)}
              <button
                type="button"
                class="seg-btn"
                class:active={portScanOpts.engine === eng}
                on:click={() => (portScanOpts.engine = eng)}
              >
                {$t(`recon.ports.engines.${eng}`)}
                {#if eng === 'nmap' && toolchain && !toolchain.nmap?.ready}
                  <span class="warn-dot" title={toolchain.nmap?.issue || ''}></span>
                {/if}
              </button>
            {/each}
          </div>
        </div>

        <span class="v-sep"></span>

        <div class="opt-cluster">
          <span class="opt-group-label">{$t('recon.ports.presetLabel')}</span>
          <div class="seg-toggle">
            {#each PORT_PRESETS as preset (preset)}
              <button
                type="button"
                class="seg-btn"
                class:active={portScanOpts.preset === preset}
                on:click={() => (portScanOpts.preset = preset)}
              >
                {$t(`recon.ports.presets.${preset}`)}
              </button>
            {/each}
          </div>
        </div>

        {#if portScanOpts.preset === 'custom'}
          <div class="custom-ports-wrap">
            <input
              type="text"
              class="cap-input custom-ports-input mono"
              class:invalid={!customPortsCheck.valid}
              bind:value={portScanOpts.portsSpec}
              placeholder={$t('recon.ports.customPortsPlaceholder')}
              aria-label={$t('recon.ports.customPortsLabel')}
            />
            {#if customPortsCheck.valid}
              <Badge variant="success" size="xs" mono>
                {$t('recon.ports.customPortsCount', { count: customPortsCheck.count })}
              </Badge>
            {:else}
              <span class="validation-err">{$t(customPortsCheck.errorKey)}</span>
            {/if}
          </div>
        {/if}

        <span class="v-sep"></span>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={portScanOpts.serviceVersion} />
          <span>{$t('recon.ports.optServiceVersion')}</span>
        </label>

        <label class="chk-pill">
          <input type="checkbox" bind:checked={portScanOpts.skipHostDiscovery} />
          <span>{$t('recon.ports.optSkipPing')}</span>
        </label>

        <label class="inline-num-field">
          <span>{$t('recon.ports.optTimeoutMs')}</span>
          <input
            type="number"
            min="200"
            max="10000"
            step="100"
            class="cap-input num-input mono"
            bind:value={portScanOpts.timeoutMs}
          />
        </label>
      </div>

      <div class="tab-content">
        <!-- Live Console for Port Scan Jobs -->
        {#if jobState && (jobState.kind === 'portscan' || (isJobRunning && activeJobKind === 'portscan'))}
          <section class="cap-card console-card">
            <div class="console-head">
              <div class="card-title-row">
                <Icon name="terminal" size={14} />
                <span class="card-title">{$t('recon.console.title')}</span>
                <Badge variant={jobStatusVariant(jobState.status)} size="xs" dot pulse={isJobRunning}>
                  {jobStatusLabel(jobState.status)}
                </Badge>
                <span class="hint-muted mono tabular-nums">{formatClock(liveJobElapsedMs)}</span>
                <span class="hint-muted tabular-nums">
                  {$t('recon.console.eventsCount', { count: jobState.events?.length || 0 })}
                </span>
              </div>

              <div class="console-controls">
                <div class="seg-toggle">
                  {#each CONSOLE_FILTERS as f (f)}
                    <button
                      type="button"
                      class="seg-btn"
                      class:active={consoleFilter === f}
                      on:click={() => (consoleFilter = f)}
                    >
                      {$t(`recon.console.filters.${f}`)}
                    </button>
                  {/each}
                </div>
                <label class="chk-inline">
                  <input type="checkbox" bind:checked={consoleAutoScroll} />
                  <span>{$t('recon.console.autoScroll')}</span>
                </label>
                <Button variant="ghost" size="xs" icon="trash" on:click={clearJobLogs}>
                  {$t('recon.console.clearLogs')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon={consoleCollapsed ? 'chevron-down' : 'chevron-up'}
                  iconOnly
                  on:click={() => (consoleCollapsed = !consoleCollapsed)}
                />
              </div>
            </div>

            {#if !consoleCollapsed}
              <div class="console-body mono" bind:this={consoleEl}>
                {#if activeConsoleEvents.length === 0}
                  <div class="console-empty">{$t('recon.console.empty')}</div>
                {:else}
                  {#each activeConsoleEvents as ev (`${ev.job_id || ''}-${ev.seq}`)}
                    <div class="log-line lvl-{ev.level || 'info'}">
                      <span class="log-ts tabular-nums">{formatTime(ev.timestamp_ms)}</span>
                      <span class="log-lvl">{(ev.level || 'info').toUpperCase()}</span>
                      <span class="log-msg">{ev.message}</span>
                    </div>
                  {/each}
                {/if}
              </div>
            {/if}
          </section>
        {/if}

        {#if !portScanResult}
          {#if !(isJobRunning && activeJobKind === 'portscan')}
            <EmptyState
              icon="radar"
              title={$t('recon.ports.emptyTitle')}
              description={$t('recon.ports.emptyDesc')}
            />
          {/if}
        {:else}
          <!-- Port Scan Summary Card -->
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="radar" size={15} />
                <h2 class="hero-target mono">{portScanResult.target}</h2>
                <Badge variant={portScanResult.engine === 'nmap' ? 'purple' : 'info'} size="sm" mono>
                  {portScanResult.engine}
                </Badge>
                <Badge variant="neutral" size="sm" mono>{portScanResult.preset}</Badge>
                <Badge variant={portScanResult.open_count > 0 ? 'success' : 'neutral'} size="sm" mono>
                  {$t('recon.ports.summaryOpen', { open: portScanResult.open_count ?? 0 })}
                </Badge>
                <Badge variant="neutral" size="xs" mono>
                  {$t('recon.ports.summaryScanned', { total: portScanResult.total_scanned ?? 0 })}
                </Badge>
                <Badge variant="neutral" size="xs" mono>
                  {formatDuration(portScanResult.elapsed_ms)}
                </Badge>
              </div>

              <div class="card-actions">
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  on:click={() => copyToClipboard(JSON.stringify(portScanResult, null, 2))}
                >
                  {$t('recon.common.copyJson')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="download"
                  on:click={() => exportJsonReport(portScanResult, 'portscan', portScanResult.target)}
                >
                  {$t('recon.common.exportJson')}
                </Button>
              </div>
            </div>

            {#if portScanResult.command}
              <div class="cmd-banner">
                <span class="meta-label">{$t('recon.ports.commandLabel')}</span>
                <code class="cmd-text mono truncate" title={portScanResult.command}>{portScanResult.command}</code>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  iconOnly
                  title={$t('recon.common.copy')}
                  on:click={() => copyToClipboard(portScanResult.command)}
                />
              </div>
            {/if}

            {#if portScanResult.warnings?.length}
              <div class="warnings-banner">
                <Icon name="alert-triangle" size={13} />
                <div class="warnings-list">
                  {#each portScanResult.warnings as w, idx (idx)}
                    <span>{w}</span>
                  {/each}
                </div>
              </div>
            {/if}

            <div class="filter-bar">
              <div class="search-box">
                <Icon name="search" size={13} />
                <input
                  type="text"
                  class="search-input"
                  bind:value={portSearch}
                  placeholder={$t('recon.ports.searchPlaceholder')}
                />
              </div>

              <div class="seg-toggle">
                <button
                  type="button"
                  class="seg-btn"
                  class:active={portStateFilter === 'all'}
                  on:click={() => (portStateFilter = 'all')}
                >
                  {$t('recon.ports.stateAll')}
                </button>
                <button
                  type="button"
                  class="seg-btn"
                  class:active={portStateFilter === 'open'}
                  on:click={() => (portStateFilter = 'open')}
                >
                  {$t('recon.ports.stateOpen')}
                </button>
                <button
                  type="button"
                  class="seg-btn"
                  class:active={portStateFilter === 'filtered'}
                  on:click={() => (portStateFilter = 'filtered')}
                >
                  {$t('recon.ports.stateFiltered')}
                </button>
              </div>
            </div>
          </section>

          {#if filteredPortHosts.length === 0}
            <div class="cap-card card-empty">{$t('recon.ports.noHosts')}</div>
          {:else}
            {#each filteredPortHosts as host, hIdx (`${host.address}-${hIdx}`)}
              <section class="cap-card section-card">
                <div class="card-head">
                  <div class="card-title-row">
                    <Badge
                      variant={host.state === 'up' ? 'success' : host.state === 'down' ? 'danger' : 'neutral'}
                      size="xs"
                      dot
                    >
                      {host.state === 'up'
                        ? $t('recon.ports.hostStateUp')
                        : host.state === 'down'
                          ? $t('recon.ports.hostStateDown')
                          : $t('recon.ports.hostStateUnknown')}
                    </Badge>
                    <span class="mono fw-600">{host.address}</span>
                    {#if host.hostname && host.hostname !== host.address}
                      <span class="hint-muted mono">({host.hostname})</span>
                    {/if}
                    {#if host.addr_type}
                      <Badge variant="neutral" size="xs" mono>{host.addr_type}</Badge>
                    {/if}
                    {#if host.os_guess}
                      <Badge variant="purple" size="xs">
                        {$t('recon.ports.osGuess', { os: host.os_guess })}
                      </Badge>
                    {/if}
                  </div>
                  <Badge variant="success" size="xs" mono>
                    {$t('recon.ports.openCountBadge', {
                      count: (host.ports || []).filter((p) => p.state === 'open').length,
                    })}
                  </Badge>
                </div>

                {#if host.filteredPorts.length === 0}
                  <div class="card-empty">{$t('recon.ports.noOpenPorts')}</div>
                {:else}
                  <div class="table-wrap">
                    <table class="data-table">
                      <thead>
                        <tr>
                          <th>{$t('recon.ports.colPort')}</th>
                          <th>{$t('recon.ports.colState')}</th>
                          <th>{$t('recon.ports.colService')}</th>
                          <th>{$t('recon.ports.colProduct')}</th>
                          <th>{$t('recon.ports.colLatency')}</th>
                          <th>{$t('recon.ports.colBanner')}</th>
                          <th class="col-pivots">{$t('recon.ports.colAction')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each host.filteredPorts as p (`${p.protocol}-${p.port}`)}
                          <tr>
                            <td class="mono fw-600 tabular-nums">{p.port}/{p.protocol || 'tcp'}</td>
                            <td>
                              <Badge variant={portStateVariant(p.state)} size="xs" mono>
                                {p.state}
                              </Badge>
                            </td>
                            <td class="mono">{p.service || '—'}</td>
                            <td class="mono">
                              {#if p.product || p.version}
                                <span>{p.product || ''} {p.version || ''}</span>
                                {#if p.extra_info}
                                  <span class="inline-meta">({p.extra_info})</span>
                                {/if}
                              {:else}
                                <span class="muted-text">—</span>
                              {/if}
                            </td>
                            <td class="mono tabular-nums muted-text">
                              {p.latency_ms ? `${p.latency_ms}ms` : '—'}
                            </td>
                            <td class="banner-cell">
                              {#if p.banner}
                                <button
                                  type="button"
                                  class="banner-preview mono truncate"
                                  title={p.banner}
                                  on:click={() => copyToClipboard(p.banner)}
                                >
                                  {p.banner}
                                </button>
                              {:else}
                                <span class="muted-text">—</span>
                              {/if}
                            </td>
                            <td class="col-pivots">
                              <div class="pivot-btns">
                                {#if p.state === 'open' && isHttpLikePort(p)}
                                  <Button
                                    variant="secondary"
                                    size="xs"
                                    icon="search"
                                    iconRight="arrow-right"
                                    on:click={() => pivotToSite(buildPortProbeUrl(host, p), true)}
                                  >
                                    {$t('recon.ports.probeHttp')}
                                  </Button>
                                {/if}
                                {#if p.state === 'open' && isHttpsLikePort(p)}
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    icon="lock"
                                    iconOnly
                                    title={$t('recon.common.pivotTls')}
                                    on:click={() => pivotToTls(host.hostname || host.address, p.port)}
                                  />
                                {/if}
                              </div>
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}
              </section>
            {/each}
          {/if}
        {/if}
      </div>

    <!-- ==================== TAB 5: SCAN HISTORY ==================== -->
    {:else}
      <div class="tab-content">
        <section class="cap-card section-card">
          <div class="filter-bar">
            <div class="seg-toggle">
              {#each HISTORY_KINDS as k (k)}
                <button
                  type="button"
                  class="seg-btn"
                  class:active={historyKindFilter === k}
                  on:click={() => (historyKindFilter = k)}
                >
                  {$t(`recon.history.kinds.${k}`)}
                </button>
              {/each}
            </div>

            <div class="search-box">
              <Icon name="search" size={13} />
              <input
                type="text"
                class="search-input"
                bind:value={historySearch}
                placeholder={$t('recon.history.searchPlaceholder')}
              />
            </div>

            <div class="strip-spacer"></div>

            {#if historyEntries.length > 0}
              {#if confirmClearHistory}
                <Button variant="danger" size="xs" icon="trash" on:click={clearAllHistory}>
                  {$t('recon.history.confirmClearAll')}
                </Button>
                <Button variant="ghost" size="xs" on:click={() => (confirmClearHistory = false)}>
                  {$t('recon.history.cancelConfirm')}
                </Button>
              {:else}
                <Button
                  variant="ghost"
                  size="xs"
                  icon="trash"
                  on:click={() => (confirmClearHistory = true)}
                >
                  {$t('recon.history.clearAll')}
                </Button>
              {/if}
            {/if}
          </div>

          {#if historyEntries.length === 0}
            <EmptyState
              icon="clock"
              compact
              title={$t('recon.history.emptyTitle')}
              description={$t('recon.history.emptyDesc')}
            />
          {:else if filteredHistory.length === 0}
            <div class="card-empty">{$t('recon.history.noMatches')}</div>
          {:else}
            <div class="table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>{$t('recon.history.colKind')}</th>
                    <th>{$t('recon.history.colTarget')}</th>
                    <th>{$t('recon.history.colSummary')}</th>
                    <th>{$t('recon.history.colStatus')}</th>
                    <th>{$t('recon.history.colElapsed')}</th>
                    <th>{$t('recon.history.colCreated')}</th>
                    <th class="col-pivots">{$t('recon.history.colActions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredHistory as entry (entry.id)}
                    <tr class:selected-row={selectedHistoryId === entry.id}>
                      <td>
                        <Badge variant={historyKindVariant(entry.kind)} size="xs" mono>
                          {historyKindLabel(entry.kind, $t)}
                        </Badge>
                      </td>
                      <td class="mono fw-600">
                        <button
                          type="button"
                          class="inline-copy-btn mono"
                          on:click={() => openHistoryEntry(entry.id, false)}
                        >
                          {entry.target}
                        </button>
                      </td>
                      <td class="summary-cell">{entry.summary || '—'}</td>
                      <td>
                        <Badge variant={jobStatusVariant(entry.status)} size="xs" mono>
                          {entry.status}
                        </Badge>
                      </td>
                      <td class="mono tabular-nums muted-text">
                        {formatDuration(entry.elapsed_ms)}
                      </td>
                      <td class="mono tabular-nums muted-text">
                        {formatDateTime(entry.created_at)}
                      </td>
                      <td class="col-pivots">
                        <div class="pivot-btns">
                          <Button
                            variant="secondary"
                            size="xs"
                            icon="eye"
                            on:click={() => openHistoryEntry(entry.id, true)}
                          >
                            {$t('recon.history.openRestore')}
                          </Button>
                          <Button
                            variant="ghost"
                            size="xs"
                            icon="copy"
                            iconOnly
                            title={$t('recon.common.copyJson')}
                            on:click={() => copyHistoryJson(entry.id)}
                          />
                          <Button
                            variant="ghost"
                            size="xs"
                            icon="download"
                            iconOnly
                            title={$t('recon.common.exportJson')}
                            on:click={() => exportHistoryJson(entry.id)}
                          />
                          <Button
                            variant="ghost"
                            size="xs"
                            icon="trash"
                            iconOnly
                            title={$t('recon.history.deleteItem')}
                            on:click={() => deleteHistoryEntry(entry.id)}
                          />
                        </div>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>

        {#if previewHistoryEntry}
          <section class="cap-card section-card">
            <div class="card-head">
              <div class="card-title-row">
                <Icon name="file-code" size={14} />
                <h3 class="card-title">{$t('recon.history.previewTitle')}</h3>
                <Badge variant={historyKindVariant(previewHistoryEntry.kind)} size="xs" mono>
                  {previewHistoryEntry.kind}
                </Badge>
                <span class="mono hint-muted">{previewHistoryEntry.target}</span>
              </div>
              <div class="card-actions">
                <Button
                  variant="secondary"
                  size="xs"
                  icon="eye"
                  on:click={() => openHistoryEntry(previewHistoryEntry.id, true)}
                >
                  {$t('recon.history.openRestore')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  on:click={() => copyToClipboard(JSON.stringify(previewHistoryEntry, null, 2))}
                >
                  {$t('recon.common.copyJson')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="download"
                  on:click={() => exportJsonReport(previewHistoryEntry, previewHistoryEntry.kind || 'history', previewHistoryEntry.target)}
                >
                  {$t('recon.common.exportJson')}
                </Button>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="x"
                  iconOnly
                  on:click={() => (previewHistoryEntry = null)}
                />
              </div>
            </div>
            <pre class="raw-pre mono">{JSON.stringify(previewHistoryEntry, null, 2)}</pre>
          </section>
        {/if}
      </div>
    {/if}
  </main>
</div>

<style>
  .recon-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
    color: var(--text-primary);
    overflow: hidden;
  }

  /* ==================== Top Single-Tier Strip ==================== */
  .top-strip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    min-height: 42px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .tab-strip {
    display: flex;
    align-items: center;
    gap: 2px;
    height: 42px;
  }

  .tab-btn {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 42px;
    padding: 0 11px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: color var(--transition-fast), background var(--transition-fast);
  }

  .tab-btn:hover {
    color: var(--text-primary);
    background: var(--bg-subtle);
  }

  .tab-btn.active {
    color: var(--accent);
    font-weight: 600;
  }

  .tab-btn.active::after {
    content: '';
    position: absolute;
    left: 8px;
    right: 8px;
    bottom: 0;
    height: 2px;
    background: var(--accent);
    border-radius: 2px 2px 0 0;
  }

  .tab-pulse-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--accent);
    animation: cap-pulse 1.4s ease-in-out infinite;
  }

  .tab-count,
  .tab-mini-tag {
    display: inline-flex;
    align-items: center;
    height: 17px;
    padding: 0 5px;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    font-size: 10px;
    font-weight: 600;
  }

  .tab-btn.active .tab-count,
  .tab-btn.active .tab-mini-tag {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .strip-spacer {
    flex: 1;
    min-width: 8px;
  }

  .toolchain-strip {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 6px 0;
  }

  .tool-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 24px;
    padding: 0 7px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-muted);
    font-size: 11px;
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast), color var(--transition-fast);
  }

  .tool-pill:hover,
  .tool-pill.active {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--text-primary);
  }

  .tool-pill.ready {
    color: var(--text-secondary);
  }

  .tool-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-warning);
    flex-shrink: 0;
  }

  .tool-dot.ready {
    background: var(--status-success);
  }

  .tool-name {
    font-weight: 600;
  }

  .tool-ver {
    font-size: 10px;
    color: var(--text-muted);
  }

  /* ==================== Toolchain Drawer ==================== */
  .toolchain-drawer {
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

  .d-field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    min-width: 0;
  }

  .d-field-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    font-weight: 500;
  }

  .d-hint {
    font-size: 10px;
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
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--border-subtle);
  }

  /* ==================== Shared Target Bar ==================== */
  .target-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 14px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .target-input-wrap {
    position: relative;
    display: flex;
    align-items: center;
    flex: 1;
    min-width: 240px;
    max-width: 560px;
  }

  .target-icon {
    position: absolute;
    left: 10px;
    display: inline-flex;
    color: var(--text-muted);
    pointer-events: none;
  }

  .target-input {
    width: 100%;
    height: 30px;
    padding-left: 30px;
    padding-right: 26px;
    font-size: var(--text-sm);
  }

  .clear-target-btn {
    position: absolute;
    right: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
  }

  .clear-target-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .captured-picker-wrap {
    position: relative;
  }

  .captured-dropdown {
    position: absolute;
    top: calc(100% + 5px);
    left: 0;
    width: 340px;
    max-height: 320px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    z-index: var(--z-dropdown);
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .captured-head {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-muted);
  }

  .captured-search {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    outline: none;
  }

  .captured-list {
    overflow-y: auto;
    max-height: 268px;
  }

  .captured-empty {
    padding: 18px 12px;
    text-align: center;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .captured-item {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 7px 10px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    text-align: left;
    cursor: pointer;
  }

  .captured-item:hover {
    background: var(--bg-hover);
  }

  .captured-host {
    flex: 1;
    font-size: 11px;
  }

  .captured-count {
    font-size: 11px;
    color: var(--text-muted);
  }

  .active-job-group {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    margin-left: auto;
  }

  /* ==================== Per-Tab Options Strip ==================== */
  .options-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 7px 14px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .ports-options {
    row-gap: 8px;
  }

  .opt-cluster {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .opt-group-label {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
  }

  .v-sep {
    width: 1px;
    height: 18px;
    background: var(--border-default);
  }

  .chk-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 24px;
    padding: 0 8px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    font-size: var(--text-xs);
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .chk-pill:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .chk-pill input[type='checkbox'],
  .chk-inline input[type='checkbox'] {
    accent-color: var(--accent);
    cursor: pointer;
  }

  .chk-inline {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .inline-num-field {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .num-input {
    width: 78px;
    height: 24px;
    font-size: var(--text-xs);
    padding: 0 7px;
  }

  .custom-ports-wrap {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .custom-ports-input {
    width: 190px;
    height: 26px;
    font-size: var(--text-xs);
  }

  .custom-ports-input.invalid {
    border-color: var(--status-danger);
  }

  .validation-err {
    font-size: 11px;
    color: var(--status-danger);
  }

  .seg-toggle {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--radius-sm);
    background: var(--bg-subtle);
    border: 1px solid var(--border-default);
  }

  .seg-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 22px;
    padding: 0 8px;
    border: none;
    border-radius: calc(var(--radius-sm) - 2px);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .seg-btn:hover {
    color: var(--text-primary);
  }

  .seg-btn.active {
    background: var(--bg-elevated);
    color: var(--accent);
    font-weight: 600;
    box-shadow: var(--shadow-sm);
  }

  .warn-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
    background: var(--status-warning);
  }

  /* ==================== Main Workspace Body ==================== */
  .workspace-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .tab-content {
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .section-card {
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .card-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    flex-wrap: wrap;
  }

  .card-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .hero-target {
    font-size: var(--text-md);
    font-weight: 700;
    color: var(--text-primary);
  }

  .site-page-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
    max-width: 440px;
  }

  .card-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .card-empty {
    padding: 18px 12px;
    text-align: center;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .two-col-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    align-items: start;
  }

  .site-split {
    grid-template-columns: minmax(280px, 1fr) minmax(380px, 1.45fr);
  }

  .meta-pill-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .meta-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }

  .meta-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .pill-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .mono-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    padding: 0 8px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 11px;
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .mono-chip:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
  }

  .warnings-banner {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    color: var(--status-warning);
    font-size: var(--text-xs);
  }

  .warnings-banner.subtle {
    background: var(--status-info-bg);
    border-color: var(--status-info-border);
    color: var(--status-info);
  }

  .warnings-list {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  /* ==================== Key-Value & Tables ==================== */
  .kv-grid {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .site-meta-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px 18px;
  }

  .kv-row {
    display: grid;
    grid-template-columns: 118px minmax(0, 1fr);
    gap: 8px;
    font-size: var(--text-xs);
    align-items: baseline;
  }

  .kv-k {
    color: var(--text-muted);
    font-weight: 500;
  }

  .kv-v {
    color: var(--text-primary);
    min-width: 0;
  }

  .fingerprint-row {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    max-width: 100%;
  }

  .sub-block {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-top: 8px;
    border-top: 1px solid var(--border-subtle);
  }

  .table-wrap {
    width: 100%;
    overflow-x: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-xs);
  }

  .data-table th {
    text-align: left;
    padding: 7px 10px;
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-default);
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
  }

  .data-table td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    vertical-align: middle;
  }

  .data-table tr:last-child td {
    border-bottom: none;
  }

  .data-table tbody tr:hover {
    background: var(--bg-hover);
  }

  .data-table tbody tr.selected-row {
    background: var(--bg-active);
  }

  .compact-table th,
  .compact-table td {
    padding: 5px 8px;
  }

  .col-type {
    width: 76px;
  }

  .col-idx {
    width: 44px;
  }

  .col-act {
    width: 38px;
    text-align: right;
  }

  .col-pivots {
    width: 1%;
    white-space: nowrap;
  }

  .pivot-btns {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  .inline-meta {
    margin-left: 6px;
    color: var(--text-muted);
    font-size: 11px;
  }

  .fw-600 {
    font-weight: 600;
  }

  .break-all {
    word-break: break-all;
  }

  .muted-text {
    color: var(--text-muted);
    font-size: var(--text-xs);
  }

  .hint-muted {
    font-size: 11px;
    color: var(--text-muted);
  }

  .inline-copy-btn {
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: inherit;
    font-weight: inherit;
    text-align: left;
    cursor: pointer;
    padding: 0;
  }

  .inline-copy-btn:hover {
    color: var(--accent);
    text-decoration: underline;
  }

  /* ==================== WHOIS & TLS Specifics ==================== */
  .raw-block {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-top: 4px;
  }

  .raw-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .raw-pre {
    max-height: 260px;
    overflow: auto;
    padding: 10px;
    border-radius: var(--radius-sm);
    background: var(--terminal-bg);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-size: 11px;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .tls-port-probe {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .tls-port-input {
    width: 72px;
    height: 24px;
    font-size: var(--text-xs);
    padding: 0 7px;
  }

  .tls-badges {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .san-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    max-height: 164px;
    overflow-y: auto;
  }

  .san-pill {
    display: inline-flex;
    align-items: center;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    overflow: hidden;
  }

  .san-main {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 22px;
    padding: 0 7px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 11px;
    cursor: pointer;
  }

  .san-main:hover {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .san-sub-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border: none;
    border-left: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
  }

  .san-sub-btn:hover {
    background: var(--bg-hover);
    color: var(--accent);
  }

  .chain-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .chain-item {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }

  .chain-body {
    min-width: 0;
    flex: 1;
  }

  .chain-subj {
    font-size: 11px;
    color: var(--text-primary);
  }

  /* ==================== Site Probe Specifics ==================== */
  .redirect-chain {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .redirect-hop {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    max-width: 320px;
  }

  .redirect-hop.final {
    border-color: var(--accent-border);
    background: var(--accent-soft);
  }

  .hop-url {
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .hop-arrow {
    color: var(--text-muted);
    display: inline-flex;
  }

  .tech-groups {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .tech-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .tech-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .conf-dot {
    width: 5px;
    height: 5px;
    border-radius: 50%;
  }

  .conf-high {
    background: var(--status-success);
  }

  .conf-medium {
    background: var(--status-warning);
  }

  .conf-low {
    background: var(--text-muted);
  }

  .sec-audit-top {
    display: flex;
    align-items: flex-start;
    gap: 14px;
  }

  .score-gauge {
    position: relative;
    width: 84px;
    height: 84px;
    flex-shrink: 0;
  }

  .gauge-track {
    fill: none;
    stroke: var(--bg-elevated);
    stroke-width: 7;
  }

  .gauge-fill {
    fill: none;
    stroke-width: 7;
    stroke-linecap: round;
    transition: stroke-dashoffset 260ms ease;
  }

  .gauge-fill.tone-success {
    stroke: var(--status-success);
  }

  .gauge-fill.tone-warning {
    stroke: var(--status-warning);
  }

  .gauge-fill.tone-danger {
    stroke: var(--status-danger);
  }

  .gauge-center {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }

  .gauge-num {
    font-size: 20px;
    font-weight: 700;
  }

  .gauge-num.tone-success {
    color: var(--status-success);
  }

  .gauge-num.tone-warning {
    color: var(--status-warning);
  }

  .gauge-num.tone-danger {
    color: var(--status-danger);
  }

  .gauge-sub {
    font-size: 10px;
    color: var(--text-muted);
    margin-top: 2px;
  }

  .sec-table-wrap {
    flex: 1;
    min-width: 0;
    overflow-x: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  .sec-val-cell {
    max-width: 280px;
  }

  .sec-val {
    font-size: 11px;
    color: var(--text-secondary);
  }

  .sec-rec {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 2px;
  }

  .discovery-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }

  .disc-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 10px;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    min-width: 0;
  }

  .disc-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }

  .disc-title {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .disc-sub {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .disc-scroll-list {
    max-height: 180px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 11px;
  }

  .disc-line {
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    background: var(--bg-surface);
  }

  .disc-line.disallow {
    color: var(--status-warning);
  }

  .disc-line.allow {
    color: var(--status-success);
  }

  .sitemap-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 2px 4px;
    border-radius: var(--radius-xs);
  }

  .sitemap-row:hover {
    background: var(--bg-hover);
  }

  .wk-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 220px;
    overflow-y: auto;
  }

  .wk-item {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 7px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
  }

  .wk-item-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    font-size: 11px;
  }

  .wk-badges {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .wk-snippet {
    max-height: 90px;
    overflow: auto;
    padding: 6px;
    border-radius: var(--radius-xs);
    background: var(--terminal-bg);
    color: var(--text-secondary);
    font-size: 10px;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .header-key-col {
    width: 220px;
    color: var(--accent);
  }

  /* ==================== Live Streaming Console ==================== */
  .console-card {
    overflow: hidden;
  }

  .console-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 12px;
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
  }

  .console-controls {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .console-body {
    max-height: 188px;
    overflow-y: auto;
    padding: 8px 12px;
    background: var(--terminal-bg);
    font-size: 11px;
    line-height: 1.5;
  }

  .console-empty {
    color: var(--text-muted);
    padding: 8px 0;
  }

  .log-line {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }

  .log-ts {
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .log-lvl {
    width: 60px;
    flex-shrink: 0;
    font-weight: 600;
  }

  .log-msg {
    color: var(--text-secondary);
    word-break: break-word;
  }

  .lvl-progress .log-lvl {
    color: var(--accent);
  }

  .lvl-result .log-lvl,
  .lvl-result .log-msg {
    color: var(--status-success);
  }

  .lvl-warn .log-lvl,
  .lvl-warn .log-msg {
    color: var(--status-warning);
  }

  .lvl-error .log-lvl,
  .lvl-error .log-msg {
    color: var(--status-danger);
  }

  .lvl-system .log-lvl {
    color: var(--status-purple);
  }

  /* ==================== Filter Bars & Ports ==================== */
  .filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .search-box {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 9px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-muted);
    min-width: 220px;
  }

  .search-input {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    outline: none;
  }

  .cmd-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    background: var(--terminal-bg);
    border: 1px solid var(--border-subtle);
  }

  .cmd-text {
    flex: 1;
    font-size: 11px;
    color: var(--terminal-fg);
  }

  .banner-cell {
    max-width: 220px;
  }

  .banner-preview {
    display: block;
    max-width: 210px;
    padding: 2px 6px;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    text-align: left;
    cursor: pointer;
  }

  .banner-preview:hover {
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .summary-cell {
    color: var(--text-secondary);
    max-width: 300px;
  }

  @media (max-width: 1100px) {
    .drawer-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .two-col-grid,
    .site-split,
    .discovery-grid,
    .meta-pill-grid,
    .site-meta-grid {
      grid-template-columns: 1fr;
    }

    .sec-audit-top {
      flex-direction: column;
    }
  }
</style>
