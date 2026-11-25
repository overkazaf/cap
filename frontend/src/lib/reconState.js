import { writable } from 'svelte/store'
import { navigate } from './navigation.js'

export const RECON_TABS = ['domain', 'site', 'subdomains', 'ports', 'history']

function normalizeReconTab(tab) {
  const key = String(tab || '').trim().toLowerCase()
  if (RECON_TABS.includes(key)) return key
  if (key === 'subdomain' || key === 'sub') return 'subdomains'
  if (key === 'portscan' || key === 'port' || key === 'nmap') return 'ports'
  if (key === 'probe' || key === 'http') return 'site'
  if (key === 'intel' || key === 'dns' || key === 'tls' || key === 'whois') return 'domain'
  return ''
}

// Persistent UI state for the Site Recon workspace across route switches
export const reconState = {
  activeTab: 'domain', // 'domain' | 'site' | 'subdomains' | 'ports' | 'history'
  target: '',

  // Toolchain drawer state
  toolchain: null,

  // Tab 1: Domain Intel
  domainReport: null,
  tlsInspectPort: 443,
  showWhoisRaw: false,
  showTlsChain: false,

  // Tab 2: Site Probe
  siteOpts: {
    probeRobots: true,
    probeSitemap: true,
    probeWellKnown: true,
    probeFavicon: true,
    insecureSkipVerify: false,
    noRedirects: false,
    timeoutMs: 10000,
  },
  siteProfile: null,
  showSiteHeaders: false,

  // Tab 3: Subdomains
  subdomainOpts: {
    useSubfinder: true,
    useCTLog: true,
    useCommonDNS: true,
    resolveDNS: true,
    timeoutSec: 45,
  },
  subdomainReport: null,
  subdomainSearch: '',
  subdomainSourceFilter: 'all',

  // Tab 4: Ports & Nmap
  portScanOpts: {
    engine: 'auto', // 'auto' | 'nmap' | 'native'
    preset: 'quick', // 'quick' | 'top100' | 'web' | 'service' | 'custom'
    portsSpec: '22,80,443,8000-8100',
    serviceVersion: false,
    skipHostDiscovery: false,
    timeoutMs: 1200,
  },
  portScanResult: null,
  portStateFilter: 'all', // 'all' | 'open' | 'filtered'
  portSearch: '',

  // Live async job state & console prefs
  jobState: null,
  consoleFilter: 'all', // 'all' | 'progress' | 'result' | 'warn' | 'error' | 'system'
  consoleAutoScroll: true,
  consoleCollapsed: false,

  // Tab 5: Scan History
  historyEntries: [],
  historyKindFilter: 'all', // 'all' | 'domain' | 'site' | 'subdomain' | 'portscan'
  historySearch: '',
  selectedHistoryId: '',

  // Pending handoff (consumed once by Recon.svelte on mount)
  pendingHandoff: null,
}

// Reactive handoff store for jumping from Flows / DeepTrace / Gateway into Site Recon
export const reconHandoff = writable(null)

/**
 * Jump directly to the Site Recon workspace with an optional target domain/URL/IP
 * and target tab ('domain' | 'site' | 'subdomains' | 'ports' | 'history').
 */
export function openRecon({ target = '', tab = '', autoRun = false } = {}) {
  const cleanTarget = String(target || '').trim()
  const resolvedTab = normalizeReconTab(tab) || (cleanTarget.includes('://') ? 'site' : reconState.activeTab || 'domain')

  if (cleanTarget) {
    reconState.target = cleanTarget
  }
  reconState.activeTab = resolvedTab

  const payload = {
    ts: Date.now(),
    target: cleanTarget,
    tab: resolvedTab,
    autoRun: Boolean(autoRun),
  }
  reconState.pendingHandoff = payload
  reconHandoff.set(payload)
  navigate('recon')
}
