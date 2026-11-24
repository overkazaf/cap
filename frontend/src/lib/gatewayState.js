import { writable } from 'svelte/store'
import { navigate } from './navigation.js'

// Persistent UI state for the Service Gateway workspace across route switches
export const gatewayState = {
  activeTab: 'routes', // 'routes' | 'proxies' | 'devices' | 'signers' | 'logs'
  listenAddr: '127.0.0.1:9090',

  // Selected entity IDs
  selectedRouteId: '',
  selectedDeviceId: '',
  selectedSignerId: '',

  // Search & filter state
  routeSearch: '',
  proxySearch: '',
  proxyStatusFilter: 'all', // 'all' | 'healthy' | 'unhealthy' | 'disabled'
  deviceSearch: '',
  deviceKindFilter: 'all', // 'all' | 'virtual' | 'physical'
  signerSearch: '',
  logRouteFilter: 'all',
  logStatusFilter: 'all', // 'all' | 'ok' | '4xx' | 'error'
  logSearch: '',

  // Live Route Tester defaults
  testInputJson: '{\n  "keyword": "cap"\n}',
  testBody: '',
  testDeviceId: '',
  testProxyId: '',
  testRaw: false,
  lastTestResult: null,

  // Pending flow publish handoff (consumed once by Gateway.svelte)
  pendingPublishFlow: null,
}

// Reactive handoff store for jumping from Flows / DeepTrace into Service Gateway
export const gatewayHandoff = writable(null)

function deriveRouteSlug(flow) {
  const explicit = String(flow?.slug || '').trim()
  if (explicit) return explicit
  let candidate = ''
  const rawPath = String(flow?.path || '').trim()
  if (rawPath && rawPath !== '/') {
    candidate = rawPath.replace(/^\/+|\/+$/g, '').replace(/\//g, '-')
  } else if (flow?.url) {
    try {
      const u = new URL(flow.url)
      const p = u.pathname.replace(/^\/+|\/+$/g, '')
      candidate = p ? p.replace(/\//g, '-') : u.hostname
    } catch (_) {
      candidate = String(flow.host || '')
    }
  } else if (flow?.host) {
    candidate = String(flow.host)
  }
  const clean = candidate
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '')
  return clean || 'api-route'
}

function deriveRouteName(flow) {
  const explicit = String(flow?.name || '').trim()
  if (explicit) return explicit
  const method = String(flow?.method || 'GET').toUpperCase()
  let path = String(flow?.path || '').trim()
  if (!path && flow?.url) {
    try {
      path = new URL(flow.url).pathname || '/'
    } catch (_) {
      path = '/'
    }
  }
  return `${method} ${path || '/'}`
}

/**
 * Navigate to the Service Gateway workspace and open the "Publish from Captured Flow"
 * flow picker pre-populated with the provided captured flow.
 *
 * Accepts a FlowSummary/FlowDetail object, a flow ID string, or an options object
 * `{ flow, id, flowId, slug, name, method, url, host, path }`.
 */
export function openGatewayPublishFlow(flow) {
  const src = typeof flow === 'string'
    ? { id: flow }
    : (flow?.flow && typeof flow.flow === 'object' ? { ...flow.flow, ...flow } : (flow || {}))

  const flowId = String(src.id || src.flowId || src.flowID || src.flow_id || '').trim()
  const payload = {
    ts: Date.now(),
    type: 'publish_flow',
    flowId,
    method: String(src.method || 'GET').toUpperCase(),
    url: String(src.url || ''),
    host: String(src.host || ''),
    path: String(src.path || ''),
    slug: deriveRouteSlug(src),
    name: deriveRouteName(src),
  }

  gatewayState.activeTab = 'routes'
  gatewayState.pendingPublishFlow = payload
  gatewayHandoff.set(payload)
  navigate('gateway')
}
