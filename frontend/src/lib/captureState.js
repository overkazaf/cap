// Shared capture & flows UI state — persists across page switches
// (Svelte destroys/recreates page components when switching routes)

import './locales/core.js'

export const state = {
  // Proxy control & telemetry
  proxyAddr: '0.0.0.0:8080',
  liveAddr: '',
  hostIP: '',
  isRunning: false,
  isPaused: false,
  rate: { req_per_sec: 0, byte_per_sec: 0, total_reqs: 0, total_bytes: 0 },
  stats: null,
  tlsErrors: [],

  // Activity console logs: { id, time, level, msg }
  logs: [],
  logSeq: 0,

  // Device, Cert & Companion Guard state
  devices: [],
  selectedDevice: '',
  deviceConnected: false,
  connStatus: null, // DeviceConnectionStatus from GetDeviceConnectionStatus
  caCertInfo: null, // CACertInfo from GetCACertInfo
  port: '8080',
  installCert: true,
  vpnMode: false,
  installCompanion: true,
  deviceEnv: null,
  fridaStatus: null,
  wifiAddr: '',
  apps: [],
  selectedApp: '',

  // Capture domain filter
  whitelistText: '',
  blacklistText: '',

  // Capture page UI state
  rightTab: 'logs', // 'logs' | 'hosts' | 'tls'
  showWifiPanel: false,
  showDomainFilter: false,
  initialized: false,
}

export const flowsState = {
  filterHost: '',
  filterMethod: '',
  filterStatus: '', // '' | '2xx' | '3xx' | '4xx' | '5xx'
  filterType: '',   // '' | 'json' | 'html' | 'xml' | 'form' | 'text' | 'media' | 'other'
  filterSearch: '',
  viewMode: 'list', // 'list' | 'grouped'
  splitDirection: 'horizontal', // 'horizontal' | 'vertical'
  liveFollow: true,
  activeTab: 'params',
  exportLang: 'curl',
  rightPanel: 'detail', // 'detail' | 'device' | 'plugins'
  wordWrap: true,
  compareBaseId: '',
  compareBaseLabel: '',
}

export function appendCaptureLog(msg, level = 'info') {
  const time = new Date().toLocaleTimeString('en-US', { hour12: false })
  state.logSeq += 1
  const entry = {
    id: state.logSeq,
    time,
    level,
    msg: String(msg),
  }
  state.logs = [...state.logs, entry].slice(-300)
  return state.logs
}
