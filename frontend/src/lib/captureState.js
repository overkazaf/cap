// Shared capture state — persists across tab switches
// (Svelte destroys/recreates components when switching AppTabs)

export const state = {
  proxyAddr: '0.0.0.0:8080',
  isRunning: false,
  isPaused: false,
  logs: [],
  devices: [],
  selectedDevice: '',
  port: '8080',
  installCert: true,
  deviceEnv: null,
  rate: { req_per_sec: 0, byte_per_sec: 0, total_reqs: 0, total_bytes: 0 },
  initialized: false,
}
