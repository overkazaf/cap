import { writable } from 'svelte/store'
import { navigate } from './navigation.js'

// Persistent UI state for Frida Workbench across route switches
export const fridaState = {
  selectedDevice: '',
  target: '',
  mode: 'attach', // 'spawn' | 'attach'
  noPause: true,
  port: 27042,
  remoteHost: '',

  // Active editor draft
  scriptId: '',
  scriptName: 'Universal SSL Pinning Bypass',
  scriptCategory: 'unpin',
  scriptDescription: '',
  scriptCode: '',
  scriptBuiltin: true,
  dirty: false,

  // Sub-views & filters
  leftTab: 'scripts', // 'scripts' | 'codeshare' | 'trace'
  scriptCategoryFilter: 'all',
  scriptSearch: '',
  consoleFilter: 'all', // 'all' | 'hook' | 'console' | 'error' | 'system'
  consoleSearch: '',
  autoScroll: true,

  // CodeShare cache
  codeshareQuery: '',
  codeshareResults: [],
  fingerprintResult: null,

  // DeepTrace hook generation options
  traceGenOpts: {
    include_java: true,
    include_dex_xrefs: true,
    include_native: true,
    include_crypto: true,
    include_ssl_unpin: false,
    include_backtrace: true,
    max_hooks: 18,
  },
  lastGeneratedHook: null,
  initialized: false,
}

// Reactive handoff store for jumping from DeepTrace or Capture into Frida Studio
export const fridaHandoff = writable(null)

/**
 * Jump directly to the Frida Workbench with optional pre-populated device,
 * target package, and generated/selected hook script.
 */
export function openFridaStudio({
  serial = '',
  target = '',
  mode = '',
  scriptName = '',
  scriptCategory = 'trace',
  scriptDescription = '',
  scriptCode = '',
  leftTab = '',
  generatedHook = null,
} = {}) {
  if (serial) fridaState.selectedDevice = serial
  if (target) fridaState.target = target
  if (mode === 'spawn' || mode === 'attach') fridaState.mode = mode
  if (leftTab) fridaState.leftTab = leftTab
  if (scriptCode) {
    fridaState.scriptId = ''
    fridaState.scriptName = scriptName || 'DeepTrace Hook'
    fridaState.scriptCategory = scriptCategory || 'trace'
    fridaState.scriptDescription = scriptDescription || ''
    fridaState.scriptCode = scriptCode
    fridaState.scriptBuiltin = false
    fridaState.dirty = true
  }
  if (generatedHook) {
    fridaState.lastGeneratedHook = generatedHook
  }
  fridaHandoff.set({
    ts: Date.now(),
    serial,
    target,
    mode,
    scriptName,
    scriptCategory,
    scriptDescription,
    scriptCode,
    leftTab,
    generatedHook,
  })
  navigate('frida')
}
