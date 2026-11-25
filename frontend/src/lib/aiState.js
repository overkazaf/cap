import { writable, derived, get } from 'svelte/store'

export const DEFAULT_AI_CONFIG = {
  active_profile_id: '',
  profiles: [],
  auto_heal_enabled: false,
  max_auto_retries: 3,
  redact_secrets: true,
}

export const AI_PROVIDER_PROTOCOLS = [
  { id: 'openai_compat', label: 'OpenAI Compatible' },
  { id: 'anthropic', label: 'Anthropic Claude' },
  { id: 'gemini', label: 'Google Gemini' },
  { id: 'ollama', label: 'Ollama (Local)' },
]

export const AI_MAX_RETRIES_OPTIONS = [1, 2, 3, 4, 5]

const MAX_UNDO_PER_SCOPE = 10

function appApi() {
  return window?.go?.wailsgui?.App
}

export function normalizeAIConfig(raw) {
  if (!raw || typeof raw !== 'object') {
    return { ...DEFAULT_AI_CONFIG, profiles: [] }
  }
  const retries = Number(raw.max_auto_retries)
  return {
    active_profile_id: typeof raw.active_profile_id === 'string' ? raw.active_profile_id : '',
    profiles: Array.isArray(raw.profiles) ? raw.profiles : [],
    auto_heal_enabled: Boolean(raw.auto_heal_enabled),
    max_auto_retries: Number.isFinite(retries) && retries >= 1 && retries <= 5 ? Math.round(retries) : 3,
    redact_secrets: typeof raw.redact_secrets === 'boolean' ? raw.redact_secrets : true,
  }
}

// Cached PublicAIConfig snapshot shared across Settings and workspace drawers.
export const aiConfig = writable({ ...DEFAULT_AI_CONFIG, profiles: [] })

export const activeAIProfile = derived(aiConfig, ($cfg) => {
  if (!$cfg || !Array.isArray($cfg.profiles) || !$cfg.active_profile_id) {
    return null
  }
  return $cfg.profiles.find((p) => p && p.id === $cfg.active_profile_id) || null
})

export const isAIConfigured = derived(activeAIProfile, ($profile) => {
  return Boolean($profile && $profile.enabled)
})

export function setAIConfigSnapshot(raw) {
  const normalized = normalizeAIConfig(raw)
  aiConfig.set(normalized)
  return normalized
}

export async function refreshAIConfig() {
  const api = appApi()
  if (!api?.GetAIConfig) {
    return get(aiConfig)
  }
  try {
    const cfg = await api.GetAIConfig()
    return setAIConfigSnapshot(cfg)
  } catch (_) {
    return get(aiConfig)
  }
}

// Optional signal so Settings.svelte can auto-focus the AI section when navigated from AIHealDrawer.
export const aiSettingsFocusRequest = writable(0)

export function requestOpenAISettings() {
  aiSettingsFocusRequest.set(Date.now())
}

// Global AI Diagnose & Auto-Heal Drawer session state.
let nextSessionId = 0

export const aiHealSession = writable(null)

/**
 * Open the reusable AI Diagnose & Auto-Heal drawer from any cap workspace.
 *
 * @param {object} payload
 * @param {string} [payload.scope] - 'unidbg'|'qiling'|'angr'|'frida'|'plugin'|'signer'|'toolchain'|'recon'|'general'
 * @param {string} [payload.title] - Contextual drawer heading
 * @param {string} [payload.code] - Current source/script code
 * @param {string} [payload.language] - 'java'|'python'|'javascript'|...
 * @param {string} [payload.errorText] - Concise error message
 * @param {string} [payload.logs] - Raw execution logs
 * @param {Record<string, string>} [payload.metadata] - Extra key/value diagnostic metadata
 * @param {(patchedCode: string, meta?: any) => (void|Promise<void>)} [payload.onApplyPatch]
 * @param {(patchedCode: string, meta?: any) => (void|boolean|Promise<void|boolean>)} [payload.onApplyAndRerun]
 * @param {(appliedChanges: Record<string, string>) => (void|Promise<void>)} [payload.onApplyConfig]
 * @param {boolean} [payload.canAutoLoop] - Whether multi-round auto-heal loop is available
 * @param {(opts?: { maxRetries?: number, locale?: string }) => Promise<any>} [payload.onRunAutoLoop]
 * @param {boolean} [payload.autoLoopRunning] - True if caller already launched RunREJobWithAutoHeal
 * @param {any} [payload.autoHealResult] - Pre-populated or completed AutoHealRunResult
 * @param {any} [payload.initialResult] - Pre-populated DiagnoseResult
 * @param {boolean} [payload.autoDiagnose] - Auto-invoke DiagnoseAndFixWithAI on open (default true when no initialResult/autoHealResult/autoLoopRunning)
 * @param {string} [payload.profileId] - Optional override AI profile ID
 * @param {string} [payload.undoKey] - Custom per-scope undo stack key (defaults to normalized scope)
 * @param {() => void} [payload.onNavigateSettings] - Optional custom navigation hook to AI Settings
 */
export function openAIHealModal(payload = {}) {
  const scope = String(payload.scope || 'general').trim().toLowerCase() || 'general'
  const sessionId = ++nextSessionId
  const session = {
    sessionId,
    scope,
    title: payload.title || '',
    code: typeof payload.code === 'string' ? payload.code : '',
    language: payload.language || '',
    errorText: payload.errorText || '',
    logs: payload.logs || '',
    metadata: payload.metadata && typeof payload.metadata === 'object' ? { ...payload.metadata } : {},
    onApplyPatch: typeof payload.onApplyPatch === 'function' ? payload.onApplyPatch : null,
    onApplyAndRerun: typeof payload.onApplyAndRerun === 'function' ? payload.onApplyAndRerun : null,
    onApplyConfig: typeof payload.onApplyConfig === 'function' ? payload.onApplyConfig : null,
    canAutoLoop: Boolean(payload.canAutoLoop),
    onRunAutoLoop: typeof payload.onRunAutoLoop === 'function' ? payload.onRunAutoLoop : null,
    autoLoopRunning: Boolean(payload.autoLoopRunning),
    autoHealResult: payload.autoHealResult || null,
    initialResult: payload.initialResult || null,
    autoDiagnose:
      typeof payload.autoDiagnose === 'boolean'
        ? payload.autoDiagnose
        : !payload.initialResult && !payload.autoHealResult && !payload.autoLoopRunning,
    profileId: payload.profileId || '',
    undoKey: String(payload.undoKey || scope).trim() || 'general',
    onNavigateSettings: typeof payload.onNavigateSettings === 'function' ? payload.onNavigateSettings : null,
    openedAt: Date.now(),
  }
  aiHealSession.set(session)
  return session
}

export function updateAIHealSession(patch = {}) {
  if (!patch || typeof patch !== 'object') return
  aiHealSession.update((curr) => {
    if (!curr) return curr
    return { ...curr, ...patch }
  })
}

export function closeAIHealModal() {
  aiHealSession.set(null)
}

// Per-scope last-code backup stack so users can 1-click Undo an applied AI patch.
const undoMapStore = writable({})

function normalizeUndoKey(scope) {
  return String(scope || 'general').trim().toLowerCase() || 'general'
}

export function pushAIUndo(scope, code, meta = {}) {
  if (typeof code !== 'string') return false
  const key = normalizeUndoKey(scope)
  let pushed = false
  undoMapStore.update((map) => {
    const prevList = Array.isArray(map[key]) ? map[key] : []
    const top = prevList[prevList.length - 1]
    if (top && top.code === code) {
      return map
    }
    const entry = {
      code,
      title: meta.title || '',
      language: meta.language || '',
      timestamp: Date.now(),
    }
    const nextList = [...prevList, entry].slice(-MAX_UNDO_PER_SCOPE)
    pushed = true
    return { ...map, [key]: nextList }
  })
  return pushed
}

export function popAIUndo(scope) {
  const key = normalizeUndoKey(scope)
  let popped = null
  undoMapStore.update((map) => {
    const prevList = Array.isArray(map[key]) ? map[key] : []
    if (prevList.length === 0) return map
    popped = prevList[prevList.length - 1]
    const nextList = prevList.slice(0, -1)
    if (nextList.length === 0) {
      const next = { ...map }
      delete next[key]
      return next
    }
    return { ...map, [key]: nextList }
  })
  return popped
}

export function peekAIUndo(scope) {
  const key = normalizeUndoKey(scope)
  const map = get(undoMapStore)
  const list = map[key]
  if (!Array.isArray(list) || list.length === 0) return null
  return list[list.length - 1]
}

export function hasAIUndo(scope) {
  return peekAIUndo(scope) !== null
}

export function clearAIUndo(scope) {
  if (!scope) {
    undoMapStore.set({})
    return
  }
  const key = normalizeUndoKey(scope)
  undoMapStore.update((map) => {
    if (!(key in map)) return map
    const next = { ...map }
    delete next[key]
    return next
  })
}

export const aiUndoStack = {
  subscribe: undoMapStore.subscribe,
  push: pushAIUndo,
  pop: popAIUndo,
  peek: peekAIUndo,
  has: hasAIUndo,
  clear: clearAIUndo,
}
