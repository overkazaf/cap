import { writable, derived, get } from 'svelte/store'

export const LOCALE_STORAGE_KEY = 'cap-locale'

export const SUPPORTED_LOCALES = [
  { id: 'en', label: 'English', nativeLabel: 'English', short: 'EN' },
  { id: 'zh-CN', label: 'Chinese (Simplified)', nativeLabel: '简体中文', short: '中文' },
]

export function normalizeLocale(code) {
  if (!code || typeof code !== 'string') return 'en'
  const lower = code.trim().toLowerCase()
  if (lower.startsWith('zh')) return 'zh-CN'
  if (lower.startsWith('en')) return 'en'
  return SUPPORTED_LOCALES.some((l) => l.id === code) ? code : 'en'
}

function detectInitialLocale() {
  try {
    if (typeof localStorage !== 'undefined') {
      const saved = localStorage.getItem(LOCALE_STORAGE_KEY)
      if (saved) return normalizeLocale(saved)
    }
  } catch (_) {}

  try {
    if (typeof navigator !== 'undefined') {
      const lang = navigator.language || (Array.isArray(navigator.languages) ? navigator.languages[0] : '')
      if (lang) return normalizeLocale(lang)
    }
  } catch (_) {}

  return 'en'
}

function applyDocumentLang(code) {
  if (typeof document !== 'undefined' && document.documentElement) {
    document.documentElement.lang = code
  }
}

const initialLocale = detectInitialLocale()
applyDocumentLang(initialLocale)

export const locale = writable(initialLocale)

locale.subscribe((val) => {
  applyDocumentLang(val)
})

const catalogs = {
  en: Object.create(null),
  'zh-CN': Object.create(null),
}

const messagesVersion = writable(0)

function flattenMessages(obj, prefix = '', target = Object.create(null)) {
  if (!obj || typeof obj !== 'object') return target
  for (const [k, v] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${k}` : k
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      flattenMessages(v, fullKey, target)
    } else if (typeof v === 'string' || typeof v === 'number') {
      target[fullKey] = String(v)
    }
  }
  return target
}

/**
 * Register a namespaced message catalog without colliding with other modules.
 * Example:
 *   registerMessages('core', {
 *     en: { 'flows.title': 'Flows', capture: { start: 'Start' } },
 *     'zh-CN': { 'flows.title': '请求流', capture: { start: '开始' } },
 *   })
 * Keys are stored as `<namespace>.<key>` (unless already prefixed with `<namespace>.`).
 */
export function registerMessages(namespace, dict) {
  if (!dict || typeof dict !== 'object') return
  const ns = typeof namespace === 'string' ? namespace.trim() : ''

  for (const [rawLang, entries] of Object.entries(dict)) {
    const lang = normalizeLocale(rawLang)
    if (!catalogs[lang]) catalogs[lang] = Object.create(null)
    const flat = flattenMessages(entries)
    for (const [k, v] of Object.entries(flat)) {
      const finalKey = ns && !k.startsWith(`${ns}.`) ? `${ns}.${k}` : k
      catalogs[lang][finalKey] = v
    }
  }

  messagesVersion.update((n) => n + 1)
}

function interpolate(template, params) {
  if (!params || typeof params !== 'object') return template
  return template.replace(/\{([a-zA-Z0-9_.-]+)\}/g, (match, key) => {
    const val = params[key]
    return val === undefined || val === null ? match : String(val)
  })
}

export function translate(key, params = undefined, activeLocale = undefined) {
  if (!key) return ''
  const lang = activeLocale ? normalizeLocale(activeLocale) : get(locale)
  const raw =
    catalogs[lang]?.[key] ??
    catalogs.en?.[key] ??
    key
  return interpolate(raw, params)
}

export const t = derived([locale, messagesVersion], ([$locale]) => {
  return (key, params) => translate(key, params, $locale)
})

export function setLocale(code) {
  const normalized = normalizeLocale(code)
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(LOCALE_STORAGE_KEY, normalized)
    }
  } catch (_) {}
  locale.set(normalized)
  try {
    window?.go?.wailsgui?.App?.SetSetting?.('locale', normalized)?.catch?.(() => {})
  } catch (_) {}
  return normalized
}

export function toggleLocale() {
  const current = get(locale)
  const next = current === 'zh-CN' ? 'en' : 'zh-CN'
  return setLocale(next)
}

export function getLocaleMeta(code) {
  const normalized = normalizeLocale(code || get(locale))
  return SUPPORTED_LOCALES.find((l) => l.id === normalized) || SUPPORTED_LOCALES[0]
}

export async function syncLocaleFromSettings() {
  try {
    if (typeof localStorage !== 'undefined' && localStorage.getItem(LOCALE_STORAGE_KEY)) {
      return get(locale)
    }
    const saved = await window?.go?.wailsgui?.App?.GetSetting?.('locale')
    if (saved) {
      return setLocale(saved)
    }
  } catch (_) {}
  return get(locale)
}
