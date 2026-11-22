export const isMac =
  typeof navigator !== 'undefined' &&
  /Mac|iPod|iPhone|iPad/i.test(navigator.platform || navigator.userAgent || '')

export const MOD_LABEL = isMac ? '⌘' : 'Ctrl'

export function isEditableTarget(target) {
  if (!target || !(target instanceof HTMLElement)) return false
  const tag = target.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true
  if (target.isContentEditable) return true
  return false
}

export function hasPrimaryMod(event) {
  return isMac ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey
}

export function formatShortcut(keys) {
  if (Array.isArray(keys)) {
    return keys.map((k) => (k === 'Mod' ? MOD_LABEL : k))
  }
  return String(keys || '')
    .split('+')
    .map((part) => (part === 'Mod' ? MOD_LABEL : part))
}
