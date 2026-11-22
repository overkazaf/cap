import { writable } from 'svelte/store'

export const paletteOpen = writable(false)
export const customCommands = writable([])

export function openPalette() {
  paletteOpen.set(true)
}

export function closePalette() {
  paletteOpen.set(false)
}

export function togglePalette() {
  paletteOpen.update((v) => !v)
}

/**
 * Register temporary page-level commands. Returns an unregister cleanup function.
 * Each command: { id, label, category, icon?, shortcut?, keywords?, run: () => void }
 */
export function registerCommands(list) {
  const items = Array.isArray(list) ? list : []
  const ids = new Set(items.map((c) => c.id))
  customCommands.update((prev) => [
    ...prev.filter((c) => !ids.has(c.id)),
    ...items,
  ])
  return () => {
    customCommands.update((prev) => prev.filter((c) => !ids.has(c.id)))
  }
}
