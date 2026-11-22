import { writable } from 'svelte/store'

const MAX_TOASTS = 5
let seq = 0
const timers = new Map()

const store = writable([])

function push(variant, message, opts = {}) {
  if (!message) return null
  const id = ++seq
  const duration = opts.duration ?? (variant === 'error' ? 4500 : 2800)
  const item = {
    id,
    variant,
    title: opts.title || '',
    message: String(message),
    action: opts.action || null, // { label, onClick }
  }

  store.update((list) => {
    const next = [...list, item]
    return next.length > MAX_TOASTS ? next.slice(next.length - MAX_TOASTS) : next
  })

  if (duration > 0) {
    const t = setTimeout(() => dismissToast(id), duration)
    timers.set(id, t)
  }
  return id
}

export function dismissToast(id) {
  const t = timers.get(id)
  if (t) {
    clearTimeout(t)
    timers.delete(id)
  }
  store.update((list) => list.filter((item) => item.id !== id))
}

export function clearToasts() {
  for (const t of timers.values()) clearTimeout(t)
  timers.clear()
  store.set([])
}

export const toasts = { subscribe: store.subscribe }

export const toast = {
  info: (msg, opts) => push('info', msg, opts),
  success: (msg, opts) => push('success', msg, opts),
  warning: (msg, opts) => push('warning', msg, opts),
  error: (msg, opts) => push('error', msg, opts),
  dismiss: dismissToast,
  clear: clearToasts,
}
