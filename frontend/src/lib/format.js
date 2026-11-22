import { toast } from './toast.js'
import { translate } from './i18n.js'

export function formatBytes(bytes) {
  const n = Number(bytes) || 0
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export function formatDuration(ms) {
  const n = Number(ms)
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n < 1) return '<1ms'
  if (n < 1000) return `${Math.round(n)}ms`
  return `${(n / 1000).toFixed(2)}s`
}

export function formatRate(reqPerSec) {
  const n = Number(reqPerSec) || 0
  if (n === 0) return '0 req/s'
  if (n < 10) return `${n.toFixed(1)} req/s`
  return `${Math.round(n)} req/s`
}

export function formatCount(count) {
  const n = Number(count) || 0
  if (n < 1000) return String(n)
  if (n < 1000000) return `${(n / 1000).toFixed(1)}k`
  return `${(n / 1000000).toFixed(1)}M`
}

export function formatTime(ts) {
  if (!ts) return '—'
  const d = typeof ts === 'number' || typeof ts === 'string' ? new Date(ts) : ts
  if (Number.isNaN(d.getTime())) return String(ts)
  return d.toLocaleTimeString('en-US', { hour12: false })
}

export function methodColorVar(method) {
  switch (String(method || '').toUpperCase()) {
    case 'GET':
      return 'var(--method-get)'
    case 'POST':
      return 'var(--method-post)'
    case 'PUT':
      return 'var(--method-put)'
    case 'PATCH':
      return 'var(--method-patch)'
    case 'DELETE':
      return 'var(--method-delete)'
    case 'WS':
    case 'WSS':
      return 'var(--method-ws)'
    default:
      return 'var(--method-options)'
  }
}

export function statusVariant(code) {
  const n = Number(code) || 0
  if (n >= 200 && n < 300) return 'success'
  if (n >= 300 && n < 400) return 'info'
  if (n >= 400 && n < 500) return 'warning'
  if (n >= 500) return 'danger'
  return 'neutral'
}

export async function copyToClipboard(text, label = undefined) {
  try {
    if (navigator?.clipboard?.writeText) {
      await navigator.clipboard.writeText(String(text ?? ''))
    } else {
      const ta = document.createElement('textarea')
      ta.value = String(text ?? '')
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    const msg = label === undefined ? translate('common.toast.copied') : label
    if (msg) toast.success(msg)
    return true
  } catch (e) {
    toast.error(translate('common.toast.copyFailed', { error: e?.message || e }))
    return false
  }
}
