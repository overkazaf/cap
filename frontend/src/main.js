import './lib/tokens.css'
import './lib/locales/common.js'
import { applyTheme } from './lib/theme.js'
import App from './App.svelte'

// Apply default Obsidian theme synchronously before first paint to prevent FOUC
applyTheme('dark')

const TEXT_INPUT_TYPES = new Set(['', 'text', 'search', 'url', 'email'])

function sanitizeInputElement(el) {
  if (!el || el.nodeType !== 1) return
  if (el.getAttribute('data-allow-autocorrect') === 'true') return
  const tag = el.tagName
  if (tag === 'TEXTAREA') {
    el.setAttribute('autocapitalize', 'none')
    el.setAttribute('autocorrect', 'off')
    el.setAttribute('autocomplete', 'off')
    el.setAttribute('spellcheck', 'false')
    el.spellcheck = false
    return
  }
  if (tag === 'INPUT') {
    const type = (el.getAttribute('type') || '').toLowerCase()
    if (!TEXT_INPUT_TYPES.has(type)) return
    el.setAttribute('autocapitalize', 'none')
    el.setAttribute('autocorrect', 'off')
    el.setAttribute('autocomplete', 'off')
    el.setAttribute('spellcheck', 'false')
    el.spellcheck = false
  }
}

function sanitizeSubtree(root) {
  if (!root || root.nodeType !== 1) return
  sanitizeInputElement(root)
  if (typeof root.querySelectorAll === 'function') {
    root.querySelectorAll('input, textarea').forEach(sanitizeInputElement)
  }
}

// Disable macOS WKWebView auto-capitalization, smart quotes & autocorrect globally
function disableInputAutoCorrect() {
  if (typeof document === 'undefined' || !document.body) return
  sanitizeSubtree(document.body)
  if (typeof MutationObserver === 'undefined') return
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) sanitizeSubtree(node)
      }
    }
  })
  observer.observe(document.body, { childList: true, subtree: true })
}

const app = new App({
  target: document.getElementById('app'),
})

disableInputAutoCorrect()

export default app
