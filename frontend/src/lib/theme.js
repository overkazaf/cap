import { writable } from 'svelte/store'

export const THEME_META = [
  {
    id: 'dark',
    label: 'Obsidian',
    scheme: 'dark',
    preview: { bg: '#0b0c10', surface: '#13151c', accent: '#38bdf8' },
  },
  {
    id: 'light',
    label: 'Porcelain',
    scheme: 'light',
    preview: { bg: '#f6f7f9', surface: '#ffffff', accent: '#0284c7' },
  },
  {
    id: 'mocha',
    label: 'Mocha',
    scheme: 'dark',
    preview: { bg: '#181825', surface: '#1e1e2e', accent: '#89b4fa' },
  },
  {
    id: 'nord',
    label: 'Nord',
    scheme: 'dark',
    preview: { bg: '#262b36', surface: '#2e3440', accent: '#88c0d0' },
  },
]

const themes = {
  dark: {
    scheme: 'dark',
    vars: {
      '--bg-app': '#0b0c10',
      '--bg-sidebar': '#0e1015',
      '--bg-header': '#101218',
      '--bg-surface': '#13151c',
      '--bg-elevated': '#191c25',
      '--bg-input': '#0d0f14',
      '--bg-hover': '#1b1e28',
      '--bg-active': '#1e2638',
      '--bg-subtle': 'rgba(255, 255, 255, 0.04)',

      '--border-subtle': 'rgba(255, 255, 255, 0.06)',
      '--border-default': 'rgba(255, 255, 255, 0.10)',
      '--border-strong': 'rgba(255, 255, 255, 0.18)',

      '--text-primary': '#eceef4',
      '--text-secondary': '#a8b0c0',
      '--text-muted': '#767f92',
      '--text-faint': '#4d5566',
      '--text-inverse': '#0b0c10',

      '--accent': '#38bdf8',
      '--accent-hover': '#5ccbfa',
      '--accent-soft': 'rgba(56, 189, 248, 0.14)',
      '--accent-border': 'rgba(56, 189, 248, 0.36)',
      '--focus-ring': '0 0 0 2px rgba(56, 189, 248, 0.35)',

      '--status-success': '#34d399',
      '--status-success-bg': 'rgba(52, 211, 153, 0.13)',
      '--status-success-border': 'rgba(52, 211, 153, 0.32)',

      '--status-info': '#60a5fa',
      '--status-info-bg': 'rgba(96, 165, 250, 0.13)',
      '--status-info-border': 'rgba(96, 165, 250, 0.32)',

      '--status-warning': '#fbbf24',
      '--status-warning-bg': 'rgba(251, 191, 36, 0.13)',
      '--status-warning-border': 'rgba(251, 191, 36, 0.32)',

      '--status-danger': '#f87171',
      '--status-danger-bg': 'rgba(248, 113, 113, 0.13)',
      '--status-danger-border': 'rgba(248, 113, 113, 0.32)',

      '--status-purple': '#c084fc',
      '--status-purple-bg': 'rgba(192, 132, 252, 0.13)',
      '--status-purple-border': 'rgba(192, 132, 252, 0.32)',

      '--method-get': '#34d399',
      '--method-post': '#38bdf8',
      '--method-put': '#fb923c',
      '--method-patch': '#c084fc',
      '--method-delete': '#f87171',
      '--method-options': '#94a3b8',
      '--method-ws': '#2dd4bf',

      '--shadow-sm': '0 1px 2px rgba(0, 0, 0, 0.35)',
      '--shadow-md': '0 6px 20px rgba(0, 0, 0, 0.45)',
      '--shadow-lg': '0 18px 48px rgba(0, 0, 0, 0.65)',

      '--scrollbar': 'rgba(255, 255, 255, 0.14)',
      '--scrollbar-hover': 'rgba(255, 255, 255, 0.26)',
      '--selection': 'rgba(56, 189, 248, 0.28)',
      '--terminal-fg': '#34d399',
      '--terminal-bg': '#090a0e',

      /* Legacy compatibility */
      '--bg': '#0b0c10',
      '--bg-panel': '#13151c',
      '--bg-selected': '#1e2638',
      '--bg-btn': '#191c25',
      '--border': 'rgba(255, 255, 255, 0.10)',
      '--fg': '#eceef4',
      '--fg-muted': '#a8b0c0',
      '--fg-dim': '#767f92',
      '--fg-faint': '#4d5566',
      '--fg-ghost': '#3d4454',
      '--accent-bg': 'rgba(56, 189, 248, 0.14)',
      '--green': '#34d399',
      '--red': '#f87171',
      '--orange': '#fb923c',
      '--yellow': '#fbbf24',
      '--purple': '#c084fc',
      '--success-bg': 'rgba(52, 211, 153, 0.13)',
      '--success-border': 'rgba(52, 211, 153, 0.32)',
      '--danger-bg': 'rgba(248, 113, 113, 0.13)',
      '--danger-border': 'rgba(248, 113, 113, 0.32)',
      '--sidebar-bg': '#0e1015',
    },
  },

  light: {
    scheme: 'light',
    vars: {
      '--bg-app': '#f6f7f9',
      '--bg-sidebar': '#eff1f5',
      '--bg-header': '#ffffff',
      '--bg-surface': '#ffffff',
      '--bg-elevated': '#ffffff',
      '--bg-input': '#ffffff',
      '--bg-hover': '#eef1f6',
      '--bg-active': '#e3effc',
      '--bg-subtle': 'rgba(15, 23, 42, 0.04)',

      '--border-subtle': 'rgba(15, 23, 42, 0.06)',
      '--border-default': 'rgba(15, 23, 42, 0.11)',
      '--border-strong': 'rgba(15, 23, 42, 0.20)',

      '--text-primary': '#0f172a',
      '--text-secondary': '#334155',
      '--text-muted': '#64748b',
      '--text-faint': '#94a3b8',
      '--text-inverse': '#ffffff',

      '--accent': '#0284c7',
      '--accent-hover': '#0369a1',
      '--accent-soft': 'rgba(2, 132, 199, 0.11)',
      '--accent-border': 'rgba(2, 132, 199, 0.32)',
      '--focus-ring': '0 0 0 2px rgba(2, 132, 199, 0.26)',

      '--status-success': '#059669',
      '--status-success-bg': 'rgba(5, 150, 105, 0.10)',
      '--status-success-border': 'rgba(5, 150, 105, 0.28)',

      '--status-info': '#2563eb',
      '--status-info-bg': 'rgba(37, 99, 235, 0.10)',
      '--status-info-border': 'rgba(37, 99, 235, 0.28)',

      '--status-warning': '#d97706',
      '--status-warning-bg': 'rgba(217, 119, 6, 0.11)',
      '--status-warning-border': 'rgba(217, 119, 6, 0.30)',

      '--status-danger': '#dc2626',
      '--status-danger-bg': 'rgba(220, 38, 38, 0.10)',
      '--status-danger-border': 'rgba(220, 38, 38, 0.28)',

      '--status-purple': '#7c3aed',
      '--status-purple-bg': 'rgba(124, 58, 237, 0.10)',
      '--status-purple-border': 'rgba(124, 58, 237, 0.28)',

      '--method-get': '#059669',
      '--method-post': '#0284c7',
      '--method-put': '#ea580c',
      '--method-patch': '#7c3aed',
      '--method-delete': '#dc2626',
      '--method-options': '#64748b',
      '--method-ws': '#0d9488',

      '--shadow-sm': '0 1px 2px rgba(15, 23, 42, 0.06)',
      '--shadow-md': '0 6px 20px rgba(15, 23, 42, 0.10)',
      '--shadow-lg': '0 18px 44px rgba(15, 23, 42, 0.16)',

      '--scrollbar': 'rgba(15, 23, 42, 0.16)',
      '--scrollbar-hover': 'rgba(15, 23, 42, 0.30)',
      '--selection': 'rgba(2, 132, 199, 0.18)',
      '--terminal-fg': '#34d399',
      '--terminal-bg': '#0f172a',

      /* Legacy compatibility */
      '--bg': '#f6f7f9',
      '--bg-panel': '#ffffff',
      '--bg-selected': '#e3effc',
      '--bg-btn': '#f1f5f9',
      '--border': 'rgba(15, 23, 42, 0.11)',
      '--fg': '#0f172a',
      '--fg-muted': '#334155',
      '--fg-dim': '#64748b',
      '--fg-faint': '#94a3b8',
      '--fg-ghost': '#cbd5e1',
      '--accent-bg': 'rgba(2, 132, 199, 0.11)',
      '--green': '#059669',
      '--red': '#dc2626',
      '--orange': '#ea580c',
      '--yellow': '#d97706',
      '--purple': '#7c3aed',
      '--success-bg': 'rgba(5, 150, 105, 0.10)',
      '--success-border': 'rgba(5, 150, 105, 0.28)',
      '--danger-bg': 'rgba(220, 38, 38, 0.10)',
      '--danger-border': 'rgba(220, 38, 38, 0.28)',
      '--sidebar-bg': '#eff1f5',
    },
  },

  mocha: {
    scheme: 'dark',
    vars: {
      '--bg-app': '#181825',
      '--bg-sidebar': '#14141f',
      '--bg-header': '#1a1a28',
      '--bg-surface': '#1e1e2e',
      '--bg-elevated': '#262638',
      '--bg-input': '#161622',
      '--bg-hover': '#29293d',
      '--bg-active': '#2c324a',
      '--bg-subtle': 'rgba(205, 214, 244, 0.04)',

      '--border-subtle': 'rgba(205, 214, 244, 0.06)',
      '--border-default': 'rgba(205, 214, 244, 0.11)',
      '--border-strong': 'rgba(205, 214, 244, 0.20)',

      '--text-primary': '#cdd6f4',
      '--text-secondary': '#bac2de',
      '--text-muted': '#9399b2',
      '--text-faint': '#6c7086',
      '--text-inverse': '#181825',

      '--accent': '#89b4fa',
      '--accent-hover': '#a6c8fc',
      '--accent-soft': 'rgba(137, 180, 250, 0.15)',
      '--accent-border': 'rgba(137, 180, 250, 0.36)',
      '--focus-ring': '0 0 0 2px rgba(137, 180, 250, 0.35)',

      '--status-success': '#a6e3a1',
      '--status-success-bg': 'rgba(166, 227, 161, 0.14)',
      '--status-success-border': 'rgba(166, 227, 161, 0.34)',

      '--status-info': '#89dceb',
      '--status-info-bg': 'rgba(137, 220, 235, 0.14)',
      '--status-info-border': 'rgba(137, 220, 235, 0.34)',

      '--status-warning': '#f9e2af',
      '--status-warning-bg': 'rgba(249, 226, 175, 0.14)',
      '--status-warning-border': 'rgba(249, 226, 175, 0.34)',

      '--status-danger': '#f38ba8',
      '--status-danger-bg': 'rgba(243, 139, 168, 0.14)',
      '--status-danger-border': 'rgba(243, 139, 168, 0.34)',

      '--status-purple': '#cba6f7',
      '--status-purple-bg': 'rgba(203, 166, 247, 0.14)',
      '--status-purple-border': 'rgba(203, 166, 247, 0.34)',

      '--method-get': '#a6e3a1',
      '--method-post': '#89b4fa',
      '--method-put': '#fab387',
      '--method-patch': '#cba6f7',
      '--method-delete': '#f38ba8',
      '--method-options': '#9399b2',
      '--method-ws': '#94e2d5',

      '--shadow-sm': '0 1px 2px rgba(0, 0, 0, 0.35)',
      '--shadow-md': '0 6px 20px rgba(0, 0, 0, 0.45)',
      '--shadow-lg': '0 18px 48px rgba(0, 0, 0, 0.65)',

      '--scrollbar': 'rgba(205, 214, 244, 0.16)',
      '--scrollbar-hover': 'rgba(205, 214, 244, 0.28)',
      '--selection': 'rgba(137, 180, 250, 0.28)',
      '--terminal-fg': '#a6e3a1',
      '--terminal-bg': '#14141f',

      /* Legacy compatibility */
      '--bg': '#181825',
      '--bg-panel': '#1e1e2e',
      '--bg-selected': '#2c324a',
      '--bg-btn': '#262638',
      '--border': 'rgba(205, 214, 244, 0.11)',
      '--fg': '#cdd6f4',
      '--fg-muted': '#bac2de',
      '--fg-dim': '#9399b2',
      '--fg-faint': '#6c7086',
      '--fg-ghost': '#585b70',
      '--accent-bg': 'rgba(137, 180, 250, 0.15)',
      '--green': '#a6e3a1',
      '--red': '#f38ba8',
      '--orange': '#fab387',
      '--yellow': '#f9e2af',
      '--purple': '#cba6f7',
      '--success-bg': 'rgba(166, 227, 161, 0.14)',
      '--success-border': 'rgba(166, 227, 161, 0.34)',
      '--danger-bg': 'rgba(243, 139, 168, 0.14)',
      '--danger-border': 'rgba(243, 139, 168, 0.34)',
      '--sidebar-bg': '#14141f',
    },
  },

  nord: {
    scheme: 'dark',
    vars: {
      '--bg-app': '#262b36',
      '--bg-sidebar': '#222731',
      '--bg-header': '#292f3b',
      '--bg-surface': '#2e3440',
      '--bg-elevated': '#373e4d',
      '--bg-input': '#242933',
      '--bg-hover': '#3b4252',
      '--bg-active': '#404b5e',
      '--bg-subtle': 'rgba(236, 239, 244, 0.04)',

      '--border-subtle': 'rgba(236, 239, 244, 0.06)',
      '--border-default': 'rgba(236, 239, 244, 0.11)',
      '--border-strong': 'rgba(236, 239, 244, 0.20)',

      '--text-primary': '#eceff4',
      '--text-secondary': '#d8dee9',
      '--text-muted': '#a5b1c5',
      '--text-faint': '#738096',
      '--text-inverse': '#262b36',

      '--accent': '#88c0d0',
      '--accent-hover': '#9fd0de',
      '--accent-soft': 'rgba(136, 192, 208, 0.16)',
      '--accent-border': 'rgba(136, 192, 208, 0.38)',
      '--focus-ring': '0 0 0 2px rgba(136, 192, 208, 0.35)',

      '--status-success': '#a3be8c',
      '--status-success-bg': 'rgba(163, 190, 140, 0.15)',
      '--status-success-border': 'rgba(163, 190, 140, 0.35)',

      '--status-info': '#81a1c1',
      '--status-info-bg': 'rgba(129, 161, 193, 0.16)',
      '--status-info-border': 'rgba(129, 161, 193, 0.36)',

      '--status-warning': '#ebcb8b',
      '--status-warning-bg': 'rgba(235, 203, 139, 0.15)',
      '--status-warning-border': 'rgba(235, 203, 139, 0.35)',

      '--status-danger': '#d06f79',
      '--status-danger-bg': 'rgba(191, 97, 106, 0.18)',
      '--status-danger-border': 'rgba(191, 97, 106, 0.38)',

      '--status-purple': '#b48ead',
      '--status-purple-bg': 'rgba(180, 142, 173, 0.16)',
      '--status-purple-border': 'rgba(180, 142, 173, 0.36)',

      '--method-get': '#a3be8c',
      '--method-post': '#88c0d0',
      '--method-put': '#d08770',
      '--method-patch': '#b48ead',
      '--method-delete': '#d06f79',
      '--method-options': '#a5b1c5',
      '--method-ws': '#8fbcbb',

      '--shadow-sm': '0 1px 2px rgba(0, 0, 0, 0.30)',
      '--shadow-md': '0 6px 20px rgba(0, 0, 0, 0.40)',
      '--shadow-lg': '0 18px 48px rgba(0, 0, 0, 0.58)',

      '--scrollbar': 'rgba(236, 239, 244, 0.16)',
      '--scrollbar-hover': 'rgba(236, 239, 244, 0.28)',
      '--selection': 'rgba(136, 192, 208, 0.28)',
      '--terminal-fg': '#a3be8c',
      '--terminal-bg': '#222731',

      /* Legacy compatibility */
      '--bg': '#262b36',
      '--bg-panel': '#2e3440',
      '--bg-selected': '#404b5e',
      '--bg-btn': '#373e4d',
      '--border': 'rgba(236, 239, 244, 0.11)',
      '--fg': '#eceff4',
      '--fg-muted': '#d8dee9',
      '--fg-dim': '#a5b1c5',
      '--fg-faint': '#738096',
      '--fg-ghost': '#5c6578',
      '--accent-bg': 'rgba(136, 192, 208, 0.16)',
      '--green': '#a3be8c',
      '--red': '#d06f79',
      '--orange': '#d08770',
      '--yellow': '#ebcb8b',
      '--purple': '#b48ead',
      '--success-bg': 'rgba(163, 190, 140, 0.15)',
      '--success-border': 'rgba(163, 190, 140, 0.35)',
      '--danger-bg': 'rgba(191, 97, 106, 0.18)',
      '--danger-border': 'rgba(191, 97, 106, 0.38)',
      '--sidebar-bg': '#222731',
    },
  },
}

export const currentTheme = writable('dark')

export function applyTheme(name) {
  const resolved = themes[name] ? name : 'dark'
  const theme = themes[resolved]
  const root = document.documentElement
  root.dataset.theme = resolved
  root.style.colorScheme = theme.scheme
  for (const [key, val] of Object.entries(theme.vars)) {
    root.style.setProperty(key, val)
  }
  currentTheme.set(resolved)
  return resolved
}

export function getThemeNames() {
  return Object.keys(themes)
}

export function getThemeMeta() {
  return THEME_META
}

export function nextTheme(active) {
  const names = getThemeNames()
  const idx = names.indexOf(active)
  return names[(idx + 1) % names.length]
}
