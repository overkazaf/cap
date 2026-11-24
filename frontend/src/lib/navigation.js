import { writable } from 'svelte/store'

export const PAGES = [
  {
    id: 'capture',
    label: 'Capture',
    title: 'Capture Control',
    subtitle: 'MITM proxy & Android device workbench',
    labelKey: 'common.nav.pages.capture.label',
    titleKey: 'common.nav.pages.capture.title',
    subtitleKey: 'common.nav.pages.capture.subtitle',
    icon: 'radio',
    group: 'traffic',
    shortcut: '1',
  },
  {
    id: 'flows',
    label: 'Flows',
    title: 'Traffic Inspector',
    subtitle: 'Inspect, filter, replay & export HTTP(S) flows',
    labelKey: 'common.nav.pages.flows.label',
    titleKey: 'common.nav.pages.flows.title',
    subtitleKey: 'common.nav.pages.flows.subtitle',
    icon: 'activity',
    group: 'traffic',
    shortcut: '2',
  },
  {
    id: 'rules',
    label: 'Rules',
    title: 'Intercept Rules',
    subtitle: 'Breakpoints, mocks, request & response rewrites',
    labelKey: 'common.nav.pages.rules.label',
    titleKey: 'common.nav.pages.rules.title',
    subtitleKey: 'common.nav.pages.rules.subtitle',
    icon: 'sliders',
    group: 'inspect',
    shortcut: '3',
  },
  {
    id: 'trace',
    label: 'DeepTrace',
    title: 'Deep Trace',
    subtitle: 'Call-graph correlation & static/native reverse analysis',
    labelKey: 'common.nav.pages.trace.label',
    titleKey: 'common.nav.pages.trace.title',
    subtitleKey: 'common.nav.pages.trace.subtitle',
    icon: 'git-branch',
    group: 'inspect',
    shortcut: '4',
  },
  {
    id: 'frida',
    label: 'Frida',
    title: 'Frida Studio',
    subtitle: 'Dynamic hooking, server lifecycle, CodeShare & live trace bridge',
    labelKey: 'common.nav.pages.frida.label',
    titleKey: 'common.nav.pages.frida.title',
    subtitleKey: 'common.nav.pages.frida.subtitle',
    icon: 'zap',
    group: 'inspect',
    shortcut: '5',
  },
  {
    id: 'relab',
    label: 'RE Lab',
    title: 'Reverse Engineering Lab',
    subtitle: 'radare2, Unidbg/Qiling/angr emulation, Deobf/VMP & ExecTrace taint',
    labelKey: 'common.nav.pages.relab.label',
    titleKey: 'common.nav.pages.relab.title',
    subtitleKey: 'common.nav.pages.relab.subtitle',
    icon: 'cpu',
    group: 'inspect',
    shortcut: '6',
  },
  {
    id: 'plugins',
    label: 'Plugins',
    title: 'Analyzer Plugins',
    subtitle: 'Custom scriptable analyzers & flow hooks',
    labelKey: 'common.nav.pages.plugins.label',
    titleKey: 'common.nav.pages.plugins.title',
    subtitleKey: 'common.nav.pages.plugins.subtitle',
    icon: 'puzzle',
    group: 'inspect',
    shortcut: '7',
  },
  {
    id: 'gateway',
    label: 'Gateway',
    title: 'Service Gateway',
    subtitle: 'Open API HTTP gateway, proxy IP pool, device fingerprints & signers',
    labelKey: 'common.nav.pages.gateway.label',
    titleKey: 'common.nav.pages.gateway.title',
    subtitleKey: 'common.nav.pages.gateway.subtitle',
    icon: 'globe',
    group: 'service',
    shortcut: '8',
  },
  {
    id: 'terminal',
    label: 'Terminal',
    title: 'Workbench Shell',
    subtitle: 'Execute CLI, ADB & reverse-engineering commands',
    labelKey: 'common.nav.pages.terminal.label',
    titleKey: 'common.nav.pages.terminal.title',
    subtitleKey: 'common.nav.pages.terminal.subtitle',
    icon: 'terminal',
    group: 'tools',
    shortcut: '9',
  },
  {
    id: 'settings',
    label: 'Settings',
    title: 'Preferences',
    subtitle: 'Appearance, proxy defaults & export configuration',
    labelKey: 'common.nav.pages.settings.label',
    titleKey: 'common.nav.pages.settings.title',
    subtitleKey: 'common.nav.pages.settings.subtitle',
    icon: 'settings',
    group: 'tools',
    shortcut: ',',
  },
]

export const PAGE_GROUPS = [
  { id: 'traffic', label: 'Traffic', labelKey: 'common.nav.groups.traffic' },
  { id: 'inspect', label: 'Analysis', labelKey: 'common.nav.groups.inspect' },
  { id: 'service', label: 'Services', labelKey: 'common.nav.groups.service' },
  { id: 'tools', label: 'System', labelKey: 'common.nav.groups.tools' },
]

export const currentPage = writable('capture')

export function navigate(pageId) {
  if (PAGES.some((p) => p.id === pageId)) {
    currentPage.set(pageId)
  }
}

export function getPageMeta(pageId) {
  return PAGES.find((p) => p.id === pageId) || PAGES[0]
}
