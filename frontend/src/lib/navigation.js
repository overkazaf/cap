import { writable } from 'svelte/store'

export const RE_SECTION_IDS = ['re-static', 're-emulate', 're-defense', 're-crypto']

const PAGE_ALIASES = {
  relab: 're-static',
}

export function isRESection(pageId) {
  return RE_SECTION_IDS.includes(pageId)
}

export const PAGES = [
  // Group 1 — Traffic
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
    group: 'traffic',
    shortcut: '3',
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
    group: 'traffic',
    shortcut: '4',
  },

  // Group 2 — Reverse Engineering
  {
    id: 'trace',
    label: 'DeepTrace',
    title: 'Deep Trace',
    subtitle: 'Flow → Code call-graph correlation & static/native provenance',
    labelKey: 'common.nav.pages.trace.label',
    titleKey: 'common.nav.pages.trace.title',
    subtitleKey: 'common.nav.pages.trace.subtitle',
    icon: 'git-branch',
    group: 'inspect',
    shortcut: '5',
  },
  {
    id: 're-static',
    label: 'Static RE',
    title: 'Static Reverse Engineering',
    subtitle: 'Native/r2 · iOS Mach-O/IPA · JADX Java↔JNI · IDA/Ghidra Symbols',
    labelKey: 'common.nav.pages.re-static.label',
    titleKey: 'common.nav.pages.re-static.title',
    subtitleKey: 'common.nav.pages.re-static.subtitle',
    icon: 'file-code',
    group: 'inspect',
    shortcut: '6',
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
    shortcut: '7',
  },
  {
    id: 're-emulate',
    label: 'Emulate & Trace',
    title: 'Emulation & Execution Trace',
    subtitle: 'Unidbg/Qiling/angr + Auto-Stub · ExecTrace & Taint',
    labelKey: 'common.nav.pages.re-emulate.label',
    titleKey: 'common.nav.pages.re-emulate.title',
    subtitleKey: 'common.nav.pages.re-emulate.subtitle',
    icon: 'cpu',
    group: 'inspect',
    shortcut: '8',
  },
  {
    id: 're-defense',
    label: 'Deobf & TLS',
    title: 'Deobfuscation, VMP & TLS',
    subtitle: 'Packer/OLLVM/VMP audit, Stealth/Unpack scripts, VMP trace, APK Certs & Flutter/Cronet/mTLS',
    labelKey: 'common.nav.pages.re-defense.label',
    titleKey: 'common.nav.pages.re-defense.title',
    subtitleKey: 'common.nav.pages.re-defense.subtitle',
    icon: 'shield',
    group: 'inspect',
  },
  {
    id: 're-crypto',
    label: 'Crypto & DFA',
    title: 'CryptoLab & White-Box DFA',
    subtitle: 'CyberChef codec/cipher pipeline, SM4, Protobuf Wire, White-Box AES-128 DFA',
    labelKey: 'common.nav.pages.re-crypto.label',
    titleKey: 'common.nav.pages.re-crypto.title',
    subtitleKey: 'common.nav.pages.re-crypto.subtitle',
    icon: 'key',
    group: 'inspect',
  },

  // Group 3 — Services
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
    shortcut: '9',
  },

  // Group 4 — System
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
    shortcut: '0',
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
  { id: 'inspect', label: 'Reverse Engineering', labelKey: 'common.nav.groups.inspect' },
  { id: 'service', label: 'Services', labelKey: 'common.nav.groups.service' },
  { id: 'tools', label: 'System', labelKey: 'common.nav.groups.tools' },
]

export const currentPage = writable('capture')

export function navigate(pageId) {
  const resolved = PAGE_ALIASES[pageId] || pageId
  if (PAGES.some((p) => p.id === resolved)) {
    currentPage.set(resolved)
  }
}

export function getPageMeta(pageId) {
  const resolved = PAGE_ALIASES[pageId] || pageId
  return PAGES.find((p) => p.id === resolved) || PAGES[0]
}
