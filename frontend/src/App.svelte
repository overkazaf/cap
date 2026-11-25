<script>
  import { onMount, onDestroy } from 'svelte'
  import { applyTheme, currentTheme, getThemeMeta } from './lib/theme.js'
  import { PAGES, PAGE_GROUPS, currentPage, navigate, getPageMeta, isRESection } from './lib/navigation.js'
  import { openPalette, togglePalette } from './lib/commandPalette.js'
  import { hasPrimaryMod, isEditableTarget, MOD_LABEL } from './lib/shortcuts.js'
  import { formatBytes, formatCount, formatRate } from './lib/format.js'
  import { toast } from './lib/toast.js'
  import {
    t,
    locale,
    SUPPORTED_LOCALES,
    setLocale,
    toggleLocale,
    getLocaleMeta,
    syncLocaleFromSettings,
    translate,
  } from './lib/i18n.js'

  import Icon from './components/Icon.svelte'
  import Kbd from './components/Kbd.svelte'
  import ToastHost from './components/ToastHost.svelte'
  import CommandPalette from './components/CommandPalette.svelte'

  import Capture from './pages/Capture.svelte'
  import Flows from './pages/Flows.svelte'
  import Terminal from './pages/Terminal.svelte'
  import Plugins from './pages/Plugins.svelte'
  import Rules from './pages/Rules.svelte'
  import DeepTrace from './pages/DeepTrace.svelte'
  import Frida from './pages/Frida.svelte'
  import RELab from './pages/RELab.svelte'
  import Gateway from './pages/Gateway.svelte'
  import Settings from './pages/Settings.svelte'

  const SIDEBAR_KEY = 'cap.ui.sidebarExpanded'
  const GITHUB_REPO_URL = 'https://github.com/overkazaf/cap'

  let sidebarExpanded = true
  let version = 'v0.2.0'
  let proxyRunning = false
  let proxyPaused = false
  let proxyAddr = ''
  let defaultProxyAddr = '0.0.0.0:8080'
  let proxyBusy = false

  let flowCount = 0
  let rate = { req_per_sec: 0, byte_per_sec: 0, total_reqs: 0, total_bytes: 0 }
  let pendingBreakpoints = 0
  let activeRuleCount = 0
  let deviceCount = 0
  let fridaRunning = false
  let reJobRunning = false
  let reJobEngine = ''
  let gatewayRunning = false
  let gatewayAddr = ''

  let pollTimer = null
  let unsubs = []

  const appApi = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  function openExternal(url) {
    const rt = runtimeApi()
    if (rt?.BrowserOpenURL) {
      rt.BrowserOpenURL(url)
      return
    }
    window.open(url, '_blank', 'noopener')
  }

  function toggleSidebar() {
    sidebarExpanded = !sidebarExpanded
    try {
      localStorage.setItem(SIDEBAR_KEY, sidebarExpanded ? '1' : '0')
    } catch (_) {}
  }

  async function selectTheme(name) {
    const resolved = applyTheme(name)
    try {
      await appApi()?.SetSetting?.('theme', resolved)
    } catch (_) {}
    return resolved
  }

  async function toggleLightDark() {
    const target = $currentTheme === 'light' ? 'dark' : 'light'
    await selectTheme(target)
    toast.info(translate('common.toast.themeSwitched', { theme: translate(`common.themes.${target}`) }))
  }

  function handleSelectLocale(code) {
    const next = setLocale(code)
    const meta = getLocaleMeta(next)
    toast.info(translate('common.toast.languageSwitched', { lang: meta.nativeLabel }))
  }

  function handleToggleLocale() {
    const next = toggleLocale()
    const meta = getLocaleMeta(next)
    toast.info(translate('common.toast.languageSwitched', { lang: meta.nativeLabel }))
  }

  async function syncShellState() {
    const api = appApi()
    if (!api) return
    try {
      const [running, paused, addr] = await Promise.all([
        api.IsProxyRunning?.().catch(() => false),
        api.IsPaused?.().catch(() => false),
        api.ProxyAddr?.().catch(() => ''),
      ])
      proxyRunning = Boolean(running)
      proxyPaused = Boolean(paused)
      proxyAddr = addr || ''

      if (proxyRunning) {
        const r = await api.GetTrafficRate?.().catch(() => null)
        if (r) rate = r
      } else {
        rate = { req_per_sec: 0, byte_per_sec: 0, total_reqs: rate.total_reqs || 0, total_bytes: rate.total_bytes || 0 }
      }

      const [stats, rulesList, bps, fridaSess, reJob, gwStats] = await Promise.all([
        api.GetTrafficStats?.().catch(() => null),
        api.ListRules?.().catch(() => []),
        api.GetPendingBreakpoints?.().catch(() => []),
        api.GetFridaSessionState?.().catch(() => null),
        api.GetREJobState?.().catch(() => null),
        api.GetGatewayStatus?.().catch(() => null),
      ])
      if (fridaSess && typeof fridaSess.running === 'boolean') {
        fridaRunning = fridaSess.running
      }
      if (reJob) {
        reJobRunning = Boolean(reJob.running || reJob.status === 'running')
        reJobEngine = reJob.engine || ''
      }
      if (gwStats && typeof gwStats.running === 'boolean') {
        gatewayRunning = gwStats.running
        gatewayAddr = gwStats.listen_addr || ''
      }
      if (stats && typeof stats.total_flows === 'number') {
        flowCount = stats.total_flows
      } else if (stats && typeof stats.TotalFlows === 'number') {
        flowCount = stats.TotalFlows
      } else {
        const list = await api.GetFlows?.('', '', '', 1000).catch(() => null)
        if (Array.isArray(list)) flowCount = list.length
      }
      if (Array.isArray(rulesList)) {
        activeRuleCount = rulesList.filter((r) => r?.enabled).length
      }
      if (Array.isArray(bps)) {
        pendingBreakpoints = bps.length
      }
    } catch (_) {}
  }

  async function refreshDeviceCount() {
    const api = appApi()
    if (!api?.ListDevices) return
    try {
      const devs = await api.ListDevices()
      deviceCount = Array.isArray(devs) ? devs.length : 0
    } catch (_) {}
  }

  async function toggleProxyQuick() {
    const api = appApi()
    if (!api || proxyBusy) return
    proxyBusy = true
    try {
      if (proxyRunning) {
        await api.StopProxy()
        proxyRunning = false
        proxyPaused = false
        proxyAddr = ''
        toast.info(translate('common.toast.proxyStopped'))
      } else {
        const configured = (await api.GetSetting?.('proxy_addr').catch(() => '')) || defaultProxyAddr
        defaultProxyAddr = configured
        await api.StartProxy(configured)
        proxyRunning = true
        proxyPaused = false
        proxyAddr = (await api.ProxyAddr?.().catch(() => configured)) || configured
        toast.success(translate('common.toast.proxyStarted', { addr: proxyAddr }))
      }
    } catch (e) {
      toast.error(translate('common.toast.proxyError', { error: e?.message || e }))
    } finally {
      proxyBusy = false
    }
  }

  async function togglePauseQuick() {
    const api = appApi()
    if (!api || !proxyRunning) return
    try {
      if (proxyPaused) {
        await api.ResumeCapture()
        proxyPaused = false
        toast.info(translate('common.toast.captureResumed'))
      } else {
        await api.PauseCapture()
        proxyPaused = true
        toast.warning(translate('common.toast.capturePaused'))
      }
    } catch (e) {
      toast.error(translate('common.toast.captureToggleFailed', { error: e?.message || e }))
    }
  }

  async function clearAllFlows() {
    const api = appApi()
    if (!api?.ClearFlows) return
    try {
      await api.ClearFlows()
      flowCount = 0
      toast.success(translate('common.toast.flowsCleared'))
    } catch (e) {
      toast.error(translate('common.toast.flowsClearFailed', { error: e?.message || e }))
    }
  }

  function handleGlobalKeydown(e) {
    if (hasPrimaryMod(e)) {
      const key = e.key.toLowerCase()
      if (key === 'k') {
        e.preventDefault()
        togglePalette()
        return
      }
      if (key === 'b') {
        e.preventDefault()
        toggleSidebar()
        return
      }
      if (!e.shiftKey && !e.altKey && ((key >= '0' && key <= '9') || key === ',')) {
        const target = PAGES.find((p) => p.shortcut && p.shortcut === key)
        if (target) {
          e.preventDefault()
          navigate(target.id)
          return
        }
      }
    }

    if (isEditableTarget(e.target)) return
  }

  function subscribeEvents() {
    const rt = runtimeApi()
    if (!rt?.EventsOn) return

    const on = (event, handler) => {
      const off = rt.EventsOn(event, handler)
      if (typeof off === 'function') unsubs.push(off)
    }

    on('proxy:started', (ev) => {
      proxyRunning = true
      proxyPaused = false
      if (ev?.address) proxyAddr = ev.address
    })
    on('proxy:stopped', () => {
      proxyRunning = false
      proxyPaused = false
      proxyAddr = ''
    })
    on('proxy:capture', (ev) => {
      if (typeof ev?.paused === 'boolean') proxyPaused = ev.paused
    })
    on('proxy:flow', () => {
      flowCount += 1
    })
    on('proxy:error', (ev) => {
      if (ev?.error) toast.error(ev.error)
    })
    on('frida:status', (st) => {
      if (st && typeof st.running === 'boolean') {
        fridaRunning = st.running
      }
    })
    on('re:status', (st) => {
      if (st) {
        reJobRunning = Boolean(st.running || st.status === 'running')
        reJobEngine = st.engine || ''
      }
    })
    on('gateway:status', (st) => {
      if (st && typeof st.running === 'boolean') {
        gatewayRunning = st.running
        gatewayAddr = st.listen_addr || ''
      }
    })
  }

  onMount(async () => {
    try {
      const saved = localStorage.getItem(SIDEBAR_KEY)
      if (saved === '0') sidebarExpanded = false
      else if (saved === '1') sidebarExpanded = true
      else sidebarExpanded = window.innerWidth >= 1120
    } catch (_) {}

    const api = appApi()
    try {
      const [theme, fontSize, addr, ver] = await Promise.all([
        api?.GetSetting?.('theme').catch(() => 'dark'),
        api?.GetSetting?.('font_size').catch(() => ''),
        api?.GetSetting?.('proxy_addr').catch(() => ''),
        api?.GetVersion?.().catch(() => ''),
        syncLocaleFromSettings(),
      ])
      applyTheme(theme || 'dark')
      if (fontSize) {
        document.documentElement.style.setProperty('--font-size', `${fontSize}px`)
      }
      if (addr) defaultProxyAddr = addr
      if (ver) version = ver.startsWith('v') ? ver : `v${ver}`
    } catch (_) {
      applyTheme('dark')
    }

    subscribeEvents()
    await syncShellState()
    refreshDeviceCount()
    pollTimer = setInterval(syncShellState, 2500)
  })

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer)
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
  })

  $: activeMeta = getPageMeta($currentPage)
  $: activeLocaleMeta = getLocaleMeta($locale)
  $: alternateLocaleMeta = SUPPORTED_LOCALES.find((l) => l.id !== $locale) || SUPPORTED_LOCALES[0]
  $: activeThemeLabel = $t(`common.themes.${$currentTheme}`)

  $: paletteCommands = [
    ...PAGES.map((p) => {
      const label = $t(p.labelKey)
      return {
        id: `nav:${p.id}`,
        label: $t('common.palette.commands.goTo', { label }),
        category: $t('common.palette.categories.workspaces'),
        icon: p.icon,
        shortcut: p.shortcut ? ['Mod', p.shortcut] : undefined,
        keywords: `${p.id} ${p.label} ${label} ${$t(p.titleKey)} ${$t(p.subtitleKey)}`,
        badge: $currentPage === p.id ? $t('common.palette.badges.active') : '',
        run: () => navigate(p.id),
      }
    }),
    {
      id: 'proxy:toggle',
      label: proxyRunning
        ? $t('common.palette.commands.stopProxy')
        : $t('common.palette.commands.startProxy'),
      category: $t('common.palette.categories.proxy'),
      icon: proxyRunning ? 'square' : 'play',
      keywords: 'mitm capture listen server proxy 代理 抓包',
      badge: proxyRunning ? proxyAddr : defaultProxyAddr,
      run: toggleProxyQuick,
    },
    ...(proxyRunning
      ? [
          {
            id: 'proxy:pause',
            label: proxyPaused
              ? $t('common.palette.commands.resumeCapture')
              : $t('common.palette.commands.pauseCapture'),
            category: $t('common.palette.categories.proxy'),
            icon: proxyPaused ? 'play' : 'pause',
            keywords: 'freeze hold capture pause resume 暂停 恢复',
            run: togglePauseQuick,
          },
        ]
      : []),
    {
      id: 'flows:clear',
      label: $t('common.palette.commands.clearFlows'),
      category: $t('common.palette.categories.proxy'),
      icon: 'trash',
      keywords: 'delete reset database history clear flows 清空 流量',
      run: clearAllFlows,
    },
    {
      id: 'ui:sidebar',
      label: sidebarExpanded
        ? $t('common.palette.commands.collapseSidebar')
        : $t('common.palette.commands.expandSidebar'),
      category: $t('common.palette.categories.interface'),
      icon: 'panel-left',
      shortcut: ['Mod', 'B'],
      keywords: 'rail layout compact sidebar 侧边栏',
      run: toggleSidebar,
    },
    {
      id: 'lang:toggle',
      label: $t('common.palette.commands.toggleLanguage', { next: alternateLocaleMeta.nativeLabel }),
      category: $t('common.palette.categories.language'),
      icon: 'globe',
      keywords: 'language locale i18n english chinese 中文 英文 切换语言',
      badge: activeLocaleMeta.short,
      run: handleToggleLocale,
    },
    ...SUPPORTED_LOCALES.map((lang) => ({
      id: `lang:${lang.id}`,
      label: $t('common.palette.commands.setLanguage', { lang: lang.nativeLabel }),
      category: $t('common.palette.categories.language'),
      icon: 'globe',
      keywords: `language locale i18n ${lang.id} ${lang.label} ${lang.nativeLabel} 语言 中文`,
      badge: $locale === lang.id ? $t('common.palette.badges.current') : '',
      run: () => handleSelectLocale(lang.id),
    })),
    ...getThemeMeta().map((th) => {
      const thLabel = $t(`common.themes.${th.id}`)
      return {
        id: `theme:${th.id}`,
        label: $t('common.palette.commands.switchTheme', { theme: thLabel }),
        category: $t('common.palette.categories.appearance'),
        icon: th.scheme === 'light' ? 'sun' : 'moon',
        keywords: `color dark light theme ${th.id} ${th.label} ${thLabel} 主题 深色 浅色`,
        badge: $currentTheme === th.id ? $t('common.palette.badges.current') : '',
        run: async () => {
          await selectTheme(th.id)
          toast.info(translate('common.toast.themeSwitched', { theme: translate(`common.themes.${th.id}`) }))
        },
      }
    }),
    {
      id: 'link:github',
      label: $t('common.palette.commands.openGithub'),
      category: $t('common.palette.categories.links'),
      icon: 'external-link',
      keywords: 'github repository source code author 0xaf overkazaf license mit 仓库 源码 开源',
      badge: 'overkazaf/cap',
      run: () => openExternal(GITHUB_REPO_URL),
    },
  ]
</script>

<svelte:window on:keydown={handleGlobalKeydown} />

<div class="workbench" class:sidebar-compact={!sidebarExpanded}>
  <!-- Left Navigation Rail -->
  <aside class="sidebar" aria-label={$t('common.nav.primaryAria')}>
    <div class="brand-header">
      <button
        class="brand-btn"
        title={$t('common.app.brandTooltip', { version, mod: MOD_LABEL })}
        on:click={toggleSidebar}
      >
        <span class="brand-mark" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <rect x="2" y="2" width="20" height="20" rx="6" fill="currentColor" fill-opacity="0.14" stroke="currentColor" stroke-width="1.6"/>
            <path d="M7.5 13.5L10.5 8.5L13.5 15.5L16.5 10.5" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        {#if sidebarExpanded}
          <span class="brand-text">
            <span class="brand-name">cap</span>
            <span class="brand-ver mono">{version}</span>
          </span>
        {/if}
      </button>
    </div>

    <nav class="nav-scroll">
      {#each PAGE_GROUPS as group}
        {#if sidebarExpanded}
          <div class="nav-group-label">{$t(group.labelKey)}</div>
        {:else}
          <div class="nav-divider"></div>
        {/if}
        {#each PAGES.filter((p) => p.group === group.id) as page (page.id)}
          <button
            class="nav-item"
            class:active={$currentPage === page.id}
            title={(!sidebarExpanded ? $t(page.labelKey) : $t(page.titleKey)) +
              (page.shortcut ? ` (${MOD_LABEL}${page.shortcut})` : '')}
            aria-current={$currentPage === page.id ? 'page' : undefined}
            on:click={() => navigate(page.id)}
          >
            <span class="nav-icon-wrap">
              <Icon name={page.icon} size={16} strokeWidth={1.8} />
              {#if page.id === 'capture' && proxyRunning}
                <span class="nav-dot" class:paused={proxyPaused}></span>
              {/if}
              {#if page.id === 'rules' && pendingBreakpoints > 0 && !sidebarExpanded}
                <span class="nav-dot warn"></span>
              {/if}
              {#if page.id === 'frida' && fridaRunning && !sidebarExpanded}
                <span class="nav-dot"></span>
              {/if}
              {#if page.id === 're-emulate' && reJobRunning && !sidebarExpanded}
                <span class="nav-dot"></span>
              {/if}
              {#if page.id === 'gateway' && gatewayRunning && !sidebarExpanded}
                <span class="nav-dot"></span>
              {/if}
            </span>

            {#if sidebarExpanded}
              <span class="nav-label">{$t(page.labelKey)}</span>
              <span class="nav-meta">
                {#if page.id === 'capture' && proxyRunning}
                  <span class="pill-live" class:paused={proxyPaused}>
                    {proxyPaused ? $t('common.sidebar.pausedBadge') : $t('common.sidebar.liveBadge')}
                  </span>
                {:else if page.id === 'frida' && fridaRunning}
                  <span class="pill-live">{$t('common.sidebar.hookBadge')}</span>
                {:else if page.id === 're-emulate' && reJobRunning}
                  <span class="pill-live">{$t('common.sidebar.reJobBadge')}</span>
                {:else if page.id === 'gateway' && gatewayRunning}
                  <span class="pill-live">{$t('common.sidebar.gwBadge')}</span>
                {:else if page.id === 'flows' && flowCount > 0}
                  <span class="pill-count mono tabular-nums">{formatCount(flowCount)}</span>
                {:else if page.id === 'rules' && pendingBreakpoints > 0}
                  <span class="pill-warn mono tabular-nums">{pendingBreakpoints}</span>
                {:else if page.id === 'rules' && activeRuleCount > 0}
                  <span class="pill-count mono tabular-nums">{activeRuleCount}</span>
                {/if}
              </span>
            {/if}
          </button>
        {/each}
      {/each}
    </nav>

    <div class="sidebar-footer">
      <button
        class="rail-action"
        title={$t('common.sidebar.commandsTooltip', { mod: MOD_LABEL })}
        on:click={openPalette}
      >
        <Icon name="command" size={15} />
        {#if sidebarExpanded}
          <span class="rail-action-label">{$t('common.sidebar.commands')}</span>
          <Kbd keys={['Mod', 'K']} size="xs" />
        {/if}
      </button>
      <button
        class="rail-action"
        title={sidebarExpanded
          ? $t('common.sidebar.collapseTooltip', { mod: MOD_LABEL })
          : $t('common.sidebar.expandTooltip', { mod: MOD_LABEL })}
        on:click={toggleSidebar}
      >
        <Icon name="panel-left" size={15} />
        {#if sidebarExpanded}
          <span class="rail-action-label">{$t('common.sidebar.collapse')}</span>
          <Kbd keys={['Mod', 'B']} size="xs" />
        {/if}
      </button>
    </div>
  </aside>

  <!-- Main Shell Column -->
  <div class="shell-main">
    <!-- Top Desktop Workbench Header -->
    <header class="topbar">
      <div class="topbar-left">
        <span class="page-icon">
          <Icon name={activeMeta.icon} size={15} />
        </span>
        <span class="page-title">{$t(activeMeta.titleKey)}</span>
        <span class="page-sep" aria-hidden="true">/</span>
        <span class="page-subtitle truncate">{$t(activeMeta.subtitleKey)}</span>
      </div>

      <div class="topbar-center">
        <button
          class="palette-trigger"
          on:click={openPalette}
          title={$t('common.topbar.paletteTooltip', { mod: MOD_LABEL })}
        >
          <Icon name="search" size={13} />
          <span class="trigger-text">{$t('common.topbar.paletteTrigger')}</span>
          <Kbd keys={['Mod', 'K']} size="xs" />
        </button>
      </div>

      <div class="topbar-right">
        <!-- Live Proxy Status & Quick Controls -->
        <div
          class="proxy-pill"
          class:running={proxyRunning && !proxyPaused}
          class:paused={proxyRunning && proxyPaused}
        >
          <span class="proxy-indicator"></span>
          {#if proxyRunning}
            <button
              class="proxy-addr-btn mono tabular-nums"
              title={$t('common.topbar.proxyOpenCapture')}
              on:click={() => navigate('capture')}
            >
              {proxyAddr || defaultProxyAddr}
            </button>
            <span class="proxy-rate mono tabular-nums">
              {proxyPaused ? $t('common.topbar.proxyPaused') : formatRate(rate.req_per_sec)}
            </span>
            <button
              class="proxy-mini-btn"
              title={proxyPaused ? $t('common.topbar.proxyResumeTooltip') : $t('common.topbar.proxyPauseTooltip')}
              on:click={togglePauseQuick}
            >
              <Icon name={proxyPaused ? 'play' : 'pause'} size={12} />
            </button>
            <button
              class="proxy-mini-btn danger"
              title={$t('common.topbar.proxyStopTooltip')}
              disabled={proxyBusy}
              on:click={toggleProxyQuick}
            >
              <Icon name="square" size={11} />
            </button>
          {:else}
            <span class="proxy-idle-label">{$t('common.topbar.proxyOff')}</span>
            <button
              class="proxy-start-btn"
              disabled={proxyBusy}
              title={$t('common.topbar.proxyStartTooltip', { addr: defaultProxyAddr })}
              on:click={toggleProxyQuick}
            >
              <Icon name="play" size={11} />
              <span>{$t('common.topbar.proxyStart')}</span>
            </button>
          {/if}
        </div>

        <!-- Compact Language Switcher Pill -->
        <button
          class="lang-pill"
          title={$t('common.topbar.langTooltip', {
            current: activeLocaleMeta.nativeLabel,
            next: alternateLocaleMeta.nativeLabel,
          })}
          aria-label={$t('common.topbar.langAria')}
          on:click={handleToggleLocale}
        >
          <span class="lang-seg" class:active={$locale === 'en'}>EN</span>
          <span class="lang-div" aria-hidden="true">/</span>
          <span class="lang-seg" class:active={$locale === 'zh-CN'}>中文</span>
        </button>

        <button
          class="topbar-icon-btn"
          title={$t('common.topbar.themeTooltip', { theme: activeThemeLabel })}
          aria-label={$t('common.topbar.themeAria')}
          on:click={toggleLightDark}
        >
          <Icon name={$currentTheme === 'light' ? 'moon' : 'sun'} size={15} />
        </button>
      </div>
    </header>

    <!-- Active Workspace Viewport -->
    <main class="workspace">
      {#if $currentPage === 'capture'}
        <Capture />
      {:else if $currentPage === 'flows'}
        <Flows />
      {:else if $currentPage === 'rules'}
        <Rules />
      {:else if $currentPage === 'plugins'}
        <Plugins />
      {:else if $currentPage === 'trace'}
        <DeepTrace />
      {:else if $currentPage === 'frida'}
        <Frida />
      {:else if isRESection($currentPage)}
        <RELab section={$currentPage} />
      {:else if $currentPage === 'gateway'}
        <Gateway />
      {:else if $currentPage === 'terminal'}
        <Terminal />
      {:else if $currentPage === 'settings'}
        <Settings />
      {/if}
    </main>

    <!-- Bottom IDE-Style Status Bar -->
    <footer class="statusbar">
      <div class="status-left">
        <button
          class="status-item"
          class:status-live={proxyRunning && !proxyPaused}
          class:status-warn={proxyRunning && proxyPaused}
          on:click={() => navigate('capture')}
          title={$t('common.statusbar.proxyStatusTooltip')}
        >
          <span class="status-dot"></span>
          <span class="mono tabular-nums">
            {#if proxyRunning && proxyPaused}
              {$t('common.statusbar.paused', { addr: proxyAddr })}
            {:else if proxyRunning}
              {$t('common.statusbar.live', { addr: proxyAddr })}
            {:else}
              {$t('common.statusbar.idle')}
            {/if}
          </span>
        </button>

        <span class="status-sep"></span>

        <button
          class="status-item mono tabular-nums"
          on:click={() => navigate('flows')}
          title={$t('common.statusbar.flowsTooltip')}
        >
          <Icon name="database" size={11} />
          <span>{$t('common.statusbar.flowsCount', { count: flowCount.toLocaleString() })}</span>
        </button>

        {#if proxyRunning}
          <span class="status-sep"></span>
          <span class="status-item static mono tabular-nums">
            {formatRate(rate.req_per_sec)} · {formatBytes(rate.byte_per_sec)}/s
          </span>
        {/if}

        {#if deviceCount > 0}
          <span class="status-sep"></span>
          <button
            class="status-item mono tabular-nums"
            on:click={() => navigate('capture')}
            title={$t('common.statusbar.devicesTooltip')}
          >
            <Icon name="smartphone" size={11} />
            <span>
              {deviceCount === 1
                ? $t('common.statusbar.devicesOne')
                : $t('common.statusbar.devicesMany', { count: deviceCount })}
            </span>
          </button>
        {/if}

        {#if pendingBreakpoints > 0}
          <span class="status-sep"></span>
          <button class="status-item status-bp mono tabular-nums" on:click={() => navigate('rules')}>
            <Icon name="alert-triangle" size={11} />
            <span>
              {pendingBreakpoints === 1
                ? $t('common.statusbar.breakpointsOne')
                : $t('common.statusbar.breakpointsMany', { count: pendingBreakpoints })}
            </span>
          </button>
        {/if}

        {#if gatewayRunning}
          <span class="status-sep"></span>
          <button
            class="status-item status-live mono tabular-nums"
            on:click={() => navigate('gateway')}
            title={$t('common.statusbar.gatewayStatusTooltip')}
          >
            <span class="status-dot"></span>
            <span>{$t('common.statusbar.gatewayLive', { addr: gatewayAddr || '127.0.0.1:9090' })}</span>
          </button>
        {/if}

        {#if reJobRunning}
          <span class="status-sep"></span>
          <button
            class="status-item status-live mono"
            on:click={() => navigate('re-emulate')}
            title={$t('common.statusbar.reJobTooltip')}
          >
            <Icon name="cpu" size={11} />
            <span>{$t('common.statusbar.reJobRunning', { engine: reJobEngine || 'job' })}</span>
          </button>
        {/if}
      </div>

      <div class="status-right">
        <span class="status-hint">{$t('common.statusbar.hintSwitch', { mod: MOD_LABEL })}</span>
        <span class="status-hint">{$t('common.statusbar.hintPalette', { mod: MOD_LABEL })}</span>
        <span class="status-sep"></span>
        <button
          class="status-item"
          on:click={handleToggleLocale}
          title={$t('common.statusbar.switchLangTooltip')}
        >
          <Icon name="globe" size={11} />
          <span>{activeLocaleMeta.short}</span>
        </button>
        <span class="status-sep"></span>
        <button
          class="status-item"
          on:click={toggleLightDark}
          title={$t('common.statusbar.switchThemeTooltip')}
        >
          <Icon name="palette" size={11} />
          <span>{activeThemeLabel}</span>
        </button>
        <span class="status-sep"></span>
        <button
          class="status-item status-copyright"
          on:click={() => openExternal(GITHUB_REPO_URL)}
          title={$t('common.statusbar.copyrightTooltip')}
        >
          <span>{$t('common.statusbar.copyrightLabel')}</span>
          <Icon name="external-link" size={10} />
        </button>
        <span class="status-sep"></span>
        <span class="status-item static mono">{version}</span>
      </div>
    </footer>
  </div>
</div>

<ToastHost />
<CommandPalette commands={paletteCommands} />

<style>
  .workbench {
    display: flex;
    width: 100vw;
    height: 100vh;
    overflow: hidden;
    background: var(--bg-app);
    color: var(--text-primary);
  }

  /* ==================== Sidebar Rail ==================== */
  .sidebar {
    width: var(--sidebar-width-expanded);
    flex-shrink: 0;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    transition: width var(--transition-base);
    user-select: none;
  }

  .sidebar-compact .sidebar {
    width: var(--sidebar-width-compact);
  }

  .brand-header {
    height: var(--topbar-height);
    padding: 0 10px;
    display: flex;
    align-items: center;
    border-bottom: 1px solid var(--border-subtle);
  }

  .sidebar-compact .brand-header {
    justify-content: center;
    padding: 0;
  }

  .brand-btn {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
    height: 30px;
    padding: 0 6px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .sidebar-compact .brand-btn {
    width: 36px;
    justify-content: center;
    padding: 0;
  }

  .brand-btn:hover {
    background: var(--bg-hover);
  }

  .brand-mark {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--accent);
    flex-shrink: 0;
  }

  .brand-text {
    display: flex;
    align-items: baseline;
    gap: 6px;
    min-width: 0;
  }

  .brand-name {
    font-size: 14px;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: var(--text-primary);
  }

  .brand-ver {
    font-size: 10px;
    color: var(--text-faint);
    padding: 1px 5px;
    border-radius: var(--radius-xs);
    background: var(--bg-subtle);
  }

  .nav-scroll {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .sidebar-compact .nav-scroll {
    padding: 8px 6px;
    align-items: center;
  }

  .nav-group-label {
    padding: 10px 8px 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-faint);
  }

  .nav-group-label:first-child {
    padding-top: 2px;
  }

  .nav-divider {
    width: 24px;
    height: 1px;
    background: var(--border-subtle);
    margin: 6px 0;
  }

  .nav-divider:first-child {
    display: none;
  }

  .nav-item {
    position: relative;
    width: 100%;
    height: 32px;
    padding: 0 9px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 9px;
    cursor: pointer;
    font-size: var(--text-sm);
    font-weight: 500;
    text-align: left;
    transition:
      background var(--transition-fast),
      color var(--transition-fast),
      border-color var(--transition-fast);
  }

  .sidebar-compact .nav-item {
    width: 38px;
    height: 36px;
    padding: 0;
    justify-content: center;
  }

  .nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .nav-item.active {
    background: var(--bg-active);
    color: var(--text-primary);
    border-color: var(--accent-border);
  }

  .nav-item.active .nav-icon-wrap {
    color: var(--accent);
  }

  .nav-icon-wrap {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .nav-dot {
    position: absolute;
    top: -2px;
    right: -3px;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--status-success);
    box-shadow: 0 0 0 2px var(--bg-sidebar);
    animation: cap-pulse 1.8s ease-in-out infinite;
  }

  .nav-dot.paused {
    background: var(--status-warning);
    animation: none;
  }

  .nav-dot.warn {
    background: var(--status-warning);
  }

  .nav-label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .nav-meta {
    display: flex;
    align-items: center;
    flex-shrink: 0;
  }

  .pill-live {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 2px 5px;
    border-radius: var(--radius-xs);
    color: var(--status-success);
    background: var(--status-success-bg);
    border: 1px solid var(--status-success-border);
  }

  .pill-live.paused {
    color: var(--status-warning);
    background: var(--status-warning-bg);
    border-color: var(--status-warning-border);
  }

  .pill-count {
    font-size: 10px;
    color: var(--text-muted);
    background: var(--bg-subtle);
    padding: 1px 6px;
    border-radius: var(--radius-full);
  }

  .pill-warn {
    font-size: 10px;
    font-weight: 700;
    color: var(--status-warning);
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    padding: 1px 6px;
    border-radius: var(--radius-full);
  }

  .sidebar-footer {
    padding: 8px;
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .sidebar-compact .sidebar-footer {
    padding: 8px 6px;
    align-items: center;
  }

  .rail-action {
    width: 100%;
    height: 30px;
    padding: 0 8px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: var(--text-xs);
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .sidebar-compact .rail-action {
    width: 36px;
    padding: 0;
    justify-content: center;
  }

  .rail-action:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .rail-action-label {
    flex: 1;
    text-align: left;
  }

  /* ==================== Shell Main Column ==================== */
  .shell-main {
    flex: 1;
    min-width: 0;
    min-height: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ==================== Top Bar ==================== */
  .topbar {
    height: var(--topbar-height);
    flex-shrink: 0;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    padding: 0 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    user-select: none;
  }

  .topbar-left {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    flex: 1;
  }

  .page-icon {
    display: flex;
    color: var(--accent);
    flex-shrink: 0;
  }

  .page-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
  }

  .page-sep {
    color: var(--text-faint);
    font-size: var(--text-xs);
  }

  .page-subtitle {
    font-size: var(--text-xs);
    color: var(--text-muted);
    min-width: 0;
  }

  .topbar-center {
    flex: 0 1 280px;
    display: flex;
    justify-content: center;
  }

  .palette-trigger {
    width: 100%;
    max-width: 268px;
    height: 28px;
    padding: 0 8px 0 10px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-xs);
    cursor: pointer;
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .palette-trigger:hover {
    border-color: var(--border-strong);
    color: var(--text-secondary);
  }

  .trigger-text {
    flex: 1;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .topbar-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .proxy-pill {
    height: 28px;
    padding: 0 6px 0 10px;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-default);
    background: var(--bg-surface);
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-xs);
  }

  .proxy-pill.running {
    border-color: var(--status-success-border);
    background: var(--status-success-bg);
  }

  .proxy-pill.paused {
    border-color: var(--status-warning-border);
    background: var(--status-warning-bg);
  }

  .proxy-indicator {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-faint);
    flex-shrink: 0;
  }

  .proxy-pill.running .proxy-indicator {
    background: var(--status-success);
    animation: cap-pulse 1.8s ease-in-out infinite;
  }

  .proxy-pill.paused .proxy-indicator {
    background: var(--status-warning);
  }

  .proxy-addr-btn {
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    padding: 0;
  }

  .proxy-rate {
    font-size: 10.5px;
    color: var(--status-success);
    padding-left: 4px;
    border-left: 1px solid var(--border-default);
  }

  .proxy-pill.paused .proxy-rate {
    color: var(--status-warning);
    font-weight: 600;
  }

  .proxy-idle-label {
    color: var(--text-muted);
    font-weight: 500;
  }

  .proxy-start-btn {
    height: 20px;
    padding: 0 8px;
    border: 1px solid var(--status-success-border);
    border-radius: var(--radius-full);
    background: var(--status-success-bg);
    color: var(--status-success);
    font-size: 11px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .proxy-start-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--status-success) 24%, transparent);
  }

  .proxy-mini-btn {
    width: 20px;
    height: 20px;
    border: none;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .proxy-mini-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .proxy-mini-btn.danger:hover {
    background: var(--status-danger-bg);
    color: var(--status-danger);
  }

  .lang-pill {
    height: 28px;
    padding: 0 8px;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .lang-pill:hover {
    background: var(--bg-hover);
    border-color: var(--border-strong);
  }

  .lang-seg {
    color: var(--text-faint);
    transition: color var(--transition-fast);
  }

  .lang-seg.active {
    color: var(--accent);
  }

  .lang-div {
    color: var(--border-strong);
    font-weight: 400;
  }

  .topbar-icon-btn {
    width: 28px;
    height: 28px;
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .topbar-icon-btn:hover {
    background: var(--bg-hover);
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  /* ==================== Workspace Viewport ==================== */
  .workspace {
    flex: 1;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    background: var(--bg-app);
  }

  /* ==================== Bottom Status Bar ==================== */
  .statusbar {
    height: var(--statusbar-height);
    flex-shrink: 0;
    background: var(--bg-sidebar);
    border-top: 1px solid var(--border-default);
    padding: 0 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    font-size: 11px;
    color: var(--text-muted);
    user-select: none;
  }

  .status-left,
  .status-right {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .status-item {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 20px;
    padding: 0 5px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .status-item:hover:not(.static) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .status-item.static {
    cursor: default;
  }

  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--text-faint);
  }

  .status-live {
    color: var(--status-success);
  }

  .status-live .status-dot {
    background: var(--status-success);
  }

  .status-warn {
    color: var(--status-warning);
  }

  .status-warn .status-dot {
    background: var(--status-warning);
  }

  .status-bp {
    color: var(--status-warning);
    background: var(--status-warning-bg);
    font-weight: 600;
  }

  .status-sep {
    width: 1px;
    height: 11px;
    background: var(--border-default);
  }

  .status-hint {
    font-size: 10.5px;
    color: var(--text-faint);
    white-space: nowrap;
  }

  .status-copyright {
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .status-copyright:hover {
    color: var(--accent);
  }

  @media (max-width: 1040px) {
    .page-sep,
    .page-subtitle,
    .status-hint {
      display: none;
    }
    .topbar-center {
      flex: 0 1 190px;
    }
  }
</style>
