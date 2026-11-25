<script>
  import { onMount } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate, locale, setLocale, SUPPORTED_LOCALES, getLocaleMeta } from '../lib/i18n.js'
  import { applyTheme, getThemeMeta, currentTheme } from '../lib/theme.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard } from '../lib/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Kbd from '../components/Kbd.svelte'

  const api = () => window?.go?.wailsgui?.App

  let activeSection = 'appearance'

  let settings = {
    theme: 'dark',
    font_size: '13',
    proxy_addr: '0.0.0.0:8080',
    proxy_port: '8080',
    auto_detect: 'true',
    install_cert: 'true',
    max_body_size: '4096',
    frida_python_path: '',
    frida_cli_path: '',
    frida_default_port: '27042',
    re_r2_path: '',
    re_java_path: '',
    re_mvn_path: '',
    re_unidbg_dir: '',
    re_python_path: '',
    re_qiling_python_path: '',
    re_angr_python_path: '',
    re_qiling_rootfs: '',
    gateway_addr: '127.0.0.1:9090',
  }

  let version = 'v0.2.0'
  let proxyRunning = false
  let proxyAddr = ''
  let hostIP = 'auto'
  let flowCount = 0
  let tlsErrors = []
  let confirmClearFlows = false
  let clearingFlows = false

  const themeMeta = getThemeMeta()

  const sectionSpecs = [
    { id: 'appearance', icon: 'palette' },
    { id: 'proxy', icon: 'shield' },
    { id: 'android', icon: 'smartphone' },
    { id: 'relab_gateway', icon: 'cpu' },
    { id: 'storage', icon: 'database' },
    { id: 'shortcuts', icon: 'command' },
    { id: 'about', icon: 'info' },
  ]

  const bodySizePresets = [
    { label: '2 KB', value: '2048' },
    { label: '4 KB', value: '4096' },
    { label: '16 KB', value: '16384' },
    { label: '64 KB', value: '65536' },
  ]

  $: sections = sectionSpecs.map((s) => ({
    ...s,
    label: $t(`tools.settings.sections.${s.id}.label`),
    desc: $t(`tools.settings.sections.${s.id}.desc`),
  }))

  $: shortcutGroups = [
    {
      title: $t('tools.settings.shortcuts.groupNav'),
      items: [
        { label: $t('tools.settings.shortcuts.items.palette'), keys: ['Mod', 'K'] },
        { label: $t('tools.settings.shortcuts.items.sidebar'), keys: ['Mod', 'B'] },
        { label: $t('tools.settings.shortcuts.items.capture'), keys: ['Mod', '1'] },
        { label: $t('tools.settings.shortcuts.items.flows'), keys: ['Mod', '2'] },
        { label: $t('tools.settings.shortcuts.items.rules'), keys: ['Mod', '3'] },
        { label: $t('tools.settings.shortcuts.items.plugins'), keys: ['Mod', '4'] },
        { label: $t('tools.settings.shortcuts.items.trace'), keys: ['Mod', '5'] },
        { label: $t('tools.settings.shortcuts.items.reStatic'), keys: ['Mod', '6'] },
        { label: $t('tools.settings.shortcuts.items.frida'), keys: ['Mod', '7'] },
        { label: $t('tools.settings.shortcuts.items.reEmulate'), keys: ['Mod', '8'] },
        { label: $t('tools.settings.shortcuts.items.gateway'), keys: ['Mod', '9'] },
        { label: $t('tools.settings.shortcuts.items.terminal'), keys: ['Mod', '0'] },
        { label: $t('tools.settings.shortcuts.items.settings'), keys: ['Mod', ','] },
      ],
    },
    {
      title: $t('tools.settings.shortcuts.groupTools'),
      items: [
        { label: $t('tools.settings.shortcuts.items.savePlugin'), keys: ['Mod', 'S'] },
        { label: $t('tools.settings.shortcuts.items.runDraftOrJob'), keys: ['Mod', '↵'] },
        { label: $t('tools.settings.shortcuts.items.hotReloadFrida'), keys: ['Mod', 'R'] },
        { label: $t('tools.settings.shortcuts.items.newTermTab'), keys: ['Mod', 'T'] },
        { label: $t('tools.settings.shortcuts.items.closeTermTab'), keys: ['Mod', 'W'] },
        { label: $t('tools.settings.shortcuts.items.cycleTermTabs'), keys: ['Ctrl', 'Tab'] },
        { label: $t('tools.settings.shortcuts.items.clearTerm'), keys: ['Ctrl', 'L'] },
        { label: $t('tools.settings.shortcuts.items.termHistory'), keys: ['↑', '↓'] },
      ],
    },
  ]

  async function loadAll() {
    const app = api()
    if (!app) return
    try {
      const [s, ver, running, addr, ip, stats, errs] = await Promise.all([
        app.GetSettings?.().catch(() => null),
        app.GetVersion?.().catch(() => ''),
        app.IsProxyRunning?.().catch(() => false),
        app.ProxyAddr?.().catch(() => ''),
        app.GetHostIP?.().catch(() => 'auto'),
        app.GetTrafficStats?.().catch(() => null),
        app.GetTLSErrors?.().catch(() => []),
      ])
      if (s && typeof s === 'object') {
        settings = { ...settings, ...s }
      }
      if (ver) version = ver.startsWith('v') ? ver : `v${ver}`
      proxyRunning = Boolean(running)
      proxyAddr = addr || ''
      hostIP = ip || 'auto'
      if (stats && typeof stats.total_flows === 'number') {
        flowCount = stats.total_flows
      } else if (stats && typeof stats.TotalFlows === 'number') {
        flowCount = stats.TotalFlows
      } else {
        const list = await app.GetFlows?.('', '', '', 1000).catch(() => null)
        if (Array.isArray(list)) flowCount = list.length
      }
      tlsErrors = Array.isArray(errs) ? errs : []
    } catch (_) {}
  }

  function handleSelectLanguage(langId) {
    const resolved = setLocale(langId)
    const meta = getLocaleMeta(resolved)
    toast.success(translate('common.toast.languageSwitched', { lang: meta.nativeLabel }, resolved))
  }

  async function setSetting(key, value, toastMsg = '') {
    const strVal = String(value)
    settings[key] = strVal
    settings = settings

    if (key === 'theme') {
      applyTheme(strVal)
    }
    if (key === 'font_size') {
      document.documentElement.style.setProperty('--font-size', `${strVal}px`)
    }

    const app = api()
    if (!app?.SetSetting) {
      if (toastMsg) toast.success(toastMsg)
      return
    }
    try {
      await app.SetSetting(key, strVal)
      toast.success(toastMsg || translate('tools.settings.toast.saved'))
    } catch (e) {
      toast.error(translate('tools.settings.toast.saveFailed', { key, error: e?.message || e }))
    }
  }

  async function clearTLSErrors() {
    const app = api()
    if (!app?.ClearTLSErrors) return
    try {
      await app.ClearTLSErrors()
      tlsErrors = []
      toast.info(translate('tools.settings.toast.tlsCleared'))
    } catch (e) {
      toast.error(translate('tools.settings.toast.tlsClearFailed', { error: e?.message || e }))
    }
  }

  async function clearCapturedFlows() {
    const app = api()
    if (!app?.ClearFlows) return
    clearingFlows = true
    try {
      await app.ClearFlows()
      flowCount = 0
      confirmClearFlows = false
      toast.success(translate('tools.settings.toast.flowsCleared'))
    } catch (e) {
      toast.error(translate('tools.settings.toast.flowsClearFailed', { error: e?.message || e }))
    } finally {
      clearingFlows = false
    }
  }

  const GITHUB_PROFILE_URL = 'https://github.com/overkazaf'
  const GITHUB_REPO_URL = 'https://github.com/overkazaf/cap'
  const DOCS_URL = 'https://overkazaf.github.io/cap/'

  function openExternal(url) {
    if (!url) return
    try {
      if (window?.runtime?.BrowserOpenURL) {
        window.runtime.BrowserOpenURL(url)
        return
      }
    } catch (_) {}
    window.open(url, '_blank', 'noopener')
  }

  function copyDiagnostics() {
    const diag = [
      `cap ${version}`,
      'Copyright: © 2026 0xaf (@overkazaf) · MIT License',
      `Repository: ${GITHUB_REPO_URL}`,
      `Docs: ${DOCS_URL}`,
      `Locale: ${$locale}`,
      `Theme: ${settings.theme}`,
      `Font size: ${settings.font_size}px`,
      `Proxy default: ${settings.proxy_addr} (port ${settings.proxy_port})`,
      `Gateway default: ${settings.gateway_addr}`,
      `Proxy state: ${proxyRunning ? `running (${proxyAddr})` : 'idle'}`,
      `Captured flows: ${flowCount}`,
      `TLS errors: ${tlsErrors.length}`,
      `Auto-detect ADB: ${settings.auto_detect}`,
      `Auto-install CA: ${settings.install_cert}`,
    ].join('\n')
    copyToClipboard(diag, translate('tools.settings.toast.diagnosticsCopied'))
  }

  $: activeThemeId = $currentTheme || settings.theme || 'dark'
  $: activeLocaleMeta = getLocaleMeta($locale)

  onMount(loadAll)
</script>

<div class="settings-page">
  <!-- Left Section Navigation -->
  <aside class="settings-nav" aria-label={$t('tools.settings.navAria')}>
    <div class="nav-header">
      <span class="nav-title">{$t('tools.settings.sidebarTitle')}</span>
      <span class="nav-ver mono">{version}</span>
    </div>
    <div class="nav-list">
      {#each sections as sec (sec.id)}
        <button
          type="button"
          class="sec-btn"
          class:active={activeSection === sec.id}
          on:click={() => (activeSection = sec.id)}
        >
          <span class="sec-icon"><Icon name={sec.icon} size={15} /></span>
          <span class="sec-text">
            <span class="sec-label">{sec.label}</span>
            <span class="sec-desc">{sec.desc}</span>
          </span>
        </button>
      {/each}
    </div>
  </aside>

  <!-- Right Settings Content -->
  <div class="settings-body">
    <div class="settings-inner">
      {#if activeSection === 'appearance'}
        <header class="panel-head">
          <h2>{$t('tools.settings.appearance.title')}</h2>
          <p>{$t('tools.settings.appearance.subtitle')}</p>
        </header>

        <!-- Display Language Card -->
        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.appearance.languageTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.appearance.languageDesc')}</div>
            </div>
            <Badge variant="accent" size="xs">{activeLocaleMeta.nativeLabel}</Badge>
          </div>

          <div class="lang-grid">
            {#each SUPPORTED_LOCALES as lang (lang.id)}
              <button
                type="button"
                class="lang-card"
                class:active={$locale === lang.id}
                on:click={() => handleSelectLanguage(lang.id)}
              >
                <span class="lang-badge mono">{lang.short}</span>
                <div class="lang-info">
                  <div class="lang-native">{lang.nativeLabel}</div>
                  <div class="lang-sub">
                    {lang.id === 'zh-CN' ? $t('tools.settings.appearance.zhSub') : $t('tools.settings.appearance.enSub')}
                  </div>
                </div>
                {#if $locale === lang.id}
                  <span class="lang-check"><Icon name="check" size={14} /></span>
                {/if}
              </button>
            {/each}
          </div>
        </div>

        <!-- Color Theme Card -->
        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.appearance.themeTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.appearance.themeDesc')}</div>
            </div>
            <Badge variant="accent" size="xs">{$t(`common.themes.${activeThemeId}`)}</Badge>
          </div>

          <div class="theme-grid">
            {#each themeMeta as th (th.id)}
              <button
                type="button"
                class="theme-card"
                class:active={activeThemeId === th.id}
                on:click={() =>
                  setSetting('theme', th.id, translate('common.toast.themeSwitched', { theme: translate(`common.themes.${th.id}`) }))}
              >
                <div class="theme-swatch" style="background: {th.preview.bg};">
                  <div class="swatch-rail" style="background: {th.preview.surface};"></div>
                  <div class="swatch-body">
                    <div class="swatch-bar" style="background: {th.preview.surface};">
                      <span class="swatch-dot" style="background: {th.preview.accent};"></span>
                    </div>
                    <div class="swatch-lines">
                      <span class="swatch-line" style="background: {th.preview.accent}; opacity: 0.75; width: 65%;"></span>
                      <span class="swatch-line" style="background: {th.preview.surface}; width: 88%;"></span>
                    </div>
                  </div>
                </div>
                <div class="theme-card-foot">
                  <span class="theme-name">{$t(`common.themes.${th.id}`)}</span>
                  <span class="theme-scheme">
                    {th.scheme === 'light' ? $t('tools.settings.appearance.schemeLight') : $t('tools.settings.appearance.schemeDark')}
                  </span>
                  {#if activeThemeId === th.id}
                    <span class="theme-check"><Icon name="check" size={12} /></span>
                  {/if}
                </div>
              </button>
            {/each}
          </div>
        </div>

        <!-- Interface Font Size Card -->
        <div class="pref-card cap-card">
          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.appearance.fontSizeTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.appearance.fontSizeDesc')}</div>
            </div>
            <div class="range-control">
              <input
                type="range"
                min="11"
                max="18"
                step="1"
                bind:value={settings.font_size}
                on:change={() =>
                  setSetting('font_size', settings.font_size, translate('tools.settings.toast.fontSizeSet', { size: settings.font_size }))}
                class="range-slider"
              />
              <span class="range-val mono tabular-nums">{settings.font_size}px</span>
              {#if settings.font_size !== '13'}
                <Button
                  variant="ghost"
                  size="xs"
                  on:click={() => setSetting('font_size', '13', translate('tools.settings.toast.fontSizeReset'))}
                >
                  {$t('common.actions.reset')}
                </Button>
              {/if}
            </div>
          </div>
          <div class="font-preview">
            <Badge variant="method" method="POST" size="xs" />
            <span class="mono" style="font-size: {settings.font_size}px;">https://api.example.com/v2/session/refresh</span>
            <Badge variant="status" status={200} size="xs" />
          </div>
        </div>

      {:else if activeSection === 'proxy'}
        <header class="panel-head">
          <h2>{$t('tools.settings.proxy.title')}</h2>
          <p>{$t('tools.settings.proxy.subtitle')}</p>
        </header>

        <div class="pref-card cap-card">
          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.proxy.bindAddrTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.proxy.bindAddrDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.proxy_addr}
              on:change={() => setSetting('proxy_addr', settings.proxy_addr, translate('tools.settings.toast.proxyAddrUpdated'))}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.proxy.portTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.proxy.portDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono port-input tabular-nums"
              bind:value={settings.proxy_port}
              on:change={() => setSetting('proxy_port', settings.proxy_port, translate('tools.settings.toast.proxyPortUpdated'))}
            />
          </div>
        </div>

        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.proxy.runtimeTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.proxy.runtimeDesc')}</div>
            </div>
            <Badge variant={proxyRunning ? 'success' : 'neutral'} size="xs" dot pulse={proxyRunning}>
              {proxyRunning ? $t('tools.settings.proxy.listening') : $t('tools.settings.proxy.idle')}
            </Badge>
          </div>

          <div class="status-grid">
            <div class="stat-tile">
              <span class="stat-k">{$t('tools.settings.proxy.activeListener')}</span>
              <span class="stat-v mono tabular-nums">{proxyRunning ? proxyAddr : $t('tools.settings.proxy.notRunning')}</span>
            </div>
            <div class="stat-tile">
              <span class="stat-k">{$t('tools.settings.proxy.resolvedHostIp')}</span>
              <span class="stat-v mono tabular-nums">{hostIP}</span>
            </div>
            <div class="stat-tile">
              <span class="stat-k">{$t('tools.settings.proxy.caStorePath')}</span>
              <span class="stat-v mono">~/.cap/ca.crt</span>
            </div>
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.proxy.tlsErrorsTitle', { count: tlsErrors.length })}</div>
              <div class="pref-desc">{$t('tools.settings.proxy.tlsErrorsDesc')}</div>
            </div>
            <Button variant="secondary" size="xs" icon="trash" disabled={tlsErrors.length === 0} on:click={clearTLSErrors}>
              {$t('tools.settings.proxy.clearLog')}
            </Button>
          </div>
          {#if tlsErrors.length > 0}
            <div class="tls-list">
              {#each tlsErrors as err}
                <div class="tls-row mono">
                  <span>{err.host}</span>
                  <Badge variant="danger" size="xs" mono>{err.count}x</Badge>
                </div>
              {/each}
            </div>
          {/if}
        </div>

      {:else if activeSection === 'android'}
        <header class="panel-head">
          <h2>{$t('tools.settings.android.title')}</h2>
          <p>{$t('tools.settings.android.subtitle')}</p>
        </header>

        <div class="pref-card cap-card">
          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.android.autoDetectTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.autoDetectDesc')}</div>
            </div>
            <label class="switch">
              <input
                type="checkbox"
                checked={settings.auto_detect === 'true'}
                on:change={(e) =>
                  setSetting(
                    'auto_detect',
                    e.target.checked ? 'true' : 'false',
                    translate(e.target.checked ? 'tools.settings.toast.autoDetectEnabled' : 'tools.settings.toast.autoDetectDisabled')
                  )}
              />
              <span class="switch-track"></span>
            </label>
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.android.autoCertTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.autoCertDesc')}</div>
            </div>
            <label class="switch">
              <input
                type="checkbox"
                checked={settings.install_cert === 'true'}
                on:change={(e) =>
                  setSetting(
                    'install_cert',
                    e.target.checked ? 'true' : 'false',
                    translate(e.target.checked ? 'tools.settings.toast.autoCertEnabled' : 'tools.settings.toast.autoCertDisabled')
                  )}
              />
              <span class="switch-track"></span>
            </label>
          </div>
        </div>

        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.android.fridaTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.fridaDesc')}</div>
            </div>
            <Badge variant="accent" size="xs" mono>Frida</Badge>
          </div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.android.fridaPythonTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.fridaPythonDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.frida_python_path}
              placeholder="auto"
              on:change={() => setSetting('frida_python_path', settings.frida_python_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.android.fridaCliTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.fridaCliDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.frida_cli_path}
              placeholder="auto"
              on:change={() => setSetting('frida_cli_path', settings.frida_cli_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.android.fridaPortTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.android.fridaPortDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono port-input tabular-nums"
              bind:value={settings.frida_default_port}
              placeholder="27042"
              on:change={() => setSetting('frida_default_port', settings.frida_default_port)}
            />
          </div>
        </div>

      {:else if activeSection === 'relab_gateway'}
        <header class="panel-head">
          <h2>{$t('tools.settings.relabGateway.title')}</h2>
          <p>{$t('tools.settings.relabGateway.subtitle')}</p>
        </header>

        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.relabGateway.reTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.reDesc')}</div>
            </div>
            <Badge variant="accent" size="xs" mono>RE Lab</Badge>
          </div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.r2Title')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.r2Desc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_r2_path}
              placeholder="auto"
              on:change={() => setSetting('re_r2_path', settings.re_r2_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.javaTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.javaDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_java_path}
              placeholder="auto"
              on:change={() => setSetting('re_java_path', settings.re_java_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.mvnTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.mvnDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_mvn_path}
              placeholder="auto"
              on:change={() => setSetting('re_mvn_path', settings.re_mvn_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.unidbgTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.unidbgDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_unidbg_dir}
              placeholder="/path/to/unidbg"
              on:change={() => setSetting('re_unidbg_dir', settings.re_unidbg_dir)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.pythonTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.pythonDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_python_path}
              placeholder="auto"
              on:change={() => setSetting('re_python_path', settings.re_python_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.qilingPythonTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.qilingPythonDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_qiling_python_path}
              placeholder="auto"
              on:change={() => setSetting('re_qiling_python_path', settings.re_qiling_python_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.angrPythonTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.angrPythonDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_angr_python_path}
              placeholder="auto"
              on:change={() => setSetting('re_angr_python_path', settings.re_angr_python_path)}
            />
          </div>

          <div class="pref-divider"></div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.qilingTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.qilingDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.re_qiling_rootfs}
              placeholder="/path/to/qiling/rootfs/arm64_linux"
              on:change={() => setSetting('re_qiling_rootfs', settings.re_qiling_rootfs)}
            />
          </div>
        </div>

        <div class="pref-card cap-card">
          <div class="pref-card-head">
            <div>
              <div class="pref-title">{$t('tools.settings.relabGateway.gwTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.gwDesc')}</div>
            </div>
            <Badge variant="accent" size="xs" mono>Gateway</Badge>
          </div>

          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.relabGateway.gwAddrTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.relabGateway.gwAddrDesc')}</div>
            </div>
            <input
              type="text"
              class="cap-input mono addr-input"
              bind:value={settings.gateway_addr}
              placeholder="127.0.0.1:9090"
              on:change={() => setSetting('gateway_addr', settings.gateway_addr, translate('tools.settings.toast.gatewayAddrUpdated'))}
            />
          </div>
        </div>

      {:else if activeSection === 'storage'}
        <header class="panel-head">
          <h2>{$t('tools.settings.storage.title')}</h2>
          <p>{$t('tools.settings.storage.subtitle')}</p>
        </header>

        <div class="pref-card cap-card">
          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.storage.maxBodyTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.storage.maxBodyDesc')}</div>
            </div>
            <div class="size-control">
              <input
                type="text"
                class="cap-input mono port-input tabular-nums"
                bind:value={settings.max_body_size}
                on:change={() => setSetting('max_body_size', settings.max_body_size, translate('tools.settings.toast.maxBodyUpdated'))}
              />
              <span class="unit-label">{$t('tools.settings.storage.bytesUnit')}</span>
            </div>
          </div>

          <div class="preset-chips-row">
            {#each bodySizePresets as p}
              <button
                type="button"
                class="size-chip mono"
                class:active={settings.max_body_size === p.value}
                on:click={() =>
                  setSetting('max_body_size', p.value, translate('tools.settings.toast.maxBodyPreset', { label: p.label }))}
              >
                {p.label} ({p.value})
              </button>
            {/each}
          </div>
        </div>

        <div class="pref-card cap-card">
          <div class="pref-row">
            <div class="pref-info">
              <div class="pref-title">{$t('tools.settings.storage.dbTitle')}</div>
              <div class="pref-desc">{$t('tools.settings.storage.dbDesc', { count: flowCount.toLocaleString() })}</div>
            </div>
            <div class="maint-actions">
              {#if confirmClearFlows}
                <Button variant="danger" size="xs" icon="trash" loading={clearingFlows} on:click={clearCapturedFlows}>
                  {$t('tools.settings.storage.confirmClearAll')}
                </Button>
                <Button variant="ghost" size="xs" on:click={() => (confirmClearFlows = false)}>{$t('common.actions.cancel')}</Button>
              {:else}
                <Button
                  variant="danger"
                  size="xs"
                  icon="trash"
                  disabled={flowCount === 0}
                  on:click={() => (confirmClearFlows = true)}
                >
                  {$t('tools.settings.storage.clearAllFlows')}
                </Button>
              {/if}
            </div>
          </div>
        </div>

      {:else if activeSection === 'shortcuts'}
        <header class="panel-head">
          <h2>{$t('tools.settings.shortcuts.title')}</h2>
          <p>{$t('tools.settings.shortcuts.subtitle')}</p>
        </header>

        {#each shortcutGroups as group}
          <div class="pref-card cap-card">
            <div class="pref-title">{group.title}</div>
            <div class="shortcuts-table">
              {#each group.items as item}
                <div class="shortcut-row">
                  <span class="shortcut-label">{item.label}</span>
                  <Kbd keys={item.keys} size="sm" />
                </div>
              {/each}
            </div>
          </div>
        {/each}

      {:else if activeSection === 'about'}
        <header class="panel-head">
          <h2>{$t('tools.settings.about.title')}</h2>
          <p>{$t('tools.settings.about.subtitle')}</p>
        </header>

        <div class="pref-card cap-card about-card">
          <div class="about-hero">
            <div class="about-mark">
              <Icon name="radar" size={22} />
            </div>
            <div class="about-hero-text">
              <div class="about-name">
                <span>cap</span>
                <Badge variant="accent" size="xs" mono>{version}</Badge>
                <Badge variant="neutral" size="xs" mono>MIT</Badge>
              </div>
              <div class="about-tagline">{$t('tools.settings.about.tagline')}</div>
            </div>
          </div>

          <div class="pref-divider"></div>

          <div class="about-meta-grid">
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.author')}</span>
              <button
                type="button"
                class="about-link mono"
                title={$t('tools.settings.about.openLinkTitle', { url: GITHUB_PROFILE_URL })}
                on:click={() => openExternal(GITHUB_PROFILE_URL)}
              >
                <span>0xaf (@overkazaf)</span>
                <Icon name="external-link" size={11} />
              </button>
            </div>
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.repository')}</span>
              <button
                type="button"
                class="about-link mono"
                title={$t('tools.settings.about.openLinkTitle', { url: GITHUB_REPO_URL })}
                on:click={() => openExternal(GITHUB_REPO_URL)}
              >
                <span>github.com/overkazaf/cap</span>
                <Icon name="external-link" size={11} />
              </button>
            </div>
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.documentation')}</span>
              <button
                type="button"
                class="about-link mono"
                title={$t('tools.settings.about.openLinkTitle', { url: DOCS_URL })}
                on:click={() => openExternal(DOCS_URL)}
              >
                <span>overkazaf.github.io/cap</span>
                <Icon name="external-link" size={11} />
              </button>
            </div>
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.license')}</span>
              <span class="stat-v">{$t('tools.settings.about.copyrightNotice')}</span>
            </div>
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.runtime')}</span>
              <span class="stat-v mono">Go + Wails v2 + Svelte 4</span>
            </div>
            <div class="meta-kv">
              <span class="stat-k">{$t('tools.settings.about.configDir')}</span>
              <span class="stat-v mono">~/.cap</span>
            </div>
          </div>

          <div class="pref-divider"></div>

          <div class="about-footer">
            <Button variant="secondary" size="sm" icon="external-link" on:click={() => openExternal(GITHUB_REPO_URL)}>
              {$t('tools.settings.about.openGithub')}
            </Button>
            <Button variant="secondary" size="sm" icon="copy" on:click={copyDiagnostics}>
              {$t('tools.settings.about.copyDiagnostics')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              icon="refresh"
              on:click={() => {
                loadAll()
                toast.info(translate('tools.settings.toast.statusRefreshed'))
              }}
            >
              {$t('tools.settings.about.refreshStatus')}
            </Button>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .settings-page {
    display: flex;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Left Preference Sidebar */
  .settings-nav {
    width: 224px;
    flex-shrink: 0;
    background: var(--bg-header);
    border-right: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .nav-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .nav-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .nav-ver {
    font-size: 10px;
    color: var(--text-faint);
    padding: 1px 6px;
    border-radius: var(--radius-xs);
    background: var(--bg-subtle);
  }

  .nav-list {
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    overflow-y: auto;
  }

  .sec-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-secondary);
    text-align: left;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .sec-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .sec-btn.active {
    background: var(--bg-active);
    border-color: var(--accent-border);
    color: var(--text-primary);
  }

  .sec-btn.active .sec-icon {
    color: var(--accent);
  }

  .sec-icon {
    color: var(--text-muted);
    display: flex;
    flex-shrink: 0;
  }

  .sec-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }

  .sec-label {
    font-size: var(--text-sm);
    font-weight: 600;
  }

  .sec-desc {
    font-size: 11px;
    color: var(--text-muted);
  }

  /* Right Content Area */
  .settings-body {
    flex: 1;
    overflow-y: auto;
    padding: 24px 28px;
    min-width: 0;
  }

  .settings-inner {
    max-width: 680px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .panel-head h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--text-primary);
  }

  .panel-head p {
    font-size: var(--text-sm);
    color: var(--text-muted);
    margin-top: 3px;
  }

  .pref-card {
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .pref-card-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .pref-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .pref-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .pref-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .pref-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .pref-divider {
    height: 1px;
    background: var(--border-subtle);
  }

  /* Language Cards */
  .lang-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .lang-card {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 11px 13px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    cursor: pointer;
    text-align: left;
    transition: all var(--transition-fast);
  }

  .lang-card:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .lang-card.active {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: var(--focus-ring);
  }

  .lang-badge {
    width: 36px;
    height: 28px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 700;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .lang-card.active .lang-badge {
    background: var(--accent);
    border-color: transparent;
    color: var(--text-inverse);
  }

  .lang-info {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
  }

  .lang-native {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .lang-sub {
    font-size: 11px;
    color: var(--text-muted);
  }

  .lang-check {
    margin-left: auto;
    color: var(--accent);
    display: flex;
    flex-shrink: 0;
  }

  /* Theme Cards */
  .theme-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }

  .theme-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 8px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    cursor: pointer;
    text-align: left;
    transition: all var(--transition-fast);
  }

  .theme-card:hover {
    border-color: var(--border-strong);
  }

  .theme-card.active {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: var(--focus-ring);
  }

  .theme-swatch {
    height: 54px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-subtle);
    display: flex;
    overflow: hidden;
  }

  .swatch-rail {
    width: 24%;
    height: 100%;
    border-right: 1px solid rgba(128, 128, 128, 0.16);
  }

  .swatch-body {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  .swatch-bar {
    height: 14px;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding: 0 5px;
    border-bottom: 1px solid rgba(128, 128, 128, 0.14);
  }

  .swatch-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }

  .swatch-lines {
    padding: 7px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .swatch-line {
    height: 4px;
    border-radius: 2px;
  }

  .theme-card-foot {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .theme-name {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .theme-scheme {
    font-size: 10px;
    color: var(--text-faint);
  }

  .theme-check {
    margin-left: auto;
    color: var(--accent);
    display: flex;
  }

  /* Font Size Slider & Preview */
  .range-control {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }

  .range-slider {
    width: 140px;
    accent-color: var(--accent);
    cursor: pointer;
  }

  .range-val {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    min-width: 34px;
    text-align: right;
  }

  .font-preview {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    overflow: hidden;
  }

  /* Inputs */
  .addr-input {
    width: 210px;
  }

  .port-input {
    width: 110px;
  }

  .size-control {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .unit-label {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .preset-chips-row {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .size-chip {
    padding: 4px 9px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .size-chip:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .size-chip.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  /* Status Grid */
  .status-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
  }

  .stat-tile {
    padding: 10px 12px;
    border-radius: var(--radius-md);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .stat-k {
    font-size: 10.5px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .stat-v {
    font-size: var(--text-xs);
    color: var(--text-primary);
    font-weight: 500;
  }

  .tls-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    max-height: 160px;
    overflow-y: auto;
  }

  .tls-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 5px 10px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .maint-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  /* Toggle Switch */
  .switch {
    position: relative;
    display: inline-block;
    width: 36px;
    height: 20px;
    flex-shrink: 0;
    cursor: pointer;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
    position: absolute;
  }

  .switch-track {
    position: absolute;
    inset: 0;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .switch-track::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: transform var(--transition-fast), background var(--transition-fast);
  }

  .switch input:checked + .switch-track {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .switch input:checked + .switch-track::after {
    transform: translateX(16px);
    background: var(--status-success);
  }

  .switch input:focus-visible + .switch-track {
    box-shadow: var(--focus-ring);
  }

  /* Shortcuts Table */
  .shortcuts-table {
    display: flex;
    flex-direction: column;
  }

  .shortcut-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid var(--border-subtle);
  }

  .shortcut-row:last-child {
    border-bottom: none;
    padding-bottom: 0;
  }

  .shortcut-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  /* About Card */
  .about-hero {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .about-mark {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-lg);
    background: var(--accent-soft);
    border: 1px solid var(--accent-border);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .about-name {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-lg);
    font-weight: 700;
    color: var(--text-primary);
  }

  .about-tagline {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: 2px;
  }

  .about-meta-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px 16px;
  }

  .meta-kv {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
    min-width: 0;
  }

  .about-link {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
    text-align: left;
    transition: color var(--transition-fast);
  }

  .about-link:hover {
    color: var(--accent-hover);
    text-decoration: underline;
  }

  .about-footer {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    padding-top: 2px;
  }
</style>
