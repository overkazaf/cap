<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/core.js'
  import { t, translate } from '../lib/i18n.js'
  import { state as S, flowsState as FS, appendCaptureLog } from '../lib/captureState.js'
  import { formatBytes, formatDuration, formatCount, copyToClipboard } from '../lib/format.js'
  import { navigate } from '../lib/navigation.js'
  import { openFridaStudio } from '../lib/fridaState.js'
  import { toast } from '../lib/toast.js'
  import { registerCommands } from '../lib/commandPalette.js'

  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  const appApi = () => window?.go?.wailsgui?.App

  let proxyAddr = S.proxyAddr
  let liveAddr = S.liveAddr
  let hostIP = S.hostIP
  let isRunning = S.isRunning
  let isPaused = S.isPaused
  let rate = S.rate
  let stats = S.stats
  let tlsErrors = S.tlsErrors
  let logs = S.logs
  let logFilter = ''

  let devices = S.devices
  let selectedDevice = S.selectedDevice
  let deviceConnected = S.deviceConnected
  let connStatus = S.connStatus
  let caCertInfo = S.caCertInfo
  let port = S.port
  let installCert = S.installCert
  let vpnMode = S.vpnMode
  let installCompanion = S.installCompanion
  let deviceEnv = S.deviceEnv
  let fridaStatus = S.fridaStatus
  let wifiAddr = S.wifiAddr
  let apps = S.apps
  let selectedApp = S.selectedApp

  let whitelistText = S.whitelistText
  let blacklistText = S.blacklistText

  let rightTab = S.rightTab || 'logs'
  let showWifiPanel = S.showWifiPanel
  let showDomainFilter = S.showDomainFilter

  let proxyBusy = false
  let deviceBusy = false
  let statusLoading = false
  let certBusy = false
  let guardBusy = false
  let envLoading = false
  let fridaBusy = false
  let wifiBusy = false
  let appsLoading = false
  let filterSaving = false
  let syncInFlight = false
  let lastManualCertPrompt = false

  let logEl = null
  let pollTimer = null
  let unsubs = []
  let unregisterCmds = null

  $: {
    S.proxyAddr = proxyAddr
    S.liveAddr = liveAddr
    S.hostIP = hostIP
    S.isRunning = isRunning
    S.isPaused = isPaused
    S.rate = rate
    S.stats = stats
    S.tlsErrors = tlsErrors
    S.logs = logs
    S.devices = devices
    S.selectedDevice = selectedDevice
    S.deviceConnected = deviceConnected
    S.connStatus = connStatus
    S.caCertInfo = caCertInfo
    S.port = port
    S.installCert = installCert
    S.vpnMode = vpnMode
    S.installCompanion = installCompanion
    S.deviceEnv = deviceEnv
    S.fridaStatus = fridaStatus
    S.wifiAddr = wifiAddr
    S.apps = apps
    S.selectedApp = selectedApp
    S.whitelistText = whitelistText
    S.blacklistText = blacklistText
    S.rightTab = rightTab
    S.showWifiPanel = showWifiPanel
    S.showDomainFilter = showDomainFilter
  }

  $: displayAddr = (isRunning && liveAddr) ? liveAddr : proxyAddr
  $: totalFlows = stats?.total_flows ?? rate?.total_reqs ?? 0
  $: totalBytes = stats?.total_bytes ?? rate?.total_bytes ?? 0
  $: activeHosts = stats?.by_host?.length ?? 0
  $: errorRatePct = stats && typeof stats.error_rate === 'number' ? (stats.error_rate * 100) : 0
  $: errorVariant = errorRatePct >= 10 ? 'danger' : errorRatePct > 0 ? 'warning' : 'success'
  $: topHosts = stats?.by_host?.slice(0, 12) || []
  $: filteredLogs = logFilter.trim()
    ? logs.filter((l) => {
        const text = typeof l === 'string' ? l : `${l.time} ${l.level} ${l.msg}`
        return text.toLowerCase().includes(logFilter.trim().toLowerCase())
      })
    : logs

  $: hasDevice = devices.length > 0 && Boolean(selectedDevice)
  $: isWifiDevice = Boolean(selectedDevice && selectedDevice.includes(':'))
  $: isRooted = Boolean(connStatus?.rooted || deviceEnv?.rooted)

  $: certStore = connStatus?.cert_status?.store || 'none'
  $: certMethod = connStatus?.cert_status?.method || ''
  $: certDetails = connStatus?.cert_status?.details || ''
  $: certInstalled = Boolean(connStatus?.cert_status?.installed)
  $: certHash = connStatus?.cert_status?.hash || caCertInfo?.hash || ''
  $: certNeedsReboot = Boolean(connStatus?.cert_status?.needs_reboot)

  $: companion = connStatus?.companion || null
  $: companionInstalled = Boolean(companion?.installed)
  $: companionWatchdog = Boolean(companion?.watchdog_running)
  $: companionPerm = Boolean(companion?.has_secure_settings)

  $: proxyMismatch = Boolean(connStatus?.proxy_mismatch)
  $: activeRouteConnected = Boolean(connStatus ? connStatus.connected : deviceConnected)
  $: activeRouteMode = connStatus?.mode === 'vpn' ? $t('core.capture.device.modeVpn') : $t('core.capture.device.modeProxy')

  $: certStoreLabel =
    certNeedsReboot && !certInstalled
      ? $t('core.capture.protection.certNeedsReboot')
      : certInstalled && certStore === 'system'
        ? $t('core.capture.protection.certStoreSystem')
        : certInstalled && certStore === 'user'
          ? $t('core.capture.protection.certStoreUser')
          : $t('core.capture.protection.certStoreNone')

  $: certStoreVariant =
    certNeedsReboot && !certInstalled
      ? 'warning'
      : certInstalled && certStore === 'system'
        ? 'success'
        : certInstalled && certStore === 'user'
          ? 'info'
          : 'warning'

  $: guardStatusLabel = companionWatchdog
    ? $t('core.capture.protection.guardWatchdogActive')
    : companionInstalled
      ? $t('core.capture.protection.guardInstalledIdle')
      : $t('core.capture.protection.guardNotInstalled')

  $: guardStatusVariant = companionWatchdog ? 'success' : companionInstalled ? 'info' : 'neutral'

  $: setupSteps = [
    {
      id: 'adb',
      label: $t('core.capture.device.stepAdb'),
      done: hasDevice,
      detail: hasDevice
        ? `${isWifiDevice ? 'Wi-Fi' : 'USB'} · ${isRooted ? $t('core.capture.profile.rooted') : $t('core.capture.profile.noRoot')}`
        : $t('core.capture.device.stepAdbNone'),
    },
    {
      id: 'cert',
      label: $t('core.capture.device.stepCert'),
      done: certInstalled,
      warn: certNeedsReboot || (!certInstalled && (certMethod === 'legacy_system_only' || certMethod === 'fingerprint_mismatch')),
      detail:
        certNeedsReboot && !certInstalled
          ? $t('core.capture.protection.certNeedsReboot')
          : certInstalled && certStore === 'system'
            ? $t('core.capture.device.stepCertSystem')
            : certInstalled && certStore === 'user'
              ? $t('core.capture.device.stepCertUser')
              : $t('core.capture.device.stepCertNone'),
    },
    {
      id: 'guard',
      label: $t('core.capture.device.stepGuard'),
      done: companionWatchdog || companionInstalled,
      pulse: companionWatchdog,
      detail: companionWatchdog
        ? $t('core.capture.device.stepGuardActive')
        : companionInstalled
          ? $t('core.capture.device.stepGuardIdle')
          : $t('core.capture.device.stepGuardNone'),
    },
    {
      id: 'route',
      label: $t('core.capture.device.stepRoute'),
      done: activeRouteConnected && !proxyMismatch,
      warn: proxyMismatch,
      detail: proxyMismatch
        ? $t('core.capture.device.stepRouteMismatch', { actual: connStatus?.proxy_address || '?' })
        : activeRouteConnected
          ? $t('core.capture.device.stepRouteActive', { mode: activeRouteMode })
          : $t('core.capture.device.stepRouteIdle'),
    },
  ]

  // Reactive Command Palette registration
  $: {
    const _t = $t
    if (unregisterCmds) {
      unregisterCmds()
      unregisterCmds = null
    }
    if (typeof window !== 'undefined') {
      const catDevice = _t('nav.capture.title') !== 'nav.capture.title' ? _t('nav.capture.title') : 'Capture'
      unregisterCmds = registerCommands([
        {
          id: 'capture:scan-devices',
          label: _t('core.capture.cmd.scanDevices'),
          category: catDevice,
          icon: 'smartphone',
          keywords: 'adb android usb refresh scan',
          run: refreshDevices,
        },
        {
          id: 'capture:copy-addr',
          label: _t('core.capture.cmd.copyAddr'),
          category: catDevice,
          icon: 'copy',
          keywords: 'ip port host proxy',
          run: copyProxyAddress,
        },
        {
          id: 'capture:install-cert',
          label: _t('core.capture.cmd.installCert'),
          category: catDevice,
          icon: 'shield-check',
          keywords: 'ca certificate ssl mitm android',
          run: installDeviceCert,
        },
        {
          id: 'capture:install-guard',
          label: _t('core.capture.cmd.installGuard'),
          category: catDevice,
          icon: 'shield',
          keywords: 'companion apk watchdog guard android',
          run: installCompanionApk,
        },
      ])
    }
  }

  function extractValidPort(addr) {
    if (!addr || typeof addr !== 'string') return ''
    const trimmed = addr.trim()
    const idx = trimmed.lastIndexOf(':')
    if (idx < 0) return ''
    const candidate = trimmed.slice(idx + 1).trim()
    if (!/^\d{1,5}$/.test(candidate)) return ''
    const num = Number(candidate)
    return num >= 1 && num <= 65535 ? String(num) : ''
  }

  function replaceAddrPort(addr, newPort) {
    const trimmed = String(addr || '').trim()
    const idx = trimmed.lastIndexOf(':')
    const hostPart = idx >= 0 ? trimmed.slice(0, idx) : (trimmed || '0.0.0.0')
    return `${hostPart}:${newPort}`
  }

  function handleProxyAddrInput() {
    const parsed = extractValidPort(proxyAddr)
    if (parsed) port = parsed
  }

  function handlePortInput() {
    if (isRunning) return
    const trimmed = String(port || '').trim()
    if (!/^\d{1,5}$/.test(trimmed)) return
    const num = Number(trimmed)
    if (num >= 1 && num <= 65535) {
      proxyAddr = replaceAddrPort(proxyAddr, String(num))
    }
  }

  async function addLog(msg, level = 'info') {
    logs = appendCaptureLog(msg, level)
    await tick()
    if (logEl && rightTab === 'logs') {
      logEl.scrollTop = logEl.scrollHeight
    }
  }

  async function syncBackendState() {
    const api = appApi()
    if (!api || syncInFlight) return
    syncInFlight = true
    try {
      const [running, paused, addr, ip, st, errs] = await Promise.all([
        api.IsProxyRunning?.().catch(() => isRunning),
        api.IsPaused?.().catch(() => isPaused),
        api.ProxyAddr?.().catch(() => ''),
        api.GetHostIP?.().catch(() => ''),
        api.GetTrafficStats?.().catch(() => null),
        api.GetTLSErrors?.().catch(() => []),
      ])
      isRunning = Boolean(running)
      isPaused = Boolean(paused)
      if (addr) {
        liveAddr = addr
        const livePort = extractValidPort(addr)
        if (isRunning && livePort) port = livePort
      } else if (!isRunning) {
        liveAddr = ''
      }
      if (ip) hostIP = ip
      if (st) stats = st
      if (Array.isArray(errs)) tlsErrors = errs

      if (isRunning) {
        const r = await api.GetTrafficRate?.().catch(() => null)
        if (r) rate = r
      } else {
        rate = { ...rate, req_per_sec: 0, byte_per_sec: 0 }
      }
    } catch (_) {}
    syncInFlight = false
  }

  async function loadCACertInfo() {
    const api = appApi()
    if (!api?.GetCACertInfo) return
    try {
      caCertInfo = await api.GetCACertInfo()
    } catch (_) {}
  }

  async function refreshConnectionStatus(serial = selectedDevice) {
    const api = appApi()
    if (!api?.GetDeviceConnectionStatus || !serial) {
      connStatus = null
      deviceConnected = false
      return
    }
    if (statusLoading) return
    statusLoading = true
    try {
      const st = await api.GetDeviceConnectionStatus(serial)
      if (st) {
        connStatus = st
        deviceConnected = Boolean(st.connected)
        if (st.mode === 'vpn') vpnMode = true
      }
    } catch (_) {}
    statusLoading = false
  }

  async function loadDomainFilter() {
    const api = appApi()
    if (!api?.GetDomainFilter) return
    try {
      const df = await api.GetDomainFilter()
      if (df) {
        whitelistText = (df.whitelist || []).join(', ')
        blacklistText = (df.blacklist || []).join(', ')
      }
    } catch (_) {}
  }

  async function saveDomainFilter() {
    const api = appApi()
    if (!api?.SetDomainFilter) return
    filterSaving = true
    try {
      const parseList = (txt) =>
        txt
          .split(/[,\n]+/)
          .map((s) => s.trim())
          .filter(Boolean)
      const wl = parseList(whitelistText)
      const bl = parseList(blacklistText)
      await api.SetDomainFilter(wl, bl)
      addLog(translate('core.capture.logs.domainFilterUpdated', { allow: wl.length, block: bl.length }), 'success')
      toast.success(translate('core.capture.toast.domainFilterUpdated'))
    } catch (e) {
      addLog(translate('core.capture.logs.domainFilterError', { err: e }), 'error')
      toast.error(translate('core.capture.toast.domainFilterFailed', { err: e }))
    }
    filterSaving = false
  }

  async function toggleProxy() {
    const api = appApi()
    if (!api || proxyBusy) return
    proxyBusy = true
    try {
      if (isRunning) {
        await api.StopProxy()
        isRunning = false
        isPaused = false
        liveAddr = ''
        rate = { ...rate, req_per_sec: 0, byte_per_sec: 0 }
        addLog(translate('core.capture.logs.proxyStopped'), 'info')
        toast.info(translate('core.capture.toast.proxyStopped'))
        if (selectedDevice) refreshConnectionStatus(selectedDevice)
      } else {
        await api.StartProxy(proxyAddr)
        isRunning = true
        isPaused = false
        const addr = (await api.ProxyAddr?.().catch(() => proxyAddr)) || proxyAddr
        liveAddr = addr
        const parsedPort = extractValidPort(addr)
        if (parsedPort) port = parsedPort
        addLog(translate('core.capture.logs.proxyListening', { addr }), 'success')
        toast.success(translate('core.capture.toast.proxyStarted', { addr }))
        syncBackendState()
        loadCACertInfo()
      }
    } catch (e) {
      addLog(translate('core.capture.logs.proxyError', { err: e }), 'error')
      toast.error(translate('core.capture.toast.proxyError', { err: e }))
    }
    proxyBusy = false
  }

  async function togglePause() {
    const api = appApi()
    if (!api || !isRunning) return
    try {
      if (isPaused) {
        await api.ResumeCapture()
        isPaused = false
        addLog(translate('core.capture.logs.captureResumed'), 'success')
        toast.info(translate('core.capture.toast.captureResumed'))
      } else {
        await api.PauseCapture()
        isPaused = true
        addLog(translate('core.capture.logs.capturePaused'), 'warn')
        toast.warning(translate('core.capture.toast.capturePaused'))
      }
    } catch (e) {
      addLog(translate('core.capture.logs.captureToggleFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.actionFailed', { err: e }))
    }
  }

  async function copyProxyAddress() {
    const addr = displayAddr || proxyAddr
    await copyToClipboard(addr, translate('core.capture.copiedAddr', { addr }))
  }

  async function refreshDevices() {
    const api = appApi()
    if (!api?.ListDevices || deviceBusy) return
    deviceBusy = true
    addLog(translate('core.capture.logs.scanningDevices'), 'info')
    try {
      const devs = await api.ListDevices()
      devices = devs || []
      if (devices.length > 0) {
        if (!devices.some((d) => d.serial === selectedDevice)) {
          selectedDevice = devices[0].serial
        }
        addLog(
          translate('core.capture.logs.foundDevices', {
            count: devices.length,
            list: devices.map((d) => d.serial).join(', '),
          }),
          'success'
        )
        await Promise.all([refreshConnectionStatus(selectedDevice), scanEnv()])
      } else {
        selectedDevice = ''
        deviceEnv = null
        fridaStatus = null
        connStatus = null
        deviceConnected = false
        addLog(translate('core.capture.logs.noDevices'), 'warn')
      }
    } catch (e) {
      addLog(translate('core.capture.logs.scanFailed', { err: e }), 'error')
    }
    deviceBusy = false
  }

  async function onDeviceChange() {
    deviceEnv = null
    fridaStatus = null
    connStatus = null
    apps = []
    selectedApp = ''
    lastManualCertPrompt = false
    if (selectedDevice) {
      await Promise.all([refreshConnectionStatus(selectedDevice), scanEnv()])
    }
  }

  async function connectDevice() {
    const api = appApi()
    if (!api || !selectedDevice) {
      toast.warning(translate('core.capture.toast.selectDeviceFirst'))
      return
    }
    deviceBusy = true
    const modeLabel = vpnMode ? translate('core.capture.device.modeVpn') : translate('core.capture.device.modeProxy')
    addLog(
      translate('core.capture.logs.connectingDevice', {
        serial: selectedDevice,
        port,
        mode: modeLabel,
        cert: installCert ? 'on' : 'off',
        guard: installCompanion ? 'on' : 'off',
      }),
      'info'
    )
    try {
      if (api.ConnectDeviceAdvanced) {
        const st = await api.ConnectDeviceAdvanced(selectedDevice, port, installCert, vpnMode, installCompanion)
        if (st) {
          connStatus = st
          deviceConnected = Boolean(st.connected)
          if (st.companion_warning) {
            addLog(translate('core.capture.logs.companionWarning', { msg: st.companion_warning }), 'warn')
          }
        }
      } else {
        await api.ConnectDevice(selectedDevice, port, installCert)
        deviceConnected = true
      }
      addLog(translate('core.capture.logs.deviceConnected', { serial: selectedDevice, mode: modeLabel }), 'success')
      toast.success(translate('core.capture.toast.deviceConnected', { serial: selectedDevice }))
      await Promise.all([refreshConnectionStatus(selectedDevice), scanEnv(), loadCACertInfo()])
    } catch (e) {
      addLog(translate('core.capture.logs.deviceConnectFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.deviceConnectFailed', { err: e }))
    }
    deviceBusy = false
  }

  async function disconnectDevice() {
    const api = appApi()
    if (!api || !selectedDevice) return
    deviceBusy = true
    try {
      await api.DisconnectDevice(selectedDevice)
      deviceConnected = false
      addLog(translate('core.capture.logs.deviceDisconnected', { serial: selectedDevice }), 'info')
      toast.info(translate('core.capture.toast.deviceDisconnected'))
      await refreshConnectionStatus(selectedDevice)
    } catch (e) {
      addLog(translate('core.capture.logs.deviceDisconnectError', { err: e }), 'error')
      toast.error(translate('core.capture.toast.deviceDisconnectFailed', { err: e }))
    }
    deviceBusy = false
  }

  async function installDeviceCert() {
    const api = appApi()
    if (!api?.InstallDeviceCert || !selectedDevice) {
      toast.warning(translate('core.capture.toast.selectDeviceFirst'))
      return
    }
    certBusy = true
    addLog(translate('core.capture.logs.certInstalling', { serial: selectedDevice }), 'info')
    try {
      const res = await api.InstallDeviceCert(selectedDevice)
      lastManualCertPrompt = Boolean(res?.needs_manual)
      await Promise.all([refreshConnectionStatus(selectedDevice), loadCACertInfo()])
      if (res?.needs_manual) {
        addLog(res.message || translate('core.capture.protection.nonRootCertHint'), 'warn')
        toast.info(translate('core.capture.toast.certUserAction'))
      } else {
        const storeLabel = res?.store || 'system'
        addLog(translate('core.capture.logs.certInstalled', { serial: selectedDevice, store: storeLabel }), 'success')
        toast.success(translate('core.capture.toast.certInstalled', { store: storeLabel }))
      }
    } catch (e) {
      addLog(translate('core.capture.logs.certInstallFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.certInstallFailed', { err: e }))
    }
    certBusy = false
  }

  async function installCompanionApk() {
    const api = appApi()
    if (!api?.InstallCompanionAPK || !selectedDevice) {
      toast.warning(translate('core.capture.toast.selectDeviceFirst'))
      return
    }
    guardBusy = true
    addLog(translate('core.capture.logs.guardInstalling', { serial: selectedDevice }), 'info')
    try {
      const st = await api.InstallCompanionAPK(selectedDevice)
      if (st && connStatus) {
        connStatus = { ...connStatus, companion: st }
      }
      await refreshConnectionStatus(selectedDevice)
      addLog(translate('core.capture.logs.guardInstalled', { serial: selectedDevice }), 'success')
      toast.success(translate('core.capture.toast.guardInstalled'))
    } catch (e) {
      addLog(translate('core.capture.logs.guardInstallFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.guardInstallFailed', { err: e }))
    }
    guardBusy = false
  }

  async function scanEnv() {
    const api = appApi()
    if (!api || !selectedDevice || envLoading) return
    envLoading = true
    try {
      const [env, frida] = await Promise.all([
        api.GetDeviceEnv?.(selectedDevice).catch((err) => {
          addLog(translate('core.capture.logs.envScanError', { err }), 'warn')
          return null
        }),
        api.CheckFrida?.(selectedDevice).catch(() => null),
      ])
      if (env) deviceEnv = env
      if (frida) fridaStatus = frida
    } catch (e) {
      addLog(translate('core.capture.logs.envScanError', { err: e }), 'warn')
    }
    envLoading = false
  }

  async function startFridaServer() {
    const api = appApi()
    if (!api?.StartFrida || !selectedDevice) return
    fridaBusy = true
    addLog(translate('core.capture.logs.fridaStarting', { serial: selectedDevice }), 'info')
    try {
      await api.StartFrida(selectedDevice)
      await new Promise((r) => setTimeout(r, 600))
      fridaStatus = await api.CheckFrida?.(selectedDevice).catch(() => fridaStatus)
      addLog(translate('core.capture.logs.fridaStarted'), 'success')
      toast.success(translate('core.capture.toast.fridaStarted'))
    } catch (e) {
      addLog(translate('core.capture.logs.fridaFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.fridaFailed', { err: e }))
    }
    fridaBusy = false
  }

  async function stopFridaServer() {
    const api = appApi()
    if (!api?.StopFridaServer || !selectedDevice) return
    fridaBusy = true
    try {
      await api.StopFridaServer(selectedDevice, '', Number(fridaStatus?.port) || 27042)
      fridaStatus = await api.CheckFrida?.(selectedDevice).catch(() => ({ status: 'not running' }))
      addLog(translate('core.capture.logs.fridaStopped'), 'info')
      toast.info(translate('core.capture.toast.fridaStopped'))
    } catch (e) {
      addLog(translate('core.capture.logs.fridaFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.fridaFailed', { err: e }))
    }
    fridaBusy = false
  }

  function jumpToFridaStudio() {
    openFridaStudio({
      serial: selectedDevice,
      target: selectedApp || '',
    })
  }

  async function connectWifi() {
    const api = appApi()
    if (!api?.ConnectWiFiADB || !wifiAddr.trim()) return
    wifiBusy = true
    addLog(translate('core.capture.logs.wifiConnecting', { addr: wifiAddr.trim() }), 'info')
    try {
      const out = await api.ConnectWiFiADB(wifiAddr.trim())
      addLog(translate('core.capture.logs.wifiConnected', { out: out || 'connected' }), 'success')
      toast.success(out || translate('core.capture.toast.wifiConnected'))
      await refreshDevices()
    } catch (e) {
      addLog(translate('core.capture.logs.wifiFailed', { err: e }), 'error')
      toast.error(translate('core.capture.toast.wifiFailed', { err: e }))
    }
    wifiBusy = false
  }

  async function disconnectWifi() {
    const api = appApi()
    if (!api?.DisconnectWiFiADB || !wifiAddr.trim()) return
    wifiBusy = true
    try {
      const out = await api.DisconnectWiFiADB(wifiAddr.trim())
      addLog(translate('core.capture.logs.wifiDisconnected', { out: out || wifiAddr.trim() }), 'info')
      toast.info(translate('core.capture.toast.wifiDisconnected'))
      await refreshDevices()
    } catch (e) {
      addLog(translate('core.capture.logs.wifiDisconnectError', { err: e }), 'error')
      toast.error(translate('core.capture.toast.deviceDisconnectFailed', { err: e }))
    }
    wifiBusy = false
  }

  async function loadInstalledApps() {
    const api = appApi()
    if (!api?.ListApps || !selectedDevice) return
    appsLoading = true
    try {
      const list = await api.ListApps(selectedDevice)
      apps = list || []
      if (apps.length > 0 && !selectedApp) {
        selectedApp = apps[0].package
      }
      addLog(translate('core.capture.logs.loadedApps', { count: apps.length }), 'info')
    } catch (e) {
      addLog(translate('core.capture.logs.listAppsError', { err: e }), 'warn')
    }
    appsLoading = false
  }

  async function launchSelectedApp() {
    const api = appApi()
    if (!api?.LaunchApp || !selectedDevice || !selectedApp) return
    try {
      await api.LaunchApp(selectedDevice, selectedApp)
      addLog(translate('core.capture.logs.launchedApp', { pkg: selectedApp }), 'success')
      toast.success(translate('core.capture.toast.launchedApp', { pkg: selectedApp }))
    } catch (e) {
      addLog(translate('core.capture.logs.launchAppError', { err: e }), 'error')
      toast.error(translate('core.capture.toast.launchFailed', { err: e }))
    }
  }

  async function clearTlsErrors() {
    const api = appApi()
    if (!api?.ClearTLSErrors) return
    try {
      await api.ClearTLSErrors()
      tlsErrors = []
      toast.info(translate('core.capture.toast.tlsCleared'))
    } catch (e) {
      toast.error(translate('core.capture.toast.actionFailed', { err: e }))
    }
  }

  function clearLogs() {
    logs = []
    S.logs = []
  }

  function copyLogs() {
    const text = filteredLogs
      .map((l) => (typeof l === 'string' ? l : `[${l.time}] [${l.level.toUpperCase()}] ${l.msg}`))
      .join('\n')
    copyToClipboard(text, translate('core.capture.toast.copiedLogs'))
  }

  function subscribeEvents() {
    const rt = window?.runtime
    if (!rt?.EventsOn) return
    const on = (event, fn) => {
      const off = rt.EventsOn(event, fn)
      if (typeof off === 'function') unsubs.push(off)
    }
    on('proxy:started', (ev) => {
      isRunning = true
      isPaused = false
      if (ev?.address) {
        liveAddr = ev.address
        const parsedPort = extractValidPort(ev.address)
        if (parsedPort) port = parsedPort
      }
    })
    on('proxy:stopped', () => {
      isRunning = false
      isPaused = false
      liveAddr = ''
      rate = { ...rate, req_per_sec: 0, byte_per_sec: 0 }
    })
    on('proxy:capture', (ev) => {
      if (typeof ev?.paused === 'boolean') isPaused = ev.paused
    })
    on('proxy:rate', (r) => {
      if (r) rate = r
    })
    on('proxy:error', (ev) => {
      if (ev?.error) addLog(translate('core.capture.logs.proxyError', { err: ev.error }), 'error')
    })
    on('device:status', (st) => {
      if (!st) return
      if (!selectedDevice || !st.serial || st.serial === selectedDevice) {
        connStatus = st
        deviceConnected = Boolean(st.connected)
      }
    })
    on('device:disconnected', (ev) => {
      if (!ev) return
      if (!selectedDevice || !ev.serial || ev.serial === selectedDevice) {
        deviceConnected = false
        if (connStatus) {
          connStatus = {
            ...connStatus,
            connected: false,
            mode: 'none',
            proxy_address: '',
            vpn_active: false,
            adb_state: ev.reason === 'adb_disconnected' ? 'disconnected' : connStatus.adb_state,
          }
        }
      }
      if (ev.reason === 'adb_disconnected') {
        addLog(translate('core.capture.logs.deviceUnplugged', { serial: ev.serial || selectedDevice }), 'warn')
        toast.warning(translate('core.capture.toast.deviceUnplugged'))
      } else if (ev.reason === 'proxy_stopped') {
        addLog(translate('core.capture.logs.deviceProxyStoppedCleanup', { serial: ev.serial || selectedDevice }), 'info')
        toast.info(translate('core.capture.toast.deviceProxyStoppedCleanup'))
      } else if (ev.reason === 'reconnect_cleanup') {
        addLog(translate('core.capture.logs.deviceReconnectCleanup', { serial: ev.serial || selectedDevice }), 'success')
        toast.info(translate('core.capture.toast.deviceReconnectCleanup'))
      }
    })
  }

  onMount(async () => {
    subscribeEvents()
    await Promise.all([syncBackendState(), loadDomainFilter(), loadCACertInfo()])

    if (!S.initialized) {
      S.initialized = true
      refreshDevices()
    } else if (selectedDevice) {
      refreshConnectionStatus(selectedDevice)
    }

    pollTimer = setInterval(syncBackendState, 1500)
  })

  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer)
    for (const off of unsubs) {
      try { off() } catch (_) {}
    }
    unsubs = []
    if (unregisterCmds) unregisterCmds()
  })
</script>

<div class="capture-page">
  <!-- Executive Proxy Control Hero -->
  <section class="hero-card cap-card">
    <div class="hero-top">
      <div class="hero-status">
        <div class="status-ring" class:live={isRunning && !isPaused} class:paused={isRunning && isPaused}>
          <Icon name="radio" size={18} strokeWidth={1.9} />
        </div>
        <div class="hero-title-group">
          <div class="hero-title-row">
            <h2>{$t('core.capture.title')}</h2>
            {#if isRunning && isPaused}
              <Badge variant="warning" size="xs" dot>{$t('core.capture.status.paused')}</Badge>
            {:else if isRunning}
              <Badge variant="success" size="xs" dot pulse>{$t('core.capture.status.live')}</Badge>
            {:else}
              <Badge variant="neutral" size="xs" dot>{$t('core.capture.status.stopped')}</Badge>
            {/if}
            {#if hostIP && hostIP !== 'auto'}
              <span class="host-hint mono">{$t('core.capture.lanHint', { ip: hostIP })}</span>
            {/if}
          </div>
          <p class="hero-sub">
            {#if isRunning}
              {$t('core.capture.subtitleLive')} <code class="mono">{displayAddr}</code>
            {:else}
              {$t('core.capture.subtitleStopped')}
            {/if}
          </p>
        </div>
      </div>

      <div class="hero-controls">
        <div class="addr-field">
          <span class="addr-prefix">
            <Icon name="globe" size={13} />
          </span>
          <input
            type="text"
            class="addr-input mono"
            bind:value={proxyAddr}
            on:input={handleProxyAddrInput}
            disabled={isRunning}
            placeholder="0.0.0.0:8080"
            aria-label={$t('core.capture.addrAria')}
          />
          <button
            class="addr-copy-btn"
            type="button"
            title={$t('core.capture.copyAddrTitle')}
            on:click={copyProxyAddress}
          >
            <Icon name="copy" size={13} />
          </button>
        </div>

        <Button
          variant={isRunning ? 'danger' : 'primary'}
          size="md"
          icon={isRunning ? 'square' : 'play'}
          loading={proxyBusy}
          on:click={toggleProxy}
        >
          {isRunning ? $t('core.capture.stopProxy') : $t('core.capture.startProxy')}
        </Button>

        {#if isRunning}
          <Button
            variant={isPaused ? 'success' : 'secondary'}
            size="md"
            icon={isPaused ? 'play' : 'pause'}
            title={isPaused ? $t('core.capture.resumeTitle') : $t('core.capture.pauseTitle')}
            on:click={togglePause}
          >
            {isPaused ? $t('core.capture.resumeCapture') : $t('core.capture.pauseCapture')}
          </Button>
        {/if}

        <Button
          variant="subtle"
          size="md"
          icon="activity"
          iconRight="arrow-right"
          on:click={() => navigate('flows')}
        >
          {$t('core.capture.openInspector')}
        </Button>
      </div>
    </div>

    <!-- Live KPI Strip -->
    <div class="kpi-strip">
      <div class="kpi-cell">
        <div class="kpi-label">
          <Icon name="zap" size={12} />
          <span>{$t('core.capture.kpi.throughput')}</span>
        </div>
        <div class="kpi-value mono tabular-nums">
          {(rate?.req_per_sec || 0).toFixed(1)}
          <span class="kpi-unit">{$t('core.capture.kpi.reqPerSec')}</span>
        </div>
        <div class="kpi-sub mono tabular-nums">
          {$t('core.capture.kpi.bandwidthSub', { rate: formatBytes(rate?.byte_per_sec || 0) })}
        </div>
      </div>

      <div class="kpi-cell">
        <div class="kpi-label">
          <Icon name="database" size={12} />
          <span>{$t('core.capture.kpi.capturedFlows')}</span>
        </div>
        <div class="kpi-value mono tabular-nums">{formatCount(totalFlows)}</div>
        <div class="kpi-sub mono tabular-nums">
          {$t('core.capture.kpi.payloadSub', { bytes: formatBytes(totalBytes) })}
        </div>
      </div>

      <div class="kpi-cell">
        <div class="kpi-label">
          <Icon name="globe" size={12} />
          <span>{$t('core.capture.kpi.activeHosts')}</span>
        </div>
        <div class="kpi-value mono tabular-nums">{activeHosts}</div>
        <div class="kpi-sub mono tabular-nums">
          {#if stats?.avg_latency_ms}
            {$t('core.capture.kpi.latencySub', { avg: formatDuration(stats.avg_latency_ms), p95: formatDuration(stats.p95_latency_ms) })}
          {:else}
            {$t('core.capture.kpi.noLatencySub')}
          {/if}
        </div>
      </div>

      <div class="kpi-cell">
        <div class="kpi-label">
          <Icon name="alert-triangle" size={12} />
          <span>{$t('core.capture.kpi.errorRate')}</span>
        </div>
        <div class="kpi-value-row">
          <span class="kpi-value mono tabular-nums err-{errorVariant}">{errorRatePct.toFixed(1)}%</span>
          {#if tlsErrors.length > 0}
            <button class="tls-pill" type="button" on:click={() => (rightTab = 'tls')}>
              <Badge variant="warning" size="xs">{$t('core.capture.kpi.tlsBadge', { count: tlsErrors.length })}</Badge>
            </button>
          {/if}
        </div>
        <div class="kpi-sub">
          {tlsErrors.length > 0 ? $t('core.capture.kpi.tlsHintSub') : $t('core.capture.kpi.errorRatioSub')}
        </div>
      </div>
    </div>
  </section>

  <!-- Main Workspace Grid -->
  <div class="workspace-grid">
    <!-- Left Column: Guided Android Setup, CA Cert & Companion Guard, Device Profile -->
    <div class="device-column">
      <!-- Guided Setup & Connect Card -->
      <section class="cap-card stepper-card">
        <div class="section-head">
          <div class="section-title">
            <Icon name="smartphone" size={14} />
            <span>{$t('core.capture.device.workbenchTitle')}</span>
          </div>
          <Button
            variant="ghost"
            size="xs"
            icon="refresh"
            loading={deviceBusy}
            on:click={refreshDevices}
          >
            {$t('core.capture.device.scan')}
          </Button>
        </div>

        <div class="stepper">
          {#each setupSteps as step, idx}
            <div class="step" class:done={step.done} class:warn={step.warn}>
              <div class="step-dot" class:pulse-dot={step.pulse}>
                {#if step.warn}
                  <Icon name="alert-triangle" size={11} strokeWidth={2.2} />
                {:else if step.done}
                  <Icon name="check" size={11} strokeWidth={2.4} />
                {:else}
                  <span class="mono">{idx + 1}</span>
                {/if}
              </div>
              <div class="step-info">
                <div class="step-label">{step.label}</div>
                <div class="step-detail truncate mono" title={step.detail}>{step.detail}</div>
              </div>
            </div>
          {/each}
        </div>

        <div class="device-controls-body">
          <div class="field-row">
            <label class="field-label" for="device-select">{$t('core.capture.device.targetDevice')}</label>
            <div class="select-wrap">
              <select
                id="device-select"
                class="cap-input device-select mono"
                bind:value={selectedDevice}
                on:change={onDeviceChange}
                disabled={deviceBusy}
              >
                {#if devices.length === 0}
                  <option value="">{$t('core.capture.device.noDevicesOpt')}</option>
                {/if}
                {#each devices as d}
                  <option value={d.serial}>{d.serial} ({d.state})</option>
                {/each}
              </select>
            </div>
          </div>

          <!-- Capture Mode + Port Row -->
          <div class="mode-port-row">
            <div class="mode-col">
              <span class="field-label">{$t('core.capture.device.captureMode')}</span>
              <div class="mode-seg" role="group" aria-label={$t('core.capture.device.captureMode')}>
                <button
                  type="button"
                  class="mode-btn"
                  class:active={!vpnMode}
                  disabled={deviceBusy}
                  on:click={() => (vpnMode = false)}
                >
                  <Icon name="wifi" size={12} />
                  <span>{$t('core.capture.device.modeProxy')}</span>
                </button>
                <button
                  type="button"
                  class="mode-btn"
                  class:active={vpnMode}
                  disabled={deviceBusy}
                  title={!isRooted && hasDevice ? $t('core.capture.device.modeVpnHint') : ''}
                  on:click={() => (vpnMode = true)}
                >
                  <Icon name="shield" size={12} />
                  <span>{$t('core.capture.device.modeVpn')}</span>
                </button>
              </div>
            </div>

            <label class="port-col">
              <span class="field-label">{$t('core.capture.device.proxyPort')}</span>
              <input
                type="text"
                class="cap-input port-input mono tabular-nums"
                bind:value={port}
                on:input={handlePortInput}
                disabled={deviceBusy}
              />
            </label>
          </div>

          <!-- Safety Toggles -->
          <div class="toggles-stack">
            <label class="toggle-opt">
              <input type="checkbox" bind:checked={installCert} disabled={deviceBusy} />
              <span>{$t('core.capture.device.installCertOpt')}</span>
            </label>

            <label class="toggle-opt">
              <input type="checkbox" bind:checked={installCompanion} disabled={deviceBusy} />
              <span class="toggle-text-col">
                <span>{$t('core.capture.device.installCompanionOpt')}</span>
                <small class="toggle-hint">{$t('core.capture.device.companionHint')}</small>
              </span>
            </label>
          </div>

          {#if proxyMismatch}
            <div class="prot-banner warn">
              <Icon name="alert-triangle" size={14} />
              <span>
                {$t('core.capture.device.proxyMismatch', {
                  actual: connStatus?.proxy_address || '—',
                  expected: connStatus?.expected_proxy || displayAddr,
                })}
              </span>
            </div>
          {/if}

          <div class="action-row">
            <Button
              variant="primary"
              size="sm"
              icon="link"
              disabled={!selectedDevice}
              loading={deviceBusy}
              fullWidth
              on:click={connectDevice}
            >
              {$t('core.capture.device.routeDevice')}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              icon="x-circle"
              disabled={!selectedDevice || deviceBusy}
              on:click={disconnectDevice}
            >
              {$t('core.capture.device.teardown')}
            </Button>
          </div>

          <!-- Collapsible Utilities: Wi-Fi ADB & Scope Filter -->
          <div class="utility-toggles">
            <button
              class="util-toggle"
              class:open={showWifiPanel}
              type="button"
              on:click={() => (showWifiPanel = !showWifiPanel)}
            >
              <Icon name="wifi" size={13} />
              <span>{$t('core.capture.device.wifiAdb')}</span>
              <Icon name={showWifiPanel ? 'chevron-up' : 'chevron-down'} size={12} />
            </button>
            <button
              class="util-toggle"
              class:open={showDomainFilter}
              type="button"
              on:click={() => (showDomainFilter = !showDomainFilter)}
            >
              <Icon name="filter" size={13} />
              <span>{$t('core.capture.device.scopeFilter')}</span>
              <Icon name={showDomainFilter ? 'chevron-up' : 'chevron-down'} size={12} />
            </button>
          </div>

          {#if showWifiPanel}
            <div class="sub-panel">
              <div class="sub-row">
                <input
                  type="text"
                  class="cap-input mono flex-1"
                  bind:value={wifiAddr}
                  placeholder="192.168.1.50:5555"
                  on:keydown={(e) => e.key === 'Enter' && connectWifi()}
                />
                <Button variant="secondary" size="xs" loading={wifiBusy} on:click={connectWifi}>
                  {$t('core.capture.device.wifiConnect')}
                </Button>
                <Button variant="ghost" size="xs" disabled={wifiBusy} on:click={disconnectWifi}>
                  {$t('core.capture.device.wifiDrop')}
                </Button>
              </div>
            </div>
          {/if}

          {#if showDomainFilter}
            <div class="sub-panel scope-panel">
              <div class="scope-field">
                <label class="scope-label" for="wl-input">{$t('core.capture.device.allowlistLabel')}</label>
                <input
                  id="wl-input"
                  type="text"
                  class="cap-input mono"
                  bind:value={whitelistText}
                  placeholder="api.example.com, auth.example.com"
                />
              </div>
              <div class="scope-field">
                <label class="scope-label" for="bl-input">{$t('core.capture.device.blocklistLabel')}</label>
                <input
                  id="bl-input"
                  type="text"
                  class="cap-input mono"
                  bind:value={blacklistText}
                  placeholder="googleapis.com, crashlytics.com"
                />
              </div>
              <div class="scope-actions">
                <Button variant="primary" size="xs" icon="check" loading={filterSaving} on:click={saveDomainFilter}>
                  {$t('core.capture.device.applyScope')}
                </Button>
              </div>
            </div>
          {/if}
        </div>
      </section>

      <!-- CA Certificate & Companion Guard Safety Card -->
      <section class="cap-card protection-card">
        <div class="section-head">
          <div class="section-title">
            <Icon name="shield-check" size={14} />
            <span>{$t('core.capture.protection.title')}</span>
          </div>
          {#if selectedDevice}
            <Button variant="ghost" size="xs" icon="refresh" loading={statusLoading} on:click={() => refreshConnectionStatus(selectedDevice)}>
              {$t('core.capture.protection.verifyBtn')}
            </Button>
          {/if}
        </div>

        <div class="protection-body">
          <!-- CA Certificate Sub-Card -->
          <div class="prot-block">
            <div class="prot-row">
              <div class="prot-head-left">
                <span class="prot-name">{$t('core.capture.protection.certLabel')}</span>
                <Badge variant={certStoreVariant} size="xs" dot>{certStoreLabel}</Badge>
              </div>
              <Button
                variant="secondary"
                size="xs"
                icon="shield-check"
                disabled={!selectedDevice}
                loading={certBusy}
                on:click={installDeviceCert}
              >
                {$t('core.capture.protection.installCertBtn')}
              </Button>
            </div>

            <div class="prot-meta mono">
              {#if certHash}
                <span>{$t('core.capture.protection.certHash', { hash: certHash })}</span>
              {:else if caCertInfo && !caCertInfo.exists}
                <span>{$t('core.capture.protection.caLocalMissing')}</span>
              {/if}
              {#if caCertInfo?.fingerprint}
                <span class="truncate" title={caCertInfo.fingerprint}>
                  {$t('core.capture.protection.caFingerprint')}: {caCertInfo.fingerprint.slice(0, 23)}…
                </span>
              {/if}
            </div>

            {#if certNeedsReboot}
              <div class="prot-banner warn">
                <Icon name="alert-triangle" size={13} />
                <span>{$t('core.capture.protection.certNeedsReboot')}</span>
              </div>
            {:else if !certInstalled && (certMethod === 'legacy_system_only' || certMethod === 'fingerprint_mismatch') && certDetails}
              <div class="prot-banner warn">
                <Icon name="alert-triangle" size={13} />
                <span>{certDetails}</span>
              </div>
            {:else if hasDevice && !isRooted && (lastManualCertPrompt || certStore !== 'system')}
              <div class="prot-banner info">
                <Icon name="info" size={13} />
                <span>{$t('core.capture.protection.nonRootCertHint')}</span>
              </div>
            {/if}
          </div>

          <!-- Companion Guard APK Sub-Card -->
          <div class="prot-block">
            <div class="prot-row">
              <div class="prot-head-left">
                <span class="prot-name">{$t('core.capture.protection.guardLabel')}</span>
                <Badge variant={guardStatusVariant} size="xs" dot pulse={companionWatchdog}>
                  {guardStatusLabel}
                </Badge>
              </div>
              <Button
                variant="secondary"
                size="xs"
                icon="shield"
                disabled={!selectedDevice}
                loading={guardBusy}
                on:click={installCompanionApk}
              >
                {$t('core.capture.protection.installGuardBtn')}
              </Button>
            </div>

            {#if companionInstalled}
              <div class="guard-badges">
                {#if companion?.version}
                  <Badge variant="neutral" size="xs" mono>{$t('core.capture.protection.guardVersion', { ver: companion.version })}</Badge>
                {/if}
                <Badge variant={companionPerm ? 'success' : 'warning'} size="xs" mono>
                  {companionPerm ? $t('core.capture.protection.guardPermGranted') : $t('core.capture.protection.guardPermMissing')}
                </Badge>
              </div>
            {/if}

            {#if connStatus?.companion_warning || companion?.error}
              <div class="prot-banner warn">
                <Icon name="alert-triangle" size={13} />
                <span>{connStatus?.companion_warning || companion?.error}</span>
              </div>
            {/if}

            <p class="prot-desc">{$t('core.capture.protection.guardDesc')}</p>
          </div>
        </div>
      </section>

      <!-- Device Environment & Capabilities Card -->
      <section class="cap-card env-card">
        <div class="section-head">
          <div class="section-title">
            <Icon name="cpu" size={14} />
            <span>{$t('core.capture.profile.title')}</span>
          </div>
          {#if selectedDevice}
            <Button variant="ghost" size="xs" icon="refresh" loading={envLoading} on:click={scanEnv}>
              {$t('core.capture.profile.probe')}
            </Button>
          {/if}
        </div>

        {#if deviceEnv}
          <div class="env-body">
            <div class="device-identity">
              <div>
                <div class="device-name">{deviceEnv.brand} {deviceEnv.model}</div>
                <div class="device-meta mono">
                  {$t('core.capture.profile.androidMeta', {
                    android: deviceEnv.android || '?',
                    sdk: deviceEnv.sdk ? ` (API ${deviceEnv.sdk})` : '',
                    cpu: deviceEnv.cpu || 'arm64',
                    ram: deviceEnv.ram || '—',
                  })}
                </div>
              </div>
              {#if deviceEnv.battery}
                <Badge variant="neutral" size="xs" mono>{deviceEnv.battery}</Badge>
              {/if}
            </div>

            <div class="cap-badges-grid">
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.root')}</span>
                <Badge variant={deviceEnv.rooted ? 'success' : 'neutral'} size="xs">
                  {deviceEnv.rooted ? (deviceEnv.root_method || $t('core.capture.profile.rooted')) : $t('core.capture.profile.noRoot')}
                </Badge>
              </div>
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.magisk')}</span>
                <Badge variant={deviceEnv.magisk === 'installed' ? 'success' : 'neutral'} size="xs">
                  {deviceEnv.magisk === 'installed' ? (deviceEnv.magisk_ver || $t('core.capture.profile.installed')) : $t('core.capture.profile.absent')}
                </Badge>
              </div>
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.kernelsu')}</span>
                <Badge variant={deviceEnv.kernelsu ? 'success' : 'neutral'} size="xs">
                  {deviceEnv.kernelsu ? (deviceEnv.kernelsu_ver || $t('core.capture.profile.active')) : $t('core.capture.profile.absent')}
                </Badge>
              </div>
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.zygisk')}</span>
                <Badge variant={deviceEnv.zygisk ? 'info' : 'neutral'} size="xs">
                  {deviceEnv.zygisk ? $t('core.capture.profile.enabled') : $t('core.capture.profile.off')}
                </Badge>
              </div>
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.lsposed')}</span>
                <Badge variant={deviceEnv.lsposed ? 'purple' : 'neutral'} size="xs">
                  {deviceEnv.lsposed ? (deviceEnv.lsposed_ver || $t('core.capture.profile.active')) : $t('core.capture.profile.absent')}
                </Badge>
              </div>
              <div class="cap-item">
                <span class="cap-key">{$t('core.capture.profile.selinux')}</span>
                <Badge variant={deviceEnv.selinux === 'Enforcing' ? 'warning' : 'success'} size="xs">
                  {deviceEnv.selinux || $t('core.capture.profile.unknown')}
                </Badge>
              </div>
            </div>

            <!-- Frida Unpin Server Control -->
            <div class="frida-bar">
              <div class="frida-info">
                <Icon name="zap" size={14} />
                <span class="frida-label">{$t('core.capture.profile.fridaServer')}</span>
                {#if fridaStatus?.status === 'running'}
                  <Badge variant="success" size="xs" dot pulse>
                    {$t('core.capture.profile.fridaRunning', { pid: fridaStatus.pid ? ` #${fridaStatus.pid}` : '' })}
                  </Badge>
                {:else if fridaStatus?.binary}
                  <Badge variant="warning" size="xs">{$t('core.capture.profile.fridaStopped')}</Badge>
                {:else}
                  <Badge variant="neutral" size="xs">{$t('core.capture.profile.fridaNotFound')}</Badge>
                {/if}
                {#if fridaStatus?.version}
                  <Badge variant="info" size="xs" mono>v{fridaStatus.version}</Badge>
                {/if}
                {#if fridaStatus?.arch}
                  <Badge variant="neutral" size="xs" mono>{fridaStatus.arch}</Badge>
                {/if}
              </div>
              <div class="frida-actions">
                {#if fridaStatus?.status === 'running'}
                  <Button variant="danger" size="xs" icon="square" loading={fridaBusy} on:click={stopFridaServer}>
                    {$t('core.capture.profile.stopFrida')}
                  </Button>
                {:else if fridaStatus?.binary}
                  <Button variant="subtle" size="xs" icon="play" loading={fridaBusy} on:click={startFridaServer}>
                    {$t('core.capture.profile.startFrida')}
                  </Button>
                {/if}
                <Button variant="secondary" size="xs" icon="zap" on:click={jumpToFridaStudio}>
                  {$t('core.capture.profile.openFridaStudio')}
                </Button>
              </div>
            </div>

            <!-- Quick App Launcher -->
            <div class="app-launcher">
              <div class="app-launcher-row">
                <Button variant="ghost" size="xs" icon="box" loading={appsLoading} on:click={loadInstalledApps}>
                  {apps.length > 0 ? $t('core.capture.profile.appsCount', { count: apps.length }) : $t('core.capture.profile.loadApps')}
                </Button>
                {#if apps.length > 0}
                  <select class="cap-input app-select mono" bind:value={selectedApp}>
                    {#each apps as a}
                      <option value={a.package}>{a.package}</option>
                    {/each}
                  </select>
                  <Button variant="secondary" size="xs" icon="play" on:click={launchSelectedApp}>
                    {$t('core.capture.profile.launch')}
                  </Button>
                {/if}
              </div>
            </div>
          </div>
        {:else}
          <EmptyState
            icon="usb"
            title={$t('core.capture.profile.emptyTitle')}
            description={$t('core.capture.profile.emptyDesc')}
            compact
          >
            <Button variant="secondary" size="xs" icon="refresh" loading={deviceBusy} on:click={refreshDevices}>
              {$t('core.capture.profile.scanAdb')}
            </Button>
          </EmptyState>
        {/if}
      </section>
    </div>

    <!-- Right Column: Activity Console, Top Hosts, TLS Diagnostics -->
    <section class="cap-card console-card">
      <div class="console-header">
        <div class="console-tabs" role="tablist">
          <button
            class="ctab"
            class:active={rightTab === 'logs'}
            role="tab"
            aria-selected={rightTab === 'logs'}
            type="button"
            on:click={() => (rightTab = 'logs')}
          >
            <Icon name="terminal" size={13} />
            <span>{$t('core.capture.console.activityLog')}</span>
            <span class="ctab-count mono tabular-nums">{logs.length}</span>
          </button>

          <button
            class="ctab"
            class:active={rightTab === 'hosts'}
            role="tab"
            aria-selected={rightTab === 'hosts'}
            type="button"
            on:click={() => (rightTab = 'hosts')}
          >
            <Icon name="globe" size={13} />
            <span>{$t('core.capture.console.activeHosts')}</span>
            <span class="ctab-count mono tabular-nums">{activeHosts}</span>
          </button>

          <button
            class="ctab"
            class:active={rightTab === 'tls'}
            role="tab"
            aria-selected={rightTab === 'tls'}
            type="button"
            on:click={() => (rightTab = 'tls')}
          >
            <Icon name="lock" size={13} />
            <span>{$t('core.capture.console.tlsAlerts')}</span>
            {#if tlsErrors.length > 0}
              <Badge variant="warning" size="xs">{tlsErrors.length}</Badge>
            {/if}
          </button>
        </div>

        <div class="console-actions">
          {#if rightTab === 'logs'}
            <div class="mini-search">
              <Icon name="search" size={12} />
              <input
                type="text"
                bind:value={logFilter}
                placeholder={$t('core.capture.console.filterLogsPlaceholder')}
                aria-label={$t('core.capture.console.filterLogsAria')}
              />
              {#if logFilter}
                <button type="button" class="mini-clear" on:click={() => (logFilter = '')}>
                  <Icon name="x" size={11} />
                </button>
              {/if}
            </div>
            <Button variant="ghost" size="xs" icon="copy" iconOnly title={$t('core.capture.console.copyLogsTitle')} on:click={copyLogs} />
            <Button variant="ghost" size="xs" icon="trash" iconOnly title={$t('core.capture.console.clearLogsTitle')} on:click={clearLogs} />
          {:else if rightTab === 'tls' && tlsErrors.length > 0}
            <Button variant="ghost" size="xs" icon="trash" on:click={clearTlsErrors}>
              {$t('core.capture.console.clearAlerts')}
            </Button>
          {/if}
        </div>
      </div>

      <div class="console-body">
        {#if rightTab === 'logs'}
          <div class="log-stream mono" bind:this={logEl}>
            {#if filteredLogs.length === 0}
              <EmptyState
                icon="terminal"
                title={logs.length === 0 ? $t('core.capture.console.readyTitle') : $t('core.capture.console.noLogMatchTitle')}
                description={logs.length === 0
                  ? $t('core.capture.console.readyDesc')
                  : $t('core.capture.console.noLogMatchDesc')}
                compact
              />
            {:else}
              {#each filteredLogs as entry (typeof entry === 'string' ? entry : entry.id)}
                {#if typeof entry === 'string'}
                  <div class="log-row lvl-info">
                    <span class="log-msg">{entry}</span>
                  </div>
                {:else}
                  <div class="log-row lvl-{entry.level}">
                    <span class="log-time tabular-nums">{entry.time}</span>
                    <span class="log-dot"></span>
                    <span class="log-msg">{entry.msg}</span>
                  </div>
                {/if}
              {/each}
            {/if}
          </div>
        {:else if rightTab === 'hosts'}
          {#if topHosts.length === 0}
            <EmptyState
              icon="globe"
              title={$t('core.capture.console.noTrafficTitle')}
              description={$t('core.capture.console.noTrafficDesc')}
              compact
            />
          {:else}
            <div class="hosts-table">
              <div class="hosts-head">
                <span class="hc-host">{$t('core.capture.console.colHost')}</span>
                <span class="hc-num">{$t('core.capture.console.colRequests')}</span>
                <span class="hc-num">{$t('core.capture.console.colAvgLatency')}</span>
                <span class="hc-num">{$t('core.capture.console.colVolume')}</span>
              </div>
              {#each topHosts as h}
                <button
                  class="host-row"
                  type="button"
                  title={$t('core.capture.console.inspectHostTitle', { host: h.host })}
                  on:click={() => { FS.filterHost = h.host; navigate('flows') }}
                >
                  <span class="hc-host truncate mono">{h.host}</span>
                  <span class="hc-num mono tabular-nums">{formatCount(h.count)}</span>
                  <span class="hc-num mono tabular-nums">{formatDuration(h.avg_ms)}</span>
                  <span class="hc-num mono tabular-nums">{formatBytes(h.bytes)}</span>
                </button>
              {/each}
            </div>
          {/if}
        {:else if rightTab === 'tls'}
          {#if tlsErrors.length === 0}
            <EmptyState
              icon="shield-check"
              title={$t('core.capture.console.noTlsTitle')}
              description={$t('core.capture.console.noTlsDesc')}
              compact
            />
          {:else}
            <div class="tls-list">
              <div class="tls-hint">
                <Icon name="info" size={14} />
                <span>{$t('core.capture.console.tlsBanner')}</span>
              </div>
              {#each tlsErrors as item}
                <div class="tls-row">
                  <span class="mono truncate">{item.host}</span>
                  <Badge variant="danger" size="xs" mono>{$t('core.capture.console.tlsFailures', { count: item.count })}</Badge>
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </div>
    </section>
  </div>
</div>

<style>
  .capture-page {
    display: flex;
    flex-direction: column;
    gap: 12px;
    height: 100%;
    padding: 14px 16px;
    overflow: hidden;
    background: var(--bg-app);
  }

  /* Hero Proxy Card */
  .hero-card {
    flex-shrink: 0;
    overflow: hidden;
  }

  .hero-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 14px 16px;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border-subtle);
  }

  .hero-status {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 240px;
  }

  .status-ring {
    width: 38px;
    height: 38px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-muted);
    flex-shrink: 0;
    transition: all var(--transition-base);
  }

  .status-ring.live {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
    color: var(--status-success);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--status-success) 14%, transparent);
  }

  .status-ring.paused {
    background: var(--status-warning-bg);
    border-color: var(--status-warning-border);
    color: var(--status-warning);
  }

  .hero-title-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .hero-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .hero-title-row h2 {
    font-size: var(--text-md);
    font-weight: 600;
    color: var(--text-primary);
    letter-spacing: -0.01em;
  }

  .host-hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 1px 6px;
    background: var(--bg-subtle);
    border-radius: var(--radius-xs);
  }

  .hero-sub {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .hero-sub code {
    color: var(--text-secondary);
  }

  .hero-controls {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .addr-field {
    display: flex;
    align-items: center;
    height: 34px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
    overflow: hidden;
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .addr-field:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .addr-prefix {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0 8px 0 10px;
    color: var(--text-faint);
  }

  .addr-input {
    width: 144px;
    height: 100%;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-sm);
    outline: none;
  }

  .addr-input:disabled {
    color: var(--text-secondary);
    cursor: default;
  }

  .addr-copy-btn {
    width: 30px;
    height: 100%;
    border: none;
    border-left: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .addr-copy-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* KPI Strip */
  .kpi-strip {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    background: var(--bg-header);
  }

  .kpi-cell {
    padding: 11px 16px;
    display: flex;
    flex-direction: column;
    gap: 3px;
    border-right: 1px solid var(--border-subtle);
    min-width: 0;
  }

  .kpi-cell:last-child {
    border-right: none;
  }

  .kpi-label {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-2xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
  }

  .kpi-value-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .kpi-value {
    font-size: var(--text-lg);
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1.2;
  }

  .kpi-unit {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--text-muted);
  }

  .kpi-sub {
    font-size: var(--text-xs);
    color: var(--text-faint);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .err-success { color: var(--status-success); }
  .err-warning { color: var(--status-warning); }
  .err-danger { color: var(--status-danger); }

  .tls-pill {
    background: none;
    border: none;
    padding: 0;
    cursor: pointer;
  }

  /* Main Workspace Grid */
  .workspace-grid {
    flex: 1;
    min-height: 0;
    display: grid;
    grid-template-columns: minmax(360px, 440px) minmax(0, 1fr);
    gap: 12px;
  }

  .device-column {
    display: flex;
    flex-direction: column;
    gap: 12px;
    min-height: 0;
    overflow-y: auto;
    padding-right: 2px;
  }

  .section-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-header);
  }

  .section-title {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
  }

  .stepper-card,
  .protection-card,
  .env-card {
    overflow: hidden;
    flex-shrink: 0;
  }

  /* Guided 4-step strip */
  .stepper {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-app);
  }

  .step {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    min-width: 0;
  }

  .step.done {
    border-color: var(--status-success-border);
    background: color-mix(in srgb, var(--status-success-bg) 55%, var(--bg-surface));
  }

  .step.warn {
    border-color: var(--status-warning-border);
    background: color-mix(in srgb, var(--status-warning-bg) 60%, var(--bg-surface));
  }

  .step.warn .step-dot {
    background: var(--status-warning-bg);
    border-color: var(--status-warning-border);
    color: var(--status-warning);
  }

  .step-dot {
    width: 20px;
    height: 20px;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    color: var(--text-muted);
    font-size: 10px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .step.done .step-dot {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
    color: var(--status-success);
  }

  .step-dot.pulse-dot {
    animation: cap-pulse 1.8s ease-in-out infinite;
  }

  .step-info {
    min-width: 0;
    flex: 1;
  }

  .step-label {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.2;
  }

  .step-detail {
    font-size: 10px;
    color: var(--text-muted);
  }

  /* Device controls */
  .device-controls-body {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .field-row {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-label {
    font-size: var(--text-xs);
    color: var(--text-muted);
    font-weight: 500;
  }

  .device-select {
    width: 100%;
    cursor: pointer;
  }

  .mode-port-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
  }

  .mode-col {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .mode-seg {
    display: grid;
    grid-template-columns: 1fr 1fr;
    padding: 2px;
    gap: 2px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
  }

  .mode-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    height: 24px;
    padding: 0 6px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    transition: all var(--transition-fast);
  }

  .mode-btn:hover:not(:disabled) {
    color: var(--text-primary);
  }

  .mode-btn.active {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 600;
  }

  .port-col {
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 74px;
    flex-shrink: 0;
  }

  .port-input {
    width: 100%;
    height: 30px;
    text-align: center;
    padding: 0 6px;
  }

  .toggles-stack {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
  }

  .toggle-opt {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    font-size: var(--text-xs);
    color: var(--text-primary);
    cursor: pointer;
    user-select: none;
  }

  .toggle-opt input {
    margin-top: 2px;
    accent-color: var(--accent);
    cursor: pointer;
    flex-shrink: 0;
  }

  .toggle-text-col {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .toggle-hint {
    font-size: 10.5px;
    color: var(--text-muted);
    line-height: 1.35;
  }

  .action-row {
    display: flex;
    gap: 8px;
  }

  .utility-toggles {
    display: flex;
    gap: 6px;
    padding-top: 4px;
    border-top: 1px solid var(--border-subtle);
  }

  .util-toggle {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    height: 26px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
    background: var(--bg-subtle);
    color: var(--text-muted);
    font-size: var(--text-xs);
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .util-toggle:hover,
  .util-toggle.open {
    color: var(--text-primary);
    border-color: var(--border-default);
    background: var(--bg-hover);
  }

  .sub-panel {
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
  }

  .sub-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .flex-1 {
    flex: 1;
    min-width: 0;
  }

  .scope-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .scope-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .scope-label {
    font-size: 10px;
    color: var(--text-muted);
    font-weight: 500;
  }

  .scope-actions {
    display: flex;
    justify-content: flex-end;
  }

  /* CA Cert & Companion Guard Card */
  .protection-body {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .prot-block {
    padding: 10px 11px;
    border-radius: var(--radius-md);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .prot-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }

  .prot-head-left {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
  }

  .prot-name {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .prot-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 10.5px;
    color: var(--text-muted);
    flex-wrap: wrap;
  }

  .guard-badges {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .prot-banner {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    padding: 7px 9px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    line-height: 1.4;
  }

  .prot-banner.info {
    background: var(--status-info-bg);
    border: 1px solid var(--status-info-border);
    color: var(--status-info);
  }

  .prot-banner.warn {
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    color: var(--status-warning);
  }

  .prot-desc {
    font-size: 11px;
    color: var(--text-muted);
    line-height: 1.45;
  }

  /* Device Environment Card */
  .env-body {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .device-identity {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
  }

  .device-name {
    font-size: var(--text-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .device-meta {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: 2px;
  }

  .cap-badges-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 6px 12px;
  }

  .cap-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    padding: 4px 0;
    border-bottom: 1px solid var(--border-subtle);
  }

  .cap-key {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .frida-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
  }

  .frida-info {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
    color: var(--text-secondary);
    font-size: var(--text-xs);
  }

  .frida-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  .frida-label {
    font-weight: 600;
    color: var(--text-primary);
  }

  .app-launcher-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .app-select {
    flex: 1;
    min-width: 0;
    height: 26px;
    font-size: var(--text-xs);
  }

  /* Right Column Console */
  .console-card {
    display: flex;
    flex-direction: column;
    min-height: 0;
    min-width: 0;
    overflow: hidden;
  }

  .console-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 0 10px 0 6px;
    height: 38px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .console-tabs {
    display: flex;
    align-items: center;
    height: 100%;
    gap: 2px;
  }

  .ctab {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 100%;
    padding: 0 10px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .ctab:hover {
    color: var(--text-primary);
  }

  .ctab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
    font-weight: 600;
  }

  .ctab-count {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .console-actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .mini-search {
    display: flex;
    align-items: center;
    gap: 5px;
    height: 24px;
    padding: 0 7px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    color: var(--text-faint);
  }

  .mini-search:focus-within {
    border-color: var(--accent);
  }

  .mini-search input {
    width: 110px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    outline: none;
  }

  .mini-clear {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    align-items: center;
  }

  .console-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .log-stream {
    flex: 1;
    overflow-y: auto;
    padding: 8px 12px;
    font-size: var(--text-xs);
    line-height: 1.55;
  }

  .log-row {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 2px 4px;
    border-radius: var(--radius-xs);
  }

  .log-row:hover {
    background: var(--bg-subtle);
  }

  .log-time {
    color: var(--text-faint);
    flex-shrink: 0;
    font-size: 10.5px;
  }

  .log-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
    align-self: center;
    background: var(--text-faint);
  }

  .lvl-success .log-dot { background: var(--status-success); }
  .lvl-warn .log-dot { background: var(--status-warning); }
  .lvl-error .log-dot { background: var(--status-danger); }
  .lvl-info .log-dot { background: var(--status-info); }

  .log-msg {
    color: var(--text-secondary);
    word-break: break-word;
  }

  .lvl-error .log-msg { color: var(--status-danger); }
  .lvl-warn .log-msg { color: var(--status-warning); }

  /* Hosts Table */
  .hosts-table {
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .hosts-head {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 74px 86px 86px;
    padding: 7px 14px;
    font-size: var(--text-2xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    position: sticky;
    top: 0;
  }

  .host-row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 74px 86px 86px;
    align-items: center;
    padding: 7px 14px;
    border: none;
    border-bottom: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-xs);
    text-align: left;
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .host-row:hover {
    background: var(--bg-hover);
  }

  .hc-num {
    text-align: right;
    color: var(--text-secondary);
  }

  /* TLS Alerts */
  .tls-list {
    flex: 1;
    overflow-y: auto;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .tls-hint {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 9px 11px;
    border-radius: var(--radius-sm);
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    color: var(--status-warning);
    font-size: var(--text-xs);
    line-height: 1.45;
  }

  .tls-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-app);
    border: 1px solid var(--border-subtle);
    font-size: var(--text-xs);
  }

  /* Responsive polish for 900x650 compact desktop window */
  @media (max-width: 980px) {
    .capture-page {
      padding: 10px 12px;
      gap: 10px;
      overflow-y: auto;
    }

    .kpi-strip {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }

    .kpi-cell {
      border-bottom: 1px solid var(--border-subtle);
    }

    .workspace-grid {
      grid-template-columns: 1fr;
      overflow: visible;
    }

    .device-column {
      overflow: visible;
    }

    .console-card {
      min-height: 260px;
    }
  }
</style>
