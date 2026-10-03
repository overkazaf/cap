<script>
  import { onMount, onDestroy } from 'svelte'

  let proxyAddr = '0.0.0.0:8080'
  let isRunning = false
  let isPaused = false
  let status = 'Stopped'
  let logs = []
  let devices = []
  let selectedDevice = ''
  let port = '8080'
  let installCert = true
  let busy = false

  // Traffic rate
  let rate = { req_per_sec: 0, byte_per_sec: 0, total_reqs: 0, total_bytes: 0 }
  let rateInterval = null

  // Domain filter
  let filterMode = 'none' // none, whitelist, blacklist
  let filterDomains = ''

  // WiFi ADB
  let wifiIP = ''

  // App launcher
  let apps = []
  let selectedApp = ''

  // TLS errors
  let tlsErrors = []

  // Device env
  let deviceEnv = null
  let envLoading = false

  function log(msg) {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    logs = [...logs, `[${ts}] ${msg}`]
    if (logs.length > 500) logs = logs.slice(-500)
    setTimeout(() => {
      const el = document.querySelector('.log-output')
      if (el) el.scrollTop = el.scrollHeight
    }, 50)
  }

  function formatBytes(b) {
    if (b < 1024) return b + ' B'
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
    return (b / 1048576).toFixed(1) + ' MB'
  }

  async function toggleProxy() {
    if (isRunning) {
      try {
        await window.go.wailsgui.App.StopProxy()
        isRunning = false
        isPaused = false
        status = 'Stopped'
        if (rateInterval) { clearInterval(rateInterval); rateInterval = null }
        log('Proxy stopped')
      } catch(e) { log(`Error: ${e}`) }
    } else {
      try {
        // Apply domain filter before starting
        if (filterMode !== 'none' && filterDomains.trim()) {
          const domains = filterDomains.split('\n').map(d => d.trim()).filter(Boolean)
          await window.go.wailsgui.App.SetDomainFilter(
            filterMode === 'whitelist' ? domains : [],
            filterMode === 'blacklist' ? domains : []
          )
        } else {
          await window.go.wailsgui.App.SetDomainFilter([], [])
        }
        await window.go.wailsgui.App.StartProxy(proxyAddr)
        isRunning = true
        const addr = await window.go.wailsgui.App.ProxyAddr()
        status = `Running on ${addr}`
        log(`Proxy started on ${addr}`)
        rateInterval = setInterval(updateRate, 1000)
      } catch(e) { log(`Error: ${e}`) }
    }
  }

  async function togglePause() {
    if (isPaused) {
      await window.go.wailsgui.App.ResumeCapture()
      isPaused = false
      log('Capture resumed')
    } else {
      await window.go.wailsgui.App.PauseCapture()
      isPaused = true
      log('Capture paused')
    }
  }

  async function updateRate() {
    try {
      rate = await window.go.wailsgui.App.GetTrafficRate()
    } catch(e) {}
  }

  async function refreshDevices() {
    busy = true
    log('Scanning ADB devices...')
    try {
      const devs = await window.go.wailsgui.App.ListDevices()
      devices = devs || []
      if (devices.length > 0) {
        selectedDevice = devices[0].serial
        scanDeviceEnv()
      }
      log(`Found ${devices.length} device(s)`)
    } catch(e) { log(`Scan failed: ${e}`) }
    busy = false
  }

  async function connectDevice() {
    if (!selectedDevice) { log('Select a device first'); return }
    busy = true
    log(`Connecting ${selectedDevice}...`)
    try {
      await window.go.wailsgui.App.ConnectDevice(selectedDevice, port, installCert)
      log(`Connected ${selectedDevice}`)
      scanDeviceEnv()
    } catch(e) { log(`Failed: ${e}`) }
    busy = false
  }

  async function disconnectDevice() {
    if (!selectedDevice) return
    busy = true
    try {
      await window.go.wailsgui.App.DisconnectDevice(selectedDevice)
      log(`Disconnected ${selectedDevice}`)
    } catch(e) { log(`Failed: ${e}`) }
    busy = false
  }

  async function connectWiFi() {
    if (!wifiIP.trim()) { log('Enter IP:PORT'); return }
    busy = true
    log(`Connecting WiFi ADB ${wifiIP}...`)
    try {
      const result = await window.go.wailsgui.App.ConnectWiFiADB(wifiIP.trim())
      log(result)
      refreshDevices()
    } catch(e) { log(`WiFi ADB failed: ${e}`) }
    busy = false
  }

  async function loadApps() {
    if (!selectedDevice) return
    try {
      apps = await window.go.wailsgui.App.ListApps(selectedDevice) || []
      log(`Found ${apps.length} apps`)
    } catch(e) { log(`List apps failed: ${e}`) }
  }

  async function launchApp() {
    if (!selectedDevice || !selectedApp) return
    try {
      await window.go.wailsgui.App.LaunchApp(selectedDevice, selectedApp)
      log(`Launched ${selectedApp}`)
    } catch(e) { log(`Launch failed: ${e}`) }
  }

  async function scanDeviceEnv() {
    if (!selectedDevice) { log('Select a device first'); return }
    envLoading = true
    log(`Scanning ${selectedDevice} environment...`)
    try {
      deviceEnv = await window.go.wailsgui.App.GetDeviceEnv(selectedDevice)
      log('Device scan complete')
    } catch(e) { log(`Scan failed: ${e}`) }
    envLoading = false
  }

  async function checkTLS() {
    try {
      tlsErrors = await window.go.wailsgui.App.GetTLSErrors() || []
    } catch(e) {}
  }

  onMount(() => {
    refreshDevices()
    // Check TLS errors periodically
    const tlsInterval = setInterval(checkTLS, 5000)
    return () => clearInterval(tlsInterval)
  })
  onDestroy(() => { if (rateInterval) clearInterval(rateInterval) })
</script>

<div class="page">
  <div class="main-area">
    <!-- Left: Controls -->
    <div class="controls">
      <h2>PROXY</h2>
      <div class="row">
        <input type="text" bind:value={proxyAddr} disabled={isRunning} class="input mono" />
        <button class="btn" class:btn-danger={isRunning} class:btn-success={!isRunning} on:click={toggleProxy}>
          {isRunning ? '■ Stop' : '▶ Start'}
        </button>
        {#if isRunning}
          <button class="btn" class:btn-warn={!isPaused} class:btn-success={isPaused} on:click={togglePause}>
            {isPaused ? '▶' : '⏸'}
          </button>
        {/if}
      </div>
      {#if isRunning}
        <div class="rate-bar">
          <span class="ri">{rate.req_per_sec.toFixed(1)} r/s</span>
          <span class="ri">{formatBytes(rate.byte_per_sec)}/s</span>
          <span class="ri">{rate.total_reqs} reqs</span>
          <span class="status-badge" class:paused={isPaused}>{isPaused ? 'PAUSED' : 'LIVE'}</span>
        </div>
      {/if}

      <h2>DEVICE</h2>
      <div class="row">
        <select bind:value={selectedDevice} class="input" disabled={busy}>
          {#if devices.length === 0}<option value="">No device</option>{/if}
          {#each devices as d}<option value={d.serial}>{d.serial}</option>{/each}
        </select>
        <button class="btn btn-ghost" on:click={refreshDevices} disabled={busy}>⟳</button>
      </div>
      <div class="row">
        <input type="text" bind:value={port} class="input mono" style="max-width:56px" />
        <label class="ck"><input type="checkbox" bind:checked={installCert} /> Cert</label>
        <button class="btn btn-primary" on:click={connectDevice} disabled={busy}>Connect</button>
        <button class="btn btn-ghost" on:click={disconnectDevice} disabled={busy}>✕</button>
      </div>
      <div class="row">
        <input type="text" bind:value={wifiIP} placeholder="IP:5555" class="input mono" />
        <button class="btn btn-ghost" on:click={connectWiFi} disabled={busy}>WiFi</button>
      </div>

      <h2>APP</h2>
      <div class="row">
        <select bind:value={selectedApp} class="input">
          {#if apps.length === 0}<option value="">—</option>{/if}
          {#each apps as app}<option value={app.package}>{app.package}</option>{/each}
        </select>
        <button class="btn btn-ghost" on:click={loadApps}>⟳</button>
        <button class="btn btn-ghost" on:click={launchApp} disabled={!selectedApp}>▶</button>
      </div>

      <h2>FILTER</h2>
      <div class="row">
        <select bind:value={filterMode} class="input">
          <option value="none">Off</option>
          <option value="whitelist">Whitelist</option>
          <option value="blacklist">Blacklist</option>
        </select>
      </div>
      {#if filterMode !== 'none'}
        <textarea class="filter-ta" bind:value={filterDomains} placeholder="domain per line"></textarea>
      {/if}
    </div>

    <!-- Center: Device Env -->
    <div class="env-col">
      {#if deviceEnv}
        <div class="env-card">
          <div class="env-title">{deviceEnv.brand} {deviceEnv.model}</div>
          <div class="env-sub">Android {deviceEnv.android} · SDK {deviceEnv.sdk} · {deviceEnv.cpu}</div>
          <div class="env-sub">{deviceEnv.ram} RAM · {deviceEnv.screen} · 🔋{deviceEnv.battery}</div>
          <div class="env-divider"></div>
          <div class="env-items">
            <div class="ei"><span class="el">Root</span><span class="ev2" class:g={deviceEnv.rooted}>{deviceEnv.rooted ? '✓ '+deviceEnv.root_method : '✗'}</span></div>
            <div class="ei"><span class="el">Magisk</span><span class="ev2" class:g={deviceEnv.magisk==='installed'}>{deviceEnv.magisk==='installed' ? '✓ '+(deviceEnv.magisk_ver||'') : '✗'}</span></div>
            <div class="ei"><span class="el">Zygisk</span><span class="ev2" class:g={deviceEnv.zygisk}>{deviceEnv.zygisk ? '✓' : '✗'}</span></div>
            <div class="ei"><span class="el">LSPosed</span><span class="ev2" class:g={deviceEnv.lsposed}>{deviceEnv.lsposed ? '✓' : '✗'}</span></div>
            <div class="ei"><span class="el">SELinux</span><span class="ev2" class:y={deviceEnv.selinux==='Enforcing'} class:g={deviceEnv.selinux==='Permissive'}>{deviceEnv.selinux||'?'}</span></div>
            <div class="ei"><span class="el">Boot</span><span class="ev2 sm">{deviceEnv.integrity||'N/A'}</span></div>
          </div>
          <div class="env-fp">{deviceEnv.fingerprint}</div>
        </div>

        {#if tlsErrors.length > 0}
          <div class="tls-card">
            <div class="tls-title">⚠ SSL PINNING ({tlsErrors.length})</div>
            {#each tlsErrors.slice(0, 6) as e}
              <div class="tls-row"><span class="tls-h">{e.host}</span><span>×{e.count}</span></div>
            {/each}
          </div>
        {/if}
      {:else}
        <div class="env-empty-msg">
          {envLoading ? '⏳ Scanning...' : 'Device env will appear after connect'}
        </div>
      {/if}
    </div>

    <!-- Right: Log -->
    <div class="log-col">
      <div class="log-top"><span class="log-t">LOG</span><button class="log-clear" on:click={() => { logs = [] }}>Clear</button></div>
      <div class="log-body">
        {#each logs as line}<div class="ll">{line}</div>{/each}
        {#if logs.length === 0}<div class="ll dim">Waiting...</div>{/if}
      </div>
    </div>
  </div>
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; }
  .main-area { display: flex; flex: 1; min-height: 0; gap: 0; }

  /* Controls column */
  .controls {
    width: 260px; flex-shrink: 0; padding: 12px; overflow-y: auto;
    background: var(--bg-panel, #111116); border-right: 1px solid var(--border, #1e1e24);
  }
  .controls h2 { font-size: 9px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; margin: 10px 0 6px; font-weight: 600; }
  .controls h2:first-child { margin-top: 0; }
  .row { display: flex; align-items: center; gap: 4px; margin-bottom: 4px; }
  .input {
    flex: 1; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 4px;
    padding: 4px 6px; color: var(--fg, #e4e4e7); font-size: 11px; outline: none; font-family: inherit; min-width: 0;
  }
  .input:focus { border-color: var(--accent, #38bdf8); }
  .input:disabled { opacity: 0.5; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; }
  .btn {
    padding: 4px 8px; border: 1px solid var(--border, #27272a); border-radius: 4px;
    background: var(--bg-btn, #1a1a22); color: var(--fg, #e4e4e7); font-size: 10px; cursor: pointer;
    font-family: inherit; white-space: nowrap;
  }
  .btn:hover { background: var(--bg-hover, #27272a); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-success { background: #064e3b; border-color: #059669; color: var(--green, #34d399); }
  .btn-danger { background: #4c0519; border-color: #dc2626; color: var(--red, #f87171); }
  .btn-primary { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .btn-ghost { border-color: transparent; background: transparent; color: var(--fg-muted, #a1a1aa); }
  .btn-ghost:hover { background: var(--bg-btn, #1a1a22); }
  .btn-warn { background: #422006; border-color: #f59e0b; color: var(--yellow, #fbbf24); }
  .ck { display: flex; align-items: center; gap: 3px; font-size: 10px; color: var(--fg-muted, #a1a1aa); cursor: pointer; white-space: nowrap; }
  .ck input { accent-color: var(--accent, #38bdf8); }
  .rate-bar { display: flex; gap: 8px; padding: 4px 0; font-size: 10px; align-items: center; flex-wrap: wrap; }
  .ri { color: var(--fg-faint, #52525b); font-family: 'SF Mono', monospace; }
  .status-badge {
    padding: 1px 6px; border-radius: 3px; font-size: 8px; letter-spacing: 0.5px; font-weight: 600;
    background: rgba(52, 211, 153, 0.15); color: var(--green, #34d399);
  }
  .status-badge.paused { background: rgba(251, 191, 36, 0.15); color: var(--yellow, #fbbf24); }
  .filter-ta {
    width: 100%; min-height: 40px; max-height: 60px; resize: vertical;
    background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 4px;
    padding: 4px 6px; color: var(--fg, #e4e4e7); font-size: 10px; font-family: inherit; outline: none;
  }

  /* Env column */
  .env-col {
    flex: 1; padding: 12px; overflow-y: auto;
    display: flex; flex-direction: column; gap: 10px;
  }
  .env-card {
    background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24);
    border-radius: 8px; padding: 14px;
  }
  .env-title { font-size: 14px; font-weight: 600; color: var(--fg, #e4e4e7); }
  .env-sub { font-size: 11px; color: var(--fg-dim, #71717a); margin-top: 2px; }
  .env-divider { height: 1px; background: var(--border, #1e1e24); margin: 10px 0; }
  .env-items { display: grid; grid-template-columns: 1fr 1fr; gap: 2px 16px; }
  .ei { display: flex; justify-content: space-between; padding: 2px 0; font-size: 11px; }
  .el { color: var(--fg-dim, #71717a); }
  .ev2 { color: var(--fg-faint, #52525b); }
  .ev2.g { color: var(--green, #34d399); }
  .ev2.y { color: var(--yellow, #fbbf24); }
  .ev2.sm { font-size: 9px; font-family: 'SF Mono', monospace; }
  .env-fp { font-size: 8px; color: var(--fg-ghost, #3f3f46); margin-top: 8px; word-break: break-all; font-family: 'SF Mono', monospace; }
  .env-empty-msg { color: var(--fg-ghost, #3f3f46); font-size: 12px; padding: 40px; text-align: center; }
  .tls-card {
    background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24);
    border-radius: 8px; padding: 10px;
  }
  .tls-title { font-size: 10px; color: var(--orange, #fb923c); margin-bottom: 6px; font-weight: 600; }
  .tls-row { display: flex; justify-content: space-between; padding: 2px 0; font-size: 10px; color: var(--fg-faint, #52525b); }
  .tls-h { color: var(--orange, #fb923c); }

  /* Log column */
  .log-col {
    width: 300px; flex-shrink: 0; display: flex; flex-direction: column;
    background: var(--bg-panel, #111116); border-left: 1px solid var(--border, #1e1e24);
  }
  .log-top {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 10px; border-bottom: 1px solid var(--border, #1e1e24);
  }
  .log-t { font-size: 9px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; font-weight: 600; }
  .log-clear { background: none; border: none; color: var(--fg-ghost, #3f3f46); font-size: 10px; cursor: pointer; font-family: inherit; }
  .log-clear:hover { color: var(--fg-muted, #a1a1aa); }
  .log-body { flex: 1; overflow-y: auto; padding: 6px 10px; font-size: 10px; line-height: 1.5; }
  .ll { color: var(--fg-muted, #a1a1aa); }
  .dim { color: var(--fg-ghost, #3f3f46); font-style: italic; }
</style>
