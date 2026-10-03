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
      if (devices.length > 0) selectedDevice = devices[0].serial
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
  <div class="top-panels">
    <!-- Left: Proxy + Android -->
    <div class="panel">
      <div class="section">
        <h2>PROXY</h2>
        <div class="row">
          <span class="label">Listen</span>
          <input type="text" bind:value={proxyAddr} disabled={isRunning} class="input mono" />
          <button class="btn" class:btn-danger={isRunning} class:btn-success={!isRunning} on:click={toggleProxy}>
            {isRunning ? '■ Stop' : '▶ Start'}
          </button>
          {#if isRunning}
            <button class="btn" class:btn-warn={!isPaused} class:btn-success={isPaused} on:click={togglePause}>
              {isPaused ? '▶ Resume' : '⏸ Pause'}
            </button>
          {/if}
        </div>
        {#if isRunning}
          <div class="rate-bar">
            <span class="rate-item">{rate.req_per_sec.toFixed(1)} req/s</span>
            <span class="rate-item">{formatBytes(rate.byte_per_sec)}/s</span>
            <span class="rate-item">Total: {rate.total_reqs} reqs</span>
            <span class="rate-item">{formatBytes(rate.total_bytes)}</span>
            <span class="status-badge" class:paused={isPaused}>{isPaused ? 'PAUSED' : 'CAPTURING'}</span>
          </div>
        {/if}
      </div>

      <div class="divider"></div>

      <div class="section">
        <h2>ANDROID</h2>
        <div class="row">
          <span class="label">Device</span>
          <select bind:value={selectedDevice} class="input" disabled={busy}>
            {#if devices.length === 0}<option value="">Scanning...</option>{/if}
            {#each devices as d}<option value={d.serial}>{d.serial} ({d.state})</option>{/each}
          </select>
          <button class="btn btn-ghost" on:click={refreshDevices} disabled={busy}>⟳</button>
        </div>
        <div class="row">
          <span class="label">Port</span>
          <input type="text" bind:value={port} class="input mono small" />
          <label class="check-label"><input type="checkbox" bind:checked={installCert} /> Cert</label>
          <div class="spacer"></div>
          <button class="btn btn-primary" on:click={connectDevice} disabled={busy}>Connect</button>
          <button class="btn btn-ghost" on:click={disconnectDevice} disabled={busy}>Disconnect</button>
        </div>
        <div class="row">
          <span class="label">WiFi</span>
          <input type="text" bind:value={wifiIP} placeholder="192.168.1.x:5555" class="input mono" />
          <button class="btn btn-ghost" on:click={connectWiFi} disabled={busy}>Connect WiFi</button>
        </div>
        <div class="row">
          <span class="label">App</span>
          <select bind:value={selectedApp} class="input">
            {#if apps.length === 0}<option value="">Click Load</option>{/if}
            {#each apps as app}<option value={app.package}>{app.package}</option>{/each}
          </select>
          <button class="btn btn-ghost" on:click={loadApps}>Load</button>
          <button class="btn btn-ghost" on:click={launchApp} disabled={!selectedApp}>Launch</button>
        </div>
      </div>

      <div class="divider"></div>

      <div class="section">
        <h2>FILTER</h2>
        <div class="row">
          <span class="label">Mode</span>
          <select bind:value={filterMode} class="input small-select">
            <option value="none">No filter</option>
            <option value="whitelist">Whitelist</option>
            <option value="blacklist">Blacklist</option>
          </select>
        </div>
        {#if filterMode !== 'none'}
          <textarea class="filter-domains" bind:value={filterDomains} placeholder="One domain per line, e.g.&#10;api.example.com&#10;kugou.com"></textarea>
        {/if}
      </div>
    </div>

    <!-- Right: Device Info -->
    <div class="panel env-panel">
      <div class="env-header">
        <h2>DEVICE ENV</h2>
        <button class="btn btn-ghost" on:click={scanDeviceEnv} disabled={envLoading}>
          {envLoading ? '...' : '⟳ Scan'}
        </button>
      </div>

      {#if deviceEnv}
        <div class="env-grid">
          <div class="env-section">
            <div class="env-label">HARDWARE</div>
            <div class="env-row"><span class="ek">Model</span><span class="ev">{deviceEnv.brand} {deviceEnv.model}</span></div>
            <div class="env-row"><span class="ek">Android</span><span class="ev">{deviceEnv.android} (SDK {deviceEnv.sdk})</span></div>
            <div class="env-row"><span class="ek">CPU</span><span class="ev">{deviceEnv.cpu}</span></div>
            <div class="env-row"><span class="ek">RAM</span><span class="ev">{deviceEnv.ram}</span></div>
            <div class="env-row"><span class="ek">Screen</span><span class="ev">{deviceEnv.screen}</span></div>
            <div class="env-row"><span class="ek">Kernel</span><span class="ev mono-sm">{deviceEnv.kernel}</span></div>
            <div class="env-row"><span class="ek">Battery</span><span class="ev">{deviceEnv.battery}</span></div>
          </div>
          <div class="env-section">
            <div class="env-label">SECURITY</div>
            <div class="env-row">
              <span class="ek">Root</span>
              <span class="ev" class:ev-on={deviceEnv.rooted} class:ev-off={!deviceEnv.rooted}>
                {deviceEnv.rooted ? '✓ ' + deviceEnv.root_method : '✗ Not rooted'}
              </span>
            </div>
            <div class="env-row">
              <span class="ek">Magisk</span>
              <span class="ev" class:ev-on={deviceEnv.magisk === 'installed'}>
                {deviceEnv.magisk === 'installed' ? '✓ ' + (deviceEnv.magisk_ver || 'installed') : '✗'}
              </span>
            </div>
            <div class="env-row">
              <span class="ek">Zygisk</span>
              <span class="ev" class:ev-on={deviceEnv.zygisk}>{deviceEnv.zygisk ? '✓ Active' : '✗'}</span>
            </div>
            <div class="env-row">
              <span class="ek">LSPosed</span>
              <span class="ev" class:ev-on={deviceEnv.lsposed}>
                {deviceEnv.lsposed ? '✓ ' + (deviceEnv.lsposed_ver || 'installed') : '✗'}
              </span>
            </div>
            <div class="env-row">
              <span class="ek">SELinux</span>
              <span class="ev" class:ev-warn={deviceEnv.selinux === 'Enforcing'} class:ev-on={deviceEnv.selinux === 'Permissive'}>
                {deviceEnv.selinux || '?'}
              </span>
            </div>
            <div class="env-row">
              <span class="ek">Integrity</span>
              <span class="ev mono-sm">{deviceEnv.integrity || 'N/A'}</span>
            </div>
          </div>
        </div>
        <div class="env-fp mono-sm">{deviceEnv.fingerprint}</div>
      {:else}
        <div class="env-empty">Click Scan to detect device environment</div>
      {/if}

      {#if tlsErrors.length > 0}
        <div class="env-section" style="margin-top: 8px;">
          <div class="env-label">⚠ SSL PINNING</div>
          {#each tlsErrors.slice(0, 8) as e}
            <div class="env-row"><span class="ek tls-host">{e.host}</span><span class="ev">×{e.count}</span></div>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  <div class="log-panel">
    <div class="log-header">
      <h2>LOG</h2>
      <button class="btn-ghost-sm" on:click={() => { logs = [] }}>Clear</button>
    </div>
    <div class="log-output">
      {#each logs as line}
        <div class="log-line">{line}</div>
      {/each}
      {#if logs.length === 0}
        <div class="log-empty">Waiting for activity...</div>
      {/if}
    </div>
  </div>
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; padding: 12px; gap: 10px; }
  .top-panels { display: flex; gap: 10px; }
  .panel { background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24); border-radius: 8px; padding: 14px; flex: 1; }
  .tls-panel { max-width: 300px; flex: none; }
  .section h2 { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; margin-bottom: 10px; font-weight: 600; }
  .row { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
  .label { font-size: 11px; color: var(--fg-dim, #71717a); min-width: 40px; text-align: right; }
  .divider { height: 1px; background: var(--border, #1e1e24); margin: 10px 0; }

  .input {
    flex: 1; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 5px;
    padding: 5px 8px; color: var(--fg, #e4e4e7); font-size: 11px; outline: none; font-family: inherit;
  }
  .input:focus { border-color: var(--accent, #38bdf8); }
  .input:disabled { opacity: 0.5; }
  .input.small { max-width: 64px; flex: none; }
  .small-select { max-width: 120px; flex: none; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; }

  .btn {
    padding: 5px 12px; border: 1px solid var(--border, #27272a); border-radius: 5px;
    background: var(--bg-btn, #1a1a22); color: var(--fg, #e4e4e7); font-size: 11px; cursor: pointer;
    font-family: inherit; transition: all 0.1s; white-space: nowrap;
  }
  .btn:hover { background: var(--bg-btn, #27272a); }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-success { background: #064e3b; border-color: #059669; color: var(--green, #34d399); }
  .btn-danger { background: #4c0519; border-color: #dc2626; color: var(--red, #f87171); }
  .btn-primary { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .btn-ghost { border-color: transparent; background: transparent; color: var(--fg-muted, #a1a1aa); }
  .btn-ghost:hover { background: var(--bg-btn, #1a1a22); }
  .btn-warn { background: #422006; border-color: #f59e0b; color: var(--yellow, #fbbf24); }
  .spacer { flex: 1; }
  .check-label { display: flex; align-items: center; gap: 3px; font-size: 11px; color: var(--fg-muted, #a1a1aa); cursor: pointer; }
  .check-label input { accent-color: var(--accent, #38bdf8); }

  .rate-bar {
    display: flex; gap: 12px; padding: 6px 0; font-size: 11px; align-items: center;
  }
  .rate-item { color: var(--fg-faint, #52525b); font-family: 'SF Mono', monospace; }
  .status-badge {
    padding: 2px 8px; border-radius: 3px; font-size: 9px; letter-spacing: 0.5px; font-weight: 600;
    background: rgba(52, 211, 153, 0.15); color: var(--green, #34d399);
  }
  .status-badge.paused { background: rgba(251, 191, 36, 0.15); color: var(--yellow, #fbbf24); }

  .filter-domains {
    width: 100%; min-height: 50px; max-height: 80px; resize: vertical;
    background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 5px;
    padding: 6px 8px; color: var(--fg, #e4e4e7); font-size: 11px; font-family: inherit; outline: none;
    margin-top: 4px;
  }

  .env-panel { min-width: 280px; max-width: 340px; flex: none; overflow-y: auto; }
  .env-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .env-header h2 { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; font-weight: 600; }
  .env-grid { display: flex; flex-direction: column; gap: 8px; }
  .env-section { }
  .env-label {
    font-size: 9px; color: var(--fg-faint, #52525b); letter-spacing: 1px; margin-bottom: 4px;
    padding-bottom: 3px; border-bottom: 1px solid var(--border, #1e1e24);
  }
  .env-row { display: flex; padding: 2px 0; font-size: 11px; gap: 6px; }
  .ek { color: var(--fg-dim, #71717a); min-width: 60px; flex-shrink: 0; }
  .ev { color: var(--fg, #e4e4e7); word-break: break-all; }
  .ev-on { color: var(--green, #34d399); }
  .ev-off { color: var(--fg-faint, #52525b); }
  .ev-warn { color: var(--yellow, #fbbf24); }
  .mono-sm { font-family: 'SF Mono', monospace; font-size: 10px; }
  .env-fp { font-size: 9px; color: var(--fg-ghost, #3f3f46); margin-top: 8px; word-break: break-all; }
  .env-empty { font-size: 11px; color: var(--fg-ghost, #3f3f46); font-style: italic; padding: 12px 0; }
  .tls-host { color: var(--orange, #fb923c); }

  .log-panel {
    flex: 1; background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24); border-radius: 8px;
    padding: 12px; display: flex; flex-direction: column; min-height: 0;
  }
  .log-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
  .log-header h2 { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; font-weight: 600; }
  .btn-ghost-sm { background: transparent; border: none; color: var(--fg-ghost, #3f3f46); font-size: 10px; cursor: pointer; font-family: inherit; }
  .btn-ghost-sm:hover { color: var(--fg-muted, #a1a1aa); }
  .log-output { flex: 1; overflow-y: auto; font-size: 11px; line-height: 1.5; }
  .log-line { color: var(--fg-muted, #a1a1aa); }
  .log-empty { color: var(--fg-ghost, #3f3f46); font-style: italic; }
</style>
