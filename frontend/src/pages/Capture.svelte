<script>
  import { onMount, onDestroy } from 'svelte'
  import { state as S } from '../lib/captureState.js'

  let proxyAddr = S.proxyAddr
  let isRunning = S.isRunning
  let isPaused = S.isPaused
  let logs = S.logs
  let devices = S.devices
  let selectedDevice = S.selectedDevice
  let port = S.port
  let installCert = S.installCert
  let busy = false
  let rate = S.rate
  let rateInterval = null
  let deviceEnv = S.deviceEnv
  let envLoading = false

  // Sync back to shared state on changes
  $: { S.proxyAddr = proxyAddr; S.isRunning = isRunning; S.isPaused = isPaused; S.logs = logs; S.devices = devices; S.selectedDevice = selectedDevice; S.port = port; S.installCert = installCert; S.deviceEnv = deviceEnv; S.rate = rate; }

  function log(msg) {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    logs = [...logs, `[${ts}] ${msg}`]
    if (logs.length > 300) logs = logs.slice(-300)
    setTimeout(() => { const el = document.querySelector('.log-body'); if (el) el.scrollTop = el.scrollHeight }, 50)
  }

  function fmtBytes(b) {
    if (b < 1024) return b + ' B'
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
    return (b / 1048576).toFixed(1) + ' MB'
  }

  async function toggleProxy() {
    if (isRunning) {
      try { await window.go.wailsgui.App.StopProxy(); isRunning = false; isPaused = false; log('Proxy stopped') }
      catch(e) { log(`Error: ${e}`) }
      if (rateInterval) { clearInterval(rateInterval); rateInterval = null }
    } else {
      try {
        await window.go.wailsgui.App.StartProxy(proxyAddr)
        isRunning = true
        const addr = await window.go.wailsgui.App.ProxyAddr()
        log(`Proxy started on ${addr}`)
        rateInterval = setInterval(async () => { try { rate = await window.go.wailsgui.App.GetTrafficRate() } catch(e) {} }, 1000)
      } catch(e) { log(`Error: ${e}`) }
    }
  }

  async function togglePause() {
    if (isPaused) { await window.go.wailsgui.App.ResumeCapture(); isPaused = false; log('Resumed') }
    else { await window.go.wailsgui.App.PauseCapture(); isPaused = true; log('Paused') }
  }

  async function refreshDevices() {
    busy = true; log('Scanning...')
    try {
      const devs = await window.go.wailsgui.App.ListDevices()
      devices = devs || []
      if (devices.length > 0) { selectedDevice = devices[0].serial; scanEnv() }
      log(`Found ${devices.length} device(s)`)
    } catch(e) { log(`Scan: ${e}`) }
    busy = false
  }

  async function connectDevice() {
    if (!selectedDevice) return
    busy = true; log(`Connecting ${selectedDevice}...`)
    try {
      await window.go.wailsgui.App.ConnectDevice(selectedDevice, port, installCert)
      log(`Connected`); scanEnv()
    } catch(e) { log(`Failed: ${e}`) }
    busy = false
  }

  async function disconnectDevice() {
    if (!selectedDevice) return
    busy = true
    try { await window.go.wailsgui.App.DisconnectDevice(selectedDevice); log('Disconnected') }
    catch(e) { log(`Error: ${e}`) }
    busy = false
  }

  async function scanEnv() {
    if (!selectedDevice) return
    envLoading = true
    try { deviceEnv = await window.go.wailsgui.App.GetDeviceEnv(selectedDevice) }
    catch(e) { log(`Env scan: ${e}`) }
    envLoading = false
  }

  onMount(() => {
    if (!S.initialized) {
      S.initialized = true
      refreshDevices()
    }
    // Restart rate polling if proxy is running
    if (isRunning && !rateInterval) {
      rateInterval = setInterval(async () => { try { rate = await window.go.wailsgui.App.GetTrafficRate() } catch(e) {} }, 1000)
    }
  })
  onDestroy(() => { if (rateInterval) { clearInterval(rateInterval); rateInterval = null } })
</script>

<div class="page">
  <!-- Header: Proxy status -->
  <div class="proxy-bar">
    <div class="proxy-left">
      <input type="text" bind:value={proxyAddr} disabled={isRunning} class="addr-input" />
      <button class="proxy-btn" class:running={isRunning} on:click={toggleProxy}>
        {isRunning ? '■ STOP' : '▶ START'}
      </button>
      {#if isRunning}
        <button class="pause-btn" class:paused={isPaused} on:click={togglePause}>
          {isPaused ? '▶' : '⏸'}
        </button>
      {/if}
    </div>
    {#if isRunning}
      <div class="stats">
        <span class="stat">{rate.req_per_sec.toFixed(1)} <small>req/s</small></span>
        <span class="stat">{fmtBytes(rate.byte_per_sec)} <small>/s</small></span>
        <span class="stat">{rate.total_reqs} <small>total</small></span>
        <span class="badge" class:paused={isPaused}>{isPaused ? 'PAUSED' : 'LIVE'}</span>
      </div>
    {:else}
      <span class="proxy-status">STOPPED</span>
    {/if}
  </div>

  <div class="main">
    <!-- Left: Device + Connect -->
    <div class="device-col">
      <div class="card">
        <div class="card-title">DEVICE</div>
        <select bind:value={selectedDevice} class="sel" disabled={busy}>
          {#if devices.length === 0}<option value="">No device</option>{/if}
          {#each devices as d}<option value={d.serial}>{d.serial}</option>{/each}
        </select>
        <div class="btn-row">
          <button class="btn-sm" on:click={refreshDevices} disabled={busy}>⟳ Refresh</button>
          <button class="btn-sm primary" on:click={connectDevice} disabled={busy}>Connect</button>
          <button class="btn-sm" on:click={disconnectDevice} disabled={busy}>Disconnect</button>
        </div>
        <div class="connect-opts">
          <span class="opt">Port <input type="text" bind:value={port} class="port-input" /></span>
          <label class="opt"><input type="checkbox" bind:checked={installCert} /> CA Cert</label>
        </div>
      </div>

      {#if deviceEnv}
        <div class="card env-card">
          <div class="device-name">{deviceEnv.brand} {deviceEnv.model}</div>
          <div class="device-meta">Android {deviceEnv.android} · {deviceEnv.cpu} · {deviceEnv.ram}</div>
          <div class="env-grid">
            <div class="eg"><span class="ek">Root</span><span class:on={deviceEnv.rooted}>{deviceEnv.rooted ? '✓ '+deviceEnv.root_method : '✗'}</span></div>
            <div class="eg"><span class="ek">Magisk</span><span class:on={deviceEnv.magisk==='installed'}>{deviceEnv.magisk==='installed' ? '✓ '+(deviceEnv.magisk_ver||'') : '✗'}</span></div>
            <div class="eg"><span class="ek">Zygisk</span><span class:on={deviceEnv.zygisk}>{deviceEnv.zygisk ? '✓' : '✗'}</span></div>
            <div class="eg"><span class="ek">LSPosed</span><span class:on={deviceEnv.lsposed}>{deviceEnv.lsposed ? '✓' : '✗'}</span></div>
            <div class="eg"><span class="ek">SELinux</span><span class:warn={deviceEnv.selinux==='Enforcing'}>{deviceEnv.selinux||'?'}</span></div>
            <div class="eg"><span class="ek">Battery</span><span>{deviceEnv.battery}</span></div>
          </div>
        </div>
      {/if}
    </div>

    <!-- Right: Log -->
    <div class="log-col">
      <div class="log-header">
        <span>LOG</span>
        <button class="log-clear" on:click={() => logs = []}>Clear</button>
      </div>
      <div class="log-body">
        {#each logs as line}<div class="log-line">{line}</div>{/each}
        {#if logs.length === 0}<div class="log-line dim">Waiting for activity...</div>{/if}
      </div>
    </div>
  </div>
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; }

  .proxy-bar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 16px; background: var(--bg-panel, #111116);
    border-bottom: 1px solid var(--border, #1e1e24);
  }
  .proxy-left { display: flex; align-items: center; gap: 8px; }
  .addr-input {
    width: 180px; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a);
    border-radius: 6px; padding: 7px 12px; color: var(--fg, #e4e4e7); font-size: 13px;
    font-family: 'SF Mono', 'Fira Code', monospace; outline: none;
  }
  .addr-input:focus { border-color: var(--accent, #38bdf8); }
  .addr-input:disabled { opacity: 0.5; }
  .proxy-btn {
    padding: 7px 20px; border-radius: 6px; font-size: 12px; font-weight: 600;
    font-family: inherit; cursor: pointer; letter-spacing: 0.5px;
    background: #064e3b; border: 1px solid #059669; color: var(--green, #34d399);
  }
  .proxy-btn.running { background: #4c0519; border-color: #dc2626; color: var(--red, #f87171); }
  .proxy-btn:hover { filter: brightness(1.2); }
  .pause-btn {
    padding: 7px 12px; border-radius: 6px; font-size: 12px;
    background: transparent; border: 1px solid var(--border, #27272a); color: var(--fg-muted, #a1a1aa);
    cursor: pointer; font-family: inherit;
  }
  .pause-btn.paused { color: var(--green, #34d399); border-color: #059669; }
  .stats { display: flex; gap: 16px; align-items: center; }
  .stat { font-size: 14px; color: var(--fg, #e4e4e7); font-family: 'SF Mono', monospace; }
  .stat small { font-size: 10px; color: var(--fg-faint, #52525b); }
  .badge {
    padding: 3px 10px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: 1px;
    background: rgba(52, 211, 153, 0.15); color: var(--green, #34d399);
  }
  .badge.paused { background: rgba(251, 191, 36, 0.15); color: var(--yellow, #fbbf24); }
  .proxy-status { font-size: 12px; color: var(--fg-faint, #52525b); letter-spacing: 1px; }

  .main { display: flex; flex: 1; min-height: 0; }

  .device-col {
    width: 320px; flex-shrink: 0; padding: 16px; overflow-y: auto;
    display: flex; flex-direction: column; gap: 12px;
  }
  .card {
    background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24);
    border-radius: 10px; padding: 14px;
  }
  .card-title { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; font-weight: 600; margin-bottom: 10px; }
  .sel {
    width: 100%; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a);
    border-radius: 6px; padding: 7px 10px; color: var(--fg, #e4e4e7); font-size: 12px;
    font-family: inherit; outline: none; cursor: pointer; margin-bottom: 8px;
  }
  .btn-row { display: flex; gap: 6px; margin-bottom: 8px; }
  .btn-sm {
    flex: 1; padding: 6px 0; border: 1px solid var(--border, #27272a); border-radius: 6px;
    background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa); font-size: 11px;
    cursor: pointer; font-family: inherit; text-align: center;
  }
  .btn-sm:hover { background: var(--bg-hover, #27272a); }
  .btn-sm:disabled { opacity: 0.4; }
  .btn-sm.primary { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .connect-opts { display: flex; gap: 12px; align-items: center; }
  .opt { font-size: 11px; color: var(--fg-dim, #71717a); display: flex; align-items: center; gap: 4px; }
  .opt input[type="checkbox"] { accent-color: var(--accent, #38bdf8); }
  .port-input {
    width: 48px; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a);
    border-radius: 4px; padding: 3px 6px; color: var(--fg, #e4e4e7); font-size: 11px;
    font-family: 'SF Mono', monospace; outline: none; text-align: center;
  }

  .env-card { padding: 12px; }
  .device-name { font-size: 15px; font-weight: 600; color: var(--fg, #e4e4e7); }
  .device-meta { font-size: 11px; color: var(--fg-dim, #71717a); margin: 4px 0 10px; }
  .env-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 16px; }
  .eg { display: flex; justify-content: space-between; font-size: 11px; padding: 2px 0; }
  .ek { color: var(--fg-dim, #71717a); }
  .on { color: var(--green, #34d399); }
  .warn { color: var(--yellow, #fbbf24); }

  .log-col {
    flex: 1; display: flex; flex-direction: column;
    border-left: 1px solid var(--border, #1e1e24);
  }
  .log-header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 14px; font-size: 10px; color: var(--accent, #38bdf8);
    letter-spacing: 1.5px; font-weight: 600;
    border-bottom: 1px solid var(--border, #1e1e24);
    background: var(--bg-panel, #111116);
  }
  .log-clear { background: none; border: none; color: var(--fg-ghost, #3f3f46); font-size: 10px; cursor: pointer; font-family: inherit; }
  .log-clear:hover { color: var(--fg-muted, #a1a1aa); }
  .log-body { flex: 1; overflow-y: auto; padding: 8px 14px; font-size: 11px; line-height: 1.6; }
  .log-line { color: var(--fg-muted, #a1a1aa); }
  .dim { color: var(--fg-ghost, #3f3f46); font-style: italic; }
</style>
