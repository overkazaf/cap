<script>
  let proxyAddr = '0.0.0.0:8080'
  let isRunning = false
  let status = 'Stopped'
  let logs = []
  let devices = []
  let selectedDevice = ''
  let port = '8080'
  let installCert = true
  let busy = false

  function log(msg) {
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false })
    logs = [...logs, `[${ts}] ${msg}`]
    setTimeout(() => {
      const el = document.querySelector('.log-output')
      if (el) el.scrollTop = el.scrollHeight
    }, 50)
  }

  async function toggleProxy() {
    if (isRunning) {
      try {
        await window.go.wailsgui.App.StopProxy()
        isRunning = false
        status = 'Stopped'
        log('Proxy stopped')
      } catch(e) { log(`Error: ${e}`) }
    } else {
      try {
        await window.go.wailsgui.App.StartProxy(proxyAddr)
        isRunning = true
        const addr = await window.go.wailsgui.App.ProxyAddr()
        status = `Running on ${addr}`
        log(`Proxy started on ${addr}`)
      } catch(e) { log(`Error: ${e}`) }
    }
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
    if (!selectedDevice) { log('Select a device first'); return }
    busy = true
    try {
      await window.go.wailsgui.App.DisconnectDevice(selectedDevice)
      log(`Disconnected ${selectedDevice}`)
    } catch(e) { log(`Failed: ${e}`) }
    busy = false
  }
</script>

<div class="page">
  <div class="panel">
    <div class="section">
      <h2>PROXY</h2>
      <div class="row">
        <label>Listen</label>
        <input type="text" bind:value={proxyAddr} disabled={isRunning} class="input mono" />
        <button class="btn" class:btn-danger={isRunning} class:btn-success={!isRunning} on:click={toggleProxy}>
          {isRunning ? '■ Stop' : '▶ Start'}
        </button>
        <span class="status" class:status-on={isRunning}>{status}</span>
      </div>
    </div>

    <div class="divider"></div>

    <div class="section">
      <h2>ANDROID</h2>
      <div class="row">
        <label>Device</label>
        <select bind:value={selectedDevice} class="input" disabled={busy}>
          {#if devices.length === 0}
            <option value="">No devices</option>
          {/if}
          {#each devices as d}
            <option value={d.serial}>{d.serial} ({d.state})</option>
          {/each}
        </select>
        <button class="btn btn-ghost" on:click={refreshDevices} disabled={busy}>⟳ Refresh</button>
      </div>
      <div class="row">
        <label>Port</label>
        <input type="text" bind:value={port} class="input mono small" />
        <label class="check-label">
          <input type="checkbox" bind:checked={installCert} />
          CA Cert
        </label>
        <div class="spacer"></div>
        <button class="btn btn-primary" on:click={connectDevice} disabled={busy}>Connect</button>
        <button class="btn btn-ghost" on:click={disconnectDevice} disabled={busy}>Disconnect</button>
      </div>
    </div>
  </div>

  <div class="log-panel">
    <h2>LOG</h2>
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
  .page { display: flex; flex-direction: column; height: 100%; padding: 16px; gap: 12px; }
  .panel { background: #111116; border: 1px solid #1e1e24; border-radius: 8px; padding: 16px; }
  .section h2 { font-size: 11px; color: #38bdf8; letter-spacing: 1.5px; margin-bottom: 12px; font-weight: 600; }
  .row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .row label { font-size: 12px; color: #71717a; min-width: 48px; text-align: right; }
  .divider { height: 1px; background: #1e1e24; margin: 12px 0; }

  .input {
    flex: 1;
    background: #0a0a0f;
    border: 1px solid #27272a;
    border-radius: 6px;
    padding: 6px 10px;
    color: #e4e4e7;
    font-size: 12px;
    outline: none;
    font-family: inherit;
  }
  .input:focus { border-color: #38bdf8; }
  .input:disabled { opacity: 0.5; }
  .input.small { max-width: 72px; flex: none; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; }
  select.input { cursor: pointer; }

  .btn {
    padding: 6px 14px;
    border: 1px solid #27272a;
    border-radius: 6px;
    background: #1a1a22;
    color: #e4e4e7;
    font-size: 12px;
    cursor: pointer;
    font-family: inherit;
    transition: all 0.1s;
    white-space: nowrap;
  }
  .btn:hover { background: #27272a; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-success { background: #064e3b; border-color: #059669; color: #34d399; }
  .btn-success:hover { background: #065f46; }
  .btn-danger { background: #4c0519; border-color: #dc2626; color: #f87171; }
  .btn-danger:hover { background: #6b0c1a; }
  .btn-primary { background: #1e3a5f; border-color: #38bdf8; color: #7dd3fc; }
  .btn-primary:hover { background: #1e4a6f; }
  .btn-ghost { border-color: transparent; background: transparent; color: #a1a1aa; }
  .btn-ghost:hover { background: #1a1a22; }

  .status { font-size: 11px; color: #71717a; margin-left: auto; }
  .status-on { color: #34d399; }
  .spacer { flex: 1; }

  .check-label {
    display: flex; align-items: center; gap: 4px;
    font-size: 12px; color: #a1a1aa; cursor: pointer;
    min-width: auto;
  }
  .check-label input { accent-color: #38bdf8; }

  .log-panel {
    flex: 1;
    background: #111116;
    border: 1px solid #1e1e24;
    border-radius: 8px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .log-panel h2 { font-size: 11px; color: #38bdf8; letter-spacing: 1.5px; margin-bottom: 8px; font-weight: 600; }
  .log-output {
    flex: 1;
    overflow-y: auto;
    font-size: 12px;
    line-height: 1.6;
  }
  .log-line { color: #a1a1aa; }
  .log-empty { color: #3f3f46; font-style: italic; }
</style>
