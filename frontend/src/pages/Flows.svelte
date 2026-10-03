<script>
  import { onMount, onDestroy, tick } from 'svelte'

  let flows = []
  let selectedFlow = null
  let filterHost = ''
  let filterMethod = ''
  let filterSearch = ''
  let exportLang = 'curl'
  let exportCode = ''
  let activeTab = 'params'
  let bodyFormat = 'auto'
  let signResults = []
  let replayResult = null
  let listWidth = 45
  let dragging = false
  let exportHeight = 200
  let exportDragging = false
  let viewMode = 'list' // 'list' or 'grouped'
  let apiGroups = []
  let showReplayEditor = false
  let replayURL = ''
  let replayBody = ''
  let replayHeaders = ''
  let replaying = false

  // Device screen mirror
  let rightPanel = 'detail' // 'detail' or 'device'
  let screenSrc = ''
  let screenActive = false
  let screenInterval = null
  let screenSize = [1080, 2400]
  let deviceSerial = ''
  let shellHeight = 200
  let shellDragging = false
  let screenQuality = 50
  let shellTabs = []
  let activeShellTab = null
  let shellTabCounter = 0

  const languages = ['curl', 'python', 'go', 'java', 'js']

  async function loadFlows() {
    try {
      flows = await window.go.wailsgui.App.GetFlows(filterHost, filterMethod, filterSearch, 200) || []
    } catch(e) { console.error(e) }
  }

  async function clearFlows() {
    try {
      await window.go.wailsgui.App.ClearFlows()
      flows = []
      selectedFlow = null
      exportCode = ''
      signResults = []
    } catch(e) { console.error(e) }
  }

  async function selectFlow(f) {
    try {
      selectedFlow = await window.go.wailsgui.App.GetFlowDetail(f.id)
      bodyFormat = 'auto'
      signResults = []
      generateExport()
    } catch(e) { console.error(e) }
  }

  async function generateExport() {
    if (!selectedFlow) return
    try {
      exportCode = await window.go.wailsgui.App.ExportCode(selectedFlow.id, exportLang)
    } catch(e) { exportCode = `Error: ${e}` }
  }

  async function exportAgent() {
    try {
      exportCode = await window.go.wailsgui.App.ExportAgent()
      exportLang = 'jsonl'
    } catch(e) { exportCode = `Error: ${e}` }
  }

  async function analyzeSign() {
    if (!selectedFlow) return
    try {
      signResults = await window.go.wailsgui.App.AnalyzeSign(selectedFlow.id) || []
    } catch(e) { signResults = [{ param_name: 'error', value: String(e), encoding: '', possible_algs: [], confidence: 0 }] }
  }

  async function getHexBody(isReq) {
    if (!selectedFlow) return ''
    try {
      return await window.go.wailsgui.App.GetBodyHex(selectedFlow.id, isReq)
    } catch(e) { return `Error: ${e}` }
  }

  async function replayFlow() {
    if (!selectedFlow) return
    replaying = true
    try {
      replayResult = await window.go.wailsgui.App.ReplayFlow(selectedFlow.id)
    } catch(e) { replayResult = { error: String(e) } }
    replaying = false
  }

  async function replayModified() {
    if (!selectedFlow) return
    replaying = true
    let setHeaders = {}
    if (replayHeaders.trim()) {
      for (const line of replayHeaders.split('\n')) {
        const idx = line.indexOf(':')
        if (idx > 0) setHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
      }
    }
    try {
      replayResult = await window.go.wailsgui.App.ReplayModified({
        flow_id: selectedFlow.id,
        url: replayURL || '',
        method: '',
        set_headers: setHeaders,
        del_headers: [],
        body: replayBody || '',
      })
    } catch(e) { replayResult = { error: String(e) } }
    replaying = false
  }

  function openReplayEditor() {
    if (!selectedFlow) return
    replayURL = selectedFlow.url
    replayBody = selectedFlow.req_body || ''
    replayHeaders = ''
    replayResult = null
    showReplayEditor = !showReplayEditor
  }

  function parseParams(flow) {
    const params = []
    // URL query params
    try {
      const url = new URL(flow.url)
      for (const [k, v] of url.searchParams) {
        params.push({ source: 'query', key: k, value: v })
      }
    } catch(e) {}
    // Form body params (application/x-www-form-urlencoded)
    if (flow.req_body && flow.body_type && flow.body_type.includes('form')) {
      try {
        const pairs = flow.req_body.split('&')
        for (const pair of pairs) {
          const [k, ...rest] = pair.split('=')
          params.push({ source: 'form', key: decodeURIComponent(k), value: decodeURIComponent(rest.join('=')) })
        }
      } catch(e) {}
    }
    // JSON body params (top-level keys)
    if (flow.req_body && (!flow.body_type || flow.body_type.includes('json'))) {
      try {
        const obj = JSON.parse(flow.req_body)
        if (typeof obj === 'object' && obj !== null && !Array.isArray(obj)) {
          for (const [k, v] of Object.entries(obj)) {
            params.push({ source: 'json', key: k, value: typeof v === 'object' ? JSON.stringify(v) : String(v) })
          }
        }
      } catch(e) {}
    }
    return params
  }

  function isSignParam(key, flow) {
    const sp = flow.sign_params || []
    return sp.some(p => p.toLowerCase() === key.toLowerCase())
  }

  function copyText(text) {
    navigator.clipboard.writeText(text)
  }

  function statusClass(s) {
    if (s >= 500) return 'status-5xx'
    if (s >= 400) return 'status-4xx'
    if (s >= 300) return 'status-3xx'
    return 'status-2xx'
  }

  function methodClass(m) { return `method-${m.toLowerCase()}` }

  function formatBody(body, type, fmt) {
    if (!body) return '(empty)'
    if (fmt === 'hex') return '(loading hex...)'
    if (fmt === 'json' || (fmt === 'auto' && type && type.includes('json'))) {
      try { return JSON.stringify(JSON.parse(body), null, 2) } catch(e) {}
    }
    return body
  }

  function formatHex(hexStr) {
    if (!hexStr || hexStr === '(empty)') return hexStr
    let lines = []
    for (let i = 0; i < hexStr.length; i += 32) {
      const chunk = hexStr.slice(i, i + 32)
      const offset = (i / 2).toString(16).padStart(8, '0')
      const pairs = chunk.match(/.{1,2}/g) || []
      const ascii = pairs.map(h => {
        const c = parseInt(h, 16)
        return c >= 32 && c < 127 ? String.fromCharCode(c) : '.'
      }).join('')
      lines.push(`${offset}  ${pairs.join(' ').padEnd(48)}  ${ascii}`)
    }
    return lines.join('\n')
  }

  let hexCache = {}
  async function showHex(isReq) {
    const key = `${selectedFlow.id}-${isReq}`
    if (!hexCache[key]) {
      hexCache[key] = await getHexBody(isReq)
    }
    return formatHex(hexCache[key])
  }

  let reqHex = ''
  let respHex = ''
  async function switchBodyFormat(fmt) {
    bodyFormat = fmt
    if (fmt === 'hex' && selectedFlow) {
      reqHex = await showHex(true)
      respHex = await showHex(false)
    }
  }

  async function loadGroups() {
    try { apiGroups = await window.go.wailsgui.App.GetAPIGroups() || [] } catch(e) { console.error(e) }
  }

  function toggleView() {
    viewMode = viewMode === 'list' ? 'grouped' : 'list'
    if (viewMode === 'grouped') loadGroups()
  }

  async function startScreen() {
    try {
      const devs = await window.go.wailsgui.App.ListDevices()
      if (devs && devs.length > 0) {
        deviceSerial = devs[0].serial
        screenSize = await window.go.wailsgui.App.GetScreenSize(deviceSerial)
      }
    } catch(e) { console.error(e) }

    screenActive = true
    if (shellTabs.length === 0) addShellTab()
    captureFrame()
    screenInterval = setInterval(captureFrame, 500)
  }

  function stopScreen() {
    screenActive = false
    if (screenInterval) clearInterval(screenInterval)
    screenInterval = null
    screenSrc = ''
  }

  async function captureFrame() {
    if (!screenActive) return
    try {
      screenSrc = await window.go.wailsgui.App.CaptureScreenScaled(deviceSerial, screenQuality)
    } catch(e) { /* skip frame */ }
  }

  async function handleScreenClick(e) {
    const img = e.target
    const rect = img.getBoundingClientRect()
    const scaleX = screenSize[0] / rect.width
    const scaleY = screenSize[1] / rect.height
    const x = Math.round((e.clientX - rect.left) * scaleX)
    const y = Math.round((e.clientY - rect.top) * scaleY)
    try {
      await window.go.wailsgui.App.DeviceTap(deviceSerial, x, y)
      setTimeout(captureFrame, 300)
    } catch(err) { console.error(err) }
  }

  async function deviceBack() {
    await window.go.wailsgui.App.DeviceBack(deviceSerial)
    setTimeout(captureFrame, 300)
  }

  async function deviceHome() {
    await window.go.wailsgui.App.DeviceHome(deviceSerial)
    setTimeout(captureFrame, 300)
  }

  function toggleRightPanel(panel) {
    rightPanel = panel
    if (panel === 'device' && !screenActive) startScreen()
    if (panel === 'detail' && screenActive) stopScreen()
  }

  function addShellTab() {
    shellTabCounter++
    const tab = { id: `sh-${shellTabCounter}`, label: `sh-${shellTabCounter}`, content: '$ ', inputStart: 2, history: [], histIdx: -1 }
    shellTabs = [...shellTabs, tab]
    activeShellTab = tab.id
  }

  function closeShellTab(id) {
    shellTabs = shellTabs.filter(t => t.id !== id)
    if (activeShellTab === id) activeShellTab = shellTabs.length > 0 ? shellTabs[shellTabs.length - 1].id : null
  }

  function getShellTab(id) { return shellTabs.find(t => t.id === id) }

  async function handleShellKey(e, tabId) {
    const tab = getShellTab(tabId)
    if (!tab) return

    if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      tab.content = '$ '
      tab.inputStart = 2
      shellTabs = shellTabs
      return
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 't') {
      e.preventDefault()
      addShellTab()
      return
    }
    if (e.key === 'Enter') {
      e.preventDefault()
      const input = tab.content.slice(tab.inputStart).trim()
      if (input) { tab.history = [...tab.history, input]; tab.histIdx = -1 }
      tab.content += '\n'
      if (input === 'clear' || input === 'cls') {
        tab.content = ''
      } else if (input) {
        try {
          const r = await window.go.wailsgui.App.ExecCommand(input)
          if (r) tab.content += r + '\n'
        } catch(err) { tab.content += `error: ${err}\n` }
      }
      tab.content += '$ '
      tab.inputStart = tab.content.length
      shellTabs = shellTabs
      await tick()
      const el = e.target
      if (el) { el.scrollTop = el.scrollHeight; el.setSelectionRange(tab.content.length, tab.content.length) }
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (tab.history.length > 0) {
        if (tab.histIdx < 0) tab.histIdx = tab.history.length
        tab.histIdx = Math.max(0, tab.histIdx - 1)
        tab.content = tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        shellTabs = shellTabs
      }
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (tab.histIdx >= 0) {
        tab.histIdx++
        tab.content = tab.histIdx >= tab.history.length
          ? tab.content.slice(0, tab.inputStart)
          : tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        if (tab.histIdx >= tab.history.length) tab.histIdx = -1
        shellTabs = shellTabs
      }
      return
    }
    if (e.target.selectionStart < tab.inputStart && (e.key === 'Backspace' || e.key.length === 1)) {
      e.preventDefault()
      e.target.setSelectionRange(tab.content.length, tab.content.length)
    }
  }

  function handleShellInput(e, tabId) {
    const tab = getShellTab(tabId)
    if (!tab) return
    if (e.target.value.length < tab.inputStart) {
      e.target.value = tab.content
      e.target.setSelectionRange(tab.content.length, tab.content.length)
    } else {
      tab.content = e.target.value
    }
    shellTabs = shellTabs
  }

  function startShellDrag(e) {
    shellDragging = true
    e.preventDefault()
    const startY = e.clientY
    const startH = shellHeight
    const onMove = (ev) => { if (shellDragging) shellHeight = Math.max(60, Math.min(500, startH - (ev.clientY - startY))) }
    const onUp = () => { shellDragging = false; window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  function startExportDrag(e) {
    exportDragging = true
    e.preventDefault()
    const startY = e.clientY
    const startH = exportHeight
    const onMove = (ev) => {
      if (!exportDragging) return
      exportHeight = Math.max(80, Math.min(500, startH - (ev.clientY - startY)))
    }
    const onUp = () => { exportDragging = false; window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  function startDrag(e) {
    dragging = true
    e.preventDefault()
    const onMove = (ev) => {
      if (!dragging) return
      const container = document.querySelector('.main-split')
      if (!container) return
      const rect = container.getBoundingClientRect()
      listWidth = Math.max(20, Math.min(80, ((ev.clientX - rect.left) / rect.width) * 100))
    }
    const onUp = () => { dragging = false; window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  let interval
  onMount(() => { loadFlows(); interval = setInterval(loadFlows, 2000) })
  onDestroy(() => { clearInterval(interval); stopScreen() })
</script>

<div class="page">
  <div class="filter-bar">
    <input type="text" placeholder="Host" bind:value={filterHost} on:input={loadFlows} class="filter-input" />
    <select bind:value={filterMethod} on:change={loadFlows} class="filter-select">
      <option value="">All</option>
      <option>GET</option><option>POST</option><option>PUT</option>
      <option>DELETE</option><option>PATCH</option>
    </select>
    <input type="text" placeholder="Search..." bind:value={filterSearch} on:input={loadFlows} class="filter-input wide" />
    <span class="flow-count">{flows.length}</span>
    <button class="btn-view" class:btn-view-active={viewMode === 'grouped'} on:click={toggleView} title="Toggle API grouping">
      {viewMode === 'grouped' ? '☰ Flat' : '⊞ Group'}
    </button>
    <button class="btn-clear" on:click={clearFlows} title="Clear all flows">✕ Clear</button>
  </div>

  <div class="main-split">
    <div class="flow-list" style="width: {listWidth}%">
      <div class="list-header">
        <span class="col-method">MTD</span>
        <span class="col-status">ST</span>
        <span class="col-host">Host</span>
        <span class="col-path">Path</span>
        <span class="col-latency">ms</span>
        <span class="col-time">Time</span>
      </div>
      <div class="list-body">
        {#if viewMode === 'grouped'}
          {#each apiGroups as group}
            <div class="group-header">
              <span class="group-host">{group.host}</span>
              <span class="group-prefix">{group.prefix}</span>
              <span class="group-count">{group.count}</span>
            </div>
            {#each group.endpoints || [] as ep}
              <button class="flow-row group-row" on:click={() => { filterHost = group.host; filterSearch = ep.path; viewMode = 'list'; loadFlows() }}>
                <span class="col-method {methodClass(ep.method)}">{ep.method}</span>
                <span class="col-status"></span>
                <span class="col-host"></span>
                <span class="col-path">{ep.path}</span>
                <span class="col-latency">{ep.avg_ms}</span>
                <span class="col-time">×{ep.count}</span>
              </button>
            {/each}
          {/each}
          {#if apiGroups.length === 0}
            <div class="empty">No API groups. Capture some traffic first.</div>
          {/if}
        {:else}
          {#each flows as f}
            <button class="flow-row" class:selected={selectedFlow && selectedFlow.id === f.id} on:click={() => selectFlow(f)}>
              <span class="col-method {methodClass(f.method)}">{f.method}</span>
              <span class="col-status {statusClass(f.status)}">{f.status}</span>
              <span class="col-host">{f.host}</span>
              <span class="col-path" title={f.url}>{f.path}</span>
              <span class="col-latency">{f.latency_ms}</span>
              <span class="col-time">{f.time}</span>
            </button>
          {/each}
          {#if flows.length === 0}
            <div class="empty">No flows. Start the proxy and generate traffic.</div>
          {/if}
        {/if}
      </div>
    </div>

    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div class="drag-handle" on:mousedown={startDrag}></div>

    <div class="right-area">
      <div class="right-toggle">
        <button class="toggle-btn" class:toggle-active={rightPanel === 'detail'} on:click={() => toggleRightPanel('detail')}>Detail</button>
        <button class="toggle-btn" class:toggle-active={rightPanel === 'device'} on:click={() => toggleRightPanel('device')}>📱 Device</button>
      </div>

    {#if rightPanel === 'device'}
      <div class="device-layout">
        <div class="device-main">
          <div class="device-frame">
            <div class="device-screen-wrapper" style="aspect-ratio: {screenSize[0]} / {screenSize[1]}">
              {#if screenSrc}
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
                <img class="device-screen" src={screenSrc} alt="device" on:click={handleScreenClick} />
              {:else}
                <div class="device-placeholder">Connecting...</div>
              {/if}
            </div>
            <div class="device-controls">
              <button class="dev-btn" on:click={deviceBack}>◀</button>
              <button class="dev-btn" on:click={deviceHome}>●</button>
              <button class="dev-btn" on:click={captureFrame}>⟳</button>
              <span class="dev-info">{screenSize[0]}×{screenSize[1]}</span>
              <input type="range" min="20" max="100" step="10" bind:value={screenQuality} class="quality-slider" title="Quality: {screenQuality}%" />
              <span class="dev-info">{screenQuality}%</span>
            </div>
          </div>
        </div>
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="shell-drag" on:mousedown={startShellDrag}></div>
        <div class="device-shell" style="height: {shellHeight}px">
          <div class="shell-tab-bar">
            {#each shellTabs as st}
              <button class="sh-tab" class:sh-tab-active={st.id === activeShellTab} on:click={() => activeShellTab = st.id}>
                {st.label}
                <button class="sh-tab-close" on:click|stopPropagation={() => closeShellTab(st.id)}>×</button>
              </button>
            {/each}
            <button class="sh-tab-add" on:click={addShellTab}>+</button>
          </div>
          {#each shellTabs as st}
            {#if st.id === activeShellTab}
              <textarea
                class="shell-area"
                bind:value={st.content}
                on:keydown={(e) => handleShellKey(e, st.id)}
                on:input={(e) => handleShellInput(e, st.id)}
                spellcheck="false"
              ></textarea>
            {/if}
          {/each}
        </div>
      </div>
    {:else if selectedFlow}
      <div class="detail-panel">
        <div class="detail-header">
          <span class="detail-method {methodClass(selectedFlow.method)}">{selectedFlow.method}</span>
          <span class="detail-url" title={selectedFlow.url}>{selectedFlow.url}</span>
          <button class="btn-icon" on:click={() => copyText(selectedFlow.url)} title="Copy URL">📋</button>
          <span class="{statusClass(selectedFlow.status)}">{selectedFlow.status}</span>
          <span class="detail-latency">{selectedFlow.latency_ms}ms</span>
          <button class="btn-replay" on:click={replayFlow} disabled={replaying}>▶ Replay</button>
          <button class="btn-replay-edit" on:click={openReplayEditor}>✎ Modify</button>
        </div>

        {#if showReplayEditor}
          <div class="replay-editor">
            <div class="replay-row">
              <span class="replay-label">URL</span>
              <input type="text" class="replay-input" bind:value={replayURL} />
            </div>
            <div class="replay-row">
              <span class="replay-label">Headers</span>
              <textarea class="replay-textarea" bind:value={replayHeaders} placeholder="Key: Value (one per line)"></textarea>
            </div>
            <div class="replay-row">
              <span class="replay-label">Body</span>
              <textarea class="replay-textarea" bind:value={replayBody}></textarea>
            </div>
            <div class="replay-actions">
              <button class="btn-send" on:click={replayModified} disabled={replaying}>
                {replaying ? '...' : '▶ Send Modified'}
              </button>
            </div>
          </div>
        {/if}

        {#if replayResult}
          <div class="replay-result">
            <div class="replay-result-header">
              <span>REPLAY RESULT</span>
              {#if replayResult.error}
                <span class="status-5xx">{replayResult.error}</span>
              {:else}
                <span class="{statusClass(replayResult.status)}">{replayResult.status}</span>
                <span class="detail-latency">{replayResult.latency_ms}ms</span>
                {#if replayResult.status_diff}<span class="diff-badge">{replayResult.status_diff}</span>{/if}
              {/if}
              <button class="btn-icon" on:click={() => copyText(replayResult.body || '')}>📋</button>
            </div>
            {#if replayResult.body}
              <pre class="replay-body">{formatBody(replayResult.body, 'application/json', 'auto')}</pre>
            {/if}
          </div>
        {/if}

        <div class="sign-badge">
          {#if selectedFlow.sign_params && selectedFlow.sign_params.length > 0}
            <span>🔐 Detected: {selectedFlow.sign_params.join(', ')}</span>
          {:else}
            <span>🔍 Sign Analysis</span>
          {/if}
          <button class="btn-analyze" on:click={analyzeSign}>Analyze Algorithm</button>
        </div>

        {#if signResults.length > 0}
          <div class="sign-results">
            {#each signResults as sr}
              <div class="sign-row">
                <span class="sign-param">{sr.param_name}</span>
                <span class="sign-encoding">{sr.encoding}</span>
                <span class="sign-algs">{(sr.possible_algs || []).join(', ')}</span>
                <span class="sign-conf">{(sr.confidence * 100).toFixed(0)}%</span>
                {#if sr.input_guess}<span class="sign-guess">{sr.input_guess}</span>{/if}
              </div>
            {/each}
          </div>
        {/if}

        <div class="detail-tabs">
          {#each [
            {id: 'params', label: 'Params'},
            {id: 'req-headers', label: 'Req Headers'},
            {id: 'req-body', label: 'Req Body'},
            {id: 'resp-headers', label: 'Resp Headers'},
            {id: 'resp-body', label: 'Resp Body'},
          ] as tab}
            <button class="tab-btn" class:tab-active={activeTab === tab.id} on:click={() => activeTab = tab.id}>
              {tab.label}
            </button>
          {/each}
          <div class="tab-spacer"></div>
          {#if activeTab.includes('body')}
            <div class="format-switch">
              {#each ['auto', 'json', 'hex', 'raw'] as fmt}
                <button class="fmt-btn" class:fmt-active={bodyFormat === fmt} on:click={() => switchBodyFormat(fmt)}>
                  {fmt}
                </button>
              {/each}
            </div>
          {/if}
        </div>

        <div class="detail-content">
          {#if activeTab === 'params'}
            {@const params = parseParams(selectedFlow)}
            {#if params.length > 0}
              <div class="params-table">
                <div class="params-header-row">
                  <span class="param-col-source">Source</span>
                  <span class="param-col-key">Key</span>
                  <span class="param-col-val">Value</span>
                </div>
                {#each params as p}
                  <div class="param-row" class:param-sign={isSignParam(p.key, selectedFlow)}>
                    <span class="param-col-source">
                      <span class="param-badge" class:badge-query={p.source === 'query'} class:badge-form={p.source === 'form'} class:badge-json={p.source === 'json'}>{p.source}</span>
                    </span>
                    <span class="param-col-key" class:param-key-sign={isSignParam(p.key, selectedFlow)}>
                      {p.key}
                      {#if isSignParam(p.key, selectedFlow)}<span class="sign-tag">sign</span>{/if}
                    </span>
                    <span class="param-col-val" title={p.value}>{p.value}</span>
                  </div>
                {/each}
              </div>
              <div class="body-toolbar">
                <button class="btn-icon" on:click={() => copyText(params.map(p => p.key + '=' + p.value).join('\n'))} title="Copy params">📋 Copy All</button>
              </div>
            {:else}
              <div class="empty-params">No parameters found</div>
            {/if}
          {:else if activeTab === 'req-headers'}
            <div class="headers">
              {#each Object.entries(selectedFlow.req_headers || {}).sort() as [k, v]}
                <div class="header-row">
                  <span class="header-key">{k}</span>
                  <span class="header-val">{v}</span>
                </div>
              {/each}
            </div>
          {:else if activeTab === 'req-body'}
            <div class="body-toolbar">
              <button class="btn-icon" on:click={() => copyText(selectedFlow.req_body)} title="Copy body">📋 Copy</button>
            </div>
            <pre class="body-pre">{bodyFormat === 'hex' ? reqHex : formatBody(selectedFlow.req_body, selectedFlow.body_type, bodyFormat)}</pre>
          {:else if activeTab === 'resp-headers'}
            <div class="headers">
              {#each Object.entries(selectedFlow.resp_headers || {}).sort() as [k, v]}
                <div class="header-row">
                  <span class="header-key">{k}</span>
                  <span class="header-val">{v}</span>
                </div>
              {/each}
            </div>
          {:else if activeTab === 'resp-body'}
            <div class="body-toolbar">
              <button class="btn-icon" on:click={() => copyText(selectedFlow.resp_body)} title="Copy body">📋 Copy</button>
              {#if selectedFlow.body_type && selectedFlow.body_type.includes('json')}
                <button class="btn-icon" on:click={() => copyText(JSON.stringify(JSON.parse(selectedFlow.resp_body), null, 2))} title="Copy formatted JSON">📋 Copy JSON</button>
              {/if}
            </div>
            <pre class="body-pre">{bodyFormat === 'hex' ? respHex : formatBody(selectedFlow.resp_body, selectedFlow.body_type, bodyFormat)}</pre>
          {/if}
        </div>

        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="export-drag" on:mousedown={startExportDrag}></div>
        <div class="export-section" style="height: {exportHeight}px">
          <div class="export-bar">
            <span class="export-label">EXPORT</span>
            {#each languages as lang}
              <button class="lang-btn" class:lang-active={exportLang === lang} on:click={() => { exportLang = lang; generateExport() }}>
                {lang}
              </button>
            {/each}
            <button class="lang-btn" on:click={exportAgent}>JSONL</button>
            <div class="spacer"></div>
            <button class="btn-copy" on:click={() => copyText(exportCode)}>Copy</button>
          </div>
          <pre class="export-code">{exportCode}</pre>
        </div>
      </div>
    {:else}
      <div class="detail-empty">
        <div class="detail-empty-icon">📡</div>
        <div>Select a flow to inspect</div>
      </div>
    {/if}
    </div>
  </div>
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; }
  .filter-bar {
    display: flex; gap: 8px; padding: 8px 12px;
    background: var(--bg-panel, #111116); border-bottom: 1px solid var(--border, #1e1e24); align-items: center;
  }
  .filter-input, .filter-select {
    background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 4px;
    padding: 5px 8px; color: var(--fg, #e4e4e7); font-size: 12px; font-family: inherit; outline: none;
  }
  .filter-input:focus { border-color: var(--accent, #38bdf8); }
  .filter-input.wide { flex: 1; }
  .filter-select { cursor: pointer; }
  .flow-count { font-size: 11px; color: var(--fg-faint, #52525b); }
  .btn-view {
    padding: 4px 10px; font-size: 11px; border: 1px solid #3f3f46;
    background: transparent; color: var(--fg-dim, #71717a); border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-view:hover { background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa); }
  .btn-view-active { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .btn-clear {
    padding: 4px 10px; font-size: 11px; border: 1px solid #3f3f46;
    background: transparent; color: var(--fg-dim, #71717a); border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-clear:hover { background: var(--bg-btn, #27272a); color: var(--red, #f87171); border-color: var(--red, #f87171); }

  .main-split { flex: 1; display: flex; min-height: 0; }

  .flow-list { border-right: none; display: flex; flex-direction: column; flex-shrink: 0; }
  .drag-handle {
    width: 5px; cursor: col-resize; background: var(--border, #1e1e24);
    transition: background 0.15s; flex-shrink: 0;
  }
  .drag-handle:hover, .drag-handle:active { background: #38bdf8; }
  .list-header {
    display: flex; padding: 6px 12px; font-size: 10px; color: var(--fg-faint, #52525b);
    text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border, #1e1e24); background: var(--bg-header, #0d0d12);
  }
  .list-body { flex: 1; overflow-y: auto; }
  .flow-row {
    display: flex; width: 100%; padding: 5px 12px; font-size: 12px;
    border: none; border-bottom: 1px solid var(--border-subtle, #0f0f14); cursor: pointer;
    transition: background 0.1s; background: transparent; color: inherit;
    font-family: inherit; text-align: left;
  }
  .flow-row:hover { background: var(--bg-hover, #14141a); }
  .flow-row.selected { background: var(--bg-selected, #1a1a28); border-left: 2px solid #38bdf8; }

  .col-method { width: 50px; font-weight: 600; flex-shrink: 0; }
  .col-status { width: 36px; flex-shrink: 0; text-align: center; }
  .col-host { width: 130px; flex-shrink: 0; color: var(--fg-muted, #a1a1aa); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-path { flex: 1; color: var(--fg-dim, #71717a); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-latency { width: 42px; flex-shrink: 0; text-align: right; color: var(--fg-faint, #52525b); }
  .col-time { width: 76px; flex-shrink: 0; text-align: right; color: var(--fg-ghost, #3f3f46); }

  .method-get { color: var(--green, #34d399); }
  .method-post { color: var(--accent, #38bdf8); }
  .method-put { color: var(--yellow, #fbbf24); }
  .method-delete { color: var(--red, #f87171); }
  .method-patch { color: var(--purple, #c084fc); }
  .status-2xx { color: var(--green, #34d399); }
  .status-3xx { color: var(--yellow, #fbbf24); }
  .status-4xx { color: var(--orange, #fb923c); }
  .status-5xx { color: var(--red, #f87171); }

  .group-header {
    display: flex; gap: 8px; padding: 6px 12px; background: #0d0d14;
    border-bottom: 1px solid var(--border, #1e1e24); font-size: 11px; align-items: center;
  }
  .group-host { color: var(--accent, #38bdf8); font-weight: 600; }
  .group-prefix { color: var(--fg-dim, #71717a); flex: 1; }
  .group-count { color: var(--fg-faint, #52525b); font-size: 10px; }
  .group-row { padding-left: 24px; }

  .params-table { font-size: 12px; }
  .params-header-row {
    display: flex; padding: 6px 12px; font-size: 10px; color: var(--fg-faint, #52525b);
    text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border, #1e1e24);
    background: var(--bg-header, #0d0d12);
  }
  .param-row {
    display: flex; padding: 5px 12px; border-bottom: 1px solid var(--border-subtle, #0f0f14);
    transition: background 0.1s;
  }
  .param-row:hover { background: var(--bg-hover, #14141a); }
  .param-sign { background: rgba(251, 191, 36, 0.05); }
  .param-col-source { width: 60px; flex-shrink: 0; }
  .param-col-key { width: 180px; flex-shrink: 0; color: var(--accent, #38bdf8); font-weight: 500; display: flex; align-items: center; gap: 4px; }
  .param-col-val { flex: 1; color: var(--fg-muted, #a1a1aa); word-break: break-all; user-select: text; }
  .param-key-sign { color: var(--yellow, #fbbf24); }
  .param-badge {
    padding: 1px 5px; border-radius: 3px; font-size: 9px; text-transform: uppercase;
    letter-spacing: 0.3px; font-weight: 600;
  }
  .badge-query { background: rgba(56, 189, 248, 0.15); color: var(--accent, #38bdf8); }
  .badge-form { background: rgba(192, 132, 252, 0.15); color: var(--purple, #c084fc); }
  .badge-json { background: rgba(52, 211, 153, 0.15); color: var(--green, #34d399); }
  .sign-tag {
    padding: 0 4px; font-size: 8px; background: rgba(251, 191, 36, 0.2);
    color: var(--yellow, #fbbf24); border-radius: 2px; text-transform: uppercase;
  }
  .empty-params { padding: 20px; text-align: center; color: var(--fg-ghost, #3f3f46); }

  .empty { padding: 40px; text-align: center; color: var(--fg-ghost, #3f3f46); font-size: 13px; }

  .detail-panel { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .detail-header {
    display: flex; gap: 8px; padding: 8px 12px; align-items: center;
    background: var(--bg-header, #0d0d12); border-bottom: 1px solid var(--border, #1e1e24); font-size: 12px;
  }
  .detail-method { font-weight: 700; }
  .detail-url { flex: 1; color: var(--fg-muted, #a1a1aa); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .detail-latency { color: var(--fg-faint, #52525b); }
  .btn-icon {
    background: transparent; border: none; cursor: pointer; font-size: 11px; color: var(--fg-dim, #71717a);
    padding: 2px 6px; border-radius: 3px;
  }
  .btn-icon:hover { background: var(--bg-btn, #27272a); color: var(--fg, #e4e4e7); }

  .sign-badge {
    display: flex; align-items: center; gap: 8px;
    padding: 5px 12px; font-size: 11px; background: #1c1917;
    color: var(--yellow, #fbbf24); border-bottom: 1px solid var(--border, #1e1e24);
  }
  .btn-analyze {
    padding: 3px 10px; font-size: 10px; border: 1px solid #fbbf24;
    background: transparent; color: var(--yellow, #fbbf24); border-radius: 4px;
    cursor: pointer; font-family: inherit; margin-left: auto;
  }
  .btn-analyze:hover { background: #422006; }

  .sign-results {
    padding: 6px 12px; background: var(--bg-header, #0f0f14); border-bottom: 1px solid var(--border, #1e1e24); font-size: 11px;
  }
  .sign-row {
    display: flex; gap: 12px; padding: 3px 0; align-items: center;
  }
  .sign-param { color: var(--accent, #38bdf8); font-weight: 600; min-width: 60px; }
  .sign-encoding { color: var(--fg-muted, #a1a1aa); min-width: 40px; }
  .sign-algs { color: var(--green, #34d399); flex: 1; }
  .sign-conf { color: var(--yellow, #fbbf24); font-weight: 600; }
  .sign-guess { color: var(--fg-dim, #71717a); font-style: italic; }

  .detail-tabs {
    display: flex; background: var(--bg-header, #0d0d12); border-bottom: 1px solid var(--border, #1e1e24); align-items: center;
  }
  .tab-btn {
    padding: 6px 12px; font-size: 11px; border: none;
    background: transparent; color: var(--fg-dim, #71717a); cursor: pointer; font-family: inherit;
    border-bottom: 2px solid transparent; transition: all 0.1s;
  }
  .tab-btn:hover { color: var(--fg-muted, #a1a1aa); }
  .tab-active { color: var(--accent, #38bdf8); border-bottom-color: var(--accent, #38bdf8); }
  .tab-spacer { flex: 1; }

  .format-switch { display: flex; gap: 2px; margin-right: 8px; }
  .fmt-btn {
    padding: 2px 8px; font-size: 10px; border: 1px solid var(--border, #27272a);
    background: transparent; color: var(--fg-faint, #52525b); border-radius: 3px;
    cursor: pointer; font-family: inherit; text-transform: uppercase;
  }
  .fmt-btn:hover { color: var(--fg-muted, #a1a1aa); }
  .fmt-active { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }

  .detail-content { flex: 1; overflow-y: auto; padding: 0; min-height: 120px; }
  .headers { font-size: 12px; padding: 8px 12px; }
  .header-row { display: flex; padding: 3px 0; border-bottom: 1px solid var(--border-subtle, #0f0f14); }
  .header-key { width: 180px; color: var(--accent, #38bdf8); flex-shrink: 0; }
  .header-val { color: var(--fg-muted, #a1a1aa); word-break: break-all; }

  .body-toolbar { display: flex; gap: 4px; padding: 4px 12px; border-bottom: 1px solid var(--border-subtle, #0f0f14); }
  .body-pre {
    font-size: 12px; color: var(--fg-muted, #a1a1aa); white-space: pre-wrap; word-break: break-all;
    margin: 0; padding: 8px 12px; user-select: text;
  }

  .export-drag {
    height: 5px; cursor: row-resize; background: var(--border, #1e1e24); flex-shrink: 0;
  }
  .export-drag:hover, .export-drag:active { background: #38bdf8; }
  .export-section { display: flex; flex-direction: column; flex-shrink: 0; overflow: hidden; }
  .export-bar {
    display: flex; align-items: center; gap: 4px; padding: 5px 10px;
    background: var(--bg-header, #0d0d12); border-bottom: 1px solid var(--border, #1e1e24);
  }
  .export-label { font-size: 10px; color: var(--fg-faint, #52525b); letter-spacing: 0.5px; margin-right: 4px; }
  .lang-btn {
    padding: 3px 8px; font-size: 11px; border: 1px solid var(--border, #27272a);
    background: transparent; color: var(--fg-dim, #71717a); border-radius: 4px;
    cursor: pointer; font-family: inherit; transition: all 0.1s;
  }
  .lang-btn:hover { background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa); }
  .lang-active { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .spacer { flex: 1; }
  .btn-copy {
    padding: 3px 10px; font-size: 11px; border: 1px solid var(--border, #27272a);
    background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa); border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-copy:hover { background: var(--bg-btn, #27272a); }
  .export-code { flex: 1; overflow-y: auto; padding: 8px 12px; font-size: 11px; color: var(--fg-muted, #a1a1aa); margin: 0; white-space: pre-wrap; word-break: break-all; user-select: text; }

  .detail-empty {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: var(--fg-ghost, #3f3f46); font-size: 14px; gap: 8px;
  }
  .detail-empty-icon { font-size: 32px; opacity: 0.5; }

  .right-area { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .right-toggle {
    display: flex; background: var(--bg-header, #0d0d12); border-bottom: 1px solid var(--border, #1e1e24);
  }
  .toggle-btn {
    padding: 6px 16px; font-size: 11px; border: none; background: transparent;
    color: var(--fg-dim, #71717a); cursor: pointer; font-family: inherit;
    border-bottom: 2px solid transparent; transition: all 0.1s;
  }
  .toggle-btn:hover { color: var(--fg-muted, #a1a1aa); }
  .toggle-active { color: var(--accent, #38bdf8); border-bottom-color: var(--accent, #38bdf8); }

  .device-layout { flex: 1; display: flex; flex-direction: column; min-height: 0; }
  .device-main { flex: 1; display: flex; justify-content: center; align-items: flex-start; background: #000; overflow: hidden; padding: 4px; min-height: 0; }
  .device-frame { display: flex; flex-direction: column; align-items: center; height: 100%; }
  .device-screen-wrapper {
    height: 100%; max-width: 100%; display: flex; align-items: center; justify-content: center;
    border-radius: 8px; overflow: hidden; border: 2px solid #222;
  }
  .device-screen { width: 100%; height: 100%; object-fit: contain; cursor: pointer; display: block; }
  .device-placeholder { color: var(--fg-ghost, #3f3f46); font-size: 13px; padding: 40px; }
  .device-controls {
    display: flex; gap: 6px; padding: 6px; align-items: center;
  }
  .dev-btn {
    padding: 4px 12px; font-size: 11px; border: 1px solid var(--border, #27272a);
    background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa);
    border-radius: 5px; cursor: pointer; font-family: inherit;
  }
  .dev-btn:hover { background: var(--bg-hover, #27272a); }
  .dev-info { font-size: 10px; color: var(--fg-ghost, #3f3f46); margin-left: 4px; }

  .shell-drag { height: 5px; cursor: row-resize; background: var(--border, #1e1e24); flex-shrink: 0; }
  .shell-drag:hover, .shell-drag:active { background: var(--accent, #38bdf8); }
  .quality-slider { width: 60px; accent-color: var(--accent, #38bdf8); }

  .device-shell {
    display: flex; flex-direction: column; flex-shrink: 0; overflow: hidden;
    background: var(--bg, #0a0a0f);
  }
  .shell-tab-bar {
    display: flex; background: var(--bg-panel, #111116); border-bottom: 1px solid var(--border, #1e1e24);
    padding: 0 4px; align-items: stretch; flex-shrink: 0;
  }
  .sh-tab {
    padding: 4px 10px; font-size: 10px; border: none; background: transparent;
    color: var(--fg-dim, #71717a); cursor: pointer; font-family: inherit;
    display: flex; align-items: center; gap: 4px; border-bottom: 2px solid transparent;
  }
  .sh-tab:hover { color: var(--fg-muted, #a1a1aa); }
  .sh-tab-active { color: var(--green, #34d399); border-bottom-color: var(--green, #34d399); }
  .sh-tab-close {
    font-size: 12px; color: var(--fg-ghost, #3f3f46); background: transparent; border: none;
    cursor: pointer; padding: 0; width: 14px; height: 14px; display: flex; align-items: center; justify-content: center;
  }
  .sh-tab-close:hover { color: var(--red, #f87171); }
  .sh-tab-add {
    padding: 4px 8px; font-size: 14px; border: none; background: transparent;
    color: var(--fg-ghost, #3f3f46); cursor: pointer; font-family: inherit;
  }
  .sh-tab-add:hover { color: var(--green, #34d399); }
  .shell-area {
    flex: 1; resize: none; border: none; outline: none;
    background: var(--bg, #0a0a0f); color: var(--green, #34d399);
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px; line-height: 1.5; padding: 6px 10px;
    caret-color: var(--green, #34d399);
  }

  .btn-replay, .btn-replay-edit {
    padding: 3px 10px; font-size: 11px; border: 1px solid var(--border, #27272a);
    background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa); border-radius: 4px;
    cursor: pointer; font-family: inherit; white-space: nowrap;
  }
  .btn-replay:hover { background: var(--accent-bg, #1e3a5f); border-color: var(--accent, #38bdf8); color: var(--accent, #7dd3fc); }
  .btn-replay-edit:hover { background: #422006; border-color: var(--yellow, #fbbf24); color: var(--yellow, #fbbf24); }
  .btn-replay:disabled { opacity: 0.5; }

  .replay-editor {
    padding: 8px 12px; background: var(--bg-header, #0d0d12); border-bottom: 1px solid var(--border, #1e1e24);
  }
  .replay-row { display: flex; gap: 8px; margin-bottom: 6px; align-items: flex-start; }
  .replay-label { font-size: 11px; color: var(--fg-faint, #52525b); min-width: 50px; padding-top: 5px; }
  .replay-input {
    flex: 1; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 4px;
    padding: 4px 8px; color: var(--fg, #e4e4e7); font-size: 12px; font-family: inherit; outline: none;
  }
  .replay-textarea {
    flex: 1; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 4px;
    padding: 4px 8px; color: var(--fg, #e4e4e7); font-size: 12px; font-family: inherit;
    outline: none; resize: vertical; min-height: 40px; max-height: 100px;
  }
  .replay-actions { display: flex; justify-content: flex-end; }
  .btn-send {
    padding: 4px 14px; font-size: 11px; border: 1px solid #38bdf8;
    background: var(--accent-bg, #1e3a5f); color: var(--accent, #7dd3fc); border-radius: 4px;
    cursor: pointer; font-family: inherit;
  }
  .btn-send:hover { background: #1e4a6f; }
  .btn-send:disabled { opacity: 0.5; }

  .replay-result { border-bottom: 1px solid var(--border, #1e1e24); }
  .replay-result-header {
    display: flex; gap: 8px; padding: 5px 12px; align-items: center;
    background: var(--bg-header, #0f0f14); font-size: 11px; color: var(--fg-faint, #52525b);
  }
  .diff-badge { padding: 1px 6px; background: #422006; color: var(--yellow, #fbbf24); border-radius: 3px; font-size: 10px; }
  .replay-body {
    max-height: 120px; overflow-y: auto; padding: 6px 12px;
    font-size: 12px; color: var(--fg-muted, #a1a1aa); margin: 0; white-space: pre-wrap; word-break: break-all;
  }
</style>
