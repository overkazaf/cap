<script>
  let flows = []
  let selectedFlow = null
  let filterHost = ''
  let filterMethod = ''
  let filterSearch = ''
  let exportLang = 'curl'
  let exportCode = ''
  let activeTab = 'req-headers'

  const languages = ['curl', 'python', 'go', 'java', 'js']

  async function loadFlows() {
    try {
      flows = await window.go.wailsgui.App.GetFlows(filterHost, filterMethod, filterSearch, 200)
      flows = flows || []
    } catch(e) { console.error(e) }
  }

  async function selectFlow(f) {
    try {
      selectedFlow = await window.go.wailsgui.App.GetFlowDetail(f.id)
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

  function copyExport() {
    navigator.clipboard.writeText(exportCode)
  }

  function statusClass(status) {
    if (status >= 500) return 'status-5xx'
    if (status >= 400) return 'status-4xx'
    if (status >= 300) return 'status-3xx'
    return 'status-2xx'
  }

  function methodClass(method) {
    return `method-${method.toLowerCase()}`
  }

  function formatBody(body, type) {
    if (!body) return ''
    if (type && type.includes('json')) {
      try { return JSON.stringify(JSON.parse(body), null, 2) } catch(e) {}
    }
    return body
  }

  // Auto-refresh every 2s
  let interval
  import { onMount, onDestroy } from 'svelte'
  onMount(() => {
    loadFlows()
    interval = setInterval(loadFlows, 2000)
  })
  onDestroy(() => clearInterval(interval))
</script>

<div class="page">
  <div class="filter-bar">
    <input type="text" placeholder="Host" bind:value={filterHost} on:input={loadFlows} class="filter-input" />
    <select bind:value={filterMethod} on:change={loadFlows} class="filter-select">
      <option value="">All Methods</option>
      <option>GET</option><option>POST</option><option>PUT</option>
      <option>DELETE</option><option>PATCH</option>
    </select>
    <input type="text" placeholder="Search URL/body..." bind:value={filterSearch} on:input={loadFlows} class="filter-input wide" />
    <span class="flow-count">{flows.length} flows</span>
  </div>

  <div class="main-split">
    <div class="flow-list">
      <div class="list-header">
        <span class="col-method">Method</span>
        <span class="col-status">Status</span>
        <span class="col-host">Host</span>
        <span class="col-path">Path</span>
        <span class="col-latency">ms</span>
        <span class="col-time">Time</span>
      </div>
      <div class="list-body">
        {#each flows as f}
          <div
            class="flow-row"
            class:selected={selectedFlow && selectedFlow.id === f.id}
            on:click={() => selectFlow(f)}
          >
            <span class="col-method {methodClass(f.method)}">{f.method}</span>
            <span class="col-status {statusClass(f.status)}">{f.status}</span>
            <span class="col-host">{f.host}</span>
            <span class="col-path" title={f.url}>{f.path}</span>
            <span class="col-latency">{f.latency_ms}</span>
            <span class="col-time">{f.time}</span>
          </div>
        {/each}
        {#if flows.length === 0}
          <div class="empty">No flows captured yet. Start the proxy and generate traffic.</div>
        {/if}
      </div>
    </div>

    {#if selectedFlow}
      <div class="detail-panel">
        <div class="detail-header">
          <span class="detail-method {methodClass(selectedFlow.method)}">{selectedFlow.method}</span>
          <span class="detail-url">{selectedFlow.url}</span>
          <span class="{statusClass(selectedFlow.status)}">{selectedFlow.status}</span>
          <span class="detail-latency">{selectedFlow.latency_ms}ms</span>
        </div>

        {#if selectedFlow.sign_params && selectedFlow.sign_params.length > 0}
          <div class="sign-badge">
            🔐 Sign params: {selectedFlow.sign_params.join(', ')}
          </div>
        {/if}

        <div class="detail-tabs">
          {#each [
            {id: 'req-headers', label: 'Req Headers'},
            {id: 'req-body', label: 'Req Body'},
            {id: 'resp-headers', label: 'Resp Headers'},
            {id: 'resp-body', label: 'Resp Body'},
          ] as tab}
            <button class="tab-btn" class:tab-active={activeTab === tab.id} on:click={() => activeTab = tab.id}>
              {tab.label}
            </button>
          {/each}
        </div>

        <div class="detail-content">
          {#if activeTab === 'req-headers'}
            <div class="headers">
              {#each Object.entries(selectedFlow.req_headers || {}).sort() as [k, v]}
                <div class="header-row">
                  <span class="header-key">{k}</span>
                  <span class="header-val">{v}</span>
                </div>
              {/each}
            </div>
          {:else if activeTab === 'req-body'}
            <pre class="body-pre">{formatBody(selectedFlow.req_body, selectedFlow.body_type)}</pre>
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
            <pre class="body-pre">{formatBody(selectedFlow.resp_body, selectedFlow.body_type)}</pre>
          {/if}
        </div>

        <div class="export-section">
          <div class="export-bar">
            <span class="export-label">Export</span>
            {#each languages as lang}
              <button class="lang-btn" class:lang-active={exportLang === lang} on:click={() => { exportLang = lang; generateExport() }}>
                {lang}
              </button>
            {/each}
            <button class="lang-btn" on:click={exportAgent}>JSONL</button>
            <div class="spacer"></div>
            <button class="btn-copy" on:click={copyExport}>Copy</button>
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

<style>
  .page { display: flex; flex-direction: column; height: 100%; }
  .filter-bar {
    display: flex; gap: 8px; padding: 8px 12px;
    background: #111116; border-bottom: 1px solid #1e1e24;
    align-items: center;
  }
  .filter-input, .filter-select {
    background: #0a0a0f; border: 1px solid #27272a; border-radius: 4px;
    padding: 5px 8px; color: #e4e4e7; font-size: 12px; font-family: inherit;
    outline: none;
  }
  .filter-input:focus { border-color: #38bdf8; }
  .filter-input.wide { flex: 1; }
  .filter-select { cursor: pointer; }
  .flow-count { font-size: 11px; color: #52525b; margin-left: auto; }

  .main-split { flex: 1; display: flex; min-height: 0; }

  .flow-list { width: 50%; border-right: 1px solid #1e1e24; display: flex; flex-direction: column; }
  .list-header {
    display: flex; padding: 6px 12px; font-size: 10px; color: #52525b;
    text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #1e1e24;
    background: #0d0d12;
  }
  .list-body { flex: 1; overflow-y: auto; }
  .flow-row {
    display: flex; padding: 5px 12px; font-size: 12px;
    border-bottom: 1px solid #0f0f14; cursor: pointer; transition: background 0.1s;
  }
  .flow-row:hover { background: #14141a; }
  .flow-row.selected { background: #1a1a28; border-left: 2px solid #38bdf8; }

  .col-method { width: 56px; font-weight: 600; flex-shrink: 0; }
  .col-status { width: 42px; flex-shrink: 0; text-align: center; }
  .col-host { width: 140px; flex-shrink: 0; color: #a1a1aa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-path { flex: 1; color: #71717a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-latency { width: 48px; flex-shrink: 0; text-align: right; color: #52525b; }
  .col-time { width: 80px; flex-shrink: 0; text-align: right; color: #3f3f46; }

  .method-get { color: #34d399; }
  .method-post { color: #38bdf8; }
  .method-put { color: #fbbf24; }
  .method-delete { color: #f87171; }
  .method-patch { color: #c084fc; }

  .status-2xx { color: #34d399; }
  .status-3xx { color: #fbbf24; }
  .status-4xx { color: #fb923c; }
  .status-5xx { color: #f87171; }

  .empty { padding: 40px; text-align: center; color: #3f3f46; font-size: 13px; }

  .detail-panel { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .detail-header {
    display: flex; gap: 8px; padding: 10px 14px; align-items: center;
    background: #0d0d12; border-bottom: 1px solid #1e1e24; font-size: 12px;
  }
  .detail-method { font-weight: 700; }
  .detail-url { flex: 1; color: #a1a1aa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .detail-latency { color: #52525b; }

  .sign-badge {
    padding: 4px 14px; font-size: 11px; background: #1c1917;
    color: #fbbf24; border-bottom: 1px solid #1e1e24;
  }

  .detail-tabs {
    display: flex; background: #0d0d12; border-bottom: 1px solid #1e1e24;
  }
  .tab-btn {
    padding: 6px 14px; font-size: 11px; border: none;
    background: transparent; color: #71717a; cursor: pointer; font-family: inherit;
    border-bottom: 2px solid transparent; transition: all 0.1s;
  }
  .tab-btn:hover { color: #a1a1aa; }
  .tab-active { color: #38bdf8; border-bottom-color: #38bdf8; }

  .detail-content { flex: 1; overflow-y: auto; padding: 8px 14px; min-height: 120px; }
  .headers { font-size: 12px; }
  .header-row { display: flex; padding: 3px 0; border-bottom: 1px solid #0f0f14; }
  .header-key { width: 180px; color: #38bdf8; flex-shrink: 0; }
  .header-val { color: #a1a1aa; word-break: break-all; }
  .body-pre { font-size: 12px; color: #a1a1aa; white-space: pre-wrap; word-break: break-all; margin: 0; }

  .export-section { border-top: 1px solid #1e1e24; max-height: 200px; display: flex; flex-direction: column; }
  .export-bar {
    display: flex; align-items: center; gap: 4px; padding: 6px 10px;
    background: #0d0d12; border-bottom: 1px solid #1e1e24;
  }
  .export-label { font-size: 10px; color: #52525b; text-transform: uppercase; letter-spacing: 0.5px; margin-right: 4px; }
  .lang-btn {
    padding: 3px 8px; font-size: 11px; border: 1px solid #27272a;
    background: transparent; color: #71717a; border-radius: 4px;
    cursor: pointer; font-family: inherit; transition: all 0.1s;
  }
  .lang-btn:hover { background: #1a1a22; color: #a1a1aa; }
  .lang-active { background: #1e3a5f; border-color: #38bdf8; color: #7dd3fc; }
  .spacer { flex: 1; }
  .btn-copy {
    padding: 3px 10px; font-size: 11px; border: 1px solid #27272a;
    background: #1a1a22; color: #a1a1aa; border-radius: 4px;
    cursor: pointer; font-family: inherit;
  }
  .btn-copy:hover { background: #27272a; }
  .export-code { flex: 1; overflow-y: auto; padding: 8px 12px; font-size: 11px; color: #a1a1aa; margin: 0; white-space: pre-wrap; word-break: break-all; }

  .detail-empty {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: #3f3f46; font-size: 14px; gap: 8px;
  }
  .detail-empty-icon { font-size: 32px; opacity: 0.5; }
</style>
