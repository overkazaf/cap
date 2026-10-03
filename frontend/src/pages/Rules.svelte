<script>
  import { onMount } from 'svelte'

  let rules = []
  let editRule = null
  let isNew = false
  let pendingBPs = []
  let bpInterval = null

  // Edit form
  let eName = '', eMethod = '', eHost = '', ePath = '', eURL = '', eHeader = '', eBody = ''
  let eActionType = 'passthrough', ePriority = 10, eEnabled = true
  let eMockStatus = 200, eMockHeaders = '', eMockBody = ''
  let eSetHeaders = '', eDelHeaders = '', eReplaceBody = ''
  let eSetRespHeaders = '', eReplaceRespBody = '', eSetStatus = 0
  let eBreakReq = true, eBreakResp = false

  async function loadRules() {
    try { rules = await window.go.wailsgui.App.ListRules() || [] } catch(e) {}
  }

  async function loadBPs() {
    try { pendingBPs = await window.go.wailsgui.App.GetPendingBreakpoints() || [] } catch(e) {}
  }

  function newRule() {
    isNew = true
    editRule = null
    eName = ''; eMethod = ''; eHost = ''; ePath = ''; eURL = ''; eHeader = ''; eBody = ''
    eActionType = 'mock'; ePriority = 10; eEnabled = true
    eMockStatus = 200; eMockHeaders = ''; eMockBody = '{"ok":true}'
    eSetHeaders = ''; eDelHeaders = ''; eReplaceBody = ''
    eSetRespHeaders = ''; eReplaceRespBody = ''; eSetStatus = 0
    eBreakReq = true; eBreakResp = false
  }

  function selectRule(r) {
    editRule = r; isNew = false
    eName = r.name; ePriority = r.priority; eEnabled = r.enabled
    eMethod = r.match?.method || ''; eHost = r.match?.host || ''
    ePath = r.match?.path || ''; eURL = r.match?.url || ''
    eHeader = r.match?.header || ''; eBody = r.match?.body_contains || ''
    eActionType = r.action?.type || 'passthrough'
    eMockStatus = r.action?.mock_status || 200
    eMockBody = r.action?.mock_body || ''
    eMockHeaders = Object.entries(r.action?.mock_headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n')
    eSetHeaders = Object.entries(r.action?.set_headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n')
    eDelHeaders = (r.action?.del_headers || []).join('\n')
    eReplaceBody = r.action?.replace_body || ''
    eSetRespHeaders = Object.entries(r.action?.set_resp_headers || {}).map(([k,v]) => `${k}: ${v}`).join('\n')
    eReplaceRespBody = r.action?.replace_resp_body || ''
    eSetStatus = r.action?.set_status || 0
    eBreakReq = r.action?.break_on_req || false
    eBreakResp = r.action?.break_on_resp || false
  }

  function parseHeaders(text) {
    const h = {}
    for (const line of text.split('\n')) {
      const idx = line.indexOf(':')
      if (idx > 0) h[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
    }
    return h
  }

  async function saveRule() {
    const id = editRule?.id || 'r-' + Date.now()
    const rule = {
      id, name: eName, enabled: eEnabled, priority: ePriority,
      match: { method: eMethod, host: eHost, path: ePath, url: eURL, header: eHeader, body_contains: eBody },
      action: {
        type: eActionType,
        mock_status: eMockStatus, mock_headers: parseHeaders(eMockHeaders), mock_body: eMockBody,
        set_headers: parseHeaders(eSetHeaders), del_headers: eDelHeaders.split('\n').filter(Boolean),
        replace_body: eReplaceBody,
        set_resp_headers: parseHeaders(eSetRespHeaders), replace_resp_body: eReplaceRespBody,
        set_status: eSetStatus,
        break_on_req: eBreakReq, break_on_resp: eBreakResp,
      }
    }
    try {
      if (!isNew && editRule) await window.go.wailsgui.App.RemoveRule(editRule.id)
      await window.go.wailsgui.App.AddRule(rule)
      loadRules()
      isNew = false
    } catch(e) { alert(`Save failed: ${e}`) }
  }

  async function deleteRule(id) {
    await window.go.wailsgui.App.RemoveRule(id)
    editRule = null
    loadRules()
  }

  async function resolveBP(bp, action) {
    try {
      await window.go.wailsgui.App.ResolveBreakpoint(bp.id, action, bp.url, bp.method, '', bp.headers, 0, {}, '')
      loadBPs()
    } catch(e) { alert(`Resolve failed: ${e}`) }
  }

  const actionTypes = [
    { value: 'passthrough', label: 'Pass through' },
    { value: 'mock', label: 'Mock response' },
    { value: 'modify_request', label: 'Modify request' },
    { value: 'modify_response', label: 'Modify response' },
    { value: 'breakpoint', label: 'Breakpoint (pause)' },
    { value: 'drop', label: 'Drop (block)' },
  ]

  onMount(() => {
    loadRules()
    bpInterval = setInterval(loadBPs, 1000)
    return () => clearInterval(bpInterval)
  })
</script>

<div class="page">
  <div class="rules-list">
    <div class="list-top">
      <h2>RULES</h2>
      <button class="btn-add" on:click={newRule}>+ New Rule</button>
    </div>

    {#if pendingBPs.length > 0}
      <div class="bp-section">
        <div class="bp-title">⏸ BREAKPOINTS ({pendingBPs.length})</div>
        {#each pendingBPs as bp}
          <div class="bp-item">
            <div class="bp-info">{bp.method} {bp.url}</div>
            <div class="bp-actions">
              <button class="bp-btn bp-forward" on:click={() => resolveBP(bp, 'forward')}>▶ Forward</button>
              <button class="bp-btn bp-drop" on:click={() => resolveBP(bp, 'drop')}>✕ Drop</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}

    <div class="list-body">
      {#each rules as r}
        <button class="rule-item" class:selected={editRule && editRule.id === r.id} on:click={() => selectRule(r)}>
          <span class="rule-status" class:on={r.enabled}></span>
          <span class="rule-name">{r.name || r.id}</span>
          <span class="rule-type">{r.action?.type}</span>
          <span class="rule-pri">P{r.priority}</span>
        </button>
      {/each}
      {#if rules.length === 0}
        <div class="empty">No rules. Click "+ New Rule" to create one.</div>
      {/if}
    </div>
  </div>

  <div class="rule-editor">
    {#if editRule || isNew}
      <div class="editor-section">
        <h3>RULE</h3>
        <div class="field"><span class="fl">Name</span><input bind:value={eName} class="fi" placeholder="e.g. Block ads" /></div>
        <div class="field"><span class="fl">Priority</span><input type="number" bind:value={ePriority} class="fi num" /></div>
        <div class="field"><label class="fl-check"><input type="checkbox" bind:checked={eEnabled} /> Enabled</label></div>
      </div>

      <div class="editor-section">
        <h3>MATCH (all conditions AND)</h3>
        <div class="field"><span class="fl">Method</span><input bind:value={eMethod} class="fi" placeholder="GET, POST, or empty for any" /></div>
        <div class="field"><span class="fl">Host</span><input bind:value={eHost} class="fi" placeholder="api.example.com" /></div>
        <div class="field"><span class="fl">Path</span><input bind:value={ePath} class="fi" placeholder="/api/login or regex" /></div>
        <div class="field"><span class="fl">URL</span><input bind:value={eURL} class="fi" placeholder="contains match" /></div>
        <div class="field"><span class="fl">Header</span><input bind:value={eHeader} class="fi" placeholder="Key: Value" /></div>
        <div class="field"><span class="fl">Body</span><input bind:value={eBody} class="fi" placeholder="body contains..." /></div>
      </div>

      <div class="editor-section">
        <h3>ACTION</h3>
        <div class="field">
          <span class="fl">Type</span>
          <select bind:value={eActionType} class="fi">
            {#each actionTypes as at}<option value={at.value}>{at.label}</option>{/each}
          </select>
        </div>

        {#if eActionType === 'mock'}
          <div class="field"><span class="fl">Status</span><input type="number" bind:value={eMockStatus} class="fi num" /></div>
          <div class="field"><span class="fl">Headers</span><textarea bind:value={eMockHeaders} class="fi ta" placeholder="Key: Value per line"></textarea></div>
          <div class="field"><span class="fl">Body</span><textarea bind:value={eMockBody} class="fi ta" placeholder="response body"></textarea></div>
        {:else if eActionType === 'modify_request'}
          <div class="field"><span class="fl">Set Headers</span><textarea bind:value={eSetHeaders} class="fi ta" placeholder="Key: Value per line"></textarea></div>
          <div class="field"><span class="fl">Del Headers</span><textarea bind:value={eDelHeaders} class="fi ta" placeholder="header name per line"></textarea></div>
          <div class="field"><span class="fl">Replace Body</span><textarea bind:value={eReplaceBody} class="fi ta"></textarea></div>
        {:else if eActionType === 'modify_response'}
          <div class="field"><span class="fl">Set Status</span><input type="number" bind:value={eSetStatus} class="fi num" /></div>
          <div class="field"><span class="fl">Resp Headers</span><textarea bind:value={eSetRespHeaders} class="fi ta" placeholder="Key: Value per line"></textarea></div>
          <div class="field"><span class="fl">Resp Body</span><textarea bind:value={eReplaceRespBody} class="fi ta"></textarea></div>
        {:else if eActionType === 'breakpoint'}
          <div class="field"><label class="fl-check"><input type="checkbox" bind:checked={eBreakReq} /> Break on request</label></div>
          <div class="field"><label class="fl-check"><input type="checkbox" bind:checked={eBreakResp} /> Break on response</label></div>
        {/if}
      </div>

      <div class="editor-actions">
        <button class="btn-save" on:click={saveRule}>Save Rule</button>
        {#if editRule}<button class="btn-del" on:click={() => deleteRule(editRule.id)}>Delete</button>{/if}
      </div>
    {:else}
      <div class="editor-empty">
        <div class="ee-icon">🎯</div>
        <div class="ee-title">Intercept Rules</div>
        <div class="ee-desc">Create rules to intercept, mock, modify, or breakpoint live HTTP traffic</div>
      </div>
    {/if}
  </div>
</div>

<style>
  .page { display: flex; height: 100%; }

  .rules-list {
    width: 280px; flex-shrink: 0; display: flex; flex-direction: column;
    background: var(--bg-header, #0d0d12); border-right: 1px solid var(--border, #1e1e24);
  }
  .list-top {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 12px; border-bottom: 1px solid var(--border, #1e1e24);
  }
  .list-top h2 { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1.5px; font-weight: 600; }
  .btn-add {
    padding: 3px 10px; font-size: 11px; border: 1px solid var(--accent, #38bdf8);
    background: transparent; color: var(--accent, #38bdf8); border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-add:hover { background: var(--accent-bg, #1e3a5f); }

  .bp-section { padding: 8px 12px; border-bottom: 1px solid var(--border, #1e1e24); background: rgba(251, 191, 36, 0.05); }
  .bp-title { font-size: 10px; color: var(--yellow, #fbbf24); font-weight: 600; margin-bottom: 6px; }
  .bp-item { margin-bottom: 6px; }
  .bp-info { font-size: 11px; color: var(--fg, #e4e4e7); margin-bottom: 4px; word-break: break-all; }
  .bp-actions { display: flex; gap: 4px; }
  .bp-btn { padding: 3px 8px; font-size: 10px; border-radius: 3px; cursor: pointer; font-family: inherit; border: none; }
  .bp-forward { background: #064e3b; color: var(--green, #34d399); }
  .bp-drop { background: #4c0519; color: var(--red, #f87171); }

  .list-body { flex: 1; overflow-y: auto; }
  .rule-item {
    display: flex; align-items: center; gap: 6px; width: 100%;
    padding: 8px 12px; border: none; border-bottom: 1px solid var(--border-subtle, #0f0f14);
    background: transparent; color: var(--fg, #e4e4e7); cursor: pointer;
    font-family: inherit; font-size: 12px; text-align: left;
  }
  .rule-item:hover { background: var(--bg-hover, #14141a); }
  .rule-item.selected { background: var(--bg-selected, #1a1a28); border-left: 2px solid var(--accent, #38bdf8); }
  .rule-status { width: 6px; height: 6px; border-radius: 50%; background: var(--fg-ghost, #3f3f46); flex-shrink: 0; }
  .rule-status.on { background: var(--green, #34d399); }
  .rule-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rule-type { font-size: 9px; color: var(--fg-faint, #52525b); }
  .rule-pri { font-size: 9px; color: var(--fg-ghost, #3f3f46); }
  .empty { padding: 20px; text-align: center; color: var(--fg-ghost, #3f3f46); font-size: 12px; }

  .rule-editor { flex: 1; overflow-y: auto; padding: 16px; }
  .editor-section { margin-bottom: 16px; }
  .editor-section h3 { font-size: 10px; color: var(--accent, #38bdf8); letter-spacing: 1px; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid var(--border, #1e1e24); }
  .field { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 6px; }
  .fl { font-size: 11px; color: var(--fg-dim, #71717a); min-width: 70px; padding-top: 5px; text-align: right; }
  .fl-check { font-size: 11px; color: var(--fg-muted, #a1a1aa); display: flex; align-items: center; gap: 4px; cursor: pointer; margin-left: 78px; }
  .fl-check input { accent-color: var(--accent, #38bdf8); }
  .fi {
    flex: 1; background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 5px;
    padding: 5px 8px; color: var(--fg, #e4e4e7); font-size: 12px; font-family: inherit; outline: none;
  }
  .fi:focus { border-color: var(--accent, #38bdf8); }
  .fi.num { max-width: 80px; }
  .fi.ta { min-height: 50px; resize: vertical; }
  select.fi { cursor: pointer; }

  .editor-actions { display: flex; gap: 8px; margin-top: 16px; }
  .btn-save {
    padding: 7px 20px; border: 1px solid #059669; background: #064e3b; color: var(--green, #34d399);
    border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 12px; font-weight: 600;
  }
  .btn-save:hover { background: #065f46; }
  .btn-del {
    padding: 7px 16px; border: 1px solid #dc2626; background: transparent; color: var(--red, #f87171);
    border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 12px;
  }
  .btn-del:hover { background: #4c0519; }

  .editor-empty { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; }
  .ee-icon { font-size: 40px; opacity: 0.5; }
  .ee-title { font-size: 16px; color: var(--fg, #e4e4e7); font-weight: 600; }
  .ee-desc { font-size: 12px; color: var(--fg-dim, #71717a); text-align: center; }
</style>
