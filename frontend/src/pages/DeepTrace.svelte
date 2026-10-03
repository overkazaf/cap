<script>
  import { onMount } from 'svelte'

  let flows = []
  let selectedFlowId = ''
  let packageName = ''
  let tracing = false
  let result = null
  let activeView = 'graph'
  let traceLog = []
  let traceStartTime = 0

  async function loadFlows() {
    try { flows = await window.go.wailsgui.App.GetFlows('', '', '', 100) || [] } catch(e) {}
  }

  function tlog(msg) {
    const elapsed = ((Date.now() - traceStartTime) / 1000).toFixed(1)
    traceLog = [...traceLog, `[${elapsed}s] ${msg}`]
  }

  async function runTrace() {
    if (!selectedFlowId || !packageName.trim()) return
    tracing = true
    result = null
    traceLog = []
    traceStartTime = Date.now()
    activeView = 'steps'

    tlog('Starting Deep Trace...')
    tlog(`Flow: ${selectedFlowId}`)
    tlog(`Package: ${packageName.trim()}`)
    tlog('Pulling APK from device...')

    try {
      result = await window.go.wailsgui.App.DeepTrace(selectedFlowId, packageName.trim())

      // Show steps from result
      if (result.steps) {
        for (const s of result.steps) {
          const icon = s.status === 'ok' ? '✓' : s.status === 'skip' ? '⊘' : '✗'
          tlog(`${icon} ${s.name}: ${s.detail} (${s.duration_ms}ms)`)
        }
      }

      // Summary
      const dex = result.dex_strings?.length || 0
      const java = result.java_trace?.length || 0
      const native = result.native_trace?.length || 0
      const edges = result.call_graph?.length || 0
      tlog(`Done: ${dex} DEX matches, ${java} Java refs, ${native} native refs, ${edges} call edges`)
      tlog(`Tools: ${(result.tools_used || []).join(', ') || 'pure Go'}`)

      if (edges > 0) activeView = 'graph'
      else if (dex > 0) activeView = 'dex'
      else if (java > 0) activeView = 'java'
    } catch(e) {
      tlog(`ERROR: ${e}`)
      result = { summary: `Error: ${e}`, steps: [], dex_strings: [], java_trace: [], native_trace: [], call_graph: [], mermaid: '' }
    }
    tracing = false
  }

  function copyText(text) { navigator.clipboard.writeText(text) }

  onMount(loadFlows)
</script>

<div class="page">
  <div class="trace-header">
    <h1>DEEP TRACE</h1>
    <div class="trace-config">
      <div class="config-row">
        <span class="cfg-label">Flow</span>
        <select bind:value={selectedFlowId} class="cfg-input">
          <option value="">Select a flow...</option>
          {#each flows as f}
            <option value={f.id}>{f.id} — {f.method} {f.host}{f.path}</option>
          {/each}
        </select>
      </div>
      <div class="config-row">
        <span class="cfg-label">Package</span>
        <input type="text" bind:value={packageName} class="cfg-input" placeholder="com.example.app" />
      </div>
      <button class="trace-btn" on:click={runTrace} disabled={tracing || !selectedFlowId || !packageName.trim()}>
        {tracing ? '⏳ Tracing...' : '🔍 Trace'}
      </button>
    </div>
  </div>

  {#if tracing}
    <div class="trace-progress">
      <div class="progress-header">
        <span class="progress-spinner">⏳</span>
        <span>Analyzing {packageName}...</span>
      </div>
      <div class="progress-log">
        {#each traceLog as line}<div class="progress-line">{line}</div>{/each}
      </div>
    </div>
  {/if}

  {#if result}
    <div class="trace-tabs">
      {#each [
        {id:'steps',label:'Steps'},
        {id:'dex',label:`DEX (${result.dex_strings?.length || 0})`},
        {id:'graph',label:`Graph (${result.call_graph?.length || 0})`},
        {id:'java',label:`Java (${result.java_trace?.length || 0})`},
        {id:'native',label:`Native (${result.native_trace?.length || 0})`},
        {id:'summary',label:'Summary'},
        {id:'mermaid',label:'Mermaid'}
      ] as tab}
        <button class="tab" class:tab-active={activeView === tab.id} on:click={() => activeView = tab.id}>{tab.label}</button>
      {/each}
    </div>

    <div class="trace-content">
      {#if activeView === 'steps'}
        <div class="steps-view">
          {#each traceLog as line}
            <div class="step-line" class:step-ok={line.includes('✓')} class:step-skip={line.includes('⊘')} class:step-err={line.includes('✗') || line.includes('ERROR')}>{line}</div>
          {/each}
          {#if result.apk_info}
            <div class="apk-card">
              <div class="apk-title">📦 {result.apk_info.package || result.package}</div>
              <div class="apk-meta">SDK {result.apk_info.min_sdk}–{result.apk_info.target_sdk} · {result.apk_info.dex_count} DEX · {result.apk_info.so_files?.length || 0} SO</div>
              {#if result.apk_info.so_files?.length > 0}
                <div class="apk-so">{result.apk_info.so_files.join(', ')}</div>
              {/if}
              {#if result.apk_info.has_ns_config}
                <div class="apk-ns">⚠ network_security_config.xml detected</div>
              {/if}
            </div>
          {/if}
        </div>

      {:else if activeView === 'dex'}
        <div class="dex-view">
          {#each result.dex_strings || [] as dm}
            <div class="dex-match">
              <div class="dex-string">{dm.string}</div>
              <div class="dex-meta">{dm.dex_file} @ offset {dm.offset}</div>
              {#if dm.context?.length > 0}
                <div class="dex-context">
                  {#each dm.context.slice(0, 5) as ctx}<span class="dex-ctx">{ctx}</span>{/each}
                </div>
              {/if}
            </div>
          {/each}
          {#if !result.dex_strings?.length}
            <div class="empty">No DEX string matches found.</div>
          {/if}
        </div>

      {:else if activeView === 'graph'}
        <div class="graph-view">
          {#each result.call_graph || [] as edge}
            <div class="edge-row">
              <span class="edge-from">{edge.from}</span>
              <span class="edge-arrow" class:arrow-jni={edge.type === 'jni'} class:arrow-native={edge.type === 'native_call'} class:arrow-http={edge.type === 'http'}>
                {edge.type === 'jni' ? '⟿ JNI' : edge.type === 'native_call' ? '⟹' : edge.type === 'http' ? '→ HTTP' : '→'}
              </span>
              <span class="edge-to">{edge.to}</span>
              {#if edge.label}<span class="edge-label">{edge.label}</span>{/if}
            </div>
          {/each}
          {#if !result.call_graph || result.call_graph.length === 0}
            <div class="empty">No call graph data. Make sure jadx and the APK are accessible.</div>
          {/if}
        </div>

      {:else if activeView === 'java'}
        <div class="java-view">
          {#each result.java_trace || [] as jr, i}
            <div class="java-ref">
              <div class="ref-header">
                <span class="ref-file">{jr.file}</span>
                <span class="ref-line">:{jr.line}</span>
                {#if jr.calls_native}<span class="ref-badge native">JNI</span>{/if}
                {#if jr.annotation}<span class="ref-badge retrofit">{jr.annotation}</span>{/if}
              </div>
              <div class="ref-class">{jr.class}{jr.method ? '.' + jr.method + '()' : ''}</div>
              <pre class="ref-snippet">{jr.snippet}</pre>
              {#if jr.native_methods && jr.native_methods.length > 0}
                <div class="ref-natives">
                  Native: {jr.native_methods.join(', ')}
                </div>
              {/if}
            </div>
          {/each}
          {#if !result.java_trace || result.java_trace.length === 0}
            <div class="empty">No Java source matches found.</div>
          {/if}
        </div>

      {:else if activeView === 'native'}
        <div class="native-view">
          {#each result.native_trace || [] as nr}
            <div class="native-ref">
              <div class="nr-header">
                <span class="nr-so">{nr.so_file}</span>
                <span class="nr-func">{nr.function}</span>
                {#if nr.address}<span class="nr-addr">{nr.address}</span>{/if}
              </div>
              {#if nr.calls && nr.calls.length > 0}
                <div class="nr-section">
                  <span class="nr-label">Calls:</span>
                  {#each nr.calls as c}<span class="nr-call">{c}</span>{/each}
                </div>
              {/if}
              {#if nr.strings && nr.strings.length > 0}
                <div class="nr-section">
                  <span class="nr-label">Strings:</span>
                  {#each nr.strings.slice(0, 10) as s}<div class="nr-string">{s}</div>{/each}
                </div>
              {/if}
            </div>
          {/each}
          {#if !result.native_trace || result.native_trace.length === 0}
            <div class="empty">No native analysis data. Install radare2 for SO analysis.</div>
          {/if}
        </div>

      {:else if activeView === 'summary'}
        <pre class="summary-text">{result.summary}</pre>

      {:else if activeView === 'mermaid'}
        <div class="mermaid-view">
          <div class="mermaid-toolbar">
            <button class="btn-copy" on:click={() => copyText(result.mermaid)}>📋 Copy Mermaid</button>
          </div>
          <pre class="mermaid-code">{result.mermaid}</pre>
        </div>
      {/if}
    </div>
  {:else if !tracing}
    <div class="trace-empty">
      <div class="empty-icon">🔬</div>
      <div class="empty-title">Deep Trace</div>
      <div class="empty-desc">Select a captured flow and target package to reverse-trace<br/>the call chain from HTTP request → Java → JNI → Native SO</div>
      <div class="empty-reqs">
        <div class="req">jadx — Java decompilation</div>
        <div class="req">r2 — Native binary analysis</div>
        <div class="req">unpack — APK unpacking (optional)</div>
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; }

  .trace-header {
    padding: 16px; background: var(--bg-panel, #111116);
    border-bottom: 1px solid var(--border, #1e1e24);
  }
  h1 { font-size: 13px; color: var(--accent, #38bdf8); letter-spacing: 2px; margin-bottom: 12px; }
  .trace-config { display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap; }
  .config-row { display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 200px; }
  .cfg-label { font-size: 10px; color: var(--fg-faint, #52525b); text-transform: uppercase; letter-spacing: 0.5px; }
  .cfg-input {
    background: var(--bg, #0a0a0f); border: 1px solid var(--border, #27272a); border-radius: 5px;
    padding: 6px 10px; color: var(--fg, #e4e4e7); font-size: 12px; font-family: inherit; outline: none;
  }
  .cfg-input:focus { border-color: var(--accent, #38bdf8); }
  .trace-btn {
    padding: 6px 20px; border: 1px solid var(--accent, #38bdf8);
    background: var(--accent-bg, #1e3a5f); color: var(--accent, #7dd3fc);
    border-radius: 5px; cursor: pointer; font-family: inherit; font-size: 12px; white-space: nowrap;
    height: 34px;
  }
  .trace-btn:hover { background: #1e4a6f; }
  .trace-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .trace-tabs {
    display: flex; background: var(--bg-header, #0d0d12);
    border-bottom: 1px solid var(--border, #1e1e24);
  }
  .tab {
    padding: 8px 16px; font-size: 11px; border: none; background: transparent;
    color: var(--fg-dim, #71717a); cursor: pointer; font-family: inherit;
    border-bottom: 2px solid transparent;
  }
  .tab:hover { color: var(--fg-muted, #a1a1aa); }
  .tab-active { color: var(--accent, #38bdf8); border-bottom-color: var(--accent, #38bdf8); }

  .trace-content { flex: 1; overflow-y: auto; padding: 12px 16px; }

  /* Call Graph */
  .edge-row { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border-subtle, #0f0f14); font-size: 12px; }
  .edge-from { color: var(--fg, #e4e4e7); font-weight: 500; min-width: 200px; word-break: break-all; }
  .edge-arrow { color: var(--fg-faint, #52525b); font-size: 11px; min-width: 60px; }
  .arrow-jni { color: var(--yellow, #fbbf24); }
  .arrow-native { color: var(--red, #f87171); }
  .arrow-http { color: var(--green, #34d399); }
  .edge-to { color: var(--accent, #38bdf8); word-break: break-all; }
  .edge-label { font-size: 10px; color: var(--fg-ghost, #3f3f46); margin-left: auto; }

  /* Java */
  .java-ref { margin-bottom: 12px; padding: 10px; background: var(--bg-panel, #111116); border-radius: 6px; border: 1px solid var(--border, #1e1e24); }
  .ref-header { display: flex; gap: 6px; align-items: center; margin-bottom: 4px; }
  .ref-file { color: var(--accent, #38bdf8); font-size: 12px; }
  .ref-line { color: var(--fg-faint, #52525b); font-size: 12px; }
  .ref-badge { padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: 600; }
  .ref-badge.native { background: rgba(251, 191, 36, 0.15); color: var(--yellow, #fbbf24); }
  .ref-badge.retrofit { background: rgba(52, 211, 153, 0.15); color: var(--green, #34d399); }
  .ref-class { font-size: 11px; color: var(--fg-muted, #a1a1aa); margin-bottom: 4px; }
  .ref-snippet { font-size: 11px; color: var(--fg, #e4e4e7); margin: 4px 0; padding: 6px; background: var(--bg, #0a0a0f); border-radius: 4px; overflow-x: auto; }
  .ref-natives { font-size: 10px; color: var(--yellow, #fbbf24); margin-top: 4px; }

  /* Native */
  .native-ref { margin-bottom: 12px; padding: 10px; background: var(--bg-panel, #111116); border-radius: 6px; border: 1px solid var(--border, #1e1e24); }
  .nr-header { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; }
  .nr-so { color: var(--red, #f87171); font-size: 12px; font-weight: 600; }
  .nr-func { color: var(--fg, #e4e4e7); font-size: 12px; }
  .nr-addr { color: var(--fg-faint, #52525b); font-size: 11px; font-family: 'SF Mono', monospace; }
  .nr-section { margin-top: 4px; font-size: 11px; }
  .nr-label { color: var(--fg-dim, #71717a); margin-right: 4px; }
  .nr-call { display: inline-block; padding: 1px 6px; background: rgba(56, 189, 248, 0.1); color: var(--accent, #38bdf8); border-radius: 3px; margin: 2px; font-size: 10px; }
  .nr-string { color: var(--fg-muted, #a1a1aa); font-family: 'SF Mono', monospace; font-size: 10px; }

  .summary-text { font-size: 12px; color: var(--fg-muted, #a1a1aa); white-space: pre-wrap; margin: 0; }

  .mermaid-toolbar { margin-bottom: 8px; }
  .btn-copy {
    padding: 4px 12px; font-size: 11px; border: 1px solid var(--border, #27272a);
    background: var(--bg-btn, #1a1a22); color: var(--fg-muted, #a1a1aa);
    border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .mermaid-code { font-size: 12px; color: var(--green, #34d399); margin: 0; white-space: pre-wrap; }

  .trace-progress {
    padding: 16px; background: var(--bg-panel, #111116);
    border-bottom: 1px solid var(--border, #1e1e24);
  }
  .progress-header { display: flex; gap: 8px; align-items: center; font-size: 13px; color: var(--fg, #e4e4e7); margin-bottom: 8px; }
  .progress-spinner { animation: spin 1s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .progress-log { max-height: 200px; overflow-y: auto; }
  .progress-line { font-size: 11px; color: var(--fg-muted, #a1a1aa); line-height: 1.6; font-family: 'SF Mono', monospace; }

  .steps-view { padding: 8px 16px; }
  .step-line { font-size: 11px; color: var(--fg-muted, #a1a1aa); line-height: 1.8; font-family: 'SF Mono', monospace; }
  .step-ok { color: var(--green, #34d399); }
  .step-skip { color: var(--fg-faint, #52525b); }
  .step-err { color: var(--red, #f87171); }

  .apk-card {
    margin-top: 12px; padding: 12px; background: var(--bg-panel, #111116);
    border: 1px solid var(--border, #1e1e24); border-radius: 8px;
  }
  .apk-title { font-size: 14px; font-weight: 600; color: var(--fg, #e4e4e7); }
  .apk-meta { font-size: 11px; color: var(--fg-dim, #71717a); margin-top: 4px; }
  .apk-so { font-size: 10px; color: var(--accent, #38bdf8); margin-top: 6px; font-family: 'SF Mono', monospace; word-break: break-all; }
  .apk-ns { font-size: 11px; color: var(--yellow, #fbbf24); margin-top: 4px; }

  .dex-view { padding: 8px 16px; }
  .dex-match { margin-bottom: 12px; padding: 10px; background: var(--bg-panel, #111116); border: 1px solid var(--border, #1e1e24); border-radius: 6px; }
  .dex-string { font-size: 13px; color: var(--green, #34d399); font-family: 'SF Mono', monospace; word-break: break-all; }
  .dex-meta { font-size: 10px; color: var(--fg-faint, #52525b); margin-top: 4px; }
  .dex-context { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }
  .dex-ctx { padding: 2px 6px; background: rgba(56, 189, 248, 0.1); color: var(--fg-muted, #a1a1aa); border-radius: 3px; font-size: 10px; font-family: 'SF Mono', monospace; }

  .empty { padding: 20px; text-align: center; color: var(--fg-ghost, #3f3f46); font-size: 12px; }

  .trace-empty {
    flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px;
  }
  .empty-icon { font-size: 48px; opacity: 0.5; }
  .empty-title { font-size: 18px; color: var(--fg, #e4e4e7); font-weight: 600; }
  .empty-desc { font-size: 13px; color: var(--fg-dim, #71717a); text-align: center; line-height: 1.6; }
  .empty-reqs { margin-top: 16px; }
  .req { font-size: 12px; color: var(--fg-faint, #52525b); padding: 3px 0; }
  .req::before { content: '▸ '; color: var(--accent, #38bdf8); }
</style>
