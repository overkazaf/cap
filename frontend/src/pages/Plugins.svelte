<script>
  import { onMount } from 'svelte'

  let plugins = []
  let selectedPlugin = null
  let editName = ''
  let editDesc = ''
  let editType = 'analyzer'
  let editCode = ''
  let isNew = false
  let runOutput = ''
  let runFlowId = ''

  async function loadPlugins() {
    try { plugins = await window.go.wailsgui.App.ListPlugins() || [] } catch(e) { console.error(e) }
  }

  async function selectPlugin(p) {
    selectedPlugin = p
    editName = p.name
    editDesc = p.description
    editType = p.type
    editCode = p.code
    isNew = false
    runOutput = ''
  }

  function newPlugin() {
    selectedPlugin = null
    editName = ''
    editDesc = ''
    editType = 'analyzer'
    editCode = `// New plugin
// Type: analyzer

function analyze(flow) {
  return {
    flow_id: flow.id,
    method: flow.method,
    url: flow.url,
    result: "your analysis here"
  };
}`
    isNew = true
    runOutput = ''
  }

  async function loadExample(idx) {
    try {
      const examples = await window.go.wailsgui.App.GetExamplePlugins()
      if (examples && examples[idx]) {
        editName = examples[idx].name
        editDesc = examples[idx].description
        editType = examples[idx].type
        editCode = examples[idx].code
        isNew = true
        runOutput = ''
      }
    } catch(e) { console.error(e) }
  }

  async function savePlugin() {
    if (!editName.trim()) { runOutput = 'Error: name required'; return }
    try {
      await window.go.wailsgui.App.SavePlugin({
        name: editName, description: editDesc, type: editType,
        code: editCode, enabled: true,
      })
      runOutput = `Saved: ${editName}`
      isNew = false
      loadPlugins()
    } catch(e) { runOutput = `Save error: ${e}` }
  }

  async function deletePlugin(name) {
    try {
      await window.go.wailsgui.App.DeletePlugin(name)
      selectedPlugin = null
      editCode = ''
      runOutput = ''
      loadPlugins()
    } catch(e) { runOutput = `Delete error: ${e}` }
  }

  async function togglePlugin(name) {
    try {
      await window.go.wailsgui.App.TogglePlugin(name)
      loadPlugins()
    } catch(e) { console.error(e) }
  }

  async function runPlugin() {
    if (!editName || !runFlowId.trim()) { runOutput = 'Enter a flow ID (e.g. f1)'; return }
    try {
      const result = await window.go.wailsgui.App.RunPlugin(editName, runFlowId.trim())
      runOutput = result.error ? `Error: ${result.error}` : result.output
    } catch(e) { runOutput = `Run error: ${e}` }
  }

  function copyCode() { navigator.clipboard.writeText(editCode) }

  onMount(loadPlugins)
</script>

<div class="page">
  <div class="sidebar-list">
    <div class="list-header">
      <h2>PLUGINS</h2>
      <button class="btn-new" on:click={newPlugin}>+ New</button>
    </div>
    <div class="examples">
      <span class="examples-label">Examples:</span>
      <button class="btn-ex" on:click={() => loadExample(0)}>log-requests</button>
      <button class="btn-ex" on:click={() => loadExample(1)}>detect-keys</button>
      <button class="btn-ex" on:click={() => loadExample(2)}>sign-validator</button>
    </div>
    <div class="plugin-list">
      {#each plugins as p}
        <button class="plugin-item" class:selected={selectedPlugin && selectedPlugin.name === p.name} on:click={() => selectPlugin(p)}>
          <span class="plugin-status" class:enabled={p.enabled}></span>
          <span class="plugin-name">{p.name}</span>
          <span class="plugin-type">{p.type}</span>
          <button class="btn-toggle" on:click|stopPropagation={() => togglePlugin(p.name)}>
            {p.enabled ? 'ON' : 'OFF'}
          </button>
        </button>
      {/each}
      {#if plugins.length === 0}
        <div class="empty">No plugins. Click "+ New" or load an example.</div>
      {/if}
    </div>
  </div>

  <div class="editor-panel">
    {#if editCode || isNew}
      <div class="editor-toolbar">
        <input class="edit-name" placeholder="Plugin name" bind:value={editName} />
        <input class="edit-desc" placeholder="Description" bind:value={editDesc} />
        <select class="edit-type" bind:value={editType}>
          <option value="request_filter">request_filter</option>
          <option value="response_modifier">response_modifier</option>
          <option value="analyzer">analyzer</option>
        </select>
        <div class="spacer"></div>
        <button class="btn-save" on:click={savePlugin}>Save</button>
        <button class="btn-icon" on:click={copyCode}>📋</button>
        {#if selectedPlugin}
          <button class="btn-delete" on:click={() => deletePlugin(editName)}>Delete</button>
        {/if}
      </div>

      <textarea class="code-editor" bind:value={editCode} spellcheck="false"></textarea>

      <div class="run-bar">
        <span class="run-label">TEST</span>
        <input class="run-flow" placeholder="Flow ID (e.g. f1)" bind:value={runFlowId} />
        <button class="btn-run" on:click={runPlugin}>▶ Run</button>
      </div>
      {#if runOutput}
        <pre class="run-output">{runOutput}</pre>
      {/if}
    {:else}
      <div class="empty-editor">
        <div class="empty-icon">🔌</div>
        <div>Select a plugin or create a new one</div>
      </div>
    {/if}
  </div>
</div>

<style>
  .page { display: flex; height: 100%; }

  .sidebar-list {
    width: 250px; border-right: 1px solid #1e1e24; display: flex;
    flex-direction: column; background: #0d0d12;
  }
  .list-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 12px; border-bottom: 1px solid #1e1e24;
  }
  .list-header h2 { font-size: 11px; color: #38bdf8; letter-spacing: 1.5px; }
  .btn-new {
    padding: 3px 10px; font-size: 11px; border: 1px solid #38bdf8;
    background: transparent; color: #38bdf8; border-radius: 4px;
    cursor: pointer; font-family: inherit;
  }
  .btn-new:hover { background: #1e3a5f; }

  .examples { padding: 6px 12px; border-bottom: 1px solid #1e1e24; display: flex; gap: 4px; flex-wrap: wrap; align-items: center; }
  .examples-label { font-size: 10px; color: #52525b; }
  .btn-ex {
    padding: 2px 6px; font-size: 10px; border: 1px solid #27272a;
    background: transparent; color: #71717a; border-radius: 3px; cursor: pointer; font-family: inherit;
  }
  .btn-ex:hover { background: #1a1a22; color: #a1a1aa; }

  .plugin-list { flex: 1; overflow-y: auto; }
  .plugin-item {
    display: flex; align-items: center; gap: 8px; width: 100%;
    padding: 8px 12px; border: none; border-bottom: 1px solid #0f0f14;
    background: transparent; color: #e4e4e7; cursor: pointer;
    font-family: inherit; font-size: 12px; text-align: left;
  }
  .plugin-item:hover { background: #14141a; }
  .plugin-item.selected { background: #1a1a28; border-left: 2px solid #38bdf8; }
  .plugin-status { width: 6px; height: 6px; border-radius: 50%; background: #3f3f46; flex-shrink: 0; }
  .plugin-status.enabled { background: #34d399; }
  .plugin-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .plugin-type { font-size: 10px; color: #52525b; }
  .btn-toggle {
    padding: 2px 6px; font-size: 9px; border: 1px solid #27272a;
    background: transparent; color: #71717a; border-radius: 3px; cursor: pointer; font-family: inherit;
  }

  .editor-panel { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .editor-toolbar {
    display: flex; gap: 6px; padding: 8px 12px;
    background: #0d0d12; border-bottom: 1px solid #1e1e24; align-items: center;
  }
  .edit-name {
    width: 140px; background: #0a0a0f; border: 1px solid #27272a; border-radius: 4px;
    padding: 4px 8px; color: #e4e4e7; font-size: 12px; font-family: inherit; outline: none;
  }
  .edit-desc { flex: 1; background: #0a0a0f; border: 1px solid #27272a; border-radius: 4px; padding: 4px 8px; color: #a1a1aa; font-size: 12px; font-family: inherit; outline: none; }
  .edit-type { background: #0a0a0f; border: 1px solid #27272a; border-radius: 4px; padding: 4px 8px; color: #a1a1aa; font-size: 11px; font-family: inherit; cursor: pointer; }
  .spacer { flex: 0; }
  .btn-save {
    padding: 4px 12px; font-size: 11px; border: 1px solid #059669;
    background: #064e3b; color: #34d399; border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-save:hover { background: #065f46; }
  .btn-delete {
    padding: 4px 10px; font-size: 11px; border: 1px solid #dc2626;
    background: transparent; color: #f87171; border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-delete:hover { background: #4c0519; }
  .btn-icon {
    background: transparent; border: none; cursor: pointer; font-size: 12px; color: #71717a; padding: 4px;
  }

  .code-editor {
    flex: 1; resize: none; border: none; outline: none;
    background: #0a0a0f; color: #e4e4e7;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 13px; line-height: 1.6; padding: 12px 16px;
    tab-size: 2;
  }

  .run-bar {
    display: flex; gap: 6px; padding: 6px 12px; align-items: center;
    background: #0d0d12; border-top: 1px solid #1e1e24;
  }
  .run-label { font-size: 10px; color: #52525b; letter-spacing: 0.5px; }
  .run-flow {
    width: 100px; background: #0a0a0f; border: 1px solid #27272a; border-radius: 4px;
    padding: 4px 8px; color: #e4e4e7; font-size: 12px; font-family: inherit; outline: none;
  }
  .btn-run {
    padding: 4px 12px; font-size: 11px; border: 1px solid #38bdf8;
    background: #1e3a5f; color: #7dd3fc; border-radius: 4px; cursor: pointer; font-family: inherit;
  }
  .btn-run:hover { background: #1e4a6f; }

  .run-output {
    max-height: 150px; overflow-y: auto; padding: 8px 12px;
    font-size: 12px; color: #a1a1aa; margin: 0; white-space: pre-wrap;
    border-top: 1px solid #1e1e24; background: #0a0a0f;
  }

  .empty { padding: 20px; text-align: center; color: #3f3f46; font-size: 12px; }
  .empty-editor {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: #3f3f46; font-size: 14px; gap: 8px;
  }
  .empty-icon { font-size: 32px; opacity: 0.5; }
</style>
