<script>
  import { onMount, onDestroy, tick } from 'svelte'

  let tabs = []
  let activeTabId = null
  let tabCounter = 0

  function addTab() {
    tabCounter++
    const id = `term-${tabCounter}`
    tabs = [...tabs, { id, label: `sh-${tabCounter}`, lines: [], input: '', ws: null }]
    activeTabId = id
    initShell(id)
  }

  function closeTab(id) {
    const tab = tabs.find(t => t.id === id)
    if (tab && tab.ws) tab.ws.close()
    tabs = tabs.filter(t => t.id !== id)
    if (activeTabId === id) {
      activeTabId = tabs.length > 0 ? tabs[tabs.length - 1].id : null
    }
  }

  function getTab(id) {
    return tabs.find(t => t.id === id)
  }

  async function initShell(id) {
    // In Wails, we can't directly use PTY from frontend.
    // Instead, shell commands are sent to Go backend and output returned.
    // For now, implement a simple command executor.
    const tab = getTab(id)
    if (tab) {
      tab.lines = [{ text: 'cap terminal ready. Type commands below.', type: 'system' }]
      tabs = tabs
    }
  }

  async function handleKeydown(event, tabId) {
    if (event.key !== 'Enter') return
    const tab = getTab(tabId)
    if (!tab || !tab.input.trim()) return

    const cmd = tab.input.trim()
    tab.input = ''
    tab.lines = [...tab.lines, { text: `$ ${cmd}`, type: 'input' }]
    tabs = tabs

    try {
      // Use Wails runtime to execute command
      const result = await window.go.wailsgui.App.ExecCommand(cmd)
      if (result) {
        tab.lines = [...tab.lines, { text: result, type: 'output' }]
      }
    } catch(e) {
      tab.lines = [...tab.lines, { text: `error: ${e}`, type: 'error' }]
    }
    tabs = tabs

    await tick()
    const el = document.querySelector('.terminal-output.active')
    if (el) el.scrollTop = el.scrollHeight
  }

  onMount(() => addTab())
</script>

<div class="page">
  <div class="tab-bar">
    {#each tabs as tab}
      <button class="tab-item" class:tab-active={tab.id === activeTabId} on:click={() => activeTabId = tab.id}>
        {tab.label}
        <span class="tab-close" on:click|stopPropagation={() => closeTab(tab.id)}>×</span>
      </button>
    {/each}
    <button class="tab-add" on:click={addTab}>+</button>
  </div>

  {#each tabs as tab}
    <div class="terminal-container" class:hidden={tab.id !== activeTabId}>
      <div class="terminal-output" class:active={tab.id === activeTabId}>
        {#each tab.lines as line}
          <div class="term-line {line.type}">{line.text}</div>
        {/each}
      </div>
      <div class="terminal-input-row">
        <span class="prompt">cap$</span>
        <input
          type="text"
          class="terminal-input"
          bind:value={tab.input}
          on:keydown={(e) => handleKeydown(e, tab.id)}
          placeholder="type command..."
        />
      </div>
    </div>
  {/each}
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; background: #0a0a0f; }

  .tab-bar {
    display: flex; background: #111116; border-bottom: 1px solid #1e1e24;
    padding: 0 8px; align-items: stretch;
  }
  .tab-item {
    padding: 8px 14px; font-size: 12px; border: none;
    background: transparent; color: #71717a; cursor: pointer;
    font-family: inherit; display: flex; align-items: center; gap: 6px;
    border-bottom: 2px solid transparent; transition: all 0.1s;
  }
  .tab-item:hover { color: #a1a1aa; }
  .tab-active { color: #34d399; border-bottom-color: #34d399; }
  .tab-close {
    font-size: 14px; color: #52525b; width: 16px; height: 16px;
    display: flex; align-items: center; justify-content: center;
    border-radius: 3px;
  }
  .tab-close:hover { background: #27272a; color: #f87171; }
  .tab-add {
    padding: 8px 12px; font-size: 16px; border: none;
    background: transparent; color: #3f3f46; cursor: pointer; font-family: inherit;
  }
  .tab-add:hover { color: #34d399; }

  .terminal-container {
    flex: 1; display: flex; flex-direction: column; min-height: 0;
  }
  .terminal-container.hidden { display: none; }

  .terminal-output {
    flex: 1; overflow-y: auto; padding: 12px 16px;
    font-size: 13px; line-height: 1.7;
  }
  .term-line { white-space: pre-wrap; word-break: break-all; }
  .term-line.system { color: #3f3f46; font-style: italic; }
  .term-line.input { color: #34d399; }
  .term-line.output { color: #a1a1aa; }
  .term-line.error { color: #f87171; }

  .terminal-input-row {
    display: flex; align-items: center;
    padding: 8px 16px; background: #111116;
    border-top: 1px solid #1e1e24;
  }
  .prompt { color: #34d399; font-size: 13px; margin-right: 8px; font-weight: 600; }
  .terminal-input {
    flex: 1; background: transparent; border: none; color: #e4e4e7;
    font-size: 13px; font-family: inherit; outline: none;
    caret-color: #34d399;
  }
</style>
