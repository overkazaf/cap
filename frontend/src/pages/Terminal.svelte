<script>
  import { onMount, tick } from 'svelte'

  let tabs = []
  let activeTabId = null
  let tabCounter = 0

  function addTab() {
    tabCounter++
    const id = `term-${tabCounter}`
    tabs = [...tabs, {
      id,
      label: `sh-${tabCounter}`,
      content: '$ ',
      cursorPos: 2,
      inputStart: 2,
      history: [],
      histIdx: -1,
    }]
    activeTabId = id
    focusTerminal()
  }

  function closeTab(id) {
    tabs = tabs.filter(t => t.id !== id)
    if (activeTabId === id) {
      activeTabId = tabs.length > 0 ? tabs[tabs.length - 1].id : null
    }
  }

  function getTab(id) {
    return tabs.find(t => t.id === id)
  }

  async function focusTerminal() {
    await tick()
    const el = document.querySelector('.term-area.active')
    if (el) { el.focus(); el.scrollTop = el.scrollHeight }
  }

  async function handleKeydown(event, tabId) {
    const tab = getTab(tabId)
    if (!tab) return

    // Ctrl+L to clear
    if (event.key === 'l' && (event.ctrlKey || event.metaKey)) {
      event.preventDefault()
      tab.content = '$ '
      tab.inputStart = 2
      tabs = tabs
      return
    }

    if (event.key === 'Enter') {
      event.preventDefault()
      const input = tab.content.slice(tab.inputStart).trim()

      if (input) {
        tab.history = [...tab.history, input]
        tab.histIdx = -1
      }

      tab.content += '\n'

      if (input === 'clear' || input === 'cls') {
        tab.content = ''
      } else if (input) {
        try {
          const result = await window.go.wailsgui.App.ExecCommand(input)
          if (result) tab.content += result + '\n'
        } catch(e) {
          tab.content += `error: ${e}\n`
        }
      }

      tab.content += '$ '
      tab.inputStart = tab.content.length
      tabs = tabs
      await tick()
      const el = document.querySelector('.term-area.active')
      if (el) { el.scrollTop = el.scrollHeight; el.setSelectionRange(tab.content.length, tab.content.length) }
      return
    }

    if (event.key === 'ArrowUp') {
      event.preventDefault()
      if (tab.history.length > 0) {
        if (tab.histIdx < 0) tab.histIdx = tab.history.length
        tab.histIdx = Math.max(0, tab.histIdx - 1)
        tab.content = tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        tabs = tabs
      }
      return
    }

    if (event.key === 'ArrowDown') {
      event.preventDefault()
      if (tab.histIdx >= 0) {
        tab.histIdx++
        if (tab.histIdx >= tab.history.length) {
          tab.histIdx = -1
          tab.content = tab.content.slice(0, tab.inputStart)
        } else {
          tab.content = tab.content.slice(0, tab.inputStart) + tab.history[tab.histIdx]
        }
        tabs = tabs
      }
      return
    }

    // Prevent editing before the prompt
    const el = event.target
    if (el.selectionStart < tab.inputStart && (event.key === 'Backspace' || event.key.length === 1)) {
      event.preventDefault()
      el.setSelectionRange(tab.content.length, tab.content.length)
    }
  }

  function handleInput(event, tabId) {
    const tab = getTab(tabId)
    if (!tab) return
    const el = event.target
    if (el.value.length < tab.inputStart) {
      el.value = tab.content
      el.setSelectionRange(tab.content.length, tab.content.length)
    } else {
      tab.content = el.value
    }
    tabs = tabs
  }

  onMount(() => addTab())
</script>

<div class="page">
  <div class="tab-bar">
    {#each tabs as tab}
      <button class="tab-item" class:tab-active={tab.id === activeTabId} on:click={() => { activeTabId = tab.id; focusTerminal() }}>
        {tab.label}
        <button class="tab-close" on:click|stopPropagation={() => closeTab(tab.id)}>×</button>
      </button>
    {/each}
    <button class="tab-add" on:click={addTab}>+ New</button>
  </div>

  {#each tabs as tab}
    <div class="terminal-container" class:hidden={tab.id !== activeTabId}>
      <textarea
        class="term-area" class:active={tab.id === activeTabId}
        bind:value={tab.content}
        on:keydown={(e) => handleKeydown(e, tab.id)}
        on:input={(e) => handleInput(e, tab.id)}
        spellcheck="false"
        autocomplete="off"
      ></textarea>
    </div>
  {/each}
</div>

<style>
  .page { display: flex; flex-direction: column; height: 100%; background: var(--bg, #0a0a0f); }

  .tab-bar {
    display: flex; background: var(--bg-panel, #111116); border-bottom: 1px solid var(--border, #1e1e24);
    padding: 0 8px; align-items: stretch;
  }
  .tab-item {
    padding: 8px 12px; font-size: 12px; border: none;
    background: transparent; color: var(--fg-dim, #71717a); cursor: pointer;
    font-family: inherit; display: flex; align-items: center; gap: 6px;
    border-bottom: 2px solid transparent; transition: all 0.1s;
  }
  .tab-item:hover { color: var(--fg-muted, #a1a1aa); }
  .tab-active { color: var(--green, #34d399); border-bottom-color: var(--green, #34d399); }
  .tab-close {
    font-size: 14px; color: var(--fg-faint, #52525b); background: transparent; border: none;
    cursor: pointer; width: 16px; height: 16px; padding: 0;
    display: flex; align-items: center; justify-content: center; border-radius: 3px;
  }
  .tab-close:hover { background: var(--bg-btn, #27272a); color: var(--red, #f87171); }
  .tab-add {
    padding: 8px 12px; font-size: 12px; border: none;
    background: transparent; color: var(--fg-ghost, #3f3f46); cursor: pointer; font-family: inherit;
  }
  .tab-add:hover { color: var(--green, #34d399); }

  .terminal-container { flex: 1; display: flex; min-height: 0; }
  .terminal-container.hidden { display: none; }

  .term-area {
    flex: 1; width: 100%; resize: none; border: none; outline: none;
    background: var(--bg, #0a0a0f); color: var(--green, #34d399);
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 13px; line-height: 1.6; padding: 12px 16px;
    caret-color: var(--green, #34d399);
  }
  .term-area::selection { background: rgba(52, 211, 153, 0.2); }
</style>
