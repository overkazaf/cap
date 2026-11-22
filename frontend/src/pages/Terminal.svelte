<script>
  import { onMount, onDestroy, tick } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate } from '../lib/i18n.js'
  import { MOD_LABEL } from '../lib/shortcuts.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Kbd from '../components/Kbd.svelte'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration, formatTime } from '../lib/format.js'

  const api = () => window?.go?.wailsgui?.App

  let tabs = []
  let activeTabId = null
  let tabCounter = 0
  let blockCounter = 0
  let showPresets = true
  let wordWrap = true

  let promptEl
  let viewportEl

  const presetSpecs = [
    { key: 'adbDevices', cmd: 'adb devices -l', icon: 'smartphone' },
    { key: 'reToolchain', cmd: 'which adb jadx r2 frida 2>&1 || true', icon: 'cpu' },
    { key: 'port8080', cmd: 'lsof -nP -iTCP:8080 -sTCP:LISTEN || echo "Port 8080 free"', icon: 'radio' },
    { key: 'localIps', cmd: 'ifconfig | grep "inet " | grep -v 127.0.0.1', icon: 'wifi' },
    { key: 'capFiles', cmd: 'ls -lh ~/.cap', icon: 'folder' },
    { key: 'workingDir', cmd: 'pwd', icon: 'terminal' },
  ]

  $: activeTab = tabs.find((tItem) => tItem.id === activeTabId) || null
  $: presets = presetSpecs.map((p) => ({ ...p, label: $t(`tools.terminal.presets.${p.key}`) }))

  function addTab() {
    tabCounter++
    const id = `term-${tabCounter}`
    tabs = [
      ...tabs,
      {
        id,
        label: `sh-${tabCounter}`,
        input: '',
        running: false,
        blocks: [],
        history: [],
        histIdx: -1,
        draftInput: '',
      },
    ]
    activeTabId = id
    focusPrompt()
  }

  function closeTab(id) {
    if (tabs.length <= 1) {
      clearActiveSession()
      return
    }
    const idx = tabs.findIndex((tItem) => tItem.id === id)
    tabs = tabs.filter((tItem) => tItem.id !== id)
    if (activeTabId === id) {
      const nextIdx = Math.max(0, Math.min(idx, tabs.length - 1))
      activeTabId = tabs[nextIdx]?.id || null
    }
    focusPrompt()
  }

  async function focusPrompt() {
    await tick()
    promptEl?.focus()
  }

  async function scrollToBottom() {
    await tick()
    if (viewportEl) {
      viewportEl.scrollTop = viewportEl.scrollHeight
    }
  }

  function looksLikeError(output) {
    if (!output) return false
    const lower = output.toLowerCase()
    return (
      lower.startsWith('error:') ||
      lower.includes('command not found') ||
      lower.includes('exit status ') ||
      lower.includes('permission denied') ||
      lower.includes('no such file or directory')
    )
  }

  function clearActiveSession() {
    if (!activeTab) return
    activeTab.blocks = []
    tabs = tabs
    focusPrompt()
  }

  async function executeCommand(rawCmd, targetTabId = activeTabId) {
    const tab = tabs.find((tItem) => tItem.id === targetTabId)
    if (!tab) return
    const cmd = String(rawCmd || '').trim()
    if (!cmd) return

    if (tab.history[tab.history.length - 1] !== cmd) {
      tab.history = [...tab.history, cmd]
    }
    tab.histIdx = -1
    tab.draftInput = ''
    tab.input = ''

    if (cmd === 'clear' || cmd === 'cls') {
      tab.blocks = []
      tabs = tabs
      focusPrompt()
      return
    }

    const blockId = ++blockCounter
    const block = {
      id: blockId,
      cmd,
      timestamp: Date.now(),
      durationMs: null,
      status: 'running',
      output: '',
    }
    tab.blocks = [...tab.blocks, block]
    tab.running = true
    tabs = tabs
    await scrollToBottom()

    const app = api()
    const t0 = performance.now()

    try {
      if (!app?.ExecCommand) {
        throw new Error(translate('tools.terminal.backendUnavailable'))
      }
      const res = await app.ExecCommand(cmd)
      const out = String(res ?? '').replace(/\n+$/, '')
      block.output = out
      block.durationMs = Math.round(performance.now() - t0)
      block.status = looksLikeError(out) ? 'error' : 'ok'
    } catch (e) {
      block.output = `error: ${e?.message || e}`
      block.durationMs = Math.round(performance.now() - t0)
      block.status = 'error'
    } finally {
      tab.running = false
      tabs = tabs
      await scrollToBottom()
      focusPrompt()
    }
  }

  function handlePromptKeydown(e) {
    if (!activeTab) return

    if (e.key === 'l' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      clearActiveSession()
      return
    }

    if (e.key === 'Enter') {
      e.preventDefault()
      if (!activeTab.running) {
        executeCommand(activeTab.input, activeTab.id)
      }
      return
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (activeTab.history.length === 0) return
      if (activeTab.histIdx === -1) {
        activeTab.draftInput = activeTab.input
        activeTab.histIdx = activeTab.history.length - 1
      } else {
        activeTab.histIdx = Math.max(0, activeTab.histIdx - 1)
      }
      activeTab.input = activeTab.history[activeTab.histIdx]
      tabs = tabs
      return
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (activeTab.histIdx === -1) return
      activeTab.histIdx++
      if (activeTab.histIdx >= activeTab.history.length) {
        activeTab.histIdx = -1
        activeTab.input = activeTab.draftInput || ''
      } else {
        activeTab.input = activeTab.history[activeTab.histIdx]
      }
      tabs = tabs
      return
    }
  }

  function runPreset(preset, event) {
    if (!activeTab) return
    if (event.shiftKey) {
      activeTab.input = preset.cmd
      tabs = tabs
      focusPrompt()
      return
    }
    if (!activeTab.running) {
      executeCommand(preset.cmd, activeTab.id)
    }
  }

  function copySessionTranscript() {
    if (!activeTab || activeTab.blocks.length === 0) {
      toast.info(translate('tools.terminal.toast.nothingToCopy'))
      return
    }
    const text = activeTab.blocks
      .map((b) => `$ ${b.cmd}${b.output ? '\n' + b.output : ''}`)
      .join('\n\n')
    copyToClipboard(text, translate('tools.terminal.toast.transcriptCopied'))
  }

  function handleViewportClick() {
    const sel = window.getSelection?.()
    if (sel && String(sel).length > 0) return
    focusPrompt()
  }

  function handleGlobalKey(e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 't') {
      e.preventDefault()
      addTab()
      return
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'w') {
      e.preventDefault()
      if (activeTabId) closeTab(activeTabId)
      return
    }
    if (e.ctrlKey && e.key === 'Tab') {
      e.preventDefault()
      const idx = tabs.findIndex((tItem) => tItem.id === activeTabId)
      if (idx >= 0 && tabs.length > 1) {
        const next = (idx + (e.shiftKey ? tabs.length - 1 : 1)) % tabs.length
        activeTabId = tabs[next].id
        focusPrompt()
      }
    }
  }

  onMount(() => {
    addTab()
    window.addEventListener('keydown', handleGlobalKey)
  })

  onDestroy(() => {
    window.removeEventListener('keydown', handleGlobalKey)
  })
</script>

<div class="terminal-page">
  <!-- Session Tab Bar & Controls -->
  <div class="term-chrome">
    <div class="tabs-strip" role="tablist">
      {#each tabs as tab (tab.id)}
        <div class="tab-pill" class:active={tab.id === activeTabId}>
          <button
            type="button"
            role="tab"
            aria-selected={tab.id === activeTabId}
            class="tab-select"
            on:click={() => {
              activeTabId = tab.id
              focusPrompt()
            }}
          >
            <Icon name="terminal" size={12} />
            <span class="mono">{tab.label}</span>
            {#if tab.running}
              <span class="tab-running-dot"></span>
            {/if}
          </button>
          <button
            type="button"
            class="tab-close"
            title={tabs.length > 1 ? $t('tools.terminal.closeSessionTitle') : $t('tools.terminal.clearSessionTitle')}
            on:click={() => closeTab(tab.id)}
          >
            <Icon name="x" size={11} />
          </button>
        </div>
      {/each}

      <button type="button" class="tab-add" on:click={addTab} title={$t('tools.terminal.newTabTitle', { mod: MOD_LABEL })}>
        <Icon name="plus" size={13} />
        <span>{$t('tools.terminal.newTab')}</span>
      </button>
    </div>

    <div class="chrome-actions">
      <Button
        variant="ghost"
        size="xs"
        icon="sparkles"
        active={showPresets}
        title={$t('tools.terminal.presetsToggleTitle')}
        on:click={() => (showPresets = !showPresets)}
      >
        {$t('tools.terminal.presetsBtn')}
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon="rows"
        active={wordWrap}
        title={$t('tools.terminal.wrapToggleTitle')}
        on:click={() => (wordWrap = !wordWrap)}
      >
        {$t('tools.terminal.wrapBtn')}
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon="copy"
        disabled={!activeTab?.blocks?.length}
        title={$t('tools.terminal.copyAllTitle')}
        on:click={copySessionTranscript}
      >
        {$t('tools.terminal.copyAll')}
      </Button>
      <Button
        variant="ghost"
        size="xs"
        icon="trash"
        disabled={!activeTab?.blocks?.length}
        title={$t('tools.terminal.clearTitle')}
        on:click={clearActiveSession}
      >
        {$t('tools.terminal.clearBtn')}
      </Button>
    </div>
  </div>

  <!-- Quick Command Presets Strip -->
  {#if showPresets}
    <div class="presets-bar">
      <span class="presets-label">{$t('tools.terminal.quickCommands')}</span>
      <div class="presets-list">
        {#each presets as p}
          <button
            type="button"
            class="preset-chip"
            title={$t('tools.terminal.presetTooltip', { cmd: p.cmd })}
            disabled={activeTab?.running}
            on:click={(e) => runPreset(p, e)}
          >
            <Icon name={p.icon} size={11} />
            <span>{p.label}</span>
          </button>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Console Surface (Always sleek dark terminal canvas) -->
  <!-- svelte-ignore a11y-click-events-have-key-events -->
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="console-surface" bind:this={viewportEl} on:click={handleViewportClick}>
    {#if activeTab && activeTab.blocks.length === 0}
      <div class="welcome-banner">
        <div class="welcome-head">
          <span class="welcome-icon"><Icon name="terminal" size={16} /></span>
          <div>
            <div class="welcome-title">{$t('tools.terminal.welcomeTitle')}</div>
            <div class="welcome-sub">{$t('tools.terminal.welcomeSub')}</div>
          </div>
        </div>
        <div class="welcome-hints">
          <span class="hint-item"><Kbd keys={['↑', '↓']} size="xs" /> {$t('tools.terminal.hintHistory')}</span>
          <span class="hint-item"><Kbd keys={['Ctrl', 'L']} size="xs" /> {$t('tools.terminal.hintClear')}</span>
          <span class="hint-item"><Kbd keys={['Mod', 'T']} size="xs" /> {$t('tools.terminal.hintNewTab')}</span>
          <span class="hint-item"><Kbd keys={['Shift']} size="xs" /> {$t('tools.terminal.hintShiftPreset')}</span>
        </div>
      </div>
    {/if}

    {#if activeTab}
      <div class="blocks-list">
        {#each activeTab.blocks as block (block.id)}
          <article class="cmd-block status-{block.status}">
            <div class="block-header">
              <div class="block-cmd mono">
                <span class="prompt-glyph">$</span>
                <span class="cmd-text">{block.cmd}</span>
              </div>
              <div class="block-meta">
                <span class="block-time mono tabular-nums">{formatTime(block.timestamp)}</span>
                {#if block.status === 'running'}
                  <Badge variant="accent" size="xs" dot pulse>{$t('tools.terminal.runningBadge')}</Badge>
                {:else if block.status === 'error'}
                  <Badge variant="danger" size="xs" mono>{$t('tools.terminal.statusErr')} · {formatDuration(block.durationMs)}</Badge>
                {:else}
                  <Badge variant="success" size="xs" mono>{$t('tools.terminal.statusOk')} · {formatDuration(block.durationMs)}</Badge>
                {/if}
                <div class="block-actions">
                  <button
                    type="button"
                    class="blk-btn"
                    title={$t('tools.terminal.rerunTitle')}
                    disabled={activeTab.running}
                    on:click|stopPropagation={() => executeCommand(block.cmd, activeTab.id)}
                  >
                    <Icon name="repeat" size={12} />
                  </button>
                  <button
                    type="button"
                    class="blk-btn"
                    title={$t('tools.terminal.copyBlockTitle')}
                    on:click|stopPropagation={() =>
                      copyToClipboard(block.output || block.cmd, translate('tools.terminal.toast.blockCopied'))}
                  >
                    <Icon name="copy" size={12} />
                  </button>
                </div>
              </div>
            </div>

            {#if block.status === 'running'}
              <div class="block-running mono">
                <span class="spin-dot"></span>
                <span>{$t('tools.terminal.executing')}</span>
              </div>
            {:else if block.output}
              <pre class="block-output mono" class:wrap={wordWrap} class:is-err={block.status === 'error'}>{block.output}</pre>
            {:else}
              <div class="block-empty mono">{$t('tools.terminal.noOutput')}</div>
            {/if}
          </article>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Bottom Prompt Bar -->
  {#if activeTab}
    <div class="prompt-bar">
      <div class="prompt-prefix mono">
        <span class="prefix-tag">{activeTab.label}</span>
        <span class="prefix-dollar">$</span>
      </div>
      <input
        bind:this={promptEl}
        type="text"
        class="prompt-input mono"
        bind:value={activeTab.input}
        disabled={activeTab.running}
        on:keydown={handlePromptKeydown}
        placeholder={$t('tools.terminal.promptPlaceholder')}
        spellcheck="false"
        autocomplete="off"
      />
      <div class="prompt-right">
        {#if activeTab.history.length > 0}
          <span class="hist-count mono tabular-nums" title={$t('tools.terminal.historyTooltip')}>
            {$t('tools.terminal.historyCount', { count: activeTab.history.length })}
          </span>
        {/if}
        <Button
          variant="primary"
          size="xs"
          icon="play"
          loading={activeTab.running}
          disabled={!activeTab.input.trim() || activeTab.running}
          on:click={() => executeCommand(activeTab.input, activeTab.id)}
        >
          {$t('tools.terminal.run')}
        </Button>
      </div>
    </div>
  {/if}
</div>

<style>
  .terminal-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--terminal-bg);
    color: #e2e8f0;
  }

  /* Tab Bar Chrome */
  .term-chrome {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 0 10px;
    height: 36px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .tabs-strip {
    display: flex;
    align-items: center;
    gap: 4px;
    overflow-x: auto;
    min-width: 0;
  }

  .tab-pill {
    display: inline-flex;
    align-items: center;
    height: 26px;
    border-radius: var(--radius-sm);
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-muted);
    transition: all var(--transition-fast);
  }

  .tab-pill:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .tab-pill.active {
    background: var(--bg-active);
    border-color: var(--accent-border);
    color: var(--text-primary);
  }

  .tab-select {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 100%;
    padding: 0 6px 0 8px;
    border: none;
    background: transparent;
    color: inherit;
    font-size: var(--text-xs);
    cursor: pointer;
  }

  .tab-running-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    animation: cap-pulse 1.2s ease-in-out infinite;
  }

  .tab-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 18px;
    height: 18px;
    margin-right: 4px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
  }

  .tab-close:hover {
    background: var(--bg-subtle);
    color: var(--status-danger);
  }

  .tab-add {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    height: 24px;
    padding: 0 8px;
    border: 1px dashed var(--border-default);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-xs);
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .tab-add:hover {
    border-color: var(--accent-border);
    color: var(--accent);
    background: var(--accent-soft);
  }

  .chrome-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  /* Quick Presets Bar */
  .presets-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 12px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    overflow-x: auto;
    flex-shrink: 0;
  }

  .presets-label {
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
    white-space: nowrap;
  }

  .presets-list {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .preset-chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 23px;
    padding: 0 8px;
    border-radius: var(--radius-full);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    white-space: nowrap;
    transition: all var(--transition-fast);
  }

  .preset-chip:hover:not(:disabled) {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
  }

  .preset-chip:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }

  /* Console Viewport — dedicated high-contrast dark terminal surface */
  .console-surface {
    flex: 1;
    overflow-y: auto;
    padding: 14px 16px;
    background: var(--terminal-bg);
    min-height: 0;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .welcome-banner {
    padding: 16px 18px;
    border-radius: var(--radius-lg);
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    display: flex;
    flex-direction: column;
    gap: 12px;
    max-width: 680px;
  }

  .welcome-head {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .welcome-icon {
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    background: rgba(52, 211, 153, 0.14);
    border: 1px solid rgba(52, 211, 153, 0.32);
    color: var(--terminal-fg);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .welcome-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: #f1f5f9;
  }

  .welcome-sub {
    font-size: var(--text-xs);
    color: #94a3b8;
    margin-top: 2px;
  }

  .welcome-hints {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
    padding-top: 10px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
  }

  .hint-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    color: #94a3b8;
  }

  /* Command Blocks */
  .blocks-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .cmd-block {
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(255, 255, 255, 0.08);
    overflow: hidden;
  }

  .cmd-block.status-error {
    border-color: rgba(248, 113, 113, 0.32);
  }

  .block-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 7px 11px;
    background: rgba(255, 255, 255, 0.03);
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  }

  .block-cmd {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12.5px;
    min-width: 0;
    flex: 1;
  }

  .prompt-glyph {
    color: var(--terminal-fg);
    font-weight: 700;
    user-select: none;
  }

  .cmd-text {
    color: #f8fafc;
    font-weight: 500;
    word-break: break-all;
  }

  .block-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .block-time {
    font-size: 10.5px;
    color: #64748b;
  }

  .block-actions {
    display: inline-flex;
    align-items: center;
    gap: 2px;
  }

  .blk-btn {
    width: 22px;
    height: 22px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: #94a3b8;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .blk-btn:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.08);
    color: #f8fafc;
  }

  .blk-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .block-output {
    padding: 10px 12px;
    margin: 0;
    font-size: 12.5px;
    line-height: 1.6;
    color: #cbd5e1;
    overflow-x: auto;
    white-space: pre;
  }

  .block-output.wrap {
    white-space: pre-wrap;
    word-break: break-word;
  }

  .block-output.is-err {
    color: #fca5a5;
  }

  .block-running,
  .block-empty {
    padding: 8px 12px;
    font-size: 11.5px;
    color: #64748b;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .spin-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 1.5px solid var(--accent);
    border-top-color: transparent;
    animation: cap-spin 0.7s linear infinite;
  }

  /* Bottom Prompt Bar */
  .prompt-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    background: rgba(15, 17, 24, 0.96);
    border-top: 1px solid rgba(255, 255, 255, 0.10);
    flex-shrink: 0;
  }

  .prompt-prefix {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
    user-select: none;
  }

  .prefix-tag {
    font-size: 10.5px;
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    background: rgba(52, 211, 153, 0.14);
    color: var(--terminal-fg);
    font-weight: 600;
  }

  .prefix-dollar {
    color: var(--terminal-fg);
    font-weight: 700;
    font-size: 13px;
  }

  .prompt-input {
    flex: 1;
    min-width: 0;
    height: 28px;
    border: none;
    background: transparent;
    color: #f8fafc;
    font-size: 13px;
    outline: none;
    caret-color: var(--terminal-fg);
  }

  .prompt-input::placeholder {
    color: #475569;
  }

  .prompt-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .hist-count {
    font-size: 10.5px;
    color: #64748b;
  }
</style>
