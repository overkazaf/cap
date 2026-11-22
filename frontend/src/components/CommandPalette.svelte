<script>
  import { tick } from 'svelte'
  import { fade, scale } from 'svelte/transition'
  import { paletteOpen, closePalette, customCommands } from '../lib/commandPalette.js'
  import { t } from '../lib/i18n.js'
  import Icon from './Icon.svelte'
  import Kbd from './Kbd.svelte'

  /** @type {Array<{id:string, label:string, category:string, icon?:string, shortcut?:string|string[], keywords?:string, badge?:string, run:()=>void}>} */
  export let commands = []

  let query = ''
  let activeIndex = 0
  let inputEl

  $: allCommands = [...$customCommands, ...commands]

  $: filtered = filterCommands(allCommands, query)

  $: if (activeIndex >= filtered.length) {
    activeIndex = Math.max(0, filtered.length - 1)
  }

  $: if ($paletteOpen) {
    query = ''
    activeIndex = 0
    tick().then(() => inputEl?.focus())
  }

  function filterCommands(list, q) {
    const term = q.trim().toLowerCase()
    if (!term) return list
    const parts = term.split(/\s+/)
    return list.filter((cmd) => {
      const hay = `${cmd.label} ${cmd.category || ''} ${cmd.keywords || ''}`.toLowerCase()
      return parts.every((p) => hay.includes(p))
    })
  }

  function groupCommands(list, fallbackCategory) {
    const groups = []
    const map = new Map()
    list.forEach((cmd, idx) => {
      const cat = cmd.category || fallbackCategory
      if (!map.has(cat)) {
        const g = { name: cat, items: [] }
        map.set(cat, g)
        groups.push(g)
      }
      map.get(cat).items.push({ ...cmd, _idx: idx })
    })
    return groups
  }

  $: grouped = groupCommands(filtered, $t('common.palette.categories.actions'))

  function execute(cmd) {
    if (!cmd) return
    closePalette()
    cmd.run?.()
  }

  function onKeydown(e) {
    if (!$paletteOpen) return
    if (e.key === 'Escape') {
      e.preventDefault()
      closePalette()
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (filtered.length) activeIndex = (activeIndex + 1) % filtered.length
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (filtered.length) activeIndex = (activeIndex - 1 + filtered.length) % filtered.length
    } else if (e.key === 'Enter') {
      e.preventDefault()
      execute(filtered[activeIndex])
    }
  }
</script>

<svelte:window on:keydown={onKeydown} />

{#if $paletteOpen}
  <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
  <div
    class="palette-backdrop"
    transition:fade={{ duration: 110 }}
    on:click|self={closePalette}
  >
    <div
      class="palette-dialog"
      role="dialog"
      aria-modal="true"
      aria-label={$t('common.palette.ariaLabel')}
      transition:scale={{ start: 0.97, duration: 120 }}
    >
      <div class="palette-search">
        <Icon name="search" size={15} className="search-icon" />
        <input
          bind:this={inputEl}
          bind:value={query}
          type="text"
          class="search-input"
          placeholder={$t('common.palette.placeholder')}
          spellcheck="false"
          autocomplete="off"
        />
        {#if query}
          <button class="clear-btn" on:click={() => { query = ''; inputEl?.focus() }} aria-label={$t('common.palette.clearSearch')}>
            <Icon name="x" size={13} />
          </button>
        {/if}
        <Kbd keys="Esc" size="xs" />
      </div>

      <div class="palette-list">
        {#if filtered.length === 0}
          <div class="palette-empty">
            {$t('common.palette.noResults', { query })}
          </div>
        {:else}
          {#each grouped as group}
            <div class="group-label">{group.name}</div>
            {#each group.items as cmd (cmd.id)}
              <button
                class="cmd-row"
                class:active={cmd._idx === activeIndex}
                on:mouseenter={() => (activeIndex = cmd._idx)}
                on:click={() => execute(cmd)}
              >
                <span class="cmd-icon">
                  <Icon name={cmd.icon || 'command'} size={15} />
                </span>
                <span class="cmd-label">{cmd.label}</span>
                {#if cmd.badge}
                  <span class="cmd-badge">{cmd.badge}</span>
                {/if}
                {#if cmd.shortcut}
                  <span class="cmd-kbd">
                    <Kbd keys={cmd.shortcut} size="xs" />
                  </span>
                {/if}
              </button>
            {/each}
          {/each}
        {/if}
      </div>

      <div class="palette-footer">
        <span class="hint"><Kbd keys={['↑', '↓']} size="xs" /> {$t('common.palette.navigate')}</span>
        <span class="hint"><Kbd keys="↵" size="xs" /> {$t('common.palette.run')}</span>
        <span class="hint"><Kbd keys="Esc" size="xs" /> {$t('common.palette.close')}</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .palette-backdrop {
    position: fixed;
    inset: 0;
    z-index: var(--z-palette);
    background: rgba(0, 0, 0, 0.52);
    backdrop-filter: blur(4px);
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: min(14vh, 110px);
  }

  .palette-dialog {
    width: min(560px, calc(100vw - 32px));
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-lg);
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .palette-search {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 14px;
    border-bottom: 1px solid var(--border-default);
    color: var(--text-muted);
  }

  .search-input {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: var(--text-md);
    outline: none;
  }

  .search-input:focus-visible {
    box-shadow: none;
  }

  .search-input::placeholder {
    color: var(--text-faint);
  }

  .clear-btn {
    width: 22px;
    height: 22px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
  }

  .clear-btn:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .palette-list {
    max-height: 360px;
    overflow-y: auto;
    padding: 6px;
  }

  .palette-empty {
    padding: 28px 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .group-label {
    padding: 8px 10px 4px;
    font-size: var(--text-2xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-faint);
  }

  .cmd-row {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border: none;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-base);
    text-align: left;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .cmd-row.active {
    background: var(--accent-soft);
    color: var(--text-primary);
  }

  .cmd-icon {
    display: flex;
    color: var(--text-muted);
  }

  .cmd-row.active .cmd-icon {
    color: var(--accent);
  }

  .cmd-label {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .cmd-badge {
    font-size: var(--text-xs);
    color: var(--text-muted);
    background: var(--bg-subtle);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs);
    padding: 1px 6px;
  }

  .cmd-kbd {
    flex-shrink: 0;
  }

  .palette-footer {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 14px;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-header);
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .hint {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
</style>
