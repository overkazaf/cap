<script>
  import { formatShortcut } from '../lib/shortcuts.js'

  /** @type {string | string[]} */
  export let keys = ''
  export let size = 'sm' // 'xs' | 'sm'

  $: list = formatShortcut(keys).filter(Boolean)
</script>

<span class="kbd-group s-{size}">
  {#each list as k}
    <kbd class="kbd">{k}</kbd>
  {/each}
</span>

<style>
  .kbd-group {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    vertical-align: middle;
  }

  .kbd {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-family: var(--font-mono);
    font-weight: 500;
    line-height: 1;
    color: var(--text-muted);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    border-bottom-width: 2px;
    border-radius: var(--radius-xs);
    user-select: none;
  }

  .s-sm .kbd {
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    font-size: 10px;
  }

  .s-xs .kbd {
    min-width: 16px;
    height: 16px;
    padding: 0 4px;
    font-size: 9.5px;
  }
</style>
