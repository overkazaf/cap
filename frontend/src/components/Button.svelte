<script>
  import Icon from './Icon.svelte'

  /** @type {'primary'|'secondary'|'ghost'|'subtle'|'danger'|'success'} */
  export let variant = 'secondary'
  /** @type {'xs'|'sm'|'md'} */
  export let size = 'sm'
  export let icon = ''
  export let iconRight = ''
  export let disabled = false
  export let loading = false
  export let active = false
  export let fullWidth = false
  export let iconOnly = false
  export let title = ''
  export let type = 'button'

  $: iconSize = size === 'xs' ? 12 : size === 'sm' ? 14 : 15
</script>

<button
  {type}
  {title}
  disabled={disabled || loading}
  class="cap-btn v-{variant} s-{size}"
  class:active
  class:full={fullWidth}
  class:icon-only={iconOnly}
  on:click
  {...$$restProps}
>
  {#if loading}
    <span class="spinner" aria-hidden="true"></span>
  {:else if icon}
    <Icon name={icon} size={iconSize} />
  {/if}
  {#if $$slots.default}
    <span class="label"><slot /></span>
  {/if}
  {#if iconRight && !loading}
    <Icon name={iconRight} size={iconSize} />
  {/if}
</button>

<style>
  .cap-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    border-radius: var(--radius-sm);
    border: 1px solid transparent;
    font-weight: 500;
    line-height: 1;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
    transition:
      background var(--transition-fast),
      border-color var(--transition-fast),
      color var(--transition-fast),
      opacity var(--transition-fast);
  }

  .cap-btn:disabled {
    opacity: 0.48;
    cursor: not-allowed;
  }

  .cap-btn.full {
    width: 100%;
  }

  /* Sizes */
  .s-xs {
    height: 24px;
    padding: 0 8px;
    font-size: var(--text-xs);
    gap: 4px;
  }

  .s-sm {
    height: 28px;
    padding: 0 10px;
    font-size: var(--text-sm);
  }

  .s-md {
    height: 34px;
    padding: 0 14px;
    font-size: var(--text-base);
    border-radius: var(--radius-md);
  }

  .icon-only.s-xs {
    width: 24px;
    padding: 0;
  }

  .icon-only.s-sm {
    width: 28px;
    padding: 0;
  }

  .icon-only.s-md {
    width: 34px;
    padding: 0;
  }

  /* Variants */
  .v-primary {
    background: var(--accent);
    color: var(--text-inverse);
    font-weight: 600;
  }

  .v-primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .v-secondary {
    background: var(--bg-elevated);
    border-color: var(--border-default);
    color: var(--text-primary);
  }

  .v-secondary:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--border-strong);
  }

  .v-secondary.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .v-subtle {
    background: var(--bg-subtle);
    border-color: transparent;
    color: var(--text-secondary);
  }

  .v-subtle:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .v-subtle.active {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .v-ghost {
    background: transparent;
    color: var(--text-muted);
  }

  .v-ghost:hover:not(:disabled) {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .v-ghost.active {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .v-success {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
    color: var(--status-success);
    font-weight: 600;
  }

  .v-success:hover:not(:disabled) {
    background: color-mix(in srgb, var(--status-success) 20%, transparent);
  }

  .v-danger {
    background: var(--status-danger-bg);
    border-color: var(--status-danger-border);
    color: var(--status-danger);
    font-weight: 600;
  }

  .v-danger:hover:not(:disabled) {
    background: color-mix(in srgb, var(--status-danger) 20%, transparent);
  }

  .label {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  .spinner {
    width: 12px;
    height: 12px;
    border: 1.75px solid currentColor;
    border-top-color: transparent;
    border-radius: 50%;
    animation: cap-spin 0.65s linear infinite;
  }
</style>
