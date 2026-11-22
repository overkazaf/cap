<script>
  import { fly } from 'svelte/transition'
  import { toasts, dismissToast } from '../lib/toast.js'
  import { t } from '../lib/i18n.js'
  import Icon from './Icon.svelte'

  const ICON_MAP = {
    success: 'check-circle',
    error: 'x-circle',
    warning: 'alert-triangle',
    info: 'info',
  }
</script>

<div class="toast-host" aria-live="polite" aria-atomic="false">
  {#each $toasts as item (item.id)}
    <div
      class="toast v-{item.variant}"
      role="status"
      in:fly={{ y: 12, duration: 160 }}
      out:fly={{ x: 20, duration: 140 }}
    >
      <span class="toast-icon">
        <Icon name={ICON_MAP[item.variant] || 'info'} size={15} />
      </span>
      <div class="toast-body">
        {#if item.title}
          <div class="toast-title">{item.title}</div>
        {/if}
        <div class="toast-msg">{item.message}</div>
      </div>
      {#if item.action}
        <button
          class="toast-action"
          on:click={() => {
            item.action.onClick?.()
            dismissToast(item.id)
          }}
        >
          {item.action.label}
        </button>
      {/if}
      <button
        class="toast-close"
        aria-label={$t('common.toast.dismiss')}
        on:click={() => dismissToast(item.id)}
      >
        <Icon name="x" size={13} />
      </button>
    </div>
  {/each}
</div>

<style>
  .toast-host {
    position: fixed;
    right: 16px;
    bottom: calc(var(--statusbar-height) + 14px);
    z-index: var(--z-toast);
    display: flex;
    flex-direction: column;
    gap: 8px;
    pointer-events: none;
    max-width: 380px;
  }

  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    border-radius: var(--radius-md);
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    box-shadow: var(--shadow-md);
    color: var(--text-primary);
    font-size: var(--text-sm);
    min-width: 220px;
  }

  .toast-icon {
    display: flex;
    flex-shrink: 0;
  }

  .v-success .toast-icon { color: var(--status-success); }
  .v-error .toast-icon { color: var(--status-danger); }
  .v-warning .toast-icon { color: var(--status-warning); }
  .v-info .toast-icon { color: var(--accent); }

  .v-error {
    border-color: var(--status-danger-border);
  }

  .toast-body {
    flex: 1;
    min-width: 0;
  }

  .toast-title {
    font-weight: 600;
    margin-bottom: 2px;
  }

  .toast-msg {
    color: var(--text-secondary);
    line-height: 1.35;
    word-break: break-word;
  }

  .toast-action {
    padding: 3px 8px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
  }

  .toast-close {
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
    flex-shrink: 0;
  }

  .toast-close:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
</style>
