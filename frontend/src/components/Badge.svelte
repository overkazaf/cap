<script>
  import { statusVariant } from '../lib/format.js'

  /** @type {'neutral'|'accent'|'success'|'info'|'warning'|'danger'|'purple'|'method'|'status'} */
  export let variant = 'neutral'
  export let method = ''
  export let status = null
  /** @type {'xs'|'sm'|'md'} */
  export let size = 'sm'
  export let dot = false
  export let pulse = false
  export let mono = false
  export let solid = false

  function resolveMethodClass(m) {
    const u = String(m || '').toUpperCase()
    if (u === 'GET') return 'm-get'
    if (u === 'POST') return 'm-post'
    if (u === 'PUT') return 'm-put'
    if (u === 'PATCH') return 'm-patch'
    if (u === 'DELETE') return 'm-delete'
    if (u === 'WS' || u === 'WSS') return 'm-ws'
    return 'm-options'
  }

  $: computedVariant =
    variant === 'status' || status !== null
      ? statusVariant(status)
      : variant === 'method' || method
        ? 'method'
        : variant

  $: methodCls = computedVariant === 'method' ? resolveMethodClass(method) : ''
  $: isMono = mono || computedVariant === 'method' || status !== null
</script>

<span
  class="cap-badge size-{size} v-{computedVariant} {methodCls}"
  class:mono={isMono}
  class:tabular-nums={isMono}
  class:solid
>
  {#if dot}
    <span class="dot" class:pulse></span>
  {/if}
  <slot>{method || (status !== null ? status : '')}</slot>
</span>

<style>
  .cap-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    font-weight: 600;
    line-height: 1;
    white-space: nowrap;
    border-radius: var(--radius-xs);
    border: 1px solid transparent;
    letter-spacing: 0.01em;
    user-select: none;
  }

  .size-xs {
    height: 18px;
    padding: 0 5px;
    font-size: 10px;
  }

  .size-sm {
    height: 20px;
    padding: 0 6px;
    font-size: 11px;
  }

  .size-md {
    height: 24px;
    padding: 0 8px;
    font-size: 12px;
    border-radius: var(--radius-sm);
  }

  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
    flex-shrink: 0;
  }

  .dot.pulse {
    animation: cap-pulse 1.8s ease-in-out infinite;
  }

  /* Semantic variants */
  .v-neutral {
    color: var(--text-secondary);
    background: var(--bg-subtle);
    border-color: var(--border-default);
  }

  .v-accent {
    color: var(--accent);
    background: var(--accent-soft);
    border-color: var(--accent-border);
  }

  .v-success {
    color: var(--status-success);
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .v-info {
    color: var(--status-info);
    background: var(--status-info-bg);
    border-color: var(--status-info-border);
  }

  .v-warning {
    color: var(--status-warning);
    background: var(--status-warning-bg);
    border-color: var(--status-warning-border);
  }

  .v-danger {
    color: var(--status-danger);
    background: var(--status-danger-bg);
    border-color: var(--status-danger-border);
  }

  .v-purple {
    color: var(--status-purple);
    background: var(--status-purple-bg);
    border-color: var(--status-purple-border);
  }

  /* HTTP Method badges */
  .v-method {
    letter-spacing: 0.03em;
    font-weight: 700;
  }

  .m-get {
    color: var(--method-get);
    background: color-mix(in srgb, var(--method-get) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-get) 28%, transparent);
  }

  .m-post {
    color: var(--method-post);
    background: color-mix(in srgb, var(--method-post) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-post) 28%, transparent);
  }

  .m-put {
    color: var(--method-put);
    background: color-mix(in srgb, var(--method-put) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-put) 28%, transparent);
  }

  .m-patch {
    color: var(--method-patch);
    background: color-mix(in srgb, var(--method-patch) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-patch) 28%, transparent);
  }

  .m-delete {
    color: var(--method-delete);
    background: color-mix(in srgb, var(--method-delete) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-delete) 28%, transparent);
  }

  .m-ws {
    color: var(--method-ws);
    background: color-mix(in srgb, var(--method-ws) 12%, transparent);
    border-color: color-mix(in srgb, var(--method-ws) 28%, transparent);
  }

  .m-options {
    color: var(--method-options);
    background: var(--bg-subtle);
    border-color: var(--border-default);
  }

  .solid.v-accent {
    background: var(--accent);
    color: var(--text-inverse);
    border-color: transparent;
  }

  .solid.v-danger {
    background: var(--status-danger);
    color: #fff;
    border-color: transparent;
  }
</style>
