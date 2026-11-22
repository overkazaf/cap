<script>
  import Icon from './Icon.svelte'
  import { t } from '../lib/i18n.js'

  export let icon = 'radar'
  export let title = ''
  export let description = ''
  export let compact = false

  $: displayTitle = title || $t('common.empty.defaultTitle')
</script>

<div class="cap-empty" class:compact>
  <div class="icon-wrap">
    <Icon name={icon} size={compact ? 20 : 24} strokeWidth={1.6} />
  </div>
  <div class="title">{displayTitle}</div>
  {#if description}
    <p class="desc">{description}</p>
  {/if}
  {#if $$slots.default}
    <div class="actions">
      <slot />
    </div>
  {/if}
</div>

<style>
  .cap-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 40px 24px;
    height: 100%;
    min-height: 180px;
    gap: 8px;
    color: var(--text-muted);
  }

  .cap-empty.compact {
    padding: 20px 16px;
    min-height: 120px;
    gap: 6px;
  }

  .icon-wrap {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-lg);
    background: var(--bg-elevated);
    border: 1px solid var(--border-default);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-muted);
    margin-bottom: 4px;
  }

  .compact .icon-wrap {
    width: 36px;
    height: 36px;
  }

  .title {
    font-size: var(--text-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .compact .title {
    font-size: var(--text-base);
  }

  .desc {
    max-width: 360px;
    font-size: var(--text-sm);
    color: var(--text-muted);
    line-height: var(--leading-normal);
  }

  .actions {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
    margin-top: 8px;
  }
</style>
