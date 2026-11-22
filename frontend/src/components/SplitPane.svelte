<script>
  import { onMount, onDestroy, createEventDispatcher } from 'svelte'
  import { t } from '../lib/i18n.js'

  /** @type {'horizontal' | 'vertical'} */
  export let direction = 'horizontal'
  export let initialSize = 46
  export let size = initialSize
  export let minPrimary = 18
  export let minSecondary = 18
  /** @type {'none' | 'primary' | 'secondary'} */
  export let collapsed = 'none'
  export let storageKey = ''

  const dispatch = createEventDispatcher()
  let containerEl
  let dragging = false

  function clamp(val) {
    return Math.min(100 - minSecondary, Math.max(minPrimary, val))
  }

  onMount(() => {
    if (storageKey) {
      try {
        const saved = Number(localStorage.getItem(storageKey))
        if (Number.isFinite(saved) && saved >= minPrimary && saved <= 100 - minSecondary) {
          size = saved
        }
      } catch (_) {}
    }
  })

  function persist(val) {
    if (!storageKey) return
    try {
      localStorage.setItem(storageKey, String(Math.round(val * 10) / 10))
    } catch (_) {}
  }

  function startDrag(e) {
    if (collapsed !== 'none') return
    e.preventDefault()
    dragging = true
    window.addEventListener('pointermove', onPointerMove)
    window.addEventListener('pointerup', stopDrag)
    document.body.style.cursor = direction === 'horizontal' ? 'col-resize' : 'row-resize'
    document.body.style.userSelect = 'none'
  }

  function onPointerMove(e) {
    if (!dragging || !containerEl) return
    const rect = containerEl.getBoundingClientRect()
    let pct
    if (direction === 'horizontal') {
      pct = ((e.clientX - rect.left) / rect.width) * 100
    } else {
      pct = ((e.clientY - rect.top) / rect.height) * 100
    }
    size = clamp(pct)
    dispatch('resize', { size })
  }

  function stopDrag() {
    if (!dragging) return
    dragging = false
    window.removeEventListener('pointermove', onPointerMove)
    window.removeEventListener('pointerup', stopDrag)
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
    persist(size)
  }

  function resetSize() {
    size = clamp(initialSize)
    persist(size)
    dispatch('resize', { size })
  }

  function onKeydown(e) {
    const step = e.shiftKey ? 8 : 2
    if (direction === 'horizontal') {
      if (e.key === 'ArrowLeft') { size = clamp(size - step); persist(size) }
      if (e.key === 'ArrowRight') { size = clamp(size + step); persist(size) }
    } else {
      if (e.key === 'ArrowUp') { size = clamp(size - step); persist(size) }
      if (e.key === 'ArrowDown') { size = clamp(size + step); persist(size) }
    }
  }

  onDestroy(stopDrag)

  $: primaryStyle =
    collapsed === 'primary'
      ? 'display:none;'
      : collapsed === 'secondary'
        ? 'flex: 1 1 100%;'
        : `flex: 0 0 ${size}%;`

  $: secondaryStyle =
    collapsed === 'secondary'
      ? 'display:none;'
      : 'flex: 1 1 0%;'
</script>

<div
  bind:this={containerEl}
  class="split-pane dir-{direction}"
  class:dragging
>
  <div class="pane primary" style={primaryStyle}>
    <slot name="primary" />
  </div>

  {#if collapsed === 'none'}
    <!-- svelte-ignore a11y-no-noninteractive-tabindex a11y-no-noninteractive-element-interactions -->
    <div
      class="divider"
      role="separator"
      aria-orientation={direction === 'horizontal' ? 'vertical' : 'horizontal'}
      aria-valuenow={Math.round(size)}
      tabindex="0"
      title={$t('common.splitPane.resizeHint')}
      on:pointerdown={startDrag}
      on:dblclick={resetSize}
      on:keydown={onKeydown}
    >
      <div class="divider-line"></div>
    </div>
  {/if}

  <div class="pane secondary" style={secondaryStyle}>
    <slot name="secondary" />
  </div>
</div>

<style>
  .split-pane {
    display: flex;
    width: 100%;
    height: 100%;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
  }

  .dir-horizontal {
    flex-direction: row;
  }

  .dir-vertical {
    flex-direction: column;
  }

  .pane {
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .divider {
    position: relative;
    flex: 0 0 auto;
    z-index: 5;
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
  }

  .dir-horizontal > .divider {
    width: 7px;
    margin: 0 -3px;
    cursor: col-resize;
  }

  .dir-vertical > .divider {
    height: 7px;
    margin: -3px 0;
    cursor: row-resize;
  }

  .divider-line {
    background: var(--border-default);
    transition: background var(--transition-fast), width var(--transition-fast), height var(--transition-fast);
  }

  .dir-horizontal > .divider .divider-line {
    width: 1px;
    height: 100%;
  }

  .dir-vertical > .divider .divider-line {
    height: 1px;
    width: 100%;
  }

  .divider:hover .divider-line,
  .divider:focus-visible .divider-line,
  .split-pane.dragging .divider-line {
    background: var(--accent);
  }

  .dir-horizontal > .divider:hover .divider-line,
  .split-pane.dragging.dir-horizontal > .divider .divider-line {
    width: 2px;
  }

  .dir-vertical > .divider:hover .divider-line,
  .split-pane.dragging.dir-vertical > .divider .divider-line {
    height: 2px;
  }
</style>
