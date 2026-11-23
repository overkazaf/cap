<script>
  import { createEventDispatcher, tick } from 'svelte'
  import { t } from '../lib/i18n.js'
  import { hasPrimaryMod, isMac, MOD_LABEL } from '../lib/shortcuts.js'
  import Icon from './Icon.svelte'

  export let value = ''
  /** @type {'python3' | 'node' | 'sh' | 'builtin' | string} */
  export let runtime = 'builtin'
  export let placeholder = ''
  export let ariaLabel = ''
  export let minHeight = '160px'
  export let showToolbar = true
  export let shortcutHint = ''
  export let disabled = false
  export let readonly = false

  // Bindable undo/redo capability flags for external toolbars
  export let canUndo = false
  export let canRedo = false

  const MAX_HISTORY = 200
  const COALESCE_MS = 500
  const dispatch = createEventDispatcher()

  let textareaEl = null
  let gutterEl = null

  let history = [{ value: String(value ?? ''), start: 0, end: 0 }]
  let historyIndex = 0
  let lastKnownValue = String(value ?? '')
  let lastInputTs = 0
  let lastInputKind = ''
  let isComposing = false

  // Persist last known cursor/selection so toolbar/chip clicks preserve caret position
  let savedStart = 0
  let savedEnd = 0
  let cursorLine = 1
  let cursorCol = 1

  $: canUndo = historyIndex > 0
  $: canRedo = historyIndex < history.length - 1

  // Guard against direct external mutations of `value` outside resetHistory/replaceValue
  $: {
    const str = String(value ?? '')
    if (str !== lastKnownValue) {
      lastKnownValue = str
      history = [{ value: str, start: 0, end: 0 }]
      historyIndex = 0
      lastInputTs = 0
      lastInputKind = ''
      savedStart = Math.min(savedStart, str.length)
      savedEnd = Math.min(savedEnd, str.length)
      recomputeLineCol(str, savedStart)
    }
  }

  $: lineCount = Math.max(1, String(value ?? '').split('\n').length)
  $: lineNumbers = Array.from({ length: lineCount }, (_, i) => i + 1)
  $: commentPrefix = runtime === 'python3' || runtime === 'sh' ? '# ' : '// '
  $: commentToken = runtime === 'python3' || runtime === 'sh' ? '#' : '//'

  function recomputeLineCol(text, pos) {
    const clamped = Math.max(0, Math.min(pos, text.length))
    const before = text.slice(0, clamped)
    const lines = before.split('\n')
    cursorLine = lines.length
    cursorCol = lines[lines.length - 1].length + 1
  }

  function syncSelectionFromDom() {
    if (!textareaEl) return
    savedStart = textareaEl.selectionStart ?? savedStart
    savedEnd = textareaEl.selectionEnd ?? savedEnd
    recomputeLineCol(String(value ?? ''), savedStart)
  }

  function syncGutterScroll() {
    if (gutterEl && textareaEl) {
      gutterEl.scrollTop = textareaEl.scrollTop
    }
  }

  function commitHistory(nextVal, nextStart, nextEnd, { coalesce = false, kind = 'other', preStart = null, preEnd = null } = {}) {
    const now = Date.now()
    const current = history[historyIndex]

    if (current && current.value === nextVal) {
      current.start = nextStart
      current.end = nextEnd
      savedStart = nextStart
      savedEnd = nextEnd
      recomputeLineCol(nextVal, nextStart)
      return
    }

    const canCoalesce =
      coalesce &&
      (kind === 'insert' || kind === 'delete') &&
      kind === lastInputKind &&
      now - lastInputTs <= COALESCE_MS &&
      historyIndex === history.length - 1 &&
      historyIndex > 0 &&
      current &&
      Math.abs(nextStart - current.start) <= 2

    if (canCoalesce) {
      history[historyIndex] = { value: nextVal, start: nextStart, end: nextEnd }
      history = history
    } else {
      if (current && preStart !== null && preEnd !== null) {
        current.start = preStart
        current.end = preEnd
      }
      const nextStack = history.slice(0, historyIndex + 1)
      nextStack.push({ value: nextVal, start: nextStart, end: nextEnd })
      if (nextStack.length > MAX_HISTORY) {
        nextStack.splice(0, nextStack.length - MAX_HISTORY)
      }
      history = nextStack
      historyIndex = history.length - 1
    }

    lastInputTs = coalesce ? now : 0
    lastInputKind = coalesce ? kind : ''
    savedStart = nextStart
    savedEnd = nextEnd
    recomputeLineCol(nextVal, nextStart)
  }

  async function applyValueAndSelection(nextVal, start, end, { emitChange = true, shouldFocus = true } = {}) {
    value = nextVal
    lastKnownValue = nextVal
    savedStart = start
    savedEnd = end
    recomputeLineCol(nextVal, start)

    await tick()
    if (textareaEl) {
      if (shouldFocus) textareaEl.focus()
      textareaEl.setSelectionRange(start, end)
      syncGutterScroll()
    }
    if (emitChange) {
      dispatch('change', { value: nextVal })
      dispatch('input', { value: nextVal })
    }
  }

  // ==================== Exported Public API ====================

  export function focus() {
    textareaEl?.focus()
  }

  /**
   * Clear undo/redo history and seed it with `initialText`.
   * Call when switching plugins or creating a new plugin (never on save!).
   */
  export function resetHistory(initialText = '') {
    const str = String(initialText ?? '')
    value = str
    lastKnownValue = str
    history = [{ value: str, start: 0, end: 0 }]
    historyIndex = 0
    lastInputTs = 0
    lastInputKind = ''
    savedStart = 0
    savedEnd = 0
    recomputeLineCol(str, 0)
    tick().then(() => {
      if (textareaEl) {
        textareaEl.scrollTop = 0
        syncGutterScroll()
      }
    })
  }

  /**
   * Insert text at current cursor/selection as a single atomic undoable step.
   */
  export async function insertAtCursor(text) {
    if (disabled || readonly) return
    const insert = String(text ?? '')
    const cur = String(value ?? '')
    const rawStart =
      textareaEl && document.activeElement === textareaEl ? textareaEl.selectionStart : savedStart
    const rawEnd =
      textareaEl && document.activeElement === textareaEl ? textareaEl.selectionEnd : savedEnd
    const start = Math.max(0, Math.min(rawStart ?? cur.length, cur.length))
    const end = Math.max(start, Math.min(rawEnd ?? start, cur.length))

    const nextVal = cur.slice(0, start) + insert + cur.slice(end)
    const nextPos = start + insert.length
    commitHistory(nextVal, nextPos, nextPos, { coalesce: false, preStart: start, preEnd: end })
    await applyValueAndSelection(nextVal, nextPos, nextPos)
  }

  /**
   * Replace entire editor contents.
   * When `undoable: true`, records an atomic undo step so Cmd/Ctrl+Z restores prior code.
   * When `undoable: false`, resets the history stack cleanly.
   */
  export async function replaceValue(nextText, { undoable = true } = {}) {
    const str = String(nextText ?? '')
    if (!undoable) {
      resetHistory(str)
      dispatch('change', { value: str })
      return
    }
    if (str === String(value ?? '')) {
      focus()
      return
    }
    const cur = String(value ?? '')
    const preStart = Math.max(0, Math.min(savedStart, cur.length))
    const preEnd = Math.max(preStart, Math.min(savedEnd, cur.length))
    commitHistory(str, str.length, str.length, { coalesce: false, preStart, preEnd })
    await applyValueAndSelection(str, str.length, str.length)
  }

  export async function undo() {
    if (disabled || readonly || historyIndex <= 0) return false
    historyIndex -= 1
    lastInputTs = 0
    lastInputKind = ''
    const entry = history[historyIndex]
    await applyValueAndSelection(entry.value, entry.start, entry.end)
    return true
  }

  export async function redo() {
    if (disabled || readonly || historyIndex >= history.length - 1) return false
    historyIndex += 1
    lastInputTs = 0
    lastInputKind = ''
    const entry = history[historyIndex]
    await applyValueAndSelection(entry.value, entry.start, entry.end)
    return true
  }

  // ==================== Native Typing, Indent & Comment Handlers ====================

  function handleInput(e) {
    const nextVal = e.target.value
    const start = e.target.selectionStart ?? nextVal.length
    const end = e.target.selectionEnd ?? start

    value = nextVal
    lastKnownValue = nextVal

    if (isComposing || e.isComposing) {
      savedStart = start
      savedEnd = end
      recomputeLineCol(nextVal, start)
      dispatch('change', { value: nextVal })
      return
    }

    const inputType = e.inputType || ''
    const isPasteOrCut = inputType.includes('Paste') || inputType.includes('Cut') || inputType.includes('Drop')
    const isLineBreak = inputType === 'insertLineBreak' || inputType === 'insertParagraph' || (e.data && e.data.includes('\n'))
    const isDelete = inputType.startsWith('delete')
    const isInsert = inputType.startsWith('insert')

    const kind = isDelete ? 'delete' : isInsert ? 'insert' : 'other'
    const coalesce = !isPasteOrCut && !isLineBreak && (kind === 'insert' || kind === 'delete')

    commitHistory(nextVal, start, end, {
      coalesce,
      kind,
      preStart: savedStart,
      preEnd: savedEnd,
    })

    syncGutterScroll()
    dispatch('change', { value: nextVal })
    dispatch('input', { value: nextVal })
  }

  function handleCompositionStart() {
    isComposing = true
  }

  function handleCompositionEnd(e) {
    isComposing = false
    const nextVal = e.target.value
    const start = e.target.selectionStart ?? nextVal.length
    const end = e.target.selectionEnd ?? start
    value = nextVal
    lastKnownValue = nextVal
    commitHistory(nextVal, start, end, {
      coalesce: false,
      preStart: savedStart,
      preEnd: savedEnd,
    })
    dispatch('change', { value: nextVal })
  }

  function getSelectedLineRange(text, start, end) {
    const lineStart = text.lastIndexOf('\n', Math.max(0, start - 1)) + 1
    let effectiveEnd = end
    if (end > start && text[end - 1] === '\n') {
      effectiveEnd = end - 1
    }
    let lineEnd = text.indexOf('\n', effectiveEnd)
    if (lineEnd === -1) lineEnd = text.length
    return { lineStart, lineEnd }
  }

  async function handleIndent(outdent) {
    if (disabled || readonly || !textareaEl) return
    const cur = String(value ?? '')
    const start = textareaEl.selectionStart ?? savedStart
    const end = textareaEl.selectionEnd ?? savedEnd

    // Single cursor Tab -> insert 2 spaces
    if (!outdent && start === end) {
      const nextVal = cur.slice(0, start) + '  ' + cur.slice(end)
      const nextPos = start + 2
      commitHistory(nextVal, nextPos, nextPos, { coalesce: false, preStart: start, preEnd: end })
      await applyValueAndSelection(nextVal, nextPos, nextPos)
      return
    }

    const { lineStart, lineEnd } = getSelectedLineRange(cur, start, end)
    const block = cur.slice(lineStart, lineEnd)
    const lines = block.split('\n')

    let nextStart = start
    let nextEnd = end
    let totalDelta = 0

    const updated = lines.map((line, idx) => {
      if (!outdent) {
        if (idx === 0) nextStart += 2
        totalDelta += 2
        return '  ' + line
      }
      let removed = 0
      if (line.startsWith('  ')) removed = 2
      else if (line.startsWith('\t') || line.startsWith(' ')) removed = 1
      if (idx === 0) {
        const colInFirst = start - lineStart
        nextStart = lineStart + Math.max(0, colInFirst - removed)
      }
      totalDelta -= removed
      return line.slice(removed)
    })

    if (totalDelta === 0) return

    nextEnd = Math.max(nextStart, end + totalDelta)
    const nextVal = cur.slice(0, lineStart) + updated.join('\n') + cur.slice(lineEnd)
    commitHistory(nextVal, nextStart, nextEnd, { coalesce: false, preStart: start, preEnd: end })
    await applyValueAndSelection(nextVal, nextStart, nextEnd)
  }

  async function handleToggleComment() {
    if (disabled || readonly || !textareaEl) return
    const cur = String(value ?? '')
    const start = textareaEl.selectionStart ?? savedStart
    const end = textareaEl.selectionEnd ?? savedEnd

    const { lineStart, lineEnd } = getSelectedLineRange(cur, start, end)
    const block = cur.slice(lineStart, lineEnd)
    const lines = block.split('\n')

    const nonEmpty = lines.filter((l) => l.trim().length > 0)
    const targetLines = nonEmpty.length > 0 ? nonEmpty : lines
    const allCommented = targetLines.every((l) => l.trimStart().startsWith(commentToken))

    let firstDelta = 0
    let totalDelta = 0

    const updated = lines.map((line, idx) => {
      if (allCommented) {
        const match = line.match(/^(\s*)/)
        const indent = match ? match[1] : ''
        const rest = line.slice(indent.length)
        let nextLine = line
        let delta = 0
        if (rest.startsWith(commentPrefix)) {
          nextLine = indent + rest.slice(commentPrefix.length)
          delta = -commentPrefix.length
        } else if (rest.startsWith(commentToken)) {
          nextLine = indent + rest.slice(commentToken.length)
          delta = -commentToken.length
        }
        if (idx === 0) firstDelta = delta
        totalDelta += delta
        return nextLine
      } else {
        if (line.trim().length === 0 && nonEmpty.length > 0) {
          return line
        }
        const match = line.match(/^(\s*)/)
        const indent = match ? match[1] : ''
        const rest = line.slice(indent.length)
        const nextLine = indent + commentPrefix + rest
        const delta = commentPrefix.length
        if (idx === 0) firstDelta = delta
        totalDelta += delta
        return nextLine
      }
    })

    const nextStart = Math.max(lineStart, start + firstDelta)
    const nextEnd = Math.max(nextStart, end + totalDelta)
    const nextVal = cur.slice(0, lineStart) + updated.join('\n') + cur.slice(lineEnd)
    commitHistory(nextVal, nextStart, nextEnd, { coalesce: false, preStart: start, preEnd: end })
    await applyValueAndSelection(nextVal, nextStart, nextEnd)
  }

  function handleKeydown(e) {
    if (isComposing || e.isComposing || e.keyCode === 229) return

    const primary = hasPrimaryMod(e)
    const key = e.key.toLowerCase()

    // Undo: Cmd/Ctrl + Z
    if (primary && !e.shiftKey && !e.altKey && key === 'z') {
      e.preventDefault()
      undo()
      return
    }

    // Redo: Cmd/Ctrl + Shift + Z  OR  Ctrl + Y (Windows/Linux)
    if (
      (primary && e.shiftKey && !e.altKey && key === 'z') ||
      (!isMac && e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey && key === 'y')
    ) {
      e.preventDefault()
      redo()
      return
    }

    // Toggle comment: Cmd/Ctrl + /
    if (primary && !e.altKey && e.key === '/') {
      e.preventDefault()
      handleToggleComment()
      return
    }

    // Save: Cmd/Ctrl + S
    if (primary && !e.shiftKey && !e.altKey && key === 's') {
      e.preventDefault()
      dispatch('save')
      return
    }

    // Run: Cmd/Ctrl + Enter
    if (primary && e.key === 'Enter') {
      e.preventDefault()
      dispatch('run')
      return
    }

    // Indent / Outdent: Tab / Shift+Tab
    if (e.key === 'Tab' && !primary && !e.altKey) {
      e.preventDefault()
      handleIndent(e.shiftKey)
      return
    }

    // Flush typing coalesce boundary on explicit navigation keys
    if (
      e.key === 'ArrowLeft' ||
      e.key === 'ArrowRight' ||
      e.key === 'ArrowUp' ||
      e.key === 'ArrowDown' ||
      e.key === 'Home' ||
      e.key === 'End' ||
      e.key === 'PageUp' ||
      e.key === 'PageDown'
    ) {
      lastInputTs = 0
      lastInputKind = ''
    }
  }
</script>

<div class="code-editor-wrap" style="--editor-min-h: {minHeight};">
  <div class="editor-surface">
    <div bind:this={gutterEl} class="line-gutter mono tabular-nums" aria-hidden="true">
      {#each lineNumbers as ln (ln)}
        <div class="ln" class:active={ln === cursorLine}>{ln}</div>
      {/each}
    </div>

    <textarea
      bind:this={textareaEl}
      value={value}
      class="editor-textarea mono"
      {placeholder}
      {disabled}
      {readonly}
      aria-label={ariaLabel || $t('common.editor.ariaLabel')}
      autocapitalize="none"
      autocorrect="off"
      autocomplete="off"
      spellcheck="false"
      inputmode="text"
      on:input={handleInput}
      on:keydown={handleKeydown}
      on:click={syncSelectionFromDom}
      on:keyup={syncSelectionFromDom}
      on:select={syncSelectionFromDom}
      on:blur={syncSelectionFromDom}
      on:scroll={syncGutterScroll}
      on:compositionstart={handleCompositionStart}
      on:compositionend={handleCompositionEnd}
    ></textarea>
  </div>

  {#if showToolbar}
    <div class="editor-bar">
      <div class="bar-left">
        <button
          type="button"
          class="hist-btn"
          disabled={disabled || readonly || !canUndo}
          title={$t('common.editor.undoTooltip', { mod: MOD_LABEL })}
          aria-label={$t('common.editor.undo')}
          on:mousedown|preventDefault
          on:click={undo}
        >
          <Icon name="undo" size={12} />
        </button>
        <button
          type="button"
          class="hist-btn"
          disabled={disabled || readonly || !canRedo}
          title={$t('common.editor.redoTooltip', { mod: MOD_LABEL })}
          aria-label={$t('common.editor.redo')}
          on:mousedown|preventDefault
          on:click={redo}
        >
          <Icon name="redo" size={12} />
        </button>
        <span class="bar-sep" aria-hidden="true"></span>
        <span class="bar-hint truncate">
          {shortcutHint || $t('common.editor.shortcutHint', { mod: MOD_LABEL })}
        </span>
      </div>

      <span class="bar-pos mono tabular-nums">
        {$t('common.editor.lineCol', { line: cursorLine, col: cursorCol })}
      </span>
    </div>
  {/if}
</div>

<style>
  .code-editor-wrap {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    min-height: var(--editor-min-h, 160px);
    min-width: 0;
    background: var(--bg-input);
    overflow: hidden;
  }

  .editor-surface {
    flex: 1;
    min-height: 0;
    display: flex;
    overflow: hidden;
    position: relative;
  }

  .line-gutter {
    flex: 0 0 auto;
    min-width: 38px;
    padding: 10px 8px 10px 6px;
    background: var(--bg-header);
    border-right: 1px solid var(--border-subtle);
    color: var(--text-faint);
    font-size: 12px;
    line-height: 1.55;
    text-align: right;
    overflow: hidden;
    user-select: none;
  }

  .ln {
    height: 1.55em;
  }

  .ln.active {
    color: var(--text-secondary);
    font-weight: 600;
  }

  .editor-textarea {
    flex: 1;
    min-width: 0;
    min-height: 0;
    width: 100%;
    padding: 10px 12px;
    border: none;
    resize: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 12px;
    line-height: 1.55;
    tab-size: 2;
    white-space: pre;
    overflow: auto;
    outline: none;
  }

  .editor-textarea:focus-visible {
    box-shadow: none;
  }

  .editor-textarea::placeholder {
    color: var(--text-faint);
  }

  .editor-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 3px 8px;
    background: var(--bg-header);
    border-top: 1px solid var(--border-subtle);
    font-size: 10.5px;
    color: var(--text-faint);
    flex-shrink: 0;
    user-select: none;
  }

  .bar-left {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
  }

  .hist-btn {
    width: 22px;
    height: 20px;
    border: 1px solid transparent;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .hist-btn:hover:not(:disabled) {
    background: var(--bg-hover);
    border-color: var(--border-default);
    color: var(--text-primary);
  }

  .hist-btn:disabled {
    opacity: 0.32;
    cursor: not-allowed;
  }

  .bar-sep {
    width: 1px;
    height: 11px;
    background: var(--border-default);
    margin: 0 3px;
  }

  .bar-hint {
    min-width: 0;
    color: var(--text-faint);
  }

  .bar-pos {
    flex-shrink: 0;
    color: var(--text-muted);
  }
</style>
