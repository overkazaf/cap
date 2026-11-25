<script>
  import { onMount, onDestroy } from 'svelte'
  import { fade, fly } from 'svelte/transition'
  import '../lib/locales/ai.js'
  import { t, translate, locale } from '../lib/i18n.js'
  import { navigate } from '../lib/navigation.js'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration, formatTime } from '../lib/format.js'
  import {
    aiConfig,
    activeAIProfile,
    isAIConfigured,
    refreshAIConfig,
    aiHealSession,
    updateAIHealSession,
    closeAIHealModal,
    aiUndoStack,
    requestOpenAISettings,
  } from '../lib/aiState.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'

  const api = () => window?.go?.wailsgui?.App
  const runtimeApi = () => window?.runtime

  let destroyed = false
  let unsubHealEvent = null
  let lastSessionId = 0
  let diagnoseSeq = 0

  // Single-shot diagnosis state
  let diagnosing = false
  let diagnoseError = ''
  let result = null
  let currentCode = ''
  let diffViewMode = 'diff' // 'diff' | 'full'
  let preDiagOpen = false
  let applyingPatch = false
  let applyingConfig = false
  let appliedConfigCount = 0

  // Multi-round Auto-Heal timeline state
  let loopRunning = false
  let cancellingLoop = false
  let liveEvents = []
  let autoHealResult = null
  let expandedRounds = {}

  $: session = $aiHealSession
  $: undoKey = session?.undoKey || session?.scope || 'general'
  $: undoEntries = ($aiUndoStack && $aiUndoStack[undoKey]) || []
  $: hasUndoBackup = undoEntries.length > 0 && Boolean(session?.onApplyPatch)

  $: if (session && session.sessionId !== lastSessionId) {
    handleNewSession(session)
  } else if (session && session.sessionId === lastSessionId) {
    // Allow external callers to update autoLoopRunning / autoHealResult in-place
    if (session.autoHealResult && session.autoHealResult !== autoHealResult) {
      autoHealResult = session.autoHealResult
      syncLatestDiagnosisFromAutoHeal(session.autoHealResult)
    }
    if (typeof session.autoLoopRunning === 'boolean' && session.autoLoopRunning !== loopRunning && !cancellingLoop) {
      loopRunning = session.autoLoopRunning
    }
  }

  $: if (!session && lastSessionId !== 0) {
    lastSessionId = 0
    diagnoseSeq += 1
    diagnosing = false
    diagnoseError = ''
  }

  $: scopeVariant = resolveScopeVariant(session?.scope)
  $: scopeLabel = resolveScopeLabel(session?.scope)
  $: confidencePct = result ? Math.round(Math.min(1, Math.max(0, Number(result.confidence) || 0)) * 100) : 0
  $: confidenceTone = confidencePct >= 75 ? 'success' : confidencePct >= 45 ? 'warning' : 'danger'

  $: validation = result?.validation || null
  $: validationIssues = getValidationIssues(validation)
  $: validationWarnings = Array.isArray(validation?.warnings) ? validation.warnings : []
  $: validationBlocked = Boolean(validation && !validation.passed)

  $: parsedDiff = parseUnifiedDiff(result?.unified_diff || '')
  $: patchedCodeLines = result?.patched_code ? String(result.patched_code).replace(/\r\n/g, '\n').split('\n') : []
  $: configEntries = result?.config_changes && typeof result.config_changes === 'object'
    ? Object.entries(result.config_changes)
    : []
  $: commandHints = Array.isArray(result?.command_hints) ? result.command_hints.filter(Boolean) : []
  $: showTimelineSection = Boolean(
    session?.canAutoLoop ||
    loopRunning ||
    autoHealResult ||
    liveEvents.length > 0
  )
  $: liveRoundGroups = groupLiveEventsByAttempt(liveEvents)
  $: finalHealedCodeAvailable = Boolean(
    autoHealResult &&
    autoHealResult.final_code &&
    autoHealResult.final_code !== currentCode &&
    session?.onApplyPatch
  )

  function resolveScopeVariant(scope) {
    switch (String(scope || '').toLowerCase()) {
      case 'unidbg':
      case 'qiling':
      case 'angr':
        return 'accent'
      case 'frida':
        return 'warning'
      case 'plugin':
      case 'signer':
        return 'purple'
      case 'recon':
        return 'info'
      case 'toolchain':
        return 'success'
      default:
        return 'neutral'
    }
  }

  function resolveScopeLabel(scope) {
    const norm = String(scope || 'general').toLowerCase()
    const key = `ai.scopes.${norm}`
    const translated = translate(key)
    return translated === key ? norm.toUpperCase() : translated
  }

  function resolvePhaseVariant(phase) {
    switch (String(phase || '').toLowerCase()) {
      case 'healed':
        return 'success'
      case 'running':
      case 'patching':
        return 'accent'
      case 'diagnosing':
        return 'purple'
      case 'validating':
        return 'info'
      case 'stopped':
        return 'warning'
      default:
        return 'neutral'
    }
  }

  function resolvePhaseIcon(phase) {
    switch (String(phase || '').toLowerCase()) {
      case 'healed':
        return 'check-circle'
      case 'running':
        return 'play'
      case 'diagnosing':
        return 'sparkles'
      case 'validating':
        return 'shield-check'
      case 'patching':
        return 'diff'
      case 'stopped':
        return 'alert-triangle'
      default:
        return 'activity'
    }
  }

  function resolveOutcomeVariant(outcome) {
    switch (String(outcome || '').toLowerCase()) {
      case 'healed':
      case 'already_ok':
        return 'success'
      case 'cancelled':
        return 'neutral'
      case 'failed':
      case 'validation_failed':
      case 'diagnose_error':
      case 'repeated_error':
        return 'danger'
      default:
        return 'warning'
    }
  }

  function labelForPhase(phase) {
    const k = `ai.phases.${phase}`
    const val = translate(k)
    return val === k ? String(phase || '') : val
  }

  function labelForStopReason(reason) {
    if (!reason) return ''
    const k = `ai.stopReasons.${reason}`
    const val = translate(k)
    return val === k ? String(reason) : val
  }

  function labelForFixKind(kind) {
    if (!kind) return ''
    const k = `ai.fixKinds.${kind}`
    const val = translate(k)
    return val === k ? String(kind) : val
  }

  function getValidationIssues(val) {
    if (!val || typeof val !== 'object') return []
    const out = []
    if (Array.isArray(val.issues)) out.push(...val.issues)
    if (Array.isArray(val.errors)) out.push(...val.errors)
    return out.filter(Boolean)
  }

  /**
   * Pure-Svelte unified diff parser — plain-text rendering only.
   * Returns { rows, added, removed }.
   */
  function parseUnifiedDiff(diffText) {
    if (!diffText || typeof diffText !== 'string') {
      return { rows: [], added: 0, removed: 0 }
    }
    const lines = diffText.replace(/\r\n/g, '\n').split('\n')
    const rows = []
    let oldLine = 0
    let newLine = 0
    let added = 0
    let removed = 0

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      // Skip trailing empty element caused by final newline
      if (i === lines.length - 1 && line === '') continue

      if (line.startsWith('--- ') || line.startsWith('+++ ')) {
        rows.push({ idx: i, type: 'meta', prefix: '', content: line, oldNum: '', newNum: '' })
      } else if (line.startsWith('@@')) {
        const m = line.match(/^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/)
        if (m) {
          oldLine = parseInt(m[1], 10)
          newLine = parseInt(m[2], 10)
        }
        rows.push({ idx: i, type: 'hunk', prefix: '@@', content: line, oldNum: '…', newNum: '…' })
      } else if (line.startsWith('+')) {
        added += 1
        rows.push({ idx: i, type: 'add', prefix: '+', content: line.slice(1), oldNum: '', newNum: newLine ? String(newLine++) : '' })
      } else if (line.startsWith('-')) {
        removed += 1
        rows.push({ idx: i, type: 'del', prefix: '-', content: line.slice(1), oldNum: oldLine ? String(oldLine++) : '', newNum: '' })
      } else if (line.startsWith('\\')) {
        rows.push({ idx: i, type: 'meta', prefix: '', content: line, oldNum: '', newNum: '' })
      } else {
        const content = line.startsWith(' ') ? line.slice(1) : line
        rows.push({
          idx: i,
          type: 'ctx',
          prefix: ' ',
          content,
          oldNum: oldLine ? String(oldLine++) : '',
          newNum: newLine ? String(newLine++) : '',
        })
      }
    }
    return { rows, added, removed }
  }

  function groupLiveEventsByAttempt(events) {
    const map = new Map()
    const order = []
    for (const ev of events) {
      const key = Number.isFinite(Number(ev?.attempt)) ? Number(ev.attempt) : 0
      if (!map.has(key)) {
        const group = {
          attempt: key,
          maxRetries: Number(ev?.max_retries) || $aiConfig.max_auto_retries || 3,
          phases: [],
          lastPhase: '',
          lastMessage: '',
          exitCode: 0,
          diagnosis: null,
          timestamp: '',
        }
        map.set(key, group)
        order.push(group)
      }
      const g = map.get(key)
      if (ev?.max_retries) g.maxRetries = Number(ev.max_retries)
      if (ev?.phase) {
        g.lastPhase = ev.phase
        if (g.phases[g.phases.length - 1] !== ev.phase) {
          g.phases.push(ev.phase)
        }
      }
      if (ev?.message) g.lastMessage = ev.message
      if (typeof ev?.exit_code === 'number') g.exitCode = ev.exit_code
      if (ev?.diagnosis) g.diagnosis = ev.diagnosis
      if (ev?.timestamp) g.timestamp = ev.timestamp
    }
    return order
  }

  function syncLatestDiagnosisFromAutoHeal(runRes) {
    if (!runRes || !Array.isArray(runRes.attempts)) return
    for (let i = runRes.attempts.length - 1; i >= 0; i--) {
      if (runRes.attempts[i]?.diagnosis) {
        result = runRes.attempts[i].diagnosis
        return
      }
    }
  }

  async function handleNewSession(sess) {
    lastSessionId = sess.sessionId
    diagnoseSeq += 1
    diagnosing = false
    diagnoseError = ''
    result = sess.initialResult || null
    currentCode = typeof sess.code === 'string' ? sess.code : ''
    diffViewMode = 'diff'
    preDiagOpen = false
    applyingPatch = false
    applyingConfig = false
    appliedConfigCount = 0
    loopRunning = Boolean(sess.autoLoopRunning)
    cancellingLoop = false
    liveEvents = []
    autoHealResult = sess.autoHealResult || null
    expandedRounds = {}

    if (autoHealResult) {
      syncLatestDiagnosisFromAutoHeal(autoHealResult)
    }

    const cfg = await refreshAIConfig()
    if (destroyed || $aiHealSession?.sessionId !== sess.sessionId) return

    const active = cfg.profiles.find((p) => p.id === cfg.active_profile_id)
    const configured = Boolean(active && active.enabled)

    if (sess.autoDiagnose && !result && !loopRunning && !autoHealResult && configured) {
      runDiagnose()
    }
  }

  async function runDiagnose() {
    const sess = $aiHealSession
    if (!sess) return
    const app = api()
    if (!app?.DiagnoseAndFixWithAI) {
      diagnoseError = translate('ai.settings.toast.backendUnavailable')
      return
    }

    const seq = ++diagnoseSeq
    diagnosing = true
    diagnoseError = ''
    appliedConfigCount = 0

    const req = {
      scope: sess.scope || 'general',
      code: currentCode,
      language: sess.language || '',
      error_text: sess.errorText || '',
      logs: sess.logs || '',
      metadata: sess.metadata || {},
      locale: $locale || 'en',
      profile_id: sess.profileId || '',
    }

    try {
      const res = await app.DiagnoseAndFixWithAI(req)
      if (destroyed || seq !== diagnoseSeq) return
      if (res && res.fix_kind === 'code_patch' && res.patched_code && !res.unified_diff && app.ComputeTextUnifiedDiff) {
        try {
          const computed = await app.ComputeTextUnifiedDiff(currentCode, res.patched_code)
          if (!destroyed && seq === diagnoseSeq && computed) {
            res.unified_diff = computed
          }
        } catch (_) {}
      }
      result = res
      diffViewMode = res?.unified_diff ? 'diff' : 'full'
    } catch (e) {
      if (destroyed || seq !== diagnoseSeq) return
      diagnoseError = e?.message || String(e)
    } finally {
      if (!destroyed && seq === diagnoseSeq) {
        diagnosing = false
      }
    }
  }

  async function handleApplyPatch(andRerun = false) {
    const sess = $aiHealSession
    if (!sess || !result?.patched_code || validationBlocked) return
    const callback = andRerun ? sess.onApplyAndRerun : sess.onApplyPatch
    if (!callback) return

    applyingPatch = true
    try {
      if (typeof currentCode === 'string') {
        aiUndoStack.push(undoKey, currentCode, {
          title: sess.title || '',
          language: sess.language || '',
        })
      }
      const nextCode = result.patched_code
      const cbRet = await callback(nextCode, result)
      if (destroyed) return
      currentCode = nextCode
      updateAIHealSession({ code: nextCode })
      toast.success(
        translate(andRerun ? 'ai.drawer.toast.patchAppliedAndRerun' : 'ai.drawer.toast.patchApplied')
      )
      if (andRerun && cbRet !== false) {
        closeAIHealModal()
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.drawer.toast.patchApplyFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) applyingPatch = false
    }
  }

  async function handleApplyFinalHealedCode() {
    const sess = $aiHealSession
    if (!sess?.onApplyPatch || !autoHealResult?.final_code) return
    applyingPatch = true
    try {
      if (typeof currentCode === 'string') {
        aiUndoStack.push(undoKey, currentCode, {
          title: sess.title || '',
          language: sess.language || '',
        })
      }
      await sess.onApplyPatch(autoHealResult.final_code, autoHealResult)
      if (destroyed) return
      currentCode = autoHealResult.final_code
      updateAIHealSession({ code: autoHealResult.final_code })
      toast.success(translate('ai.drawer.toast.patchApplied'))
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.drawer.toast.patchApplyFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) applyingPatch = false
    }
  }

  async function handleUndoPatch() {
    const sess = $aiHealSession
    if (!sess?.onApplyPatch) return
    const backup = aiUndoStack.pop(undoKey)
    if (!backup) return

    applyingPatch = true
    try {
      await sess.onApplyPatch(backup.code, { undo: true, scope: sess.scope })
      if (destroyed) return
      currentCode = backup.code
      updateAIHealSession({ code: backup.code })
      toast.info(translate('ai.drawer.toast.patchUndone'))
    } catch (e) {
      // Restore popped entry if undo failed
      aiUndoStack.push(undoKey, backup.code, { title: backup.title, language: backup.language })
      if (!destroyed) {
        toast.error(translate('ai.drawer.toast.undoFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) applyingPatch = false
    }
  }

  async function handleApplyConfigChanges() {
    const app = api()
    const sess = $aiHealSession
    if (!app?.ApplyAIConfigChanges || configEntries.length === 0) return

    applyingConfig = true
    try {
      const applied = await app.ApplyAIConfigChanges(result.config_changes)
      if (destroyed) return
      const count = applied && typeof applied === 'object' ? Object.keys(applied).length : configEntries.length
      appliedConfigCount = count
      if (sess?.onApplyConfig) {
        await sess.onApplyConfig(applied || result.config_changes)
      }
      if (!destroyed) {
        toast.success(translate('ai.drawer.toast.configApplied', { count }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.drawer.toast.configApplyFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) applyingConfig = false
    }
  }

  async function handleStartAutoLoop() {
    const sess = $aiHealSession
    if (!sess?.onRunAutoLoop || loopRunning) return

    loopRunning = true
    cancellingLoop = false
    liveEvents = []
    autoHealResult = null
    expandedRounds = {}
    updateAIHealSession({ autoLoopRunning: true, autoHealResult: null })

    try {
      const res = await sess.onRunAutoLoop({
        maxRetries: $aiConfig.max_auto_retries || 3,
        locale: $locale || 'en',
      })
      if (destroyed) return
      if (res && typeof res === 'object' && ('healed' in res || Array.isArray(res.attempts))) {
        autoHealResult = res
        updateAIHealSession({ autoHealResult: res, autoLoopRunning: false })
        syncLatestDiagnosisFromAutoHeal(res)
        if (res.healed) {
          toast.success(translate('ai.drawer.toast.autoHealHealed'))
        } else {
          toast.info(
            translate('ai.drawer.toast.autoHealStopped', {
              reason: labelForStopReason(res.stop_reason) || res.stop_reason || '',
            })
          )
        }
      } else {
        updateAIHealSession({ autoLoopRunning: false })
      }
    } catch (e) {
      if (!destroyed) {
        updateAIHealSession({ autoLoopRunning: false })
        toast.error(translate('ai.drawer.toast.autoHealFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) {
        loopRunning = false
        cancellingLoop = false
      }
    }
  }

  async function handleCancelAutoHeal() {
    const app = api()
    if (!app?.CancelAIAutoHeal) return
    cancellingLoop = true
    try {
      await app.CancelAIAutoHeal()
      if (!destroyed) {
        toast.info(translate('ai.drawer.toast.autoHealCancelled'))
      }
    } catch (e) {
      if (!destroyed) {
        cancellingLoop = false
        toast.error(translate('ai.drawer.toast.autoHealCancelFailed', { error: e?.message || e }))
      }
    }
  }

  function handleHealEvent(ev) {
    if (destroyed || !$aiHealSession || !ev) return
    liveEvents = [...liveEvents, ev]
    if (ev.phase === 'running' || ev.phase === 'diagnosing' || ev.phase === 'validating' || ev.phase === 'patching') {
      loopRunning = true
    } else if (ev.phase === 'healed' || ev.phase === 'stopped') {
      loopRunning = false
      cancellingLoop = false
    }
    if (ev.diagnosis) {
      result = ev.diagnosis
    }
  }

  function toggleRoundExpanded(idx) {
    expandedRounds = { ...expandedRounds, [idx]: !expandedRounds[idx] }
  }

  function openAISettings() {
    const customNav = $aiHealSession?.onNavigateSettings
    closeAIHealModal()
    requestOpenAISettings()
    if (customNav) {
      customNav()
    } else {
      navigate('settings')
    }
  }

  function handleClose() {
    closeAIHealModal()
  }

  function handleKeydown(e) {
    if (!$aiHealSession) return
    if (e.key === 'Escape') {
      e.preventDefault()
      handleClose()
    }
  }

  onMount(() => {
    const rt = runtimeApi()
    if (rt?.EventsOn) {
      const off = rt.EventsOn('ai:heal', handleHealEvent)
      if (typeof off === 'function') {
        unsubHealEvent = off
      }
    }
    refreshAIConfig()
  })

  onDestroy(() => {
    destroyed = true
    if (typeof unsubHealEvent === 'function') {
      try {
        unsubHealEvent()
      } catch (_) {}
      unsubHealEvent = null
    }
  })
</script>

<svelte:window on:keydown={handleKeydown} />

{#if session}
  <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
  <div
    class="drawer-backdrop"
    transition:fade={{ duration: 130 }}
    on:click|self={handleClose}
  >
    <div
      class="drawer-panel"
      role="dialog"
      aria-modal="true"
      aria-label={session.title || $t('ai.drawer.defaultTitle')}
      transition:fly={{ x: 40, duration: 160 }}
    >
      <!-- Header -->
      <header class="drawer-header">
        <div class="header-left">
          <div class="header-title-row">
            <Badge variant={scopeVariant} size="sm" mono>{scopeLabel}</Badge>
            <h3 class="drawer-title truncate">{session.title || $t('ai.drawer.defaultTitle')}</h3>
          </div>
          <div class="header-model-row">
            {#if $isAIConfigured && $activeAIProfile}
              <span class="model-pill mono">
                <Icon name="sparkles" size={12} />
                <span>{$activeAIProfile.name || $activeAIProfile.provider}</span>
                <span class="pill-sep">·</span>
                <span class="pill-model">{$activeAIProfile.model}</span>
              </span>
            {:else}
              <Button variant="primary" size="xs" icon="settings" iconRight="arrow-right" on:click={openAISettings}>
                {$t('ai.drawer.configureCta')}
              </Button>
            {/if}
          </div>
        </div>

        <div class="header-actions">
          <Button
            variant="secondary"
            size="xs"
            icon="refresh"
            loading={diagnosing}
            disabled={!$isAIConfigured || loopRunning}
            on:click={runDiagnose}
          >
            {diagnosing ? $t('ai.drawer.diagnosingBtn') : $t('ai.drawer.reDiagnose')}
          </Button>
          <Button
            variant="ghost"
            size="xs"
            iconOnly
            icon="x"
            title={$t('ai.drawer.closeAria')}
            aria-label={$t('ai.drawer.closeAria')}
            on:click={handleClose}
          />
        </div>
      </header>

      <!-- Scrollable Body -->
      <div class="drawer-body">
        <!-- Multi-Round Auto-Heal Timeline -->
        {#if showTimelineSection}
          <section class="section-card cap-card timeline-card">
            <div class="section-head">
              <div class="section-title-col">
                <div class="section-title">
                  <Icon name="repeat" size={14} />
                  <span>{$t('ai.drawer.timeline.title')}</span>
                </div>
                <div class="section-sub">{$t('ai.drawer.timeline.subtitle')}</div>
              </div>
              <div class="timeline-controls">
                {#if loopRunning}
                  <Badge variant="accent" size="xs" dot pulse>{$t('ai.drawer.timeline.statusRunning')}</Badge>
                  <Button
                    variant="danger"
                    size="xs"
                    icon="square"
                    loading={cancellingLoop}
                    on:click={handleCancelAutoHeal}
                  >
                    {cancellingLoop ? $t('ai.drawer.timeline.stoppingBtn') : $t('ai.drawer.timeline.stopBtn')}
                  </Button>
                {:else if autoHealResult}
                  <Badge variant={autoHealResult.healed ? 'success' : 'warning'} size="xs" dot>
                    {autoHealResult.healed
                      ? $t('ai.drawer.timeline.statusHealed')
                      : $t('ai.drawer.timeline.statusStopped')}
                  </Badge>
                  {#if autoHealResult.stop_reason}
                    <Badge variant={resolveOutcomeVariant(autoHealResult.stop_reason)} size="xs">
                      {labelForStopReason(autoHealResult.stop_reason)}
                    </Badge>
                  {/if}
                {:else}
                  <Badge variant="neutral" size="xs">{$t('ai.drawer.timeline.statusReady')}</Badge>
                {/if}

                {#if session.canAutoLoop && session.onRunAutoLoop && !loopRunning && $isAIConfigured}
                  <Button variant="primary" size="xs" icon="play" on:click={handleStartAutoLoop}>
                    {$t('ai.drawer.timeline.runLoopBtn', { max: $aiConfig.max_auto_retries || 3 })}
                  </Button>
                {/if}
              </div>
            </div>

            {#if session.canAutoLoop && !$aiConfig.auto_heal_enabled && !loopRunning && !autoHealResult}
              <div class="subtle-hint">
                <Icon name="info" size={12} />
                <span>{$t('ai.drawer.timeline.autoHealDisabledHint')}</span>
              </div>
            {/if}

            <!-- Live Event Stream Stepper -->
            {#if liveRoundGroups.length > 0}
              <div class="live-stepper">
                {#each liveRoundGroups as grp (grp.attempt)}
                  <div class="live-round-row">
                    <div class="live-round-head">
                      <span class="round-label mono">
                        {grp.attempt === 0
                          ? $t('ai.drawer.timeline.initialRun')
                          : $t('ai.drawer.timeline.roundLabel', { round: grp.attempt, max: grp.maxRetries })}
                      </span>
                      <div class="phase-trail">
                        {#each grp.phases as ph, idx (ph + idx)}
                          {#if idx > 0}
                            <span class="trail-arrow">→</span>
                          {/if}
                          <Badge variant={resolvePhaseVariant(ph)} size="xs">
                            <Icon name={resolvePhaseIcon(ph)} size={10} />
                            <span>{labelForPhase(ph)}</span>
                          </Badge>
                        {/each}
                      </div>
                      {#if grp.timestamp}
                        <span class="round-ts mono tabular-nums">{formatTime(grp.timestamp)}</span>
                      {/if}
                    </div>
                    {#if grp.lastMessage}
                      <div class="live-round-msg">{grp.lastMessage}</div>
                    {/if}
                  </div>
                {/each}
              </div>
            {:else if loopRunning}
              <div class="loading-inline">
                <span class="mini-spinner" aria-hidden="true"></span>
                <span>{$t('ai.drawer.timeline.waitingEvents')}</span>
              </div>
            {/if}

            <!-- Completed Auto-Heal Attempts (Expandable Diff & Logs) -->
            {#if autoHealResult && Array.isArray(autoHealResult.attempts) && autoHealResult.attempts.length > 0}
              <div class="attempt-summary-bar">
                <span class="mono tabular-nums">
                  {$t('ai.drawer.timeline.finalSummary', {
                    duration: formatDuration(autoHealResult.total_elapsed_ms),
                    attempts: autoHealResult.attempts.length,
                    code: autoHealResult.final_exit_code,
                  })}
                </span>
                {#if finalHealedCodeAvailable}
                  <Button variant="success" size="xs" icon="check" loading={applyingPatch} on:click={handleApplyFinalHealedCode}>
                    {$t('ai.drawer.timeline.applyFinalCode')}
                  </Button>
                {/if}
              </div>

              <div class="attempt-list">
                {#each autoHealResult.attempts as att, idx (idx)}
                  {@const isOpen = Boolean(expandedRounds[idx])}
                  {@const roundDiff = parseUnifiedDiff(att.diagnosis?.unified_diff || '')}
                  <div class="attempt-item">
                    <button
                      type="button"
                      class="attempt-toggle"
                      on:click={() => toggleRoundExpanded(idx)}
                    >
                      <span class="attempt-left">
                        <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={13} />
                        <span class="attempt-name mono">
                          {att.attempt === 0
                            ? $t('ai.drawer.timeline.initialRun')
                            : $t('ai.drawer.timeline.roundShort', { round: att.attempt })}
                        </span>
                        <Badge variant={resolveOutcomeVariant(att.outcome)} size="xs">
                          {labelForStopReason(att.outcome) || att.outcome}
                        </Badge>
                        <Badge variant={att.exit_code === 0 ? 'success' : 'neutral'} size="xs" mono>
                          {$t('ai.drawer.timeline.exitCode', { code: att.exit_code })}
                        </Badge>
                        {#if att.applied_patch}
                          <Badge variant="accent" size="xs">{$t('ai.drawer.timeline.patchApplied')}</Badge>
                        {/if}
                      </span>
                      <span class="attempt-right mono tabular-nums">
                        {formatDuration(att.elapsed_ms)}
                      </span>
                    </button>

                    {#if isOpen}
                      <div class="attempt-detail">
                        {#if att.diagnosis}
                          <div class="detail-block">
                            <div class="detail-label">{$t('ai.drawer.timeline.roundDiagnosis')}</div>
                            <div class="round-root-cause">{att.diagnosis.root_cause}</div>
                            {#if att.diagnosis.explanation}
                              <div class="round-explanation">{att.diagnosis.explanation}</div>
                            {/if}
                          </div>
                        {/if}

                        {#if roundDiff.rows.length > 0}
                          <div class="detail-block">
                            <div class="detail-label">{$t('ai.drawer.timeline.roundDiff')}</div>
                            <div class="diff-box compact mono">
                              {#each roundDiff.rows as row (row.idx)}
                                <div class="diff-row t-{row.type}">
                                  <span class="diff-ln tabular-nums">{row.oldNum}</span>
                                  <span class="diff-ln tabular-nums">{row.newNum}</span>
                                  <span class="diff-sign">{row.prefix}</span>
                                  <span class="diff-text">{row.content}</span>
                                </div>
                              {/each}
                            </div>
                          </div>
                        {/if}

                        {#if att.logs}
                          <div class="detail-block">
                            <div class="detail-head">
                              <span class="detail-label">{$t('ai.drawer.timeline.roundLogs')}</span>
                              <Button
                                variant="ghost"
                                size="xs"
                                icon="copy"
                                on:click={() => copyToClipboard(att.logs, translate('ai.drawer.toast.logsCopied'))}
                              >
                                {$t('ai.drawer.timeline.copyLogs')}
                              </Button>
                            </div>
                            <pre class="log-pre mono">{att.logs}</pre>
                          </div>
                        {/if}
                      </div>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          </section>
        {/if}

        <!-- Primary Diagnosis Area -->
        {#if !$isAIConfigured && !result && !diagnosing}
          <section class="state-card cap-card">
            <div class="state-icon accent">
              <Icon name="sparkles" size={20} />
            </div>
            <div class="state-title">{$t('ai.drawer.noProfileTitle')}</div>
            <div class="state-desc">{$t('ai.drawer.noProfileDesc')}</div>
            <Button variant="primary" size="sm" icon="settings" iconRight="arrow-right" on:click={openAISettings}>
              {$t('ai.drawer.configureCta')}
            </Button>
          </section>
        {:else if diagnosing}
          <section class="state-card cap-card">
            <div class="big-spinner" aria-hidden="true"></div>
            <div class="state-title">{$t('ai.drawer.loadingTitle')}</div>
            <div class="state-desc">{$t('ai.drawer.loadingDesc')}</div>
          </section>
        {:else if diagnoseError}
          <section class="error-card cap-card">
            <div class="error-head">
              <Icon name="alert-circle" size={16} />
              <span>{$t('ai.drawer.errorTitle')}</span>
            </div>
            <div class="error-msg mono">{diagnoseError}</div>
            <div class="error-actions">
              <Button variant="secondary" size="xs" icon="refresh" on:click={runDiagnose}>
                {$t('ai.drawer.retryBtn')}
              </Button>
              <Button variant="ghost" size="xs" icon="settings" on:click={openAISettings}>
                {$t('ai.drawer.configureCta')}
              </Button>
            </div>
          </section>
        {:else if !result}
          <section class="state-card cap-card">
            <div class="state-icon neutral">
              <Icon name="sparkles" size={18} />
            </div>
            <div class="state-title">{$t('ai.drawer.idleTitle')}</div>
            <div class="state-desc">{$t('ai.drawer.idleDesc')}</div>
            <Button variant="primary" size="sm" icon="refresh" disabled={!$isAIConfigured} on:click={runDiagnose}>
              {$t('ai.drawer.reDiagnose')}
            </Button>
          </section>
        {:else}
          <!-- Diagnosis Summary Card -->
          <section class="section-card cap-card">
            <div class="section-head">
              <div class="section-title">
                <Icon name="sparkles" size={14} />
                <span>{$t('ai.drawer.diagnosis.sectionTitle')}</span>
              </div>
              <div class="diag-badges">
                {#if result.error_category}
                  <Badge variant="warning" size="xs" mono>{result.error_category}</Badge>
                {/if}
                {#if result.fix_kind}
                  <Badge variant="accent" size="xs">{labelForFixKind(result.fix_kind)}</Badge>
                {/if}
                {#if result.redacted_count > 0}
                  <Badge variant="success" size="xs">
                    <Icon name="shield-check" size={11} />
                    <span>{$t('ai.drawer.diagnosis.secretsScrubbed', { count: result.redacted_count })}</span>
                  </Badge>
                {:else if $aiConfig.redact_secrets}
                  <Badge variant="neutral" size="xs">
                    <Icon name="shield-check" size={11} />
                    <span>{$t('ai.drawer.diagnosis.privacyProtected')}</span>
                  </Badge>
                {/if}
              </div>
            </div>

            <div class="root-cause-box">
              <div class="micro-label">{$t('ai.drawer.diagnosis.rootCause')}</div>
              <div class="root-cause-text">{result.root_cause}</div>
            </div>

            <!-- Confidence Bar & Telemetry -->
            <div class="telemetry-row">
              <div class="confidence-box">
                <div class="confidence-head">
                  <span class="micro-label">{$t('ai.drawer.diagnosis.confidence')}</span>
                  <span class="confidence-val mono tabular-nums tone-{confidenceTone}">{confidencePct}%</span>
                </div>
                <div class="confidence-track">
                  <div class="confidence-fill tone-{confidenceTone}" style="width: {confidencePct}%;"></div>
                </div>
              </div>

              <div class="telemetry-pills mono">
                {#if result.provider_used || result.model_used}
                  <span class="tele-pill">
                    <Icon name="cpu" size={11} />
                    <span>{result.provider_used}{result.model_used ? ` · ${result.model_used}` : ''}</span>
                  </span>
                {/if}
                <span class="tele-pill tabular-nums">
                  <Icon name="clock" size={11} />
                  <span>{formatDuration(result.elapsed_ms)}</span>
                </span>
                {#if result.prompt_tokens > 0 || result.completion_tokens > 0}
                  <span class="tele-pill tabular-nums">
                    {$t('ai.drawer.diagnosis.tokens', {
                      prompt: result.prompt_tokens || 0,
                      completion: result.completion_tokens || 0,
                    })}
                  </span>
                {/if}
              </div>
            </div>

            {#if result.explanation}
              <div class="explanation-box">
                <div class="micro-label">{$t('ai.drawer.diagnosis.explanation')}</div>
                <p class="explanation-text">{result.explanation}</p>
              </div>
            {/if}

            {#if result.verify_hint}
              <div class="verify-box">
                <Icon name="check-circle" size={13} />
                <div>
                  <span class="verify-label">{$t('ai.drawer.diagnosis.verifyHint')}:</span>
                  <span>{result.verify_hint}</span>
                </div>
              </div>
            {/if}

            {#if result.pre_diagnosis}
              <div class="prediag-wrap">
                <button
                  type="button"
                  class="prediag-toggle"
                  on:click={() => (preDiagOpen = !preDiagOpen)}
                >
                  <Icon name={preDiagOpen ? 'chevron-down' : 'chevron-right'} size={13} />
                  <span>{$t('ai.drawer.diagnosis.preDiagnosisToggle')}</span>
                </button>
                {#if preDiagOpen}
                  <pre class="prediag-pre mono">{result.pre_diagnosis}</pre>
                {/if}
              </div>
            {/if}
          </section>

          <!-- Safety & Patch Validation Strip -->
          {#if validation}
            <section class="validation-strip" class:passed={validation.passed} class:failed={!validation.passed}>
              <div class="val-head">
                <div class="val-status">
                  <Icon name={validation.passed ? 'shield-check' : 'alert-triangle'} size={15} />
                  <span class="val-title">{$t('ai.drawer.validation.title')}</span>
                  <Badge variant={validation.passed ? 'success' : 'danger'} size="xs" mono>
                    {validation.passed ? $t('ai.drawer.validation.passed') : $t('ai.drawer.validation.failed')}
                  </Badge>
                </div>
                {#if validation.validator}
                  <span class="val-engine mono">
                    {$t('ai.drawer.validation.validatorLabel', { validator: validation.validator })}
                  </span>
                {/if}
              </div>

              {#if !validation.passed}
                <div class="val-blocked-msg">{$t('ai.drawer.validation.blockedNotice')}</div>
              {/if}

              {#if validationIssues.length > 0}
                <div class="val-list">
                  <div class="val-list-head danger">{$t('ai.drawer.validation.issuesHeading')}</div>
                  {#each validationIssues as issue, i (i)}
                    <div class="val-item mono danger">
                      <Icon name="x-circle" size={12} />
                      <span>{issue}</span>
                    </div>
                  {/each}
                </div>
              {/if}

              {#if validationWarnings.length > 0}
                <div class="val-list">
                  <div class="val-list-head warn">{$t('ai.drawer.validation.warningsHeading')}</div>
                  {#each validationWarnings as warn, i (i)}
                    <div class="val-item mono warn">
                      <Icon name="alert-triangle" size={12} />
                      <span>{warn}</span>
                    </div>
                  {/each}
                </div>
              {/if}
            </section>
          {/if}

          <!-- Pure-Svelte Unified Diff & Patched Code Viewer -->
          {#if result.fix_kind === 'code_patch' || result.unified_diff || result.patched_code}
            <section class="section-card cap-card">
              <div class="diff-toolbar">
                <div class="diff-title-group">
                  <span class="section-title">
                    <Icon name="diff" size={14} />
                    <span>{$t('ai.drawer.diff.title')}</span>
                  </span>
                  {#if parsedDiff.added > 0 || parsedDiff.removed > 0}
                    <div class="diff-stats mono tabular-nums">
                      <span class="stat-add">{$t('ai.drawer.diff.addedLines', { count: parsedDiff.added })}</span>
                      <span class="stat-del">{$t('ai.drawer.diff.removedLines', { count: parsedDiff.removed })}</span>
                    </div>
                  {/if}
                </div>

                <div class="diff-controls">
                  <div class="segmented">
                    <button
                      type="button"
                      class="seg-btn"
                      class:active={diffViewMode === 'diff'}
                      on:click={() => (diffViewMode = 'diff')}
                    >
                      <Icon name="diff" size={12} />
                      <span>{$t('ai.drawer.diff.tabDiff')}</span>
                    </button>
                    <button
                      type="button"
                      class="seg-btn"
                      class:active={diffViewMode === 'full'}
                      on:click={() => (diffViewMode = 'full')}
                    >
                      <Icon name="file-code" size={12} />
                      <span>{$t('ai.drawer.diff.tabFull')}</span>
                    </button>
                  </div>

                  {#if diffViewMode === 'diff' && result.unified_diff}
                    <Button
                      variant="secondary"
                      size="xs"
                      icon="copy"
                      on:click={() => copyToClipboard(result.unified_diff, translate('ai.drawer.toast.diffCopied'))}
                    >
                      {$t('ai.drawer.diff.copyDiff')}
                    </Button>
                  {:else if result.patched_code}
                    <Button
                      variant="secondary"
                      size="xs"
                      icon="copy"
                      on:click={() => copyToClipboard(result.patched_code, translate('ai.drawer.toast.codeCopied'))}
                    >
                      {$t('ai.drawer.diff.copyCode')}
                    </Button>
                  {/if}
                </div>
              </div>

              {#if diffViewMode === 'diff'}
                {#if parsedDiff.rows.length > 0}
                  <div class="diff-box mono">
                    {#each parsedDiff.rows as row (row.idx)}
                      <div class="diff-row t-{row.type}">
                        <span class="diff-ln tabular-nums">{row.oldNum}</span>
                        <span class="diff-ln tabular-nums">{row.newNum}</span>
                        <span class="diff-sign">{row.prefix}</span>
                        <span class="diff-text">{row.content}</span>
                      </div>
                    {/each}
                  </div>
                {:else}
                  <div class="empty-code-msg">{$t('ai.drawer.diff.noDiffChanges')}</div>
                {/if}
              {:else if patchedCodeLines.length > 0}
                <div class="diff-box mono">
                  {#each patchedCodeLines as line, i (i)}
                    <div class="diff-row t-ctx">
                      <span class="diff-ln single tabular-nums">{i + 1}</span>
                      <span class="diff-text">{line}</span>
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="empty-code-msg">{$t('ai.drawer.diff.noCodeAvailable')}</div>
              {/if}
            </section>
          {/if}

          <!-- Proposed Safe Configuration Changes -->
          {#if configEntries.length > 0}
            <section class="section-card cap-card">
              <div class="section-head">
                <div class="section-title-col">
                  <div class="section-title">
                    <Icon name="sliders" size={14} />
                    <span>{$t('ai.drawer.configFix.title')}</span>
                  </div>
                  <div class="section-sub">{$t('ai.drawer.configFix.desc')}</div>
                </div>
                <Button
                  variant={appliedConfigCount > 0 ? 'success' : 'primary'}
                  size="xs"
                  icon={appliedConfigCount > 0 ? 'check' : 'settings'}
                  loading={applyingConfig}
                  disabled={appliedConfigCount > 0}
                  on:click={handleApplyConfigChanges}
                >
                  {appliedConfigCount > 0
                    ? $t('ai.drawer.configFix.appliedBtn')
                    : $t('ai.drawer.configFix.applyBtn')}
                </Button>
              </div>

              <div class="config-table">
                <div class="config-row head">
                  <span>{$t('ai.drawer.configFix.keyCol')}</span>
                  <span>{$t('ai.drawer.configFix.valueCol')}</span>
                </div>
                {#each configEntries as [k, v] (k)}
                  <div class="config-row">
                    <span class="cfg-key mono">{k}</span>
                    <span class="cfg-val mono">{v}</span>
                  </div>
                {/each}
              </div>

              {#if appliedConfigCount > 0}
                <div class="applied-note">
                  <Icon name="check-circle" size={12} />
                  <span>{$t('ai.drawer.configFix.appliedCount', { count: appliedConfigCount })}</span>
                </div>
              {/if}
            </section>
          {/if}

          <!-- Advisory Command Hints (NEVER auto-executes) -->
          {#if commandHints.length > 0}
            <section class="section-card cap-card">
              <div class="section-head">
                <div class="section-title">
                  <Icon name="terminal" size={14} />
                  <span>{$t('ai.drawer.commandHints.title')}</span>
                </div>
                <Badge variant="warning" size="xs">
                  <Icon name="alert-triangle" size={11} />
                  <span>{$t('ai.drawer.commandHints.manualBadge')}</span>
                </Badge>
              </div>

              <div class="cmd-list">
                {#each commandHints as cmd, i (i)}
                  <div class="cmd-card">
                    <code class="cmd-code mono">{cmd}</code>
                    <Button
                      variant="secondary"
                      size="xs"
                      icon="copy"
                      on:click={() => copyToClipboard(cmd, translate('ai.drawer.toast.commandCopied'))}
                    >
                      {$t('ai.drawer.commandHints.copyCmd')}
                    </Button>
                  </div>
                {/each}
              </div>
            </section>
          {/if}
        {/if}
      </div>

      <!-- Sticky Action Footer -->
      <footer class="drawer-footer">
        <div class="footer-left">
          {#if hasUndoBackup}
            <Button
              variant="secondary"
              size="sm"
              icon="undo"
              loading={applyingPatch}
              on:click={handleUndoPatch}
            >
              {undoEntries.length > 1
                ? $t('ai.drawer.footer.undoCount', { count: undoEntries.length })
                : $t('ai.drawer.footer.undoBtn')}
            </Button>
          {/if}
        </div>

        <div class="footer-right">
          {#if result?.fix_kind === 'config_fix' && configEntries.length > 0}
            <Button
              variant={appliedConfigCount > 0 ? 'success' : 'primary'}
              size="sm"
              icon={appliedConfigCount > 0 ? 'check' : 'settings'}
              loading={applyingConfig}
              disabled={appliedConfigCount > 0}
              on:click={handleApplyConfigChanges}
            >
              {appliedConfigCount > 0
                ? $t('ai.drawer.configFix.appliedBtn')
                : $t('ai.drawer.configFix.applyBtn')}
            </Button>
          {/if}

          {#if result?.fix_kind === 'code_patch' && result?.patched_code}
            {#if session.onApplyPatch}
              <Button
                variant="secondary"
                size="sm"
                icon="check"
                loading={applyingPatch}
                disabled={validationBlocked}
                on:click={() => handleApplyPatch(false)}
              >
                {$t('ai.drawer.footer.applyBtn')}
              </Button>
            {/if}
            {#if session.onApplyAndRerun}
              <Button
                variant="primary"
                size="sm"
                icon="play"
                loading={applyingPatch}
                disabled={validationBlocked}
                on:click={() => handleApplyPatch(true)}
              >
                {$t('ai.drawer.footer.applyAndRerunBtn')}
              </Button>
            {/if}
          {/if}

          <Button variant="ghost" size="sm" on:click={handleClose}>
            {$t('ai.drawer.footer.closeBtn')}
          </Button>
        </div>
      </footer>
    </div>
  </div>
{/if}

<style>
  .drawer-backdrop {
    position: fixed;
    inset: 0;
    z-index: var(--z-modal);
    background: rgba(0, 0, 0, 0.56);
    backdrop-filter: blur(4px);
    display: flex;
    justify-content: flex-end;
  }

  .drawer-panel {
    width: min(760px, calc(100vw - 28px));
    height: 100%;
    background: var(--bg-app);
    border-left: 1px solid var(--border-strong);
    box-shadow: var(--shadow-lg);
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  /* Header */
  .drawer-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 18px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .header-left {
    display: flex;
    flex-direction: column;
    gap: 7px;
    min-width: 0;
    flex: 1;
  }

  .header-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .drawer-title {
    font-size: var(--text-md);
    font-weight: 600;
    color: var(--text-primary);
    min-width: 0;
  }

  .header-model-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .model-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 8px;
    border-radius: var(--radius-full);
    background: var(--accent-soft);
    border: 1px solid var(--accent-border);
    color: var(--accent);
    font-size: 11px;
    font-weight: 500;
  }

  .pill-sep {
    opacity: 0.55;
  }

  .pill-model {
    color: var(--text-primary);
    font-weight: 600;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  /* Body */
  .drawer-body {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .section-card {
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .timeline-card {
    border-color: var(--accent-border);
  }

  .section-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .section-title-col {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .section-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .section-sub {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  /* Empty / Loading / Error states */
  .state-card {
    padding: 30px 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 10px;
  }

  .state-icon {
    width: 42px;
    height: 42px;
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .state-icon.accent {
    background: var(--accent-soft);
    border: 1px solid var(--accent-border);
    color: var(--accent);
  }

  .state-icon.neutral {
    background: var(--bg-subtle);
    border: 1px solid var(--border-default);
    color: var(--text-muted);
  }

  .state-title {
    font-size: var(--text-md);
    font-weight: 600;
    color: var(--text-primary);
  }

  .state-desc {
    max-width: 460px;
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.55;
  }

  .big-spinner {
    width: 28px;
    height: 28px;
    border: 2.5px solid var(--accent-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: cap-spin 0.7s linear infinite;
  }

  .mini-spinner {
    width: 13px;
    height: 13px;
    border: 2px solid var(--accent-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: cap-spin 0.7s linear infinite;
    flex-shrink: 0;
  }

  .error-card {
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    border-color: var(--status-danger-border);
    background: color-mix(in srgb, var(--status-danger) 6%, var(--bg-surface));
  }

  .error-head {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--status-danger);
  }

  .error-msg {
    font-size: var(--text-xs);
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    padding: 8px 10px;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .error-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* Diagnosis Card */
  .diag-badges {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .micro-label {
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
  }

  .root-cause-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
  }

  .root-cause-text {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
    line-height: 1.45;
  }

  .telemetry-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    flex-wrap: wrap;
  }

  .confidence-box {
    min-width: 170px;
    flex: 1;
    max-width: 240px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .confidence-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .confidence-val {
    font-size: var(--text-xs);
    font-weight: 700;
  }

  .confidence-val.tone-success {
    color: var(--status-success);
  }

  .confidence-val.tone-warning {
    color: var(--status-warning);
  }

  .confidence-val.tone-danger {
    color: var(--status-danger);
  }

  .confidence-track {
    height: 6px;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    overflow: hidden;
  }

  .confidence-fill {
    height: 100%;
    border-radius: var(--radius-full);
    transition: width var(--transition-base);
  }

  .confidence-fill.tone-success {
    background: var(--status-success);
  }

  .confidence-fill.tone-warning {
    background: var(--status-warning);
  }

  .confidence-fill.tone-danger {
    background: var(--status-danger);
  }

  .telemetry-pills {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .tele-pill {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 7px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-size: 11px;
  }

  .explanation-box {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .explanation-text {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: 1.55;
    white-space: pre-wrap;
  }

  .verify-box {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--status-info-bg);
    border: 1px solid var(--status-info-border);
    color: var(--status-info);
    font-size: var(--text-xs);
    line-height: 1.45;
  }

  .verify-label {
    font-weight: 600;
    margin-right: 4px;
  }

  .prediag-wrap {
    border-top: 1px solid var(--border-subtle);
    padding-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .prediag-toggle {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    padding: 2px 0;
    align-self: flex-start;
  }

  .prediag-toggle:hover {
    color: var(--text-primary);
  }

  .prediag-pre {
    margin: 0;
    padding: 9px 11px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-size: 11px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 180px;
    overflow-y: auto;
  }

  /* Safety & Patch Validation Strip */
  .validation-strip {
    padding: 12px 14px;
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .validation-strip.passed {
    background: color-mix(in srgb, var(--status-success) 7%, var(--bg-surface));
    border-color: var(--status-success-border);
  }

  .validation-strip.failed {
    background: color-mix(in srgb, var(--status-danger) 8%, var(--bg-surface));
    border-color: var(--status-danger-border);
  }

  .val-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .val-status {
    display: inline-flex;
    align-items: center;
    gap: 7px;
  }

  .validation-strip.passed .val-status {
    color: var(--status-success);
  }

  .validation-strip.failed .val-status {
    color: var(--status-danger);
  }

  .val-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .val-engine {
    font-size: 11px;
    color: var(--text-muted);
  }

  .val-blocked-msg {
    font-size: var(--text-xs);
    color: var(--status-danger);
    line-height: 1.45;
  }

  .val-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .val-list-head {
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .val-list-head.danger {
    color: var(--status-danger);
  }

  .val-list-head.warn {
    color: var(--status-warning);
  }

  .val-item {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    font-size: 11px;
    line-height: 1.45;
    padding: 5px 8px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    word-break: break-word;
  }

  .val-item.danger {
    color: var(--status-danger);
    border: 1px solid var(--status-danger-border);
  }

  .val-item.warn {
    color: var(--status-warning);
    border: 1px solid var(--status-warning-border);
  }

  /* Pure-Svelte Unified Diff Viewer */
  .diff-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .diff-title-group {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .diff-stats {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    font-weight: 600;
  }

  .stat-add {
    color: var(--status-success);
  }

  .stat-del {
    color: var(--status-danger);
  }

  .diff-controls {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .segmented {
    display: inline-flex;
    padding: 2px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    gap: 2px;
  }

  .seg-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    height: 22px;
    padding: 0 8px;
    border: none;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 500;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .seg-btn:hover {
    color: var(--text-primary);
  }

  .seg-btn.active {
    background: var(--bg-active);
    color: var(--accent);
    font-weight: 600;
  }

  .diff-box {
    border-radius: var(--radius-md);
    background: var(--terminal-bg);
    border: 1px solid var(--border-default);
    overflow: auto;
    max-height: 340px;
    font-size: 11.5px;
    line-height: 1.5;
  }

  .diff-box.compact {
    max-height: 210px;
  }

  .diff-row {
    display: flex;
    align-items: stretch;
    min-width: max-content;
    padding: 0 10px 0 0;
  }

  .diff-ln {
    width: 38px;
    padding: 0 6px;
    text-align: right;
    color: var(--text-faint);
    user-select: none;
    flex-shrink: 0;
    border-right: 1px solid var(--border-subtle);
  }

  .diff-ln.single {
    width: 44px;
  }

  .diff-sign {
    width: 22px;
    text-align: center;
    user-select: none;
    flex-shrink: 0;
    font-weight: 700;
  }

  .diff-text {
    white-space: pre;
    padding-left: 4px;
    color: var(--text-primary);
  }

  .diff-row.t-meta {
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .diff-row.t-meta .diff-text {
    color: var(--text-muted);
    font-weight: 600;
  }

  .diff-row.t-hunk {
    background: var(--status-info-bg);
    border-top: 1px solid var(--border-subtle);
    border-bottom: 1px solid var(--border-subtle);
  }

  .diff-row.t-hunk .diff-sign,
  .diff-row.t-hunk .diff-text {
    color: var(--status-info);
    font-weight: 600;
  }

  .diff-row.t-add {
    background: var(--status-success-bg);
  }

  .diff-row.t-add .diff-sign {
    color: var(--status-success);
  }

  .diff-row.t-del {
    background: var(--status-danger-bg);
  }

  .diff-row.t-del .diff-sign {
    color: var(--status-danger);
  }

  .diff-row.t-ctx .diff-text {
    color: var(--text-secondary);
  }

  .empty-code-msg {
    padding: 12px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px dashed var(--border-default);
    color: var(--text-muted);
    font-size: var(--text-xs);
  }

  /* Config Changes Table */
  .config-table {
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    overflow: hidden;
  }

  .config-row {
    display: grid;
    grid-template-columns: minmax(150px, 38%) minmax(0, 1fr);
    gap: 10px;
    padding: 7px 11px;
    border-bottom: 1px solid var(--border-subtle);
    font-size: var(--text-xs);
    align-items: center;
  }

  .config-row:last-child {
    border-bottom: none;
  }

  .config-row.head {
    background: var(--bg-elevated);
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
  }

  .cfg-key {
    color: var(--accent);
    word-break: break-all;
  }

  .cfg-val {
    color: var(--text-primary);
    word-break: break-all;
  }

  .applied-note {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-xs);
    color: var(--status-success);
  }

  /* Command Hints */
  .cmd-list {
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .cmd-card {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    background: var(--bg-input);
    border: 1px solid var(--border-default);
  }

  .cmd-code {
    font-size: 11.5px;
    color: var(--terminal-fg);
    word-break: break-all;
    white-space: pre-wrap;
    flex: 1;
  }

  /* Auto-Heal Timeline */
  .timeline-controls {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
  }

  .subtle-hint {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
  }

  .loading-inline {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    padding: 6px 2px;
  }

  .live-stepper {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .live-round-row {
    display: flex;
    flex-direction: column;
    gap: 5px;
    padding: 9px 11px;
    border-radius: var(--radius-md);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
  }

  .live-round-head {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .round-label {
    font-size: 11px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .phase-trail {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
  }

  .trail-arrow {
    font-size: 11px;
    color: var(--text-faint);
  }

  .round-ts {
    margin-left: auto;
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .live-round-msg {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .attempt-summary-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    font-size: 11px;
    color: var(--text-secondary);
  }

  .attempt-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .attempt-item {
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    overflow: hidden;
  }

  .attempt-toggle {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding: 8px 11px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
    transition: background var(--transition-fast);
  }

  .attempt-toggle:hover {
    background: var(--bg-hover);
  }

  .attempt-left {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
    min-width: 0;
  }

  .attempt-name {
    font-size: var(--text-xs);
    font-weight: 600;
  }

  .attempt-right {
    font-size: 11px;
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .attempt-detail {
    padding: 10px 12px 12px;
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .detail-block {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .detail-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .detail-label {
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
  }

  .round-root-cause {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .round-explanation {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    line-height: 1.45;
  }

  .log-pre {
    margin: 0;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--terminal-bg);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-size: 11px;
    line-height: 1.45;
    max-height: 180px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  /* Footer */
  .drawer-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 12px 18px;
    background: var(--bg-header);
    border-top: 1px solid var(--border-default);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .footer-left,
  .footer-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
</style>
