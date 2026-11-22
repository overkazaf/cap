<script>
  import { onMount, onDestroy } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate } from '../lib/i18n.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import { toast } from '../lib/toast.js'
  import { formatTime } from '../lib/format.js'

  const api = () => window?.go?.wailsgui?.App

  let rules = []
  let editRule = null
  let isNew = false
  let pendingBPs = []
  let selectedBP = null
  let bpInterval = null

  let searchQuery = ''
  let typeFilter = 'all'
  let confirmDeleteId = null
  let saving = false

  // Rule Editor form fields
  let eName = ''
  let eMethod = ''
  let eHost = ''
  let ePath = ''
  let eURL = ''
  let eHeader = ''
  let eBody = ''
  let eActionType = 'mock'
  let ePriority = 10
  let eEnabled = true
  let eMockStatus = 200
  let eMockHeaders = ''
  let eMockBody = ''
  let eSetHeaders = ''
  let eDelHeaders = ''
  let eReplaceBody = ''
  let eSetRespHeaders = ''
  let eReplaceRespBody = ''
  let eSetStatus = 0
  let eBreakReq = true
  let eBreakResp = false

  // Breakpoint resolution editable copy
  let bpMethod = ''
  let bpURL = ''
  let bpHeadersText = ''
  let bpBody = ''
  let bpMockStatus = 200
  let bpMockRespBody = ''
  let resolvingBP = false

  const actionSpecs = [
    { value: 'mock', icon: 'sparkles', variant: 'accent' },
    { value: 'breakpoint', icon: 'pause', variant: 'warning' },
    { value: 'modify_request', icon: 'edit', variant: 'info' },
    { value: 'modify_response', icon: 'file-code', variant: 'purple' },
    { value: 'drop', icon: 'ban', variant: 'danger' },
    { value: 'passthrough', icon: 'arrow-right', variant: 'neutral' },
  ]

  const httpMethods = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']

  function getActionMeta(type, tr = translate) {
    const spec = actionSpecs.find((a) => a.value === type) || actionSpecs[5]
    return {
      ...spec,
      label: tr(`tools.rules.actions.${spec.value}.label`),
      fullLabel: tr(`tools.rules.actions.${spec.value}.full`),
      desc: tr(`tools.rules.actions.${spec.value}.desc`),
    }
  }

  function formatHeadersMap(map) {
    return Object.entries(map || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n')
  }

  function parseHeaders(text) {
    const h = {}
    for (const line of String(text || '').split('\n')) {
      const idx = line.indexOf(':')
      if (idx > 0) {
        const k = line.slice(0, idx).trim()
        const v = line.slice(idx + 1).trim()
        if (k) h[k] = v
      }
    }
    return h
  }

  function checkPathRegex(pattern, tr) {
    if (!pattern) return { state: 'empty', label: '' }
    try {
      new RegExp(pattern)
      return { state: 'regex', label: tr('tools.rules.validRegex') }
    } catch (_) {
      return { state: 'substring', label: tr('tools.rules.substringFallback') }
    }
  }

  $: pathSyntax = checkPathRegex(ePath, $t)
  $: actionTypes = actionSpecs.map((spec) => getActionMeta(spec.value, $t))

  async function loadRules() {
    const app = api()
    if (!app?.ListRules) return
    try {
      const list = (await app.ListRules()) || []
      rules = [...list].sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0))
    } catch (_) {}
  }

  async function loadBPs() {
    const app = api()
    if (!app?.GetPendingBreakpoints) return
    try {
      pendingBPs = (await app.GetPendingBreakpoints()) || []
      if (selectedBP && !pendingBPs.some((bp) => bp.id === selectedBP.id)) {
        selectedBP = null
      }
    } catch (_) {}
  }

  function newRule(preset = null) {
    selectedBP = null
    confirmDeleteId = null
    isNew = true
    editRule = null
    eName = preset?.name || ''
    eMethod = preset?.method || ''
    eHost = preset?.host || ''
    ePath = preset?.path || ''
    eURL = preset?.url || ''
    eHeader = preset?.header || ''
    eBody = preset?.body || ''
    eActionType = preset?.actionType || 'mock'
    ePriority = preset?.priority ?? 10
    eEnabled = true
    eMockStatus = preset?.mockStatus ?? 200
    eMockHeaders = preset?.mockHeaders ?? 'Content-Type: application/json'
    eMockBody = preset?.mockBody ?? '{\n  "ok": true\n}'
    eSetHeaders = preset?.setHeaders || ''
    eDelHeaders = ''
    eReplaceBody = ''
    eSetRespHeaders = ''
    eReplaceRespBody = ''
    eSetStatus = 0
    eBreakReq = true
    eBreakResp = false
  }

  function selectRule(r) {
    selectedBP = null
    confirmDeleteId = null
    editRule = r
    isNew = false
    eName = r.name || ''
    ePriority = r.priority ?? 10
    eEnabled = Boolean(r.enabled)
    eMethod = r.match?.method || ''
    eHost = r.match?.host || ''
    ePath = r.match?.path || ''
    eURL = r.match?.url || ''
    eHeader = r.match?.header || ''
    eBody = r.match?.body_contains || ''
    eActionType = r.action?.type || 'passthrough'
    eMockStatus = r.action?.mock_status || 200
    eMockBody = r.action?.mock_body || ''
    eMockHeaders = formatHeadersMap(r.action?.mock_headers)
    eSetHeaders = formatHeadersMap(r.action?.set_headers)
    eDelHeaders = (r.action?.del_headers || []).join('\n')
    eReplaceBody = r.action?.replace_body || ''
    eSetRespHeaders = formatHeadersMap(r.action?.set_resp_headers)
    eReplaceRespBody = r.action?.replace_resp_body || ''
    eSetStatus = r.action?.set_status || 0
    eBreakReq = Boolean(r.action?.break_on_req)
    eBreakResp = Boolean(r.action?.break_on_resp)
  }

  function inspectBP(bp) {
    selectedBP = bp
    editRule = null
    isNew = false
    bpMethod = bp.method || 'GET'
    bpURL = bp.url || ''
    bpHeadersText = formatHeadersMap(bp.headers)
    bpBody = bp.body || ''
    bpMockStatus = 200
    bpMockRespBody = ''
  }

  function buildRuleObject(idOverride = null) {
    return {
      id: idOverride || editRule?.id || `r-${Date.now()}`,
      name: eName.trim() || `${getActionMeta(eActionType).label}`,
      enabled: eEnabled,
      priority: Number(ePriority) || 0,
      match: {
        method: eMethod.trim().toUpperCase(),
        host: eHost.trim(),
        path: ePath.trim(),
        url: eURL.trim(),
        header: eHeader.trim(),
        body_contains: eBody,
      },
      action: {
        type: eActionType,
        mock_status: Number(eMockStatus) || 200,
        mock_headers: parseHeaders(eMockHeaders),
        mock_body: eMockBody,
        set_headers: parseHeaders(eSetHeaders),
        del_headers: eDelHeaders
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        replace_body: eReplaceBody,
        set_resp_headers: parseHeaders(eSetRespHeaders),
        replace_resp_body: eReplaceRespBody,
        set_status: Number(eSetStatus) || 0,
        break_on_req: eBreakReq,
        break_on_resp: eBreakResp,
      },
    }
  }

  async function saveRule() {
    const app = api()
    if (!app?.AddRule) return
    saving = true
    const rule = buildRuleObject()
    try {
      if (!isNew && editRule) {
        await app.RemoveRule(editRule.id)
      }
      await app.AddRule(rule)
      await loadRules()
      const saved = rules.find((r) => r.id === rule.id) || rule
      selectRule(saved)
      toast.success(translate('tools.rules.toast.saved', { name: rule.name }))
    } catch (e) {
      toast.error(translate('tools.rules.toast.saveFailed', { error: e?.message || e }))
    } finally {
      saving = false
    }
  }

  async function duplicateRule() {
    const app = api()
    if (!app?.AddRule) return
    const copy = buildRuleObject(`r-${Date.now()}`)
    copy.name = `${copy.name} ${translate('tools.rules.toast.copySuffix')}`
    try {
      await app.AddRule(copy)
      await loadRules()
      const saved = rules.find((r) => r.id === copy.id) || copy
      selectRule(saved)
      toast.success(translate('tools.rules.toast.duplicated', { name: copy.name }))
    } catch (e) {
      toast.error(translate('tools.rules.toast.duplicateFailed', { error: e?.message || e }))
    }
  }

  async function toggleRuleEnabled(rule) {
    const app = api()
    if (!app) return
    const updated = { ...rule, enabled: !rule.enabled }
    try {
      if (app.SetRules) {
        const nextList = rules.map((r) => (r.id === rule.id ? updated : r))
        await app.SetRules(nextList)
      } else {
        await app.RemoveRule(rule.id)
        await app.AddRule(updated)
      }
      if (editRule?.id === rule.id) {
        eEnabled = updated.enabled
        editRule = updated
      }
      await loadRules()
      const key = updated.enabled ? 'tools.rules.toast.enabled' : 'tools.rules.toast.disabled'
      toast.info(translate(key, { name: updated.name || updated.id }))
    } catch (e) {
      toast.error(translate('tools.rules.toast.toggleFailed', { error: e?.message || e }))
    }
  }

  async function nudgePriority(rule, delta) {
    const app = api()
    if (!app) return
    const nextPri = Math.max(0, (Number(rule.priority) || 0) + delta)
    const updated = { ...rule, priority: nextPri }
    try {
      if (app.SetRules) {
        const nextList = rules.map((r) => (r.id === rule.id ? updated : r))
        await app.SetRules(nextList)
      } else {
        await app.RemoveRule(rule.id)
        await app.AddRule(updated)
      }
      if (editRule?.id === rule.id) {
        ePriority = nextPri
        editRule = updated
      }
      await loadRules()
    } catch (e) {
      toast.error(translate('tools.rules.toast.reorderFailed', { error: e?.message || e }))
    }
  }

  async function deleteRule(id) {
    const app = api()
    if (!app?.RemoveRule) return
    const target = rules.find((r) => r.id === id)
    try {
      await app.RemoveRule(id)
      confirmDeleteId = null
      if (editRule?.id === id) {
        editRule = null
        isNew = false
      }
      await loadRules()
      toast.info(translate('tools.rules.toast.deleted', { name: target?.name || id }))
    } catch (e) {
      toast.error(translate('tools.rules.toast.deleteFailed', { error: e?.message || e }))
    }
  }

  async function resolveBP(bp, action, useEdited = false) {
    const app = api()
    if (!app?.ResolveBreakpoint) return
    resolvingBP = true
    try {
      const url = useEdited ? bpURL : bp.url
      const method = useEdited ? bpMethod : bp.method
      const body = useEdited ? bpBody : ''
      const headers = useEdited ? parseHeaders(bpHeadersText) : bp.headers || {}
      const status = action === 'mock' ? Number(bpMockStatus) || 200 : 0
      const respBody = action === 'mock' ? bpMockRespBody : ''
      await app.ResolveBreakpoint(bp.id, action, url, method, body, headers, status, {}, respBody)
      if (selectedBP?.id === bp.id) selectedBP = null
      await loadBPs()
      const msgKey =
        action === 'drop'
          ? 'tools.rules.toast.bpDropped'
          : action === 'mock'
            ? 'tools.rules.toast.bpMocked'
            : 'tools.rules.toast.bpForwarded'
      toast.success(translate(msgKey))
    } catch (e) {
      toast.error(translate('tools.rules.toast.bpResolveFailed', { error: e?.message || e }))
    } finally {
      resolvingBP = false
    }
  }

  function formatJsonField(which) {
    const raw = which === 'mock' ? eMockBody : which === 'req' ? eReplaceBody : eReplaceRespBody
    try {
      const pretty = JSON.stringify(JSON.parse(raw), null, 2)
      if (which === 'mock') eMockBody = pretty
      else if (which === 'req') eReplaceBody = pretty
      else eReplaceRespBody = pretty
      toast.info(translate('tools.rules.toast.jsonFormatted'))
    } catch (_) {
      toast.warning(translate('tools.rules.toast.jsonInvalid'))
    }
  }

  function summarizeMatch(r, tr) {
    const m = r.match || {}
    const parts = []
    if (m.method) parts.push(m.method)
    if (m.host || m.path) parts.push(`${m.host || '*'}${m.path || ''}`)
    else if (m.url) parts.push(m.url)
    else if (m.header) parts.push(`hdr:${m.header}`)
    else if (m.body_contains) parts.push(`body~"${m.body_contains}"`)
    return parts.join(' ') || tr('tools.rules.anyTraffic')
  }

  $: filteredRules = rules.filter((r) => {
    if (typeFilter !== 'all' && r.action?.type !== typeFilter) return false
    const q = searchQuery.trim().toLowerCase()
    if (!q) return true
    return (
      (r.name || '').toLowerCase().includes(q) ||
      (r.match?.host || '').toLowerCase().includes(q) ||
      (r.match?.path || '').toLowerCase().includes(q) ||
      (r.match?.url || '').toLowerCase().includes(q) ||
      (r.action?.type || '').toLowerCase().includes(q)
    )
  })

  $: enabledCount = rules.filter((r) => r.enabled).length
  $: currentActionMeta = getActionMeta(eActionType, $t)

  onMount(() => {
    loadRules()
    loadBPs()
    bpInterval = setInterval(loadBPs, 1000)
  })

  onDestroy(() => {
    if (bpInterval) clearInterval(bpInterval)
  })
</script>

<div class="rules-page">
  <SplitPane direction="horizontal" initialSize={33} minPrimary={24} minSecondary={42} storageKey="cap.rules.split">
    <!-- Left Master List -->
    <div slot="primary" class="list-pane">
      <div class="list-toolbar">
        <div class="list-title-group">
          <span class="pane-title">{$t('tools.rules.title')}</span>
          <Badge variant="neutral" size="xs" mono>{enabledCount}/{rules.length}</Badge>
        </div>
        <Button variant="primary" size="xs" icon="plus" on:click={() => newRule()}>{$t('tools.rules.newRule')}</Button>
      </div>

      <!-- Pending Breakpoints Queue -->
      {#if pendingBPs.length > 0}
        <div class="bp-queue">
          <div class="bp-queue-head">
            <span class="bp-head-left">
              <Icon name="alert-triangle" size={13} />
              <span>{$t('tools.rules.heldBreakpoints')}</span>
            </span>
            <Badge variant="warning" size="xs" dot pulse mono>{pendingBPs.length}</Badge>
          </div>
          {#each pendingBPs as bp (bp.id)}
            <div class="bp-card" class:active={selectedBP?.id === bp.id}>
              <button type="button" class="bp-select" on:click={() => inspectBP(bp)}>
                <div class="bp-row-top">
                  <Badge variant="method" method={bp.method} size="xs" />
                  <span class="bp-rule truncate">{bp.rule_name || $t('tools.rules.defaultBreakpointName')}</span>
                  <span class="bp-time mono tabular-nums">{formatTime(bp.timestamp)}</span>
                </div>
                <div class="bp-url mono truncate" title={bp.url}>{bp.url}</div>
              </button>
              <div class="bp-quick-actions">
                <Button variant="success" size="xs" icon="play" disabled={resolvingBP} on:click={() => resolveBP(bp, 'forward')}>
                  {$t('tools.rules.forward')}
                </Button>
                <Button variant="danger" size="xs" icon="ban" disabled={resolvingBP} on:click={() => resolveBP(bp, 'drop')}>
                  {$t('tools.rules.drop')}
                </Button>
                <Button variant="ghost" size="xs" icon="edit" on:click={() => inspectBP(bp)}>
                  {$t('tools.rules.edit')}
                </Button>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      <!-- Search & Action Type Filter -->
      <div class="list-filters">
        <div class="search-wrap">
          <Icon name="search" size={13} />
          <input
            type="text"
            class="search-input"
            bind:value={searchQuery}
            placeholder={$t('tools.rules.filterPlaceholder')}
          />
          {#if searchQuery}
            <button type="button" class="icon-clear" title={$t('common.actions.clear')} on:click={() => (searchQuery = '')}>
              <Icon name="x" size={12} />
            </button>
          {/if}
        </div>
        <div class="type-pills">
          <button type="button" class="type-pill" class:active={typeFilter === 'all'} on:click={() => (typeFilter = 'all')}>
            {$t('tools.rules.filterAll')}
          </button>
          {#each actionTypes.slice(0, 5) as at}
            <button
              type="button"
              class="type-pill"
              class:active={typeFilter === at.value}
              on:click={() => (typeFilter = typeFilter === at.value ? 'all' : at.value)}
            >
              {at.label}
            </button>
          {/each}
        </div>
      </div>

      <!-- Rules List -->
      <div class="rules-scroll">
        {#each filteredRules as r (r.id)}
          {@const meta = getActionMeta(r.action?.type, $t)}
          <div class="rule-row" class:selected={editRule?.id === r.id} class:disabled={!r.enabled}>
            <label class="switch" title={r.enabled ? $t('tools.rules.disableRuleTitle') : $t('tools.rules.enableRuleTitle')}>
              <input type="checkbox" checked={r.enabled} on:change={() => toggleRuleEnabled(r)} />
              <span class="switch-track"></span>
            </label>

            <button type="button" class="rule-select" on:click={() => selectRule(r)}>
              <div class="rule-top">
                <span class="rule-name truncate">{r.name || r.id}</span>
                <Badge variant={meta.variant} size="xs">{meta.label}</Badge>
              </div>
              <div class="rule-sub mono truncate">{summarizeMatch(r, $t)}</div>
            </button>

            <div class="rule-pri-ctrl">
              <span class="pri-tag mono tabular-nums" title={$t('tools.rules.priorityTooltip')}>P{r.priority}</span>
              <div class="pri-arrows">
                <button type="button" class="pri-btn" title={$t('tools.rules.higherPriorityTitle')} on:click={() => nudgePriority(r, -1)}>
                  <Icon name="chevron-up" size={11} />
                </button>
                <button type="button" class="pri-btn" title={$t('tools.rules.lowerPriorityTitle')} on:click={() => nudgePriority(r, 1)}>
                  <Icon name="chevron-down" size={11} />
                </button>
              </div>
            </div>
          </div>
        {/each}

        {#if filteredRules.length === 0}
          <EmptyState
            icon="sliders"
            title={rules.length === 0 ? $t('tools.rules.empty.noRulesTitle') : $t('tools.rules.empty.filteredTitle')}
            description={rules.length === 0 ? $t('tools.rules.empty.noRulesDesc') : $t('tools.rules.empty.filteredDesc')}
            compact
          >
            {#if rules.length === 0}
              <Button variant="primary" size="xs" icon="plus" on:click={() => newRule()}>{$t('tools.rules.empty.createFirst')}</Button>
            {/if}
          </EmptyState>
        {/if}
      </div>
    </div>

    <!-- Right Detail / Editor Pane -->
    <div slot="secondary" class="editor-pane">
      {#if selectedBP}
        <!-- Live Breakpoint Inspector -->
        <div class="editor-topbar">
          <div class="editor-head-left">
            <Badge variant="warning" size="sm" dot pulse>{$t('tools.rules.pausedBreakpoint')}</Badge>
            <span class="editor-title mono truncate">{selectedBP.rule_name || selectedBP.id}</span>
          </div>
          <div class="editor-head-actions">
            <Button variant="success" size="sm" icon="play" loading={resolvingBP} on:click={() => resolveBP(selectedBP, 'forward', true)}>
              {$t('tools.rules.forwardEdited')}
            </Button>
            <Button variant="secondary" size="sm" icon="sparkles" loading={resolvingBP} on:click={() => resolveBP(selectedBP, 'mock', true)}>
              {$t('tools.rules.mockResponse')}
            </Button>
            <Button variant="danger" size="sm" icon="ban" loading={resolvingBP} on:click={() => resolveBP(selectedBP, 'drop')}>
              {$t('tools.rules.drop403')}
            </Button>
          </div>
        </div>

        <div class="editor-scroll">
          <div class="form-card cap-card">
            <div class="card-head">
              <span class="card-title">{$t('tools.rules.interceptedPayload')}</span>
              <span class="card-hint mono tabular-nums">{$t('tools.rules.capturedAt', { time: formatTime(selectedBP.timestamp) })}</span>
            </div>
            <div class="form-grid-2">
              <div class="form-field">
                <label class="f-label" for="bp-method">{$t('tools.rules.method')}</label>
                <input id="bp-method" type="text" class="cap-input mono" bind:value={bpMethod} />
              </div>
              <div class="form-field span-2">
                <label class="f-label" for="bp-url">{$t('tools.rules.url')}</label>
                <input id="bp-url" type="text" class="cap-input mono" bind:value={bpURL} />
              </div>
            </div>
            <div class="form-field">
              <label class="f-label" for="bp-headers">{$t('tools.rules.headersPerLine')}</label>
              <textarea id="bp-headers" class="cap-textarea mono" rows="5" bind:value={bpHeadersText}></textarea>
            </div>
            <div class="form-field">
              <label class="f-label" for="bp-body">{$t('tools.rules.body')}</label>
              <textarea id="bp-body" class="cap-textarea mono" rows="6" bind:value={bpBody}></textarea>
            </div>
          </div>

          <div class="form-card cap-card">
            <div class="card-head">
              <span class="card-title">{$t('tools.rules.optionalMockTitle')}</span>
              <span class="card-hint">{$t('tools.rules.optionalMockHint')}</span>
            </div>
            <div class="form-row-inline">
              <div class="form-field small">
                <label class="f-label" for="bp-mock-status">{$t('tools.rules.httpStatus')}</label>
                <input id="bp-mock-status" type="number" class="cap-input mono tabular-nums" bind:value={bpMockStatus} />
              </div>
            </div>
            <div class="form-field">
              <label class="f-label" for="bp-mock-body">{$t('tools.rules.mockResponseBody')}</label>
              <textarea id="bp-mock-body" class="cap-textarea mono" rows="4" bind:value={bpMockRespBody} placeholder={'{"mocked": true}'}></textarea>
            </div>
          </div>
        </div>

      {:else if editRule || isNew}
        <!-- Rule Editor -->
        <div class="editor-topbar">
          <div class="editor-head-left">
            <Badge variant={currentActionMeta.variant} size="sm">{currentActionMeta.label}</Badge>
            <span class="editor-title truncate">{isNew ? $t('tools.rules.newRuleTitle') : eName || editRule.id}</span>
          </div>
          <div class="editor-head-actions">
            {#if editRule}
              <Button variant="ghost" size="sm" icon="copy" on:click={duplicateRule} title={$t('tools.rules.duplicateTitle')}>
                {$t('tools.rules.duplicate')}
              </Button>
              {#if confirmDeleteId === editRule.id}
                <Button variant="danger" size="sm" icon="trash" on:click={() => deleteRule(editRule.id)}>
                  {$t('tools.rules.confirmDelete')}
                </Button>
                <Button variant="ghost" size="sm" on:click={() => (confirmDeleteId = null)}>{$t('common.actions.cancel')}</Button>
              {:else}
                <Button variant="ghost" size="sm" icon="trash" on:click={() => (confirmDeleteId = editRule.id)}>
                  {$t('common.actions.delete')}
                </Button>
              {/if}
            {/if}
            <Button variant="primary" size="sm" icon="save" loading={saving} on:click={saveRule}>
              {$t('tools.rules.saveRule')}
            </Button>
          </div>
        </div>

        <div class="editor-scroll">
          <!-- General Card -->
          <div class="form-card cap-card">
            <div class="card-head">
              <span class="card-title">{$t('tools.rules.general')}</span>
              <label class="inline-switch-label">
                <span>{eEnabled ? $t('tools.rules.active') : $t('tools.rules.disabled')}</span>
                <span class="switch">
                  <input type="checkbox" bind:checked={eEnabled} />
                  <span class="switch-track"></span>
                </span>
              </label>
            </div>
            <div class="general-grid">
              <div class="form-field flex-1">
                <label class="f-label" for="rule-name">{$t('tools.rules.ruleName')}</label>
                <input id="rule-name" type="text" class="cap-input" bind:value={eName} placeholder={$t('tools.rules.ruleNamePlaceholder')} />
              </div>
              <div class="form-field pri-field">
                <label class="f-label" for="rule-priority">{$t('tools.rules.priority')}</label>
                <input id="rule-priority" type="number" min="0" class="cap-input mono tabular-nums" bind:value={ePriority} />
                <span class="f-hint">{$t('tools.rules.priorityHint')}</span>
              </div>
            </div>
          </div>

          <!-- Match Criteria Card -->
          <div class="form-card cap-card">
            <div class="card-head">
              <div class="card-head-left">
                <span class="card-title">{$t('tools.rules.matchConditions')}</span>
                <Badge variant="neutral" size="xs">{$t('tools.rules.matchAndBadge')}</Badge>
              </div>
              <span class="card-hint">{$t('tools.rules.matchBlankHint')}</span>
            </div>

            <div class="match-grid">
              <div class="form-field">
                <label class="f-label" for="m-method">{$t('tools.rules.httpMethod')}</label>
                <select id="m-method" class="cap-input mono" bind:value={eMethod}>
                  {#each httpMethods as m}
                    <option value={m}>{m || $t('tools.rules.anyMethod')}</option>
                  {/each}
                </select>
              </div>
              <div class="form-field">
                <label class="f-label" for="m-host">{$t('tools.rules.hostLabel')} <span class="syntax-tag">{$t('tools.rules.syntaxSubstring')}</span></label>
                <input id="m-host" type="text" class="cap-input mono" bind:value={eHost} placeholder="api.example.com" />
              </div>
              <div class="form-field">
                <div class="label-row">
                  <label class="f-label" for="m-path">{$t('tools.rules.pathLabel')} <span class="syntax-tag">{$t('tools.rules.syntaxRegex')}</span></label>
                  {#if pathSyntax.label}
                    <Badge variant={pathSyntax.state === 'regex' ? 'success' : 'warning'} size="xs">{pathSyntax.label}</Badge>
                  {/if}
                </div>
                <input id="m-path" type="text" class="cap-input mono" bind:value={ePath} placeholder={$t('tools.rules.pathPlaceholder')} />
              </div>
              <div class="form-field">
                <label class="f-label" for="m-url">{$t('tools.rules.fullUrlLabel')} <span class="syntax-tag">{$t('tools.rules.syntaxSubstring')}</span></label>
                <input id="m-url" type="text" class="cap-input mono" bind:value={eURL} placeholder={$t('tools.rules.urlPlaceholder')} />
              </div>
              <div class="form-field">
                <label class="f-label" for="m-header">{$t('tools.rules.headerLabel')} <span class="syntax-tag">{$t('tools.rules.syntaxHeader')}</span></label>
                <input id="m-header" type="text" class="cap-input mono" bind:value={eHeader} placeholder={$t('tools.rules.headerPlaceholder')} />
              </div>
              <div class="form-field">
                <label class="f-label" for="m-body">{$t('tools.rules.requestBodyLabel')} <span class="syntax-tag">{$t('tools.rules.syntaxContains')}</span></label>
                <input id="m-body" type="text" class="cap-input mono" bind:value={eBody} placeholder={$t('tools.rules.bodyPlaceholder')} />
              </div>
            </div>
          </div>

          <!-- Action Card -->
          <div class="form-card cap-card">
            <div class="card-head">
              <span class="card-title">{$t('tools.rules.actionSection')}</span>
              <span class="card-hint">{currentActionMeta.desc}</span>
            </div>

            <div class="action-selector">
              {#each actionTypes as at (at.value)}
                <button
                  type="button"
                  class="action-tile"
                  class:active={eActionType === at.value}
                  on:click={() => (eActionType = at.value)}
                >
                  <Icon name={at.icon} size={14} />
                  <span>{at.fullLabel}</span>
                </button>
              {/each}
            </div>

            {#if eActionType === 'mock'}
              <div class="action-fields">
                <div class="form-field small">
                  <label class="f-label" for="a-mock-status">{$t('tools.rules.httpStatusCode')}</label>
                  <input id="a-mock-status" type="number" class="cap-input mono tabular-nums" bind:value={eMockStatus} />
                </div>
                <div class="form-field">
                  <label class="f-label" for="a-mock-headers">{$t('tools.rules.responseHeadersLabel')}</label>
                  <textarea id="a-mock-headers" class="cap-textarea mono" rows="3" bind:value={eMockHeaders} placeholder="Content-Type: application/json"></textarea>
                </div>
                <div class="form-field">
                  <div class="label-row">
                    <label class="f-label" for="a-mock-body">{$t('tools.rules.responseBodyLabel')}</label>
                    <button type="button" class="mini-action" on:click={() => formatJsonField('mock')}>{$t('tools.rules.formatJson')}</button>
                  </div>
                  <textarea id="a-mock-body" class="cap-textarea mono" rows="6" bind:value={eMockBody} placeholder={'{"ok": true}'}></textarea>
                </div>
              </div>

            {:else if eActionType === 'modify_request'}
              <div class="action-fields">
                <div class="form-field">
                  <label class="f-label" for="a-set-hdr">{$t('tools.rules.setReqHeadersLabel')}</label>
                  <textarea id="a-set-hdr" class="cap-textarea mono" rows="3" bind:value={eSetHeaders} placeholder="X-Debug: true"></textarea>
                </div>
                <div class="form-field">
                  <label class="f-label" for="a-del-hdr">{$t('tools.rules.delReqHeadersLabel')}</label>
                  <textarea id="a-del-hdr" class="cap-textarea mono" rows="2" bind:value={eDelHeaders} placeholder="If-None-Match"></textarea>
                </div>
                <div class="form-field">
                  <div class="label-row">
                    <label class="f-label" for="a-rep-body">{$t('tools.rules.replaceReqBodyLabel')}</label>
                    <button type="button" class="mini-action" on:click={() => formatJsonField('req')}>{$t('tools.rules.formatJson')}</button>
                  </div>
                  <textarea id="a-rep-body" class="cap-textarea mono" rows="4" bind:value={eReplaceBody}></textarea>
                </div>
              </div>

            {:else if eActionType === 'modify_response'}
              <div class="action-fields">
                <div class="form-field small">
                  <label class="f-label" for="a-set-status">{$t('tools.rules.overrideStatusLabel')}</label>
                  <input id="a-set-status" type="number" class="cap-input mono tabular-nums" bind:value={eSetStatus} />
                </div>
                <div class="form-field">
                  <label class="f-label" for="a-set-rhdr">{$t('tools.rules.setRespHeadersLabel')}</label>
                  <textarea id="a-set-rhdr" class="cap-textarea mono" rows="3" bind:value={eSetRespHeaders} placeholder="Access-Control-Allow-Origin: *"></textarea>
                </div>
                <div class="form-field">
                  <div class="label-row">
                    <label class="f-label" for="a-rep-rbody">{$t('tools.rules.replaceRespBodyLabel')}</label>
                    <button type="button" class="mini-action" on:click={() => formatJsonField('resp')}>{$t('tools.rules.formatJson')}</button>
                  </div>
                  <textarea id="a-rep-rbody" class="cap-textarea mono" rows="5" bind:value={eReplaceRespBody}></textarea>
                </div>
              </div>

            {:else if eActionType === 'breakpoint'}
              <div class="bp-checks">
                <label class="check-card">
                  <input type="checkbox" bind:checked={eBreakReq} />
                  <div>
                    <div class="check-title">{$t('tools.rules.pauseOnRequest')}</div>
                    <div class="check-desc">{$t('tools.rules.pauseOnRequestDesc')}</div>
                  </div>
                </label>
                <label class="check-card">
                  <input type="checkbox" bind:checked={eBreakResp} />
                  <div>
                    <div class="check-title">{$t('tools.rules.pauseOnResponse')}</div>
                    <div class="check-desc">{$t('tools.rules.pauseOnResponseDesc')}</div>
                  </div>
                </label>
              </div>
            {/if}
          </div>
        </div>
      {:else}
        <EmptyState
          icon="sliders"
          title={$t('tools.rules.empty.editorTitle')}
          description={$t('tools.rules.empty.editorDesc')}
        >
          <Button
            variant="secondary"
            size="sm"
            icon="sparkles"
            on:click={() =>
              newRule({
                name: translate('tools.rules.presets.mockJsonName'),
                method: 'GET',
                path: '/api/config',
                actionType: 'mock',
                mockStatus: 200,
                mockBody: '{\n  "feature_enabled": true\n}',
              })}
          >
            {$t('tools.rules.presets.mockJson')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="pause"
            on:click={() =>
              newRule({
                name: translate('tools.rules.presets.breakpointName'),
                method: 'POST',
                path: '/login',
                actionType: 'breakpoint',
              })}
          >
            {$t('tools.rules.presets.addBreakpoint')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="ban"
            on:click={() =>
              newRule({
                name: translate('tools.rules.presets.blockDomainName'),
                host: 'analytics',
                actionType: 'drop',
              })}
          >
            {$t('tools.rules.presets.blockDomain')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            icon="edit"
            on:click={() =>
              newRule({
                name: translate('tools.rules.presets.rewriteHeaderName'),
                actionType: 'modify_request',
                setHeaders: 'X-Cap-Debug: 1',
              })}
          >
            {$t('tools.rules.presets.rewriteHeader')}
          </Button>
        </EmptyState>
      {/if}
    </div>
  </SplitPane>
</div>

<style>
  .rules-page {
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Left Pane */
  .list-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: var(--bg-header);
    min-height: 0;
  }

  .list-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .list-title-group {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pane-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  /* Breakpoint Queue */
  .bp-queue {
    padding: 10px 12px;
    background: var(--status-warning-bg);
    border-bottom: 1px solid var(--status-warning-border);
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 240px;
    overflow-y: auto;
    flex-shrink: 0;
  }

  .bp-queue-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .bp-head-left {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--status-warning);
  }

  .bp-card {
    background: var(--bg-surface);
    border: 1px solid var(--status-warning-border);
    border-radius: var(--radius-md);
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .bp-card.active {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .bp-select {
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 4px;
    width: 100%;
    padding: 0;
  }

  .bp-row-top {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .bp-rule {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
    min-width: 0;
  }

  .bp-time {
    font-size: var(--text-2xs);
    color: var(--text-muted);
  }

  .bp-url {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .bp-quick-actions {
    display: flex;
    gap: 6px;
  }

  /* Search & Filter */
  .list-filters {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 7px;
    flex-shrink: 0;
  }

  .search-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 8px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
  }

  .search-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .search-input {
    border: none;
    background: transparent;
    outline: none;
    flex: 1;
    min-width: 0;
    font-size: var(--text-xs);
    color: var(--text-primary);
  }

  .icon-clear {
    border: none;
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    display: flex;
    padding: 2px;
  }

  .icon-clear:hover {
    color: var(--text-primary);
  }

  .type-pills {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  .type-pill {
    padding: 2px 7px;
    height: 21px;
    font-size: 10.5px;
    font-weight: 500;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .type-pill:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .type-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  /* Rules List */
  .rules-scroll {
    flex: 1;
    overflow-y: auto;
    min-height: 0;
  }

  .rule-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px 8px 12px;
    border-bottom: 1px solid var(--border-subtle);
    border-left: 2px solid transparent;
    transition: background var(--transition-fast);
  }

  .rule-row:hover {
    background: var(--bg-hover);
  }

  .rule-row.selected {
    background: var(--bg-active);
    border-left-color: var(--accent);
  }

  .rule-row.disabled .rule-name,
  .rule-row.disabled .rule-sub {
    opacity: 0.55;
  }

  .rule-select {
    flex: 1;
    min-width: 0;
    border: none;
    background: transparent;
    text-align: left;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 0;
  }

  .rule-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }

  .rule-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .rule-sub {
    font-size: 11px;
    color: var(--text-muted);
  }

  .rule-pri-ctrl {
    display: flex;
    align-items: center;
    gap: 3px;
    flex-shrink: 0;
  }

  .pri-tag {
    font-size: 10px;
    color: var(--text-faint);
    min-width: 24px;
    text-align: right;
  }

  .pri-arrows {
    display: flex;
    flex-direction: column;
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .rule-row:hover .pri-arrows,
  .rule-row.selected .pri-arrows {
    opacity: 1;
  }

  .pri-btn {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    padding: 0 2px;
    border-radius: 2px;
  }

  .pri-btn:hover {
    background: var(--bg-subtle);
    color: var(--text-primary);
  }

  /* Toggle Switch */
  .switch {
    position: relative;
    display: inline-block;
    width: 30px;
    height: 17px;
    flex-shrink: 0;
    cursor: pointer;
  }

  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
    position: absolute;
  }

  .switch-track {
    position: absolute;
    inset: 0;
    border-radius: var(--radius-full);
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .switch-track::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 11px;
    height: 11px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: transform var(--transition-fast), background var(--transition-fast);
  }

  .switch input:checked + .switch-track {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .switch input:checked + .switch-track::after {
    transform: translateX(13px);
    background: var(--status-success);
  }

  .switch input:focus-visible + .switch-track {
    box-shadow: var(--focus-ring);
  }

  /* Right Editor Pane */
  .editor-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-app);
  }

  .editor-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 16px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .editor-head-left {
    display: flex;
    align-items: center;
    gap: 9px;
    min-width: 0;
  }

  .editor-title {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .editor-head-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  .editor-scroll {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    min-height: 0;
  }

  .form-card {
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border-subtle);
  }

  .card-head-left {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .card-title {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
  }

  .card-hint {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .inline-switch-label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    cursor: pointer;
  }

  .general-grid {
    display: flex;
    gap: 12px;
    align-items: flex-start;
  }

  .flex-1 {
    flex: 1;
  }

  .pri-field {
    width: 110px;
  }

  .match-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .form-grid-2 {
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 10px;
  }

  .span-2 {
    grid-column: span 1;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
  }

  .form-field.small {
    max-width: 180px;
  }

  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .f-label {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--text-secondary);
  }

  .syntax-tag {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-faint);
    margin-left: 4px;
  }

  .f-hint {
    font-size: 10.5px;
    color: var(--text-faint);
  }

  .mini-action {
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: var(--text-xs);
    cursor: pointer;
    padding: 0;
  }

  .mini-action:hover {
    text-decoration: underline;
  }

  .cap-textarea {
    width: 100%;
    padding: 8px 10px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: var(--text-xs);
    line-height: 1.55;
    resize: vertical;
    outline: none;
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
  }

  .cap-textarea:focus {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  /* Action Selector Grid */
  .action-selector {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }

  .action-tile {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-secondary);
    font-size: var(--text-xs);
    font-weight: 500;
    cursor: pointer;
    text-align: left;
    transition: all var(--transition-fast);
  }

  .action-tile:hover {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .action-tile.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .action-fields {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding-top: 6px;
  }

  .bp-checks {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
  }

  .check-card {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    cursor: pointer;
  }

  .check-card input {
    margin-top: 2px;
    accent-color: var(--accent);
  }

  .check-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .check-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
    margin-top: 2px;
  }
</style>
