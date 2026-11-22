<script>
  import { onMount } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate } from '../lib/i18n.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration } from '../lib/format.js'

  const api = () => window?.go?.wailsgui?.App

  let flows = []
  let loadingFlows = false
  let selectedFlowId = ''
  let packageName = ''
  let deviceApps = []
  let loadingApps = false
  let showAppPicker = false

  let signHints = []
  let tracing = false
  let result = null
  let activeView = 'steps'
  let traceLog = []
  let traceStartTime = 0
  let filterQuery = ''
  let showPermissions = false
  let showActivities = false

  $: selectedFlow = flows.find((f) => f.id === selectedFlowId) || null

  $: if (selectedFlowId) {
    loadSignHints(selectedFlowId)
  } else {
    signHints = []
  }

  async function loadFlows(notify = false) {
    const app = api()
    if (!app?.GetFlows) return
    loadingFlows = true
    try {
      flows = (await app.GetFlows('', '', '', 100)) || []
      if (notify) toast.info(translate('tools.deepTrace.toast.loadedFlows', { count: flows.length }))
    } catch (e) {
      if (notify) toast.error(translate('tools.deepTrace.toast.loadFlowsFailed', { error: e?.message || e }))
    } finally {
      loadingFlows = false
    }
  }

  async function loadSignHints(flowId) {
    const app = api()
    if (!app?.AnalyzeSign) return
    try {
      const res = await app.AnalyzeSign(flowId)
      signHints = Array.isArray(res) ? res : []
    } catch (_) {
      signHints = []
    }
  }

  async function loadDeviceApps() {
    const app = api()
    if (!app?.ListDevices || !app?.ListApps) return
    loadingApps = true
    try {
      const devices = (await app.ListDevices()) || []
      if (!devices.length) {
        toast.warning(translate('tools.deepTrace.toast.noDevice'))
        deviceApps = []
        showAppPicker = false
        return
      }
      const apps = (await app.ListApps(devices[0].serial)) || []
      deviceApps = apps
      showAppPicker = apps.length > 0
      if (!apps.length) {
        toast.info(translate('tools.deepTrace.toast.noApps'))
      }
    } catch (e) {
      toast.error(translate('tools.deepTrace.toast.appLookupFailed', { error: e?.message || e }))
    } finally {
      loadingApps = false
    }
  }

  function pickApp(pkg) {
    packageName = pkg
    showAppPicker = false
  }

  function tlog(msg, status = 'info') {
    const elapsed = ((Date.now() - traceStartTime) / 1000).toFixed(1)
    traceLog = [...traceLog, { elapsed, msg, status }]
  }

  async function runTrace() {
    const pkg = packageName.trim()
    if (!selectedFlowId || !pkg) {
      toast.warning(translate('tools.deepTrace.toast.missingInputs'))
      return
    }
    const app = api()
    if (!app?.DeepTrace) {
      toast.error(translate('tools.deepTrace.toast.backendUnavailable'))
      return
    }

    tracing = true
    result = null
    traceLog = []
    filterQuery = ''
    showPermissions = false
    showActivities = false
    traceStartTime = Date.now()
    activeView = 'steps'

    tlog(translate('tools.deepTrace.log.starting'), 'info')
    tlog(
      translate('tools.deepTrace.log.flowLine', {
        flowId: selectedFlowId,
        detail: selectedFlow ? ` (${selectedFlow.method} ${selectedFlow.host}${selectedFlow.path})` : '',
      }),
      'info'
    )
    tlog(translate('tools.deepTrace.log.packageLine', { pkg }), 'info')
    tlog(translate('tools.deepTrace.log.scanning'), 'info')

    try {
      const res = await app.DeepTrace(selectedFlowId, pkg)
      result = res

      if (res?.steps?.length) {
        for (const s of res.steps) {
          tlog(`${s.name}: ${s.detail} (${formatDuration(s.duration_ms)})`, s.status || 'info')
        }
      }

      const dex = res?.dex_strings?.length || 0
      const java = res?.java_trace?.length || 0
      const nat = res?.native_trace?.length || 0
      const edges = res?.call_graph?.length || 0
      tlog(translate('tools.deepTrace.log.completed', { dex, java, nat, edges }), 'ok')
      tlog(
        translate('tools.deepTrace.log.toolsUsed', {
          tools: (res?.tools_used || []).join(', ') || translate('tools.deepTrace.metrics.pureGo'),
        }),
        'info'
      )

      if (edges > 0) activeView = 'graph'
      else if (java > 0) activeView = 'java'
      else if (dex > 0) activeView = 'dex'
      else activeView = 'steps'

      toast.success(translate('tools.deepTrace.toast.traceComplete', { edges, dex }))
    } catch (e) {
      const errMsg = e?.message || String(e)
      tlog(translate('tools.deepTrace.log.errorPrefix', { error: errMsg }), 'error')
      result = {
        summary: `Error: ${errMsg}`,
        steps: [],
        dex_strings: [],
        java_trace: [],
        native_trace: [],
        call_graph: [],
        mermaid: '',
        tools_used: [],
      }
      toast.error(translate('tools.deepTrace.toast.traceFailed', { error: errMsg }))
    } finally {
      tracing = false
    }
  }

  function stepStatusVariant(status) {
    if (status === 'ok') return 'success'
    if (status === 'skip') return 'neutral'
    return 'danger'
  }

  function stepStatusIcon(status) {
    if (status === 'ok') return 'check-circle'
    if (status === 'skip') return 'minus'
    return 'x-circle'
  }

  function stepStatusLabel(status, tr) {
    if (status === 'ok') return tr('tools.deepTrace.stepStatus.ok')
    if (status === 'skip') return tr('tools.deepTrace.stepStatus.skip')
    return tr('tools.deepTrace.stepStatus.error')
  }

  function edgeTypeMeta(type) {
    switch (type) {
      case 'http':
        return { label: 'HTTP', variant: 'success' }
      case 'jni':
        return { label: 'JNI', variant: 'warning' }
      case 'native_call':
        return { label: 'NATIVE', variant: 'danger' }
      default:
        return { label: 'JAVA', variant: 'accent' }
    }
  }

  $: q = filterQuery.trim().toLowerCase()
  $: filteredEdges = (result?.call_graph || []).filter(
    (e) =>
      !q ||
      (e.from || '').toLowerCase().includes(q) ||
      (e.to || '').toLowerCase().includes(q) ||
      (e.label || '').toLowerCase().includes(q) ||
      (e.type || '').toLowerCase().includes(q)
  )
  $: filteredDex = (result?.dex_strings || []).filter(
    (d) =>
      !q ||
      (d.string || '').toLowerCase().includes(q) ||
      (d.dex_file || '').toLowerCase().includes(q) ||
      (d.context || []).some((c) => c.toLowerCase().includes(q))
  )
  $: filteredJava = (result?.java_trace || []).filter(
    (j) =>
      !q ||
      (j.file || '').toLowerCase().includes(q) ||
      (j.class || '').toLowerCase().includes(q) ||
      (j.method || '').toLowerCase().includes(q) ||
      (j.snippet || '').toLowerCase().includes(q) ||
      (j.annotation || '').toLowerCase().includes(q)
  )
  $: filteredNative = (result?.native_trace || []).filter(
    (n) =>
      !q ||
      (n.so_file || '').toLowerCase().includes(q) ||
      (n.function || '').toLowerCase().includes(q) ||
      (n.calls || []).some((c) => c.toLowerCase().includes(q)) ||
      (n.strings || []).some((s) => s.toLowerCase().includes(q))
  )

  $: tabs = result
    ? [
        { id: 'steps', label: $t('tools.deepTrace.tabs.steps'), icon: 'list', count: result.steps?.length || 0 },
        { id: 'graph', label: $t('tools.deepTrace.tabs.graph'), icon: 'git-branch', count: result.call_graph?.length || 0 },
        { id: 'dex', label: $t('tools.deepTrace.tabs.dex'), icon: 'database', count: result.dex_strings?.length || 0 },
        { id: 'java', label: $t('tools.deepTrace.tabs.java'), icon: 'file-code', count: result.java_trace?.length || 0 },
        { id: 'native', label: $t('tools.deepTrace.tabs.native'), icon: 'cpu', count: result.native_trace?.length || 0 },
        { id: 'summary', label: $t('tools.deepTrace.tabs.summary'), icon: 'file-text', count: null },
        { id: 'mermaid', label: $t('tools.deepTrace.tabs.mermaid'), icon: 'code', count: null },
      ]
    : []

  $: okStepsCount = (result?.steps || []).filter((s) => s.status === 'ok').length

  onMount(() => loadFlows(false))
</script>

<div class="trace-page">
  <!-- Top Configuration Bar -->
  <section class="config-panel">
    <div class="config-grid">
      <div class="field flow-field">
        <div class="field-head">
          <label class="field-label" for="trace-flow-select">{$t('tools.deepTrace.capturedFlow')}</label>
          <button
            type="button"
            class="inline-link"
            on:click={() => loadFlows(true)}
            disabled={loadingFlows}
            title={$t('tools.deepTrace.refreshFlowsTitle')}
          >
            <Icon name="refresh" size={11} />
            <span>{loadingFlows ? $t('tools.deepTrace.refreshing') : $t('tools.deepTrace.availableCount', { count: flows.length })}</span>
          </button>
        </div>
        <select id="trace-flow-select" bind:value={selectedFlowId} class="cap-input select-input mono">
          <option value="">{$t('tools.deepTrace.selectFlowPlaceholder')}</option>
          {#each flows as f (f.id)}
            <option value={f.id}>
              [{f.id}] {f.method} {f.host}{f.path} ({f.status || '—'})
            </option>
          {/each}
        </select>
      </div>

      <div class="field pkg-field">
        <div class="field-head">
          <label class="field-label" for="trace-pkg-input">{$t('tools.deepTrace.targetPackage')}</label>
          <button
            type="button"
            class="inline-link"
            on:click={loadDeviceApps}
            disabled={loadingApps}
            title={$t('tools.deepTrace.pickFromDeviceTitle')}
          >
            <Icon name="smartphone" size={11} />
            <span>{loadingApps ? $t('tools.deepTrace.queryingAdb') : $t('tools.deepTrace.pickFromDevice')}</span>
          </button>
        </div>
        <div class="pkg-input-wrap">
          <input
            id="trace-pkg-input"
            type="text"
            bind:value={packageName}
            class="cap-input mono pkg-input"
            placeholder="com.example.app"
            on:keydown={(e) => {
              if (e.key === 'Enter' && selectedFlowId && packageName.trim() && !tracing) runTrace()
            }}
          />
          {#if showAppPicker && deviceApps.length > 0}
            <div class="app-dropdown">
              <div class="dropdown-head">
                <span>{$t('tools.deepTrace.installedPackages', { count: deviceApps.length })}</span>
                <button type="button" class="dropdown-close" title={$t('common.actions.close')} on:click={() => (showAppPicker = false)}>
                  <Icon name="x" size={12} />
                </button>
              </div>
              <div class="dropdown-list">
                {#each deviceApps as app (app.package)}
                  <button type="button" class="dropdown-item mono" on:click={() => pickApp(app.package)}>
                    <Icon name="box" size={12} />
                    <span class="truncate">{app.package}</span>
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      </div>

      <div class="field action-field">
        <Button
          variant="primary"
          size="md"
          icon="radar"
          loading={tracing}
          disabled={tracing || !selectedFlowId || !packageName.trim()}
          on:click={runTrace}
        >
          {tracing ? $t('tools.deepTrace.tracing') : $t('tools.deepTrace.runTrace')}
        </Button>
      </div>
    </div>

    {#if selectedFlow}
      <div class="flow-preview">
        <Badge variant="method" method={selectedFlow.method} size="xs" />
        {#if selectedFlow.status}
          <Badge variant="status" status={selectedFlow.status} size="xs" />
        {/if}
        <span class="preview-url mono truncate" title={selectedFlow.url || `${selectedFlow.host}${selectedFlow.path}`}>
          {selectedFlow.host}{selectedFlow.path}
        </span>
        {#if selectedFlow.latency_ms}
          <span class="preview-meta mono tabular-nums">{formatDuration(selectedFlow.latency_ms)}</span>
        {/if}
        {#if signHints.length > 0}
          <div class="sign-strip">
            <Icon name="key" size={12} />
            <span class="sign-label">{$t('tools.deepTrace.signParams')}</span>
            {#each signHints.slice(0, 3) as sh}
              <Badge variant="warning" size="xs" mono>{sh.param_name}</Badge>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  </section>

  <!-- Live Execution Progress -->
  {#if tracing}
    <section class="progress-panel">
      <div class="progress-head">
        <div class="progress-title">
          <span class="spin-wrap"><Icon name="refresh" size={14} /></span>
          <span>{$t('tools.deepTrace.correlatingBanner', { pkg: packageName.trim(), flowId: selectedFlowId })}</span>
        </div>
        <Badge variant="accent" size="xs" dot pulse>{$t('tools.deepTrace.runningPipeline')}</Badge>
      </div>
      <div class="log-stream mono">
        {#each traceLog as entry}
          <div class="log-line s-{entry.status}">
            <span class="log-time tabular-nums">[{entry.elapsed}s]</span>
            <span class="log-msg">{entry.msg}</span>
          </div>
        {/each}
      </div>
    </section>
  {/if}

  <!-- Trace Results -->
  {#if result}
    <!-- Metrics Summary Strip -->
    <section class="metrics-strip">
      <div class="metric-card">
        <span class="metric-label">{$t('tools.deepTrace.metrics.pipeline')}</span>
        <span class="metric-val mono tabular-nums">{okStepsCount}/{result.steps?.length || 0}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">{$t('tools.deepTrace.metrics.callEdges')}</span>
        <span class="metric-val mono tabular-nums accent">{result.call_graph?.length || 0}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">{$t('tools.deepTrace.metrics.dexStrings')}</span>
        <span class="metric-val mono tabular-nums success">{result.dex_strings?.length || 0}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">{$t('tools.deepTrace.metrics.javaRefs')}</span>
        <span class="metric-val mono tabular-nums">{result.java_trace?.length || 0}</span>
      </div>
      <div class="metric-card">
        <span class="metric-label">{$t('tools.deepTrace.metrics.nativeSo')}</span>
        <span class="metric-val mono tabular-nums">{result.native_trace?.length || 0}</span>
      </div>
      <div class="tools-used">
        <span class="metric-label">{$t('tools.deepTrace.metrics.engines')}</span>
        <div class="tool-pills">
          {#if result.tools_used?.length}
            {#each result.tools_used as tool}
              <Badge variant="info" size="xs" mono>{tool}</Badge>
            {/each}
          {:else}
            <Badge variant="neutral" size="xs" mono>{$t('tools.deepTrace.metrics.pureGo')}</Badge>
          {/if}
        </div>
      </div>
    </section>

    <!-- Tabs & Inline Filter Bar -->
    <div class="tabs-bar">
      <div class="tabs-list" role="tablist">
        {#each tabs as tab (tab.id)}
          <button
            type="button"
            role="tab"
            aria-selected={activeView === tab.id}
            class="tab-btn"
            class:active={activeView === tab.id}
            on:click={() => (activeView = tab.id)}
          >
            <Icon name={tab.icon} size={13} />
            <span>{tab.label}</span>
            {#if tab.count !== null}
              <span class="tab-count mono tabular-nums">{tab.count}</span>
            {/if}
          </button>
        {/each}
      </div>

      {#if activeView === 'graph' || activeView === 'dex' || activeView === 'java' || activeView === 'native'}
        <div class="filter-box">
          <Icon name="search" size={13} />
          <input
            type="text"
            class="filter-input"
            bind:value={filterQuery}
            placeholder={$t('tools.deepTrace.filterPlaceholder')}
          />
          {#if filterQuery}
            <button type="button" class="filter-clear" on:click={() => (filterQuery = '')} title={$t('tools.deepTrace.clearFilterTitle')}>
              <Icon name="x" size={12} />
            </button>
          {/if}
        </div>
      {/if}
    </div>

    <!-- Tab Body -->
    <div class="trace-body">
      {#if activeView === 'steps'}
        <div class="steps-layout">
          {#if result.steps?.length}
            <div class="section-block">
              <h3 class="section-heading">{$t('tools.deepTrace.executionTimeline')}</h3>
              <div class="timeline">
                {#each result.steps as step, idx}
                  <div class="timeline-card status-{step.status}">
                    <div class="timeline-icon s-{step.status}">
                      <Icon name={stepStatusIcon(step.status)} size={15} />
                    </div>
                    <div class="timeline-main">
                      <div class="timeline-top">
                        <span class="step-idx mono tabular-nums">0{idx + 1}</span>
                        <span class="step-name mono">{step.name}</span>
                        <Badge variant={stepStatusVariant(step.status)} size="xs">{stepStatusLabel(step.status, $t)}</Badge>
                        <span class="step-dur mono tabular-nums">{formatDuration(step.duration_ms)}</span>
                      </div>
                      <div class="step-detail">{step.detail}</div>
                    </div>
                  </div>
                {/each}
              </div>
            </div>
          {/if}

          {#if result.apk_info}
            <div class="section-block">
              <h3 class="section-heading">{$t('tools.deepTrace.apkInspection')}</h3>
              <div class="apk-card cap-card">
                <div class="apk-header">
                  <div class="apk-title-row">
                    <span class="apk-icon"><Icon name="box" size={16} /></span>
                    <div>
                      <div class="apk-pkg mono">{result.apk_info.package || result.package}</div>
                      {#if result.apk_path}
                        <div class="apk-path mono truncate" title={result.apk_path}>{result.apk_path}</div>
                      {/if}
                    </div>
                  </div>
                  <div class="apk-badges">
                    <Badge variant="neutral" size="xs" mono>SDK {result.apk_info.min_sdk || '?'}–{result.apk_info.target_sdk || '?'}</Badge>
                    <Badge variant="accent" size="xs" mono>{result.apk_info.dex_count} DEX</Badge>
                    <Badge variant="purple" size="xs" mono>{result.apk_info.so_files?.length || 0} SO</Badge>
                    {#if result.apk_info.has_ns_config}
                      <Badge variant="warning" size="xs">network_security_config.xml</Badge>
                    {/if}
                  </div>
                </div>

                {#if result.apk_info.so_files?.length > 0}
                  <div class="apk-sub">
                    <div class="apk-sub-label">{$t('tools.deepTrace.nativeLibraries', { count: result.apk_info.so_files.length })}</div>
                    <div class="chip-wrap">
                      {#each result.apk_info.so_files as so}
                        <span class="mono-chip">{so}</span>
                      {/each}
                    </div>
                  </div>
                {/if}

                {#if result.apk_info.permissions?.length > 0}
                  <div class="apk-sub">
                    <button type="button" class="collapse-toggle" on:click={() => (showPermissions = !showPermissions)}>
                      <Icon name={showPermissions ? 'chevron-down' : 'chevron-right'} size={13} />
                      <span>{$t('tools.deepTrace.permissions', { count: result.apk_info.permissions.length })}</span>
                    </button>
                    {#if showPermissions}
                      <div class="chip-wrap">
                        {#each result.apk_info.permissions as perm}
                          <span class="mono-chip">{perm}</span>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}

                {#if result.apk_info.activities?.length > 0}
                  <div class="apk-sub">
                    <button type="button" class="collapse-toggle" on:click={() => (showActivities = !showActivities)}>
                      <Icon name={showActivities ? 'chevron-down' : 'chevron-right'} size={13} />
                      <span>{$t('tools.deepTrace.activities', { count: result.apk_info.activities.length })}</span>
                    </button>
                    {#if showActivities}
                      <div class="chip-wrap">
                        {#each result.apk_info.activities as act}
                          <span class="mono-chip">{act}</span>
                        {/each}
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </div>
          {/if}

          {#if traceLog.length > 0}
            <div class="section-block">
              <div class="section-head-row">
                <h3 class="section-heading">{$t('tools.deepTrace.traceLog')}</h3>
                <Button
                  variant="ghost"
                  size="xs"
                  icon="copy"
                  on:click={() =>
                    copyToClipboard(
                      traceLog.map((l) => `[${l.elapsed}s] ${l.msg}`).join('\n'),
                      translate('tools.deepTrace.toast.logCopied')
                    )}
                >
                  {$t('tools.deepTrace.copyLog')}
                </Button>
              </div>
              <div class="log-stream cap-card mono">
                {#each traceLog as entry}
                  <div class="log-line s-{entry.status}">
                    <span class="log-time tabular-nums">[{entry.elapsed}s]</span>
                    <span class="log-msg">{entry.msg}</span>
                  </div>
                {/each}
              </div>
            </div>
          {/if}
        </div>

      {:else if activeView === 'graph'}
        {#if filteredEdges.length > 0}
          <div class="cards-stack">
            {#each filteredEdges as edge}
              {@const meta = edgeTypeMeta(edge.type)}
              <div class="edge-card cap-card">
                <div class="edge-node from mono">{edge.from}</div>
                <div class="edge-connector">
                  <Badge variant={meta.variant} size="xs" mono>{meta.label}</Badge>
                  <Icon name="arrow-right" size={14} />
                </div>
                <div class="edge-node to mono">{edge.to}</div>
                {#if edge.label}
                  <span class="edge-meta mono">{edge.label}</span>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <EmptyState
            icon="git-branch"
            title={filterQuery ? $t('tools.deepTrace.empty.graphFilteredTitle') : $t('tools.deepTrace.empty.graphTitle')}
            description={filterQuery ? $t('tools.deepTrace.empty.filteredDesc') : $t('tools.deepTrace.empty.graphDesc')}
            compact
          />
        {/if}

      {:else if activeView === 'dex'}
        {#if filteredDex.length > 0}
          <div class="cards-stack">
            {#each filteredDex as dm}
              <div class="evidence-card cap-card">
                <div class="ev-header">
                  <div class="ev-meta">
                    <Badge variant="success" size="xs" mono>{dm.dex_file}</Badge>
                    <span class="ev-offset mono tabular-nums">
                      {$t('tools.deepTrace.offsetLabel', { hex: Number(dm.offset || 0).toString(16), dec: dm.offset })}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    on:click={() => copyToClipboard(dm.string, translate('tools.deepTrace.toast.dexCopied'))}
                  >
                    {$t('common.actions.copy')}
                  </Button>
                </div>
                <div class="dex-value mono">{dm.string}</div>
                {#if dm.context?.length > 0}
                  <div class="dex-ctx-block">
                    <span class="ctx-label">{$t('tools.deepTrace.nearbyStrings')}</span>
                    <div class="chip-wrap">
                      {#each dm.context.slice(0, 6) as ctx}
                        <span class="mono-chip">{ctx}</span>
                      {/each}
                    </div>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <EmptyState
            icon="database"
            title={filterQuery ? $t('tools.deepTrace.empty.dexFilteredTitle') : $t('tools.deepTrace.empty.dexTitle')}
            description={$t('tools.deepTrace.empty.dexDesc')}
            compact
          />
        {/if}

      {:else if activeView === 'java'}
        {#if filteredJava.length > 0}
          <div class="cards-stack">
            {#each filteredJava as jr}
              <div class="evidence-card cap-card">
                <div class="ev-header">
                  <div class="ev-meta">
                    <Icon name="file-code" size={14} />
                    <span class="ref-file mono">{jr.file}<span class="ref-line">:{jr.line}</span></span>
                    {#if jr.calls_native}
                      <Badge variant="warning" size="xs" mono>JNI</Badge>
                    {/if}
                    {#if jr.annotation}
                      <Badge variant="success" size="xs" mono>{jr.annotation}</Badge>
                    {/if}
                    {#if jr.matched_term}
                      <Badge variant="accent" size="xs" mono>{jr.matched_term}</Badge>
                    {/if}
                  </div>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    on:click={() =>
                      copyToClipboard(jr.snippet || `${jr.class}.${jr.method}`, translate('tools.deepTrace.toast.javaCopied'))}
                  >
                    {$t('common.actions.copy')}
                  </Button>
                </div>
                <div class="ref-symbol mono">{jr.class}{jr.method ? `.${jr.method}()` : ''}</div>
                {#if jr.snippet}
                  <pre class="code-viewer mono">{jr.snippet}</pre>
                {/if}
                {#if jr.native_methods?.length > 0}
                  <div class="native-methods-row">
                    <span class="ctx-label">{$t('tools.deepTrace.declaredNativeMethods')}</span>
                    <div class="chip-wrap">
                      {#each jr.native_methods as nm}
                        <Badge variant="warning" size="xs" mono>{nm}</Badge>
                      {/each}
                    </div>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <EmptyState
            icon="file-code"
            title={filterQuery ? $t('tools.deepTrace.empty.javaFilteredTitle') : $t('tools.deepTrace.empty.javaTitle')}
            description={$t('tools.deepTrace.empty.javaDesc')}
            compact
          />
        {/if}

      {:else if activeView === 'native'}
        {#if filteredNative.length > 0}
          <div class="cards-stack">
            {#each filteredNative as nr}
              <div class="evidence-card cap-card">
                <div class="ev-header">
                  <div class="ev-meta">
                    <Badge variant="danger" size="xs" mono>{nr.so_file}</Badge>
                    <span class="nr-func mono">{nr.function}</span>
                    {#if nr.address}
                      <Badge variant="neutral" size="xs" mono>{nr.address}</Badge>
                    {/if}
                  </div>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    on:click={() =>
                      copyToClipboard(`${nr.so_file} :: ${nr.function} (${nr.address || ''})`, translate('tools.deepTrace.toast.symbolCopied'))}
                  >
                    {$t('common.actions.copy')}
                  </Button>
                </div>

                {#if nr.calls?.length > 0}
                  <div class="nr-group">
                    <span class="ctx-label">{$t('tools.deepTrace.calledSymbols', { count: nr.calls.length })}</span>
                    <div class="chip-wrap">
                      {#each nr.calls as c}
                        <Badge variant="accent" size="xs" mono>{c}</Badge>
                      {/each}
                    </div>
                  </div>
                {/if}

                {#if nr.imports?.length > 0}
                  <div class="nr-group">
                    <span class="ctx-label">{$t('tools.deepTrace.imports', { count: nr.imports.length })}</span>
                    <div class="chip-wrap">
                      {#each nr.imports.slice(0, 12) as imp}
                        <span class="mono-chip">{imp}</span>
                      {/each}
                    </div>
                  </div>
                {/if}

                {#if nr.strings?.length > 0}
                  <div class="nr-group">
                    <span class="ctx-label">{$t('tools.deepTrace.strings', { count: nr.strings.length })}</span>
                    <pre class="code-viewer mono">{nr.strings.slice(0, 15).join('\n')}</pre>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else}
          <EmptyState
            icon="cpu"
            title={filterQuery ? $t('tools.deepTrace.empty.nativeFilteredTitle') : $t('tools.deepTrace.empty.nativeTitle')}
            description={$t('tools.deepTrace.empty.nativeDesc')}
            compact
          />
        {/if}

      {:else if activeView === 'summary'}
        <div class="doc-card cap-card">
          <div class="doc-toolbar">
            <span class="doc-title">{$t('tools.deepTrace.reportTitle')}</span>
            <Button
              variant="secondary"
              size="xs"
              icon="copy"
              on:click={() => copyToClipboard(result.summary || '', translate('tools.deepTrace.toast.summaryCopied'))}
            >
              {$t('tools.deepTrace.copySummary')}
            </Button>
          </div>
          <pre class="doc-pre mono">{result.summary || $t('tools.deepTrace.noSummary')}</pre>
        </div>

      {:else if activeView === 'mermaid'}
        <div class="doc-card cap-card">
          <div class="doc-toolbar">
            <span class="doc-title">{$t('tools.deepTrace.mermaidTitle')}</span>
            <Button
              variant="secondary"
              size="xs"
              icon="copy"
              disabled={!result.mermaid}
              on:click={() => copyToClipboard(result.mermaid || '', translate('tools.deepTrace.toast.mermaidCopied'))}
            >
              {$t('tools.deepTrace.copyMermaid')}
            </Button>
          </div>
          <pre class="doc-pre mermaid-pre mono">{result.mermaid || $t('tools.deepTrace.noMermaid')}</pre>
        </div>
      {/if}
    </div>
  {:else if !tracing}
    <!-- Polished Onboarding / Empty State -->
    <div class="onboarding-wrap">
      <EmptyState
        icon="git-branch"
        title={$t('tools.deepTrace.empty.onboardingTitle')}
        description={$t('tools.deepTrace.empty.onboardingDesc')}
      >
        <div class="pipeline-preview">
          <div class="pipe-step">
            <Icon name="globe" size={14} />
            <span>{$t('tools.deepTrace.empty.stageHttp')}</span>
          </div>
          <Icon name="arrow-right" size={13} />
          <div class="pipe-step">
            <Icon name="database" size={14} />
            <span>{$t('tools.deepTrace.empty.stageDex')}</span>
          </div>
          <Icon name="arrow-right" size={13} />
          <div class="pipe-step">
            <Icon name="file-code" size={14} />
            <span>{$t('tools.deepTrace.empty.stageJava')}</span>
          </div>
          <Icon name="arrow-right" size={13} />
          <div class="pipe-step">
            <Icon name="cpu" size={14} />
            <span>{$t('tools.deepTrace.empty.stageNative')}</span>
          </div>
        </div>

        <div class="prereq-grid">
          <div class="prereq-card">
            <Badge variant="success" size="xs" mono>{$t('tools.deepTrace.empty.prereqBuiltIn')}</Badge>
            <div class="prereq-name">{$t('tools.deepTrace.empty.prereqDexTitle')}</div>
            <div class="prereq-desc">{$t('tools.deepTrace.empty.prereqDexDesc')}</div>
          </div>
          <div class="prereq-card">
            <Badge variant="accent" size="xs" mono>jadx</Badge>
            <div class="prereq-name">{$t('tools.deepTrace.empty.prereqJavaTitle')}</div>
            <div class="prereq-desc">{$t('tools.deepTrace.empty.prereqJavaDesc')}</div>
          </div>
          <div class="prereq-card">
            <Badge variant="purple" size="xs" mono>r2</Badge>
            <div class="prereq-name">{$t('tools.deepTrace.empty.prereqNativeTitle')}</div>
            <div class="prereq-desc">{$t('tools.deepTrace.empty.prereqNativeDesc')}</div>
          </div>
        </div>
      </EmptyState>
    </div>
  {/if}
</div>

<style>
  .trace-page {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Configuration Panel */
  .config-panel {
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    flex-shrink: 0;
  }

  .config-grid {
    display: flex;
    align-items: flex-end;
    gap: 10px;
    flex-wrap: wrap;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .flow-field {
    flex: 2;
    min-width: 260px;
  }

  .pkg-field {
    flex: 1.3;
    min-width: 220px;
  }

  .action-field {
    flex-shrink: 0;
  }

  .field-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .field-label {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-muted);
  }

  .inline-link {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border: none;
    background: transparent;
    color: var(--accent);
    font-size: var(--text-xs);
    cursor: pointer;
    padding: 0;
    transition: opacity var(--transition-fast);
  }

  .inline-link:hover:not(:disabled) {
    text-decoration: underline;
  }

  .inline-link:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .select-input,
  .pkg-input {
    width: 100%;
    height: 34px;
  }

  .pkg-input-wrap {
    position: relative;
  }

  .app-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    right: 0;
    background: var(--bg-elevated);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    z-index: var(--z-dropdown);
    overflow: hidden;
  }

  .dropdown-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border-subtle);
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
  }

  .dropdown-close {
    border: none;
    background: transparent;
    color: var(--text-muted);
    cursor: pointer;
    display: flex;
    padding: 2px;
    border-radius: var(--radius-xs);
  }

  .dropdown-close:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .dropdown-list {
    max-height: 220px;
    overflow-y: auto;
    padding: 4px;
  }

  .dropdown-item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-xs);
    border-radius: var(--radius-xs);
    cursor: pointer;
    text-align: left;
  }

  .dropdown-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  /* Selected Flow Preview Strip */
  .flow-preview {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    min-width: 0;
  }

  .preview-url {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    flex: 1;
    min-width: 0;
  }

  .preview-meta {
    font-size: var(--text-xs);
    color: var(--text-muted);
    flex-shrink: 0;
  }

  .sign-strip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding-left: 8px;
    border-left: 1px solid var(--border-default);
    color: var(--status-warning);
    flex-shrink: 0;
  }

  .sign-label {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  /* Progress Panel */
  .progress-panel {
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-default);
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .progress-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  .progress-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-sm);
    color: var(--text-primary);
  }

  .spin-wrap {
    display: inline-flex;
    color: var(--accent);
    animation: cap-spin 1s linear infinite;
  }

  .log-stream {
    max-height: 200px;
    overflow-y: auto;
    padding: 10px 12px;
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .log-line {
    font-size: var(--text-xs);
    line-height: 1.55;
    display: flex;
    gap: 8px;
    color: var(--text-secondary);
  }

  .log-time {
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .log-line.s-ok .log-msg {
    color: var(--status-success);
  }

  .log-line.s-skip .log-msg {
    color: var(--text-faint);
  }

  .log-line.s-error .log-msg {
    color: var(--status-danger);
  }

  /* Metrics Strip */
  .metrics-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .metric-card {
    display: flex;
    align-items: baseline;
    gap: 6px;
    padding: 5px 10px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
  }

  .metric-label {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .metric-val {
    font-size: var(--text-sm);
    font-weight: 700;
    color: var(--text-primary);
  }

  .metric-val.accent {
    color: var(--accent);
  }

  .metric-val.success {
    color: var(--status-success);
  }

  .tools-used {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .tool-pills {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  /* Tabs Bar */
  .tabs-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 0 16px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-shrink: 0;
  }

  .tabs-list {
    display: flex;
    align-items: center;
    gap: 2px;
    overflow-x: auto;
  }

  .tab-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 38px;
    padding: 0 11px;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--text-muted);
    font-size: var(--text-sm);
    font-weight: 500;
    cursor: pointer;
    white-space: nowrap;
    transition: color var(--transition-fast), border-color var(--transition-fast);
  }

  .tab-btn:hover {
    color: var(--text-primary);
  }

  .tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .tab-count {
    font-size: 10px;
    padding: 1px 5px;
    border-radius: var(--radius-full);
    background: var(--bg-subtle);
    color: var(--text-muted);
  }

  .tab-btn.active .tab-count {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .filter-box {
    display: flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 8px;
    background: var(--bg-input);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    width: 210px;
    flex-shrink: 0;
  }

  .filter-box:focus-within {
    border-color: var(--accent);
    box-shadow: var(--focus-ring);
  }

  .filter-input {
    border: none;
    background: transparent;
    outline: none;
    font-size: var(--text-xs);
    color: var(--text-primary);
    flex: 1;
    min-width: 0;
  }

  .filter-clear {
    border: none;
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    display: flex;
    padding: 1px;
  }

  .filter-clear:hover {
    color: var(--text-primary);
  }

  /* Main Results Viewport */
  .trace-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    min-height: 0;
  }

  .steps-layout {
    display: flex;
    flex-direction: column;
    gap: 18px;
    max-width: 980px;
  }

  .section-block {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .section-head-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .section-heading {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
  }

  .timeline {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .timeline-card {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-md);
  }

  .timeline-icon {
    margin-top: 2px;
    flex-shrink: 0;
  }

  .timeline-icon.s-ok {
    color: var(--status-success);
  }

  .timeline-icon.s-skip {
    color: var(--text-faint);
  }

  .timeline-icon.s-error {
    color: var(--status-danger);
  }

  .timeline-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .timeline-top {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .step-idx {
    font-size: var(--text-xs);
    color: var(--text-faint);
  }

  .step-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .step-dur {
    margin-left: auto;
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .step-detail {
    font-size: var(--text-xs);
    color: var(--text-secondary);
    line-height: 1.5;
  }

  /* APK Card */
  .apk-card {
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .apk-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }

  .apk-title-row {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .apk-icon {
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    border: 1px solid var(--accent-border);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .apk-pkg {
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .apk-path {
    font-size: var(--text-xs);
    color: var(--text-muted);
    max-width: 460px;
  }

  .apk-badges {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }

  .apk-sub {
    padding-top: 10px;
    border-top: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .apk-sub-label {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
  }

  .collapse-toggle {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
    padding: 0;
    width: fit-content;
  }

  .collapse-toggle:hover {
    color: var(--text-primary);
  }

  .chip-wrap {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }

  .mono-chip {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 2px 7px;
    border-radius: var(--radius-xs);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    word-break: break-all;
  }

  /* Call Graph & Evidence Cards */
  .cards-stack {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .edge-card {
    padding: 10px 14px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .edge-node {
    font-size: var(--text-xs);
    word-break: break-all;
  }

  .edge-node.from {
    color: var(--text-primary);
    font-weight: 600;
  }

  .edge-node.to {
    color: var(--accent);
    font-weight: 500;
  }

  .edge-connector {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--text-faint);
    flex-shrink: 0;
  }

  .edge-meta {
    margin-left: auto;
    font-size: var(--text-2xs);
    color: var(--text-muted);
  }

  .evidence-card {
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .ev-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    flex-wrap: wrap;
  }

  .ev-meta {
    display: flex;
    align-items: center;
    gap: 7px;
    flex-wrap: wrap;
    color: var(--text-muted);
  }

  .ev-offset {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .dex-value {
    font-size: var(--text-sm);
    color: var(--status-success);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    padding: 8px 10px;
    word-break: break-all;
  }

  .dex-ctx-block,
  .native-methods-row,
  .nr-group {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .ctx-label {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .ref-file {
    font-size: var(--text-xs);
    color: var(--accent);
    font-weight: 500;
  }

  .ref-line {
    color: var(--text-faint);
  }

  .ref-symbol {
    font-size: var(--text-xs);
    color: var(--text-secondary);
  }

  .nr-func {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .code-viewer {
    font-size: var(--text-xs);
    line-height: 1.6;
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    padding: 10px 12px;
    overflow-x: auto;
    margin: 0;
  }

  /* Summary & Mermaid Docs */
  .doc-card {
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .doc-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 9px 14px;
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-subtle);
  }

  .doc-title {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .doc-pre {
    padding: 14px;
    font-size: var(--text-xs);
    line-height: 1.65;
    color: var(--text-secondary);
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
  }

  .mermaid-pre {
    color: var(--status-success);
  }

  /* Onboarding Empty State */
  .onboarding-wrap {
    flex: 1;
    overflow-y: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .pipeline-preview {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    justify-content: center;
    margin-top: 8px;
    color: var(--text-faint);
  }

  .pipe-step {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 10px;
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    color: var(--text-secondary);
    font-size: var(--text-xs);
    font-weight: 500;
  }

  .prereq-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(160px, 210px));
    gap: 10px;
    margin-top: 14px;
    text-align: left;
  }

  .prereq-card {
    padding: 12px;
    border-radius: var(--radius-md);
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
  }

  .prereq-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .prereq-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }
</style>
