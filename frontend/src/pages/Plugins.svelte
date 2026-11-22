<script>
  import { onMount } from 'svelte'
  import '../lib/locales/tools.js'
  import { t, translate } from '../lib/i18n.js'
  import { MOD_LABEL } from '../lib/shortcuts.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import SplitPane from '../components/SplitPane.svelte'
  import { toast } from '../lib/toast.js'
  import { copyToClipboard, formatDuration } from '../lib/format.js'

  const api = () => window?.go?.wailsgui?.App

  let plugins = []
  let examples = []
  let recentFlows = []
  let selectedPlugin = null

  let editName = ''
  let editDesc = ''
  let editType = 'analyzer'
  let editCode = ''
  let editEnabled = true
  let isNew = false
  let dirty = false

  let searchQuery = ''
  let typeFilter = 'all'
  let confirmDelete = false
  let saving = false
  let running = false

  let runOutput = ''
  let runError = false
  let runDurationMs = null
  let runFlowId = ''

  const pluginTypeStyles = {
    analyzer: { variant: 'accent', icon: 'radar' },
    request_filter: { variant: 'info', icon: 'filter' },
    response_modifier: { variant: 'purple', icon: 'edit' },
  }

  function getTypeMeta(type, tr = translate) {
    const style = pluginTypeStyles[type] || { variant: 'neutral', icon: 'puzzle' }
    const labelKey = pluginTypeStyles[type] ? `tools.plugins.types.${type}` : 'tools.plugins.types.fallback'
    return { ...style, label: tr(labelKey) }
  }

  function formatUpdated(ts) {
    if (!ts) return ''
    const d = new Date(ts)
    if (Number.isNaN(d.getTime())) return ''
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
  }

  async function loadPlugins(notify = false) {
    const app = api()
    if (!app?.ListPlugins) return
    try {
      plugins = (await app.ListPlugins()) || []
      if (selectedPlugin) {
        const refreshed = plugins.find((p) => p.name === selectedPlugin.name)
        if (refreshed) {
          selectedPlugin = refreshed
          editEnabled = Boolean(refreshed.enabled)
        }
      }
      if (notify) toast.info(translate('tools.plugins.toast.reloaded', { count: plugins.length }))
    } catch (e) {
      if (notify) toast.error(translate('tools.plugins.toast.loadFailed', { error: e?.message || e }))
    }
  }

  async function loadExamples() {
    const app = api()
    if (!app?.GetExamplePlugins) return
    try {
      examples = (await app.GetExamplePlugins()) || []
    } catch (_) {
      examples = []
    }
  }

  async function loadRecentFlows() {
    const app = api()
    if (!app?.GetFlows) return
    try {
      recentFlows = (await app.GetFlows('', '', '', 50)) || []
      if (!runFlowId && recentFlows.length > 0) {
        runFlowId = recentFlows[0].id
      }
    } catch (_) {}
  }

  function selectPlugin(p) {
    selectedPlugin = p
    editName = p.name || ''
    editDesc = p.description || ''
    editType = p.type || 'analyzer'
    editCode = p.code || ''
    editEnabled = Boolean(p.enabled)
    isNew = false
    dirty = false
    confirmDelete = false
    runOutput = ''
    runError = false
    runDurationMs = null
  }

  function newPlugin(defaultType = 'analyzer') {
    selectedPlugin = null
    editName = ''
    editDesc = ''
    editType = defaultType
    editEnabled = true
    editCode =
      defaultType === 'request_filter'
        ? `// Request filter plugin\n// Inspects outgoing HTTP requests\n\nfunction onRequest(flow) {\n  return {\n    flow_id: flow.id,\n    method: flow.method,\n    url: flow.url,\n  };\n}\n`
        : defaultType === 'response_modifier'
          ? `// Response hook plugin\n// Inspects or annotates HTTP responses\n\nfunction onResponse(flow) {\n  return {\n    flow_id: flow.id,\n    status: flow.status,\n    latency_ms: flow.latency_ms,\n  };\n}\n`
          : `// Analyzer plugin\n// Runs security & signature analysis on captured flows\n\nfunction analyze(flow) {\n  return {\n    flow_id: flow.id,\n    method: flow.method,\n    url: flow.url,\n    result: "your analysis here"\n  };\n}\n`
    isNew = true
    dirty = true
    confirmDelete = false
    runOutput = ''
    runError = false
    runDurationMs = null
  }

  async function loadExample(idx) {
    const app = api()
    if (!app?.GetExamplePlugins) return
    try {
      const list = examples.length ? examples : (await app.GetExamplePlugins()) || []
      const ex = list[idx]
      if (!ex) return
      selectedPlugin = null
      editName = ex.name
      editDesc = ex.description
      editType = ex.type
      editCode = ex.code
      editEnabled = true
      isNew = true
      dirty = false
      confirmDelete = false
      await savePlugin(true)
      toast.success(translate('tools.plugins.toast.installedExample', { name: ex.name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.exampleFailed', { error: e?.message || e }))
    }
  }

  async function savePlugin(silent = false) {
    const name = editName.trim()
    if (!name) {
      toast.warning(translate('tools.plugins.toast.nameRequired'))
      return false
    }
    const app = api()
    if (!app?.SavePlugin) return false
    saving = true
    try {
      await app.SavePlugin({
        name,
        description: editDesc.trim(),
        type: editType,
        code: editCode,
        enabled: editEnabled,
      })
      isNew = false
      dirty = false
      await loadPlugins()
      selectedPlugin = plugins.find((p) => p.name === name) || selectedPlugin
      if (!silent) toast.success(translate('tools.plugins.toast.saved', { name }))
      return true
    } catch (e) {
      const msg = e?.message || String(e)
      runOutput = translate('tools.plugins.toast.saveFailed', { error: msg })
      runError = true
      toast.error(translate('tools.plugins.toast.saveFailed', { error: msg }))
      return false
    } finally {
      saving = false
    }
  }

  async function deletePlugin(name) {
    const app = api()
    if (!app?.DeletePlugin) return
    try {
      await app.DeletePlugin(name)
      selectedPlugin = null
      editName = ''
      editDesc = ''
      editCode = ''
      isNew = false
      dirty = false
      confirmDelete = false
      runOutput = ''
      runError = false
      await loadPlugins()
      toast.info(translate('tools.plugins.toast.deleted', { name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.deleteFailed', { error: e?.message || e }))
    }
  }

  async function togglePlugin(p) {
    const app = api()
    if (!app?.TogglePlugin) return
    try {
      await app.TogglePlugin(p.name)
      await loadPlugins()
      const updated = plugins.find((x) => x.name === p.name)
      const key = updated?.enabled ? 'tools.plugins.toast.enabled' : 'tools.plugins.toast.disabled'
      toast.info(translate(key, { name: p.name }))
    } catch (e) {
      toast.error(translate('tools.plugins.toast.toggleFailed', { error: e?.message || e }))
    }
  }

  async function runPlugin() {
    if (!editName.trim()) {
      toast.warning(translate('tools.plugins.toast.nameBeforeRun'))
      return
    }
    if (!runFlowId.trim()) {
      toast.warning(translate('tools.plugins.toast.flowIdRequired'))
      return
    }
    const app = api()
    if (!app?.RunPlugin) return

    if (isNew || dirty) {
      const ok = await savePlugin(true)
      if (!ok) return
    }

    running = true
    const t0 = performance.now()
    try {
      const result = await app.RunPlugin(editName.trim(), runFlowId.trim())
      runDurationMs = Math.round(performance.now() - t0)
      if (result?.error) {
        runOutput = result.error
        runError = true
        toast.error(translate('tools.plugins.toast.pluginError', { error: result.error }))
      } else {
        runOutput = result?.output || translate('tools.plugins.noOutput')
        runError = false
      }
    } catch (e) {
      runDurationMs = Math.round(performance.now() - t0)
      runOutput = e?.message || String(e)
      runError = true
      toast.error(translate('tools.plugins.toast.runFailed', { error: runOutput }))
    } finally {
      running = false
    }
  }

  function handleCodeKeydown(e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's') {
      e.preventDefault()
      savePlugin()
      return
    }
    if (e.key === 'Tab') {
      e.preventDefault()
      const el = e.target
      const start = el.selectionStart
      const end = el.selectionEnd
      editCode = editCode.slice(0, start) + '  ' + editCode.slice(end)
      dirty = true
      requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = start + 2
      })
    }
  }

  $: filteredPlugins = plugins.filter((p) => {
    if (typeFilter !== 'all' && p.type !== typeFilter) return false
    const q = searchQuery.trim().toLowerCase()
    if (!q) return true
    return (
      (p.name || '').toLowerCase().includes(q) ||
      (p.description || '').toLowerCase().includes(q) ||
      (p.type || '').toLowerCase().includes(q)
    )
  })

  $: enabledCount = plugins.filter((p) => p.enabled).length
  $: lineCount = editCode ? editCode.split('\n').length : 0

  onMount(() => {
    loadPlugins()
    loadExamples()
    loadRecentFlows()
  })
</script>

<div class="plugins-page">
  <SplitPane direction="horizontal" initialSize={30} minPrimary={22} minSecondary={45} storageKey="cap.plugins.split">
    <!-- Left Extension Directory -->
    <div slot="primary" class="sidebar-pane">
      <div class="list-toolbar">
        <div class="list-title-group">
          <span class="pane-title">{$t('tools.plugins.title')}</span>
          <Badge variant="neutral" size="xs" mono>{enabledCount}/{plugins.length}</Badge>
        </div>
        <div class="toolbar-btns">
          <Button variant="ghost" size="xs" icon="refresh" iconOnly title={$t('tools.plugins.reloadTitle')} on:click={() => loadPlugins(true)} />
          <Button variant="primary" size="xs" icon="plus" on:click={() => newPlugin()}>{$t('tools.plugins.newBtn')}</Button>
        </div>
      </div>

      <!-- Search & Filter -->
      <div class="list-filters">
        <div class="search-wrap">
          <Icon name="search" size={13} />
          <input type="text" class="search-input" bind:value={searchQuery} placeholder={$t('tools.plugins.searchPlaceholder')} />
          {#if searchQuery}
            <button type="button" class="icon-clear" title={$t('common.actions.clear')} on:click={() => (searchQuery = '')}>
              <Icon name="x" size={12} />
            </button>
          {/if}
        </div>
        <div class="filter-pills">
          {#each ['all', 'analyzer', 'request_filter', 'response_modifier'] as val}
            <button type="button" class="f-pill" class:active={typeFilter === val} on:click={() => (typeFilter = val)}>
              {$t(`tools.plugins.filters.${val}`)}
            </button>
          {/each}
        </div>
      </div>

      <!-- Installed Plugins -->
      <div class="plugin-list">
        {#each filteredPlugins as p (p.name)}
          {@const meta = getTypeMeta(p.type, $t)}
          <div class="plugin-card" class:selected={selectedPlugin?.name === p.name} class:disabled={!p.enabled}>
            <button type="button" class="plugin-select" on:click={() => selectPlugin(p)}>
              <div class="plugin-top">
                <span class="plugin-name truncate">{p.name}</span>
                <Badge variant={meta.variant} size="xs">{meta.label}</Badge>
              </div>
              {#if p.description}
                <div class="plugin-desc truncate">{p.description}</div>
              {/if}
              {#if p.updated_at}
                <div class="plugin-meta">{$t('tools.plugins.updatedAt', { date: formatUpdated(p.updated_at) })}</div>
              {/if}
            </button>

            <label class="switch" title={p.enabled ? $t('tools.plugins.disableTitle') : $t('tools.plugins.enableTitle')}>
              <input type="checkbox" checked={p.enabled} on:change={() => togglePlugin(p)} />
              <span class="switch-track"></span>
            </label>
          </div>
        {/each}

        {#if filteredPlugins.length === 0}
          <EmptyState
            icon="puzzle"
            title={plugins.length === 0 ? $t('tools.plugins.empty.noPluginsTitle') : $t('tools.plugins.empty.filteredTitle')}
            description={plugins.length === 0 ? $t('tools.plugins.empty.noPluginsDesc') : $t('tools.plugins.empty.filteredDesc')}
            compact
          />
        {/if}
      </div>

      <!-- Built-in Templates -->
      <div class="examples-box">
        <div class="examples-head">
          <Icon name="sparkles" size={12} />
          <span>{$t('tools.plugins.starterTemplates')}</span>
        </div>
        <div class="examples-list">
          {#if examples.length > 0}
            {#each examples as ex, idx (ex.name)}
              <button type="button" class="example-chip" on:click={() => loadExample(idx)} title={ex.description}>
                <Icon name="plus" size={11} />
                <span class="mono">{ex.name}</span>
              </button>
            {/each}
          {:else}
            {#each ['log-requests', 'detect-keys', 'sign-validator'] as label, idx}
              <button type="button" class="example-chip" on:click={() => loadExample(idx)}>
                <Icon name="plus" size={11} />
                <span class="mono">{label}</span>
              </button>
            {/each}
          {/if}
        </div>
      </div>
    </div>

    <!-- Right Code Editor + Output Drawer -->
    <div slot="secondary" class="studio-pane">
      {#if editCode || isNew}
        <!-- Metadata & Action Toolbar -->
        <div class="studio-toolbar">
          <div class="meta-inputs">
            <input
              type="text"
              class="cap-input name-input mono"
              placeholder={$t('tools.plugins.namePlaceholder')}
              bind:value={editName}
              on:input={() => (dirty = true)}
            />
            <input
              type="text"
              class="cap-input desc-input"
              placeholder={$t('tools.plugins.descPlaceholder')}
              bind:value={editDesc}
              on:input={() => (dirty = true)}
            />
            <select
              class="cap-input type-select"
              bind:value={editType}
              on:change={() => (dirty = true)}
            >
              <option value="analyzer">{$t('tools.plugins.types.analyzer')}</option>
              <option value="request_filter">{$t('tools.plugins.types.request_filter')}</option>
              <option value="response_modifier">{$t('tools.plugins.types.response_modifier')}</option>
            </select>
          </div>

          <div class="toolbar-actions">
            {#if dirty}
              <Badge variant="warning" size="xs" dot>{$t('tools.plugins.unsaved')}</Badge>
            {/if}
            <Button
              variant="ghost"
              size="xs"
              icon="copy"
              title={$t('tools.plugins.copyCodeTitle')}
              on:click={() => copyToClipboard(editCode, translate('tools.plugins.toast.codeCopied'))}
            >
              {$t('common.actions.copy')}
            </Button>
            {#if selectedPlugin}
              {#if confirmDelete}
                <Button variant="danger" size="xs" icon="trash" on:click={() => deletePlugin(selectedPlugin.name)}>
                  {$t('common.actions.confirm')}
                </Button>
                <Button variant="ghost" size="xs" on:click={() => (confirmDelete = false)}>{$t('common.actions.cancel')}</Button>
              {:else}
                <Button variant="ghost" size="xs" icon="trash" on:click={() => (confirmDelete = true)}>
                  {$t('common.actions.delete')}
                </Button>
              {/if}
            {/if}
            <Button variant="primary" size="xs" icon="save" loading={saving} on:click={() => savePlugin()}>
              {$t('common.actions.save')}
            </Button>
          </div>
        </div>

        <!-- Vertical Split: Code Editor + Test Runner Drawer -->
        <div class="studio-split-wrap">
          <SplitPane direction="vertical" initialSize={64} minPrimary={28} minSecondary={20} storageKey="cap.plugins.drawer">
            <div slot="primary" class="code-pane">
              <textarea
                class="code-editor mono"
                bind:value={editCode}
                on:input={() => (dirty = true)}
                on:keydown={handleCodeKeydown}
                spellcheck="false"
                placeholder={$t('tools.plugins.codePlaceholder')}
              ></textarea>
              <div class="editor-status mono">
                <span>{getTypeMeta(editType, $t).label}</span>
                <span>·</span>
                <span class="tabular-nums">{$t('tools.plugins.linesCount', { count: lineCount })}</span>
                <span>·</span>
                <span class="tabular-nums">{$t('tools.plugins.charsCount', { count: editCode.length })}</span>
                <span class="status-spacer"></span>
                <span>{$t('tools.plugins.editorHint', { mod: MOD_LABEL })}</span>
              </div>
            </div>

            <div slot="secondary" class="drawer-pane">
              <div class="drawer-bar">
                <div class="drawer-left">
                  <Icon name="terminal" size={13} />
                  <span class="drawer-title">{$t('tools.plugins.testRunner')}</span>
                  {#if runDurationMs !== null}
                    <Badge variant={runError ? 'danger' : 'success'} size="xs" mono>
                      {runError ? $t('tools.plugins.statusError') : $t('tools.plugins.statusOk')} · {formatDuration(runDurationMs)}
                    </Badge>
                  {/if}
                </div>

                <div class="drawer-controls">
                  {#if recentFlows.length > 0}
                    <select class="cap-input flow-select mono" bind:value={runFlowId} title={$t('tools.plugins.pickFlowTitle')}>
                      {#each recentFlows as f (f.id)}
                        <option value={f.id}>{f.id} — {f.method} {f.host}{f.path}</option>
                      {/each}
                    </select>
                  {/if}
                  <input
                    type="text"
                    class="cap-input flow-id-input mono"
                    placeholder={$t('tools.plugins.flowIdPlaceholder')}
                    bind:value={runFlowId}
                    on:keydown={(e) => {
                      if (e.key === 'Enter') runPlugin()
                    }}
                  />
                  <Button variant="primary" size="xs" icon="play" loading={running} on:click={runPlugin}>
                    {$t('tools.plugins.run')}
                  </Button>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="copy"
                    iconOnly
                    disabled={!runOutput}
                    title={$t('tools.plugins.copyOutputTitle')}
                    on:click={() => copyToClipboard(runOutput, translate('tools.plugins.toast.outputCopied'))}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon="x"
                    iconOnly
                    disabled={!runOutput}
                    title={$t('tools.plugins.clearOutputTitle')}
                    on:click={() => {
                      runOutput = ''
                      runError = false
                      runDurationMs = null
                    }}
                  />
                </div>
              </div>

              <pre class="drawer-output mono" class:is-error={runError}>{runOutput || $t('tools.plugins.outputPlaceholder')}</pre>
            </div>
          </SplitPane>
        </div>
      {:else}
        <EmptyState
          icon="puzzle"
          title={$t('tools.plugins.empty.studioTitle')}
          description={$t('tools.plugins.empty.studioDesc')}
        >
          <Button variant="primary" size="sm" icon="plus" on:click={() => newPlugin('analyzer')}>
            {$t('tools.plugins.empty.newAnalyzer')}
          </Button>
          <Button variant="secondary" size="sm" icon="filter" on:click={() => newPlugin('request_filter')}>
            {$t('tools.plugins.empty.newRequestFilter')}
          </Button>
          <Button variant="secondary" size="sm" icon="sparkles" on:click={() => loadExample(0)}>
            {$t('tools.plugins.empty.installExample')}
          </Button>
        </EmptyState>
      {/if}
    </div>
  </SplitPane>
</div>

<style>
  .plugins-page {
    height: 100%;
    min-height: 0;
    background: var(--bg-app);
  }

  /* Left Sidebar */
  .sidebar-pane {
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

  .toolbar-btns {
    display: flex;
    align-items: center;
    gap: 4px;
  }

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

  .filter-pills {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  .f-pill {
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

  .f-pill:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .f-pill.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
  }

  .plugin-list {
    flex: 1;
    overflow-y: auto;
    min-height: 0;
  }

  .plugin-card {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    border-bottom: 1px solid var(--border-subtle);
    border-left: 2px solid transparent;
    transition: background var(--transition-fast);
  }

  .plugin-card:hover {
    background: var(--bg-hover);
  }

  .plugin-card.selected {
    background: var(--bg-active);
    border-left-color: var(--accent);
  }

  .plugin-card.disabled .plugin-name,
  .plugin-card.disabled .plugin-desc {
    opacity: 0.55;
  }

  .plugin-select {
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

  .plugin-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }

  .plugin-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .plugin-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }

  .plugin-meta {
    font-size: 10px;
    color: var(--text-faint);
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

  /* Examples Footer */
  .examples-box {
    padding: 10px 12px;
    border-top: 1px solid var(--border-default);
    background: var(--bg-surface);
    display: flex;
    flex-direction: column;
    gap: 7px;
    flex-shrink: 0;
  }

  .examples-head {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-muted);
  }

  .examples-list {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }

  .example-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 8px;
    border-radius: var(--radius-xs);
    border: 1px solid var(--border-default);
    background: var(--bg-elevated);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .example-chip:hover {
    border-color: var(--accent-border);
    background: var(--accent-soft);
    color: var(--accent);
  }

  /* Right Studio */
  .studio-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-app);
  }

  .studio-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 8px 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .meta-inputs {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 260px;
  }

  .name-input {
    width: 155px;
    height: 28px;
  }

  .desc-input {
    flex: 1;
    min-width: 120px;
    height: 28px;
  }

  .type-select {
    width: 145px;
    height: 28px;
    cursor: pointer;
  }

  .toolbar-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  .studio-split-wrap {
    flex: 1;
    min-height: 0;
  }

  .code-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .code-editor {
    flex: 1;
    width: 100%;
    resize: none;
    border: none;
    outline: none;
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 13px;
    line-height: 1.65;
    padding: 14px 16px;
    tab-size: 2;
  }

  .editor-status {
    height: 24px;
    padding: 0 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 10.5px;
    color: var(--text-faint);
    background: var(--bg-header);
    border-top: 1px solid var(--border-subtle);
    flex-shrink: 0;
  }

  .status-spacer {
    flex: 1;
  }

  /* Test Drawer */
  .drawer-pane {
    height: 100%;
    display: flex;
    flex-direction: column;
    min-height: 0;
    background: var(--bg-surface);
  }

  .drawer-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 6px 12px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-subtle);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .drawer-left {
    display: flex;
    align-items: center;
    gap: 7px;
    color: var(--text-secondary);
  }

  .drawer-title {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .drawer-controls {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .flow-select {
    height: 26px;
    max-width: 240px;
    font-size: var(--text-xs);
  }

  .flow-id-input {
    height: 26px;
    width: 110px;
    font-size: var(--text-xs);
  }

  .drawer-output {
    flex: 1;
    overflow-y: auto;
    padding: 12px 14px;
    margin: 0;
    font-size: var(--text-xs);
    line-height: 1.6;
    color: var(--text-secondary);
    background: var(--bg-input);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .drawer-output.is-error {
    color: var(--status-danger);
  }
</style>
