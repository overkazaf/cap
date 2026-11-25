<script>
  import { onMount, onDestroy } from 'svelte'
  import '../lib/locales/ai.js'
  import { t, translate } from '../lib/i18n.js'
  import { toast } from '../lib/toast.js'
  import {
    aiConfig,
    activeAIProfile,
    refreshAIConfig,
    setAIConfigSnapshot,
    AI_PROVIDER_PROTOCOLS,
    AI_MAX_RETRIES_OPTIONS,
  } from '../lib/aiState.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'

  const api = () => window?.go?.wailsgui?.App

  let destroyed = false
  let presets = []
  let loadingPresets = false

  // Profile editor state
  let editorOpen = false
  let isEditingExisting = false
  let selectedPresetId = ''
  let showApiKey = false
  let savingProfile = false
  let testingConn = false
  let testResult = null
  let confirmDeleteId = ''
  let deletingId = ''
  let activatingId = ''
  let updatingGuardrails = false

  let headerSeq = 0
  let headerRows = []

  let form = createBlankForm()

  function createBlankForm() {
    return {
      id: '',
      name: '',
      provider: 'openai_compat',
      base_url: 'https://api.openai.com/v1',
      api_key: '',
      clear_api_key: false,
      has_api_key: false,
      api_key_preview: '',
      model: 'gpt-4.1',
      max_tokens: 4096,
      temperature: 0.1,
      timeout_sec: 90,
      enabled: true,
    }
  }

  function mapToHeaderRows(extraHeaders) {
    if (!extraHeaders || typeof extraHeaders !== 'object') return []
    return Object.entries(extraHeaders).map(([key, value]) => ({
      uid: ++headerSeq,
      key: String(key),
      value: String(value ?? ''),
    }))
  }

  function headerRowsToMap(rows) {
    const out = {}
    for (const row of rows) {
      const k = String(row.key || '').trim()
      if (!k) continue
      out[k] = String(row.value ?? '')
    }
    return out
  }

  function findPresetForForm(provider, baseUrl, presetId) {
    if (presetId) {
      const exact = presets.find((p) => p.id === presetId)
      if (exact) return exact
    }
    const normBase = String(baseUrl || '').trim().replace(/\/+$/, '').toLowerCase()
    if (normBase) {
      const byUrl = presets.find((p) => String(p.base_url || '').replace(/\/+$/, '').toLowerCase() === normBase)
      if (byUrl) return byUrl
    }
    return presets.find((p) => p.provider === provider) || null
  }

  $: activePreset = findPresetForForm(form.provider, form.base_url, selectedPresetId)
  $: suggestedModels = Array.isArray(activePreset?.suggested_models) ? activePreset.suggested_models : []
  $: hasRedactedHeader = headerRows.some((r) => String(r.value || '').includes('[REDACTED]'))

  function loadProfileIntoEditor(profile) {
    if (!profile) return
    isEditingExisting = true
    editorOpen = true
    selectedPresetId = ''
    showApiKey = false
    testResult = null
    form = {
      id: profile.id || '',
      name: profile.name || '',
      provider: profile.provider || 'openai_compat',
      base_url: profile.base_url || '',
      api_key: '',
      clear_api_key: false,
      has_api_key: Boolean(profile.has_api_key),
      api_key_preview: profile.api_key_preview || '',
      model: profile.model || '',
      max_tokens: Number(profile.max_tokens) || 4096,
      temperature: Number.isFinite(Number(profile.temperature)) ? Number(profile.temperature) : 0.1,
      timeout_sec: Number(profile.timeout_sec) || 90,
      enabled: typeof profile.enabled === 'boolean' ? profile.enabled : true,
    }
    headerRows = mapToHeaderRows(profile.extra_headers)
  }

  function openNewCustomProfile() {
    isEditingExisting = false
    editorOpen = true
    selectedPresetId = ''
    showApiKey = false
    testResult = null
    form = createBlankForm()
    headerRows = []
  }

  function applyPreset(preset) {
    if (!preset) return
    isEditingExisting = false
    editorOpen = true
    selectedPresetId = preset.id || ''
    showApiKey = false
    testResult = null
    form = {
      id: '',
      name: preset.name || '',
      provider: preset.provider || 'openai_compat',
      base_url: preset.base_url || '',
      api_key: '',
      clear_api_key: false,
      has_api_key: false,
      api_key_preview: '',
      model: preset.default_model || '',
      max_tokens: 4096,
      temperature: 0.1,
      timeout_sec: 90,
      enabled: true,
    }
    headerRows = []
    toast.info(translate('ai.settings.toast.presetLoaded', { name: preset.name }))
  }

  function handleProviderChange(newProvider) {
    form.provider = newProvider
    if (!isEditingExisting) {
      const matched = presets.find((p) => p.provider === newProvider)
      if (matched) {
        selectedPresetId = matched.id
        if (!form.base_url || presets.some((p) => p.base_url === form.base_url)) {
          form.base_url = matched.base_url
        }
        if (!form.model || presets.some((p) => p.default_model === form.model)) {
          form.model = matched.default_model
        }
      }
    }
  }

  function addHeaderRow() {
    headerRows = [...headerRows, { uid: ++headerSeq, key: '', value: '' }]
  }

  function removeHeaderRow(uid) {
    headerRows = headerRows.filter((r) => r.uid !== uid)
  }

  function buildProviderPayload() {
    const parsedMaxTokens = parseInt(String(form.max_tokens), 10)
    const parsedTemp = parseFloat(String(form.temperature))
    const parsedTimeout = parseInt(String(form.timeout_sec), 10)

    return {
      id: String(form.id || '').trim(),
      name: String(form.name || '').trim(),
      provider: String(form.provider || 'openai_compat').trim(),
      base_url: String(form.base_url || '').trim(),
      api_key: form.clear_api_key ? '' : String(form.api_key || '').trim(),
      clear_api_key: Boolean(form.clear_api_key),
      model: String(form.model || '').trim(),
      max_tokens: Number.isFinite(parsedMaxTokens) && parsedMaxTokens > 0 ? parsedMaxTokens : 4096,
      temperature: Number.isFinite(parsedTemp) ? Math.min(2, Math.max(0, parsedTemp)) : 0.1,
      timeout_sec: Number.isFinite(parsedTimeout) && parsedTimeout > 0 ? parsedTimeout : 90,
      extra_headers: headerRowsToMap(headerRows),
      enabled: Boolean(form.enabled),
    }
  }

  function validateForm(payload) {
    if (!payload.base_url || !/^https?:\/\//i.test(payload.base_url)) {
      toast.error(translate('ai.settings.validation.baseUrlRequired'))
      return false
    }
    if (!payload.model) {
      toast.error(translate('ai.settings.validation.modelRequired'))
      return false
    }
    return true
  }

  async function saveProfile() {
    const app = api()
    if (!app?.UpsertAIProfile) {
      toast.error(translate('ai.settings.toast.backendUnavailable'))
      return
    }
    const payload = buildProviderPayload()
    if (!validateForm(payload)) return

    savingProfile = true
    try {
      const saved = await app.UpsertAIProfile(payload)
      if (destroyed) return
      const cfg = await refreshAIConfig()
      if (destroyed) return
      const refreshed = cfg.profiles.find((p) => p.id === saved?.id) || saved
      if (refreshed) {
        loadProfileIntoEditor(refreshed)
      }
      toast.success(translate('ai.settings.toast.profileSaved', { name: refreshed?.name || payload.model }))
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.settings.toast.profileSaveFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) savingProfile = false
    }
  }

  async function testConnection() {
    const app = api()
    if (!app?.TestAIConnection) {
      toast.error(translate('ai.settings.toast.backendUnavailable'))
      return
    }
    const payload = buildProviderPayload()
    if (!validateForm(payload)) return

    testingConn = true
    testResult = null
    try {
      const res = await app.TestAIConnection(payload)
      if (destroyed) return
      testResult = res || { ok: false, error: 'Empty response from backend', latency_ms: 0 }
      if (testResult.ok) {
        toast.success(translate('ai.settings.toast.testPassed', { ms: testResult.latency_ms ?? 0 }))
      } else {
        toast.error(translate('ai.settings.toast.testFailed', { error: testResult.error || 'Unknown error' }))
      }
    } catch (e) {
      if (!destroyed) {
        const errMsg = e?.message || String(e)
        testResult = { ok: false, provider: payload.provider, model: payload.model, error: errMsg, latency_ms: 0 }
        toast.error(translate('ai.settings.toast.testFailed', { error: errMsg }))
      }
    } finally {
      if (!destroyed) testingConn = false
    }
  }

  async function activateProfile(profile) {
    const app = api()
    if (!app?.SetActiveAIProfile || !profile?.id) return
    activatingId = profile.id
    try {
      await app.SetActiveAIProfile(profile.id)
      if (destroyed) return
      await refreshAIConfig()
      if (!destroyed) {
        toast.success(translate('ai.settings.toast.profileActivated', { name: profile.name || profile.model }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.settings.toast.profileActivateFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) activatingId = ''
    }
  }

  async function deleteProfile(profile) {
    const app = api()
    if (!app?.DeleteAIProfile || !profile?.id) return
    deletingId = profile.id
    try {
      await app.DeleteAIProfile(profile.id)
      if (destroyed) return
      confirmDeleteId = ''
      if (editorOpen && form.id === profile.id) {
        editorOpen = false
        isEditingExisting = false
        form = createBlankForm()
        headerRows = []
        testResult = null
      }
      await refreshAIConfig()
      if (!destroyed) {
        toast.success(translate('ai.settings.toast.profileDeleted', { name: profile.name || profile.model }))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.settings.toast.profileDeleteFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) deletingId = ''
    }
  }

  async function updateGuardrails(patch) {
    const app = api()
    if (!app?.UpdateAISettings) {
      toast.error(translate('ai.settings.toast.backendUnavailable'))
      return
    }
    updatingGuardrails = true
    try {
      const updated = await app.UpdateAISettings(patch)
      if (destroyed) return
      if (updated && typeof updated === 'object') {
        setAIConfigSnapshot(updated)
      } else {
        await refreshAIConfig()
      }
      if (!destroyed) {
        toast.success(translate('ai.settings.toast.settingsUpdated'))
      }
    } catch (e) {
      if (!destroyed) {
        toast.error(translate('ai.settings.toast.settingsUpdateFailed', { error: e?.message || e }))
      }
    } finally {
      if (!destroyed) updatingGuardrails = false
    }
  }

  async function loadInitialData() {
    const app = api()
    loadingPresets = true
    try {
      const [cfg, presetList] = await Promise.all([
        refreshAIConfig(),
        app?.ListAIProviderPresets?.().catch(() => []) ?? [],
      ])
      if (destroyed) return
      presets = Array.isArray(presetList) ? presetList : []
      // If user has an active profile and editor isn't open yet, keep list clean;
      // if no profiles exist yet, leave quick presets front-and-center.
      if (cfg && cfg.profiles.length > 0 && editorOpen && form.id) {
        const latest = cfg.profiles.find((p) => p.id === form.id)
        if (latest) loadProfileIntoEditor(latest)
      }
    } finally {
      if (!destroyed) loadingPresets = false
    }
  }

  function providerLabel(providerId) {
    const key = `ai.providers.${providerId}`
    const val = translate(key)
    return val === key ? providerId : val
  }

  onMount(loadInitialData)
  onDestroy(() => {
    destroyed = true
  })
</script>

<div class="ai-settings-panel">
  <header class="panel-head">
    <div class="head-row">
      <div>
        <h2>{$t('ai.settings.title')}</h2>
        <p>{$t('ai.settings.subtitle')}</p>
      </div>
      {#if $activeAIProfile && $activeAIProfile.enabled}
        <Badge variant="accent" size="sm" dot pulse>
          {$t('ai.settings.activeBadge', { model: $activeAIProfile.model })}
        </Badge>
      {:else}
        <Badge variant="neutral" size="sm">
          {$t('ai.settings.notConfiguredBadge')}
        </Badge>
      {/if}
    </div>
  </header>

  <!-- Quick Provider Presets Strip -->
  <div class="pref-card cap-card">
    <div class="pref-card-head">
      <div>
        <div class="pref-title">
          <Icon name="zap" size={14} />
          <span>{$t('ai.settings.presets.title')}</span>
        </div>
        <div class="pref-desc">{$t('ai.settings.presets.desc')}</div>
      </div>
      <Badge variant="accent" size="xs" mono>{presets.length}</Badge>
    </div>

    {#if presets.length > 0}
      <div class="preset-grid">
        {#each presets as preset (preset.id)}
          <button
            type="button"
            class="preset-btn"
            class:selected={editorOpen && !isEditingExisting && selectedPresetId === preset.id}
            title={preset.description}
            on:click={() => applyPreset(preset)}
          >
            <div class="preset-top">
              <span class="preset-name">{$t('ai.settings.presets.addPrefix', { name: preset.name })}</span>
              {#if !preset.requires_api_key}
                <Badge variant="success" size="xs">{$t('ai.settings.presets.noKeyRequired')}</Badge>
              {/if}
            </div>
            <div class="preset-meta mono truncate">{preset.default_model}</div>
          </button>
        {/each}
      </div>
    {:else if !loadingPresets}
      <div class="muted-note">{$t('ai.settings.presets.empty')}</div>
    {/if}
  </div>

  <!-- Configured Profiles List -->
  <div class="pref-card cap-card">
    <div class="pref-card-head">
      <div>
        <div class="pref-title">
          <Icon name="sparkles" size={14} />
          <span>{$t('ai.settings.profiles.title')}</span>
        </div>
        <div class="pref-desc">{$t('ai.settings.profiles.desc')}</div>
      </div>
      <div class="head-actions">
        <Badge variant="neutral" size="xs" mono>
          {$t('ai.settings.profiles.count', { count: $aiConfig.profiles.length })}
        </Badge>
        <Button variant="secondary" size="xs" icon="plus" on:click={openNewCustomProfile}>
          {$t('ai.settings.profiles.addCustom')}
        </Button>
      </div>
    </div>

    {#if $aiConfig.profiles.length === 0}
      <div class="empty-profiles">
        <div class="empty-icon">
          <Icon name="sparkles" size={18} />
        </div>
        <div class="empty-copy">
          <div class="empty-title">{$t('ai.settings.profiles.emptyTitle')}</div>
          <div class="empty-desc">{$t('ai.settings.profiles.emptyDesc')}</div>
        </div>
      </div>
    {:else}
      <div class="profile-list">
        {#each $aiConfig.profiles as prof (prof.id)}
          {@const isActive = $aiConfig.active_profile_id === prof.id}
          {@const isEditing = editorOpen && isEditingExisting && form.id === prof.id}
          <div class="profile-item" class:active={isActive} class:editing={isEditing}>
            <div class="profile-main">
              <div class="profile-title-row">
                <span class="profile-name">{prof.name || prof.model}</span>
                {#if isActive}
                  <Badge variant="accent" size="xs" dot>{$t('ai.settings.profiles.active')}</Badge>
                {/if}
                {#if !prof.enabled}
                  <Badge variant="warning" size="xs">{$t('ai.settings.profiles.disabled')}</Badge>
                {/if}
                <Badge variant="neutral" size="xs" mono>{providerLabel(prof.provider)}</Badge>
              </div>
              <div class="profile-sub-row mono">
                <span class="profile-model">{prof.model}</span>
                <span class="sep">·</span>
                <span class="profile-url truncate">{prof.base_url}</span>
              </div>
              <div class="profile-key-row">
                {#if prof.has_api_key}
                  <span class="key-pill saved mono">
                    <Icon name="key" size={11} />
                    <span>{$t('ai.settings.profiles.keySaved', { preview: prof.api_key_preview || '••••' })}</span>
                  </span>
                {:else}
                  <span class="key-pill none">
                    <Icon name="key" size={11} />
                    <span>{$t('ai.settings.profiles.noKey')}</span>
                  </span>
                {/if}
                <span class="meta-pill mono tabular-nums">{prof.max_tokens} tok</span>
                <span class="meta-pill mono tabular-nums">T={prof.temperature}</span>
                <span class="meta-pill mono tabular-nums">{prof.timeout_sec}s</span>
              </div>
            </div>

            <div class="profile-actions">
              {#if !isActive}
                <Button
                  variant="secondary"
                  size="xs"
                  icon="check"
                  disabled={!prof.enabled}
                  loading={activatingId === prof.id}
                  on:click={() => activateProfile(prof)}
                >
                  {$t('ai.settings.profiles.setActive')}
                </Button>
              {/if}
              <Button
                variant={isEditing ? 'primary' : 'subtle'}
                size="xs"
                icon="edit"
                on:click={() => loadProfileIntoEditor(prof)}
              >
                {$t('ai.settings.profiles.edit')}
              </Button>
              {#if confirmDeleteId === prof.id}
                <Button
                  variant="danger"
                  size="xs"
                  icon="trash"
                  loading={deletingId === prof.id}
                  on:click={() => deleteProfile(prof)}
                >
                  {$t('ai.settings.profiles.confirmDelete')}
                </Button>
                <Button variant="ghost" size="xs" on:click={() => (confirmDeleteId = '')}>
                  {$t('ai.settings.profiles.cancelDelete')}
                </Button>
              {:else}
                <Button
                  variant="ghost"
                  size="xs"
                  icon="trash"
                  title={$t('ai.settings.profiles.delete')}
                  on:click={() => (confirmDeleteId = prof.id)}
                />
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Profile Editor Card -->
  {#if editorOpen}
    <div class="pref-card cap-card editor-card">
      <div class="pref-card-head">
        <div class="pref-title">
          <Icon name="edit" size={14} />
          <span>
            {isEditingExisting
              ? $t('ai.settings.editor.editTitle', { name: form.name || form.model || form.id })
              : $t('ai.settings.editor.newTitle')}
          </span>
        </div>
        <Button variant="ghost" size="xs" icon="x" on:click={() => (editorOpen = false)}>
          {$t('ai.settings.editor.close')}
        </Button>
      </div>

      <div class="form-grid-2">
        <div class="field">
          <label class="field-label" for="ai-prof-name">{$t('ai.settings.editor.nameLabel')}</label>
          <input
            id="ai-prof-name"
            type="text"
            class="cap-input"
            bind:value={form.name}
            placeholder={$t('ai.settings.editor.namePlaceholder')}
          />
        </div>

        <div class="field">
          <label class="field-label" for="ai-prof-provider">{$t('ai.settings.editor.providerLabel')}</label>
          <select
            id="ai-prof-provider"
            class="cap-input"
            value={form.provider}
            on:change={(e) => handleProviderChange(e.currentTarget.value)}
          >
            {#each AI_PROVIDER_PROTOCOLS as proto (proto.id)}
              <option value={proto.id}>{$t(`ai.providers.${proto.id}`)}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="field">
        <label class="field-label" for="ai-prof-baseurl">{$t('ai.settings.editor.baseUrlLabel')}</label>
        <input
          id="ai-prof-baseurl"
          type="text"
          class="cap-input mono"
          bind:value={form.base_url}
          placeholder={$t('ai.settings.editor.baseUrlPlaceholder')}
        />
      </div>

      <div class="field">
        <label class="field-label" for="ai-prof-model">{$t('ai.settings.editor.modelLabel')}</label>
        <input
          id="ai-prof-model"
          type="text"
          class="cap-input mono"
          bind:value={form.model}
          placeholder={$t('ai.settings.editor.modelPlaceholder')}
        />
        {#if suggestedModels.length > 0}
          <div class="model-chips">
            <span class="chips-label">{$t('ai.settings.editor.suggestedModels')}</span>
            {#each suggestedModels as m (m)}
              <button
                type="button"
                class="size-chip mono"
                class:active={form.model === m}
                on:click={() => (form.model = m)}
              >
                {m}
              </button>
            {/each}
          </div>
        {/if}
      </div>

      <!-- API Key Field with Masked Badge & Explicit Clear Checkbox -->
      <div class="field">
        <div class="label-row">
          <label class="field-label" for="ai-prof-apikey">{$t('ai.settings.editor.apiKeyLabel')}</label>
          {#if form.has_api_key && !form.clear_api_key}
            <Badge variant="success" size="xs" mono>
              <Icon name="key" size={10} />
              <span>{$t('ai.settings.editor.savedKeyBadge', { preview: form.api_key_preview || '••••' })}</span>
            </Badge>
          {/if}
        </div>
        <div class="key-input-row">
          {#if showApiKey}
            <input
              id="ai-prof-apikey"
              type="text"
              class="cap-input mono key-input"
              bind:value={form.api_key}
              disabled={form.clear_api_key}
              placeholder={form.has_api_key
                ? $t('ai.settings.editor.apiKeyPlaceholderSaved')
                : $t('ai.settings.editor.apiKeyPlaceholderNew')}
              autocomplete="off"
            />
          {:else}
            <input
              id="ai-prof-apikey"
              type="password"
              class="cap-input mono key-input"
              bind:value={form.api_key}
              disabled={form.clear_api_key}
              placeholder={form.has_api_key
                ? $t('ai.settings.editor.apiKeyPlaceholderSaved')
                : $t('ai.settings.editor.apiKeyPlaceholderNew')}
              autocomplete="new-password"
            />
          {/if}
          <Button
            variant="secondary"
            size="sm"
            iconOnly
            icon={showApiKey ? 'eye-off' : 'eye'}
            disabled={form.clear_api_key}
            title={showApiKey ? $t('ai.settings.editor.hideKey') : $t('ai.settings.editor.showKey')}
            on:click={() => (showApiKey = !showApiKey)}
          />
        </div>
        {#if form.has_api_key}
          <label class="clear-key-check">
            <input type="checkbox" bind:checked={form.clear_api_key} />
            <span>{$t('ai.settings.editor.clearSavedKey')}</span>
          </label>
          {#if form.clear_api_key}
            <div class="field-warn">{$t('ai.settings.editor.clearSavedKeyHint')}</div>
          {/if}
        {/if}
      </div>

      <!-- Tuning Parameters -->
      <div class="form-grid-3">
        <div class="field">
          <label class="field-label" for="ai-prof-maxtokens">{$t('ai.settings.editor.maxTokensLabel')}</label>
          <input
            id="ai-prof-maxtokens"
            type="number"
            min="256"
            max="131072"
            step="256"
            class="cap-input mono tabular-nums"
            bind:value={form.max_tokens}
          />
        </div>

        <div class="field">
          <label class="field-label" for="ai-prof-temp">{$t('ai.settings.editor.temperatureLabel')}</label>
          <input
            id="ai-prof-temp"
            type="number"
            min="0"
            max="2"
            step="0.05"
            class="cap-input mono tabular-nums"
            bind:value={form.temperature}
          />
        </div>

        <div class="field">
          <label class="field-label" for="ai-prof-timeout">{$t('ai.settings.editor.timeoutLabel')}</label>
          <input
            id="ai-prof-timeout"
            type="number"
            min="5"
            max="600"
            step="5"
            class="cap-input mono tabular-nums"
            bind:value={form.timeout_sec}
          />
        </div>
      </div>

      <!-- Enabled Toggle -->
      <div class="pref-row">
        <div class="pref-info">
          <div class="pref-title-sm">{$t('ai.settings.editor.enabledLabel')}</div>
          <div class="pref-desc">{$t('ai.settings.editor.enabledDesc')}</div>
        </div>
        <label class="switch">
          <input type="checkbox" bind:checked={form.enabled} />
          <span class="switch-track"></span>
        </label>
      </div>

      <div class="pref-divider"></div>

      <!-- Extra Headers KV Editor -->
      <div class="headers-section">
        <div class="pref-card-head">
          <div>
            <div class="pref-title-sm">{$t('ai.settings.editor.headersTitle')}</div>
            <div class="pref-desc">{$t('ai.settings.editor.headersDesc')}</div>
          </div>
          <Button variant="secondary" size="xs" icon="plus" on:click={addHeaderRow}>
            {$t('ai.settings.editor.addHeader')}
          </Button>
        </div>

        {#if headerRows.length > 0}
          <div class="header-rows">
            {#each headerRows as row (row.uid)}
              <div class="header-kv-row">
                <input
                  type="text"
                  class="cap-input mono kv-key"
                  bind:value={row.key}
                  placeholder={$t('ai.settings.editor.headerKeyPlaceholder')}
                />
                <input
                  type="text"
                  class="cap-input mono kv-val"
                  bind:value={row.value}
                  placeholder={$t('ai.settings.editor.headerValPlaceholder')}
                />
                <Button
                  variant="ghost"
                  size="xs"
                  iconOnly
                  icon="x"
                  title={$t('ai.settings.editor.removeHeader')}
                  on:click={() => removeHeaderRow(row.uid)}
                />
              </div>
            {/each}
          </div>
        {/if}
        {#if hasRedactedHeader}
          <div class="field-hint">
            <Icon name="lock" size={11} />
            <span>{$t('ai.settings.editor.headerRedactedHint')}</span>
          </div>
        {/if}
      </div>

      <!-- Live Connection Test Banner -->
      {#if testResult}
        <div class="test-banner" class:ok={testResult.ok} class:fail={!testResult.ok}>
          <div class="test-banner-head">
            <span class="test-banner-title">
              <Icon name={testResult.ok ? 'check-circle' : 'alert-circle'} size={14} />
              <span>{testResult.ok ? $t('ai.settings.editor.testOkTitle') : $t('ai.settings.editor.testFailTitle')}</span>
            </span>
            <div class="test-banner-badges">
              {#if testResult.model}
                <Badge variant="neutral" size="xs" mono>{testResult.model}</Badge>
              {/if}
              <Badge variant={testResult.ok ? 'success' : 'danger'} size="xs" mono>
                {$t('ai.settings.editor.testLatency', { ms: testResult.latency_ms ?? 0 })}
              </Badge>
            </div>
          </div>
          {#if testResult.ok && testResult.reply}
            <div class="test-banner-body mono">
              {$t('ai.settings.editor.testReply', { reply: testResult.reply })}
            </div>
          {:else if !testResult.ok && testResult.error}
            <div class="test-banner-body mono">{testResult.error}</div>
          {/if}
        </div>
      {/if}

      <div class="editor-footer">
        <Button
          variant="primary"
          size="sm"
          icon="save"
          loading={savingProfile}
          on:click={saveProfile}
        >
          {$t('ai.settings.editor.saveBtn')}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          icon="activity"
          loading={testingConn}
          on:click={testConnection}
        >
          {testingConn ? $t('ai.settings.editor.testingBtn') : $t('ai.settings.editor.testBtn')}
        </Button>
      </div>
    </div>
  {/if}

  <!-- Self-Healing Guardrails & Privacy Card -->
  <div class="pref-card cap-card">
    <div class="pref-card-head">
      <div>
        <div class="pref-title">
          <Icon name="sliders" size={14} />
          <span>{$t('ai.settings.guardrails.title')}</span>
        </div>
        <div class="pref-desc">{$t('ai.settings.guardrails.desc')}</div>
      </div>
      <Badge variant={$aiConfig.redact_secrets ? 'success' : 'warning'} size="xs">
        <Icon name={$aiConfig.redact_secrets ? 'shield-check' : 'alert-triangle'} size={11} />
        <span>
          {$aiConfig.redact_secrets
            ? $t('ai.settings.guardrails.privacyBadgeOn')
            : $t('ai.settings.guardrails.privacyBadgeOff')}
        </span>
      </Badge>
    </div>

    <div class="pref-row">
      <div class="pref-info">
        <div class="pref-title-sm">{$t('ai.settings.guardrails.autoHealTitle')}</div>
        <div class="pref-desc">{$t('ai.settings.guardrails.autoHealDesc')}</div>
      </div>
      <label class="switch">
        <input
          type="checkbox"
          checked={$aiConfig.auto_heal_enabled}
          disabled={updatingGuardrails}
          on:change={(e) => updateGuardrails({ auto_heal_enabled: e.currentTarget.checked })}
        />
        <span class="switch-track"></span>
      </label>
    </div>

    <div class="pref-divider"></div>

    <div class="pref-row">
      <div class="pref-info">
        <div class="pref-title-sm">{$t('ai.settings.guardrails.maxRetriesTitle')}</div>
        <div class="pref-desc">{$t('ai.settings.guardrails.maxRetriesDesc')}</div>
      </div>
      <div class="retry-pills">
        {#each AI_MAX_RETRIES_OPTIONS as n (n)}
          <button
            type="button"
            class="size-chip mono tabular-nums"
            class:active={$aiConfig.max_auto_retries === n}
            disabled={updatingGuardrails}
            on:click={() => updateGuardrails({ max_auto_retries: n })}
          >
            {$t('ai.settings.guardrails.retryUnit', { n })}
          </button>
        {/each}
      </div>
    </div>

    <div class="pref-divider"></div>

    <div class="pref-row">
      <div class="pref-info">
        <div class="pref-title-sm">
          <Icon name="shield-check" size={13} />
          <span>{$t('ai.settings.guardrails.redactTitle')}</span>
        </div>
        <div class="pref-desc">{$t('ai.settings.guardrails.redactDesc')}</div>
      </div>
      <label class="switch">
        <input
          type="checkbox"
          checked={$aiConfig.redact_secrets}
          disabled={updatingGuardrails}
          on:change={(e) => updateGuardrails({ redact_secrets: e.currentTarget.checked })}
        />
        <span class="switch-track"></span>
      </label>
    </div>

    {#if !$aiConfig.redact_secrets}
      <div class="redact-warning">
        <Icon name="alert-triangle" size={13} />
        <span>{$t('ai.settings.guardrails.redactWarning')}</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .ai-settings-panel {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .head-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .panel-head h2 {
    font-size: var(--text-lg);
    font-weight: 600;
    color: var(--text-primary);
  }

  .panel-head p {
    font-size: var(--text-sm);
    color: var(--text-muted);
    margin-top: 3px;
  }

  .pref-card {
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .editor-card {
    border-color: var(--accent-border);
  }

  .pref-card-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .head-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  .pref-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .pref-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .pref-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-base);
    font-weight: 600;
    color: var(--text-primary);
  }

  .pref-title-sm {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .pref-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .pref-divider {
    height: 1px;
    background: var(--border-subtle);
  }

  /* Quick Provider Presets */
  .preset-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 8px;
  }

  .preset-btn {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 9px 11px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-primary);
    text-align: left;
    cursor: pointer;
    transition: all var(--transition-fast);
    min-width: 0;
  }

  .preset-btn:hover {
    border-color: var(--border-strong);
    background: var(--bg-hover);
  }

  .preset-btn.selected {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: var(--focus-ring);
  }

  .preset-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    flex-wrap: wrap;
  }

  .preset-name {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-primary);
  }

  .preset-meta {
    font-size: 11px;
    color: var(--text-muted);
  }

  .muted-note {
    font-size: var(--text-xs);
    color: var(--text-muted);
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: var(--bg-input);
    border: 1px dashed var(--border-default);
  }

  /* Profiles List */
  .empty-profiles {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px;
    border-radius: var(--radius-md);
    background: var(--bg-input);
    border: 1px dashed var(--border-default);
  }

  .empty-icon {
    width: 34px;
    height: 34px;
    border-radius: var(--radius-md);
    background: var(--accent-soft);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .empty-copy {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .empty-title {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .empty-desc {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.45;
  }

  .profile-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .profile-item {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 11px 13px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    transition: border-color var(--transition-fast), background var(--transition-fast);
  }

  .profile-item.active {
    border-color: var(--accent-border);
    background: color-mix(in srgb, var(--accent) 6%, var(--bg-input));
  }

  .profile-item.editing {
    box-shadow: var(--focus-ring);
  }

  .profile-main {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
    flex: 1;
  }

  .profile-title-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .profile-name {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
  }

  .profile-sub-row {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 11px;
    color: var(--text-secondary);
    min-width: 0;
  }

  .profile-model {
    color: var(--accent);
    flex-shrink: 0;
  }

  .sep {
    color: var(--text-faint);
  }

  .profile-url {
    color: var(--text-muted);
    min-width: 0;
  }

  .profile-key-row {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 2px;
  }

  .key-pill {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 6px;
    border-radius: var(--radius-xs);
    font-size: 10.5px;
  }

  .key-pill.saved {
    background: var(--status-success-bg);
    border: 1px solid var(--status-success-border);
    color: var(--status-success);
  }

  .key-pill.none {
    background: var(--bg-subtle);
    border: 1px solid var(--border-subtle);
    color: var(--text-muted);
  }

  .meta-pill {
    font-size: 10.5px;
    color: var(--text-muted);
    background: var(--bg-subtle);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs);
    padding: 1px 5px;
  }

  .profile-actions {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  /* Editor Form */
  .form-grid-2 {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .form-grid-3 {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    min-width: 0;
  }

  .label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .field-label {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--text-secondary);
  }

  .model-chips {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-wrap: wrap;
    margin-top: 2px;
  }

  .chips-label {
    font-size: 11px;
    color: var(--text-muted);
  }

  .key-input-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .key-input {
    flex: 1;
    min-width: 0;
  }

  .clear-key-check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
    margin-top: 2px;
  }

  .clear-key-check input {
    accent-color: var(--status-danger);
    cursor: pointer;
  }

  .field-warn {
    font-size: 11px;
    color: var(--status-warning);
  }

  .field-hint {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    color: var(--text-muted);
  }

  /* Extra Headers */
  .headers-section {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .header-rows {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .header-kv-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .kv-key {
    width: 38%;
    min-width: 0;
  }

  .kv-val {
    flex: 1;
    min-width: 0;
  }

  /* Test Result Banner */
  .test-banner {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 12px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-default);
  }

  .test-banner.ok {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
    color: var(--status-success);
  }

  .test-banner.fail {
    background: var(--status-danger-bg);
    border-color: var(--status-danger-border);
    color: var(--status-danger);
  }

  .test-banner-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }

  .test-banner-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: var(--text-xs);
    font-weight: 600;
  }

  .test-banner-badges {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .test-banner-body {
    font-size: 11px;
    color: var(--text-primary);
    background: var(--bg-input);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xs);
    padding: 6px 8px;
    word-break: break-word;
    white-space: pre-wrap;
  }

  .editor-footer {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 2px;
  }

  /* Guardrails & Chips */
  .retry-pills {
    display: flex;
    align-items: center;
    gap: 5px;
    flex-shrink: 0;
  }

  .size-chip {
    padding: 4px 9px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-default);
    background: var(--bg-input);
    color: var(--text-secondary);
    font-size: 11px;
    cursor: pointer;
    transition: all var(--transition-fast);
  }

  .size-chip:hover:not(:disabled) {
    border-color: var(--border-strong);
    color: var(--text-primary);
  }

  .size-chip.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
    font-weight: 600;
  }

  .size-chip:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .redact-warning {
    display: flex;
    align-items: flex-start;
    gap: 7px;
    padding: 9px 11px;
    border-radius: var(--radius-md);
    background: var(--status-warning-bg);
    border: 1px solid var(--status-warning-border);
    color: var(--status-warning);
    font-size: var(--text-xs);
    line-height: 1.45;
  }

  /* Toggle Switch (matching Settings.svelte) */
  .switch {
    position: relative;
    display: inline-block;
    width: 36px;
    height: 20px;
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
    width: 14px;
    height: 14px;
    border-radius: 50%;
    background: var(--text-muted);
    transition: transform var(--transition-fast), background var(--transition-fast);
  }

  .switch input:checked + .switch-track {
    background: var(--status-success-bg);
    border-color: var(--status-success-border);
  }

  .switch input:checked + .switch-track::after {
    transform: translateX(16px);
    background: var(--status-success);
  }

  .switch input:focus-visible + .switch-track {
    box-shadow: var(--focus-ring);
  }

  .switch input:disabled + .switch-track {
    opacity: 0.5;
    cursor: not-allowed;
  }

  @media (max-width: 640px) {
    .preset-grid,
    .form-grid-2,
    .form-grid-3 {
      grid-template-columns: 1fr;
    }
  }
</style>
