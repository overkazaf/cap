<script>
  import { onMount } from 'svelte'

  let settings = {}
  let saved = false
  let themes = ['dark', 'light', 'mocha', 'nord']

  async function loadSettings() {
    try { settings = await window.go.wailsgui.App.GetSettings() || {} } catch(e) { console.error(e) }
  }

  async function setSetting(key, value) {
    settings[key] = value
    settings = settings
    try {
      await window.go.wailsgui.App.SetSetting(key, value)
      saved = true
      setTimeout(() => saved = false, 1500)
    } catch(e) { console.error(e) }
  }

  onMount(loadSettings)
</script>

<div class="page">
  <div class="settings-container">
    <h1>Settings</h1>
    {#if saved}
      <div class="saved-badge">Saved</div>
    {/if}

    <div class="section">
      <h2>APPEARANCE</h2>
      <div class="setting-row">
        <span class="setting-label">Theme</span>
        <div class="theme-options">
          {#each themes as t}
            <button
              class="theme-btn"
              class:theme-active={settings.theme === t}
              on:click={() => setSetting('theme', t)}
            >
              <span class="theme-preview {t}"></span>
              <span>{t}</span>
            </button>
          {/each}
        </div>
      </div>
      <div class="setting-row">
        <span class="setting-label">Font Size</span>
        <input type="range" min="11" max="18" bind:value={settings.font_size}
          on:change={() => setSetting('font_size', settings.font_size)} class="range" />
        <span class="setting-value">{settings.font_size}px</span>
      </div>
    </div>

    <div class="section">
      <h2>PROXY</h2>
      <div class="setting-row">
        <span class="setting-label">Default Address</span>
        <input type="text" bind:value={settings.proxy_addr} class="setting-input"
          on:change={() => setSetting('proxy_addr', settings.proxy_addr)} />
      </div>
      <div class="setting-row">
        <span class="setting-label">Default Port</span>
        <input type="text" bind:value={settings.proxy_port} class="setting-input small"
          on:change={() => setSetting('proxy_port', settings.proxy_port)} />
      </div>
    </div>

    <div class="section">
      <h2>ANDROID</h2>
      <div class="setting-row">
        <span class="setting-label">Auto-detect devices</span>
        <label class="toggle">
          <input type="checkbox" checked={settings.auto_detect === 'true'}
            on:change={(e) => setSetting('auto_detect', e.target.checked ? 'true' : 'false')} />
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="setting-row">
        <span class="setting-label">Auto-install CA cert</span>
        <label class="toggle">
          <input type="checkbox" checked={settings.install_cert === 'true'}
            on:change={(e) => setSetting('install_cert', e.target.checked ? 'true' : 'false')} />
          <span class="toggle-slider"></span>
        </label>
      </div>
    </div>

    <div class="section">
      <h2>EXPORT</h2>
      <div class="setting-row">
        <span class="setting-label">Max Body Size (Agent)</span>
        <input type="text" bind:value={settings.max_body_size} class="setting-input small"
          on:change={() => setSetting('max_body_size', settings.max_body_size)} />
        <span class="setting-hint">bytes for JSONL truncation</span>
      </div>
    </div>

    <div class="section">
      <h2>ABOUT</h2>
      <div class="about-info">
        <div>cap v0.1.0</div>
        <div class="about-sub">MITM proxy for reverse engineering</div>
        <div class="about-sub">github.com/overkazaf/cap</div>
      </div>
    </div>
  </div>
</div>

<style>
  .page { height: 100%; overflow-y: auto; padding: 24px; }
  .settings-container { max-width: 600px; margin: 0 auto; }
  h1 { font-size: 18px; color: #e4e4e7; margin-bottom: 24px; font-weight: 600; }

  .saved-badge {
    position: fixed; top: 12px; right: 80px;
    padding: 4px 12px; font-size: 11px; background: #064e3b;
    color: #34d399; border-radius: 4px; border: 1px solid #059669;
  }

  .section { margin-bottom: 28px; }
  .section h2 {
    font-size: 11px; color: #38bdf8; letter-spacing: 1.5px;
    margin-bottom: 14px; padding-bottom: 6px; border-bottom: 1px solid #1e1e24;
  }

  .setting-row {
    display: flex; align-items: center; gap: 12px;
    padding: 8px 0; min-height: 36px;
  }
  .setting-label { font-size: 13px; color: #a1a1aa; min-width: 160px; }
  .setting-input {
    background: #111116; border: 1px solid #27272a; border-radius: 6px;
    padding: 6px 10px; color: #e4e4e7; font-size: 12px; font-family: inherit;
    outline: none; flex: 1;
  }
  .setting-input:focus { border-color: #38bdf8; }
  .setting-input.small { max-width: 100px; flex: none; }
  .setting-value { font-size: 12px; color: #71717a; min-width: 40px; }
  .setting-hint { font-size: 11px; color: #52525b; }

  .range {
    flex: 1; accent-color: #38bdf8; max-width: 200px;
  }

  .theme-options { display: flex; gap: 8px; }
  .theme-btn {
    display: flex; flex-direction: column; align-items: center; gap: 4px;
    padding: 8px 12px; border: 1px solid #27272a; border-radius: 8px;
    background: transparent; cursor: pointer; font-family: inherit;
    font-size: 11px; color: #71717a; transition: all 0.15s;
  }
  .theme-btn:hover { border-color: #52525b; color: #a1a1aa; }
  .theme-active { border-color: #38bdf8; color: #38bdf8; background: #0d1b2a; }
  .theme-preview {
    width: 32px; height: 20px; border-radius: 4px; border: 1px solid #27272a;
  }
  .theme-preview.dark { background: #0a0a0f; }
  .theme-preview.light { background: #fafafa; }
  .theme-preview.mocha { background: #1e1e2e; }
  .theme-preview.nord { background: #2e3440; }

  .toggle { position: relative; display: inline-block; width: 36px; height: 20px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle-slider {
    position: absolute; cursor: pointer; inset: 0;
    background: #27272a; border-radius: 10px; transition: 0.2s;
  }
  .toggle-slider::before {
    content: ''; position: absolute; width: 16px; height: 16px;
    left: 2px; bottom: 2px; background: #71717a;
    border-radius: 50%; transition: 0.2s;
  }
  .toggle input:checked + .toggle-slider { background: #064e3b; }
  .toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: #34d399; }

  .about-info { font-size: 13px; color: #71717a; }
  .about-sub { font-size: 12px; color: #52525b; margin-top: 4px; }
</style>
