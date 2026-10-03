<script>
  import { onMount } from 'svelte'
  import { applyTheme } from './lib/theme.js'
  import Capture from './pages/Capture.svelte'
  import Flows from './pages/Flows.svelte'
  import Terminal from './pages/Terminal.svelte'
  import Plugins from './pages/Plugins.svelte'
  import Rules from './pages/Rules.svelte'
  import DeepTrace from './pages/DeepTrace.svelte'
  import Settings from './pages/Settings.svelte'

  let currentPage = 'capture'

  const pages = [
    { id: 'capture', label: 'Capture', icon: '⚡' },
    { id: 'flows', label: 'Flows', icon: '📡' },
    { id: 'terminal', label: 'Terminal', icon: '⌨' },
    { id: 'rules', label: 'Rules', icon: '🎯' },
    { id: 'plugins', label: 'Plugins', icon: '🔌' },
    { id: 'trace', label: 'Trace', icon: '🔬' },
    { id: 'settings', label: 'Settings', icon: '⚙' },
  ]

  onMount(async () => {
    try {
      const theme = await window.go.wailsgui.App.GetSetting('theme')
      applyTheme(theme || 'dark')
    } catch(e) {
      applyTheme('dark')
    }
  })
</script>

<div class="app">
  <nav class="sidebar">
    <div class="logo">cap</div>
    {#each pages as page}
      <button
        class="nav-btn"
        class:active={currentPage === page.id}
        on:click={() => currentPage = page.id}
      >
        <span class="nav-icon">{page.icon}</span>
        <span class="nav-label">{page.label}</span>
      </button>
    {/each}
    <div class="sidebar-spacer"></div>
    <div class="version">v0.2.0</div>
  </nav>

  <main class="content">
    {#if currentPage === 'capture'}
      <Capture />
    {:else if currentPage === 'flows'}
      <Flows />
    {:else if currentPage === 'terminal'}
      <Terminal />
    {:else if currentPage === 'rules'}
      <Rules />
    {:else if currentPage === 'plugins'}
      <Plugins />
    {:else if currentPage === 'trace'}
      <DeepTrace />
    {:else if currentPage === 'settings'}
      <Settings />
    {/if}
  </main>
</div>

<style>
  :global(*) { margin: 0; padding: 0; box-sizing: border-box; }
  :global(body) {
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', 'JetBrains Mono', monospace;
    background: var(--bg, #0a0a0f);
    color: var(--fg, #e4e4e7);
    overflow: hidden; height: 100vh;
  }
  :global(::selection) { background: var(--selection, rgba(56, 189, 248, 0.3)); }
  :global(::-webkit-scrollbar) { width: 6px; height: 6px; }
  :global(::-webkit-scrollbar-track) { background: transparent; }
  :global(::-webkit-scrollbar-thumb) { background: var(--scrollbar, #333); border-radius: 3px; }

  .app { display: flex; height: 100vh; }

  .sidebar {
    width: 64px; background: var(--sidebar-bg, #111116);
    border-right: 1px solid var(--border, #1e1e24);
    display: flex; flex-direction: column; align-items: center;
    padding: 12px 0; gap: 4px;
  }
  .logo {
    font-size: 14px; font-weight: 800; color: var(--accent, #38bdf8);
    margin-bottom: 16px; letter-spacing: -0.5px;
  }
  .nav-btn {
    width: 48px; height: 48px; border: none; background: transparent;
    border-radius: 10px; cursor: pointer; display: flex; flex-direction: column;
    align-items: center; justify-content: center; gap: 2px;
    transition: all 0.15s ease; color: var(--fg-dim, #71717a);
  }
  .nav-btn:hover { background: var(--bg-hover, #1a1a22); color: var(--fg-muted, #a1a1aa); }
  .nav-btn.active { background: var(--bg-selected, #1e1e28); color: var(--accent, #38bdf8); }
  .nav-icon { font-size: 18px; line-height: 1; }
  .nav-label { font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px; }
  .sidebar-spacer { flex: 1; }
  .version { font-size: 9px; color: var(--fg-ghost, #3f3f46); margin-bottom: 8px; }
  .content { flex: 1; overflow: hidden; display: flex; flex-direction: column; }
</style>
