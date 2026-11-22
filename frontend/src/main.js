import './lib/tokens.css'
import './lib/locales/common.js'
import { applyTheme } from './lib/theme.js'
import App from './App.svelte'

// Apply default Obsidian theme synchronously before first paint to prevent FOUC
applyTheme('dark')

const app = new App({
  target: document.getElementById('app'),
})

export default app
