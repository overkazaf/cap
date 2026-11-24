<div align="center">

![Stars](https://img.shields.io/github/stars/overkazaf/cap?style=flat-square&color=58a6ff)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go&logoColor=white)
![Svelte](https://img.shields.io/badge/Svelte-4+-FF3E00?style=flat-square&logo=svelte&logoColor=white)
![Last Commit](https://img.shields.io/github/last-commit/overkazaf/cap?style=flat-square&color=58a6ff)

</div>

# cap

<p align="center">
  <strong>Commercial-grade HTTP(S) MITM proxy &amp; reverse-engineering workbench</strong><br>
  Native Desktop GUI · Full-Screen Interactive TUI · Android Companion Guard · EN / 简体中文 · LLM-Ready Output
</p>

<p align="center">
  <a href="README_CN.md">中文文档</a> ·
  <a href="https://overkazaf.github.io/cap/">Documentation &amp; Preview</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#install--build">Install &amp; Build</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#command-reference">CLI &amp; TUI Reference</a>
</p>

---

## Screenshots

<p align="center">
  <img src="docs/screenshots/flows-detail.png" alt="cap Unified Flows + Plugins Single-Page Debugger (Obsidian Dark)" width="100%">
  <br>
  <em>Unified Flows + Plugins Single-Page Debugger — inspect live traffic on the left while writing, matching, and running Python 3 / Node / Shell scripts with live parsed <code>query_params</code> variables on the right.</em>
</p>

<table>
  <tr>
    <td width="50%" align="center">
      <img src="docs/screenshots/capture-tab.png" alt="Capture Control Center" width="100%"><br>
      <strong>Capture Control Center</strong> — Live KPIs, 4-step Android APEX CA &amp; Companion Guard Watchdog
    </td>
    <td width="50%" align="center">
      <img src="docs/screenshots/flows-tab.png" alt="Flows Traffic Inspector" width="100%"><br>
      <strong>Flows Traffic Inspector</strong> — Draggable SplitPane, JSON/XML/Protobuf/Hex &amp; Sign Detection
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <img src="docs/screenshots/deeptrace-tab.png" alt="DeepTrace 8-Stage Pipeline" width="100%"><br>
      <strong>DeepTrace 8-Stage Live Pipeline</strong> — HTTP → Java → JNI → Native Call Graph &amp; APK/JADX Cache
    </td>
    <td width="50%" align="center">
      <img src="docs/screenshots/terminal-tab.png" alt="Workbench Multi-Tab Terminal" width="100%"><br>
      <strong>Workbench Multi-Tab Terminal</strong> — Structured diagnostic blocks for ADB, Frida &amp; CLI tools
    </td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="docs/screenshots/light-zh-preview.png" alt="Porcelain Light Theme + Simplified Chinese" width="88%"><br>
      <strong>Porcelain Light Theme + Native 简体中文</strong> — Live hot-switching across 4 themes &amp; EN / 中文
    </td>
  </tr>
</table>

---

## Why cap?

Most HTTP proxies (Burp Suite, mitmproxy, HTTP Toolkit) are designed for web security testing rather than **mobile app reverse engineering**. `cap` combines a fast Go MITM core, a native Wails desktop workbench, a flicker-free full-screen TUI, and a self-healing Android Companion Guard APK into a single binary:

| Capability | Burp Suite | mitmproxy | HTTP Toolkit | **cap** |
|------------|:----------:|:---------:|:------------:|:-------:|
| CLI-first automation | ✗ GUI only | ✓ mitmdump | ✗ GUI only | **✓ ANSI CLI + `--json`** |
| Full-screen interactive TUI | ✗ | ✓ mitmproxy | ✗ | **✓ split-pane (`cap tui`)** |
| Native desktop GUI | ✗ Java/Swing | △ mitmweb (basic) | ✓ Electron | **✓ Wails v2 + Svelte 4** |
| Multi-language (`EN` / `简体中文`) | ✗ | ✗ | ✗ | **✓ GUI + TUI + CLI + APK** |
| LLM/Agent-ready output | ✗ XML/HAR | △ HAR (verbose) | △ HAR | **✓ compact JSONL** |
| Multi-language codegen | ✗ | △ curl + Python | ✗ | **✓ 5 languages** |
| Sign param auto-detect | ✗ | ✗ | ✗ | **✓** |
| Sign algorithm inference | ✗ | ✗ | ✗ | **✓ MD5/SHA/HMAC** |
| Static analysis & DeepTrace | ✗ | ✗ | ✗ | **✓ 8-stage live jadx / DEX / Call Graph** |
| Frida Studio & live hooking | ✗ | ✗ | ✗ | **✓ Server deploy / live hot-reload / Trace→Hook** |
| Native RE & Emulation (r2/Unidbg/Qiling/angr) | ✗ | ✗ | ✗ | **✓ Static r2 + pure-Go ELF / Emulation / Symbolic** |
| Anti-Obfuscation, Anti-Debug & VMP | ✗ | ✗ | ✗ | **✓ 13 packers / OLLVM / Inline SVC / VMP trace** |
| Execution Trace & Taint Analysis | ✗ | ✗ | ✗ | **✓ Multi-format / Reg+Mem Taint / ASLR Diff / Tenet** |
| Service Gateway (Open API + Pools) | ✗ | ✗ | ✗ | **✓ HTTP API / Proxy Pool / Device Pool / Signers** |
| One-cmd Android setup | ✗ | ✗ | △ app-based | **✓ ADB direct + Guard APK** |
| Auto network restore on disconnect | ✗ | ✗ | △ app-based | **✓ Companion Watchdog (rootless)** |
| Cert inject (Android 7–15) | ✗ manual | ✗ manual | ✓ | **✓ APEX Conscrypt / mount --bind / Magisk / KeyChain** |
| SSL unpinning | △ manual | ✗ | ✗ | **✓ Frida / patch / Magisk / CodeShare** |
| Intercept rules & breakpoints | ✓ | ✓ addon | ✓ Pro | **✓ rules + held breakpoints** |
| Request replay + diff | ✓ Repeater | ✗ | ✗ | **✓ modify-replay + side-by-side diff** |
| API auto-grouping & sequences | ✗ | ✗ | ✗ | **✓ host/path + token propagation** |
| Traffic dashboard | ✗ | ✗ | ✗ | **✓ P95 / timeline / TLS alerts** |
| Embedded terminal | ✗ | ✗ | ✗ | **✓ multi-tab PTY** |
| HAR / Charles import | ✓ | ✓ | ✓ | **✓** |
| WebSocket capture | ✓ | ✓ | ✓ | **⧗ experimental** |
| SSE stream capture | ✗ | △ | ✗ | **⧗ experimental** |
| Protobuf auto-decode | ✗ addon | △ addon | ✗ | **⧗ experimental (schema-less)** |
| Plugin system | ✓ BApp | ✓ addon | ✗ | **✓ single-page Python/Node/Sh workbench** |
| Single binary | ✗ JVM | ✗ Python | ✗ Electron | **✓ Go single binary** |
| Open source | ✗ ($449/yr) | ✓ | △ core only | **✓ MIT** |

### Maturity Labels

- **Stable**: covered by automated tests and suitable for daily use.
- **Experimental**: implemented and tested, but not yet validated across enough protocol/device combinations for unconditional claims.

The comparison table uses `⧗ experimental` where `cap`'s support exists but is not yet release-hardened. These labels are deliberately conservative.

---

## Architecture

### System Overview

```mermaid
flowchart TB
    subgraph Client["Client & Localization Layer (EN / 简体中文)"]
        CLI["cap CLI<br/>(cobra + i18n)"]
        TUI["cap TUI<br/>(double-buffered ANSI)"]
        GUI["cap GUI<br/>(Wails v2 + Svelte 4)"]
        TTY["Embedded Terminal<br/>(multi-tab PTY)"]
    end

    subgraph Core["Core Engine"]
        PROXY["MITM Proxy<br/>(goproxy + rules/breakpoints)"]
        STORE["Flow Store<br/>(SQLite WAL)"]
        REPLAY["Request Replay<br/>+ Diff & Sequence Engine"]
    end

    subgraph Analysis["Analysis & Reverse Engineering"]
        SIGN["Sign Inference<br/>(MD5/SHA/HMAC)"]
        TRACE["DeepTrace & Source Mapper<br/>(jadx / DEX / Call Graph)"]
        DETECT["Param Detector<br/>(sign / ts / nonce)"]
        RELAB["RE Lab Engine<br/>(r2 / Unidbg / Qiling / angr)"]
        DEOBF["Deobf & VMP Engine<br/>(Packer / OLLVM / SVC / VMP)"]
        EXECTRACE["ExecTrace & Taint<br/>(Multi-format / Taint / Diff)"]
    end

    subgraph Service["Service Gateway & Integration Hub"]
        GW["Open API HTTP Gateway<br/>(:9090 / Auth / OpenAPI 3.0.3)"]
        POOLS["Proxy IP Pool &<br/>Device Fingerprint Pool"]
        SIGNERS["Pluggable Signers<br/>(HMAC / Script / HTTP / Unidbg / Frida)"]
    end

    subgraph Export["Export Layer"]
        CODEGEN["Code Generator<br/>(curl/py/go/java/js)"]
        AGENT["Agent Exporter<br/>(compact JSONL)"]
    end

    subgraph Capture["Stream Layer (Experimental)"]
        WS["WebSocket<br/>Frame Parser"]
        SSE["SSE Stream<br/>Parser"]
    end

    subgraph Device["Android Device & Guard Layer"]
        ADB["Android ADB<br/>(proxy + 3-strategy cert)"]
        GUARD["Cap Companion Guard APK<br/>(ProxyGuardService Watchdog)"]
    end

    subgraph Unpin["Frida Studio & SSL Unpinning Layer"]
        FRIDA["Frida Studio & Bridge<br/>(server deploy / hot-reload / hooks)"]
        PATCH["APK Patcher<br/>(NSConfig)"]
        CODESHARE["CodeShare<br/>(fingerprint → script)"]
    end

    CLI --> PROXY
    TUI --> PROXY
    TUI --> STORE
    GUI --> PROXY
    GUI --> TTY
    PROXY --> STORE
    PROXY --> WS
    PROXY --> SSE
    WS --> STORE
    SSE --> STORE
    STORE --> CODEGEN
    STORE --> AGENT
    STORE --> SIGN
    STORE --> REPLAY
    STORE --> GW
    TRACE --> STORE
    TRACE --> FRIDA
    TRACE --> RELAB
    TRACE --> DEOBF
    RELAB --> EXECTRACE
    DEOBF --> FRIDA
    GW --> POOLS
    GW --> SIGNERS
    SIGNERS --> RELAB
    SIGNERS --> FRIDA
    DETECT --> STORE
    ADB --> PROXY
    ADB --> GUARD
    ADB --> FRIDA
    ADB --> PATCH
    ADB --> POOLS
    CODESHARE --> FRIDA

    style Client fill:#1e3a5f,color:#fff
    style Core fill:#14532d,color:#fff
    style Analysis fill:#7c2d12,color:#fff
    style Service fill:#1e40af,color:#fff
    style Export fill:#581c87,color:#fff
    style Capture fill:#7f1d1d,color:#fff
    style Device fill:#164e63,color:#fff
    style Unpin fill:#713f12,color:#fff
```

### Data Flow

```mermaid
sequenceDiagram
    participant Phone as Android Device + Cap Guard APK
    participant Proxy as cap MITM Proxy
    participant Store as SQLite (WAL)
    participant Detect as Param Detector
    participant Sign as Sign Inference
    participant Export as GUI / TUI / Exporter

    Phone->>Proxy: HTTP/HTTPS request (Watchdog probes every 3s)
    Proxy->>Proxy: Rules / Breakpoints & MITM intercept
    Proxy->>Store: Save Flow
    Proxy->>Phone: Forward to upstream & return response
    Proxy-->>Store: Update Flow (response & timing)

    Store->>Detect: Analyze params
    Detect-->>Store: Tag sign_params

    Store->>Sign: Analyze sign values across requests
    Sign-->>Store: Algorithm guess & brute-force check

    Store->>Export: Live stream / cap tui / cap export
    Export-->>Export: GUI Inspector / cURL / Python / JSONL
```

---

## Features

### Refactored Commercial Desktop GUI (`cap gui`)

Native Wails v2 + Svelte 4 desktop workbench compiled into a single binary (no Electron overhead):

- **Workbench Shell & Navigation**:
  - **4 Built-in Themes**: **Obsidian Dark** (default), **Porcelain Light**, **Mocha** (Catppuccin), and **Nord** with crisp 1px borders, layered elevation tokens, and `tabular-nums` monospace telemetry.
  - **Command Palette (`⌘K` / `Ctrl+K`)**: Instant jump across workspaces, proxy start/stop/pause, theme switching, and live `EN ↔ 简体中文` language toggling.
  - **Collapsible Left Nav Rail (`⌘B`)** with `⌘1–9` / `⌘,` workspace shortcuts, live proxy, Frida hook, RE job & Service Gateway status badges, compact `EN / 中文` switcher, and an IDE-style bottom status bar.
- **10 Integrated Workspaces**:
  1. **Capture (`⌘1`)**: Live 4-KPI telemetry strip (`req/s` + bandwidth, total flows/bytes, active hosts + avg/P95 latency, error rate + TLS alerts), guided 4-step Android setup (`ADB Device` → `CA Certificate` → `Cap Companion Guard` → `Proxy Route`), domain scope filters, Frida server quick controls (Start/Stop/ABI/version + jump to Frida Studio), and a tabbed Activity Log / Active Hosts / TLS Alerts console.
  2. **Flows (`⌘2`)**: Multi-facet filter toolbar (`/` focus, host suggestions, method/status/content-type pills, Flat vs API Groups), horizontal/vertical draggable `SplitPane`, keyboard navigation (`↑/↓`/`j/k`, `Esc`), tabbed inspector (`Params`, `Req/Resp Headers`, `Req/Resp Body` with JSON / XML / Protobuf / Hex + inline search, `Raw`, `Timing`, `Export` to cURL/Python/Go/Java/JS/Agent JSONL), Replay & Modify-Replay, Side-by-Side Flow Diff, Sign Analysis, 1-click **Publish to Gateway** handoff, HAR/Charles Import, native loopback **MJPEG Device Monitor** (`Fast` / `scrcpy`, live FPS & drag-swipe), and an inline **Plugins** mode (`PluginWorkbench`) for uninterrupted single-page Flow ↔ Plugin debugging.
  3. **Rules (`⌘3`)**: Split-pane intercept rules engine + live **Held Breakpoints** queue (Forward Edited / Mock / Drop 403), 6 action types, priority ordering, and regex/substring path validation.
  4. **DeepTrace (`⌘4`)**: Live 8-stage cancellable trace pipeline with real-time progress events, pure-Go DEX bytecode XRefs, 3-perspective interactive SVG Call Graph, and APK/JADX caching — plus 1-click **Hook in Frida**, **Emulate in RE Lab**, and **Scan Protection** handoffs from the Executive Report, module cards, and Native `.so` findings.
  5. **Frida (`⌘5`)**: Dedicated **Frida Studio** workbench with full `frida-server` lifecycle (ABI auto-detect, GitHub Release auto-download or local `.xz` push, stealth binary rename, custom port + `adb forward`, host vs device version-match diagnostics), zero-CGO Python Frida Bridge (with automatic `frida-cli` fallback), searchable process/app picker, `Spawn (-f)` / `Attach`, **live script hot-reload (`⌘R`)** without restarting the app, structured `send()` JSON event cards & JSONL export, 7 built-in RE templates + `~/.cap/frida-scripts/` disk hot-reload, CodeShare & app fingerprint browser, and **From Trace** auto-hook generator.
  6. **RE Lab (`⌘6`)**: Unified 4-tab Native Reverse Engineering workbench combining **Native / radare2** static & pseudo-C inspection (with pure-Go ELF fallback), **Unidbg · Qiling · angr** emulation & symbolic execution with live job streaming (`~/.cap/re-projects/*.json`), **Deobf · Anti-Debug · VMP** protection scanner & script generator (1-click handoff to Frida or Emulation), and **ExecTrace · Taint** dynamic trace analyzer with forward/backward taint slicing, crypto detection, ASLR-normalized trace diff, and Tenet/JSONL/Markdown export.
  7. **Plugins (`⌘7`)**: Scriptable analyzer workbench & unified single-page debugger (`~/.cap/plugins/*.json` with disk hot-reload) supporting `python3`, `node`, `sh`, and `builtin` runtimes, live parsed `query_params` & flow variable inspector with click-to-insert snippets, live `stdin JSON` preview, real-time `Matches flow` indicator (supporting query strings & glob `*`), instant unsaved draft execution (`⌘Enter`), auto-run hooks on live traffic, and a real-time Execution Log drawer.
  8. **Service Gateway (`⌘8`)**: Embedded Open API HTTP Gateway (`:9090`) turning reverse-engineered mobile endpoints into production-ready REST APIs — featuring 1-click Flow-to-Service route publishing, live Route Tester, API Key auth & per-route rate limiting, OpenAPI 3.0.3 export, **Proxy IP Pool** (HTTP/HTTPS/SOCKS5, dynamic provider fetch, health checks, rotation/sticky-device), **Device Pool** (virtual fingerprint presets + ADB sync), **Pluggable Signer Providers** (Built-in HMAC, Script, HTTP, Unidbg HTTP, Frida RPC), and real-time Invocation Logs.
  9. **Terminal (`⌘9`)**: Multi-tab embedded PTY console (`⌘T` / `⌘W` / `Ctrl+Tab` / `Ctrl+L`) with quick diagnostic presets for `adb`, `frida`, and `curl`.
  10. **Settings (`⌘,`)**: Sectioned preferences for Appearance & Display Language (`English` / `简体中文`), Proxy & Certs, Android / Frida Runtime Paths, RE Toolchain (`r2`, `java`, `mvn`, `unidbg`, `python3`, `qiling rootfs`) & Default Gateway Address, Export & Storage, Shortcuts, and About & Diagnostics.

### Full-Screen Interactive TUI (`cap tui` & `cap start --tui`)

A flicker-free, double-buffered full-screen ANSI terminal UI (using DEC Synchronized Output + alternate screen + guaranteed terminal restore) with responsive wide (`≥110` cols) and stacked split-pane layouts:

```bash
cap start --tui                      # Live MITM proxy inside the interactive TUI
cap tui                              # Browse & inspect saved SQLite flows
cap tui --live -a 0.0.0.0:8080       # Live capture on all interfaces
cap tui -f 'm:POST s:4xx' --light    # Initial filter + Porcelain Light theme
cap tui --lang zh                    # Launch directly in Simplified Chinese
```

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate flow list or scroll detail pane |
| `Tab` / `Shift+Tab` | Switch focus between flow list and inspector pane |
| `1` – `6` | Switch inspector tab: `1` Overview · `2` Request · `3` Response · `4` Headers · `5` Timing · `6` cURL/Code |
| `l` | Cycle codegen language on tab `6` (`curl`, `python`, `go`, `java`, `js`) |
| `/` | Open live filter bar (`m:POST s:4xx h:api.example.com !static`) |
| `m` / `e` / `c` | Cycle method filter / toggle errors-only (`4xx`/`5xx`) / clear filters |
| `f` / `p` | Toggle auto-follow newest flows / pause live stream |
| `z` | Zoom focused pane full-width |
| `r` | Async replay selected request |
| `y` / `x` | Copy cURL snippet to clipboard / export flow to file |
| `R` / `d` | Reload SQLite store / delete selected flow |
| `t` | Toggle **Obsidian Dark** ↔ **Porcelain Light** theme |
| `L` | Live hot-switch **`EN` ↔ `简体中文`** (with full CJK double-width alignment) |
| `?` / `q` / `Ctrl+C` | Toggle Help overlay / quit cleanly |

**Machine-readable CLI guarantee**: `--json`, `--format json`, `cap export`, `cap unpin script`, `NO_COLOR=1`, and non-TTY piped stdout always emit pure, uncolored output suitable for scripts and pipelines.

### Multi-Language Support (`EN` / `简体中文`)

Full bilingual localization across every surface of `cap`:

- **Desktop GUI**: Instant hot-switch via the top bar `EN / 中文` pill, bottom status bar, Command Palette (`⌘K`), or Settings → Language. Persisted automatically and synced with system locale on first launch.
- **Interactive TUI & CLI**: Auto-detected from `CAP_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG`, overridable via the persistent `--lang en|zh` flag on any command, or hot-toggled inside the TUI with `L`.
  - *Note*: On `cap export`, `-l` / `--lang` selects the generated code language (`curl`, `python`, `go`, `java`, `js`, `all`).
- **Android Companion Guard APK**: Native Android bilingual resources (`Cap Guard` / `Cap 代理守护`) adapting automatically to the device system language.

### Hardened Android Capture & Cap Companion Guard APK

Connecting a phone to a proxy should **never** leave the device stranded without internet when you unplug USB, switch Wi-Fi, or close the proxy.

`cap` embeds a signed, 33 KB, zero-dependency pure Android SDK APK (`com.overkazaf.cap.companion`, `minSdk=24`, `targetSdk=34`) directly inside the `cap` binary (`internal/android/bin/cap-companion.apk`):

- **Zero-Touch Deployment**: Automatically installed and started on `cap android connect` (skip with `--no-companion`) and GUI Connect.
- **Rootless Autonomous Proxy Cleanup**: `cap` grants `WRITE_SECURE_SETTINGS` and battery/background whitelisting over ADB on connect — **no root required** for autonomous Wi-Fi proxy restoration.
- **Active Heartbeat Watchdog (`ProxyGuardService`)**: Foreground service probes `proxy_host:proxy_port` every 3 seconds. After 3 consecutive misses — or on `ACTION_POWER_DISCONNECTED`, reboot (`BootReceiver`), or tapping **Restore Network / 恢复网络** directly in the notification — the APK autonomously clears `http_proxy` (and kills `cap-redir` / iptables rules in `--vpn` root mode) and posts a confirmation notification.
- **CA Certificate Lifecycle (Android 7–15)**:
  - **Rooted devices**: HTTP Toolkit-style Android 14+ APEX Conscrypt namespace injection (`mount --bind` + `TRUST_STORE_CHANGED` live trust reload), Android 10–13 `mount --bind`, persistent Magisk module, or legacy `/system` remount — plus `cap android cert --check` / `--remove`.
  - **Non-rooted devices**: Built-in `MainActivity` launches Android's `KeyChain` CA installer directly for `/sdcard/Download/cap-ca.crt` with guided verification.
- **Desktop Auto-Teardown**: `cap start --auto-disconnect`, `cap tui --live --auto-disconnect`, and Desktop GUI `StopProxy()` / `App.Shutdown()` automatically tear down tracked Android devices before stopping the proxy.

### Frida Dynamic Instrumentation Studio (`cap frida` & GUI `⌘5`)

End-to-end Android dynamic instrumentation without CGO bloat or external Frida GUI tools:

```bash
cap frida status                                           # Check Python Bridge / frida CLI & device frida-server
cap frida deploy --start --name hluda-srv                  # Auto-download matching ABI/ver, stealth rename & start
cap frida ps                                               # List apps & running PIDs (Bridge → frida-ps → ADB)
cap frida scripts                                          # List 7 built-in RE templates + ~/.cap/frida-scripts/
cap frida run --pkg com.example.app --spawn \
  --script builtin:crypto-sign-tracer                      # Stream structured send() hook events live
```

- **Server Lifecycle & Stealth Deploy**: Batched ADB probe detects CPU ABI (`arm64`/`arm`/`x86_64`/`x86`), root, running PID/port, and host-vs-device version compatibility (`match` / `minor_diff` / `major_mismatch`). Deploys from GitHub Releases (cached in `~/.cap/frida-cache/`) or local `.xz`/raw binaries with optional stealth renaming and `adb forward`.
- **Embedded Python Frida Bridge + CLI Fallback**: Auto-discovers working Python 3 / venv / conda / pipx runtimes (configurable in Frida Studio or Settings) for structured `send()` JSON cards, binary hex previews, Spawn pause/resume, and **live hot-reload (`⌘R`)** without restarting the target app — gracefully falling back to `frida` CLI when needed.
- **Built-in Script Library & CodeShare**: Ships 7 curated scripts (14+ Universal SSL Unpin, Anti-Root & Anti-Frida Stealth, OkHttp3/URLConnection Tracer, Crypto/Sign Tracer for MD5/SHA/HMAC/AES, JNI `RegisterNatives` & `dlopen` Tracer, SharedPreferences/SQLite Watcher, Dynamic Class Explorer), persistent custom scripts (`~/.cap/frida-scripts/*.json` with disk hot-reload), and integrated CodeShare search + app fingerprinting.
- **DeepTrace → Frida Closed Loop**: Generate runnable Java, DEX XRef, and delayed `dlopen` Native `.so` hooks directly from any DeepTrace report, module card, or native export in one click.

### RE Lab — Native Binary Analysis & Algorithm Emulation (`cap re` & GUI `⌘6`)

Full native `.so`/ELF/Mach-O reverse-engineering and algorithm emulation pipeline without leaving `cap`:

```bash
cap re status                                              # Probe radare2, JDK/Maven/Unidbg, Python/Qiling/angr
cap re analyze ./libsign.so --func Java_com_app_sign       # Static ELF/r2 analysis + disassembly/pseudo-C/xrefs
cap re r2 ./libsign.so "iI;iEj"                            # Sanitized read-only radare2 command execution
cap re gen -e unidbg --apk app.apk --so libsign.so \
  --class com/app/Signer --method sign --http-server       # Synthesize Unidbg harness (with optional HTTP signer mode)
```

- **radare2 + Pure-Go ELF Fallback**: Extracts architecture, mitigations (`PIE`, `NX`, `Canary`, `RELRO`), functions, dynamic exports/imports, strings, xrefs, disassembly, and pseudo-C (`pdg`/`pdc`), falling back seamlessly to a pure-Go `debug/elf` analyzer when `r2` is absent.
- **Unidbg · Qiling · angr Emulation & Symbolic Execution**: Ships curated starter templates and parameterized harness generators for Android JNI `.so` emulation (Unidbg, including embedded HTTP signer server mode), ARM64/ARM Linux/Android emulation (Qiling with RootFS & syscall hooks), and symbolic constraint solving (angr with `claripy` concrete solution extraction).
- **DeepTrace → RE Lab Closed Loop**: Click **Emulate in RE Lab** from any DeepTrace report or Native `.so` finding to synthesize a tailored Unidbg/Qiling/angr harness pre-filled with APK, `.so`, JNI symbols, and captured request inputs, with live cancellable job streaming and `~/.cap/re-projects/*.json` persistence.

### Anti-Obfuscation, Anti-Debug & VMP Analysis (`cap deobf` & GUI `⌘6`)

Automated mobile hardening audit and composable bypass/deobfuscation script generation:

```bash
cap deobf scan ./target.apk                                # Audit 13 packers, OLLVM, VMP & ARM64 inline SVC #0
cap deobf stealth --scan ./target.apk --pkg com.app -o stealth.js
cap deobf unpack --pkg com.app -o unpack.js                # In-memory Frida DEX unpacker
cap deobf ollvm --so ./libsec.so --addr 0x1a400            # angr OLLVM CFF de-flattening & binary patcher
cap deobf vmp --mode stalker --so libvmp.so --entry JNI_OnLoad
cap deobf vmp-trace ./vmp.log --base 0x7000000000          # Identify VMP dispatchers, handlers & external calls
```

- **Protection & Hardening Scanner**: Pure-Go APK/ELF scanner detecting **13 commercial packers** (Qihoo 360, Tencent Legu, Bangcle, Ijiami, Baidu, Ali, Dingxiang, Najia, SecNeo, Virbox, Jiagu, Naga, etc.), **OLLVM** Control-Flow Flattening / Bogus Control Flow / Instruction Substitution, **VMP** interpreters, anti-debug symbols, and raw **ARM64 inline `SVC #0`** syscalls.
- **Composable Stealth & Unpacking Generators**: Auto-tailors Frida Anti-Debug / Anti-Frida stealth scripts (`TracerPid` / `/proc/self/maps`, `ptrace` / signal traps, inline ARM64 `SVC` patching with dry-run mode, timing / `inotify`, Java debug checks), in-memory DEX unpackers, OLLVM CFF de-flattening (`angr`), string decryption (Qiling / Unidbg), and Java deobfuscation scripts — with 1-click handoff to Frida Studio or RE Lab Emulation.
- **VMP Tracing & Analysis**: Generates Frida Stalker, `RegisterNatives`, and Unidbg VMP collectors, and analyzes captured VMP instruction traces to recover dispatcher PCs, handler tables, hot blocks, and external API calls.

### Execution Trace & Taint Analysis (`cap exectrace` & GUI `⌘6`)

Multi-engine dynamic instruction trace inspection, taint slicing, and differential analysis:

```bash
cap exectrace import ./sign.trace --format auto --base 0x7000000000
cap exectrace taint --session <id> --direction backward --seq 4200 --reg x0
cap exectrace diff <sessionA> <sessionB> --max-divergences 25
cap exectrace collect --kind stalker --module libsign.so --symbol Java_com_app_sign
cap exectrace export <sessionID> -f tenet -o trace.tenet.txt
```

- **Multi-Format Parser**: Auto-detects and normalizes traces from **Unidbg**, **Frida Stalker**, **Qiling**, **Java/JNI calls**, **JSONL**, and **Tenet**.
- **Forward & Backward Register + Memory Taint**: Tracks register and concrete memory propagation (ARM64 shifted/extended addressing, x86 scaled indexing, constant kills, and per-thread hot loops) to slice from output signatures back to key inputs or vice versa.
- **Crypto Detection, ASLR Diff & Export**: Automatically detects standard crypto constants (AES S-Box, MD5/SHA/CRC32/ChaCha/SM4/RC4), hot loops, and call trees; computes ASLR-normalized trace diffs across runs; generates ready-to-run Stalker / Java / Unidbg / Qiling collectors; and exports to **Tenet**, **JSONL**, or **Markdown**.

### Service Gateway & Integration Hub (`cap gateway` & GUI `⌘8`)

Turn reverse-engineered mobile APIs into reliable, authenticated HTTP endpoints backed by proxy, device, and signer pools:

```bash
cap gateway publish --flow f1 --slug search-feed           # Publish a captured flow as an Open API route
cap gateway proxies --add socks5://user:pass@1.2.3.4:1080 --check
cap gateway devices --from-preset pixel-8-pro              # Create virtual fingerprint (or --sync-adb)
cap gateway signers --test <signerID> --url https://api.example.com/v1/feed
cap gateway start -a 127.0.0.1:9090 --require-auth --api-key sk-live-demo
cap gateway openapi -o openapi.json                        # Export OpenAPI 3.0.3 spec
```

- **Open API HTTP Gateway (`:9090`)**: Publishes captured flows into reusable `POST /gw/<slug>` routes with template substitution (`{{input.*}}`, `{{device.*}}`, `{{timestamp}}`, `{{nonce}}`), API Key auth (`X-API-Key` / `Bearer`), per-route rate limiting, retries/failover, raw passthrough mode, live Route Tester, real-time invocation telemetry, and **OpenAPI 3.0.3** spec export.
- **Proxy IP Pool**: Manages `HTTP` / `HTTPS` / `SOCKS5` nodes with bulk import, dynamic provider fetch (`lines` or `json` path extraction), concurrent health/latency probing, and `round_robin`, `random`, `least_latency`, or `sticky_device` rotation policies.
- **Device Pool & Virtual Fingerprints**: Ships realistic Android fingerprint presets (UA, OAID, Android ID, build props, screen metrics, cookies/tokens) alongside 1-click **ADB physical device sync**.
- **Pluggable Signer Providers**: Computes fresh request signatures per invocation via **Built-in HMAC/Hash** (MD5/SHA/HMAC), **Local Script** (`python3`/`node`/`sh`), **External HTTP**, **Unidbg HTTP Signer**, or **Frida RPC** (`rpc.exports`).

### SSL Unpinning

Four strategies to bypass app-level certificate pinning:

```bash
cap unpin frida --pkg com.example.app --spawn   # Frida: hooks 14+ pinning implementations
cap unpin patch --apk ./target.apk              # Patch: rewrite network_security_config.xml
cap unpin magisk                                # Magisk: promote user certs to system store
cap unpin codeshare --pkg com.example.app       # CodeShare: auto-fingerprint → matching scripts
cap unpin script                                # Print raw Frida unpinning JS to stdout
```

Covers TrustManagerImpl, OkHttp3 CertificatePinner, SSLContext, WebViewClient, Conscrypt, Flutter BoringSSL, Apache HTTP, TrustKit, Cordova, NetworkSecurityConfig, and more.

### Reverse-Engineering & Export Suite

- **Multi-Language Codegen**: Export any captured flow to runnable `curl`, `python` (`requests`), `go` (`net/http`), `java` (`OkHttp3`), `js` (`fetch`), or `all`.
- **LLM/Agent-Ready JSONL (`cap export -f agent`)**: Compact one-line-per-flow JSONL with noise headers stripped, `sign_params` auto-tagged, inline JSON bodies, and SHA-256 hashes for truncated large bodies.
- **Signature Algorithm Inference**: Length/encoding heuristics, cross-request consistency checks, and MD5/SHA1/SHA256/HMAC brute-force verification on sorted parameters.
- **API Auto-Grouping, Flow Compare & Sequence Replay**: Group endpoints by host/path prefix, diff any two flows side-by-side, and replay multi-step sequences with automatic token/cookie propagation.
- **HAR / Charles Import**: Import existing `.har` or Charles XML captures with zero friction.

---

## Install & Build

### Prerequisites

- **Go** `1.27+` (matches `go.mod`)
- **Node.js** `18+` (for building the Svelte 4 frontend)
- **macOS**: Xcode Command Line Tools (`xcode-select --install`)
- **Linux** (for Desktop GUI): `libgtk-3-dev libwebkit2gtk-4.0-dev`
- **Android** *(optional)*: `adb` in `PATH` for device capture; Android SDK `build-tools` only if rebuilding `android-companion/` from source (a prebuilt signed APK is already embedded)

### Recommended Full Build (Desktop GUI + TUI + CLI + Embedded Companion APK)

```bash
git clone https://github.com/overkazaf/cap.git
cd cap

# Build & sync Svelte frontend assets, verify SHA-256 match, and compile Wails desktop binary
make assets && make build

# Run
./dist/cap gui                     # Launch native Desktop GUI
./dist/cap tui --live              # Launch full-screen interactive TUI with live MITM proxy
./dist/cap --help                  # View CLI commands
```

> `make build` automatically sets `-tags 'desktop,production'` for Wails v2 and adds `-framework UniformTypeIdentifiers` on macOS.

### CLI & TUI Only (Fast Build without GUI)

```bash
git clone https://github.com/overkazaf/cap.git
cd cap
go build -o dist/cap ./cmd/cap
./dist/cap tui
```

### Verification & Tests

```bash
make test     # Run network-safe unit test suite
make check    # Run tests + frontend build + embedded asset SHA-256 check
```

### Rebuilding the Android Companion Guard APK *(Optional)*

`internal/android/bin/cap-companion.apk` is already checked in and embedded via `go:embed`. To rebuild it offline from source:

```bash
ANDROID_HOME=~/Library/Android/sdk ./android-companion/build.sh
```

---

## Quick Start

```bash
# 1. Start live MITM proxy inside the interactive full-screen TUI
./dist/cap start --tui -a 0.0.0.0:8080

# 2. Connect an Android device (sets proxy, installs CA cert, starts Cap Companion Guard watchdog)
./dist/cap android connect

# 3. Check Android proxy, CA cert, and Companion Guard watchdog status
./dist/cap android status

# 4. Query saved flows from CLI or browse in TUI
./dist/cap flows --host api.example.com --method POST -n 20
./dist/cap tui --filter 'm:POST s:4xx'

# 5. Export runnable code or compact LLM-ready JSONL
./dist/cap export --flow f1 -l python
./dist/cap export -f agent | pbcopy

# 6. Disconnect cleanly (or just close cap / unplug USB — Companion Guard auto-restores!)
./dist/cap android disconnect

# 7. Or launch the full Desktop GUI workbench
./dist/cap gui
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `cap gui [-d db]` | Launch the native Wails desktop GUI |
| `cap start [--tui] [-a addr] [-d db] [--auto-disconnect]` | Start MITM proxy (ANSI stream or `--tui` full-screen mode) |
| `cap tui [--live] [-a addr] [-f filter] [--light] [--no-color]` | Open interactive full-screen TUI for stored or live flows |
| `cap flows [--host] [--method] [--tag] [-s search] [-n limit] [--json]` | List and filter captured flows (`table` or `json`) |
| `cap export --flow <id> [-l curl\|python\|go\|java\|js\|all] [-f code\|agent]` | Export flow as runnable code or compact Agent JSONL |
| `cap android connect [--vpn] [--no-cert] [--no-companion] [-p port] [-s serial]` | Configure Android proxy, CA cert, and Companion Guard watchdog |
| `cap android status [--json] [-s serial]` | Inspect device identity, proxy, CA cert, and Companion Guard state |
| `cap android cert [--check\|--remove] [-s serial]` | Install, verify, or remove cap's CA certificate on device |
| `cap android disconnect [-s serial]` | Clear proxy, VPN redirect, and stop Companion Guard cleanly |
| `cap frida status [-s serial] [-p port] [--json]` | Inspect host Python/Frida toolchain & device `frida-server` status |
| `cap frida deploy [--version v] [--binary path] [--name stealth] [--start]` | Download or push `frida-server` matching device ABI & version |
| `cap frida start\|stop [-s serial] [-p port]` | Start or stop `frida-server` on device with optional `adb forward` |
| `cap frida ps [-s serial] [--json]` | List installed apps and running PIDs on Android device |
| `cap frida scripts [--show <id>] [--json]` | List built-in & custom Frida scripts or print script source |
| `cap frida run --pkg <pkg> [--spawn] [--script <id\|file>]` | Spawn or attach with live structured `send()` hook output |
| `cap unpin frida --pkg <pkg> [--spawn]` | Runtime SSL pinning bypass via Frida (14+ hooks) |
| `cap unpin patch --apk <file>` | Patch APK `network_security_config.xml` to trust user CA |
| `cap unpin magisk` | Deploy system-wide Magisk CA cert promotion module |
| `cap unpin codeshare [--pkg <pkg>\|--query <q>]` | Fingerprint APK & search Frida CodeShare scripts |
| `cap unpin script` | Print raw Frida unpinning script to stdout |
| `cap re status [--r2\|--java\|--unidbg-dir\|--python\|--rootfs] [--json]` | Probe host RE toolchain (`r2`, JDK/Maven/Unidbg, Python/Qiling/angr) |
| `cap re analyze <file> [--func <name\|addr>] [--json]` | Static ELF/Mach-O analysis & function disassembly/pseudo-C/xrefs |
| `cap re r2 <file> <cmd> [--json]` | Run a sanitized read-only radare2 command on a binary |
| `cap re projects [-e engine] [--show <id>] [--json]` | List built-in & saved RE projects or print harness source |
| `cap re gen -e <unidbg\|qiling\|angr\|radare2> [--apk\|--so\|--http-server]` | Synthesize an emulation, symbolic execution, or r2 harness |
| `cap deobf scan <apk\|so> [--json]` | Audit APK/ELF for 13 packers, OLLVM, VMP, anti-debug & inline `SVC #0` |
| `cap deobf stealth [--scan <path>] [--pkg <pkg>] [--patch-svc] [-o file]` | Generate composable Frida Anti-Debug / Anti-Frida stealth script |
| `cap deobf unpack [--pkg <pkg>] [-o file]` | Generate Frida in-memory DEX unpacker script |
| `cap deobf ollvm --so <path> --addr <hex> [--arch arm64] [-o file]` | Generate angr OLLVM CFF de-flattening & patching script |
| `cap deobf vmp [--mode stalker\|jni\|unidbg] [--so <lib>] [-o file]` | Generate VMP tracing collector (Stalker, `RegisterNatives`, Unidbg) |
| `cap deobf vmp-trace <file> [--base <hex>] [--json]` | Analyze raw VMP trace for dispatchers, handlers & external calls |
| `cap exectrace import <file> [--format auto\|unidbg\|stalker\|qiling\|tenet]` | Import & analyze dynamic execution trace (crypto, loops, call tree) |
| `cap exectrace list [--show <id>\|--delete <id>] [--json]` | List, inspect, or delete stored execution trace sessions |
| `cap exectrace taint --session <id> --direction <forward\|backward> --seq <n>` | Run forward/backward register & memory taint analysis |
| `cap exectrace diff <sessionA> <sessionB> [--max-divergences 25]` | Compute ASLR-normalized differential comparison between two traces |
| `cap exectrace collect --kind <stalker\|java_call\|unidbg\|qiling> [-o file]` | Generate ready-to-run execution trace collector script |
| `cap exectrace export <sessionID> [-f tenet\|jsonl\|markdown] [-o file]` | Export trace session to Tenet, JSONL, or Markdown |
| `cap gateway start [-a 127.0.0.1:9090] [--require-auth] [--api-key <k>]` | Start embedded Open API HTTP Service Gateway |
| `cap gateway status [--json]` | Inspect gateway listener status, routes & pool counts |
| `cap gateway publish --flow <id> [--slug <slug>] [--name <name>]` | Publish a captured flow as an Open API Gateway route |
| `cap gateway routes [--test <slug> --input k=v] [--delete <id>] [--json]` | List, test-invoke, or delete published service routes |
| `cap gateway proxies [--add <url>\|--import <file>\|--fetch <url>\|--check]` | Manage Proxy IP Pool (HTTP/HTTPS/SOCKS5, dynamic fetch, health check) |
| `cap gateway devices [--presets\|--from-preset <id>\|--sync-adb]` | Manage virtual Android device fingerprints & ADB device sync |
| `cap gateway signers [--test <id> --url <url>] [--delete <id>] [--json]` | List, test, or delete pluggable Signer Providers |
| `cap gateway openapi [-o openapi.json]` | Export OpenAPI 3.0.3 JSON specification for enabled routes |

**Global Flag**: `--lang en|zh` (auto-detected from `CAP_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG`).

---

## Project Structure

```text
android-companion/      Pure-SDK Android Companion Guard APK source & offline build.sh
cmd/cap/                Main entrypoint & embedded frontend/dist assets
frontend/
├── src/App.svelte      Workbench shell (collapsible nav rail, topbar, status bar, ⌘K)
├── src/components/     Icon, Badge, Button, SplitPane, CommandPalette, ToastHost, Kbd, EmptyState
├── src/lib/            tokens.css, theme.js (4 themes), i18n.js, {frida,reLab,gateway}State.js, locales/{common,core,frida,reLab,gateway,tools}.js
└── src/pages/          Capture, Flows, Rules, DeepTrace, Frida, RELab, Plugins, Gateway, Terminal, Settings
internal/
├── android/            ADB helpers, 3-strategy cert install/verify, companion.go, bin/cap-companion.apk
├── buildinfo/          Version injection metadata
├── capture/            WebSocket frame parser, SSE stream parser (experimental)
├── cli/                Cobra commands (start, tui, gui, flows, export, android, frida, unpin, re, deobf, exectrace, gateway)
├── compare/            Side-by-side flow comparison with structured diff
├── config/             Shared path defaults (~/.cap)
├── context/            jadx scanner, Retrofit/OkHttp parser, URL-to-source mapper
├── deobf/              APK/ELF protection scanner (13 packers, OLLVM, VMP, inline SVC), stealth/unpack/deobf generators & VMP analyzer
├── exectrace/          Multi-format execution trace parser, forward/backward taint slicer, crypto/loop detector, ASLR diff & Tenet export
├── export/             codegen/ (5 languages) & agent/ (compact JSONL)
├── frida/              Frida toolchain probe, server deploy/lifecycle, Python Bridge, script store & Trace→Hook codegen
├── gateway/            Open API HTTP gateway, Proxy IP Pool, Device Fingerprint Pool, Pluggable Signer Providers & OpenAPI 3.0.3
├── grouping/           API auto-grouping by host + path prefix
├── i18n/               Zero-dependency EN / zh-CN localization catalog for TUI & CLI
├── importer/           HAR and Charles proxy XML import
├── plugin/             Built-in analyzer plugin engine (experimental)
├── proto/              Schema-less protobuf wire format decoder (experimental)
├── proxy/              goproxy MITM core, ECDSA CA cert gen, stream capture
├── replay/             HTTP replay, request modification, response diff
├── retools/            Native RE & emulation engine (radare2 + pure-Go ELF, Unidbg, Qiling, angr, DeepTrace harness codegen & job runner)
├── rules/              Intercept rules, mocks, and held breakpoints persistence & engine
├── screen/             Android device screen mirror (screencap + scrcpy)
├── sequence/           Request sequence record/replay with variable propagation
├── sign/               Signature parameter detection, heuristics, brute-force verification
├── stats/              Traffic telemetry (P95 latency, error rate, timeline)
├── store/sqlite/       SQLite WAL persistence, filtering, JSON codec
├── terminal/           Multi-tab PTY backend for GUI Terminal
├── trace/              DeepTrace: DEX search, jadx, call-graph & native analysis
├── tui/                Flicker-free double-buffered ANSI full-screen TUI
├── types/              Flow, WSFrame, SSEEvent models
├── unpin/              SSL unpinning: Frida hooks, APK patch, Magisk, CodeShare
└── wailsgui/           Wails v2 desktop bindings, live events & graceful device teardown
docs/                   GitHub Pages site (Obsidian/Porcelain theme + EN/中文 switcher)
```

---

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, testing, and security review guidelines.

## Author & License

© 2026 [0xaf (@overkazaf)](https://github.com/overkazaf) · MIT License (see [LICENSE](LICENSE)) · [GitHub](https://github.com/overkazaf/cap) · [Docs](https://overkazaf.github.io/cap/)
