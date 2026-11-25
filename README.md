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
| Site Recon & Nmap Port Scanner | ✗ | ✗ | ✗ | **✓ DNS/WHOIS/TLS/Tech/Subdomains/Nmap + Native TCP** |
| Multi-Model AI Auto-Heal Loop | ✗ | ✗ | ✗ | **✓ OpenAI/Claude/Gemini/Ollama + Secret Redaction + Diff + ≤5x Loop** |
| Static analysis & DeepTrace | ✗ | ✗ | ✗ | **✓ 8-stage live jadx / DEX / Call Graph** |
| Frida Studio & live hooking | ✗ | ✗ | ✗ | **✓ Server deploy / live hot-reload / Trace→Hook** |
| Native RE & Emulation (r2/Unidbg/Qiling/angr) | ✗ | ✗ | ✗ | **✓ Static r2/ELF/iOS Mach-O / Auto-Stub / JADX↔JNI / Symbol Bridge** |
| Anti-Obfuscation, Anti-Debug & VMP | ✗ | ✗ | ✗ | **✓ 13 packers / OLLVM / Inline SVC / VMP trace** |
| Execution Trace & Taint Analysis | ✗ | ✗ | ✗ | **✓ Multi-format / Reg+Mem Taint / ASLR Diff / Tenet** |
| CryptoLab & White-Box AES DFA | ✗ | ✗ | ✗ | **✓ Codec/Cipher Pipeline (SM4/AES/ChaCha20) / Protobuf / R9 DFA** |
| Modern TLS / mTLS & Cert Diagnostics | ✗ | △ basic | △ basic | **✓ 6 TLS/JA3 Profiles / APK Cert+Pin Scan / mTLS / Flutter & Cronet** |
| Service Gateway (Production Open API) | ✗ | ✗ | ✗ | **✓ Proxy/Device/Account Pools / Managed Workers / Cache / Circuit / Prom & Docker** |
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
| Protobuf auto-decode | ✗ addon | △ addon | ✗ | **✓ Schema-less AST decode & lossless re-encode** |
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
        RECON["Site Recon & Scanner<br/>(DNS / WHOIS / TLS / Subdomains / Nmap)"]
        AI["AI Assistant & Auto-Heal<br/>(OpenAI / Claude / Gemini / Ollama · Diff · Loop)"]
        SIGN["Sign Inference<br/>(MD5/SHA/HMAC)"]
        TRACE["DeepTrace & Source Mapper<br/>(jadx / DEX / Call Graph)"]
        DETECT["Param Detector<br/>(sign / ts / nonce)"]
        RELAB["RE Lab & Pro Suite<br/>(r2 / Unidbg / Qiling / angr / JADX↔JNI / iOS)"]
        CRYPTOLAB["CryptoLab & DFA<br/>(Codecs / SM4 / Protobuf / AES-128 DFA)"]
        TLSKIT["TLS / mTLS Kit<br/>(6 JA3 Profiles / APK Certs / Flutter / Cronet)"]
        DEOBF["Deobf & VMP Engine<br/>(Packer / OLLVM / SVC / VMP)"]
        EXECTRACE["ExecTrace & Taint<br/>(Multi-format / Taint / Diff)"]
    end

    subgraph Service["Service Gateway & Integration Hub"]
        GW["Open API HTTP Gateway<br/>(:9090 / Cache / Circuit / Prom / Docker)"]
        POOLS["Proxy, Device & Account Pools<br/>(Singleflight 401/403 Refresh / TLS+mTLS)"]
        SIGNERS["Pluggable Signers & Managed Workers<br/>(HMAC / Script / HTTP / 1-8 Worker Pool / Frida)"]
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
    STORE --> RECON
    AI --> RELAB
    AI --> FRIDA
    TRACE --> STORE
    TRACE --> FRIDA
    TRACE --> RELAB
    TRACE --> DEOBF
    RELAB --> EXECTRACE
    RELAB --> CRYPTOLAB
    DEOBF --> FRIDA
    DEOBF --> TLSKIT
    GW --> POOLS
    GW --> SIGNERS
    GW --> TLSKIT
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
  - **Collapsible Left Nav Rail (`⌘B`)** with `⌘1–9` / `⌘0` / `⌘,` workspace shortcuts across 4 clear groups (**Traffic**, **Reverse Engineering**, **Services**, **System**), live proxy, Site Recon scan, Frida hook, emulation job & Service Gateway status badges, compact `EN / 中文` switcher, global **AI Diagnose & Auto-Heal Drawer**, and an IDE-style bottom status bar.
- **14 Focused Workspaces (Zero Mega-Tabs)**:
  - **Traffic**:
    1. **Capture (`⌘1`)**: Live 4-KPI telemetry strip (`req/s` + bandwidth, total flows/bytes, active hosts + avg/P95 latency, error rate + TLS alerts), guided 4-step Android setup (`ADB Device` → `CA Certificate` → `Cap Companion Guard` → `Proxy Route`), domain scope filters, Frida server quick controls (Start/Stop/ABI/version + jump to Frida Studio), and a tabbed Activity Log / Active Hosts / TLS Alerts console.
    2. **Flows (`⌘2`)**: Multi-facet filter toolbar (`/` focus, host suggestions, method/status/content-type pills, Flat vs API Groups), horizontal/vertical draggable `SplitPane`, keyboard navigation (`↑/↓`/`j/k`, `Esc`), tabbed inspector (`Params`, `Req/Resp Headers`, `Req/Resp Body` with JSON / XML / Protobuf / Hex + inline search, `Raw`, `Timing`, `Export` to cURL/Python/Go/Java/JS/Agent JSONL), Replay & Modify-Replay, Side-by-Side Flow Diff, Sign Analysis, 1-click **Publish to Gateway** & **Site Recon** handoffs, HAR/Charles Import, native loopback **MJPEG Device Monitor** (`Fast` / `scrcpy`, live FPS & drag-swipe), and an inline **Plugins** mode (`PluginWorkbench`) for uninterrupted single-page Flow ↔ Plugin debugging.
    3. **Rules (`⌘3`)**: Split-pane intercept rules engine + live **Held Breakpoints** queue (Forward Edited / Mock / Drop 403), 6 action types, priority ordering, and regex/substring path validation.
    4. **Plugins (`⌘4`)**: Scriptable analyzer workbench & unified single-page debugger (`~/.cap/plugins/*.json` with disk hot-reload) supporting `python3`, `node`, `sh`, and `builtin` runtimes, live parsed `query_params` & flow variable inspector with click-to-insert snippets, live `stdin JSON` preview, real-time `Matches flow` indicator (supporting query strings & glob `*`), instant unsaved draft execution (`⌘Enter`), 1-click **AI Fix** on draft errors, auto-run hooks on live traffic, and a real-time Execution Log drawer.
  - **Reverse Engineering**:
    5. **Site Recon (Sidebar / `⌘K`)**: Authorized site reconnaissance & asset inventory workbench with 5 focused tabs — **Domain Intel** (pure-Go DNS records, CDN/WAF hints, WHOIS, live TLS certificate chain & SAN audit), **Site Probe** (HTTP redirect chain, 45+ tech/CDN/WAF fingerprints, `0–100` 7-header security audit, `/robots.txt` · `/sitemap.xml` · `/.well-known/*` · favicon SHA-256), **Subdomains** (`subfinder` + passive CT logs + wildcard-filtered DNS), **Ports & Nmap** (allowlisted Nmap XML wrapper + built-in pure-Go concurrent TCP/banner scanner with `/24` CIDR guardrails and live streaming console), and **Scan History** (`~/.cap/recon-history/*.json`), plus Captured Hosts quick-picker and **Ask AI** error diagnosis.
    6. **DeepTrace (`⌘5`)**: Live 8-stage cancellable trace pipeline with real-time progress events, pure-Go DEX bytecode XRefs, 3-perspective interactive SVG Call Graph, and APK/JADX caching — plus 1-click **Hook in Frida**, **Emulate in RE Lab**, and **Scan Protection** handoffs from the Executive Report, module cards, and Native `.so` findings.
    7. **Static RE (`⌘6`)**: Focused static analysis workspace with single-tier tabs for **Native / r2 · iOS** (radare2 + pure-Go ELF fallback, iOS Mach-O/IPA FairPlay `cryptid` & ObjC inspector, Unidbg iOS harness, iOS Stealth, and **IDA Pro / Ghidra / JSON Symbol Bridge**) and **JADX · Java↔JNI** (cached APK/DEX decompiler, full-text search, and static + `RegisterNatives` Java↔JNI cross-linker).
    8. **Frida (`⌘7`)**: Dedicated **Frida Studio** workbench with full `frida-server` lifecycle (ABI auto-detect, GitHub Release auto-download or local `.xz` push, stealth binary rename, custom port + `adb forward`, host vs device version-match diagnostics), zero-CGO Python Frida Bridge (with automatic `frida-cli` fallback), searchable process/app picker, `Spawn (-f)` / `Attach`, **live script hot-reload (`⌘R`)** without restarting the app, 1-click **AI Fix Script** on runtime errors, structured `send()` JSON event cards & JSONL export, 7 built-in RE templates + `~/.cap/frida-scripts/` disk hot-reload, CodeShare & app fingerprint browser, and **From Trace** auto-hook generator.
    9. **Emulate & Trace (`⌘8`)**: Dedicated algorithm emulation & dynamic trace workspace combining **Unidbg · Qiling · angr** (with **Unidbg Auto-Stub Assistant**, **Frida Env Snapshot**, **1-Click AI Fix & Bounded ≤3-Round AI Auto-Heal Loop**, live job streaming, `~/.cap/re-projects/*.json` persistence, and JDK-first / Maven-cached / per-engine Python virtualenv auto-discovery) and **ExecTrace · Taint** (multi-format instruction trace parser, forward/backward register + memory taint slicing, crypto constant detection, ASLR-normalized diff, and Tenet export).
    10. **Deobf & TLS (Sidebar / `⌘K`)**: Single-tier hardening & transport defense workspace directly exposing **Protection Audit** (13 packers, OLLVM, VMP, inline ARM64 `SVC #0`), **Stealth & Unpack Scripts**, **VMP Trace Analyzer**, and **TLS · Certs · Proxy** (APK cert/pin scan, mTLS validator, 6 JA3 profiles, Flutter/Cronet/mTLS compat Frida scripts).
    11. **Crypto & DFA (Sidebar / `⌘K`)**: Single-tier cryptographic algorithm workspace directly exposing **Codec & Cipher Pipeline** (CyberChef-style composable Base64/SM4/AES/ChaCha20/RC4/XOR + Auto-Identify), **Protobuf Wire** (schema-less AST decode & lossless re-encode), and **White-Box AES-128 DFA** (Round-9 Master Key solver + Unidbg/Qiling fault-injection harness generator).
  - **Services**:
    12. **Gateway (`⌘9`)**: Production Open API HTTP Gateway (`:9090`) turning reverse-engineered mobile endpoints into resilient REST APIs — featuring 1-click Flow-to-Service route publishing, live Route Tester, API Key auth, per-route rate limiting, **Per-Route TTL Cache**, **Circuit Breaker**, **6 TLS/HTTP2 Fingerprint Profiles + JA3 + mTLS validation**, OpenAPI 3.0.3 export, **Proxy IP Pool**, **Device Pool** (virtual presets + ADB sync), **Multi-Account / Session Pool** with singleflight 401/403 auto-refresh, **Managed Signer Worker Pools** (`1..8` instances with health probes & auto-restart), **Pluggable Signer Providers** (with 1-click **AI Fix** on signer test errors), **Prometheus `/metrics/prometheus`** telemetry drawer, **Docker / Compose** headless deployment export, and real-time Invocation Logs.
  - **System**:
    13. **Terminal (`⌘0`)**: Multi-tab embedded PTY console (`⌘T` / `⌘W` / `Ctrl+Tab` / `Ctrl+L`) with quick diagnostic presets for `adb`, `frida`, and `curl`.
    14. **Settings (`⌘,`)**: Sectioned preferences for Appearance & Display Language (`English` / `简体中文`), Proxy & Certs, Android / Frida Runtime Paths, RE Toolchain (`r2`, `java`, `mvn`, `unidbg`, `python3`, dedicated `qiling` / `angr` Python virtualenvs, `qiling rootfs`), **Site Recon Toolchain (`nmap`, `subfinder`, `whois`, `dig`)** & Default Gateway Address, **AI Assistant** (multi-provider presets, `0600` local API key store, secret redaction & auto-heal guardrails), Export & Storage, Shortcuts, and About & Diagnostics.

| Shortcut | Workspace | Group |
|----------|-----------|-------|
| `⌘1` / `⌘2` / `⌘3` / `⌘4` | Capture · Flows · Rules · Plugins | Traffic |
| `⌘5` / `⌘6` / `⌘7` / `⌘8` | DeepTrace · Static RE · Frida · Emulate & Trace | Reverse Engineering |
| Sidebar / `⌘K` | Site Recon · Deobf & TLS · Crypto & DFA | Reverse Engineering |
| `⌘9` | Gateway | Services |
| `⌘0` / `⌘,` | Terminal · Settings | System |
| `⌘K` / `⌘B` | Command Palette · Toggle Sidebar Rail | Shell |

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

### Frida Dynamic Instrumentation Studio (`cap frida` & GUI `⌘7`)

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

### Static RE & Algorithm Emulation (`cap re` & GUI `⌘6` / `⌘8`)

Full native `.so`/ELF/Mach-O reverse-engineering and algorithm emulation pipeline without leaving `cap`:

```bash
cap re status                                              # Probe r2, JDK/Maven/Unidbg, independent Qiling/angr venvs
cap re run -e unidbg -f ./SignerHarness.java --apk app.apk # Run Unidbg/Qiling/angr/r2 job directly from CLI
cap re analyze ./libsign.so --func Java_com_app_sign       # Static ELF/r2 analysis + disassembly/pseudo-C/xrefs
cap re r2 ./libsign.so "iI;iEj"                            # Sanitized read-only radare2 command execution
cap re gen -e unidbg --apk app.apk --so libsign.so \
  --class com/app/Signer --method sign --http-server       # Synthesize Unidbg harness (with optional HTTP signer mode)
```

- **Host Toolchain Auto-Discovery & Caching**: Automatically co-matches `java` + `javac` + `JAVA_HOME` (JDK-first discovery across Homebrew/JVM paths), caches resolved Unidbg Maven classpaths (with offline `~/.m2` repository fallback for fast repeat launches), and resolves independent Python virtualenvs for `qiling` (`--qiling-python`) and `angr` (`--angr-python`) so conflicting dependencies never collide.
- **radare2 + Pure-Go ELF Fallback**: Extracts architecture, mitigations (`PIE`, `NX`, `Canary`, `RELRO`), functions, dynamic exports/imports, strings, xrefs, disassembly, and pseudo-C (`pdg`/`pdc`), falling back seamlessly to a pure-Go `debug/elf` analyzer when `r2` is absent.
- **Unidbg · Qiling · angr Emulation & Symbolic Execution**: Ships curated starter templates, parameterized harness generators, and `cap re run` CLI/GUI job execution with live cancellable streaming and `~/.cap/re-projects/*.json` persistence.
- **DeepTrace → RE Lab Closed Loop**: Click **Emulate in RE Lab** from any DeepTrace report or Native `.so` finding to synthesize a tailored Unidbg/Qiling/angr harness pre-filled with APK, `.so`, JNI symbols, and captured request inputs.

### RE Pro Suite — Auto-Stub, JADX↔JNI, Symbol Bridge & iOS (`cap repro` & GUI `⌘6` / `⌘8`)

Commercial-grade productivity extensions for Android & iOS native reverse engineering:

```bash
cap repro autostub --file ./unidbg.log -o AutoStubs.java   # Diagnose Unidbg logs → Java AbstractJni/IOResolver/SysProp stubs
cap repro env-snapshot --pkg com.acme.app -o snapshot.js   # Generate Frida Android runtime env snapshot for Unidbg
cap repro jadx ./target.apk --link-so ./libsign.so --json  # Decompile APK/DEX workspace & cross-link Java <-> JNI symbols
cap repro symbols --in ./symbols.json -f ida -o apply.py   # Export SymbolBundle to IDAPython, Ghidra Python, or JSON
cap repro ios ./Target.ipa --json                          # Static Mach-O / Fat Mach-O / IPA inspector & FairPlay audit
cap repro ios-harness --binary ./Target --objc-class Signer --objc-selector sign:
cap repro ios-stealth --bundle-id com.acme.ios -o ios_stealth.js
```

- **Unidbg Auto-Stub Assistant & Frida Env Snapshot**: Parses Unidbg runtime exceptions for missing JNI callbacks, classes, files, system properties, and libraries, synthesizing paste-ready Java `AbstractJni` / `IOResolver` / `SystemPropertyHook` stubs alongside a Frida environment snapshot collector.
- **JADX Decompiler & Java↔JNI Cross-Linker**: Caches decompiled APK/DEX workspaces (`~/.cap/jadx-cache`), supports fast class listing, source viewing, case-insensitive full-text search, and automated static + Frida `RegisterNatives` dynamic Java↔JNI native symbol resolution.
- **IDA Pro / Ghidra / JSON Symbol Bridge**: Imports/validates `SymbolBundle` JSON annotations (function names, comments, struct tags) and exports deterministic IDAPython or Ghidra Python scripts.
- **iOS Mach-O / IPA Static Inspector & Harnesses**: Pure-Go parser for thin/universal Mach-O and `.ipa` archives covering `Info.plist`/ATS audit, FairPlay encryption (`cryptid`), PIE/NX/ARC/Canary mitigations, linked dylibs/frameworks, Objective-C classes & selectors, plus Unidbg `DarwinEmulatorBuilder` iOS harness and Frida iOS stealth generators.

### CryptoLab & White-Box AES-128 DFA (`cap crypto` & GUI Crypto & DFA)

Built-in CyberChef-style cryptographic workbench, schema-less Protobuf inspector, and White-Box AES-128 Round-9 Differential Fault Analysis (DFA) solver:

```bash
cap crypto ops --json                                      # List all composable codec, hash, cipher & protobuf operations
cap crypto identify "SGVsbG8gV29ybGQ=" --json              # Auto-detect encoding, magic bytes, JWT claims, entropy & recipes
cap crypto run --op sm4_encrypt -p mode=ecb -p key=<32-hex> -i "hello" --output-format hex
cap crypto protobuf --decode "08 96 01 12 05 68 65 6c 6c 6f"
cap crypto dfa --valid <32-hex> --fault-file ./faults.txt --plaintext <32-hex>
cap crypto dfa-script -e unidbg --binary ./libwb.so --hook-addr 0x12a40 -o WhiteboxDFA.java
```

- **Composable Crypto/Codec Pipeline**: Chains Base64 (including custom 64-char alphabets), Base32, Hex, URL, Gzip/Zlib/Deflate, XOR & single-byte XOR bruteforce, custom-IV MD5/SHA-256, HMAC, and pure-Go **SM4**, **AES** (ECB/CBC/CTR/GCM), **ChaCha20**, and **RC4** with step-by-step intermediate inspection and automatic payload identification.
- **Schema-less Protobuf Wire Inspector**: Decodes raw hex/Base64 Protobuf wire payloads into an editable nested AST without `.proto` definitions and losslessly re-encodes modified fields back to hex/Base64.
- **White-Box AES-128 Round-9 DFA Solver**: Recovers the Round-10 subkey and inverted AES-128 Master Key directly from Round-9 single-byte faulty ciphertexts (with optional plaintext verification), and generates Unidbg (Java) or Qiling (Python) fault-injection scripts.

### Modern TLS / mTLS & Proxy Compatibility Diagnostics (`cap tls` & GUI Deobf & TLS / `⌘9`)

Pure-Go TLS fingerprint profiling, APK certificate auditing, mTLS validation, and local-proxy compatibility templates:

```bash
cap tls profiles                                           # List 6 curated TLS/HTTP2 profiles + JA3 hashes
cap tls ja3 chrome_131 --json                              # Compute deterministic JA3 fingerprint summary
cap tls scan-apk ./target.apk --json                       # Scan APK for X.509 certs, BKS/JKS/PKCS12 keystores & pins
cap tls validate-mtls --cert ./client.pem --key ./client.key
cap tls flutter --offset 0x5a1230 --proxy 127.0.0.1:8080 -o flutter_debug.js
cap tls cronet --pkg com.acme.app -o cronet_h2.js          # Cronet QUIC→HTTP/2 & OkHttp local-proxy compat script
cap tls mtls-observer --pkg com.acme.app -o mtls_obs.js    # Read-only KeyStore/SSLContext metadata observer
cap tls curl-impersonate --json                            # Detect host curl-impersonate binaries on PATH
```

- **6 Curated TLS / HTTP2 Fingerprint Profiles**: `go_default`, `chrome_131`, `safari_17`, `firefox_132`, `okhttp_android`, and `ios_cfnetwork` with deterministic JA3 hashes, `curl-impersonate` host discovery, and direct integration into Service Gateway routes.
- **APK Certificate / Pin Scanner & mTLS Validator**: Scans APKs (including binary AXML & plain `network_security_config.xml`) for embedded PEM/DER certificates, keystores, and public-key pins, and validates PEM client cert/key pairs (key match, chain length, ClientAuth EKU, expiry).
- **Local-Proxy Diagnostic Templates**: Generates sanitized Frida scripts for Flutter local-proxy debugging, Cronet QUIC-to-HTTP/2 fallback, and strictly read-only mTLS KeyStore/SSLContext observation.

### Anti-Obfuscation, Anti-Debug & VMP Analysis (`cap deobf` & GUI Deobf & TLS)

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

### Execution Trace & Taint Analysis (`cap exectrace` & GUI `⌘8`)

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

### Service Gateway & Integration Hub (`cap gateway` & GUI `⌘9`)

Turn reverse-engineered mobile APIs into production-grade, observable, authenticated HTTP endpoints backed by proxy, device, account, and supervised signer worker pools:

```bash
cap gateway publish --flow f1 --slug search-feed           # Publish a captured flow as an Open API route
cap gateway proxies --add socks5://user:pass@1.2.3.4:1080 --check
cap gateway devices --from-preset pixel-8-pro              # Create virtual fingerprint (or --sync-adb)
cap gateway accounts --add "VIP-1" --token "tok_abc" --tags vip
cap gateway workers --add "Unidbg-Pool" --kind unidbg_http --cmd java --base-port 18900 --instances 4
cap gateway signers --test <signerID> --url https://api.example.com/v1/feed
cap gateway circuits --reset search-feed --clear-cache all
cap gateway serve -a 0.0.0.0:9090 --require-auth --api-key sk-live-demo
cap gateway prometheus -o metrics.prom                     # Export Prometheus exposition metrics
cap gateway export-docker -a 0.0.0.0:9090 -o ./deploy      # Generate Dockerfile + docker-compose.yml
cap gateway openapi -o openapi.json                        # Export OpenAPI 3.0.3 spec
```

- **Open API HTTP Gateway (`:9090`) & Headless `serve` Mode**: Publishes captured flows into reusable `POST /gw/<slug>` routes with template substitution (`{{input.*}}`, `{{device.*}}`, `{{account.*}}`, `{{timestamp}}`, `{{nonce}}`), API Key auth (`X-API-Key` / `Bearer`), per-route rate limiting, retries/failover, raw passthrough, **Per-Route TTL Cache** (LRU + `X-Cap-No-Cache` bypass), **Circuit Breaker** (closed/open/half-open fast-fail & manual reset), per-route **TLS/HTTP2 Fingerprint Profiles + mTLS**, **Prometheus `/metrics/prometheus`** telemetry, **OpenAPI 3.0.3** export, and headless **`cap gateway serve`** (`CAP_GW_LISTEN_ADDR` + auto-started Managed Workers) with **Dockerfile & `docker-compose.yml` export**.
- **Multi-Account / Session Pool & Singleflight Auto-Refresh**: Manages multi-account tokens, cookies, tags, sticky-device bindings, and `round_robin` / `least_used` / `sticky_device` policies, with singleflight 401/403/body-match auto-refresh (recursion-guarded) and challenge webhook notifications.
- **Managed Signer Worker Pools (`1..8` Instances)**: Supervises local `unidbg_http`, `qiling_http`, `script_http`, or `custom` signer processes across sequential loopback ports with periodic `/health` probing, round-robin load balancing, stderr tail capture, auto-restart backoff, and clean process-group teardown.
- **Proxy IP Pool, Device Pool & Pluggable Signers**: Manages `HTTP`/`HTTPS`/`SOCKS5` proxies (bulk import, dynamic provider fetch, health/latency checks, rotation/sticky-device), realistic Android fingerprint presets + ADB sync, and pluggable **Built-in HMAC/Hash**, **Local Script**, **External HTTP**, **Unidbg HTTP / Managed Worker**, and **Frida RPC** signers.

### Site Recon & Nmap Port Scanner (`cap recon` & GUI Site Recon)

Authorized site reconnaissance, asset discovery, security header auditing, live TLS inspection, subdomain enumeration, and allowlisted Nmap / pure-Go TCP port scanning:

```bash
cap recon status --json                                    # Check host nmap, subfinder, whois & dig readiness
cap recon domain example.com                               # DNS (A/AAAA/CNAME/MX/NS/TXT/PTR), CDN/WAF, WHOIS & TLS
cap recon site https://example.com --json                  # HTTP redirect chain, 45+ tech fingerprints, 0-100 header audit & discovery
cap recon tls example.com --port 443                       # Live TLS handshake, cipher suite, SANs & X.509 cert chain
cap recon subdomains example.com --no-subfinder            # Passive CT logs + subfinder + wildcard-guarded common DNS
cap recon ports 127.0.0.1 --engine auto --preset web       # Allowlisted Nmap XML or built-in concurrent Go TCP/banner scan
cap recon history --json                                   # List, inspect, or clear persisted ~/.cap/recon-history scans
```

- **Domain Intelligence & Live TLS Inspector**: Pure-Go DNS record enumeration, CDN/WAF infrastructure heuristics, direct-exec bounded WHOIS lookups, and live TLS certificate verification (enforcing hostname & IP SAN checks, cipher suite, expiry warnings, and chain inspection).
- **Site Fingerprinting & Security Header Audit**: Probes HTTP/HTTPS redirect chains (capped at 10 hops) with 1 MiB bounded reads, detects 45+ web server/framework/CDN/WAF fingerprints, scores 7 security headers (`0–100`), and inspects `/robots.txt`, `/sitemap.xml`, `/.well-known/*`, and `/favicon.ico` SHA-256 hashes.
- **Subdomain Discovery & Allowlisted Nmap / Pure-Go Port Scanner**: Combines `subfinder`, passive CT logs, and wildcard-filtered common DNS resolution; validates scan targets strictly (rejecting flag injection, shell metacharacters, IPv6 CIDRs, and IPv4 CIDRs wider than `/24` or >4096 ports) with allowlisted Nmap XML output (`-sT -T4`) and automatic pure-Go TCP/banner fallback, plus 1-click **Flows → Site Recon** handoff.

### Multi-Model AI Provider & Self-Healing Auto-Fix Closed Loop (`cap ai` & GUI AI Assistant)

Plug-in cloud or local LLM assistant engineered for mobile reverse engineering, script debugging, and bounded self-healing repair loops with client-side secret redaction:

```bash
cap ai status                                              # Inspect active AI profile, auto-heal guardrails & redaction state
cap ai presets --json                                      # List built-in OpenAI, Anthropic, Gemini, DeepSeek, Qwen & Ollama presets
cap ai profiles --add --provider deepseek --api-key-env DEEPSEEK_API_KEY
cap ai profiles --add "Local Ollama" --provider ollama --model qwen2.5-coder:14b
cap ai test                                                # Probe connectivity & measure model latency
cap ai diagnose --scope qiling --file ./emulate.py --log-file ./run.log
cap ai fix --scope frida --file ./hook.js --error "has more than one overload" --apply
```

- **4 Native Protocols & Isolated `0600` Credential Store**: Zero-dependency `net/http` clients for **OpenAI-compatible** (OpenAI, DeepSeek, Qwen/DashScope, OpenRouter, custom), **Anthropic Claude**, **Google Gemini**, and **local Ollama**; keys are stored locally in `~/.cap/ai.json` (`0600`) and never echoed back in plaintext to the frontend.
- **Deterministic Pre-Diagnosis & Client-Side Secret Redaction**: Redacts Bearer/Basic tokens, API keys (`sk-`/`AIza`/`ghp_`/`AKIA`), cookies, PEM private keys, and proxy credentials *before* compressing head/tail logs (`≤24 KiB`), while enriching prompts with local deterministic pre-diagnosis (`repro.AnalyzeUnidbgLog` + Frida/Qiling/toolchain hints).
- **Validated Diffs & Bounded Auto-Heal Loop (`1..5` Rounds)**: Verifies every proposed patch for destructive commands and syntax (`node --check`, `python3 -m py_compile`, Java structural checks), renders pure-Svelte Unified Diffs with 1-click **Apply**, **Apply & Re-Run**, and per-scope **Undo**, and executes bounded **Run → Diagnose → Validate → Patch → Re-Run** loops in **Emulate & Trace** (with repeated-error circuit breaking, unchanged-code detection, live `ai:heal` timeline streaming, and instant cancellation) plus 1-click **AI Fix** across **Frida**, **Plugins**, **Gateway Signers**, and **Site Recon**.

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
| `cap re status [--r2\|--java\|--mvn\|--unidbg-dir\|--python\|--qiling-python\|--angr-python\|--rootfs] [--json]` | Probe host RE toolchain (`r2`, JDK/Maven/Unidbg, independent Qiling/angr venvs) |
| `cap re run [-e unidbg\|qiling\|angr\|radare2] (-f <file>\|-p <id>) [--binary\|--apk\|--rootfs] [--timeout n] [--arg a] [--json]` | Execute a Unidbg, Qiling, angr, or radare2 harness with live output & `[CAP_RE]` results |
| `cap re analyze <file> [--r2 path] [--func <name\|addr>] [--json]` | Static ELF/Mach-O analysis & function disassembly/pseudo-C/xrefs |
| `cap re r2 <file> <cmd> [--r2 path] [--json]` | Run a sanitized read-only radare2 command on a binary |
| `cap re projects [-e engine] [--show <id>] [--json]` | List built-in & saved RE projects or print harness source |
| `cap re gen -e <unidbg\|qiling\|angr\|radare2> [--apk\|--so\|--binary\|--http-server] [-o file]` | Synthesize an emulation, symbolic execution, or r2 harness |
| `cap repro autostub [file] [-f <log>\|--stdin] [-o stub.java] [--json]` | Diagnose Unidbg logs & generate Java `AbstractJni`/`IOResolver`/SysProp stubs |
| `cap repro env-snapshot [--pkg <pkg>] [-o snapshot.js] [--json]` | Generate Frida Android runtime environment snapshot script for Unidbg |
| `cap repro jadx [apk] [--detect\|--filter q\|--search q\|--class c\|--link-so .so\|--register-natives json] [--json]` | Decompile APK/DEX workspace, search/read Java classes & cross-link Java↔JNI |
| `cap repro symbols --in <bundle.json\|-> [-f ida\|ghidra\|json] [-o file]` | Validate & export `SymbolBundle` JSON to IDAPython, Ghidra Python, or JSON |
| `cap repro ios <macho-or-ipa> [--json]` | Static Mach-O / Universal Fat Mach-O / `.ipa` inspection & FairPlay audit |
| `cap repro ios-harness [--binary\|--ipa] [--bundle-id id] [--symbol\|--objc-class --objc-selector\|--offset] [-o file]` | Generate Unidbg `DarwinEmulatorBuilder` iOS Java emulation harness |
| `cap repro ios-stealth [--bundle-id id] [--binary name] [--ptrace\|--sysctl\|--getppid\|--dyld\|--jailbreak] [-o file]` | Generate Frida iOS anti-debug & jailbreak-check diagnostic script |
| `cap crypto ops [--category codec\|compression\|xor\|hash\|hmac\|cipher\|protobuf] [--json]` | List composable CryptoLab pipeline operations & parameters |
| `cap crypto identify [input\|-] [-f file] [--json]` | Auto-identify payload encodings, magic bytes, JWT claims, entropy & recipes |
| `cap crypto run (--op <name> [-p k=v]\|--pipeline-json <json\|file>) (-i <in>\|-f <file>) [--input-format\|--output-format] [--json]` | Execute single operation or multi-step CryptoLab pipeline |
| `cap crypto protobuf (--decode <hex\|b64\|->\|--encode-json <json\|file\|->) [--json]` | Schema-less Protobuf wire decoder and lossless JSON AST re-encoder |
| `cap crypto dfa --valid <hex> (--fault <hex>\|--fault-file <file>) [--plaintext <hex>] [--json]` | Recover AES-128 Round-10 subkey & Master Key via Round-9 DFA |
| `cap crypto dfa-script [-e unidbg\|qiling] [--binary path] [--apk path] [--hook-addr hex] [--reg r\|--state-addr hex] [--xor 0x01] [-o file]` | Generate Unidbg (Java) or Qiling (Python) Round-9 DFA fault-injection script |
| `cap tls profiles [--json]` | List 6 curated TLS / HTTP2 client fingerprint profiles & JA3 hashes |
| `cap tls ja3 [profile] [--json]` | Compute deterministic JA3 fingerprint summary for a TLS profile |
| `cap tls scan-apk <apk> [--json]` | Pure-Go APK scan for X.509 certs, keystores & `network_security_config` pins |
| `cap tls validate-mtls --cert <pem> --key <key> [--json]` | Validate PEM client certificate & private key pair for mutual TLS |
| `cap tls flutter [--offset hex] [--proxy host:port] [--platform android\|ios] [--pkg id] [-o file]` | Generate local-proxy Flutter diagnostic Frida script |
| `cap tls cronet [--pkg id] [--disable-quic] [--okhttp] [--log-alt-svc] [--proxy-hint addr] [-o file]` | Generate Cronet QUIC→HTTP/2 & OkHttp local-proxy compat Frida script |
| `cap tls mtls-observer [--pkg id] [--keystore\|--keymanager\|--sslcontext\|--certs] [-o file]` | Generate read-only mTLS KeyStore/SSLContext observer Frida script |
| `cap tls curl-impersonate [--json]` | Detect optional `curl-impersonate` binaries installed on `PATH` |
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
| `cap gateway serve [-a 0.0.0.0:9090] [--require-auth] [--api-key <k>] [--start-workers]` | Run headless production Gateway server (`CAP_GW_LISTEN_ADDR` + Managed Workers) |
| `cap gateway status [--json]` | Inspect gateway listener status, routes, cache/circuits & pool counts |
| `cap gateway publish --flow <id> [--slug <slug>] [--name <name>]` | Publish a captured flow as an Open API Gateway route |
| `cap gateway routes [--test <slug> --input k=v] [--body s] [--raw] [--delete <id>] [--json]` | List, test-invoke, or delete published service routes |
| `cap gateway proxies [--add <url>\|--import <file>\|--fetch <url>\|--check]` | Manage Proxy IP Pool (HTTP/HTTPS/SOCKS5, dynamic fetch, health check) |
| `cap gateway devices [--presets\|--from-preset <id>\|--sync-adb]` | Manage virtual Android device fingerprints & ADB device sync |
| `cap gateway signers [--test <id> --url <url>] [--delete <id>] [--json]` | List, test, or delete pluggable Signer Providers |
| `cap gateway accounts [--add <name> --token <t> --cookie <c>\|--strategy <s>\|--mark-healthy <id>\|--delete <id>] [--json]` | Manage multi-account / session pool & rotation strategy |
| `cap gateway workers [--add <name> --kind <k> --cmd <bin> --base-port <p> --instances <1..8>\|--start\|--stop\|--restart\|--status\|--delete <id>] [--json]` | Manage supervised local Signer Worker Process Pools |
| `cap gateway circuits [--reset <slug\|all>] [--clear-cache <slug\|all>] [--json]` | Inspect/reset per-route circuit breakers & clear route TTL caches |
| `cap gateway prometheus [-o metrics.prom]` | Export live gateway telemetry in Prometheus text exposition format |
| `cap gateway export-docker [-a 0.0.0.0:9090] [-o ./deploy] [--json]` | Export production `Dockerfile` & `docker-compose.yml` for `cap gateway serve` |
| `cap gateway openapi [-o openapi.json]` | Export OpenAPI 3.0.3 JSON specification for enabled routes |
| `cap recon status [--nmap\|--subfinder\|--whois\|--dig] [--json]` | Inspect host recon toolchain readiness (`nmap`, `subfinder`, `whois`, `dig`) |
| `cap recon domain <target> [--json]` | Resolve DNS records, CDN/WAF hints, WHOIS metadata & live TLS |
| `cap recon site <url> [--no-discovery] [--no-redirects] [--insecure] [--json]` | Fingerprint HTTP stack, score security headers (`0–100`) & probe discovery paths |
| `cap recon tls <host> [--port 443] [--json]` | Inspect live TLS handshake, cipher suite, SANs & X.509 cert chain |
| `cap recon subdomains <domain> [--no-subfinder] [--no-ct] [--no-common] [--json]` | Discover subdomains via CT logs, `subfinder` & wildcard-guarded common DNS |
| `cap recon ports <target> [--engine auto\|nmap\|native] [--preset quick\|top100\|web\|service\|custom] [--ports spec] [-sV] [--json]` | Run authorized TCP/Nmap port & service scan with CIDR/port guardrails |
| `cap recon history [--show <id>\|--delete <id>\|--clear] [--json]` | List, inspect, delete, or clear persisted `~/.cap/recon-history` scans |
| `cap ai status [--json]` | Show active AI profile, auto-heal settings & masked profile summary |
| `cap ai presets [--json]` | List built-in cloud & local LLM provider presets |
| `cap ai profiles [--add [name] --provider p --model m --api-key-env ENV\|--activate id\|--delete id] [--json]` | Manage multi-model AI profiles stored in `~/.cap/ai.json` (`0600`) |
| `cap ai test [--profile <id>] [--json]` | Probe connectivity & latency against active or specified AI profile |
| `cap ai diagnose --scope <s> [--file path] [--error msg] [--log-file path] [--json]` | Run secret-redacted pre-diagnosis & AI root-cause analysis |
| `cap ai fix --scope <s> --file <path> [--error msg] [--log-file path] [--apply] [--json]` | Synthesize validated patch, print unified diff & optionally apply safely |

**Global Flag**: `--lang en|zh` (auto-detected from `CAP_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG`).

---

## Project Structure

```text
android-companion/      Pure-SDK Android Companion Guard APK source & offline build.sh
cmd/cap/                Main entrypoint & embedded frontend/dist assets
frontend/
├── src/App.svelte      Workbench shell (collapsible nav rail, topbar, status bar, ⌘K)
├── src/components/     Icon, Badge, Button, SplitPane, CommandPalette, ToastHost, Kbd, EmptyState, AIHealDrawer, AISettingsPanel
├── src/lib/            tokens.css, theme.js (4 themes), i18n.js, {frida,reLab,gateway,recon,ai}State.js, locales/{common,core,frida,reLab,gateway,recon,ai,tools}.js
└── src/pages/          Capture, Flows, Rules, Recon, DeepTrace, Frida, RELab, Plugins, Gateway, Terminal, Settings
internal/
├── ai/                 Multi-model AI clients (OpenAI/Claude/Gemini/Ollama), 0600 store, secret redaction, validator, LCS diff & bounded auto-heal loop
├── android/            ADB helpers, 3-strategy cert install/verify, companion.go, bin/cap-companion.apk
├── buildinfo/          Version injection metadata
├── capture/            WebSocket frame parser, SSE stream parser (experimental)
├── cli/                Cobra commands (start, tui, gui, flows, export, android, frida, unpin, re, repro, crypto, tls, deobf, exectrace, gateway, recon, ai)
├── compare/            Side-by-side flow comparison with structured diff
├── config/             Shared path defaults (~/.cap)
├── context/            jadx scanner, Retrofit/OkHttp parser, URL-to-source mapper
├── cryptolab/          CyberChef-style codec/cipher pipeline (SM4/AES/ChaCha20/RC4), schema-less Protobuf AST & AES-128 Round-9 DFA solver
├── deobf/              APK/ELF protection scanner (13 packers, OLLVM, VMP, inline SVC), stealth/unpack/deobf generators & VMP analyzer
├── exectrace/          Multi-format execution trace parser, forward/backward taint slicer, crypto/loop detector, ASLR diff & Tenet export
├── export/             codegen/ (5 languages) & agent/ (compact JSONL)
├── frida/              Frida toolchain probe, server deploy/lifecycle, Python Bridge, script store & Trace→Hook codegen
├── gateway/            Open API HTTP gateway, Proxy/Device/Account pools, singleflight refresh, Managed Workers, TTL cache, circuit breaker, Prometheus & Docker export
├── grouping/           API auto-grouping by host + path prefix
├── i18n/               Zero-dependency EN / zh-CN localization catalog for TUI & CLI
├── importer/           HAR and Charles proxy XML import
├── plugin/             Built-in analyzer plugin engine (experimental)
├── proto/              Schema-less protobuf wire format decoder
├── proxy/              goproxy MITM core, ECDSA CA cert gen, stream capture
├── recon/              Site reconnaissance engine (DNS/WHOIS/TLS, HTTP tech & header audit, subdomains, allowlisted Nmap + pure-Go TCP scanner & history)
├── replay/             HTTP replay, request modification, response diff
├── repro/              RE Pro extensions: Unidbg Auto-Stub, Frida Env Snapshot, JADX↔JNI Cross-Linker, IDA/Ghidra Symbol Bridge & iOS Mach-O/IPA
├── retools/            Native RE & emulation engine (JDK-first/Maven-cached Unidbg, per-engine Python venvs for Qiling/angr, r2 + pure-Go ELF & job runner)
├── rules/              Intercept rules, mocks, and held breakpoints persistence & engine
├── screen/             Android device screen mirror (screencap + scrcpy)
├── sequence/           Request sequence record/replay with variable propagation
├── sign/               Signature parameter detection, heuristics, brute-force verification
├── stats/              Traffic telemetry (P95 latency, error rate, timeline)
├── store/sqlite/       SQLite WAL persistence, filtering, JSON codec
├── terminal/           Multi-tab PTY backend for GUI Terminal
├── tlskit/             Curated TLS/HTTP2 profiles + JA3, APK cert/pin scanner, mTLS validator, curl-impersonate probe & Flutter/Cronet compat scripts
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
