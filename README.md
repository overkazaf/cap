# cap

<p align="center">
  <strong>MITM proxy built for reverse engineering</strong><br>
  LLM-ready output · multi-language codegen · sign algorithm inference · native desktop GUI
</p>

<p align="center">
  <a href="README_CN.md">中文文档</a> ·
  <a href="https://overkazaf.github.io/cap/">Documentation</a> ·
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick Start</a>
</p>

---

<p align="center">
  <img src="docs/screenshots/capture-tab.png" alt="cap GUI" width="800">
</p>

## Why cap?

Existing tools (Burp Suite, mitmproxy, HTTP Toolkit) are built for web security testing — not for **reverse engineering mobile apps**. Cap fills the gap:

| Capability | Burp Suite | mitmproxy | HTTP Toolkit | **cap** |
|------------|:----------:|:---------:|:------------:|:-------:|
| CLI-first automation | ✗ GUI only | ✓ mitmdump | ✗ GUI only | **✓** |
| Native desktop GUI | ✗ Java/Swing | △ mitmweb (basic) | ✓ Electron | **✓ Wails (native)** |
| LLM/Agent-ready output | ✗ XML/HAR | △ HAR (verbose) | △ HAR | **✓ compact JSONL** |
| Multi-language codegen | ✗ | △ curl + Python | ✗ | **✓ 5 languages** |
| Sign param auto-detect | ✗ | ✗ | ✗ | **✓** |
| Sign algorithm inference | ✗ | ✗ | ✗ | **✓ MD5/SHA/HMAC** |
| Static analysis mapping | ✗ | ✗ | ✗ | **✓ jadx → URL** |
| One-cmd Android setup | ✗ | ✗ | △ app-based | **✓ ADB direct** |
| Cert inject (Android 10+) | ✗ manual | ✗ manual | ✓ | **✓ mount --bind + Magisk** |
| WebSocket capture | ✓ | ✓ | ✓ | **✓** |
| SSE stream capture | ✗ | △ | ✗ | **✓** |
| Request replay + diff | ✓ Repeater | ✗ | ✗ | **✓** |
| Embedded terminal | ✗ | ✗ | ✗ | **✓ multi-tab PTY** |
| API auto-grouping | ✗ | ✗ | ✗ | **✓ host + path prefix** |
| Flow comparison | ✗ | ✗ | ✗ | **✓ side-by-side diff** |
| Sequence replay | ✗ | ✗ | ✗ | **✓ token propagation** |
| Protobuf decode | ✗ addon | △ addon | ✗ | **✓ schema-less** |
| Traffic dashboard | ✗ | ✗ | ✗ | **✓ P95/timeline/errors** |
| HAR/Charles import | ✓ | ✓ | ✓ | **✓** |
| Plugin system | ✓ BApp | ✓ addon | ✗ | **✓ live editor** |
| Single binary | ✗ JVM | ✗ Python | ✗ Electron | **✓ Go** |
| Open source | ✗ ($449/yr) | ✓ | △ core only | **✓ MIT** |

## Architecture

### System Overview

```mermaid
flowchart TB
    subgraph Client["Client Layer"]
        CLI["cap CLI<br/>(cobra)"]
        GUI["cap GUI<br/>(Wails native)"]
        TTY["Embedded Terminal<br/>(PTY)"]
    end

    subgraph Core["Core Engine"]
        PROXY["MITM Proxy<br/>(goproxy)"]
        STORE["Flow Store<br/>(SQLite WAL)"]
        REPLAY["Request Replay<br/>+ Diff Engine"]
    end

    subgraph Analysis["Analysis Layer"]
        SIGN["Sign Inference<br/>(MD5/SHA/HMAC)"]
        CONTEXT["Source Mapper<br/>(jadx scanner)"]
        DETECT["Param Detector<br/>(sign/ts/nonce)"]
    end

    subgraph Export["Export Layer"]
        CODEGEN["Code Generator<br/>(curl/py/go/java/js)"]
        AGENT["Agent Exporter<br/>(compact JSONL)"]
    end

    subgraph Capture["Capture Layer"]
        WS["WebSocket<br/>Frame Parser"]
        SSE["SSE Stream<br/>Parser"]
    end

    subgraph Device["Device Layer"]
        ADB["Android ADB<br/>(proxy + cert)"]
    end

    CLI --> PROXY
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
    CONTEXT --> STORE
    DETECT --> STORE
    ADB --> PROXY

    style Client fill:#2d5aa0,color:#fff
    style Core fill:#1a6b3c,color:#fff
    style Analysis fill:#8b5e3c,color:#fff
    style Export fill:#6b3a8a,color:#fff
    style Capture fill:#8a3a3a,color:#fff
    style Device fill:#3a6b8a,color:#fff
```

### Data Flow

```mermaid
sequenceDiagram
    participant Phone as Android Device
    participant Proxy as cap Proxy
    participant Store as SQLite
    participant Detect as Param Detector
    participant Sign as Sign Inference
    participant Export as Exporter

    Phone->>Proxy: HTTP/HTTPS request
    Proxy->>Proxy: MITM intercept
    Proxy->>Store: Save Flow
    Proxy->>Phone: Forward to server
    Phone-->>Proxy: Response
    Proxy-->>Store: Update Flow (response)
    Proxy-->>Phone: Forward response

    Store->>Detect: Analyze params
    Detect-->>Store: Tag sign_params

    Store->>Sign: Analyze sign values
    Sign-->>Store: Algorithm guess

    Store->>Export: cap export
    Export-->>Export: cURL / Python / JSONL
```

### Module Dependency

```mermaid
flowchart LR
    types["types<br/>Flow, WSFrame, SSEEvent"]
    store["store<br/>Store interface"]
    sqlite["store/sqlite<br/>SQLite impl"]
    proxy["proxy<br/>MITM core"]
    android["android<br/>ADB setup"]
    context["context<br/>jadx mapper"]
    codegen["export/codegen<br/>5 languages"]
    agent["export/agent<br/>JSONL"]
    sign["sign<br/>inference"]
    replay["replay<br/>replay + diff"]
    capture["capture<br/>WS + SSE"]
    cli["cli<br/>cobra commands"]
    gui["gui<br/>Wails desktop"]

    sqlite --> store --> types
    proxy --> types
    android -.-> proxy
    context --> types
    codegen --> types
    agent --> types
    sign --> types
    replay --> types
    capture --> types
    cli --> proxy & sqlite & codegen & agent & android & context
    gui --> proxy & sqlite & codegen & agent & android & sign & replay

    style types fill:#e8b4b8
    style cli fill:#b4cce8
    style gui fill:#b4cce8
```

## Features

### MITM Proxy
- HTTP and HTTPS interception with auto-generated ECDSA CA certificate
- Flow capture: method, URL, headers, body, status, latency
- Noise header stripping (Accept-Encoding, Connection, etc.)
- SQLite persistence with WAL mode for concurrent reads

### Android Integration
Three-strategy CA cert installation for modern Android:
1. **mount --bind** (Android 10+, instant, non-persistent) — HTTP Toolkit approach
2. **Magisk module** (persistent, requires reboot)
3. **Legacy /system remount** (Android 9 and below)

### Multi-Language Code Generation
```bash
cap export --flow f1 --lang curl       # cURL command
cap export --flow f1 --lang python     # requests library
cap export --flow f1 --lang go         # net/http
cap export --flow f1 --lang java       # OkHttp3
cap export --flow f1 --lang js         # fetch API
```

### LLM-Ready Output
```json
{"ts":1696200000,"method":"POST","url":"https://api.com/login","req_headers":{"Content-Type":"application/json"},"req_body":{"user":"test","sign":"a3b2c1"},"status":200,"resp_body":{"token":"eyJ..."},"sign_params":["sign","ts"],"latency_ms":120}
```

- Compact JSONL, one flow per line
- Noise headers stripped
- Sign parameters auto-tagged
- Large bodies truncated with SHA256 hash
- JSON bodies inline as objects (not escaped strings)

### Signature Algorithm Inference
Analyzes `sign` parameters across multiple requests to guess the algorithm:
- Length + encoding analysis (32 hex → MD5, 64 hex → SHA256, etc.)
- Cross-request consistency checking
- Brute-force verification: tries MD5/SHA1/SHA256/HMAC on sorted params
- Common pattern matching (Chinese app API conventions)

### Static Analysis Correlation
```bash
# Scan jadx decompiled output
cap context import --jadx ./jadx-output/

# Captured flows now show source references:
# POST /api/v1/login → com/example/api/LoginApi.java:42 (method: login)
```

Scans for:
- Retrofit annotations (`@POST`, `@GET`, etc.)
- OkHttp `Request.Builder` patterns
- Maps URL patterns to source file, class, method, and line number

### Desktop GUI
Native Wails-based desktop app (Go + Svelte, single binary, no Electron):
- **Capture**: proxy start/stop + Android device connect
- **Flows**: filterable table, detail panel, inline export, replay with modification, body viewer (JSON/hex/raw), sign analysis
- **Terminal**: multi-tab embedded shell with command history
- **Plugins**: live code editor with examples, save/load/test
- **Settings**: theme, font, proxy, Android, export configuration

### API Auto-Grouping
Automatically groups captured flows by host and path prefix — see your target app's full API structure at a glance.

### Flow Comparison
Select two flows and see a structured side-by-side diff: URL, headers, JSON body keys, latency percentage change.

### Request Sequence Replay
Record a sequence of flows (login → fetch → submit), save it, replay with automatic token/cookie propagation between steps.

### Protobuf Auto-Decode
Schema-less protobuf decoder — automatically detects and decodes binary protobuf responses without needing a .proto file.

### Traffic Dashboard
Aggregated statistics: requests by host/status/method, P95 latency, error rate, top slowest endpoints, per-minute timeline.

### HAR/Charles Import
Import existing captures from HAR files or Charles proxy XML exports — zero migration friction.

### Plugin System
Built-in plugin editor with 3 example plugins. Write JavaScript-style analysis scripts, test against captured flows, save and toggle on/off.

## Install

```bash
# From source (recommended)
git clone https://github.com/overkazaf/cap.git
cd cap
go build -o cap ./cmd/cap

# Or via go install
go install github.com/overkazaf/cap/cmd/cap@latest
```

**Requirements**: Go 1.21+, macOS or Linux (for Wails GUI: Xcode CLI tools on macOS)

## Quick Start

```bash
# 1. Start proxy (listens on all interfaces)
cap start -a 0.0.0.0:8080

# 2. Connect Android device
cap android connect

# 3. Use the phone — traffic flows through cap

# 4. View captured requests
cap flows

# 5. Export for analysis
cap export --flow f1 --lang all        # code in 5 languages
cap export --format agent | llm chat   # feed to your LLM

# 6. Or use the GUI
cap gui
```

## Project Structure

```
internal/
├── types/          Flow, WSFrame, SSEEvent structs
├── proxy/          goproxy MITM, CA cert gen, header filter
├── store/sqlite/   SQLite with WAL, filtering, JSON codec
├── export/
│   ├── codegen/    Go templates → curl/python/go/java/js
│   └── agent/      Compact JSONL + sign param detection
├── android/        ADB device setup, 3-strategy cert install
├── context/        jadx scanner, Retrofit/OkHttp parser, URL matcher
├── sign/           Length analysis, pattern matching, brute-force verify
├── replay/         HTTP replay, request modification, response diff
├── capture/        WebSocket frame parser, SSE stream parser
├── compare/        Side-by-side flow comparison with structured diff
├── grouping/       API auto-grouping by host + path prefix
├── importer/       HAR and Charles proxy XML import
├── proto/          Schema-less protobuf wire format decoder
├── sequence/       Request sequence record/replay with variable propagation
├── stats/          Traffic statistics (P95, error rate, timeline)
├── plugin/         Plugin engine with save/load/toggle
├── wailsgui/       Wails backend bindings for all modules
├── cli/            Cobra commands: start/flows/export/android/gui
└── gui/            Legacy Fyne GUI (deprecated, use Wails)
frontend/           Svelte SPA (Capture, Flows, Terminal, Plugins, Settings)
```

## License

MIT

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
