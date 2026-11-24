# cap

<p align="center">
  <strong>商业级 HTTP(S) MITM 抓包与移动逆向工程工作台</strong><br>
  原生桌面 GUI · 全屏交互式 TUI · Android 守护伴侣 APK · 中英双语 · LLM 友好输出
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="https://overkazaf.github.io/cap/">文档与预览站</a> ·
  <a href="#产品界面预览">界面预览</a> ·
  <a href="#安装与构建">安装与构建</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#命令参考">CLI / TUI 命令参考</a>
</p>

---

## 产品界面预览

<p align="center">
  <img src="docs/screenshots/flows-detail.png" alt="cap 请求流与插件单页联调工作台（Obsidian 暗黑主题）" width="100%">
  <br>
  <em>请求流 + 插件单页联调工作台 —— 左侧实时浏览抓包请求，右侧内嵌 <code>PluginWorkbench</code> 即时查看解析后的 <code>query_params</code> 变量、匹配状态并按 <code>⌘Enter</code> 运行 Python 3 / Node / Shell 脚本草稿。</em>
</p>

<table>
  <tr>
    <td width="50%" align="center">
      <img src="docs/screenshots/capture-tab.png" alt="抓包控制中心" width="100%"><br>
      <strong>抓包控制中心</strong> —— 实时 KPI 看板、4 步 Android APEX 证书与代理守护看门狗
    </td>
    <td width="50%" align="center">
      <img src="docs/screenshots/flows-tab.png" alt="流量检查器" width="100%"><br>
      <strong>Flows 流量检查器</strong> —— 可拖拽分屏、JSON/XML/Protobuf/Hex 与签名参数自动识别
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <img src="docs/screenshots/deeptrace-tab.png" alt="DeepTrace 8 阶段实时追踪" width="100%"><br>
      <strong>DeepTrace 8 阶段实时流水线</strong> —— HTTP → Java → JNI → Native 调用链与 APK/JADX 缓存
    </td>
    <td width="50%" align="center">
      <img src="docs/screenshots/terminal-tab.png" alt="多标签内嵌终端" width="100%"><br>
      <strong>工作台多标签终端</strong> —— 结构化诊断命令块，无缝执行 ADB、Frida 与 CLI 工具
    </td>
  </tr>
  <tr>
    <td colspan="2" align="center">
      <img src="docs/screenshots/light-zh-preview.png" alt="Porcelain 陶瓷浅色主题 + 简体中文" width="88%"><br>
      <strong>Porcelain 陶瓷浅色主题 + 原生简体中文</strong> —— 4 套主题与中英双语零延迟热切换
    </td>
  </tr>
</table>

---

## 为什么选择 cap？

现有抓包工具（Burp Suite、mitmproxy、HTTP Toolkit）大多面向 Web 安全测试，而非**移动端 App 逆向工程**。`cap` 将高性能 Go MITM 代理内核、原生 Wails 桌面工作台、无闪烁全屏 TUI 与断网自愈 Android 守护伴侣 APK 打包为单一二进制：

| 能力 | Burp Suite | mitmproxy | HTTP Toolkit | **cap** |
|------|:----------:|:---------:|:------------:|:-------:|
| CLI 自动化 | ✗ 纯 GUI | ✓ mitmdump | ✗ 纯 GUI | **✓ 彩色 CLI + `--json`** |
| 全屏交互式 TUI | ✗ | ✓ mitmproxy | ✗ | **✓ 分屏交互 (`cap tui`)** |
| 原生桌面 GUI | ✗ Java/Swing | △ mitmweb (简陋) | ✓ Electron (重) | **✓ Wails v2 + Svelte 4** |
| 全栈双语 (`EN` / `简体中文`) | ✗ | ✗ | ✗ | **✓ GUI + TUI + CLI + APK** |
| LLM/Agent 友好输出 | ✗ XML/HAR | △ HAR (冗余) | △ HAR | **✓ 精简 JSONL** |
| 多语言代码生成 | ✗ | △ curl + Python | ✗ | **✓ 5 种语言** |
| 签名参数自动识别 | ✗ | ✗ | ✗ | **✓** |
| 签名算法推理 | ✗ | ✗ | ✗ | **✓ MD5/SHA/HMAC** |
| 静态分析与 DeepTrace | ✗ | ✗ | ✗ | **✓ 8 阶段实时 jadx / DEX / 调用图** |
| Frida 工作室与实时 Hook | ✗ | ✗ | ✗ | **✓ 服务端一键部署 / 在线热重载 / 追踪生成 Hook** |
| 原生逆向与算法仿真 (r2/Unidbg/Qiling/angr) | ✗ | ✗ | ✗ | **✓ r2 + 纯 Go ELF / 算法仿真 / 符号执行** |
| 反混淆、反调试与 VMP 逆向 | ✗ | ✗ | ✗ | **✓ 13 种加固 / OLLVM / 内联 SVC / VMP 追踪** |
| 执行追踪与污点分析 | ✗ | ✗ | ✗ | **✓ 多格式解析 / 寄存器+内存污点 / ASLR Diff / Tenet** |
| 服务化网关 (Open API + 资源池) | ✗ | ✗ | ✗ | **✓ HTTP API / 代理池 / 设备指纹池 / 签名器** |
| 一键连接 Android | ✗ | ✗ | △ 需装 App | **✓ ADB 直连 + 守护 APK** |
| 拔线/断网自动恢复代理 | ✗ | ✗ | △ 依赖 App | **✓ Companion 看门狗（免 Root）** |
| 证书注入 (Android 7–15) | ✗ 手动 | ✗ 手动 | ✓ | **✓ APEX Conscrypt / mount --bind / Magisk / KeyChain** |
| SSL Unpinning 脱钉 | △ 手动 | ✗ | ✗ | **✓ Frida / patch / Magisk / CodeShare** |
| 拦截规则与断点 | ✓ | ✓ 插件 | ✓ Pro | **✓ 规则改写 + 实时断点放行** |
| 请求重放 + Diff | ✓ Repeater | ✗ | ✗ | **✓ 改参重放 + 并排 Diff** |
| API 自动分组与序列回放 | ✗ | ✗ | ✗ | **✓ 路径聚类 + Token 传递** |
| 流量仪表盘 | ✗ | ✗ | ✗ | **✓ P95 / 时间线 / TLS 告警** |
| 内嵌终端 | ✗ | ✗ | ✗ | **✓ 多 Tab PTY** |
| HAR / Charles 导入 | ✓ | ✓ | ✓ | **✓** |
| WebSocket 抓取 | ✓ | ✓ | ✓ | **⧗ 实验性** |
| SSE 流抓取 | ✗ | △ | ✗ | **⧗ 实验性** |
| Protobuf 无 Schema 解码 | ✗ 插件 | △ 插件 | ✗ | **⧗ 实验性** |
| 插件系统 | ✓ BApp | ✓ addon | ✗ | **✓ 单页联调 Python/Node/Sh 工作台** |
| 单文件分发 | ✗ JVM | ✗ Python | ✗ Electron | **✓ Go 单二进制** |
| 开源免费 | ✗ ($449/年) | ✓ | △ 核心开源 | **✓ MIT** |

### 成熟度标识

- **稳定**：已有自动化测试覆盖，适合日常使用。
- **实验性**：功能已实现并具备基础测试，但协议与设备组合验证尚未全面覆盖，暂不做绝对声明。

对比表中的 `⧗ 实验性` 为保守标识，如实反映当前工程进度。

---

## 系统架构

### 系统总览

```mermaid
flowchart TB
    subgraph 客户端["客户端与国际化层 (EN / 简体中文)"]
        CLI["cap CLI<br/>(cobra + i18n)"]
        TUI["cap TUI<br/>(双缓冲全屏 ANSI)"]
        GUI["cap GUI<br/>(Wails v2 + Svelte 4)"]
        TTY["内嵌终端<br/>(多 Tab PTY)"]
    end

    subgraph 核心引擎["核心引擎"]
        PROXY["MITM 代理<br/>(goproxy + 规则/断点)"]
        STORE["Flow 存储<br/>(SQLite WAL)"]
        REPLAY["请求重放<br/>+ Diff 与序列回放"]
    end

    subgraph 分析层["分析与逆向层"]
        SIGN["签名推理<br/>(MD5/SHA/HMAC)"]
        TRACE["DeepTrace 与源码映射<br/>(jadx / DEX / 调用图)"]
        DETECT["参数检测<br/>(sign / ts / nonce)"]
        RELAB["逆向实验室引擎<br/>(r2 / Unidbg / Qiling / angr)"]
        DEOBF["反混淆与 VMP 引擎<br/>(加固 / OLLVM / SVC / VMP)"]
        EXECTRACE["执行追踪与污点<br/>(多格式 / 污点切片 / Diff)"]
    end

    subgraph 服务层["服务化网关与集成中心"]
        GW["Open API HTTP 网关<br/>(:9090 / 鉴权 / OpenAPI 3.0.3)"]
        POOLS["代理 IP 池与<br/>虚拟设备指纹池"]
        SIGNERS["可插拔签名器<br/>(HMAC / 脚本 / HTTP / Unidbg / Frida)"]
    end

    subgraph 导出层["导出层"]
        CODEGEN["代码生成<br/>(curl/py/go/java/js)"]
        AGENT["Agent 导出<br/>(精简 JSONL)"]
    end

    subgraph 抓取层["流式协议层 (实验性)"]
        WS["WebSocket<br/>帧解析"]
        SSE["SSE 流<br/>解析"]
    end

    subgraph 设备层["Android 设备与守护层"]
        ADB["Android ADB<br/>(代理 + 三策略证书)"]
        GUARD["Cap 代理守护 APK<br/>(ProxyGuardService 看门狗)"]
    end

    subgraph 脱钉层["Frida 工作室与 SSL Unpinning"]
        FRIDA["Frida 工作室与 Bridge<br/>(服务端部署 / 热重载 / 动态 Hook)"]
        PATCH["APK 补丁<br/>(NSConfig)"]
        CODESHARE["CodeShare<br/>(指纹 → 脚本)"]
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

    style 客户端 fill:#1e3a5f,color:#fff
    style 核心引擎 fill:#14532d,color:#fff
    style 分析层 fill:#7c2d12,color:#fff
    style 服务层 fill:#1e40af,color:#fff
    style 导出层 fill:#581c87,color:#fff
    style 抓取层 fill:#7f1d1d,color:#fff
    style 设备层 fill:#164e63,color:#fff
    style 脱钉层 fill:#713f12,color:#fff
```

### 数据流

```mermaid
sequenceDiagram
    participant 手机 as Android 设备 + Cap 代理守护 APK
    participant 代理 as cap MITM 代理
    participant 存储 as SQLite (WAL)
    participant 检测 as 参数检测器
    participant 推理 as 签名推理
    participant 视图 as GUI / TUI / 导出器

    手机->>代理: HTTP/HTTPS 请求（看门狗每 3 秒心跳探测）
    代理->>代理: 规则/断点拦截与 MITM 解密
    代理->>存储: 保存 Flow
    代理->>手机: 转发上游并返回响应
    代理-->>存储: 更新 Flow（响应体与耗时）

    存储->>检测: 分析参数
    检测-->>存储: 标记 sign_params

    存储->>推理: 跨请求分析签名值
    推理-->>存储: 推测算法并暴力校验

    存储->>视图: 实时推送 / cap tui / cap export
    视图-->>视图: 桌面检查器 / cURL / Python / JSONL
```

---

## 核心功能

### 商业级原生桌面 GUI（`cap gui`）

基于 Wails v2 + Svelte 4 构建的单文件原生桌面工作台（无 Electron 内存开销）：

- **桌面工作台外壳与体验**：
  - **4 套精致主题**：**Obsidian 曜石暗黑**（默认）、**Porcelain 陶瓷浅色**、**Mocha** (Catppuccin) 与 **Nord**，配合 1px 精细描边、语义层级表面色与等宽 `tabular-nums` 指标排版。
  - **全局命令面板（`⌘K` / `Ctrl+K`）**：一键跳转 10 大工作区、启停/暂停代理、切换主题以及实时热切换 `EN ↔ 简体中文`。
  - **可折叠左侧导航栏（`⌘B`）**：支持 `⌘1–9` / `⌘,` 快捷键直达工作区，实时展示代理、Frida 注入、逆向任务与服务网关活跃标识，顶部集成实时代理状态胶囊与 `EN / 中文` 切换按钮，底部配备 IDE 风格状态栏。
- **10 大核心工作区**：
  1. **Capture 抓包中心（`⌘1`）**：4 指标 KPI 实时看板（`req/s` + 吞吐带宽、总流量/字节数、活跃主机 + 平均/P95 延迟、错误率 + TLS 告警）、4 步向导式 Android 接入卡片（`ADB 设备` → `CA 证书` → `Cap 代理守护` → `代理路由`）、域名作用域过滤、Frida 服务端快捷启停与一键跳转 Frida 工作室，以及活动日志 / 活跃主机 / TLS 告警多标签控制台。
  2. **Flows 流量分析器（`⌘2`）**：多维过滤工具栏（`/` 聚焦、主机自动补全、方法/状态码/内容类型胶囊、平铺与 API 分组视图）、可拖拽横向/纵向 `SplitPane`、键盘导航（`↑/↓`/`j/k`、`Esc`）、多标签详情检查器（`Params`、`Req/Resp Headers`、`Req/Resp Body` 支持 JSON / XML / Protobuf / Hex 及内联搜索、`Raw`、`Timing`、`Export` 一键生成 cURL/Python/Go/Java/JS/Agent JSONL）、改参重放、并排 Flow Diff、签名分析、**一键发布到服务网关**、HAR/Charles 导入、原生回环 **MJPEG 设备投屏**（`Fast` / `scrcpy`，实时 FPS 与拖拽滑动），以及右侧内置 **插件调试（`PluginWorkbench`）** 模式实现单页无缝联调。
  3. **Rules 拦截规则与断点（`⌘3`）**：分屏规则管理 + 实时**挂起断点队列**（支持编辑后放行 / Mock 返回 / 丢弃 403），涵盖 6 类动作、优先级排序及正则/路径校验。
  4. **DeepTrace 深度追踪（`⌘4`）**：8 阶段实时可取消追踪流水线，支持纯 Go DEX 字节码交叉引用（XRefs）、3 视角交互式 SVG 调用图与 APK/JADX 缓存复用，并支持从综合报告、模块卡片与 Native `.so` 符号**一键跳转 Frida Hook、逆向实验室仿真或保护审计**。
  5. **Frida 动态工作室（`⌘5`）**：全流程 Frida 逆向工作台，覆盖 `frida-server` 全生命周期（自动识别设备 ABI、GitHub Release 一键下载或本地 `.xz` 推送、防检测重命名、自定义端口与 `adb forward`、宿主与设备版本一致性校验）、零额外 CGO 的内置 Python Frida Bridge（自动降级 `frida-cli`）、可搜索进程/应用选择器、`Spawn (-f)` / `Attach` 注入、**无需重启 App 的在线脚本热重载（`⌘R`）**、结构化 `send()` JSON 事件卡片与 JSONL 导出、7 套内置实战模板 + `~/.cap/frida-scripts/` 磁盘热重载、CodeShare 与应用指纹检索，以及 **DeepTrace 一键合成 Hook**。
  6. **RE Lab 逆向实验室（`⌘6`）**：四合一原生逆向工作台，集成 **Native / radare2** 静态与伪 C 分析（无 `r2` 时纯 Go ELF 自动兜底）、**Unidbg · Qiling · angr** 算法仿真与符号执行（支持实时日志流与 `~/.cap/re-projects/*.json` 持久化）、**反混淆 · 反调试 · VMP** 保护审计与脚本生成（一键推送 Frida 或仿真执行），以及 **ExecTrace · 污点分析**（多格式指令追踪、前向/后向寄存器+内存污点切片、加密常量/S-Box/热循环识别、ASLR 归一化 Diff 与 Tenet/JSONL/Markdown 导出）。
  7. **Plugins 插件工坊（`⌘7`）**：可脚本化分析插件工作台与单页联调器（本地 `~/.cap/plugins/*.json` 自动热重载），支持 `python3` / `node` / `sh` / `builtin` 运行时、实时解析 `query_params` 与流变量检查器（点击即插代码片段）、实时 `stdin JSON` 预览、`命中当前请求` 实时匹配指示（支持查询字符串与通配符 `*`）、`⌘Enter` 免保存即刻运行草稿、实时流量自动触发及实时执行日志面板。
  8. **Service Gateway 服务网关（`⌘8`）**：内置 Open API HTTP 服务化网关（默认 `:9090`），将抓包并逆向完成的移动端接口一键封装为标准化 REST 服务 —— 支持抓包流量一键发布、实时路由测试器、API Key 鉴权与路由级限流、OpenAPI 3.0.3 导出、**代理 IP 池**（HTTP/HTTPS/SOCKS5、动态提取源、健康检测与轮询/设备粘性策略）、**设备指纹池**（内置虚拟 Android 机型预设 + 实体 ADB 同步）、**可插拔签名器**（内置 HMAC、本地脚本、HTTP、Unidbg HTTP、Frida RPC）及实时调用日志。
  9. **Terminal 内嵌终端（`⌘9`）**：多 Tab 暗色 PTY 终端（`⌘T` / `⌘W` / `Ctrl+Tab` / `Ctrl+L`），内置 `adb`、`frida`、`curl` 常用诊断快捷指令。
  10. **Settings 系统设置（`⌘,`）**：分栏配置外观与显示语言（`English` / `简体中文`）、代理与证书、Android / Frida 运行环境、逆向工具链路径（`r2`、`java`、`mvn`、`unidbg`、`python3`、`qiling rootfs`）与默认网关地址、导出与存储、快捷键速查及关于/诊断信息。

### 全屏交互式 TUI 与命令行体验（`cap tui` / `cap start --tui`）

无闪烁双缓冲全屏 ANSI 终端界面（基于 DEC 同步输出 + 备用屏幕 + 退出安全还原终端状态），自适应宽屏（`≥110` 列）与上下分屏布局：

```bash
cap start --tui                      # 在交互式 TUI 内启动实时 MITM 代理
cap tui                              # 交互式浏览与检查已保存的 SQLite 流量
cap tui --live -a 0.0.0.0:8080       # 监听全网卡并实时流式展示
cap tui -f 'm:POST s:4xx' --light    # 带初始过滤条件 + Porcelain 浅色主题启动
cap tui --lang zh                    # 直接以简体中文界面启动
```

| 快捷键 | 功能说明 |
|--------|----------|
| `↑` / `↓` 或 `j` / `k` | 切换流量列表项或滚动右侧详情 |
| `Tab` / `Shift+Tab` | 在流量列表与详情面板之间切换焦点 |
| `1` – `6` | 切换详情标签：`1` 概览 · `2` 请求 · `3` 响应 · `4` 请求头 · `5` 耗时 · `6` cURL/代码 |
| `l` | 在标签 `6` 中循环切换导出语言（`curl` / `python` / `go` / `java` / `js`） |
| `/` | 打开实时过滤栏（支持 `m:POST s:4xx h:api.example.com !static`） |
| `m` / `e` / `c` | 循环筛选 HTTP 方法 / 仅看错误（`4xx`/`5xx`）/ 清空过滤 |
| `f` / `p` | 开关自动跟随最新请求 / 暂停实时流 |
| `z` | 最大化当前焦点面板 |
| `r` | 异步重放当前选中请求 |
| `y` / `x` | 复制 cURL 到剪贴板 / 导出流量到文件 |
| `R` / `d` | 重载 SQLite 数据库 / 删除当前流量 |
| `t` | 即时切换 **Obsidian 暗黑** ↔ **Porcelain 浅色** 主题 |
| `L` | 即时热切换 **`EN` ↔ `简体中文`**（严格对齐双宽 CJK 表格边框） |
| `?` / `q` / `Ctrl+C` | 打开快捷键帮助弹窗 / 干净退出 |

**机器可读输出保证**：`--json`、`--format json`、`cap export`、`cap unpin script`、`NO_COLOR=1` 及非 TTY 管道输出始终保持纯净无 ANSI 颜色转义，方便直接接入脚本与 AI 工作流。

### 全链路多语言支持（`EN` / `简体中文`）

- **桌面 GUI**：可通过顶部栏 `EN / 中文` 切换胶囊、底部状态栏、`⌘K` 命令面板或“设置 → 语言”实时热切换，无需重启并自动持久化。
- **交互式 TUI 与 CLI**：自动按 `CAP_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG` 检测系统语言，可通过全局持久化参数 `--lang en|zh` 覆盖，或在 TUI 内按 `L` 一键切换。
  - *注*：`cap export` 命令上的 `-l` / `--lang` 参数用于指定生成代码的编程语言（`curl`、`python`、`go`、`java`、`js`、`all`）。
- **Android 守护伴侣 APK**：内置 Android 原生双语资源（`Cap Guard` / `Cap 代理守护`），自动跟随手机系统语言显示。

### 强化版 Android 抓包与 Cap 代理守护 APK

让抓包后的手机**永不因为拔掉数据线、切 Wi-Fi 或桌面端意外退出而断网**。

`cap` 将一个仅 33 KB、零第三方依赖、纯 Android SDK 离线编译并签名的守护 APK（`com.overkazaf.cap.companion`，`minSdk=24`，`targetSdk=34`）直接嵌入 Go 二进制（`internal/android/bin/cap-companion.apk`）：

- **无感自动部署**：执行 `cap android connect`（可用 `--no-companion` 跳过）或在 GUI 点击连接时自动安装并拉起守护服务。
- **免 Root 自主清理代理**：连接时通过 ADB 自动授予 `WRITE_SECURE_SETTINGS` 与后台/电池白名单 —— **无需 Root 权限**即可由手机端自主还原系统代理。
- **前台心跳看门狗（`ProxyGuardService`）**：每 3 秒主动探测 `proxy_host:proxy_port` 连通性。连续失败 3 次、拔掉 USB（`ACTION_POWER_DISCONNECTED`）、设备重启（`BootReceiver`）或点击通知栏**「恢复网络」**按钮时，自动清除全局 `http_proxy`（在 Root `--vpn` 模式下同时清理 `cap-redir` 与 iptables 规则），并弹出「代理已自动清理，网络已恢复」通知。
- **全版本 CA 证书管理（Android 7–15）**：
  - **Root 设备**：支持 HTTP Toolkit 方案的 Android 14+ APEX Conscrypt 命名空间注入（`mount --bind` + `TRUST_STORE_CHANGED` 实时重载信任库）、Android 10–13 `mount --bind`、Magisk 持久化模块与 Android 9 及以下 `/system` 重挂，并提供 `cap android cert --check` 验证与 `--remove` 移除。
  - **非 Root 设备**：守护 App 内置 `MainActivity` 一键调起系统 `KeyChain` 安装 `/sdcard/Download/cap-ca.crt`，配合 GUI 状态向导快速校验。
- **桌面端自动收尾**：`cap start --auto-disconnect`、`cap tui --live --auto-disconnect` 以及桌面 GUI 的 `StopProxy()` / `App.Shutdown()` 都会在停止代理前自动断开并恢复已追踪的 Android 设备。

### Frida 动态逆向工作室（`cap frida` 与桌面端 `⌘5`）

零额外 CGO 依赖的端到端 Android Frida 动态插桩工作流，打通服务端部署、实时热重载与 DeepTrace 动态验证闭环：

```bash
cap frida status                                           # 检测宿主机 Python Bridge / frida CLI 与设备 frida-server 状态
cap frida deploy --start --name hluda-srv                  # 自动下载匹配 ABI/版本、防检测重命名并启动
cap frida ps                                               # 枚举设备应用与运行中 PID（Bridge → frida-ps → ADB）
cap frida scripts                                          # 查看 7 套内置实战模板与 ~/.cap/frida-scripts/ 自定义脚本
cap frida run --pkg com.example.app --spawn \
  --script builtin:crypto-sign-tracer                      # 实时流式输出结构化 send() Hook 事件
```

- **Server 全生命周期与防检测部署**：单次批量 ADB 探针自动识别 CPU ABI（`arm64`/`arm`/`x86_64`/`x86`）、Root 权限、运行 PID/端口与宿主/设备版本一致性（`match` / `minor_diff` / `major_mismatch`）；支持从 GitHub Releases 自动下载缓存（`~/.cap/frida-cache/`）或推送本地 `.xz`/二进制文件，支持防检测重命名与自动 `adb forward`。
- **内置 Python Frida Bridge + CLI 自动降级**：自动探测本机 Python 3 / venv / conda / pipx 环境（也可在 Frida 工作室或偏好设置中自定义路径），支持结构化 `send()` JSON 事件卡片、二进制 Hex 预览、Spawn 暂停/继续与**在线脚本热重载（`⌘R`）**，无 Python `frida` 模块时自动降级兼容 `frida` CLI。
- **内置实战脚本库与 CodeShare**：预置 7 套常用模板（14+ 通用 SSL Unpin、防 Root/防 Frida 隐身绕过、OkHttp3/URLConnection 追踪、MD5/SHA/HMAC/AES 签名加解密追踪、JNI `RegisterNatives` & `dlopen` 追踪、SharedPreferences/SQLite 监控、动态类浏览器），支持 `~/.cap/frida-scripts/*.json` 磁盘热重载、CodeShare 社区检索与应用特征指纹推荐。
- **DeepTrace → Frida 闭环联动**：在 DeepTrace 报告页、模块卡片或 Native `.so` 列表点击「一键 Frida Hook」，自动合成含安全 Overload 包装与 `dlopen` 延迟注入的 JS 脚本并直达 Frida Studio 运行验证。

### RE Lab — 原生二进制逆向与算法仿真实验室（`cap re` 与桌面端 `⌘6`）

无需切换多个外部工具，在 `cap` 内一站式完成 `.so`/ELF/Mach-O 静态分析与跨平台算法仿真：

```bash
cap re status                                              # 探测 radare2、JDK/Maven/Unidbg、Python/Qiling/angr 就绪度
cap re analyze ./libsign.so --func Java_com_app_sign       # 静态分析 + 指定函数反汇编 / 伪 C / 交叉引用
cap re r2 ./libsign.so "iI;iEj"                            # 安全执行只读 radare2 命令
cap re gen -e unidbg --apk app.apk --so libsign.so \
  --class com/app/Signer --method sign --http-server       # 一键生成 Unidbg 仿真工程（可选内置 HTTP 签名服务模式）
```

- **radare2 静态分析 + 纯 Go ELF 自动兜底**：解析架构、安全缓解措施（`PIE` / `NX` / `Canary` / `RELRO`）、函数列表、动态导入导出、字符串、交叉引用、反汇编与伪 C（`pdg`/`pdc`）；未安装 `r2` 时自动降级至纯 Go `debug/elf` 扫描引擎。
- **Unidbg · Qiling · angr 算法仿真与符号执行**：内置实战起步模板与参数化代码生成器，覆盖 Android JNI `.so` 仿真（Unidbg，支持内置轻量 HTTP 签名服务模式）、ARM64/ARM Linux/Android 仿真（Qiling RootFS 与系统调用 Hook）及符号约束求解（angr + `claripy` 自动提取具体解）。
- **DeepTrace → RE Lab 联动闭环**：在 DeepTrace 报告页或 Native `.so` 卡片点击「在逆向实验室仿真」，自动携带 APK、`.so`、JNI 符号与样本入参合成可运行脚本，并支持可取消的实时流式任务执行与 `~/.cap/re-projects/*.json` 持久化。

### 反混淆、反调试与 VMP 逆向套件（`cap deobf` 与桌面端 `⌘6`）

自动化识别移动端加固与反调试保护，并按扫描结果合成可组合绕过与反混淆脚本：

```bash
cap deobf scan ./target.apk                                # 审计 13 种加固壳、OLLVM、VMP 与 ARM64 内联 SVC #0
cap deobf stealth --scan ./target.apk --pkg com.app -o stealth.js
cap deobf unpack --pkg com.app -o unpack.js                # 生成 Frida 内存脱壳 DEX Dump 脚本
cap deobf ollvm --so ./libsec.so --addr 0x1a400            # 生成 angr OLLVM 控制流平坦化还原与补丁脚本
cap deobf vmp --mode stalker --so libvmp.so --entry JNI_OnLoad
cap deobf vmp-trace ./vmp.log --base 0x7000000000          # 分析 VMP 执行轨迹：分发器、Handler 与外部调用
```

- **APK / ELF 保护审计扫描器**：纯 Go 静态扫描引擎，覆盖 **13 种商业加固壳**（360 加固、腾讯乐固、梆梆、爱加密、百度、阿里、顶象、娜迦、几维、Virbox 等）、**OLLVM** 控制流平坦化（CFF）/ 虚假控制流（BCF）/ 指令替换（SUB）、**VMP** 解释器特征、反调试符号与 **ARM64 内联 `SVC #0`** 系统调用扫描。
- **可组合隐身与脱壳生成器**：支持按扫描报告自动定制 Frida 反调试/反 Frida 隐身脚本（`TracerPid` / `/proc/self/maps`、`ptrace` / 信号屏蔽、内联 ARM64 `SVC` 补丁及 dry-run 模式、时序 / `inotify`、Java 调试检测）、内存 DEX 脱壳、OLLVM CFF 还原（`angr`）、字符串解密（Qiling / Unidbg）与 Java 反混淆脚本，并支持一键推送至 Frida Studio 或逆向实验室执行。
- **VMP 动态追踪与分析**：一键生成 Frida Stalker、`RegisterNatives` 与 Unidbg VMP 采集脚本，并对原始轨迹日志执行分发器（Dispatcher）、Handler 分布、热点基本块与外部 API 调用聚合分析。

### 动态执行追踪与污点分析引擎（`cap exectrace` 与桌面端 `⌘6`）

面向 Native 与 JNI 算法还原的多格式执行轨迹解析、污点切片与差分分析引擎：

```bash
cap exectrace import ./sign.trace --format auto --base 0x7000000000
cap exectrace taint --session <id> --direction backward --seq 4200 --reg x0
cap exectrace diff <sessionA> <sessionB> --max-divergences 25
cap exectrace collect --kind stalker --module libsign.so --symbol Java_com_app_sign
cap exectrace export <sessionID> -f tenet -o trace.tenet.txt
```

- **多格式自动识别解析**：统一解析 **Unidbg**、**Frida Stalker**、**Qiling**、**Java/JNI 调用链**、**JSONL** 与 **Tenet** 轨迹文件。
- **前向 / 后向寄存器与内存污点切片**：支持 ARM64 移位/扩展寻址、x86 比例变址、常量覆写清除及按线程隔离的热循环分析，可从最终签名值反向溯源至输入明文与密钥，或从输入前向追踪扩散路径。
- **加密算法识别、ASLR 差分对比与导出**：内置 AES S-Box、MD5/SHA/CRC32/ChaCha/SM4/RC4 等加密常量、热循环与调用树识别；支持 ASLR 基址归一化的双轨迹差分对比（Diff）；内置 Stalker / Java / Unidbg / Qiling 采集器生成，并支持导出为 **Tenet**、**JSONL** 与 **Markdown**。

### 服务化网关与集成中心（`cap gateway` 与桌面端 `⌘8`）

将逆向还原后的移动端接口一键封装为稳定、鉴权、可编排的标准化 HTTP Open API 服务：

```bash
cap gateway publish --flow f1 --slug search-feed           # 将抓包请求流一键发布为 Open API 路由
cap gateway proxies --add socks5://user:pass@1.2.3.4:1080 --check
cap gateway devices --from-preset pixel-8-pro              # 创建虚拟 Android 指纹（或 --sync-adb 同步真机）
cap gateway signers --test <signerID> --url https://api.example.com/v1/feed
cap gateway start -a 127.0.0.1:9090 --require-auth --api-key sk-live-demo
cap gateway openapi -o openapi.json                        # 导出 OpenAPI 3.0.3 接口规范
```

- **Open API HTTP 网关（默认 `:9090`）**：支持从抓包 Flow 一键发布 `POST /gw/<slug>` 路由，内置模板变量渲染（`{{input.*}}`、`{{device.*}}`、`{{timestamp}}`、`{{nonce}}`）、API Key 鉴权（`X-API-Key` / `Bearer`）、路由级限流、失败自动重试切换、原始透传模式、在线路由测试器、实时调用日志以及 **OpenAPI 3.0.3** 文档导出。
- **代理 IP 池**：支持 `HTTP` / `HTTPS` / `SOCKS5` 节点管理、批量导入、动态代理商 API 拉取（纯文本按行或 JSON 路径提取）、并发健康探测与延迟测速，提供轮询（`round_robin`）、随机（`random`）、最低延迟（`least_latency`）与设备粘性（`sticky_device`）调度策略。
- **设备池与虚拟指纹**：预置主流 Android 机型虚拟指纹模板（UA、OAID、Android ID、Build 属性、屏幕参数、会话 Cookie/Token），并支持一键同步已连接的 **ADB 实体设备**。
- **可插拔签名提供者（Signer Providers）**：支持在每次网关调用时自动注入动态签名，覆盖 **内置 HMAC/Hash**（MD5/SHA/HMAC）、**本地脚本**（`python3`/`node`/`sh`）、**外部 HTTP 接口**、**Unidbg HTTP 签名服务** 与 **Frida RPC**（`rpc.exports`）。

### SSL Unpinning 脱钉

四种策略绕过 App 证书固定：

```bash
cap unpin frida --pkg com.example.app --spawn   # Frida：运行时 hook 14+ 种 pinning 实现
cap unpin patch --apk ./target.apk              # 补丁：重写 network_security_config.xml
cap unpin magisk                                # Magisk：系统级用户证书提权模块
cap unpin codeshare --pkg com.example.app       # CodeShare：自动指纹识别 → 搜索社区脚本
cap unpin script                                # 输出原始 Frida 脱钉脚本到 stdout
```

覆盖 TrustManagerImpl、OkHttp3 CertificatePinner、SSLContext、WebViewClient、Conscrypt、Flutter BoringSSL、Apache HTTP、TrustKit、Cordova、NetworkSecurityConfig 等常见实现。

### 逆向分析与导出套件

- **5 种语言代码生成**：任意请求一键导出可运行的 `curl`、`python`（`requests`）、`go`（`net/http`）、`java`（`OkHttp3`）、`js`（`fetch`）或 `all`。
- **LLM/Agent 友好 JSONL（`cap export -f agent`）**：每行一条精简 JSON，自动剥离噪声头、标记 `sign_params`、JSON body 内联对象化、大响应体截断并附带 SHA-256 哈希。
- **签名算法推理**：结合长度/编码特征、跨请求一致性与排序参数 MD5/SHA1/SHA256/HMAC 暴力校验，快速定位签名逻辑。
- **API 自动分组、并排 Diff 与序列回放**：按主机与路径前缀自动聚合接口树；双请求并排对比差异；录制并回放多步请求链并自动传递 Token/Cookie。
- **HAR / Charles 导入**：零门槛导入已有抓包归档。

---

## 安装与构建

### 环境要求

- **Go** `1.27+`（与 `go.mod` 保持一致）
- **Node.js** `18+`（构建 Svelte 4 前端资源）
- **macOS**：Xcode 命令行工具（`xcode-select --install`）
- **Linux**（桌面 GUI 需安装）：`libgtk-3-dev libwebkit2gtk-4.0-dev`
- **Android** *（可选）*：连接手机需安装 `adb`；仅当需要从源码重新编译 `android-companion/` 时才需 Android SDK `build-tools`（仓库已内置签好名的预构建 APK）

### 推荐完整构建（桌面 GUI + 全屏 TUI + CLI + 内置守护 APK）

```bash
git clone https://github.com/overkazaf/cap.git
cd cap

# 构建并同步 Svelte 前端资源、校验 SHA-256，编译带 Wails 桌面运行时的单文件二进制
make assets && make build

# 运行
./dist/cap gui                     # 启动原生桌面 GUI
./dist/cap tui --live              # 启动内置实时代理的全屏交互式 TUI
./dist/cap --help                  # 查看 CLI 帮助
```

> `make build` 会自动传入 Wails v2 所需的 `-tags 'desktop,production'`，并在 macOS 上自动链接 `-framework UniformTypeIdentifiers`。

### 仅构建 CLI 与 TUI（跳过桌面 GUI 前端）

```bash
git clone https://github.com/overkazaf/cap.git
cd cap
go build -o dist/cap ./cmd/cap
./dist/cap tui
```

### 运行测试与校验

```bash
make test     # 运行无网络依赖的单元测试套件
make check    # 运行单元测试 + 前端构建 + 内嵌资源 SHA-256 校验
```

### 从源码重编 Android 守护伴侣 APK *（可选）*

`internal/android/bin/cap-companion.apk` 已随仓库提供并通过 `go:embed` 内嵌。如需自行离线重编：

```bash
ANDROID_HOME=~/Library/Android/sdk ./android-companion/build.sh
```

---

## 快速开始

```bash
# 1. 在全屏交互式 TUI 中启动 MITM 代理
./dist/cap start --tui -a 0.0.0.0:8080

# 2. 一键连接 Android 手机（配置代理 + 安装 CA 证书 + 拉起 Cap 代理守护看门狗）
./dist/cap android connect

# 3. 查看手机代理、CA 证书与守护看门狗状态
./dist/cap android status

# 4. 在 CLI 查询或用 TUI 过滤浏览抓到的流量
./dist/cap flows --host api.example.com --method POST -n 20
./dist/cap tui --filter 'm:POST s:4xx'

# 5. 导出可运行代码或 LLM 友好 JSONL
./dist/cap export --flow f1 -l python
./dist/cap export -f agent | pbcopy

# 6. 断开手机（即使直接拔线或关闭 cap，守护 APK 也会自动恢复手机网络）
./dist/cap android disconnect

# 7. 或直接启动原生桌面 GUI 工作台
./dist/cap gui
```

---

## 命令参考

| 命令 | 说明 |
|------|------|
| `cap gui [-d db]` | 启动 Wails 原生桌面 GUI |
| `cap start [--tui] [-a addr] [-d db] [--auto-disconnect]` | 启动 MITM 代理（彩色终端流或 `--tui` 全屏模式） |
| `cap tui [--live] [-a addr] [-f filter] [--light] [--no-color]` | 启动全屏交互式 TUI（离线查看库或 `--live` 实时抓包） |
| `cap flows [--host] [--method] [--tag] [-s search] [-n limit] [--json]` | 查询并过滤已捕获的流量（`table` 或 `json`） |
| `cap export --flow <id> [-l curl\|python\|go\|java\|js\|all] [-f code\|agent]` | 导出为 5 种语言代码或 Agent 精简 JSONL |
| `cap android connect [--vpn] [--no-cert] [--no-companion] [-p port] [-s serial]` | 一键连接 Android：设代理、装证书并部署守护看门狗 |
| `cap android status [--json] [-s serial]` | 查看设备信息、代理配置、CA 证书及守护服务状态 |
| `cap android cert [--check\|--remove] [-s serial]` | 安装、校验或移除设备上的 cap CA 证书 |
| `cap android disconnect [-s serial]` | 清理系统代理、VPN 转发并停止守护看门狗 |
| `cap frida status [-s serial] [-p port] [--json]` | 检测宿主机 Python/Frida 工具链与设备 `frida-server` 状态 |
| `cap frida deploy [--version v] [--binary path] [--name stealth] [--start]` | 自动下载或推送匹配 ABI/版本的 `frida-server`（支持防检测改名） |
| `cap frida start\|stop [-s serial] [-p port]` | 启动或停止设备端 `frida-server` 并配置 `adb forward` |
| `cap frida ps [-s serial] [--json]` | 列出设备上已安装应用与运行中进程 PID |
| `cap frida scripts [--show <id>] [--json]` | 列出内置与自定义 Frida 脚本或输出指定脚本源码 |
| `cap frida run --pkg <pkg> [--spawn] [--script <id\|file>]` | 冷启动或附加目标应用并实时流式输出结构化 Hook 日志 |
| `cap unpin frida --pkg <pkg> [--spawn]` | Frida 运行时 hook 绕过 SSL pinning（14+ 实现） |
| `cap unpin patch --apk <file>` | 补丁 APK `network_security_config.xml` 信任用户证书 |
| `cap unpin magisk` | 部署系统级 Magisk 证书提权模块 |
| `cap unpin codeshare [--pkg <pkg>\|--query <q>]` | 指纹识别目标 APK 并搜索 Frida CodeShare 脚本 |
| `cap unpin script` | 输出原始 Frida 脱钉脚本至 stdout |
| `cap re status [--r2\|--java\|--unidbg-dir\|--python\|--rootfs] [--json]` | 检测宿主机逆向工具链（`r2`、JDK/Maven/Unidbg、Python/Qiling/angr） |
| `cap re analyze <file> [--func <name\|addr>] [--json]` | 静态分析 ELF/Mach-O 二进制及指定函数反汇编/伪 C/交叉引用 |
| `cap re r2 <file> <cmd> [--json]` | 对目标二进制安全执行只读 radare2 命令 |
| `cap re projects [-e engine] [--show <id>] [--json]` | 列出内置与已保存逆向工程或查看仿真代码 |
| `cap re gen -e <unidbg\|qiling\|angr\|radare2> [--apk\|--so\|--http-server]` | 合成 Unidbg、Qiling、angr 或 radare2 仿真/分析脚本 |
| `cap deobf scan <apk\|so> [--json]` | 审计 APK/ELF 的 13 种加固壳、OLLVM、VMP、反调试与内联 `SVC #0` |
| `cap deobf stealth [--scan <path>] [--pkg <pkg>] [--patch-svc] [-o file]` | 生成可组合 Frida 反调试 / 反 Frida 隐身脚本 |
| `cap deobf unpack [--pkg <pkg>] [-o file]` | 生成 Frida 内存 DEX 脱壳脚本 |
| `cap deobf ollvm --so <path> --addr <hex> [--arch arm64] [-o file]` | 生成 angr OLLVM 控制流平坦化还原与二进制修补脚本 |
| `cap deobf vmp [--mode stalker\|jni\|unidbg] [--so <lib>] [-o file]` | 生成 VMP 追踪脚本（Stalker、`RegisterNatives` 或 Unidbg） |
| `cap deobf vmp-trace <file> [--base <hex>] [--json]` | 分析原始 VMP 轨迹，提取分发器、Handler 与外部调用 |
| `cap exectrace import <file> [--format auto\|unidbg\|stalker\|qiling\|tenet]` | 导入并分析动态执行轨迹（加密常量、热循环、调用树） |
| `cap exectrace list [--show <id>\|--delete <id>] [--json]` | 查看、导出详情或删除已保存的执行轨迹会话 |
| `cap exectrace taint --session <id> --direction <forward\|backward> --seq <n>` | 对指定轨迹执行前向/后向寄存器与内存污点分析 |
| `cap exectrace diff <sessionA> <sessionB> [--max-divergences 25]` | 对两条执行轨迹进行 ASLR 归一化差分对比 |
| `cap exectrace collect --kind <stalker\|java_call\|unidbg\|qiling> [-o file]` | 生成即用型执行轨迹采集脚本 |
| `cap exectrace export <sessionID> [-f tenet\|jsonl\|markdown] [-o file]` | 将执行轨迹导出为 Tenet、JSONL 或 Markdown 格式 |
| `cap gateway start [-a 127.0.0.1:9090] [--require-auth] [--api-key <k>]` | 启动内置 Open API HTTP 服务化网关 |
| `cap gateway status [--json]` | 查看网关运行状态、路由与各类资源池统计 |
| `cap gateway publish --flow <id> [--slug <slug>] [--name <name>]` | 将已捕获请求流一键发布为网关服务路由 |
| `cap gateway routes [--test <slug> --input k=v] [--delete <id>] [--json]` | 列出、测试调用或删除已发布的网关路由 |
| `cap gateway proxies [--add <url>\|--import <file>\|--fetch <url>\|--check]` | 管理代理 IP 池（HTTP/HTTPS/SOCKS5、动态拉取与健康检测） |
| `cap gateway devices [--presets\|--from-preset <id>\|--sync-adb]` | 管理虚拟 Android 设备指纹池及 ADB 真机同步 |
| `cap gateway signers [--test <id> --url <url>] [--delete <id>] [--json]` | 列出、测试或删除可插拔签名提供者 |
| `cap gateway openapi [-o openapi.json]` | 导出已启用网关路由的 OpenAPI 3.0.3 JSON 规范 |

**全局参数**：`--lang en|zh`（默认按 `CAP_LANG` > `LC_ALL` > `LC_MESSAGES` > `LANG` 自动识别）。

---

## 项目结构

```text
android-companion/      纯 Android SDK 守护伴侣 APK 源码与离线构建脚本 build.sh
cmd/cap/                主入口与内嵌的 frontend/dist 前端构建产物
frontend/
├── src/App.svelte      桌面工作台外壳（折叠导航栏、顶栏、底栏、⌘K 命令面板）
├── src/components/     Icon、Badge、Button、SplitPane、CommandPalette、ToastHost、Kbd、EmptyState
├── src/lib/            tokens.css、theme.js（4 套主题）、i18n.js、{frida,reLab,gateway}State.js、locales/{common,core,frida,reLab,gateway,tools}.js
└── src/pages/          Capture、Flows、Rules、DeepTrace、Frida、RELab、Plugins、Gateway、Terminal、Settings
internal/
├── android/            ADB 工具、三策略证书安装/校验、companion.go、bin/cap-companion.apk
├── buildinfo/          版本构建信息注入
├── capture/            WebSocket 帧解析、SSE 流解析（实验性）
├── cli/                Cobra 命令集（start、tui、gui、flows、export、android、frida、unpin、re、deobf、exectrace、gateway）
├── compare/            并排流量对比与结构化 Diff
├── config/             共享默认路径配置（~/.cap）
├── context/            jadx 扫描器、Retrofit/OkHttp 解析与 URL 源码映射
├── deobf/              APK/ELF 保护扫描器（13 种加固、OLLVM、VMP、内联 SVC）、隐身/脱壳/反混淆生成与 VMP 分析
├── exectrace/          多格式执行轨迹解析、前向/后向污点切片、加密常量/热循环检测、ASLR 差分对比与 Tenet 导出
├── export/             codegen/（5 种语言）与 agent/（精简 JSONL）
├── frida/              Frida 工具链探测、服务端部署/启停、Python Bridge、脚本库与 DeepTrace→Hook 生成器
├── gateway/            Open API HTTP 服务网关、代理 IP 池、虚拟设备指纹池、可插拔签名器与 OpenAPI 3.0.3
├── grouping/           按域名与路径前缀自动分组 API
├── i18n/               零依赖 TUI / CLI 中英双语本地化词库
├── importer/           HAR 与 Charles XML 导入
├── plugin/             内置分析器插件引擎（实验性）
├── proto/              无 Schema Protobuf 二进制解码器（实验性）
├── proxy/              goproxy MITM 核心、ECDSA CA 生成与流式抓包
├── replay/             HTTP 重放、改参重发与响应 Diff
├── retools/            原生逆向与算法仿真引擎（radare2 + 纯 Go ELF、Unidbg、Qiling、angr、DeepTrace 生成器与任务管理）
├── rules/              拦截规则、Mock 与挂起断点引擎及持久化
├── screen/             Android 设备屏幕镜像（screencap + scrcpy）
├── sequence/           多步请求序列录制/回放与变量传递
├── sign/               签名参数检测、启发式分析与暴力算法验证
├── stats/              流量遥测统计（P95 延迟、错误率、时间线）
├── store/sqlite/       SQLite WAL 持久化、多条件过滤与 JSON 编解码
├── terminal/           桌面 GUI 多 Tab PTY 终端后端
├── trace/              DeepTrace：DEX 搜索、jadx、调用图与 Native 分析
├── tui/                无闪烁双缓冲全屏 ANSI TUI 引擎
├── types/              Flow、WSFrame、SSEEvent 核心数据结构
├── unpin/              SSL Unpinning：Frida、APK 补丁、Magisk、CodeShare
└── wailsgui/           Wails v2 桌面绑定、实时事件推送与退出自动清理
docs/                   GitHub Pages 官网（Obsidian/Porcelain 双主题 + 实时中英切换）
```

---

## 参与贡献

欢迎提交 Issue 与 Pull Request，开发环境搭建、测试与安全审查规范请见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 作者与开源协议

© 2026 [0xaf (@overkazaf)](https://github.com/overkazaf) · MIT 协议（见 [LICENSE](LICENSE)） · [GitHub](https://github.com/overkazaf/cap) · [文档站](https://overkazaf.github.io/cap/)
