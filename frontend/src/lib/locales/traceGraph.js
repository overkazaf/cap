import { registerMessages } from '../i18n.js'

registerMessages('traceGraph', {
  en: {
    perspectives: {
      flow: 'Execution Flow',
      modules: 'Module Architecture',
      sequence: 'Call Sequence',
    },
    layers: {
      entry: 'Entry / UI',
      business: 'Business',
      network: 'Network / API',
      sdk: 'SDK',
      crypto: 'Crypto / Sign',
      native: 'Native JNI',
      http: 'HTTP Wire',
    },
    edgeTypes: {
      call: 'calls',
      builds_request: 'builds request',
      signs: 'signs',
      loads_so: 'loads .so',
      jni: 'JNI',
      native_call: 'native call',
      http: 'HTTP',
    },
    controls: {
      zoomOut: 'Zoom out',
      zoomIn: 'Zoom in',
      fitView: 'Fit',
      fitTooltip: 'Fit diagram to viewport',
      resetZoomTooltip: 'Reset zoom to 100%',
      exportSvg: 'Export SVG',
      exportSvgTooltip: 'Download standalone SVG diagram',
      panHint: 'Drag to pan · Scroll to zoom · Click node to inspect',
    },
    stats: {
      flow: '{nodes} nodes · {edges} edges',
      modules: '{modules} modules · {links} links',
      sequence: '{actors} lifelines · {steps} steps',
    },
    moduleCard: {
      classes: '{count} cls',
      methods: '{count} fn',
      libs: '{count} .so',
      evidence: '{count} hits',
    },
    empty: {
      title: 'No trace graph data yet',
      description: 'Run DeepTrace on a captured request to visualize execution flow, module architecture, and call sequence.',
    },
    toast: {
      svgExported: 'SVG diagram exported',
      svgExportFailed: 'Failed to export SVG',
    },
  },

  'zh-CN': {
    perspectives: {
      flow: '执行链路',
      modules: '模块架构',
      sequence: '调用时序',
    },
    layers: {
      entry: '入口 / UI',
      business: '业务模块',
      network: '网络 / API',
      sdk: '三方 SDK',
      crypto: '加密 / 签名',
      native: 'Native JNI',
      http: 'HTTP 请求',
    },
    edgeTypes: {
      call: '调用',
      builds_request: '构造请求',
      signs: '签名计算',
      loads_so: '加载 .so',
      jni: 'JNI 桥接',
      native_call: 'Native 调用',
      http: '发起请求',
    },
    controls: {
      zoomOut: '缩小',
      zoomIn: '放大',
      fitView: '自适应',
      fitTooltip: '缩放并居中以完整显示图谱',
      resetZoomTooltip: '重置缩放为 100%',
      exportSvg: '导出 SVG',
      exportSvgTooltip: '下载独立可打开的 SVG 矢量图',
      panHint: '拖拽平移 · 滚轮缩放 · 点击节点查看证据详情',
    },
    stats: {
      flow: '{nodes} 节点 · {edges} 连线',
      modules: '{modules} 模块 · {links} 协作关系',
      sequence: '{actors} 参与方 · {steps} 调用步骤',
    },
    moduleCard: {
      classes: '{count} 类',
      methods: '{count} 方法',
      libs: '{count} .so',
      evidence: '{count} 处证据',
    },
    empty: {
      title: '暂无调用图谱数据',
      description: '对任意捕获请求执行深度追踪后，即可从执行链路、模块架构与调用时序三个视角可视化溯源。',
    },
    toast: {
      svgExported: '已导出 SVG 矢量图',
      svgExportFailed: '导出 SVG 失败',
    },
  },
})
