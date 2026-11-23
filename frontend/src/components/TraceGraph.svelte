<script>
  import { createEventDispatcher, onMount, tick } from 'svelte'
  import '../lib/locales/traceGraph.js'
  import { t, translate } from '../lib/i18n.js'
  import { toast } from '../lib/toast.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import EmptyState from './EmptyState.svelte'

  /** @type {{ nodes?: any[], edges?: any[], sequence?: any[] } | null} */
  export let graph = null
  /** @type {any[]} */
  export let modules = []
  /** @type {any[]} */
  export let callGraph = []
  export let selectedNodeId = ''
  /** @type {'flow' | 'modules' | 'sequence'} */
  export let perspective = 'flow'

  const dispatch = createEventDispatcher()

  const LAYER_ORDER = ['entry', 'business', 'network', 'sdk', 'crypto', 'native', 'http']

  const LAYER_STYLE = {
    entry: { color: 'var(--status-info)', soft: 'var(--status-info-bg)', border: 'var(--status-info-border)' },
    business: { color: 'var(--accent)', soft: 'var(--accent-soft)', border: 'var(--accent-border)' },
    network: { color: 'var(--method-ws)', soft: 'rgba(45, 212, 191, 0.12)', border: 'rgba(45, 212, 191, 0.34)' },
    sdk: { color: 'var(--status-warning)', soft: 'var(--status-warning-bg)', border: 'var(--status-warning-border)' },
    crypto: { color: 'var(--status-purple)', soft: 'var(--status-purple-bg)', border: 'var(--status-purple-border)' },
    native: { color: 'var(--method-put)', soft: 'rgba(251, 146, 60, 0.13)', border: 'rgba(251, 146, 60, 0.34)' },
    http: { color: 'var(--status-success)', soft: 'var(--status-success-bg)', border: 'var(--status-success-border)' },
  }

  const KIND_GLYPH = {
    activity: 'M4 5h16v14H4z M4 9h16',
    class: 'M12 2L2 7l10 5 10-5-10-5z M2 17l10 5 10-5 M2 12l10 5 10-5',
    method: 'M16 18l6-6-6-6 M8 6l-6 6 6 6',
    sdk: 'M12 2l8 4.5v11L12 22l-8-4.5v-11L12 2z',
    native_lib: 'M4 4h16v16H4z M9 9h6v6H9z',
    native_fn: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z',
    endpoint: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M2 12h20',
    module: 'M3 3h7v7H3z M14 3h7v7h-7z M14 14h7v7h-7z M3 14h7v7H3z',
  }

  // Pan & Zoom state
  let viewportEl = null
  let svgEl = null
  let zoom = 1
  let panX = 24
  let panY = 20
  let isPanning = false
  let panMoved = false
  let panStartX = 0
  let panStartY = 0
  let panOriginX = 0
  let panOriginY = 0
  let hoveredId = ''
  let hoveredSeqIdx = -1

  function normalizeLayer(raw) {
    const l = String(raw || '').toLowerCase().trim()
    if (l === 'ui' || l === 'activity' || l === 'app' || l === 'entry') return 'entry'
    if (l === 'business' || l === 'domain' || l === 'logic') return 'business'
    if (l === 'network' || l === 'api' || l === 'client') return 'network'
    if (l === 'sdk' || l === 'third_party' || l === '3p') return 'sdk'
    if (l === 'crypto' || l === 'sign' || l === 'security' || l === 'auth') return 'crypto'
    if (l === 'native' || l === 'jni' || l === 'so' || l === 'c' || l === 'cpp') return 'native'
    if (l === 'http' || l === 'wire' || l === 'endpoint' || l === 'server') return 'http'
    return 'business'
  }

  function layerStyle(layer) {
    return LAYER_STYLE[normalizeLayer(layer)] || LAYER_STYLE.business
  }

  function confidenceColor(conf) {
    const c = String(conf || '').toLowerCase()
    if (c === 'high') return 'var(--status-success)'
    if (c === 'medium') return 'var(--status-warning)'
    return 'var(--text-faint)'
  }

  function trunc(str, max) {
    const s = String(str || '').trim()
    if (s.length <= max) return s
    return s.slice(0, max - 1) + '…'
  }

  function inferLayerFromLegacyLabel(label, edgeType) {
    const s = String(label || '').toLowerCase()
    const tpe = String(edgeType || '').toLowerCase()
    if (tpe === 'http' || s.startsWith('http') || s.startsWith('get ') || s.startsWith('post ')) return 'http'
    if (tpe === 'jni' || tpe === 'native_call' || s.endsWith('.so') || s.includes('java_')) return 'native'
    if (s.includes('sign') || s.includes('crypt') || s.includes('hmac') || s.includes('md5') || s.includes('sha')) return 'crypto'
    if (s.includes('okhttp') || s.includes('retrofit') || s.includes('http') || s.includes('api') || s.includes('client')) return 'network'
    if (s.includes('activity') || s.includes('fragment') || s === 'app') return 'entry'
    return 'business'
  }

  // Normalize graph data with graceful fallback to legacy `callGraph`
  function normalizeGraphData(g, legacyEdges) {
    const rawNodes = Array.isArray(g?.nodes) ? g.nodes : []
    const rawEdges = Array.isArray(g?.edges) ? g.edges : []
    const rawSeq = Array.isArray(g?.sequence) ? g.sequence : []

    if (rawNodes.length > 0) {
      const nodes = rawNodes.map((n) => ({
        id: String(n.id ?? n.ID ?? ''),
        label: String(n.label ?? n.Label ?? n.id ?? ''),
        sublabel: String(n.sublabel ?? n.Sublabel ?? ''),
        layer: normalizeLayer(n.layer ?? n.Layer),
        module_id: String(n.module_id ?? n.ModuleID ?? ''),
        kind: String(n.kind ?? n.Kind ?? 'method').toLowerCase(),
        confidence: String(n.confidence ?? n.Confidence ?? 'medium').toLowerCase(),
        evidence_count: Number(n.evidence_count ?? n.EvidenceCount ?? 0),
        details: Array.isArray(n.details ?? n.Details) ? (n.details ?? n.Details) : [],
        matched_terms: Array.isArray(n.matched_terms ?? n.MatchedTerms) ? (n.matched_terms ?? n.MatchedTerms) : [],
        file: String(n.file ?? n.File ?? ''),
        raw: n,
      })).filter((n) => n.id)

      const nodeSet = new Set(nodes.map((n) => n.id))
      const edges = rawEdges.map((e, i) => ({
        id: String(e.id ?? e.ID ?? `e-${i}`),
        from: String(e.from ?? e.From ?? ''),
        to: String(e.to ?? e.To ?? ''),
        type: String(e.type ?? e.Type ?? 'call').toLowerCase(),
        label: String(e.label ?? e.Label ?? ''),
        weight: Math.max(1, Number(e.weight ?? e.Weight ?? 1)),
      })).filter((e) => nodeSet.has(e.from) && nodeSet.has(e.to) && e.from !== e.to)

      const sequence = rawSeq.map((s, i) => ({
        order: Number(s.order ?? s.Order ?? i + 1),
        from: String(s.from ?? s.From ?? ''),
        from_layer: normalizeLayer(s.from_layer ?? s.FromLayer),
        to: String(s.to ?? s.To ?? ''),
        to_layer: normalizeLayer(s.to_layer ?? s.ToLayer),
        action: String(s.action ?? s.Action ?? ''),
        detail: String(s.detail ?? s.Detail ?? ''),
        evidence: String(s.evidence ?? s.Evidence ?? ''),
      })).filter((s) => s.from && s.to)

      return { nodes, edges, sequence }
    }

    // Fallback: synthesize from legacy callGraph edges
    const leg = Array.isArray(legacyEdges) ? legacyEdges : []
    if (leg.length === 0) return { nodes: [], edges: [], sequence: [] }

    const map = new Map()
    const edges = []
    const sequence = []

    leg.forEach((e, idx) => {
      const from = String(e.from ?? e.From ?? '').trim()
      const to = String(e.to ?? e.To ?? '').trim()
      if (!from || !to) return
      const type = String(e.type ?? e.Type ?? 'call').toLowerCase()
      const detail = String(e.detail ?? e.Detail ?? '')
      if (!map.has(from)) {
        const layer = inferLayerFromLegacyLabel(from, '')
        map.set(from, {
          id: from,
          label: trunc(from, 30),
          sublabel: layer,
          layer,
          module_id: `mod-${layer}`,
          kind: layer === 'http' ? 'endpoint' : layer === 'native' ? 'native_fn' : 'method',
          confidence: 'medium',
          evidence_count: 1,
          details: detail ? [detail] : [],
          matched_terms: [],
          file: '',
        })
      }
      if (!map.has(to)) {
        const layer = inferLayerFromLegacyLabel(to, type)
        map.set(to, {
          id: to,
          label: trunc(to, 30),
          sublabel: layer,
          layer,
          module_id: `mod-${layer}`,
          kind: layer === 'http' ? 'endpoint' : layer === 'native' ? 'native_fn' : 'method',
          confidence: 'medium',
          evidence_count: 1,
          details: detail ? [detail] : [],
          matched_terms: [],
          file: '',
        })
      }
      edges.push({ id: `leg-${idx}`, from, to, type, label: detail || type, weight: 1 })
      sequence.push({
        order: idx + 1,
        from,
        from_layer: map.get(from).layer,
        to,
        to_layer: map.get(to).layer,
        action: type,
        detail,
        evidence: '',
      })
    })

    return { nodes: Array.from(map.values()), edges, sequence }
  }

  $: norm = normalizeGraphData(graph, callGraph)

  // ==================== Perspective 1: Execution Flow Swimlane DAG ====================
  function computeFlowLayout(nodes, edges) {
    if (!nodes.length) {
      return { width: 800, height: 420, lanes: [], placed: [], edges: [], nodeById: new Map() }
    }

    const LANE_W = 248
    const LANE_GAP = 56
    const NODE_W = 220
    const NODE_H = 70
    const NODE_GAP_Y = 22
    const HEADER_H = 44
    const PAD_X = 28
    const PAD_Y = 22

    const byLayer = new Map()
    for (const l of LAYER_ORDER) byLayer.set(l, [])
    for (const n of nodes) {
      const l = normalizeLayer(n.layer)
      if (!byLayer.has(l)) byLayer.set(l, [])
      byLayer.get(l).push(n)
    }

    const activeLayers = LAYER_ORDER.filter((l) => (byLayer.get(l)?.length || 0) > 0)
    const incoming = new Map()
    for (const e of edges) {
      if (!incoming.has(e.to)) incoming.set(e.to, [])
      incoming.get(e.to).push(e.from)
    }

    const rankInLayer = new Map()
    const lanes = []
    const placed = []
    const nodeById = new Map()
    let maxNodesInLane = 1

    activeLayers.forEach((layer, colIdx) => {
      const list = [...byLayer.get(layer)]
      if (colIdx === 0) {
        list.sort((a, b) => (b.evidence_count - a.evidence_count) || a.label.localeCompare(b.label))
      } else {
        // Barycenter sort against already-ranked upstream neighbors to minimize crossings
        list.sort((a, b) => {
          const avg = (id) => {
            const preds = (incoming.get(id) || []).filter((p) => rankInLayer.has(p))
            if (!preds.length) return 999
            return preds.reduce((sum, p) => sum + rankInLayer.get(p), 0) / preds.length
          }
          const da = avg(a.id)
          const db = avg(b.id)
          if (da !== db) return da - db
          return (b.evidence_count - a.evidence_count) || a.label.localeCompare(b.label)
        })
      }

      if (list.length > maxNodesInLane) maxNodesInLane = list.length

      const laneX = PAD_X + colIdx * (LANE_W + LANE_GAP)
      lanes.push({
        layer,
        x: laneX,
        y: PAD_Y,
        w: LANE_W,
        count: list.length,
        style: layerStyle(layer),
      })

      list.forEach((n, rowIdx) => {
        rankInLayer.set(n.id, rowIdx)
        const x = laneX + (LANE_W - NODE_W) / 2
        const y = PAD_Y + HEADER_H + 16 + rowIdx * (NODE_H + NODE_GAP_Y)
        const item = {
          ...n,
          colIdx,
          rowIdx,
          x,
          y,
          w: NODE_W,
          h: NODE_H,
          cx: x + NODE_W / 2,
          cy: y + NODE_H / 2,
          style: layerStyle(n.layer),
        }
        placed.push(item)
        nodeById.set(n.id, item)
      })
    })

    const contentH = HEADER_H + 24 + maxNodesInLane * NODE_H + Math.max(0, maxNodesInLane - 1) * NODE_GAP_Y + 24
    const laneH = Math.max(300, contentH)
    lanes.forEach((l) => { l.h = laneH })

    const totalW = PAD_X * 2 + activeLayers.length * LANE_W + Math.max(0, activeLayers.length - 1) * LANE_GAP
    const totalH = PAD_Y * 2 + laneH

    // Compute smooth cubic Bezier paths
    const routedEdges = edges.map((e) => {
      const src = nodeById.get(e.from)
      const dst = nodeById.get(e.to)
      if (!src || !dst) return null

      let d = ''
      let lx = 0
      let ly = 0

      if (src.colIdx < dst.colIdx) {
        const x1 = src.x + src.w
        const y1 = src.cy
        const x2 = dst.x
        const y2 = dst.cy
        const dx = Math.max(40, (x2 - x1) * 0.5)
        d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
        lx = (x1 + x2) / 2
        ly = (y1 + y2) / 2
      } else if (src.colIdx > dst.colIdx) {
        const x1 = src.x
        const y1 = src.cy
        const x2 = dst.x + dst.w
        const y2 = dst.cy
        const dx = Math.max(40, (x1 - x2) * 0.5)
        d = `M ${x1} ${y1} C ${x1 - dx} ${y1}, ${x2 + dx} ${y2}, ${x2} ${y2}`
        lx = (x1 + x2) / 2
        ly = (y1 + y2) / 2 - 12
      } else {
        // Same swimlane: clean right-side arc
        const x1 = src.x + src.w
        const y1 = src.cy
        const x2 = dst.x + dst.w
        const y2 = dst.cy
        const arc = 34 + Math.min(28, Math.abs(dst.rowIdx - src.rowIdx) * 10)
        d = `M ${x1} ${y1} C ${x1 + arc} ${y1}, ${x2 + arc} ${y2}, ${x2} ${y2}`
        lx = x1 + arc * 0.78
        ly = (y1 + y2) / 2
      }

      return {
        ...e,
        d,
        lx,
        ly,
        displayLabel: trunc(e.label || translate(`traceGraph.edgeTypes.${e.type}`), 20),
      }
    }).filter(Boolean)

    return { width: Math.max(680, totalW), height: Math.max(360, totalH), lanes, placed, edges: routedEdges, nodeById }
  }

  // ==================== Perspective 2: Module Architecture Map ====================
  function computeModuleLayout(rawModules, nodes, edges) {
    const modList = []
    const modMap = new Map()

    const incomingMods = Array.isArray(rawModules) ? rawModules : []
    for (const m of incomingMods) {
      const id = String(m.id ?? m.ID ?? m.name ?? m.Name ?? '')
      if (!id || modMap.has(id)) continue
      const item = {
        id,
        name: String(m.name ?? m.Name ?? id),
        layer: normalizeLayer(m.layer ?? m.Layer),
        package_prefix: String(m.package_prefix ?? m.PackagePrefix ?? ''),
        role: String(m.role ?? m.Role ?? ''),
        class_count: Number(m.class_count ?? m.ClassCount ?? 0),
        method_count: Number(m.method_count ?? m.MethodCount ?? 0),
        native_libs: Array.isArray(m.native_libs ?? m.NativeLibs) ? (m.native_libs ?? m.NativeLibs) : [],
        key_symbols: Array.isArray(m.key_symbols ?? m.KeySymbols) ? (m.key_symbols ?? m.KeySymbols) : [],
        matched_terms: Array.isArray(m.matched_terms ?? m.MatchedTerms) ? (m.matched_terms ?? m.MatchedTerms) : [],
        evidence_count: Number(m.evidence_count ?? m.EvidenceCount ?? 0),
        confidence: String(m.confidence ?? m.Confidence ?? 'medium').toLowerCase(),
        raw: m,
      }
      modMap.set(id, item)
      modList.push(item)
    }

    // Ensure every graph node maps to a module (synthesizes missing/HTTP modules cleanly)
    const nodeToMod = new Map()
    for (const n of nodes) {
      const mid = n.module_id && modMap.has(n.module_id) ? n.module_id : `layer:${n.layer}`
      nodeToMod.set(n.id, mid)
      if (!modMap.has(mid)) {
        const syn = {
          id: mid,
          name: n.layer === 'http' ? (n.label || 'HTTP Wire') : translate(`traceGraph.layers.${n.layer}`),
          layer: n.layer,
          package_prefix: n.sublabel || '',
          role: n.layer === 'http' ? (n.sublabel || 'Target Endpoint') : '',
          class_count: n.kind === 'class' ? 1 : 0,
          method_count: n.kind === 'method' || n.kind === 'native_fn' ? 1 : 0,
          native_libs: n.kind === 'native_lib' ? [n.label] : [],
          key_symbols: [n.label],
          matched_terms: n.matched_terms || [],
          evidence_count: n.evidence_count || 1,
          confidence: n.confidence || 'medium',
          raw: n,
        }
        modMap.set(mid, syn)
        modList.push(syn)
      }
    }

    if (!modList.length) {
      return { width: 800, height: 420, lanes: [], placed: [], edges: [], modById: new Map() }
    }

    // Aggregate cross-module edges
    const aggEdges = new Map()
    for (const e of edges) {
      const sm = nodeToMod.get(e.from)
      const dm = nodeToMod.get(e.to)
      if (!sm || !dm || sm === dm) continue
      const key = `${sm}-->${dm}`
      if (!aggEdges.has(key)) {
        aggEdges.set(key, { id: key, from: sm, to: dm, type: e.type, label: e.label, weight: e.weight || 1 })
      } else {
        const cur = aggEdges.get(key)
        cur.weight += e.weight || 1
      }
    }

    const LANE_W = 280
    const LANE_GAP = 64
    const CARD_W = 252
    const CARD_H = 122
    const CARD_GAP_Y = 24
    const HEADER_H = 44
    const PAD_X = 28
    const PAD_Y = 22

    const byLayer = new Map()
    for (const l of LAYER_ORDER) byLayer.set(l, [])
    for (const m of modList) {
      const l = normalizeLayer(m.layer)
      if (!byLayer.has(l)) byLayer.set(l, [])
      byLayer.get(l).push(m)
    }

    const activeLayers = LAYER_ORDER.filter((l) => (byLayer.get(l)?.length || 0) > 0)
    const lanes = []
    const placed = []
    const modById = new Map()
    let maxRows = 1

    activeLayers.forEach((layer, colIdx) => {
      const list = [...byLayer.get(layer)].sort((a, b) => (b.evidence_count - a.evidence_count) || a.name.localeCompare(b.name))
      if (list.length > maxRows) maxRows = list.length

      const laneX = PAD_X + colIdx * (LANE_W + LANE_GAP)
      lanes.push({ layer, x: laneX, y: PAD_Y, w: LANE_W, count: list.length, style: layerStyle(layer) })

      list.forEach((m, rowIdx) => {
        const x = laneX + (LANE_W - CARD_W) / 2
        const y = PAD_Y + HEADER_H + 16 + rowIdx * (CARD_H + CARD_GAP_Y)
        const card = {
          ...m,
          colIdx,
          rowIdx,
          x,
          y,
          w: CARD_W,
          h: CARD_H,
          cx: x + CARD_W / 2,
          cy: y + CARD_H / 2,
          style: layerStyle(m.layer),
        }
        placed.push(card)
        modById.set(m.id, card)
      })
    })

    const laneH = Math.max(320, HEADER_H + 24 + maxRows * CARD_H + Math.max(0, maxRows - 1) * CARD_GAP_Y + 24)
    lanes.forEach((l) => { l.h = laneH })

    const totalW = PAD_X * 2 + activeLayers.length * LANE_W + Math.max(0, activeLayers.length - 1) * LANE_GAP
    const totalH = PAD_Y * 2 + laneH

    const routedEdges = Array.from(aggEdges.values()).map((e) => {
      const src = modById.get(e.from)
      const dst = modById.get(e.to)
      if (!src || !dst) return null

      let d = ''
      let lx = 0
      let ly = 0

      if (src.colIdx < dst.colIdx) {
        const x1 = src.x + src.w
        const y1 = src.cy
        const x2 = dst.x
        const y2 = dst.cy
        const dx = Math.max(44, (x2 - x1) * 0.48)
        d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`
        lx = (x1 + x2) / 2
        ly = (y1 + y2) / 2
      } else if (src.colIdx > dst.colIdx) {
        const x1 = src.x
        const y1 = src.cy
        const x2 = dst.x + dst.w
        const y2 = dst.cy
        const dx = Math.max(44, (x1 - x2) * 0.48)
        d = `M ${x1} ${y1} C ${x1 - dx} ${y1}, ${x2 + dx} ${y2}, ${x2} ${y2}`
        lx = (x1 + x2) / 2
        ly = (y1 + y2) / 2 - 14
      } else {
        const x1 = src.x + src.w
        const y1 = src.cy
        const x2 = dst.x + dst.w
        const y2 = dst.cy
        const arc = 40
        d = `M ${x1} ${y1} C ${x1 + arc} ${y1}, ${x2 + arc} ${y2}, ${x2} ${y2}`
        lx = x1 + arc * 0.8
        ly = (y1 + y2) / 2
      }

      const typeLabel = translate(`traceGraph.edgeTypes.${e.type}`)
      const displayLabel = e.weight > 1 ? `${typeLabel} ×${e.weight}` : typeLabel
      return {
        ...e,
        d,
        lx,
        ly,
        strokeWidth: Math.min(3.2, 1.5 + Math.log2(e.weight + 1) * 0.65),
        displayLabel,
      }
    }).filter(Boolean)

    return { width: Math.max(680, totalW), height: Math.max(380, totalH), lanes, placed, edges: routedEdges, modById }
  }

  // ==================== Perspective 3: Call Sequence UML Diagram ====================
  function computeSequenceLayout(sequence, nodes, edges) {
    let steps = Array.isArray(sequence) ? [...sequence] : []

    // Fallback synthesis if backend didn't emit explicit sequence
    if (!steps.length && edges.length) {
      const nodeMap = new Map(nodes.map((n) => [n.id, n]))
      steps = edges.slice(0, 20).map((e, i) => {
        const sn = nodeMap.get(e.from)
        const dn = nodeMap.get(e.to)
        return {
          order: i + 1,
          from: sn?.label || e.from,
          from_layer: sn?.layer || 'business',
          to: dn?.label || e.to,
          to_layer: dn?.layer || 'http',
          action: e.label || translate(`traceGraph.edgeTypes.${e.type}`),
          detail: dn?.sublabel || '',
          evidence: '',
        }
      })
    }

    if (!steps.length) {
      return { width: 800, height: 380, actors: [], steps: [], topY: 24, bottomY: 320 }
    }

    steps.sort((a, b) => a.order - b.order)

    const actorMap = new Map()
    const addActor = (name, layer) => {
      if (!name || actorMap.has(name)) return
      actorMap.set(name, { id: name, name, layer: normalizeLayer(layer), style: layerStyle(layer) })
    }
    for (const s of steps) {
      addActor(s.from, s.from_layer)
      addActor(s.to, s.to_layer)
    }

    const ACTOR_W = 166
    const ACTOR_H = 46
    const ACTOR_GAP = 42
    const PAD_X = 36
    const TOP_Y = 24
    const STEP_START_Y = TOP_Y + ACTOR_H + 38
    const STEP_PITCH = 60

    const actors = Array.from(actorMap.values()).map((a, idx) => {
      const x = PAD_X + idx * (ACTOR_W + ACTOR_GAP)
      return {
        ...a,
        idx,
        x,
        y: TOP_Y,
        w: ACTOR_W,
        h: ACTOR_H,
        cx: x + ACTOR_W / 2,
        firstStep: Infinity,
        lastStep: -1,
      }
    })

    const actorByName = new Map(actors.map((a) => [a.name, a]))

    const laidSteps = steps.map((s, idx) => {
      const src = actorByName.get(s.from)
      const dst = actorByName.get(s.to)
      if (!src || !dst) return null
      const y = STEP_START_Y + idx * STEP_PITCH
      src.firstStep = Math.min(src.firstStep, idx)
      src.lastStep = Math.max(src.lastStep, idx)
      dst.firstStep = Math.min(dst.firstStep, idx)
      dst.lastStep = Math.max(dst.lastStep, idx)

      const isSelf = src.idx === dst.idx
      const leftToRight = src.cx <= dst.cx
      const x1 = src.cx + (isSelf ? 5 : leftToRight ? 5 : -5)
      const x2 = dst.cx + (isSelf ? 5 : leftToRight ? -6 : 6)

      return {
        ...s,
        idx,
        y,
        x1,
        x2,
        isSelf,
        leftToRight,
        midX: isSelf ? src.cx + 58 : (x1 + x2) / 2,
        style: layerStyle(s.to_layer),
      }
    }).filter(Boolean)

    const bottomY = STEP_START_Y + laidSteps.length * STEP_PITCH + 20
    const totalW = PAD_X * 2 + actors.length * ACTOR_W + Math.max(0, actors.length - 1) * ACTOR_GAP
    const totalH = bottomY + ACTOR_H + 24

    // Compute activation bar segments per actor
    actors.forEach((a) => {
      if (a.lastStep >= a.firstStep) {
        a.actY = STEP_START_Y + a.firstStep * STEP_PITCH - 10
        a.actH = (a.lastStep - a.firstStep) * STEP_PITCH + 24
      } else {
        a.actY = 0
        a.actH = 0
      }
    })

    return { width: Math.max(680, totalW), height: Math.max(360, totalH), actors, steps: laidSteps, topY: TOP_Y, bottomY }
  }

  $: flowLayout = computeFlowLayout(norm.nodes, norm.edges)
  $: moduleLayout = computeModuleLayout(modules, norm.nodes, norm.edges)
  $: seqLayout = computeSequenceLayout(norm.sequence, norm.nodes, norm.edges)

  $: activeCanvas =
    perspective === 'flow'
      ? { width: flowLayout.width, height: flowLayout.height }
      : perspective === 'modules'
        ? { width: moduleLayout.width, height: moduleLayout.height }
        : { width: seqLayout.width, height: seqLayout.height }

  $: hasData =
    perspective === 'flow'
      ? flowLayout.placed.length > 0
      : perspective === 'modules'
        ? moduleLayout.placed.length > 0
        : seqLayout.steps.length > 0

  $: activeLegendLayers = (() => {
    const set = new Set()
    if (perspective === 'flow') flowLayout.lanes.forEach((l) => set.add(l.layer))
    else if (perspective === 'modules') moduleLayout.lanes.forEach((l) => set.add(l.layer))
    else seqLayout.actors.forEach((a) => set.add(a.layer))
    return LAYER_ORDER.filter((l) => set.has(l))
  })()

  // ==================== Interactive Upstream + Downstream Path Highlighting ====================
  function computeHighlightSet(edges, targetId) {
    if (!targetId) return { nodes: null, edges: null }
    const nodesSet = new Set([targetId])
    const edgesSet = new Set()

    // Downstream BFS
    const downQ = [targetId]
    const seenDown = new Set([targetId])
    while (downQ.length) {
      const cur = downQ.shift()
      for (const e of edges) {
        if (e.from === cur) {
          edgesSet.add(e.id)
          nodesSet.add(e.to)
          if (!seenDown.has(e.to)) {
            seenDown.add(e.to)
            downQ.push(e.to)
          }
        }
      }
    }

    // Upstream BFS
    const upQ = [targetId]
    const seenUp = new Set([targetId])
    while (upQ.length) {
      const cur = upQ.shift()
      for (const e of edges) {
        if (e.to === cur) {
          edgesSet.add(e.id)
          nodesSet.add(e.from)
          if (!seenUp.has(e.from)) {
            seenUp.add(e.from)
            upQ.push(e.from)
          }
        }
      }
    }

    return { nodes: nodesSet, edges: edgesSet }
  }

  $: activeFocusId = hoveredId || selectedNodeId
  $: flowHL = perspective === 'flow' ? computeHighlightSet(flowLayout.edges, activeFocusId) : { nodes: null, edges: null }
  $: modHL = perspective === 'modules' ? computeHighlightSet(moduleLayout.edges, activeFocusId) : { nodes: null, edges: null }

  // ==================== Pan, Zoom & Fit-to-View ====================
  function fitToView() {
    if (!viewportEl) return
    const rect = viewportEl.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return
    const pad = 28
    const scaleX = (rect.width - pad * 2) / activeCanvas.width
    const scaleY = (rect.height - pad * 2) / activeCanvas.height
    const nextZoom = Math.max(0.4, Math.min(1.15, Math.min(scaleX, scaleY)))
    zoom = Math.round(nextZoom * 100) / 100
    panX = Math.max(12, Math.round((rect.width - activeCanvas.width * zoom) / 2))
    panY = Math.max(12, Math.round((rect.height - activeCanvas.height * zoom) / 2))
  }

  function resetZoom() {
    zoom = 1
    panX = 24
    panY = 20
  }

  function stepZoom(delta) {
    const next = Math.max(0.35, Math.min(2.2, Math.round((zoom + delta) * 100) / 100))
    if (!viewportEl) {
      zoom = next
      return
    }
    const rect = viewportEl.getBoundingClientRect()
    const cx = rect.width / 2
    const cy = rect.height / 2
    const ratio = next / zoom
    panX = cx - (cx - panX) * ratio
    panY = cy - (cy - panY) * ratio
    zoom = next
  }

  function onWheel(e) {
    if (!viewportEl) return
    e.preventDefault()
    const rect = viewportEl.getBoundingClientRect()
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const factor = e.deltaY < 0 ? 1.1 : 0.91
    const next = Math.max(0.35, Math.min(2.2, zoom * factor))
    const ratio = next / zoom
    panX = mx - (mx - panX) * ratio
    panY = my - (my - panY) * ratio
    zoom = Math.round(next * 100) / 100
  }

  function onPointerDown(e) {
    if (e.button !== 0) return
    isPanning = true
    panMoved = false
    panStartX = e.clientX
    panStartY = e.clientY
    panOriginX = panX
    panOriginY = panY
    viewportEl?.setPointerCapture?.(e.pointerId)
  }

  function onPointerMove(e) {
    if (!isPanning) return
    const dx = e.clientX - panStartX
    const dy = e.clientY - panStartY
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) panMoved = true
    panX = panOriginX + dx
    panY = panOriginY + dy
  }

  function onPointerUp(e) {
    if (!isPanning) return
    isPanning = false
    viewportEl?.releasePointerCapture?.(e.pointerId)
  }

  // ==================== Node / Module / Sequence Selection ====================
  function selectFlowNode(node) {
    if (panMoved) return
    selectedNodeId = node.id
    dispatch('selectNode', { node })
  }

  function selectModuleCard(mod) {
    if (panMoved) return
    selectedNodeId = mod.id
    dispatch('selectNode', {
      node: {
        id: mod.id,
        label: mod.name,
        sublabel: mod.package_prefix || mod.role,
        layer: mod.layer,
        module_id: mod.id,
        kind: 'module',
        confidence: mod.confidence,
        evidence_count: mod.evidence_count,
        details: [
          mod.role,
          ...(mod.key_symbols || []).slice(0, 6),
          ...(mod.native_libs || []).map((l) => `SO: ${l}`),
        ].filter(Boolean),
        matched_terms: mod.matched_terms || [],
        file: mod.package_prefix || '',
        isModule: true,
        module: mod.raw || mod,
      },
    })
  }

  function selectSequenceStep(step) {
    if (panMoved) return
    const matchNode = norm.nodes.find((n) => n.label === step.to || n.id === step.to || n.label === step.from)
    if (matchNode) {
      selectedNodeId = matchNode.id
      dispatch('selectNode', { node: { ...matchNode, sequenceStep: step } })
      return
    }
    const synId = `seq-${step.order}`
    selectedNodeId = synId
    dispatch('selectNode', {
      node: {
        id: synId,
        label: `${step.from} → ${step.to}`,
        sublabel: step.action,
        layer: step.to_layer,
        kind: 'method',
        confidence: 'medium',
        evidence_count: step.evidence ? 1 : 0,
        details: [step.detail, step.evidence].filter(Boolean),
        matched_terms: [],
        file: '',
        sequenceStep: step,
      },
    })
  }

  // ==================== Standalone SVG Export ====================
  function exportStandaloneSvg() {
    if (!svgEl) return
    try {
      const clone = svgEl.cloneNode(true)
      const cs = getComputedStyle(document.documentElement)
      const bg = cs.getPropertyValue('--bg-app').trim() || '#0b0c10'

      clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
      clone.setAttribute('width', String(activeCanvas.width))
      clone.setAttribute('height', String(activeCanvas.height))
      clone.setAttribute('viewBox', `0 0 ${activeCanvas.width} ${activeCanvas.height}`)

      // Reset pan/zoom group transform on exported full canvas
      const vpGroup = clone.querySelector('[data-viewport-group="true"]')
      if (vpGroup) vpGroup.setAttribute('transform', 'translate(0, 0) scale(1)')

      // Inject solid background rect so exported SVG looks crisp anywhere
      const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect')
      bgRect.setAttribute('x', '0')
      bgRect.setAttribute('y', '0')
      bgRect.setAttribute('width', String(activeCanvas.width))
      bgRect.setAttribute('height', String(activeCanvas.height))
      bgRect.setAttribute('fill', bg)
      clone.insertBefore(bgRect, clone.firstChild)

      // Resolve CSS var(--...) inline so standalone SVG viewers render exact theme colors
      let serialized = new XMLSerializer().serializeToString(clone)
      serialized = serialized.replace(/var\((--[a-zA-Z0-9-]+)\)/g, (_, varName) => {
        const val = cs.getPropertyValue(varName).trim()
        return val || '#888888'
      })

      const blob = new Blob([serialized], { type: 'image/svg+xml;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `cap-deeptrace-${perspective}.svg`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      toast.success(translate('traceGraph.toast.svgExported'))
    } catch (_) {
      toast.error(translate('traceGraph.toast.svgExportFailed'))
    }
  }

  let lastFitSignature = ''
  $: fitSig = `${perspective}:${activeCanvas.width}x${activeCanvas.height}:${norm.nodes.length}:${modules?.length || 0}`
  $: if (viewportEl && hasData && fitSig !== lastFitSignature) {
    lastFitSignature = fitSig
    tick().then(fitToView)
  }

  onMount(() => {
    tick().then(fitToView)
  })
</script>

<div class="trace-graph">
  <!-- Top Commercial Graph Toolbar -->
  <div class="tg-toolbar">
    <div class="tg-perspectives" role="tablist">
      <button
        type="button"
        role="tab"
        aria-selected={perspective === 'flow'}
        class="persp-btn"
        class:active={perspective === 'flow'}
        on:click={() => (perspective = 'flow')}
      >
        <Icon name="git-branch" size={13} />
        <span>{$t('traceGraph.perspectives.flow')}</span>
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={perspective === 'modules'}
        class="persp-btn"
        class:active={perspective === 'modules'}
        on:click={() => (perspective = 'modules')}
      >
        <Icon name="layers" size={13} />
        <span>{$t('traceGraph.perspectives.modules')}</span>
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={perspective === 'sequence'}
        class="persp-btn"
        class:active={perspective === 'sequence'}
        on:click={() => (perspective = 'sequence')}
      >
        <Icon name="activity" size={13} />
        <span>{$t('traceGraph.perspectives.sequence')}</span>
      </button>
    </div>

    <div class="tg-stats mono tabular-nums">
      {#if perspective === 'flow'}
        {$t('traceGraph.stats.flow', { nodes: flowLayout.placed.length, edges: flowLayout.edges.length })}
      {:else if perspective === 'modules'}
        {$t('traceGraph.stats.modules', { modules: moduleLayout.placed.length, links: moduleLayout.edges.length })}
      {:else}
        {$t('traceGraph.stats.sequence', { actors: seqLayout.actors.length, steps: seqLayout.steps.length })}
      {/if}
    </div>

    <div class="tg-controls">
      <div class="zoom-group">
        <button type="button" class="zoom-btn" title={$t('traceGraph.controls.zoomOut')} on:click={() => stepZoom(-0.15)}>
          <Icon name="minus" size={12} />
        </button>
        <button type="button" class="zoom-pct mono tabular-nums" title={$t('traceGraph.controls.resetZoomTooltip')} on:click={resetZoom}>
          {Math.round(zoom * 100)}%
        </button>
        <button type="button" class="zoom-btn" title={$t('traceGraph.controls.zoomIn')} on:click={() => stepZoom(0.15)}>
          <Icon name="plus" size={12} />
        </button>
        <button type="button" class="zoom-fit" title={$t('traceGraph.controls.fitTooltip')} on:click={fitToView}>
          {$t('traceGraph.controls.fitView')}
        </button>
      </div>

      <Button
        variant="secondary"
        size="xs"
        icon="download"
        disabled={!hasData}
        title={$t('traceGraph.controls.exportSvgTooltip')}
        on:click={exportStandaloneSvg}
      >
        {$t('traceGraph.controls.exportSvg')}
      </Button>
    </div>
  </div>

  <!-- Interactive SVG Viewport -->
  {#if !hasData}
    <div class="tg-empty">
      <EmptyState
        icon="git-branch"
        title={$t('traceGraph.empty.title')}
        description={$t('traceGraph.empty.description')}
      />
    </div>
  {:else}
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      bind:this={viewportEl}
      class="tg-viewport"
      class:panning={isPanning}
      role="region"
      aria-label={$t(`traceGraph.perspectives.${perspective}`)}
      on:wheel|nonpassive={onWheel}
      on:pointerdown={onPointerDown}
      on:pointermove={onPointerMove}
      on:pointerup={onPointerUp}
      on:pointercancel={onPointerUp}
    >
      <svg bind:this={svgEl} class="tg-svg" width="100%" height="100%">
        <defs>
          <marker id="tg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
            <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="var(--text-faint)" />
          </marker>
          <marker id="tg-arrow-hl" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="var(--accent)" />
          </marker>
        </defs>

        <g data-viewport-group="true" transform="translate({panX}, {panY}) scale({zoom})">
          <!-- ==================== PERSPECTIVE 1: EXECUTION FLOW ==================== -->
          {#if perspective === 'flow'}
            <!-- Swimlane Background Columns -->
            {#each flowLayout.lanes as lane (lane.layer)}
              <g class="swimlane">
                <rect
                  x={lane.x}
                  y={lane.y}
                  width={lane.w}
                  height={lane.h}
                  rx="12"
                  fill="var(--bg-surface)"
                  fill-opacity="0.62"
                  stroke="var(--border-subtle)"
                  stroke-width="1"
                />
                <rect
                  x={lane.x}
                  y={lane.y}
                  width={lane.w}
                  height="38"
                  rx="12"
                  fill={lane.style.soft}
                />
                <circle cx={lane.x + 16} cy={lane.y + 19} r="4" fill={lane.style.color} />
                <text x={lane.x + 27} y={lane.y + 23} fill="var(--text-primary)" font-size="11.5" font-weight="600" font-family="var(--font-sans)">
                  {$t(`traceGraph.layers.${lane.layer}`)}
                </text>
                <rect x={lane.x + lane.w - 34} y={lane.y + 10} width="24" height="18" rx="9" fill="var(--bg-app)" fill-opacity="0.7" />
                <text x={lane.x + lane.w - 22} y={lane.y + 22.5} text-anchor="middle" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">
                  {lane.count}
                </text>
              </g>
            {/each}

            <!-- Directed Cubic Bezier Edges -->
            {#each flowLayout.edges as edge (edge.id)}
              {@const isHl = flowHL.edges ? flowHL.edges.has(edge.id) : false}
              {@const isDim = flowHL.edges ? !isHl : false}
              <g class="tg-edge" style="opacity: {isDim ? 0.16 : 1};">
                <path
                  d={edge.d}
                  fill="none"
                  stroke={isHl ? 'var(--accent)' : 'var(--border-strong)'}
                  stroke-width={isHl ? 2.1 : 1.4}
                  marker-end={isHl ? 'url(#tg-arrow-hl)' : 'url(#tg-arrow)'}
                />
                {#if edge.displayLabel}
                  {@const pillW = Math.min(132, Math.max(44, edge.displayLabel.length * 6.2 + 14))}
                  <rect
                    x={edge.lx - pillW / 2}
                    y={edge.ly - 9}
                    width={pillW}
                    height="18"
                    rx="9"
                    fill="var(--bg-elevated)"
                    stroke={isHl ? 'var(--accent-border)' : 'var(--border-default)'}
                    stroke-width="1"
                  />
                  <text
                    x={edge.lx}
                    y={edge.ly + 3.5}
                    text-anchor="middle"
                    fill={isHl ? 'var(--accent)' : 'var(--text-muted)'}
                    font-size="9.5"
                    font-family="var(--font-mono)"
                  >
                    {edge.displayLabel}
                  </text>
                {/if}
              </g>
            {/each}

            <!-- Node Cards -->
            {#each flowLayout.placed as node (node.id)}
              {@const isSel = selectedNodeId === node.id}
              {@const isHl = flowHL.nodes ? flowHL.nodes.has(node.id) : false}
              {@const isDim = flowHL.nodes ? !isHl : false}
              <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
              <g
                class="tg-node"
                style="opacity: {isDim ? 0.26 : 1}; cursor: pointer;"
                on:mouseenter={() => (hoveredId = node.id)}
                on:mouseleave={() => { if (hoveredId === node.id) hoveredId = '' }}
                on:click|stopPropagation={() => selectFlowNode(node)}
              >
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={node.h}
                  rx="10"
                  fill="var(--bg-elevated)"
                  stroke={isSel ? 'var(--accent)' : isHl ? node.style.color : 'var(--border-default)'}
                  stroke-width={isSel ? 2 : isHl ? 1.5 : 1}
                />
                <!-- Left Accent Strip -->
                <rect x={node.x + 1} y={node.y + 8} width="3.5" height={node.h - 16} rx="2" fill={node.style.color} />

                <!-- Kind Icon -->
                <g transform="translate({node.x + 13}, {node.y + 14}) scale(0.58)" fill="none" stroke={node.style.color} stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d={KIND_GLYPH[node.kind] || KIND_GLYPH.method} />
                </g>

                <!-- Primary Label -->
                <text x={node.x + 32} y={node.y + 26} fill="var(--text-primary)" font-size="12" font-weight="600" font-family="var(--font-sans)">
                  {trunc(node.label, 21)}
                </text>

                <!-- Confidence Dot -->
                <circle cx={node.x + node.w - 14} cy={node.y + 21} r="3.5" fill={confidenceColor(node.confidence)} />

                <!-- Sublabel -->
                <text x={node.x + 14} y={node.y + 46} fill="var(--text-muted)" font-size="10.5" font-family="var(--font-mono)">
                  {trunc(node.sublabel || node.file || node.kind, 27)}
                </text>

                <!-- Footer Metadata Badges -->
                {#if node.evidence_count > 0}
                  <rect x={node.x + 14} y={node.y + 52} width="46" height="13" rx="4" fill={node.style.soft} />
                  <text x={node.x + 37} y={node.y + 61.5} text-anchor="middle" fill={node.style.color} font-size="9" font-weight="600" font-family="var(--font-mono)">
                    ×{node.evidence_count}
                  </text>
                {/if}
                {#if node.matched_terms.length > 0}
                  <text x={node.x + (node.evidence_count > 0 ? 66 : 14)} y={node.y + 61.5} fill="var(--text-faint)" font-size="9.5" font-family="var(--font-mono)">
                    {trunc(node.matched_terms.slice(0, 2).join(', '), 20)}
                  </text>
                {/if}
              </g>
            {/each}

          <!-- ==================== PERSPECTIVE 2: MODULE ARCHITECTURE ==================== -->
          {:else if perspective === 'modules'}
            {#each moduleLayout.lanes as lane (lane.layer)}
              <g class="swimlane">
                <rect
                  x={lane.x}
                  y={lane.y}
                  width={lane.w}
                  height={lane.h}
                  rx="12"
                  fill="var(--bg-surface)"
                  fill-opacity="0.58"
                  stroke="var(--border-subtle)"
                  stroke-width="1"
                />
                <rect x={lane.x} y={lane.y} width={lane.w} height="38" rx="12" fill={lane.style.soft} />
                <circle cx={lane.x + 16} cy={lane.y + 19} r="4" fill={lane.style.color} />
                <text x={lane.x + 27} y={lane.y + 23} fill="var(--text-primary)" font-size="11.5" font-weight="600" font-family="var(--font-sans)">
                  {$t(`traceGraph.layers.${lane.layer}`)}
                </text>
              </g>
            {/each}

            {#each moduleLayout.edges as edge (edge.id)}
              {@const isHl = modHL.edges ? modHL.edges.has(edge.id) : false}
              {@const isDim = modHL.edges ? !isHl : false}
              <g class="tg-edge" style="opacity: {isDim ? 0.16 : 1};">
                <path
                  d={edge.d}
                  fill="none"
                  stroke={isHl ? 'var(--accent)' : 'var(--border-strong)'}
                  stroke-width={isHl ? Math.max(2.2, edge.strokeWidth) : edge.strokeWidth}
                  marker-end={isHl ? 'url(#tg-arrow-hl)' : 'url(#tg-arrow)'}
                />
                {#if edge.displayLabel}
                  {@const pillW = Math.min(130, Math.max(50, edge.displayLabel.length * 6.4 + 14))}
                  <rect
                    x={edge.lx - pillW / 2}
                    y={edge.ly - 9}
                    width={pillW}
                    height="18"
                    rx="9"
                    fill="var(--bg-elevated)"
                    stroke={isHl ? 'var(--accent-border)' : 'var(--border-default)'}
                  />
                  <text
                    x={edge.lx}
                    y={edge.ly + 3.5}
                    text-anchor="middle"
                    fill={isHl ? 'var(--accent)' : 'var(--text-muted)'}
                    font-size="9.5"
                    font-family="var(--font-mono)"
                  >
                    {edge.displayLabel}
                  </text>
                {/if}
              </g>
            {/each}

            {#each moduleLayout.placed as mod (mod.id)}
              {@const isSel = selectedNodeId === mod.id}
              {@const isHl = modHL.nodes ? modHL.nodes.has(mod.id) : false}
              {@const isDim = modHL.nodes ? !isHl : false}
              <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
              <g
                class="tg-node"
                style="opacity: {isDim ? 0.25 : 1}; cursor: pointer;"
                on:mouseenter={() => (hoveredId = mod.id)}
                on:mouseleave={() => { if (hoveredId === mod.id) hoveredId = '' }}
                on:click|stopPropagation={() => selectModuleCard(mod)}
              >
                <rect
                  x={mod.x}
                  y={mod.y}
                  width={mod.w}
                  height={mod.h}
                  rx="12"
                  fill="var(--bg-elevated)"
                  stroke={isSel ? 'var(--accent)' : isHl ? mod.style.color : 'var(--border-default)'}
                  stroke-width={isSel ? 2 : isHl ? 1.5 : 1}
                />
                <rect x={mod.x + 1} y={mod.y + 10} width="4" height={mod.h - 20} rx="2" fill={mod.style.color} />

                <text x={mod.x + 14} y={mod.y + 24} fill="var(--text-primary)" font-size="12.5" font-weight="700" font-family="var(--font-sans)">
                  {trunc(mod.name, 24)}
                </text>
                <circle cx={mod.x + mod.w - 14} cy={mod.y + 20} r="4" fill={confidenceColor(mod.confidence)} />

                <text x={mod.x + 14} y={mod.y + 42} fill="var(--text-muted)" font-size="10.5" font-family="var(--font-mono)">
                  {trunc(mod.package_prefix || mod.layer, 30)}
                </text>

                <text x={mod.x + 14} y={mod.y + 59} fill="var(--text-secondary)" font-size="10.5" font-family="var(--font-sans)">
                  {trunc(mod.role || '', 30)}
                </text>

                <!-- Metric Chips Row -->
                <text x={mod.x + 14} y={mod.y + 82} fill={mod.style.color} font-size="10" font-weight="600" font-family="var(--font-mono)">
                  {[
                    mod.class_count > 0 ? $t('traceGraph.moduleCard.classes', { count: mod.class_count }) : '',
                    mod.method_count > 0 ? $t('traceGraph.moduleCard.methods', { count: mod.method_count }) : '',
                    mod.native_libs.length > 0 ? $t('traceGraph.moduleCard.libs', { count: mod.native_libs.length }) : '',
                    mod.evidence_count > 0 ? $t('traceGraph.moduleCard.evidence', { count: mod.evidence_count }) : '',
                  ].filter(Boolean).join(' · ')}
                </text>

                <!-- Key Symbols Preview -->
                {#if mod.key_symbols.length > 0}
                  <rect x={mod.x + 12} y={mod.y + 92} width={mod.w - 24} height="20" rx="5" fill="var(--bg-app)" fill-opacity="0.72" />
                  <text x={mod.x + 18} y={mod.y + 105} fill="var(--text-faint)" font-size="9.5" font-family="var(--font-mono)">
                    {trunc(mod.key_symbols.slice(0, 2).join(' · '), 32)}
                  </text>
                {/if}
              </g>
            {/each}

          <!-- ==================== PERSPECTIVE 3: CALL SEQUENCE (UML) ==================== -->
          {:else}
            <!-- Actor Lifelines, Headers & Activation Bars -->
            {#each seqLayout.actors as actor (actor.id)}
              <g class="seq-actor">
                <!-- Dashed vertical lifeline -->
                <line
                  x1={actor.cx}
                  y1={actor.y + actor.h}
                  x2={actor.cx}
                  y2={seqLayout.bottomY}
                  stroke="var(--border-strong)"
                  stroke-width="1.2"
                  stroke-dasharray="4 4"
                />

                <!-- Activation bar -->
                {#if actor.actH > 0}
                  <rect
                    x={actor.cx - 5}
                    y={actor.actY}
                    width="10"
                    height={actor.actH}
                    rx="3"
                    fill={actor.style.soft}
                    stroke={actor.style.color}
                    stroke-width="1.2"
                  />
                {/if}

                <!-- Top Header Box -->
                <rect
                  x={actor.x}
                  y={actor.y}
                  width={actor.w}
                  height={actor.h}
                  rx="8"
                  fill="var(--bg-elevated)"
                  stroke={actor.style.color}
                  stroke-width="1.3"
                />
                <rect x={actor.x + 1} y={actor.y + 1} width={actor.w - 2} height="4" rx="2" fill={actor.style.color} />
                <text x={actor.cx} y={actor.y + 23} text-anchor="middle" fill="var(--text-primary)" font-size="11.5" font-weight="600" font-family="var(--font-sans)">
                  {trunc(actor.name, 20)}
                </text>
                <text x={actor.cx} y={actor.y + 37} text-anchor="middle" fill={actor.style.color} font-size="9.5" font-family="var(--font-mono)">
                  {$t(`traceGraph.layers.${actor.layer}`)}
                </text>

                <!-- Bottom Footer Box -->
                <rect
                  x={actor.x}
                  y={seqLayout.bottomY}
                  width={actor.w}
                  height={actor.h - 10}
                  rx="8"
                  fill="var(--bg-surface)"
                  stroke="var(--border-default)"
                  stroke-width="1"
                />
                <text x={actor.cx} y={seqLayout.bottomY + 22} text-anchor="middle" fill="var(--text-muted)" font-size="10.5" font-weight="500" font-family="var(--font-sans)">
                  {trunc(actor.name, 20)}
                </text>
              </g>
            {/each}

            <!-- Numbered Sequence Arrows -->
            {#each seqLayout.steps as step (step.order)}
              {@const isHov = hoveredSeqIdx === step.idx}
              {@const labelText = `#${step.order}  ${trunc(step.action, 30)}`}
              {@const pillW = Math.min(240, Math.max(76, labelText.length * 6.5 + 16))}
              <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
              <g
                class="seq-step"
                style="cursor: pointer;"
                on:mouseenter={() => (hoveredSeqIdx = step.idx)}
                on:mouseleave={() => { if (hoveredSeqIdx === step.idx) hoveredSeqIdx = -1 }}
                on:click|stopPropagation={() => selectSequenceStep(step)}
              >
                <!-- Subtle hover row highlight -->
                {#if isHov}
                  <rect
                    x="12"
                    y={step.y - 24}
                    width={seqLayout.width - 24}
                    height="46"
                    rx="6"
                    fill="var(--accent-soft)"
                    fill-opacity="0.45"
                  />
                {/if}

                {#if step.isSelf}
                  <path
                    d="M {step.x1} {step.y - 8} C {step.x1 + 52} {step.y - 8}, {step.x1 + 52} {step.y + 12}, {step.x1 + 2} {step.y + 12}"
                    fill="none"
                    stroke={isHov ? 'var(--accent)' : step.style.color}
                    stroke-width={isHov ? 2.2 : 1.6}
                    marker-end={isHov ? 'url(#tg-arrow-hl)' : 'url(#tg-arrow)'}
                  />
                {:else}
                  <line
                    x1={step.x1}
                    y1={step.y}
                    x2={step.x2}
                    y2={step.y}
                    stroke={isHov ? 'var(--accent)' : step.style.color}
                    stroke-width={isHov ? 2.2 : 1.6}
                    marker-end={isHov ? 'url(#tg-arrow-hl)' : 'url(#tg-arrow)'}
                  />
                {/if}

                <!-- Step Number Pill + Action Label -->
                <rect
                  x={step.midX - pillW / 2}
                  y={step.y - 22}
                  width={pillW}
                  height="18"
                  rx="9"
                  fill="var(--bg-elevated)"
                  stroke={isHov ? 'var(--accent-border)' : 'var(--border-default)'}
                />
                <text
                  x={step.midX}
                  y={step.y - 9.5}
                  text-anchor="middle"
                  fill={isHov ? 'var(--accent)' : 'var(--text-primary)'}
                  font-size="10"
                  font-weight="600"
                  font-family="var(--font-mono)"
                >
                  {labelText}
                </text>

                {#if step.detail || step.evidence}
                  <text
                    x={step.midX}
                    y={step.y + 14}
                    text-anchor="middle"
                    fill="var(--text-muted)"
                    font-size="9.5"
                    font-family="var(--font-mono)"
                  >
                    {trunc(step.detail || step.evidence, 38)}
                  </text>
                {/if}
              </g>
            {/each}
          {/if}
        </g>
      </svg>

      <!-- Floating Bottom Layer Legend + Pan Hint -->
      <div class="tg-overlay-bottom">
        <div class="tg-legend">
          {#each activeLegendLayers as layer (layer)}
            <span class="legend-item">
              <span class="legend-dot" style="background: {layerStyle(layer).color};"></span>
              <span>{$t(`traceGraph.layers.${layer}`)}</span>
            </span>
          {/each}
        </div>
        <span class="tg-hint">{$t('traceGraph.controls.panHint')}</span>
      </div>
    </div>
  {/if}
</div>

<style>
  .trace-graph {
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100%;
    min-height: 360px;
    background: var(--bg-app);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  .tg-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 7px 10px;
    background: var(--bg-header);
    border-bottom: 1px solid var(--border-default);
    flex-wrap: wrap;
    flex-shrink: 0;
  }

  .tg-perspectives {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 2px;
    background: var(--bg-app);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-sm);
  }

  .persp-btn {
    height: 24px;
    padding: 0 9px;
    border: 1px solid transparent;
    border-radius: var(--radius-xs);
    background: transparent;
    color: var(--text-muted);
    font-size: 11.5px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }

  .persp-btn:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .persp-btn.active {
    background: var(--accent-soft);
    border-color: var(--accent-border);
    color: var(--accent);
    font-weight: 600;
  }

  .tg-stats {
    font-size: 11px;
    color: var(--text-muted);
  }

  .tg-controls {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .zoom-group {
    display: inline-flex;
    align-items: center;
    height: 24px;
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: var(--radius-xs);
    overflow: hidden;
  }

  .zoom-btn,
  .zoom-pct,
  .zoom-fit {
    height: 100%;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    transition: background var(--transition-fast), color var(--transition-fast);
  }

  .zoom-btn {
    width: 24px;
  }

  .zoom-pct {
    min-width: 42px;
    padding: 0 5px;
    border-left: 1px solid var(--border-subtle);
    border-right: 1px solid var(--border-subtle);
    font-size: 10.5px;
  }

  .zoom-fit {
    padding: 0 8px;
    border-left: 1px solid var(--border-subtle);
    font-weight: 500;
  }

  .zoom-btn:hover,
  .zoom-pct:hover,
  .zoom-fit:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .tg-empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .tg-viewport {
    position: relative;
    flex: 1;
    min-height: 300px;
    overflow: hidden;
    cursor: grab;
    user-select: none;
    background-image: radial-gradient(var(--border-subtle) 1px, transparent 1px);
    background-size: 20px 20px;
  }

  .tg-viewport.panning {
    cursor: grabbing;
  }

  .tg-svg {
    display: block;
    width: 100%;
    height: 100%;
  }

  .tg-node,
  .tg-edge {
    transition: opacity 150ms ease;
  }

  .tg-overlay-bottom {
    position: absolute;
    left: 10px;
    right: 10px;
    bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    pointer-events: none;
    flex-wrap: wrap;
  }

  .tg-legend {
    pointer-events: auto;
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 4px 10px;
    border-radius: var(--radius-full);
    background: color-mix(in srgb, var(--bg-elevated) 88%, transparent);
    backdrop-filter: blur(6px);
    border: 1px solid var(--border-default);
    font-size: 10.5px;
    color: var(--text-secondary);
    flex-wrap: wrap;
  }

  .legend-item {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    white-space: nowrap;
  }

  .legend-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .tg-hint {
    padding: 3px 9px;
    border-radius: var(--radius-full);
    background: color-mix(in srgb, var(--bg-elevated) 80%, transparent);
    border: 1px solid var(--border-subtle);
    font-size: 10px;
    color: var(--text-faint);
  }
</style>
