package exectrace

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	reHexLiteral = regexp.MustCompile(`(?:#)?0x([0-9a-fA-F]+)`)
	reRegWord    = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9]{1,4})\b`)
	reBracketMem = regexp.MustCompile(`\[([^\]]+)\]`)
)

// cryptoConstEntry associates a well-known 32-bit magic constant with its
// cryptographic algorithm and human-readable label.
type cryptoConstEntry struct {
	Algorithm string
	Label     string
	BaseConf  float64
}

var cryptoMagic32 = map[uint32]cryptoConstEntry{
	// MD5 (IVs & sine-table T constants)
	0x67452301: {"MD5", "MD5/SHA-1 IV A (0x67452301)", 0.80},
	0xefcdab89: {"MD5", "MD5/SHA-1 IV B (0xefcdab89)", 0.80},
	0x98badcfe: {"MD5", "MD5/SHA-1 IV C (0x98badcfe)", 0.80},
	0x10325476: {"MD5", "MD5/SHA-1 IV D (0x10325476)", 0.80},
	0xd76aa478: {"MD5", "MD5 T[0] (0xd76aa478)", 0.92},
	0xe8c7b756: {"MD5", "MD5 T[1] (0xe8c7b756)", 0.92},
	0x242070db: {"MD5", "MD5 T[2] (0x242070db)", 0.92},
	0xc1bdceee: {"MD5", "MD5 T[3] (0xc1bdceee)", 0.92},
	0xf57c0faf: {"MD5", "MD5 T[4] (0xf57c0faf)", 0.90},
	0x4787c62a: {"MD5", "MD5 T[5] (0x4787c62a)", 0.90},

	// SHA-1 (round constants K & H4 IV)
	0x5a827999: {"SHA-1", "SHA-1 K[0..19] (0x5a827999)", 0.92},
	0x6ed9eba1: {"SHA-1", "SHA-1 K[20..39] (0x6ed9eba1)", 0.92},
	0x8f1bbcdc: {"SHA-1", "SHA-1 K[40..59] (0x8f1bbcdc)", 0.92},
	0xca62c1d6: {"SHA-1", "SHA-1 K[60..79] (0xca62c1d6)", 0.92},
	0xc3d2e1f0: {"SHA-1", "SHA-1 IV H4 (0xc3d2e1f0)", 0.88},

	// SHA-256 (IVs & K round constants)
	0x6a09e667: {"SHA-256", "SHA-256 IV H0 (0x6a09e667)", 0.93},
	0xbb67ae85: {"SHA-256", "SHA-256 IV H1 (0xbb67ae85)", 0.93},
	0x3c6ef372: {"SHA-256", "SHA-256 IV H2 (0x3c6ef372)", 0.93},
	0xa54ff53a: {"SHA-256", "SHA-256 IV H3 (0xa54ff53a)", 0.93},
	0x510e527f: {"SHA-256", "SHA-256 IV H4 (0x510e527f)", 0.92},
	0x9b05688c: {"SHA-256", "SHA-256 IV H5 (0x9b05688c)", 0.92},
	0x1f83d9ab: {"SHA-256", "SHA-256 IV H6 (0x1f83d9ab)", 0.92},
	0x5be0cd19: {"SHA-256", "SHA-256 IV H7 (0x5be0cd19)", 0.92},
	0x428a2f98: {"SHA-256", "SHA-256 K[0] (0x428a2f98)", 0.95},
	0x71374491: {"SHA-256", "SHA-256 K[1] (0x71374491)", 0.95},
	0xb5c0fbcf: {"SHA-256", "SHA-256 K[2] (0xb5c0fbcf)", 0.94},
	0xe9b5dba5: {"SHA-256", "SHA-256 K[3] (0xe9b5dba5)", 0.94},
	0x3956c25b: {"SHA-256", "SHA-256 K[4] (0x3956c25b)", 0.93},
	0x59f111f1: {"SHA-256", "SHA-256 K[5] (0x59f111f1)", 0.93},

	// SM3 (IV & T_j)
	0x7380166f: {"SM3", "SM3 IV[0] (0x7380166f)", 0.94},
	0x4914b2b9: {"SM3", "SM3 IV[1] (0x4914b2b9)", 0.93},
	0x172442d7: {"SM3", "SM3 IV[2] (0x172442d7)", 0.93},
	0xda8a0600: {"SM3", "SM3 IV[3] (0xda8a0600)", 0.92},
	0xa96f30bc: {"SM3", "SM3 IV[4] (0xa96f30bc)", 0.92},
	0x163138aa: {"SM3", "SM3 IV[5] (0x163138aa)", 0.92},
	0xe38dee4d: {"SM3", "SM3 IV[6] (0xe38dee4d)", 0.92},
	0xb0fb0e4e: {"SM3", "SM3 IV[7] (0xb0fb0e4e)", 0.92},
	0x79cc4519: {"SM3", "SM3 T[0..15] (0x79cc4519)", 0.94},
	0x7a879d8a: {"SM3", "SM3 T[16..63] (0x7a879d8a)", 0.94},

	// AES (S-box, Inv S-box, Te0 table)
	0x637c777b: {"AES", "AES S-box[0..3] BE (0x637c777b)", 0.95},
	0x7b777c63: {"AES", "AES S-box[0..3] LE (0x7b777c63)", 0.95},
	0xf26b6fc5: {"AES", "AES S-box[4..7] BE (0xf26b6fc5)", 0.94},
	0xc56f6bf2: {"AES", "AES S-box[4..7] LE (0xc56f6bf2)", 0.94},
	0x52096ad5: {"AES", "AES InvS-box[0..3] BE (0x52096ad5)", 0.94},
	0xd56a0952: {"AES", "AES InvS-box[0..3] LE (0xd56a0952)", 0.94},
	0xc66363a5: {"AES", "AES Te0[0] (0xc66363a5)", 0.94},
	0xa56363c6: {"AES", "AES Te0[0] LE (0xa56363c6)", 0.94},

	// SM4 (FK, CK, S-box)
	0xa3b1bac6: {"SM4", "SM4 FK[0] (0xa3b1bac6)", 0.94},
	0x56aa3350: {"SM4", "SM4 FK[1] (0x56aa3350)", 0.94},
	0x677d9197: {"SM4", "SM4 FK[2] (0x677d9197)", 0.93},
	0xb27022dc: {"SM4", "SM4 FK[3] (0xb27022dc)", 0.93},
	0xd690e9fe: {"SM4", "SM4 S-box[0..3] BE (0xd690e9fe)", 0.94},
	0xfee990d6: {"SM4", "SM4 S-box[0..3] LE (0xfee990d6)", 0.94},

	// ChaCha20 ("expand 32-byte k")
	0x61707865: {"ChaCha20", "ChaCha20 sigma[0] 'expa' (0x61707865)", 0.95},
	0x65787061: {"ChaCha20", "ChaCha20 sigma[0] BE 'expa' (0x65787061)", 0.93},
	0x3320646e: {"ChaCha20", "ChaCha20 sigma[1] 'nd 3' (0x3320646e)", 0.93},
	0x79622d32: {"ChaCha20", "ChaCha20 sigma[2] '2-by' (0x79622d32)", 0.93},
	0x6b206574: {"ChaCha20", "ChaCha20 sigma[3] 'te k' (0x6b206574)", 0.93},

	// TEA / XXTEA (golden ratio delta)
	0x9e3779b9: {"TEA/XXTEA", "TEA/XXTEA delta (0x9e3779b9)", 0.93},
	0x61c88647: {"TEA/XXTEA", "TEA/XXTEA -delta (0x61c88647)", 0.90},

	// CRC32 (IEEE 802.3 & Castagnoli)
	0xedb88320: {"CRC32", "CRC32 IEEE polynomial (0xedb88320)", 0.94},
	0x04c11db7: {"CRC32", "CRC32 IEEE normal poly (0x04c11db7)", 0.92},
	0x82f63b78: {"CRC32", "CRC32C Castagnoli poly (0x82f63b78)", 0.92},
	0x77073096: {"CRC32", "CRC32 table[1] (0x77073096)", 0.90},
}

// AnalyzeSession runs full pure-Go dynamic trace analytics: call hierarchy
// reconstruction, hot function profiling, cryptographic constant and custom
// XOR/rotate round loop detection, memory region aggregation, hot loop
// discovery, and syscall statistics.
func AnalyzeSession(s *ExecTraceSession) *TraceAnalysis {
	if s == nil {
		return &TraceAnalysis{SummaryText: "Empty session"}
	}

	callTree, hotFuncs := analyzeCallTreeAndFunctions(s)
	hotLoops := analyzeHotLoops(s)
	memRegions := analyzeMemoryRegions(s)
	cryptoHits := analyzeCryptoPatterns(s, hotLoops, memRegions)
	syscalls := analyzeSyscalls(s)

	analysis := &TraceAnalysis{
		HotFunctions:  hotFuncs,
		CallTree:      callTree,
		CryptoHits:    cryptoHits,
		MemoryRegions: memRegions,
		HotLoops:      hotLoops,
		Syscalls:      syscalls,
	}
	analysis.SummaryText = buildAnalysisSummary(s, analysis)
	return analysis
}

func analyzeCallTreeAndFunctions(s *ExecTraceSession) ([]CallNode, []FunctionStat) {
	type frame struct {
		node    CallNode
		statKey string
	}

	var roots []CallNode
	stacks := make(map[int][]*frame)
	stats := make(map[string]*FunctionStat)
	nextID := 1

	getStat := func(name, mod string, addr, off uint64) (string, *FunctionStat) {
		key := name
		if key == "" {
			if off != 0 {
				key = fmt.Sprintf("%s+0x%x", mod, off)
			} else if addr != 0 {
				key = fmt.Sprintf("sub_%x", addr)
			} else {
				key = "unknown"
			}
		}
		st, ok := stats[key]
		if !ok {
			st = &FunctionStat{
				Name:    key,
				Module:  mod,
				Address: addr,
				Offset:  off,
			}
			stats[key] = st
		}
		if st.Address == 0 && addr != 0 {
			st.Address = addr
		}
		if st.Offset == 0 && off != 0 {
			st.Offset = off
		}
		return key, st
	}

	events := s.Events
	for i := range events {
		ev := events[i]
		tid := ev.ThreadID
		stStack := stacks[tid]

		switch ev.Kind {
		case KindCall, KindJavaEnter:
			name, targetAddr, targetOff := resolveCallTarget(events, i, s.ModuleBase)
			statKey, fstat := getStat(name, ev.Module, targetAddr, targetOff)
			fstat.Hits++

			if len(stStack) > 0 {
				parent := stStack[len(stStack)-1]
				if pst, ok := stats[parent.statKey]; ok {
					pst.ChildCalls++
				}
			}

			depth := len(stStack)
			if ev.Depth > depth && ev.Kind == KindJavaEnter {
				depth = ev.Depth
			}

			fr := &frame{
				statKey: statKey,
				node: CallNode{
					ID:       nextID,
					Name:     fstat.Name,
					Module:   ev.Module,
					Address:  targetAddr,
					Offset:   targetOff,
					Kind:     ev.Kind,
					Depth:    depth,
					EnterSeq: ev.Seq,
					Args:     ev.Args,
				},
			}
			nextID++
			stacks[tid] = append(stStack, fr)

		case KindJNI:
			name := ev.Symbol
			if name == "" {
				name = "JNI_Call"
			}
			_, fstat := getStat(name, ev.Module, ev.Address, ev.Offset)
			fstat.Hits++
			fstat.InsnCount++
			leaf := CallNode{
				ID:        nextID,
				Name:      fstat.Name,
				Module:    ev.Module,
				Address:   ev.Address,
				Offset:    ev.Offset,
				Kind:      KindJNI,
				Depth:     len(stStack),
				EnterSeq:  ev.Seq,
				ExitSeq:   ev.Seq,
				InsnCount: 1,
				Args:      ev.Args,
				RetVal:    ev.RetVal,
			}
			nextID++
			if len(stStack) > 0 {
				parent := stStack[len(stStack)-1]
				parent.node.Children = append(parent.node.Children, leaf)
				if pst, ok := stats[parent.statKey]; ok {
					pst.ChildCalls++
				}
			} else {
				roots = append(roots, leaf)
			}

		case KindRet, KindJavaExit:
			if len(stStack) > 0 {
				top := stStack[len(stStack)-1]
				stStack = stStack[:len(stStack)-1]
				stacks[tid] = stStack

				top.node.ExitSeq = ev.Seq
				if ev.RetVal != "" {
					top.node.RetVal = ev.RetVal
				}
				if ev.TimestampMs > 0 && top.node.EnterSeq > 0 {
					enterIdx := findEventIndexBySeq(events, top.node.EnterSeq)
					if enterIdx >= 0 && events[enterIdx].TimestampMs > 0 && ev.TimestampMs >= events[enterIdx].TimestampMs {
						top.node.DurationMs = ev.TimestampMs - events[enterIdx].TimestampMs
					}
				}
				if len(stStack) > 0 {
					parent := stStack[len(stStack)-1]
					parent.node.Children = append(parent.node.Children, top.node)
				} else {
					roots = append(roots, top.node)
				}
			}

		default:
			if isInstructionEvent(ev) {
				if len(stStack) > 0 {
					top := stStack[len(stStack)-1]
					top.node.InsnCount++
					if pst, ok := stats[top.statKey]; ok {
						pst.InsnCount++
					}
				} else if ev.Symbol != "" {
					_, fstat := getStat(ev.Symbol, ev.Module, ev.Address, ev.Offset)
					fstat.InsnCount++
				}
			}
		}
	}

	// Flush any unclosed frames cleanly so partial traces still yield a complete tree.
	tids := make([]int, 0, len(stacks))
	for tid := range stacks {
		tids = append(tids, tid)
	}
	sort.Ints(tids)
	for _, tid := range tids {
		stStack := stacks[tid]
		for len(stStack) > 0 {
			top := stStack[len(stStack)-1]
			stStack = stStack[:len(stStack)-1]
			if len(stStack) > 0 {
				parent := stStack[len(stStack)-1]
				parent.node.Children = append(parent.node.Children, top.node)
			} else {
				roots = append(roots, top.node)
			}
		}
	}

	hot := make([]FunctionStat, 0, len(stats))
	for _, st := range stats {
		hot = append(hot, *st)
	}
	sort.Slice(hot, func(i, j int) bool {
		if hot[i].InsnCount != hot[j].InsnCount {
			return hot[i].InsnCount > hot[j].InsnCount
		}
		if hot[i].Hits != hot[j].Hits {
			return hot[i].Hits > hot[j].Hits
		}
		return hot[i].Name < hot[j].Name
	})
	if len(hot) > 50 {
		hot = hot[:50]
	}
	return roots, hot
}

func resolveCallTarget(events []TraceEvent, idx int, moduleBase uint64) (name string, addr, off uint64) {
	ev := events[idx]
	if ev.Symbol != "" {
		return ev.Symbol, ev.Address, ev.Offset
	}

	op := strings.TrimSpace(ev.Operands)
	// Direct hex immediate target (e.g. "bl #0x40001b00" or "call 0x401200")
	if hm := reHexLiteral.FindStringSubmatch(op); hm != nil {
		if target, err := strconv.ParseUint(hm[1], 16, 64); err == nil {
			addr = target
		}
	} else if op != "" {
		// Indirect call via register (e.g. "blr x8")
		reg := strings.ToLower(op)
		if v, ok := lookupRegValue(ev.RegsBefore, reg); ok {
			addr = v
		} else if v, ok := lookupRegValue(ev.RegsAfter, reg); ok {
			addr = v
		} else if !strings.ContainsAny(op, " [],#") {
			name = op
		}
	}

	// Peek at the next executed instruction on the same thread to resolve indirect call target / symbol.
	for j := idx + 1; j < len(events) && j <= idx+4; j++ {
		nxt := events[j]
		if !isInstructionEvent(nxt) || nxt.ThreadID != ev.ThreadID {
			continue
		}
		if addr == 0 && nxt.Address != 0 && nxt.Address != safeAddUint64(ev.Address, 4) {
			addr = nxt.Address
		}
		if name == "" && nxt.Symbol != "" && nxt.Address == addr {
			name = nxt.Symbol
		}
		if off == 0 && nxt.Offset != 0 && nxt.Address == addr {
			off = nxt.Offset
		}
		break
	}

	if off == 0 && addr != 0 && moduleBase > 0 && addr >= moduleBase {
		off = addr - moduleBase
	}
	if name == "" {
		if off != 0 {
			name = fmt.Sprintf("sub_%x", off)
		} else if addr != 0 {
			name = fmt.Sprintf("sub_%x", addr)
		} else {
			name = "call_unknown"
		}
	}
	return name, addr, off
}

func analyzeHotLoops(s *ExecTraceSession) []LoopStat {
	type loopKey struct {
		mod   string
		start uint64
		end   uint64
	}
	type loopAcc struct {
		stat       LoopStat
		totalInsns int
		cryptoOps  int
	}

	accs := make(map[loopKey]*loopAcc)
	prevByTID := make(map[int]*TraceEvent)
	recentByTID := make(map[int][]TraceEvent)

	for i := range s.Events {
		ev := &s.Events[i]
		if !isInstructionEvent(*ev) || ev.Address == 0 {
			continue
		}
		tid := ev.ThreadID
		prevEv := prevByTID[tid]
		recentInsns := recentByTID[tid]

		if prevEv != nil && prevEv.ThreadID == ev.ThreadID && prevEv.Module == ev.Module && prevEv.Kind != KindCall && prevEv.Kind != KindRet {
			if ev.Address <= prevEv.Address && prevEv.Address-ev.Address <= 4096 {
				key := loopKey{mod: ev.Module, start: ev.Address, end: prevEv.Address}
				acc, ok := accs[key]
				if !ok {
					acc = &loopAcc{
						stat: LoopStat{
							StartAddr:   ev.Address,
							EndAddr:     prevEv.Address,
							StartOffset: ev.Offset,
							EndOffset:   prevEv.Offset,
							Module:      ev.Module,
							FirstSeq:    ev.Seq,
						},
					}
					accs[key] = acc
				}
				acc.stat.Iterations++
				acc.stat.LastSeq = prevEv.Seq

				// Count instructions within [start, end] from recent per-thread execution window.
				bodyCount := 0
				cryptoCount := 0
				for k := len(recentInsns) - 1; k >= 0; k-- {
					re := recentInsns[k]
					if re.Address >= ev.Address && re.Address <= prevEv.Address {
						bodyCount++
						if isCryptoMixMnemonic(re.Mnemonic) {
							cryptoCount++
						}
						if re.Address == ev.Address && bodyCount > 1 {
							break
						}
					} else if bodyCount > 0 {
						break
					}
				}
				if bodyCount == 0 {
					bodyCount = 1
				}
				if bodyCount > acc.stat.BodyInsns {
					acc.stat.BodyInsns = bodyCount
				}
				acc.totalInsns += bodyCount
				acc.cryptoOps += cryptoCount
			}
		}

		recentInsns = append(recentInsns, *ev)
		if len(recentInsns) > 512 {
			recentInsns = recentInsns[len(recentInsns)-256:]
		}
		recentByTID[tid] = recentInsns
		prevByTID[tid] = ev
	}

	out := make([]LoopStat, 0, len(accs))
	for _, acc := range accs {
		if acc.totalInsns > 0 {
			acc.stat.CryptoRatio = math.Round(float64(acc.cryptoOps)/float64(acc.totalInsns)*100) / 100
		}
		if acc.stat.CryptoRatio >= 0.4 && acc.stat.Iterations >= 2 {
			acc.stat.Hint = "potential crypto round loop"
		} else if acc.stat.Iterations >= 8 {
			acc.stat.Hint = "hot execution loop"
		}
		out = append(out, acc.stat)
	}
	sort.Slice(out, func(i, j int) bool {
		wi := out[i].Iterations * maxInt(out[i].BodyInsns, 1)
		wj := out[j].Iterations * maxInt(out[j].BodyInsns, 1)
		if wi != wj {
			return wi > wj
		}
		return out[i].StartAddr < out[j].StartAddr
	})
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

func analyzeMemoryRegions(s *ExecTraceSession) []MemoryRegionStat {
	// Collect observed stack pointer pages so we can accurately label stack regions.
	stackPages := make(map[uint64]bool)
	for i := range s.Events {
		ev := &s.Events[i]
		for _, m := range []map[string]uint64{ev.RegsBefore, ev.RegsAfter} {
			for _, spName := range []string{"sp", "rsp", "esp"} {
				if sp, ok := m[spName]; ok && sp != 0 {
					page := sp &^ uint64(0xFFF)
					stackPages[page] = true
					if page >= 0x1000 {
						stackPages[page-0x1000] = true
					}
					if page <= math.MaxUint64-0x1000 {
						stackPages[page+0x1000] = true
					}
				}
			}
		}
	}

	type pageAcc struct {
		page       uint64
		minAddr    uint64
		maxEnd     uint64
		reads      int
		writes     int
		addrs      map[uint64]struct{}
		sampleHex  string
		firstWrite bool
		seenAny    bool
	}

	pages := make(map[uint64]*pageAcc)
	record := func(addr uint64, size int, isWrite bool, valHex string) {
		if addr == 0 {
			return
		}
		if size <= 0 {
			size = 4
		}
		page := addr &^ uint64(0xFFF)
		end := safeAddUint64(addr, uint64(size))
		acc, ok := pages[page]
		if !ok {
			acc = &pageAcc{
				page:    page,
				minAddr: addr,
				maxEnd:  end,
				addrs:   make(map[uint64]struct{}),
			}
			pages[page] = acc
		}
		if addr < acc.minAddr {
			acc.minAddr = addr
		}
		if end > acc.maxEnd {
			acc.maxEnd = end
		}
		if !acc.seenAny {
			acc.seenAny = true
			acc.firstWrite = isWrite
		}
		if isWrite {
			acc.writes++
		} else {
			acc.reads++
		}
		acc.addrs[addr] = struct{}{}
		if acc.sampleHex == "" && valHex != "" {
			sample := strings.ToLower(strings.TrimPrefix(valHex, "0x"))
			if len(sample) > 32 {
				sample = sample[:32]
			}
			acc.sampleHex = sample
		}
	}

	for i := range s.Events {
		ev := &s.Events[i]
		switch ev.Kind {
		case KindMemRead:
			record(ev.MemAddr, ev.MemSize, false, ev.MemValueHex)
		case KindMemWrite:
			record(ev.MemAddr, ev.MemSize, true, ev.MemValueHex)
		default:
			if ev.MemAddr != 0 {
				isWrite := isStoreMnemonic(ev.Mnemonic)
				record(ev.MemAddr, ev.MemSize, isWrite, ev.MemValueHex)
			}
		}
	}

	out := make([]MemoryRegionStat, 0, len(pages))
	for _, acc := range pages {
		role := RoleState
		switch {
		case stackPages[acc.page]:
			role = RoleStack
		case acc.writes == 0 && acc.reads > 0:
			if acc.reads >= 4 {
				role = RoleLookupTable
			} else {
				role = RoleInputBuffer
			}
		case acc.reads == 0 && acc.writes > 0:
			role = RoleOutputBuffer
		default:
			role = RoleState
		}
		out = append(out, MemoryRegionStat{
			BaseAddr:    acc.minAddr,
			EndAddr:     acc.maxEnd,
			BaseAddrHex: fmt.Sprintf("0x%x", acc.minAddr),
			EndAddrHex:  fmt.Sprintf("0x%x", acc.maxEnd),
			ReadCount:   acc.reads,
			WriteCount:  acc.writes,
			UniqueAddrs: len(acc.addrs),
			SampleHex:   acc.sampleHex,
			RoleHint:    role,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		ti := out[i].ReadCount + out[i].WriteCount
		tj := out[j].ReadCount + out[j].WriteCount
		if ti != tj {
			return ti > tj
		}
		return out[i].BaseAddr < out[j].BaseAddr
	})
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func analyzeCryptoPatterns(s *ExecTraceSession, hotLoops []LoopStat, memRegions []MemoryRegionStat) []CryptoPatternHit {
	type dedupKey struct {
		algo  string
		label string
	}
	seen := make(map[dedupKey]*CryptoPatternHit)
	algoDistinct := make(map[string]map[string]struct{})
	var hits []*CryptoPatternHit

	addHit := func(algo, label string, seq int, addr, off uint64, mod, evidence string, conf float64) {
		key := dedupKey{algo: algo, label: label}
		if existing, ok := seen[key]; ok {
			if conf > existing.Confidence {
				existing.Confidence = conf
			}
			return
		}
		h := &CryptoPatternHit{
			Algorithm:  algo,
			Seq:        seq,
			Address:    addr,
			Offset:     off,
			Module:     mod,
			Evidence:   evidence,
			Confidence: conf,
		}
		seen[key] = h
		hits = append(hits, h)
		if algoDistinct[algo] == nil {
			algoDistinct[algo] = make(map[string]struct{})
		}
		algoDistinct[algo][label] = struct{}{}
	}

	checkWord32 := func(w uint32, ev TraceEvent, where string) {
		if entry, ok := cryptoMagic32[w]; ok {
			evidence := fmt.Sprintf("%s observed in %s", entry.Label, where)
			addHit(entry.Algorithm, entry.Label, ev.Seq, ev.Address, ev.Offset, ev.Module, evidence, entry.BaseConf)
		}
	}

	checkVal64 := func(v uint64, ev TraceEvent, where string) {
		if v == 0 {
			return
		}
		checkWord32(uint32(v&0xffffffff), ev, where)
		if hi := uint32(v >> 32); hi != 0 {
			checkWord32(hi, ev, where+"[hi32]")
		}
	}

	// Scan every event for crypto constants, hardware crypto instructions, and memory magic bytes.
	var insnWindow []TraceEvent
	reportedCustomWindows := make(map[uint64]bool)

	for i := range s.Events {
		ev := s.Events[i]

		// Hardware crypto instructions (ARMv8 Crypto / x86 AES-NI / CRC32)
		switch {
		case ev.Mnemonic == "aese" || ev.Mnemonic == "aesd" || ev.Mnemonic == "aesmc" || ev.Mnemonic == "aesimc" ||
			strings.HasPrefix(ev.Mnemonic, "aesenc") || strings.HasPrefix(ev.Mnemonic, "aesdec") || ev.Mnemonic == "aeskeygenassist":
			addHit("AES", "hw-aes:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware AES instruction %q", ev.Mnemonic), 0.99)
		case strings.HasPrefix(ev.Mnemonic, "sha256"):
			addHit("SHA-256", "hw-sha256:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware SHA-256 instruction %q", ev.Mnemonic), 0.99)
		case strings.HasPrefix(ev.Mnemonic, "sha1"):
			addHit("SHA-1", "hw-sha1:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware SHA-1 instruction %q", ev.Mnemonic), 0.99)
		case strings.HasPrefix(ev.Mnemonic, "sm3"):
			addHit("SM3", "hw-sm3:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware SM3 instruction %q", ev.Mnemonic), 0.99)
		case strings.HasPrefix(ev.Mnemonic, "sm4"):
			addHit("SM4", "hw-sm4:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware SM4 instruction %q", ev.Mnemonic), 0.99)
		case strings.HasPrefix(ev.Mnemonic, "crc32"):
			addHit("CRC32", "hw-crc32:"+ev.Mnemonic, ev.Seq, ev.Address, ev.Offset, ev.Module,
				fmt.Sprintf("Hardware CRC32 instruction %q", ev.Mnemonic), 0.98)
		}

		// Immediate hex constants in operands
		if ev.Operands != "" {
			for _, m := range reHexLiteral.FindAllStringSubmatch(ev.Operands, -1) {
				if v, err := strconv.ParseUint(m[1], 16, 64); err == nil {
					checkVal64(v, ev, fmt.Sprintf("operand (%s %s)", ev.Mnemonic, ev.Operands))
				}
			}
		}

		// Register values before and after
		for r, v := range ev.RegsBefore {
			checkVal64(v, ev, "reg "+r+" (before)")
		}
		for r, v := range ev.RegsAfter {
			checkVal64(v, ev, "reg "+r+" (after)")
		}

		// Memory payload hex values (check sliding 4-byte BE & LE windows)
		if len(ev.MemValueHex) >= 8 {
			rawHex := strings.TrimPrefix(strings.ToLower(ev.MemValueHex), "0x")
			if len(rawHex)%2 == 1 {
				rawHex = "0" + rawHex
			}
			if b, err := hex.DecodeString(rawHex); err == nil && len(b) >= 4 {
				for pos := 0; pos+4 <= len(b); pos++ {
					be := binary.BigEndian.Uint32(b[pos : pos+4])
					le := binary.LittleEndian.Uint32(b[pos : pos+4])
					where := fmt.Sprintf("mem[0x%x]", ev.MemAddr)
					checkWord32(be, ev, where)
					if le != be {
						checkWord32(le, ev, where)
					}
				}
			}
		}

		// Sliding window check for dense custom XOR + Rotate/Shift mixing sequences
		if isInstructionEvent(ev) {
			insnWindow = append(insnWindow, ev)
			if len(insnWindow) > 20 {
				insnWindow = insnWindow[len(insnWindow)-20:]
			}
			if len(insnWindow) >= 6 {
				xorCnt, rotShiftCnt := 0, 0
				for _, we := range insnWindow {
					if isXorMnemonic(we.Mnemonic) {
						xorCnt++
					} else if isRotOrShiftMnemonic(we.Mnemonic) {
						rotShiftCnt++
					}
				}
				mixTotal := xorCnt + rotShiftCnt
				ratio := float64(mixTotal) / float64(len(insnWindow))
				if xorCnt >= 2 && rotShiftCnt >= 2 && mixTotal >= 4 && ratio >= 0.40 {
					anchor := insnWindow[0]
					bucket := anchor.Address &^ uint64(0x3F)
					if !reportedCustomWindows[bucket] {
						reportedCustomWindows[bucket] = true
						conf := math.Min(0.88, 0.55+ratio*0.4)
						conf = math.Round(conf*100) / 100
						addHit(
							"Custom-XOR-Rot",
							fmt.Sprintf("xor-rot-window@0x%x", bucket),
							anchor.Seq, anchor.Address, anchor.Offset, anchor.Module,
							fmt.Sprintf("Dense XOR+Rotate/Shift sequence (%d xor, %d rot/shift in %d insns, ratio=%.0f%%)",
								xorCnt, rotShiftCnt, len(insnWindow), ratio*100),
							conf,
						)
					}
				}
			}
		}
	}

	// Promote hot loops with high crypto bitwise density to Custom-XOR-Rot hits.
	for _, loop := range hotLoops {
		if loop.CryptoRatio >= 0.40 && loop.Iterations >= 2 {
			addHit(
				"Custom-XOR-Rot",
				fmt.Sprintf("xor-rot-loop@0x%x-0x%x", loop.StartAddr, loop.EndAddr),
				loop.FirstSeq, loop.StartAddr, loop.StartOffset, loop.Module,
				fmt.Sprintf("Hot crypto-like loop 0x%x..0x%x (%d iterations, %d body insns, %.0f%% bitwise/mix ops)",
					loop.StartAddr, loop.EndAddr, loop.Iterations, loop.BodyInsns, loop.CryptoRatio*100),
				math.Min(0.90, math.Round((0.60+loop.CryptoRatio*0.35)*100)/100),
			)
		}
	}

	// Heuristic RC4 detection: 256-byte state array + mod-256 masking + XOR stream.
	detectRC4Pattern(s, memRegions, addHit)

	// Boost confidence when multiple distinct constants of the same algorithm are observed.
	out := make([]CryptoPatternHit, 0, len(hits))
	for _, h := range hits {
		distinctCount := len(algoDistinct[h.Algorithm])
		if distinctCount >= 2 && h.Confidence < 0.98 {
			h.Confidence = math.Min(0.99, math.Round((h.Confidence+0.05)*100)/100)
		}
		out = append(out, *h)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

func detectRC4Pattern(s *ExecTraceSession, memRegions []MemoryRegionStat, addHit func(algo, label string, seq int, addr, off uint64, mod, evidence string, conf float64)) {
	has256State := false
	var stateBase uint64
	for _, reg := range memRegions {
		if reg.EndAddr < reg.BaseAddr {
			continue
		}
		span := reg.EndAddr - reg.BaseAddr
		if span >= 200 && span <= 300 && reg.ReadCount >= 8 && reg.WriteCount >= 8 {
			has256State = true
			stateBase = reg.BaseAddr
			break
		}
	}
	if !has256State {
		return
	}
	mask255 := 0
	xorOps := 0
	firstSeq := 0
	var firstAddr, firstOff uint64
	var firstMod string
	for _, ev := range s.Events {
		if !isInstructionEvent(ev) {
			continue
		}
		if (ev.Mnemonic == "and" || ev.Mnemonic == "ands") && (strings.Contains(strings.ToLower(ev.Operands), "0xff") || strings.Contains(ev.Operands, "#255")) {
			mask255++
			if firstSeq == 0 {
				firstSeq, firstAddr, firstOff, firstMod = ev.Seq, ev.Address, ev.Offset, ev.Module
			}
		}
		if isXorMnemonic(ev.Mnemonic) {
			xorOps++
		}
	}
	if mask255 >= 2 && xorOps >= 1 {
		addHit("RC4", fmt.Sprintf("rc4-sbox@0x%x", stateBase), firstSeq, firstAddr, firstOff, firstMod,
			fmt.Sprintf("256-byte read/write state buffer at 0x%x with %d mod-256 masks and XOR keystream ops", stateBase, mask255),
			0.82)
	}
}

func analyzeSyscalls(s *ExecTraceSession) []SyscallStat {
	byName := make(map[string]*SyscallStat)
	for _, ev := range s.Events {
		if ev.Kind != KindSyscall {
			continue
		}
		name := ev.Symbol
		num := 0
		if name == "" {
			// ARM64 svc #0 uses x8 for syscall number; ARM uses r7; x86_64 uses rax.
			for _, nrReg := range []string{"x8", "w8", "r7", "rax", "eax"} {
				if v, ok := ev.RegsBefore[nrReg]; ok {
					num = int(v)
					name = fmt.Sprintf("syscall_%d", num)
					break
				}
			}
			if name == "" {
				name = ev.Mnemonic
			}
		}
		st, ok := byName[name]
		if !ok {
			st = &SyscallStat{
				Name:      name,
				Number:    num,
				FirstSeq:  ev.Seq,
				SampleRaw: ev.Raw,
			}
			byName[name] = st
		}
		st.Count++
	}
	out := make([]SyscallStat, 0, len(byName))
	for _, st := range byName {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func buildAnalysisSummary(s *ExecTraceSession, a *TraceAnalysis) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%d events (%d insns, %d mem ops, %d calls, %d unique PCs, arch=%s)",
		s.TotalEvents, s.InsnCount, s.MemOpCount, s.CallCount, s.UniquePCs, s.Arch))
	if len(a.CryptoHits) > 0 {
		algoSet := make(map[string]struct{})
		var algos []string
		for _, h := range a.CryptoHits {
			if _, ok := algoSet[h.Algorithm]; !ok {
				algoSet[h.Algorithm] = struct{}{}
				algos = append(algos, h.Algorithm)
			}
		}
		parts = append(parts, fmt.Sprintf("crypto detected: %s (%d hit(s))", strings.Join(algos, ", "), len(a.CryptoHits)))
	}
	if len(a.HotFunctions) > 0 {
		parts = append(parts, fmt.Sprintf("top function: %s (%d insns, %d hits)",
			a.HotFunctions[0].Name, a.HotFunctions[0].InsnCount, a.HotFunctions[0].Hits))
	}
	if len(a.MemoryRegions) > 0 {
		parts = append(parts, fmt.Sprintf("%d memory region(s)", len(a.MemoryRegions)))
	}
	if len(a.HotLoops) > 0 {
		parts = append(parts, fmt.Sprintf("%d hot loop(s)", len(a.HotLoops)))
	}
	return strings.Join(parts, " | ")
}

// ---------------------------------------------------------------------------
// Instruction-level Forward & Backward Register + Memory Taint Engine
// ---------------------------------------------------------------------------

type memInterval struct {
	start uint64
	end   uint64 // exclusive (clamped at math.MaxUint64)
}

func makeMemInterval(start uint64, size int) memInterval {
	if size <= 0 {
		size = 1
	}
	return memInterval{start: start, end: safeAddUint64(start, uint64(size))}
}

func (m memInterval) overlaps(other memInterval) bool {
	if m.start == math.MaxUint64 && other.start == math.MaxUint64 {
		return true
	}
	return m.start < other.end && other.start < m.end
}

type insnSemantics struct {
	dstRegs      []string
	srcRegs      []string
	addrRegs     []string
	isLoad       bool
	isStore      bool
	isMemRMW     bool // x86 ALU writing memory: e.g. add [rdi], rax
	isMemSrcALU  bool // x86 ALU reading memory into reg: e.g. xor eax, [rsi]
	isPair       bool
	isZeroing    bool
	isPreserving bool // e.g. movk preserves existing dst bits
	memAddr      uint64
	memSize      int
	memStride    uint64
}

// RunTaint executes instruction-level forward or backward register+memory taint
// propagation over an ExecTraceSession, returning an ordered minimal slice of
// contributing instructions and exact propagation reasons.
func RunTaint(s *ExecTraceSession, req TaintRequest) (*TaintResult, error) {
	if s == nil || len(s.Events) == 0 {
		return nil, errors.New("exectrace: empty trace session")
	}

	dir := strings.ToLower(strings.TrimSpace(req.Direction))
	if dir == "" {
		dir = TaintForward
	}
	if dir != TaintForward && dir != TaintBackward {
		return nil, fmt.Errorf("exectrace: unsupported taint direction %q (expected forward or backward)", req.Direction)
	}

	maxSteps := req.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 5000
	}

	seedReg := canonicalReg(req.SeedReg)
	seedMem := req.SeedMemAddr
	seedValHex := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(req.SeedValueHex), "0x"))

	// Determine starting index in s.Events.
	startIdx := 0
	if dir == TaintForward {
		if req.StartSeq > 0 {
			startIdx = len(s.Events)
			for i, ev := range s.Events {
				if ev.Seq >= req.StartSeq {
					startIdx = i
					break
				}
			}
			if startIdx >= len(s.Events) {
				return nil, fmt.Errorf("exectrace: start_seq %d beyond trace end", req.StartSeq)
			}
		}
	} else {
		startIdx = len(s.Events) - 1
		if req.StartSeq > 0 {
			startIdx = -1
			for i := len(s.Events) - 1; i >= 0; i-- {
				if s.Events[i].Seq <= req.StartSeq {
					startIdx = i
					break
				}
			}
			if startIdx < 0 {
				return nil, fmt.Errorf("exectrace: start_seq %d before trace start", req.StartSeq)
			}
		}
	}

	// If seeded by value hex only, resolve seed register/memory from the trace.
	if seedReg == "" && seedMem == 0 && seedValHex != "" {
		r, m, foundIdx := resolveValueSeed(s.Events, startIdx, dir, seedValHex)
		if r == "" && m == 0 {
			return nil, fmt.Errorf("exectrace: seed value 0x%s not found in trace", seedValHex)
		}
		seedReg = r
		seedMem = m
		startIdx = foundIdx
	}

	if seedReg == "" && seedMem == 0 {
		return nil, errors.New("exectrace: taint requires seed_reg, seed_mem_addr, or seed_value_hex")
	}

	seedDesc := ""
	if seedReg != "" && seedMem != 0 {
		seedDesc = fmt.Sprintf("reg:%s,mem:0x%x", seedReg, seedMem)
	} else if seedReg != "" {
		seedDesc = "reg:" + seedReg
	} else {
		seedDesc = fmt.Sprintf("mem:0x%x", seedMem)
	}

	if dir == TaintForward {
		return runForwardTaint(s, startIdx, seedReg, seedMem, seedDesc, maxSteps), nil
	}
	return runBackwardTaint(s, startIdx, seedReg, seedMem, seedDesc, maxSteps), nil
}

func runForwardTaint(s *ExecTraceSession, startIdx int, seedReg string, seedMem uint64, seedDesc string, maxSteps int) *TaintResult {
	liveRegs := make(map[string]bool)
	allTaintedRegs := make(map[string]bool)
	var liveMem []memInterval
	allTaintedMem := make(map[uint64]bool)

	if seedReg != "" {
		liveRegs[seedReg] = true
		allTaintedRegs[seedReg] = true
	}
	if seedMem != 0 {
		liveMem = addMemInterval(liveMem, makeMemInterval(seedMem, 8))
		allTaintedMem[seedMem] = true
	}

	var steps []TaintStep
	events := s.Events

	for i := startIdx; i < len(events) && len(steps) < maxSteps; i++ {
		ev := events[i]
		if !isInstructionEvent(ev) || ev.Mnemonic == "" {
			continue
		}
		sem := analyzeInsnSemantics(events, i)
		insnText := formatInsn(ev.Mnemonic, ev.Operands)

		switch {
		case sem.isMemSrcALU:
			// x86 ALU reading memory into destination register: e.g. xor eax, [rsi]
			if len(sem.dstRegs) == 0 {
				continue
			}
			dst := sem.dstRegs[0]
			if dst == "" || isZeroReg(dst) {
				continue
			}
			slotSize := sem.memSize
			if slotSize <= 0 {
				slotSize = 8
			}
			iv := makeMemInterval(sem.memAddr, slotSize)
			taintedByMem := sem.memAddr != 0 && hasMemOverlap(liveMem, iv)
			taintedByDst := liveRegs[dst]

			if taintedByMem {
				liveRegs[dst] = true
				allTaintedRegs[dst] = true
				allTaintedMem[sem.memAddr] = true
				steps = append(steps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s tainted from mem[0x%x] via %s", dst, sem.memAddr, insnText),
					DstRegs:   []string{dst},
					MemAddr:   sem.memAddr,
					MemOp:     "read",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			} else if taintedByDst {
				steps = append(steps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s retains taint via %s", dst, insnText),
					SrcRegs:   []string{dst},
					DstRegs:   []string{dst},
					MemAddr:   sem.memAddr,
					MemOp:     "read",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			}

		case sem.isMemRMW:
			// x86 ALU reading and writing memory: e.g. add [rdi], rax / add [rdi], 0x1
			if sem.memAddr == 0 {
				continue
			}
			slotSize := sem.memSize
			if slotSize <= 0 {
				slotSize = 8
			}
			iv := makeMemInterval(sem.memAddr, slotSize)
			var matchedSrcs []string
			for _, sr := range sem.srcRegs {
				if sr != "" && !isZeroReg(sr) && liveRegs[sr] {
					matchedSrcs = appendUnique(matchedSrcs, sr)
				}
			}
			if len(matchedSrcs) > 0 {
				liveMem = addMemInterval(liveMem, iv)
				allTaintedMem[sem.memAddr] = true
				steps = append(steps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("mem[0x%x] tainted from %s via %s", sem.memAddr, strings.Join(matchedSrcs, ","), insnText),
					SrcRegs:   matchedSrcs,
					MemAddr:   sem.memAddr,
					MemOp:     "write",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			} else if hasMemOverlap(liveMem, iv) {
				// Memory was already tainted and modified in-place (e.g. add [rdi], 0x1).
				allTaintedMem[sem.memAddr] = true
				steps = append(steps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("mem[0x%x] modified in-place while tainted via %s", sem.memAddr, insnText),
					MemAddr:   sem.memAddr,
					MemOp:     "write",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			}

		case sem.isLoad:
			if len(sem.dstRegs) == 0 {
				continue
			}
			for slot, dst := range sem.dstRegs {
				if dst == "" || isZeroReg(dst) {
					continue
				}
				slotAddr := sem.memAddr
				slotSize := sem.memSize
				if sem.isPair && slotAddr != 0 {
					slotAddr = safeAddUint64(slotAddr, uint64(slot)*sem.memStride)
					slotSize = int(sem.memStride)
				}
				if slotSize <= 0 {
					slotSize = 8
				}
				iv := makeMemInterval(slotAddr, slotSize)

				taintedByMem := slotAddr != 0 && hasMemOverlap(liveMem, iv)
				var taintedIdxRegs []string
				if !taintedByMem {
					for _, ar := range sem.addrRegs {
						if liveRegs[ar] && !isStackOrFrameReg(ar) {
							taintedIdxRegs = append(taintedIdxRegs, ar)
						}
					}
				}

				if taintedByMem {
					liveRegs[dst] = true
					allTaintedRegs[dst] = true
					allTaintedMem[slotAddr] = true
					steps = append(steps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    fmt.Sprintf("%s tainted from mem[0x%x] via %s", dst, slotAddr, insnText),
						DstRegs:   []string{dst},
						MemAddr:   slotAddr,
						MemOp:     "read",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				} else if len(taintedIdxRegs) > 0 {
					liveRegs[dst] = true
					allTaintedRegs[dst] = true
					steps = append(steps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    fmt.Sprintf("%s tainted from address/index %s via %s", dst, strings.Join(taintedIdxRegs, ","), insnText),
						SrcRegs:   taintedIdxRegs,
						DstRegs:   []string{dst},
						MemAddr:   slotAddr,
						MemOp:     "read",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				} else if !(i == startIdx && dst == seedReg) {
					delete(liveRegs, dst)
				}
			}

		case sem.isStore:
			// Constant store (e.g. x86 `mov [rdi], 0x0`) has no register source: kill memory taint.
			if len(sem.srcRegs) == 0 {
				if sem.memAddr != 0 {
					slotSize := sem.memSize
					if slotSize <= 0 {
						slotSize = 8
					}
					iv := makeMemInterval(sem.memAddr, slotSize)
					if !(i == startIdx && seedMem != 0 && iv.overlaps(makeMemInterval(seedMem, 8))) {
						liveMem = removeMemInterval(liveMem, iv)
					}
				}
				continue
			}
			for slot, src := range sem.srcRegs {
				slotAddr := sem.memAddr
				slotSize := sem.memSize
				if sem.isPair && slotAddr != 0 {
					slotAddr = safeAddUint64(slotAddr, uint64(slot)*sem.memStride)
					slotSize = int(sem.memStride)
				}
				if slotSize <= 0 {
					slotSize = 8
				}
				if slotAddr == 0 {
					continue
				}
				iv := makeMemInterval(slotAddr, slotSize)
				if src != "" && !isZeroReg(src) && liveRegs[src] {
					liveMem = addMemInterval(liveMem, iv)
					allTaintedMem[slotAddr] = true
					steps = append(steps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    fmt.Sprintf("mem[0x%x] tainted from %s via %s", slotAddr, src, insnText),
						SrcRegs:   []string{src},
						MemAddr:   slotAddr,
						MemOp:     "write",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				} else if !(i == startIdx && seedMem != 0 && iv.overlaps(makeMemInterval(seedMem, 8))) {
					liveMem = removeMemInterval(liveMem, iv)
				}
			}

		default:
			if len(sem.dstRegs) == 0 {
				continue
			}
			dst := sem.dstRegs[0]
			if dst == "" || isZeroReg(dst) {
				continue
			}
			if sem.isZeroing {
				if !(i == startIdx && dst == seedReg) {
					delete(liveRegs, dst)
				}
				continue
			}

			var matchedSrcs []string
			for _, sr := range sem.srcRegs {
				if sr != "" && !isZeroReg(sr) && liveRegs[sr] {
					matchedSrcs = appendUnique(matchedSrcs, sr)
				}
			}

			if len(matchedSrcs) > 0 {
				liveRegs[dst] = true
				allTaintedRegs[dst] = true
				steps = append(steps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s tainted from %s via %s", dst, strings.Join(matchedSrcs, ","), insnText),
					SrcRegs:   matchedSrcs,
					DstRegs:   []string{dst},
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			} else if !sem.isPreserving && !(i == startIdx && dst == seedReg) {
				delete(liveRegs, dst)
			}
		}
	}

	sinks := formatStateList(liveRegs, liveMem)
	taintedRegs := sortedKeys(allTaintedRegs)
	taintedMem := sortedHexAddrs(allTaintedMem)

	return &TaintResult{
		Direction:       TaintForward,
		Seed:            seedDesc,
		StartSeq:        events[startIdx].Seq,
		TaintedSteps:    steps,
		TaintedRegs:     taintedRegs,
		TaintedMemAddrs: taintedMem,
		SourcesOrSinks:  sinks,
		Summary: fmt.Sprintf("Forward taint from %s @ seq %d: %d propagating step(s), %d reg(s), %d mem addr(s), %d live sink(s)",
			seedDesc, events[startIdx].Seq, len(steps), len(taintedRegs), len(taintedMem), len(sinks)),
	}
}

func runBackwardTaint(s *ExecTraceSession, startIdx int, seedReg string, seedMem uint64, seedDesc string, maxSteps int) *TaintResult {
	neededRegs := make(map[string]bool)
	allTaintedRegs := make(map[string]bool)
	var neededMem []memInterval
	allTaintedMem := make(map[uint64]bool)

	if seedReg != "" {
		neededRegs[seedReg] = true
		allTaintedRegs[seedReg] = true
	}
	if seedMem != 0 {
		neededMem = addMemInterval(neededMem, makeMemInterval(seedMem, 8))
		allTaintedMem[seedMem] = true
	}

	var revSteps []TaintStep
	events := s.Events

	for i := startIdx; i >= 0 && len(revSteps) < maxSteps; i-- {
		if len(neededRegs) == 0 && len(neededMem) == 0 {
			break
		}
		ev := events[i]
		if !isInstructionEvent(ev) || ev.Mnemonic == "" {
			continue
		}
		sem := analyzeInsnSemantics(events, i)
		insnText := formatInsn(ev.Mnemonic, ev.Operands)

		switch {
		case sem.isMemSrcALU:
			// x86 ALU reading memory into reg: e.g. xor eax, [rsi]
			if len(sem.dstRegs) == 0 {
				continue
			}
			dst := sem.dstRegs[0]
			if !neededRegs[dst] {
				continue
			}
			allTaintedRegs[dst] = true
			slotSize := sem.memSize
			if slotSize <= 0 {
				slotSize = 8
			}
			if sem.memAddr != 0 {
				neededMem = addMemInterval(neededMem, makeMemInterval(sem.memAddr, slotSize))
				allTaintedMem[sem.memAddr] = true
				revSteps = append(revSteps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s depends on %s and mem[0x%x] via %s", dst, dst, sem.memAddr, insnText),
					SrcRegs:   []string{dst},
					DstRegs:   []string{dst},
					MemAddr:   sem.memAddr,
					MemOp:     "read",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			} else {
				revSteps = append(revSteps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s depends on %s and memory operand via %s", dst, dst, insnText),
					SrcRegs:   []string{dst},
					DstRegs:   []string{dst},
					MemOp:     "read",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			}

		case sem.isMemRMW:
			// x86 ALU modifying memory in-place: e.g. add [rdi], rax
			if sem.memAddr == 0 {
				continue
			}
			slotSize := sem.memSize
			if slotSize <= 0 {
				slotSize = 8
			}
			iv := makeMemInterval(sem.memAddr, slotSize)
			if hasMemOverlap(neededMem, iv) {
				// Keep mem[addr] in neededMem since RMW reads previous memory contents too.
				allTaintedMem[sem.memAddr] = true
				var deps []string
				for _, sr := range sem.srcRegs {
					if sr != "" && !isZeroReg(sr) {
						neededRegs[sr] = true
						allTaintedRegs[sr] = true
						deps = appendUnique(deps, sr)
					}
				}
				reason := fmt.Sprintf("mem[0x%x] modified in-place via %s", sem.memAddr, insnText)
				if len(deps) > 0 {
					reason = fmt.Sprintf("mem[0x%x] depends on %s and prior mem[0x%x] via %s", sem.memAddr, strings.Join(deps, ","), sem.memAddr, insnText)
				}
				revSteps = append(revSteps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    reason,
					SrcRegs:   deps,
					MemAddr:   sem.memAddr,
					MemOp:     "write",
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
			}

		case sem.isLoad:
			for slot, dst := range sem.dstRegs {
				if !neededRegs[dst] {
					continue
				}
				slotAddr := sem.memAddr
				slotSize := sem.memSize
				if sem.isPair && slotAddr != 0 {
					slotAddr = safeAddUint64(slotAddr, uint64(slot)*sem.memStride)
					slotSize = int(sem.memStride)
				}
				if slotSize <= 0 {
					slotSize = 8
				}

				delete(neededRegs, dst)
				allTaintedRegs[dst] = true

				if slotAddr != 0 {
					iv := makeMemInterval(slotAddr, slotSize)
					neededMem = addMemInterval(neededMem, iv)
					allTaintedMem[slotAddr] = true
					revSteps = append(revSteps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    fmt.Sprintf("%s depends on mem[0x%x] via %s", dst, slotAddr, insnText),
						DstRegs:   []string{dst},
						MemAddr:   slotAddr,
						MemOp:     "read",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				} else {
					var deps []string
					for _, ar := range sem.addrRegs {
						if ar != "" && !isZeroReg(ar) && !isStackOrFrameReg(ar) {
							neededRegs[ar] = true
							allTaintedRegs[ar] = true
							deps = appendUnique(deps, ar)
						}
					}
					revSteps = append(revSteps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    fmt.Sprintf("%s depends on load address %s via %s", dst, strings.Join(deps, ","), insnText),
						SrcRegs:   deps,
						DstRegs:   []string{dst},
						MemOp:     "read",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				}
			}

		case sem.isStore:
			// Constant store (e.g. mov [rdi], 0x0): terminates backward dependency on mem[addr].
			if len(sem.srcRegs) == 0 {
				if sem.memAddr != 0 {
					slotSize := sem.memSize
					if slotSize <= 0 {
						slotSize = 8
					}
					iv := makeMemInterval(sem.memAddr, slotSize)
					if hasMemOverlap(neededMem, iv) {
						neededMem = removeMemInterval(neededMem, iv)
						allTaintedMem[sem.memAddr] = true
						revSteps = append(revSteps, TaintStep{
							Seq:       ev.Seq,
							Address:   ev.Address,
							Offset:    ev.Offset,
							Module:    ev.Module,
							Mnemonic:  ev.Mnemonic,
							Operands:  ev.Operands,
							Reason:    fmt.Sprintf("mem[0x%x] initialized from constant via %s", sem.memAddr, insnText),
							MemAddr:   sem.memAddr,
							MemOp:     "write",
							RegsAfter: cloneRegMap(ev.RegsAfter),
						})
					}
				}
				continue
			}
			for slot, src := range sem.srcRegs {
				slotAddr := sem.memAddr
				slotSize := sem.memSize
				if sem.isPair && slotAddr != 0 {
					slotAddr = safeAddUint64(slotAddr, uint64(slot)*sem.memStride)
					slotSize = int(sem.memStride)
				}
				if slotSize <= 0 {
					slotSize = 8
				}
				if slotAddr == 0 {
					continue
				}
				iv := makeMemInterval(slotAddr, slotSize)
				if hasMemOverlap(neededMem, iv) {
					neededMem = removeMemInterval(neededMem, iv)
					allTaintedMem[slotAddr] = true
					var srcList []string
					reason := fmt.Sprintf("mem[0x%x] zeroed via %s", slotAddr, insnText)
					if src != "" && !isZeroReg(src) {
						neededRegs[src] = true
						allTaintedRegs[src] = true
						srcList = []string{src}
						reason = fmt.Sprintf("mem[0x%x] depends on %s via %s", slotAddr, src, insnText)
					}
					revSteps = append(revSteps, TaintStep{
						Seq:       ev.Seq,
						Address:   ev.Address,
						Offset:    ev.Offset,
						Module:    ev.Module,
						Mnemonic:  ev.Mnemonic,
						Operands:  ev.Operands,
						Reason:    reason,
						SrcRegs:   srcList,
						MemAddr:   slotAddr,
						MemOp:     "write",
						RegsAfter: cloneRegMap(ev.RegsAfter),
					})
				}
			}

		default:
			if len(sem.dstRegs) == 0 {
				continue
			}
			dst := sem.dstRegs[0]
			if !neededRegs[dst] {
				continue
			}
			allTaintedRegs[dst] = true

			if sem.isZeroing {
				delete(neededRegs, dst)
				revSteps = append(revSteps, TaintStep{
					Seq:       ev.Seq,
					Address:   ev.Address,
					Offset:    ev.Offset,
					Module:    ev.Module,
					Mnemonic:  ev.Mnemonic,
					Operands:  ev.Operands,
					Reason:    fmt.Sprintf("%s zeroed by %s", dst, insnText),
					DstRegs:   []string{dst},
					RegsAfter: cloneRegMap(ev.RegsAfter),
				})
				continue
			}

			if !sem.isPreserving {
				delete(neededRegs, dst)
			}

			var deps []string
			for _, sr := range sem.srcRegs {
				if sr != "" && !isZeroReg(sr) {
					neededRegs[sr] = true
					allTaintedRegs[sr] = true
					deps = appendUnique(deps, sr)
				}
			}

			reason := ""
			if len(deps) > 0 {
				reason = fmt.Sprintf("%s depends on %s via %s", dst, strings.Join(deps, ","), insnText)
			} else {
				reason = fmt.Sprintf("%s initialized from constant via %s", dst, insnText)
			}
			revSteps = append(revSteps, TaintStep{
				Seq:       ev.Seq,
				Address:   ev.Address,
				Offset:    ev.Offset,
				Module:    ev.Module,
				Mnemonic:  ev.Mnemonic,
				Operands:  ev.Operands,
				Reason:    reason,
				SrcRegs:   deps,
				DstRegs:   []string{dst},
				RegsAfter: cloneRegMap(ev.RegsAfter),
			})
		}
	}

	// Reverse steps into chronological execution order (earliest dependency -> sink).
	steps := make([]TaintStep, len(revSteps))
	for i := range revSteps {
		steps[len(revSteps)-1-i] = revSteps[i]
	}

	sources := formatStateList(neededRegs, neededMem)
	taintedRegs := sortedKeys(allTaintedRegs)
	taintedMem := sortedHexAddrs(allTaintedMem)

	return &TaintResult{
		Direction:       TaintBackward,
		Seed:            seedDesc,
		StartSeq:        events[startIdx].Seq,
		TaintedSteps:    steps,
		TaintedRegs:     taintedRegs,
		TaintedMemAddrs: taintedMem,
		SourcesOrSinks:  sources,
		Summary: fmt.Sprintf("Backward taint from %s @ seq %d: %d contributing step(s), %d reg(s), %d mem addr(s), %d source(s)",
			seedDesc, events[startIdx].Seq, len(steps), len(taintedRegs), len(taintedMem), len(sources)),
	}
}

func resolveValueSeed(events []TraceEvent, startIdx int, dir, hexNeedle string) (reg string, mem uint64, idx int) {
	needleVal, err := strconv.ParseUint(hexNeedle, 16, 64)
	checkEv := func(ev TraceEvent) (string, uint64) {
		for r, v := range ev.RegsAfter {
			if err == nil && (v == needleVal || (needleVal <= 0xffffffff && uint32(v) == uint32(needleVal))) {
				return canonicalReg(r), 0
			}
		}
		for r, v := range ev.RegsBefore {
			if err == nil && (v == needleVal || (needleVal <= 0xffffffff && uint32(v) == uint32(needleVal))) {
				return canonicalReg(r), 0
			}
		}
		if ev.MemAddr != 0 && ev.MemValueHex != "" && strings.Contains(strings.ToLower(ev.MemValueHex), hexNeedle) {
			return "", ev.MemAddr
		}
		return "", 0
	}

	if dir == TaintForward {
		for i := startIdx; i < len(events); i++ {
			if r, m := checkEv(events[i]); r != "" || m != 0 {
				return r, m, i
			}
		}
	} else {
		for i := startIdx; i >= 0; i-- {
			if r, m := checkEv(events[i]); r != "" || m != 0 {
				return r, m, i
			}
		}
	}
	return "", 0, startIdx
}

func analyzeInsnSemantics(events []TraceEvent, idx int) insnSemantics {
	ev := events[idx]
	m := strings.ToLower(strings.TrimSpace(ev.Mnemonic))
	ops := splitOperands(ev.Operands)

	var sem insnSemantics

	// Load instructions (ARM/ARM64 ldr/ldp, x86 mov reg, [mem], pop)
	if isLoadMnemonic(m) || (isMoveMnemonic(m) && len(ops) >= 2 && strings.Contains(ops[1], "[")) {
		sem.isLoad = true
		if m == "ldp" && len(ops) >= 3 {
			sem.isPair = true
			r1 := canonicalReg(ops[0])
			r2 := canonicalReg(ops[1])
			sem.dstRegs = []string{r1, r2}
			sem.memStride = regWidthBytes(ops[0])
			sem.memSize = int(sem.memStride * 2)
			sem.addrRegs = extractBracketRegs(ev.Operands)
			sem.memAddr = resolveConcreteMemAddr(events, idx, false, ev.Operands)
			return sem
		}
		if m == "pop" && len(ops) >= 1 {
			sem.dstRegs = []string{canonicalReg(ops[0])}
			sem.addrRegs = []string{"rsp"}
			sem.memSize = int(regWidthBytes(ops[0]))
			sem.memAddr = resolveConcreteMemAddr(events, idx, false, "[rsp]")
			return sem
		}
		if len(ops) >= 1 {
			sem.dstRegs = []string{canonicalReg(ops[0])}
		}
		sem.memSize = loadStoreWidth(m, ops)
		sem.addrRegs = extractBracketRegs(ev.Operands)
		sem.memAddr = resolveConcreteMemAddr(events, idx, false, ev.Operands)
		return sem
	}

	// Store instructions (ARM/ARM64 str/stp, x86 mov [mem], src/imm, push)
	if isStoreMnemonic(m) || (isMoveMnemonic(m) && len(ops) >= 2 && strings.Contains(ops[0], "[")) {
		sem.isStore = true
		if m == "stp" && len(ops) >= 3 {
			sem.isPair = true
			r1 := canonicalReg(ops[0])
			r2 := canonicalReg(ops[1])
			sem.srcRegs = []string{r1, r2}
			sem.memStride = regWidthBytes(ops[0])
			sem.memSize = int(sem.memStride * 2)
			sem.addrRegs = extractBracketRegs(ev.Operands)
			sem.memAddr = resolveConcreteMemAddr(events, idx, true, ev.Operands)
			return sem
		}
		if m == "push" && len(ops) >= 1 {
			if r := canonicalReg(ops[0]); r != "" {
				sem.srcRegs = []string{r}
			}
			sem.addrRegs = []string{"rsp"}
			sem.memSize = int(regWidthBytes(ops[0]))
			sem.memAddr = resolveConcreteMemAddr(events, idx, true, "[rsp]")
			return sem
		}
		if isMoveMnemonic(m) && len(ops) >= 2 && strings.Contains(ops[0], "[") {
			// x86: mov [mem], src (src may be a register or an immediate constant)
			if r := canonicalReg(ops[1]); r != "" {
				sem.srcRegs = []string{r}
			}
			sem.memSize = memPtrWidth(ops[0], ops[1])
		} else if len(ops) >= 1 {
			// ARM/ARM64: str src, [mem]
			if r := canonicalReg(ops[0]); r != "" {
				sem.srcRegs = []string{r}
			}
			sem.memSize = loadStoreWidth(m, ops)
		}
		sem.addrRegs = extractBracketRegs(ev.Operands)
		sem.memAddr = resolveConcreteMemAddr(events, idx, true, ev.Operands)
		return sem
	}

	// LEA computes effective address without dereferencing memory.
	if m == "lea" && len(ops) >= 2 {
		sem.dstRegs = []string{canonicalReg(ops[0])}
		sem.srcRegs = extractBracketRegs(ops[1])
		return sem
	}

	// Compare / test / branch instructions do not write general-purpose registers.
	if isNoDstMnemonic(m) || len(ops) == 0 {
		return sem
	}

	// Move / PC-relative address / sign-extend / zero-extend / byte-swap instructions
	if isMoveMnemonic(m) {
		dst := canonicalReg(ops[0])
		if dst != "" {
			sem.dstRegs = []string{dst}
		}
		if m == "movk" || m == "bfi" || m == "bfxil" {
			sem.isPreserving = true
			if dst != "" {
				sem.srcRegs = append(sem.srcRegs, dst)
			}
		}
		for _, op := range ops[1:] {
			for _, r := range extractRegTokens(op) {
				if cr := canonicalReg(r); cr != "" {
					sem.srcRegs = appendUnique(sem.srcRegs, cr)
				}
			}
		}
		return sem
	}

	// ALU / bitwise / shift / multiply instructions
	if isALUMnemonic(m) {
		// x86 memory-destination ALU (e.g. `add [rdi], rax`, `xor dword ptr [rdi], 0xff`)
		if len(ops) >= 1 && strings.Contains(ops[0], "[") {
			sem.isMemRMW = true
			sem.addrRegs = extractBracketRegs(ops[0])
			sem.memAddr = resolveConcreteMemAddr(events, idx, true, ops[0])
			if len(ops) >= 2 {
				sem.memSize = memPtrWidth(ops[0], ops[1])
				for _, r := range extractRegTokens(ops[1]) {
					if cr := canonicalReg(r); cr != "" {
						sem.srcRegs = appendUnique(sem.srcRegs, cr)
					}
				}
			} else {
				sem.memSize = memPtrWidth(ops[0], "")
			}
			return sem
		}

		// x86 memory-source ALU (e.g. `xor eax, [rsi]`, `add rax, qword ptr [rsi+8]`)
		if len(ops) == 2 && strings.Contains(ops[1], "[") {
			dst := canonicalReg(ops[0])
			if dst == "" {
				return sem
			}
			sem.isMemSrcALU = true
			sem.dstRegs = []string{dst}
			sem.srcRegs = []string{dst}
			sem.addrRegs = extractBracketRegs(ops[1])
			sem.memSize = memPtrWidth(ops[1], ops[0])
			sem.memAddr = resolveConcreteMemAddr(events, idx, false, ops[1])
			return sem
		}

		dst := canonicalReg(ops[0])
		if dst == "" {
			return sem
		}
		sem.dstRegs = []string{dst}

		if len(ops) >= 3 {
			// 3-operand form (ARM64/ARM): op dst, src1, src2 [, shift]
			// Zeroing idiom only holds when there is NO 4th shift/extend operand (e.g. `eor x0, x1, x1, lsl #4` != 0).
			src1 := canonicalReg(ops[1])
			src2 := canonicalReg(ops[2])
			if len(ops) == 3 && (m == "eor" || m == "xor" || m == "sub" || m == "subs") && src1 != "" && src1 == src2 {
				sem.isZeroing = true
				return sem
			}
			for _, op := range ops[1:] {
				for _, r := range extractRegTokens(op) {
					if cr := canonicalReg(r); cr != "" {
						sem.srcRegs = appendUnique(sem.srcRegs, cr)
					}
				}
			}
		} else if len(ops) == 2 {
			// 2-operand unary overwrite (ARM64 `neg x0, x1` / `negs x0, x1`) does NOT read dst.
			if isTwoOpUnaryOverwrite(m) {
				for _, r := range extractRegTokens(ops[1]) {
					if cr := canonicalReg(r); cr != "" {
						sem.srcRegs = appendUnique(sem.srcRegs, cr)
					}
				}
				return sem
			}
			// 2-operand form (x86 / Thumb): op dst, src => dst = dst op src
			src2 := canonicalReg(ops[1])
			if (m == "xor" || m == "eor" || m == "sub" || m == "subs") && dst == src2 {
				sem.isZeroing = true
				return sem
			}
			sem.srcRegs = appendUnique(sem.srcRegs, dst)
			for _, r := range extractRegTokens(ops[1]) {
				if cr := canonicalReg(r); cr != "" {
					sem.srcRegs = appendUnique(sem.srcRegs, cr)
				}
			}
		} else if len(ops) == 1 {
			// 1-operand form (e.g. x86 inc/dec/not/neg/bswap)
			sem.srcRegs = []string{dst}
		}
		return sem
	}

	return sem
}

func resolveConcreteMemAddr(events []TraceEvent, idx int, isWrite bool, operands string) uint64 {
	ev := events[idx]
	if ev.MemAddr != 0 {
		return ev.MemAddr
	}

	wantKind := KindMemRead
	if isWrite {
		wantKind = KindMemWrite
	}

	// Check immediately adjacent memory events without crossing another instruction.
	for _, delta := range []int{1, -1, 2, -2} {
		j := idx + delta
		if j < 0 || j >= len(events) {
			continue
		}
		if delta == 2 && isInstructionEvent(events[idx+1]) {
			continue
		}
		if delta == -2 && isInstructionEvent(events[idx-1]) {
			continue
		}
		adj := events[j]
		if isInstructionEvent(adj) {
			continue
		}
		if adj.Kind == wantKind && adj.MemAddr != 0 {
			if adj.Address == 0 || ev.Address == 0 || adj.Address == ev.Address {
				return adj.MemAddr
			}
		}
	}

	// Fallback: evaluate [base, #imm] or [base, idx, lsl #shift] from RegsBefore / RegsAfter.
	bm := reBracketMem.FindStringSubmatch(operands)
	if bm == nil {
		return 0
	}
	inside := strings.TrimSpace(bm[1])
	parts := strings.Split(inside, ",")
	if len(parts) == 1 && strings.ContainsAny(inside, "+-*") {
		return evalX86MemExpr(inside, ev)
	}

	var baseVal uint64
	var idxVal uint64
	var immOff int64
	foundBase := false
	hasIdx := false

	for idxPart, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Immediate offset: #0x10, #-8, #16
		if strings.HasPrefix(p, "#") {
			if off, ok := parseSignedImm(p); ok {
				immOff += off
			}
			continue
		}
		// ARM64 shift / extend modifier on the index register (e.g. "lsl #3", "uxtw #2", "sxtw #3")
		low := strings.ToLower(p)
		if strings.HasPrefix(low, "lsl") || strings.HasPrefix(low, "lsr") || strings.HasPrefix(low, "asr") ||
			strings.HasPrefix(low, "uxtw") || strings.HasPrefix(low, "sxtw") || strings.HasPrefix(low, "uxtx") || strings.HasPrefix(low, "sxtx") {
			if hasIdx {
				idxVal = applyARM64IndexModifier(idxVal, low)
			}
			continue
		}
		if val, ok := lookupRegForMem(ev, p); ok {
			if idxPart == 0 {
				baseVal = val
				foundBase = true
			} else {
				if strings.HasPrefix(strings.ToLower(p), "w") {
					val = uint64(uint32(val))
				}
				idxVal = val
				hasIdx = true
			}
		}
	}
	if !foundBase {
		return 0
	}
	return uint64(int64(baseVal) + int64(idxVal) + immOff)
}

func applyARM64IndexModifier(val uint64, mod string) uint64 {
	fields := strings.Fields(mod)
	if len(fields) == 0 {
		return val
	}
	op := fields[0]
	var shift uint64
	if len(fields) >= 2 {
		if s, ok := parseSignedImm(fields[1]); ok && s >= 0 && s < 64 {
			shift = uint64(s)
		}
	}
	switch op {
	case "uxtw":
		val = uint64(uint32(val)) << shift
	case "sxtw":
		val = uint64(int64(int32(val))) << shift
	case "uxtx", "sxtx", "lsl":
		val = val << shift
	case "lsr":
		val = val >> shift
	case "asr":
		val = uint64(int64(val) >> shift)
	}
	return val
}

func evalX86MemExpr(expr string, ev TraceEvent) uint64 {
	// Handles [rax + 0x10], [rbp - 0x8], [rdi + rsi*4 + 0x10]
	normalized := strings.ReplaceAll(expr, "-", "+-")
	terms := strings.Split(normalized, "+")
	var total int64
	found := false
	for _, t := range terms {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if off, ok := parseSignedImm(t); ok {
			total += off
			continue
		}
		if star := strings.IndexByte(t, '*'); star > 0 {
			lhs := strings.TrimSpace(t[:star])
			rhs := strings.TrimSpace(t[star+1:])
			if val, ok := lookupRegForMem(ev, lhs); ok {
				if scale, ok2 := parseSignedImm(rhs); ok2 {
					total += int64(val) * scale
					found = true
					continue
				}
			}
			if val, ok := lookupRegForMem(ev, rhs); ok {
				if scale, ok2 := parseSignedImm(lhs); ok2 {
					total += int64(val) * scale
					found = true
					continue
				}
			}
		}
		if val, ok := lookupRegForMem(ev, t); ok {
			total += int64(val)
			found = true
		}
	}
	if !found {
		return 0
	}
	return uint64(total)
}

func lookupRegForMem(ev TraceEvent, reg string) (uint64, bool) {
	if v, ok := lookupRegValue(ev.RegsBefore, reg); ok {
		return v, true
	}
	if v, ok := lookupRegValue(ev.RegsAfter, reg); ok {
		return v, true
	}
	return 0, false
}

func lookupRegValue(regs map[string]uint64, reg string) (uint64, bool) {
	if len(regs) == 0 {
		return 0, false
	}
	raw := strings.ToLower(strings.TrimSpace(reg))
	if v, ok := regs[raw]; ok {
		return v, true
	}
	canon := canonicalReg(raw)
	if canon == "" {
		return 0, false
	}
	if v, ok := regs[canon]; ok {
		return v, true
	}
	// Check aliased register keys in map (e.g. map has "w0" when searching "x0").
	for k, v := range regs {
		if canonicalReg(k) == canon {
			return v, true
		}
	}
	return 0, false
}

func parseSignedImm(s string) (int64, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	if s == "" {
		return 0, false
	}
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = strings.TrimSpace(s[1:])
	}
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseUint(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseUint(s, 10, 64)
	}
	if err != nil {
		return 0, false
	}
	if neg {
		return -int64(v), true
	}
	return int64(v), true
}

// ---------------------------------------------------------------------------
// ASLR-Normalized Differential Trace Engine
// ---------------------------------------------------------------------------

// DiffTraces compares two execution traces instruction-by-instruction after
// normalizing PCs by module offset so ASLR base shifts never cause false
// mismatches. It identifies the common prefix length, first and subsequent
// divergence points (with register diffs), and normalized PCs executed only in
// trace A or trace B.
func DiffTraces(a, b *ExecTraceSession, maxDivergences int) *TraceDiffResult {
	if maxDivergences <= 0 {
		maxDivergences = 50
	}

	res := &TraceDiffResult{}
	if a != nil {
		res.SessionA = a.ID
		if res.SessionA == "" {
			res.SessionA = a.Name
		}
	}
	if b != nil {
		res.SessionB = b.ID
		if res.SessionB == "" {
			res.SessionB = b.Name
		}
	}

	seqA := extractDiffableEvents(a)
	seqB := extractDiffableEvents(b)
	res.TotalInsnsA = len(seqA)
	res.TotalInsnsB = len(seqB)

	setA := make(map[string]struct{}, len(seqA))
	for _, ev := range seqA {
		setA[normalizedLocKey(a, ev)] = struct{}{}
	}
	setB := make(map[string]struct{}, len(seqB))
	for _, ev := range seqB {
		setB[normalizedLocKey(b, ev)] = struct{}{}
	}

	for loc := range setA {
		if _, ok := setB[loc]; !ok {
			res.OnlyInA = append(res.OnlyInA, loc)
		}
	}
	for loc := range setB {
		if _, ok := setA[loc]; !ok {
			res.OnlyInB = append(res.OnlyInB, loc)
		}
	}
	sort.Strings(res.OnlyInA)
	sort.Strings(res.OnlyInB)

	// Walk instruction streams with ASLR-normalized PC comparison and small-window resync.
	i, j := 0, 0
	foundDivergence := false

	for i < len(seqA) && j < len(seqB) {
		evA, evB := seqA[i], seqB[j]
		locA := normalizedLocKey(a, evA)
		locB := normalizedLocKey(b, evB)
		sameLoc := locA == locB
		sameMnem := evA.Mnemonic == evB.Mnemonic

		if sameLoc && sameMnem {
			if !foundDivergence {
				res.CommonPrefixLen++
			}
			i++
			j++
			continue
		}

		foundDivergence = true
		if len(res.DivergencePoints) < maxDivergences {
			reason := fmt.Sprintf("PC offset diverged: %s vs %s", locA, locB)
			if sameLoc && !sameMnem {
				reason = fmt.Sprintf("mnemonic diverged at %s: %q vs %q", locA, evA.Mnemonic, evB.Mnemonic)
			}
			dp := DivergencePoint{
				Index:    i,
				SeqA:     evA.Seq,
				SeqB:     evB.Seq,
				ModuleA:  eventModule(a, evA),
				ModuleB:  eventModule(b, evB),
				AddressA: evA.Address,
				AddressB: evB.Address,
				OffsetA:  normalizedOffset(a, evA),
				OffsetB:  normalizedOffset(b, evB),
				InsnA:    formatEventDesc(evA),
				InsnB:    formatEventDesc(evB),
				RegDiffs: diffRegisters(evA, evB),
				Reason:   reason,
			}
			res.DivergencePoints = append(res.DivergencePoints, dp)
			if res.FirstDivergence == nil {
				cp := dp
				res.FirstDivergence = &cp
			}
		} else {
			break
		}

		// Try to resynchronize within a lookahead window so diamond branches yield
		// clean subsequent divergence points instead of cascading false diffs.
		if ni, nj, ok := findResync(a, b, seqA, seqB, i, j, 16); ok {
			i, j = ni, nj
		} else {
			i++
			j++
		}
	}

	// Trailing length divergence when one trace ends earlier than the other.
	if (i < len(seqA) || j < len(seqB)) && len(res.DivergencePoints) < maxDivergences {
		dp := DivergencePoint{Index: i}
		if i < len(seqA) {
			evA := seqA[i]
			dp.SeqA = evA.Seq
			dp.ModuleA = eventModule(a, evA)
			dp.AddressA = evA.Address
			dp.OffsetA = normalizedOffset(a, evA)
			dp.InsnA = formatEventDesc(evA)
			dp.Reason = fmt.Sprintf("trace B ended early at index %d (trace A continues at %s)", j, normalizedLocKey(a, evA))
		} else {
			evB := seqB[j]
			dp.SeqB = evB.Seq
			dp.ModuleB = eventModule(b, evB)
			dp.AddressB = evB.Address
			dp.OffsetB = normalizedOffset(b, evB)
			dp.InsnB = formatEventDesc(evB)
			dp.Reason = fmt.Sprintf("trace A ended early at index %d (trace B continues at %s)", i, normalizedLocKey(b, evB))
		}
		res.DivergencePoints = append(res.DivergencePoints, dp)
		if res.FirstDivergence == nil {
			cp := dp
			res.FirstDivergence = &cp
		}
	}

	if res.FirstDivergence == nil {
		res.Summary = fmt.Sprintf("Traces match identically across %d normalized instruction(s)", res.CommonPrefixLen)
	} else {
		res.Summary = fmt.Sprintf("Common prefix: %d insn(s); first divergence at index %d (%s); %d total divergence(s); %d PC(s) only in A, %d only in B",
			res.CommonPrefixLen, res.FirstDivergence.Index, res.FirstDivergence.Reason,
			len(res.DivergencePoints), len(res.OnlyInA), len(res.OnlyInB))
	}
	return res
}

func extractDiffableEvents(s *ExecTraceSession) []TraceEvent {
	if s == nil {
		return nil
	}
	var insns []TraceEvent
	var calls []TraceEvent
	for _, ev := range s.Events {
		if isInstructionEvent(ev) {
			insns = append(insns, ev)
		} else if ev.Kind == KindJavaEnter || ev.Kind == KindJavaExit || ev.Kind == KindJNI {
			calls = append(calls, ev)
		}
	}
	if len(insns) > 0 {
		return insns
	}
	return calls
}

func eventModule(s *ExecTraceSession, ev TraceEvent) string {
	if ev.Module != "" {
		return ev.Module
	}
	if s != nil {
		return s.TargetModule
	}
	return ""
}

func normalizedOffset(s *ExecTraceSession, ev TraceEvent) uint64 {
	if ev.Offset != 0 {
		return ev.Offset
	}
	if ev.Address != 0 {
		if s != nil && s.ModuleBase != 0 && ev.Address >= s.ModuleBase {
			return ev.Address - s.ModuleBase
		}
		return ev.Address
	}
	return 0
}

func normalizedLocKey(s *ExecTraceSession, ev TraceEvent) string {
	if !isInstructionEvent(ev) && ev.Symbol != "" {
		return ev.Kind + ":" + ev.Symbol
	}
	mod := eventModule(s, ev)
	off := normalizedOffset(s, ev)
	if mod != "" {
		return fmt.Sprintf("%s+0x%x", mod, off)
	}
	return fmt.Sprintf("0x%x", off)
}

func findResync(a, b *ExecTraceSession, seqA, seqB []TraceEvent, i, j, window int) (int, int, bool) {
	bestDist := window*2 + 1
	bestI, bestJ := -1, -1
	for da := 0; da <= window && i+da < len(seqA); da++ {
		locA := normalizedLocKey(a, seqA[i+da])
		mnemA := seqA[i+da].Mnemonic
		for db := 0; db <= window && j+db < len(seqB); db++ {
			if da == 0 && db == 0 {
				continue
			}
			if normalizedLocKey(b, seqB[j+db]) == locA && seqB[j+db].Mnemonic == mnemA {
				dist := da + db
				if dist < bestDist {
					bestDist = dist
					bestI = i + da
					bestJ = j + db
				}
			}
		}
	}
	if bestI >= 0 {
		return bestI, bestJ, true
	}
	return 0, 0, false
}

func diffRegisters(evA, evB TraceEvent) []string {
	regsA := evA.RegsAfter
	if len(regsA) == 0 {
		regsA = evA.RegsBefore
	}
	regsB := evB.RegsAfter
	if len(regsB) == 0 {
		regsB = evB.RegsBefore
	}
	if len(regsA) == 0 && len(regsB) == 0 {
		return nil
	}
	all := make(map[string]struct{})
	for k := range regsA {
		all[k] = struct{}{}
	}
	for k := range regsB {
		all[k] = struct{}{}
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var diffs []string
	for _, k := range keys {
		va, oka := regsA[k]
		vb, okb := regsB[k]
		if oka && okb && va != vb {
			diffs = append(diffs, fmt.Sprintf("%s: 0x%x vs 0x%x", k, va, vb))
		} else if oka && !okb {
			diffs = append(diffs, fmt.Sprintf("%s: 0x%x vs <unset>", k, va))
		} else if !oka && okb {
			diffs = append(diffs, fmt.Sprintf("%s: <unset> vs 0x%x", k, vb))
		}
	}
	return diffs
}

// ---------------------------------------------------------------------------
// Architecture & Utility Helpers
// ---------------------------------------------------------------------------

// canonicalReg normalizes ARM64 (w0->x0, fp->x29, lr->x30), x86/x86_64
// sub-registers (eax/ax/al->rax, r8d->r8), and ARM32 register aliases.
// Memory operands containing '[' or ']' are never treated as registers.
func canonicalReg(raw string) string {
	r := strings.ToLower(strings.TrimSpace(raw))
	if r == "" || strings.ContainsAny(r, "[]") {
		return ""
	}
	r = strings.Trim(r, "!{}")
	if r == "" {
		return ""
	}
	if strings.HasPrefix(r, "#") || strings.HasPrefix(r, "0x") || (r[0] >= '0' && r[0] <= '9') {
		return ""
	}
	switch r {
	case "xzr", "wzr":
		return "xzr"
	case "fp":
		return "x29"
	case "lr":
		return "x30"
	case "sp", "wsp":
		return "sp"
	case "pc", "rip", "eip":
		return "pc"
	// x86 / x86_64 register families
	case "rax", "eax", "ax", "al", "ah":
		return "rax"
	case "rbx", "ebx", "bx", "bl", "bh":
		return "rbx"
	case "rcx", "ecx", "cx", "cl", "ch":
		return "rcx"
	case "rdx", "edx", "dx", "dl", "dh":
		return "rdx"
	case "rsi", "esi", "si", "sil":
		return "rsi"
	case "rdi", "edi", "di", "dil":
		return "rdi"
	case "rbp", "ebp", "bp", "bpl":
		return "rbp"
	case "rsp", "esp", "spl":
		return "rsp"
	}

	// ARM64 x0..x30 / w0..w30
	if (r[0] == 'x' || r[0] == 'w') && len(r) >= 2 && len(r) <= 3 {
		if n, err := strconv.Atoi(r[1:]); err == nil && n >= 0 && n <= 30 {
			return fmt.Sprintf("x%d", n)
		}
	}
	// ARM64 SIMD/FP v0..v31 / q0..q31 / d0..d31 / s0..s31 / h0..h31 / b0..b31
	if strings.ContainsRune("vqdshb", rune(r[0])) && len(r) >= 2 && len(r) <= 3 {
		if n, err := strconv.Atoi(r[1:]); err == nil && n >= 0 && n <= 31 {
			return fmt.Sprintf("v%d", n)
		}
	}
	// x86_64 r8..r15 with b/w/d suffix
	if r[0] == 'r' && len(r) >= 2 && len(r) <= 4 {
		trimmed := strings.TrimRight(r[1:], "bwd")
		if n, err := strconv.Atoi(trimmed); err == nil && n >= 0 && n <= 15 {
			return fmt.Sprintf("r%d", n)
		}
	}
	// x86 XMM / YMM / ZMM registers
	if (strings.HasPrefix(r, "xmm") || strings.HasPrefix(r, "ymm") || strings.HasPrefix(r, "zmm")) && len(r) >= 4 {
		if n, err := strconv.Atoi(r[3:]); err == nil && n >= 0 && n <= 31 {
			return fmt.Sprintf("xmm%d", n)
		}
	}
	return ""
}

func isZeroReg(r string) bool {
	return r == "xzr" || r == "wzr"
}

func isStackOrFrameReg(r string) bool {
	return r == "sp" || r == "rsp" || r == "rbp" || r == "x29"
}

func regWidthBytes(raw string) uint64 {
	r := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(r, "w") || strings.HasPrefix(r, "e") {
		return 4
	}
	if strings.HasPrefix(r, "q") || strings.HasPrefix(r, "v") || strings.HasPrefix(r, "xmm") {
		return 16
	}
	return 8
}

func memPtrWidth(memOp, otherOp string) int {
	low := strings.ToLower(memOp)
	switch {
	case strings.Contains(low, "byte ptr"):
		return 1
	case strings.Contains(low, "word ptr") && !strings.Contains(low, "dword") && !strings.Contains(low, "qword"):
		return 2
	case strings.Contains(low, "dword ptr"):
		return 4
	case strings.Contains(low, "qword ptr"):
		return 8
	}
	if otherOp != "" && canonicalReg(otherOp) != "" {
		return int(regWidthBytes(otherOp))
	}
	return 8
}

func loadStoreWidth(mnemonic string, ops []string) int {
	switch {
	case strings.HasSuffix(mnemonic, "b") || strings.HasSuffix(mnemonic, "sb"):
		return 1
	case strings.HasSuffix(mnemonic, "h") || strings.HasSuffix(mnemonic, "sh"):
		return 2
	case strings.HasSuffix(mnemonic, "sw"):
		return 4
	}
	if len(ops) > 0 {
		return int(regWidthBytes(ops[0]))
	}
	return 8
}

func isLoadMnemonic(m string) bool {
	switch m {
	case "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh",
		"ldxr", "ldar", "ldaxr", "ldp", "ldnp", "pop":
		return true
	default:
		return false
	}
}

func isStoreMnemonic(m string) bool {
	switch m {
	case "str", "strb", "strh", "stur", "sturb", "sturh",
		"stxr", "stlr", "stlxr", "stp", "stnp", "push":
		return true
	default:
		return false
	}
}

func isMoveMnemonic(m string) bool {
	switch m {
	case "mov", "movz", "movk", "movn", "mvn", "movzx", "movsx", "movsxd",
		"movq", "movl", "movw", "movb", "movabs",
		"adr", "adrp",
		"sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw",
		"bfi", "bfxil", "ubfx", "sbfx", "ubfm", "sbfm",
		"rbit", "rev", "rev16", "rev32", "bswap",
		"csel", "csinc", "csinv", "csneg":
		return true
	default:
		return strings.HasPrefix(m, "cmov")
	}
}

func isTwoOpUnaryOverwrite(m string) bool {
	switch m {
	case "neg", "negs", "not", "abs", "clz", "cls", "cnt":
		return true
	default:
		return false
	}
}

func isALUMnemonic(m string) bool {
	switch m {
	case "add", "adds", "adc", "adcs", "sub", "subs", "sbc", "sbcs", "rsb", "neg", "negs",
		"eor", "eors", "eon", "xor", "and", "ands", "bic", "bics", "orr", "orrs", "orn", "or", "not",
		"lsl", "lsr", "asr", "ror", "rol", "shl", "shr", "sar", "sal", "extr",
		"mul", "imul", "madd", "msub", "umull", "smull", "umulh", "smulh", "udiv", "sdiv",
		"inc", "dec", "abs", "clz", "cls", "cnt",
		"aese", "aesd", "crc32b", "crc32h", "crc32w", "crc32x":
		return true
	default:
		return false
	}
}

func isNoDstMnemonic(m string) bool {
	switch m {
	case "cmp", "cmn", "tst", "test", "b", "bl", "blr", "br", "bx", "blx",
		"cbz", "cbnz", "tbz", "tbnz", "ret", "retaa", "retab", "retq",
		"nop", "svc", "syscall", "call", "callq", "jmp":
		return true
	default:
		return strings.HasPrefix(m, "b.") || strings.HasPrefix(m, "j")
	}
}

func isXorMnemonic(m string) bool {
	return m == "eor" || m == "eors" || m == "eon" || m == "xor" || m == "pxor" || m == "vpxor"
}

func isRotOrShiftMnemonic(m string) bool {
	switch m {
	case "ror", "rol", "extr", "lsl", "lsr", "asr", "shl", "shr", "sar", "rbit", "rev", "rev32":
		return true
	default:
		return false
	}
}

func isCryptoMixMnemonic(m string) bool {
	if isXorMnemonic(m) || isRotOrShiftMnemonic(m) {
		return true
	}
	switch m {
	case "add", "adds", "and", "ands", "orr", "or", "bic", "aese", "aesd", "aesmc", "aesimc":
		return true
	default:
		return strings.HasPrefix(m, "sha") || strings.HasPrefix(m, "sm3") || strings.HasPrefix(m, "sm4") || strings.HasPrefix(m, "crc32")
	}
}

func splitOperands(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	bracket := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '[', '{':
			bracket++
			cur.WriteByte(c)
		case ']', '}':
			if bracket > 0 {
				bracket--
			}
			cur.WriteByte(c)
		case ',':
			if bracket == 0 {
				if tok := strings.TrimSpace(cur.String()); tok != "" {
					out = append(out, tok)
				}
				cur.Reset()
				continue
			}
			cur.WriteByte(c)
		default:
			cur.WriteByte(c)
		}
	}
	if tok := strings.TrimSpace(cur.String()); tok != "" {
		out = append(out, tok)
	}
	return out
}

func extractBracketRegs(operands string) []string {
	bm := reBracketMem.FindStringSubmatch(operands)
	if bm == nil {
		return nil
	}
	var regs []string
	for _, tok := range extractRegTokens(bm[1]) {
		if cr := canonicalReg(tok); cr != "" {
			regs = appendUnique(regs, cr)
		}
	}
	return regs
}

func extractRegTokens(s string) []string {
	matches := reRegWord.FindAllStringSubmatch(s, -1)
	var out []string
	for _, m := range matches {
		w := strings.ToLower(m[1])
		// Ignore instruction shift/extend keywords and memory size specifiers
		switch w {
		case "lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
			"byte", "word", "dword", "qword", "ptr":
			continue
		}
		if canonicalReg(w) != "" {
			out = append(out, w)
		}
	}
	return out
}

func addMemInterval(list []memInterval, iv memInterval) []memInterval {
	if iv.end <= iv.start && iv.start < math.MaxUint64 {
		iv.end = iv.start + 1
	}
	list = append(list, iv)
	sort.Slice(list, func(i, j int) bool {
		if list[i].start != list[j].start {
			return list[i].start < list[j].start
		}
		return list[i].end < list[j].end
	})
	merged := list[:0]
	for _, cur := range list {
		if len(merged) == 0 || cur.start > merged[len(merged)-1].end {
			merged = append(merged, cur)
		} else if cur.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = cur.end
		}
	}
	return merged
}

func removeMemInterval(list []memInterval, rm memInterval) []memInterval {
	if len(list) == 0 || (rm.end <= rm.start && rm.start < math.MaxUint64) {
		return list
	}
	var out []memInterval
	for _, iv := range list {
		if !iv.overlaps(rm) {
			out = append(out, iv)
			continue
		}
		if iv.start < rm.start {
			out = append(out, memInterval{start: iv.start, end: rm.start})
		}
		if iv.end > rm.end {
			out = append(out, memInterval{start: rm.end, end: iv.end})
		}
	}
	return out
}

func hasMemOverlap(list []memInterval, target memInterval) bool {
	for _, iv := range list {
		if iv.overlaps(target) {
			return true
		}
	}
	return false
}

func formatStateList(regs map[string]bool, mem []memInterval) []string {
	var out []string
	for _, r := range sortedKeys(regs) {
		out = append(out, "reg:"+r)
	}
	for _, iv := range mem {
		out = append(out, fmt.Sprintf("mem:0x%x", iv.start))
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, ok := range m {
		if ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sortedHexAddrs(m map[uint64]bool) []string {
	addrs := make([]uint64, 0, len(m))
	for a, ok := range m {
		if ok {
			addrs = append(addrs, a)
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = fmt.Sprintf("0x%x", a)
	}
	return out
}

func appendUnique(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

func formatInsn(mnemonic, operands string) string {
	if operands == "" {
		return mnemonic
	}
	return mnemonic + " " + operands
}

func formatEventDesc(ev TraceEvent) string {
	if ev.Mnemonic != "" {
		return formatInsn(ev.Mnemonic, ev.Operands)
	}
	if ev.Symbol != "" {
		return ev.Symbol
	}
	return ev.Kind
}

func findEventIndexBySeq(events []TraceEvent, seq int) int {
	for i, ev := range events {
		if ev.Seq == seq {
			return i
		}
	}
	return -1
}

func safeAddUint64(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
