package exectrace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Unidbg instruction line:
	// [15:23:01 123][libfoo.so 0x1a20] [a0 00 01 ca] 0x40001a20: "eor x0, x1, x2" x1=0x1 x2=0x2 => x0=0x3
	reUnidbgHeader = regexp.MustCompile(`\[([^\[\]\s]+)\s+0x([0-9a-fA-F]+)\]`)
	reUnidbgBytes  = regexp.MustCompile(`\[([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+|[0-9a-fA-F]{8})\]`)
	reUnidbgInsn   = regexp.MustCompile(`0x([0-9a-fA-F]+)\s*:\s*"([^"]+)"(.*)$`)
	reUnidbgMem    = regexp.MustCompile(`(?i)Memory\s+(READ|WRITE)\s+at\s+0x([0-9a-fA-F]+)\s*,\s*(?:data\s+)?size\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(?:data\s+)?value\s*=\s*(?:0x)?([0-9a-fA-F]+)(?:.*?\bpc\s*=\s*0x([0-9a-fA-F]+))?`)
	reUnidbgJNI    = regexp.MustCompile(`(?i)(?:JNIEnv->|JNI\s+)([A-Za-z0-9_]+)\s*\(([^)]*)\)(?:\s*(?:=>|=|returned)\s*(.+))?`)

	// Register assignment token: x0=0x1234, r1=0xabcd, rax=0x10, sp=0x7f0000
	reRegAssign = regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9_]{0,6})\s*=\s*0x([0-9a-fA-F]+)`)

	// Qiling / generic instruction line:
	// 0x40001a20: eor x0, x1, x2 ; x1=0x1 x2=0x2 => x0=0x3
	// [=] 0x40001a20: mov x0, x1
	reQilingInsn = regexp.MustCompile(`^(?:\[[^\]]*\]\s*)*(?:0x)?([0-9a-fA-F]{4,16})\s*:\s*([a-zA-Z][a-zA-Z0-9._]*)(?:\s+([^;]+?))?(?:\s*;\s*(.*))?$`)
	reQilingMem  = regexp.MustCompile(`(?i)(?:\[\s*MEM\s*(READ|WRITE)\s*\]|\bmem_(read|write)\b).*?(?:addr\s*=\s*)?0x([0-9a-fA-F]+)(?:.*?(?:size\s*=\s*)(0x[0-9a-fA-F]+|\d+))?(?:.*?(?:val(?:ue)?\s*=\s*)(?:0x)?([0-9a-fA-F]+))?(?:.*?(?:pc\s*=\s*)0x([0-9a-fA-F]+))?`)
	reSyscall    = regexp.MustCompile(`(?i)^(?:\[\s*SYSCALL\s*\]\s*|syscall\s*:\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*=\s*([^\s].*)$`)

	// Java / JNI call-tree lines:
	//   --> com.pkg.Cls.fn(arg0, arg1)
	//   <-- com.pkg.Cls.fn => ret
	//   <-- ret
	reJavaArrow = regexp.MustCompile(`^([\s|│├└]*)(?:\[([^\]]+)\]\s*)*(-->|>>>|->|<--|<<<|<-)\s*(.*)$`)
	reTidTag    = regexp.MustCompile(`(?i)tid\s*[=:]\s*(\d+)`)
	reTsTag     = regexp.MustCompile(`(?i)(\d+)\s*ms`)

	// Tenet register-delta line:
	// pc=0x40001a20,x0=0x1,mr=0x7f0010:deadbeef,mw=0x7f0020:01020304
	// Also matches 0x-less Tenet lines like pc=40001000,x0=1000
	reTenetPC = regexp.MustCompile(`(?i)(?:^|,)\s*(?:pc|rip|eip|r15)\s*=\s*(?:0x)?[0-9a-fA-F]+(?:,|$)`)
)

// flexUint64 unmarshals JSON numbers as well as hex ("0x1a20") or decimal strings.
type flexUint64 uint64

func (f *flexUint64) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		unq, err := strconv.Unquote(s)
		if err != nil {
			return err
		}
		v, err := parseUintAuto(unq)
		if err != nil {
			return err
		}
		*f = flexUint64(v)
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*f = flexUint64(v)
	return nil
}

type jsonTraceLine struct {
	Seq         int                   `json:"seq"`
	TimestampMs int64                 `json:"timestamp_ms"`
	TS          int64                 `json:"ts"`
	ThreadID    int                   `json:"thread_id"`
	TID         int                   `json:"tid"`
	Kind        string                `json:"kind"`
	Type        string                `json:"type"`
	Event       string                `json:"event"`
	Source      string                `json:"source"`
	Module      string                `json:"module"`
	Mod         string                `json:"mod"`
	ModuleBase  flexUint64            `json:"module_base"`
	Arch        string                `json:"arch"`
	Package     string                `json:"target_package"`
	Address     flexUint64            `json:"address"`
	Addr        flexUint64            `json:"addr"`
	PC          flexUint64            `json:"pc"`
	Offset      flexUint64            `json:"offset"`
	Insn        string                `json:"insn"`
	Instruction string                `json:"instruction"`
	Mnemonic    string                `json:"mnemonic"`
	Operands    string                `json:"operands"`
	RawBytes    string                `json:"raw_bytes"`
	Symbol      string                `json:"symbol"`
	Sym         string                `json:"sym"`
	Regs        map[string]flexUint64 `json:"regs"`
	RegsBefore  map[string]flexUint64 `json:"regs_before"`
	RegsAfter   map[string]flexUint64 `json:"regs_after"`
	MemAddr     flexUint64            `json:"mem_addr"`
	MemSize     int                   `json:"mem_size"`
	MemValueHex string                `json:"mem_value_hex"`
	Depth       int                   `json:"depth"`
	Args        []string              `json:"args"`
	RetVal      string                `json:"ret_val"`
	Ret         string                `json:"ret"`
	Raw         string                `json:"raw"`
}

// scanLines iterates over all lines of raw using bufio.Reader so arbitrarily
// large lines (>4 MiB) never abort parsing with bufio.ErrTooLong.
func scanLines(raw string, fn func(line string) bool) {
	r := bufio.NewReaderSize(strings.NewReader(raw), 64*1024)
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if !fn(line) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// DetectFormat inspects the leading non-empty lines of raw trace data and
// returns the best matching TraceFormat.
func DetectFormat(raw string) TraceFormat {
	scores := map[TraceFormat]int{
		FormatUnidbg:   0,
		FormatStalker:  0,
		FormatJSONL:    0,
		FormatQiling:   0,
		FormatJavaCall: 0,
		FormatTenet:    0,
	}

	inspected := 0
	scanLines(raw, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			return true
		}
		inspected++
		if inspected > 60 {
			return false
		}

		// Bound prefix inspected by regexes on giant lines (>8 KiB) to avoid O(N) backtracking.
		sample := line
		if len(sample) > 8192 {
			sample = sample[:8192]
		}

		if strings.Contains(sample, "[CAP_TRACE]") {
			if strings.Contains(sample, `"source":"qiling"`) || strings.Contains(sample, `"source": "qiling"`) {
				scores[FormatJSONL] += 6
			} else {
				scores[FormatStalker] += 6
			}
			return true
		}
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			if strings.Contains(sample, `"stalker"`) || strings.Contains(sample, `"regs_after"`) || strings.Contains(sample, `"mnemonic"`) {
				scores[FormatJSONL] += 5
			} else {
				scores[FormatJSONL] += 3
			}
			return true
		}
		if reTenetPC.MatchString(sample) {
			scores[FormatTenet] += 6
			return true
		}
		if reUnidbgInsn.MatchString(sample) || reUnidbgMem.MatchString(sample) {
			scores[FormatUnidbg] += 6
			return true
		}
		if reUnidbgJNI.MatchString(sample) {
			scores[FormatUnidbg] += 3
			return true
		}
		if reJavaArrow.MatchString(sample) {
			scores[FormatJavaCall] += 6
			return true
		}
		if reQilingMem.MatchString(sample) || reQilingInsn.MatchString(sample) {
			scores[FormatQiling] += 4
			return true
		}
		if reSyscall.MatchString(sample) {
			scores[FormatQiling] += 2
		}
		return true
	})

	best := FormatQiling
	bestScore := -1
	order := []TraceFormat{
		FormatStalker,
		FormatJSONL,
		FormatTenet,
		FormatUnidbg,
		FormatJavaCall,
		FormatQiling,
	}
	for _, f := range order {
		if scores[f] > bestScore {
			bestScore = scores[f]
			best = f
		}
	}
	if bestScore <= 0 {
		return FormatQiling
	}
	return best
}

// ParseTrace parses raw dynamic trace text in any supported format (or auto-detects
// when format is "" or "auto"), computes statistics and ASLR offsets, and runs
// AnalyzeSession on the resulting ExecTraceSession.
func ParseTrace(name, format, raw string, moduleBase uint64) (*ExecTraceSession, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("exectrace: empty trace input")
	}

	reqFmt := normalizeFormat(format)
	detectedFmt := reqFmt
	if detectedFmt == FormatAuto {
		detectedFmt = DetectFormat(raw)
	}

	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("trace-%s", detectedFmt)
	}

	session := &ExecTraceSession{
		Name:       strings.TrimSpace(name),
		Format:     detectedFmt,
		Source:     formatToSource(detectedFmt),
		ModuleBase: moduleBase,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	var events []TraceEvent
	var err error

	switch detectedFmt {
	case FormatUnidbg:
		events, err = parseUnidbgTrace(raw, session)
	case FormatStalker, FormatJSONL:
		events, err = parseJSONLTrace(raw, session, detectedFmt == FormatStalker)
	case FormatTenet:
		events, err = parseTenetTrace(raw, session)
	case FormatJavaCall:
		events, err = parseJavaCallTrace(raw, session)
	case FormatQiling:
		events, err = parseQilingTrace(raw, session)
	default:
		events, err = parseQilingTrace(raw, session)
	}
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("exectrace: no trace events parsed (format=%s)", detectedFmt)
	}

	finalizeSession(session, events)
	return session, nil
}

func normalizeFormat(format string) TraceFormat {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "auto":
		return FormatAuto
	case "unidbg":
		return FormatUnidbg
	case "stalker", "frida", "frida_stalker", "cap_trace":
		return FormatStalker
	case "qiling", "generic", "asm":
		return FormatQiling
	case "java", "java_call", "javacall", "jni":
		return FormatJavaCall
	case "jsonl", "json":
		return FormatJSONL
	case "tenet":
		return FormatTenet
	default:
		return FormatAuto
	}
}

func formatToSource(f TraceFormat) string {
	switch f {
	case FormatUnidbg:
		return SourceUnidbg
	case FormatStalker:
		return SourceStalker
	case FormatQiling:
		return SourceQiling
	case FormatJavaCall:
		return SourceJava
	default:
		return SourceImported
	}
}

func parseUnidbgTrace(raw string, session *ExecTraceSession) ([]TraceEvent, error) {
	var events []TraceEvent
	var lastModule string
	var lastPC uint64
	seq := 0

	scanLines(raw, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			return true
		}

		// Memory READ / WRITE event
		if m := reUnidbgMem.FindStringSubmatch(line); m != nil {
			addr, err := strconv.ParseUint(m[2], 16, 64)
			if err != nil {
				return true
			}
			op := strings.ToUpper(m[1])
			sz, szErr := parseIntAuto(m[3])
			if szErr != nil || sz < 0 {
				sz = 0
			}
			valHex := strings.ToLower(m[4])
			pc := lastPC
			if m[5] != "" {
				if parsedPC, err := strconv.ParseUint(m[5], 16, 64); err == nil {
					pc = parsedPC
				}
			}
			kind := KindMemRead
			if op == "WRITE" {
				kind = KindMemWrite
			}
			seq++
			events = append(events, TraceEvent{
				Seq:         seq,
				Kind:        kind,
				Module:      lastModule,
				Address:     pc,
				MemAddr:     addr,
				MemSize:     sz,
				MemValueHex: valHex,
				Raw:         capRawLine(line),
			})
			return true
		}

		// Unidbg instruction event
		if m := reUnidbgInsn.FindStringSubmatch(line); m != nil {
			addr, err := strconv.ParseUint(m[1], 16, 64)
			if err != nil {
				return true
			}
			insnText := strings.TrimSpace(m[2])
			tail := strings.TrimSpace(m[3])

			mnemonic, operands := splitInsn(insnText)
			mod := lastModule
			var offset uint64

			if hm := reUnidbgHeader.FindStringSubmatch(line); hm != nil {
				mod = hm[1]
				if parsedOff, err := strconv.ParseUint(hm[2], 16, 64); err == nil {
					offset = parsedOff
					if session.ModuleBase == 0 && addr > offset {
						session.ModuleBase = addr - offset
					}
				}
				lastModule = mod
			}

			rawBytes := ""
			if bm := reUnidbgBytes.FindStringSubmatch(line); bm != nil {
				rawBytes = strings.ToLower(strings.ReplaceAll(bm[1], " ", ""))
			}

			regsBefore, regsAfter := parseBeforeAfterRegs(tail)
			kind := classifyInsnKind(mnemonic, operands)
			lastPC = addr

			seq++
			events = append(events, TraceEvent{
				Seq:        seq,
				Kind:       kind,
				Module:     mod,
				Address:    addr,
				Offset:     offset,
				Mnemonic:   mnemonic,
				Operands:   operands,
				RawBytes:   rawBytes,
				RegsBefore: regsBefore,
				RegsAfter:  regsAfter,
				Raw:        capRawLine(line),
			})
			return true
		}

		// JNI call line
		if jm := reUnidbgJNI.FindStringSubmatch(line); jm != nil {
			seq++
			events = append(events, TraceEvent{
				Seq:    seq,
				Kind:   KindJNI,
				Module: lastModule,
				Symbol: "JNIEnv->" + jm[1],
				Args:   splitArgs(jm[2]),
				RetVal: strings.TrimSpace(jm[3]),
				Raw:    capRawLine(line),
			})
			return true
		}
		return true
	})
	return events, nil
}

func parseJSONLTrace(raw string, session *ExecTraceSession, isStalker bool) ([]TraceEvent, error) {
	var events []TraceEvent
	seq := 0
	sawJava := 0
	sawNative := 0
	explicitSource := ""

	scanLines(raw, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			return true
		}
		jsonPart := line
		if idx := strings.Index(line, "[CAP_TRACE]"); idx >= 0 {
			isStalker = true
			jsonPart = strings.TrimSpace(line[idx+len("[CAP_TRACE]"):])
		}
		if !strings.HasPrefix(jsonPart, "{") {
			if brace := strings.Index(jsonPart, "{"); brace >= 0 && strings.HasSuffix(jsonPart, "}") {
				jsonPart = jsonPart[brace:]
			} else {
				return true
			}
		}

		var jl jsonTraceLine
		if err := json.Unmarshal([]byte(jsonPart), &jl); err != nil {
			return true
		}

		if jl.ModuleBase != 0 && session.ModuleBase == 0 {
			session.ModuleBase = uint64(jl.ModuleBase)
		}
		if jl.Arch != "" && session.Arch == "" {
			session.Arch = strings.ToLower(jl.Arch)
		}
		if jl.Package != "" && session.TargetPackage == "" {
			session.TargetPackage = jl.Package
		}
		if s := strings.ToLower(strings.TrimSpace(jl.Source)); s != "" && explicitSource == "" {
			explicitSource = s
		}

		addr := uint64(jl.Address)
		if addr == 0 {
			addr = uint64(jl.Addr)
		}
		if addr == 0 {
			addr = uint64(jl.PC)
		}

		mnemonic := strings.TrimSpace(jl.Mnemonic)
		operands := strings.TrimSpace(jl.Operands)
		if mnemonic == "" {
			combined := strings.TrimSpace(jl.Insn)
			if combined == "" {
				combined = strings.TrimSpace(jl.Instruction)
			}
			if combined != "" {
				mnemonic, operands = splitInsn(combined)
			}
		}

		mod := jl.Module
		if mod == "" {
			mod = jl.Mod
		}
		sym := jl.Symbol
		if sym == "" {
			sym = jl.Sym
		}
		ts := jl.TimestampMs
		if ts == 0 {
			ts = jl.TS
		}
		tid := jl.ThreadID
		if tid == 0 {
			tid = jl.TID
		}
		retVal := jl.RetVal
		if retVal == "" {
			retVal = jl.Ret
		}

		kind := strings.ToLower(strings.TrimSpace(jl.Kind))
		if kind == "" {
			kind = strings.ToLower(strings.TrimSpace(jl.Type))
		}
		if kind == "" {
			kind = strings.ToLower(strings.TrimSpace(jl.Event))
		}
		switch kind {
		case "", "instruction", "exec":
			if mnemonic != "" {
				kind = classifyInsnKind(mnemonic, operands)
			} else if jl.MemAddr != 0 {
				kind = KindMemRead
			} else {
				kind = KindInsn
			}
		case "insn":
			if mnemonic != "" {
				kind = classifyInsnKind(mnemonic, operands)
			}
		case "read", "memread":
			kind = KindMemRead
		case "write", "memwrite":
			kind = KindMemWrite
		case "enter":
			kind = KindJavaEnter
		case "exit", "leave":
			kind = KindJavaExit
		}

		if kind == KindJavaEnter || kind == KindJavaExit {
			sawJava++
		} else {
			sawNative++
		}

		regsBefore := convertFlexRegs(jl.RegsBefore)
		regsAfter := convertFlexRegs(jl.RegsAfter)
		if len(jl.Regs) > 0 {
			if len(regsAfter) == 0 {
				regsAfter = convertFlexRegs(jl.Regs)
			} else if len(regsBefore) == 0 {
				regsBefore = convertFlexRegs(jl.Regs)
			}
		}

		seq++
		evSeq := seq
		if jl.Seq > 0 {
			evSeq = jl.Seq
			if evSeq > seq {
				seq = evSeq
			}
		}

		rawStr := jl.Raw
		if rawStr == "" {
			rawStr = capRawLine(line)
		}

		ev := TraceEvent{
			Seq:         evSeq,
			TimestampMs: ts,
			ThreadID:    tid,
			Kind:        kind,
			Module:      mod,
			Address:     addr,
			Offset:      uint64(jl.Offset),
			Mnemonic:    strings.ToLower(mnemonic),
			Operands:    operands,
			RawBytes:    strings.ToLower(strings.TrimPrefix(jl.RawBytes, "0x")),
			Symbol:      sym,
			RegsBefore:  regsBefore,
			RegsAfter:   regsAfter,
			MemAddr:     uint64(jl.MemAddr),
			MemSize:     jl.MemSize,
			MemValueHex: strings.ToLower(strings.TrimPrefix(jl.MemValueHex, "0x")),
			Depth:       jl.Depth,
			Args:        jl.Args,
			RetVal:      retVal,
			Raw:         rawStr,
		}
		if ev.Offset > 0 && ev.Address > ev.Offset && session.ModuleBase == 0 {
			session.ModuleBase = ev.Address - ev.Offset
		}
		events = append(events, ev)
		return true
	})

	if explicitSource != "" {
		session.Source = explicitSource
	} else if isStalker {
		if sawJava > 0 && sawNative == 0 {
			session.Source = SourceJava
		} else {
			session.Source = SourceStalker
		}
	}
	return events, nil
}

func parseTenetTrace(raw string, session *ExecTraceSession) ([]TraceEvent, error) {
	var events []TraceEvent
	seq := 0

	scanLines(raw, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			return true
		}

		parts := strings.Split(line, ",")
		regs := make(map[string]uint64)
		var pc uint64
		var memReads []TraceEvent
		var memWrites []TraceEvent

		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			eq := strings.IndexByte(p, '=')
			if eq <= 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(p[:eq]))
			v := strings.TrimSpace(p[eq+1:])

			switch k {
			case "mr", "mw":
				colon := strings.IndexByte(v, ':')
				if colon <= 0 {
					continue
				}
				addrStr := strings.TrimSpace(v[:colon])
				hexData := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v[colon+1:]), "0x"))
				addr, err := parseHexUint64(addrStr)
				if err != nil {
					continue
				}
				sz := len(hexData) / 2
				if sz == 0 && len(hexData) > 0 {
					sz = 1
				}
				mev := TraceEvent{
					MemAddr:     addr,
					MemSize:     sz,
					MemValueHex: hexData,
					Raw:         capRawLine(p),
				}
				if k == "mr" {
					mev.Kind = KindMemRead
					memReads = append(memReads, mev)
				} else {
					mev.Kind = KindMemWrite
					memWrites = append(memWrites, mev)
				}
			default:
				val, err := parseHexUint64(v)
				if err != nil {
					continue
				}
				if k == "pc" || k == "rip" || k == "eip" || k == "r15" {
					pc = val
					if k == "rip" && session.Arch == "" {
						session.Arch = "x86_64"
					} else if k == "eip" && session.Arch == "" {
						session.Arch = "x86"
					}
				}
				regs[k] = val
			}
		}

		if pc == 0 && len(regs) == 0 && len(memReads) == 0 && len(memWrites) == 0 {
			return true
		}

		seq++
		events = append(events, TraceEvent{
			Seq:       seq,
			Kind:      KindInsn,
			Address:   pc,
			RegsAfter: regs,
			Raw:       capRawLine(line),
		})
		for _, mr := range memReads {
			seq++
			mr.Seq = seq
			mr.Address = pc
			events = append(events, mr)
		}
		for _, mw := range memWrites {
			seq++
			mw.Seq = seq
			mw.Address = pc
			events = append(events, mw)
		}
		return true
	})
	return events, nil
}

func parseJavaCallTrace(raw string, session *ExecTraceSession) ([]TraceEvent, error) {
	var events []TraceEvent
	seq := 0
	stackDepth := 0
	var symStack []string

	scanLines(raw, func(rawLine string) bool {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			return true
		}

		m := reJavaArrow.FindStringSubmatch(rawLine)
		if m == nil {
			return true
		}
		indent := m[1]
		tag := m[2]
		arrow := m[3]
		body := strings.TrimSpace(m[4])

		var tid int
		var ts int64
		if tag != "" {
			if tm := reTidTag.FindStringSubmatch(tag); tm != nil {
				tid, _ = strconv.Atoi(tm[1])
			}
			if tsm := reTsTag.FindStringSubmatch(tag); tsm != nil {
				ts, _ = strconv.ParseInt(tsm[1], 10, 64)
			}
		}

		isEnter := arrow == "-->" || arrow == ">>>" || arrow == "->"

		if isEnter {
			sym := body
			var args []string
			if lp := strings.IndexByte(body, '('); lp >= 0 {
				if rp := strings.LastIndexByte(body, ')'); rp > lp {
					sym = strings.TrimSpace(body[:lp])
					args = splitArgs(body[lp+1 : rp])
				}
			}
			depth := stackDepth
			if inferred := inferIndentDepth(indent); inferred > depth {
				depth = inferred
			}
			stackDepth++
			symStack = append(symStack, sym)

			seq++
			events = append(events, TraceEvent{
				Seq:         seq,
				TimestampMs: ts,
				ThreadID:    tid,
				Kind:        KindJavaEnter,
				Symbol:      sym,
				Args:        args,
				Depth:       depth,
				Raw:         capRawLine(trimmed),
			})
		} else {
			if stackDepth > 0 {
				stackDepth--
			}
			var sym, retVal string
			if idx := strings.Index(body, "=>"); idx >= 0 {
				sym = strings.TrimSpace(body[:idx])
				retVal = strings.TrimSpace(body[idx+2:])
			} else if idx := strings.Index(body, "="); idx >= 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(body[:idx])), "ret") {
				retVal = strings.TrimSpace(body[idx+1:])
			} else {
				retVal = body
			}
			if sym == "" && len(symStack) > 0 {
				sym = symStack[len(symStack)-1]
			}
			if len(symStack) > 0 {
				symStack = symStack[:len(symStack)-1]
			}

			seq++
			events = append(events, TraceEvent{
				Seq:         seq,
				TimestampMs: ts,
				ThreadID:    tid,
				Kind:        KindJavaExit,
				Symbol:      sym,
				RetVal:      retVal,
				Depth:       stackDepth,
				Raw:         capRawLine(trimmed),
			})
		}
		return true
	})
	if session.Arch == "" {
		session.Arch = "dalvik"
	}
	return events, nil
}

func parseQilingTrace(raw string, session *ExecTraceSession) ([]TraceEvent, error) {
	var events []TraceEvent
	seq := 0
	var lastPC uint64
	var lastMod string

	scanLines(raw, func(rawLine string) bool {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			return true
		}

		// Memory READ / WRITE
		if mm := reQilingMem.FindStringSubmatch(line); mm != nil {
			addr, err := strconv.ParseUint(mm[3], 16, 64)
			if err != nil {
				return true
			}
			op := strings.ToUpper(mm[1])
			if op == "" {
				op = strings.ToUpper(mm[2])
			}
			sz, szErr := parseIntAuto(mm[4])
			if szErr != nil || sz < 0 {
				sz = 0
			}
			valHex := strings.ToLower(mm[5])
			pc := lastPC
			if mm[6] != "" {
				if parsed, err := strconv.ParseUint(mm[6], 16, 64); err == nil {
					pc = parsed
				}
			}
			kind := KindMemRead
			if op == "WRITE" {
				kind = KindMemWrite
			}
			seq++
			events = append(events, TraceEvent{
				Seq:         seq,
				Kind:        kind,
				Module:      lastMod,
				Address:     pc,
				MemAddr:     addr,
				MemSize:     sz,
				MemValueHex: valHex,
				Raw:         capRawLine(line),
			})
			return true
		}

		// Also accept Unidbg-style memory lines inside generic traces
		if um := reUnidbgMem.FindStringSubmatch(line); um != nil {
			addr, err := strconv.ParseUint(um[2], 16, 64)
			if err != nil {
				return true
			}
			op := strings.ToUpper(um[1])
			sz, szErr := parseIntAuto(um[3])
			if szErr != nil || sz < 0 {
				sz = 0
			}
			valHex := strings.ToLower(um[4])
			pc := lastPC
			if um[5] != "" {
				if parsed, err := strconv.ParseUint(um[5], 16, 64); err == nil {
					pc = parsed
				}
			}
			kind := KindMemRead
			if op == "WRITE" {
				kind = KindMemWrite
			}
			seq++
			events = append(events, TraceEvent{
				Seq:         seq,
				Kind:        kind,
				Module:      lastMod,
				Address:     pc,
				MemAddr:     addr,
				MemSize:     sz,
				MemValueHex: valHex,
				Raw:         capRawLine(line),
			})
			return true
		}

		// Instruction line
		if im := reQilingInsn.FindStringSubmatch(line); im != nil {
			addr, err := strconv.ParseUint(im[1], 16, 64)
			if err == nil {
				mnemonic := strings.ToLower(strings.TrimSpace(im[2]))
				operands := strings.TrimSpace(im[3])
				comment := strings.TrimSpace(im[4])

				mod := lastMod
				if hm := reUnidbgHeader.FindStringSubmatch(line); hm != nil {
					mod = hm[1]
					lastMod = mod
				}

				regsBefore, regsAfter := parseBeforeAfterRegs(comment)
				kind := classifyInsnKind(mnemonic, operands)
				lastPC = addr

				seq++
				events = append(events, TraceEvent{
					Seq:        seq,
					Kind:       kind,
					Module:     mod,
					Address:    addr,
					Mnemonic:   mnemonic,
					Operands:   operands,
					RegsBefore: regsBefore,
					RegsAfter:  regsAfter,
					Raw:        capRawLine(line),
				})
				return true
			}
		}

		// Syscall line
		if sm := reSyscall.FindStringSubmatch(line); sm != nil {
			seq++
			events = append(events, TraceEvent{
				Seq:    seq,
				Kind:   KindSyscall,
				Symbol: sm[1],
				Args:   splitArgs(sm[2]),
				RetVal: strings.TrimSpace(sm[3]),
				Raw:    capRawLine(line),
			})
			return true
		}
		return true
	})
	return events, nil
}

func capRawLine(line string) string {
	const maxRawLen = 4096
	if len(line) <= maxRawLen {
		return line
	}
	return line[:maxRawLen] + "...<truncated>"
}

func finalizeSession(s *ExecTraceSession, events []TraceEvent) {
	uniquePCs := make(map[uint64]struct{})
	modCounts := make(map[string]int)

	for i := range events {
		ev := &events[i]
		if ev.Seq == 0 {
			ev.Seq = i + 1
		}
		if ev.Module != "" {
			modCounts[ev.Module]++
		}
		if ev.Offset == 0 && s.ModuleBase > 0 && ev.Address >= s.ModuleBase {
			ev.Offset = ev.Address - s.ModuleBase
		}
		if isInstructionEvent(*ev) {
			s.InsnCount++
			if ev.Address != 0 {
				uniquePCs[ev.Address] = struct{}{}
			} else if ev.Offset != 0 {
				uniquePCs[ev.Offset] = struct{}{}
			}
		}
		switch ev.Kind {
		case KindMemRead, KindMemWrite:
			s.MemOpCount++
		case KindCall, KindJavaEnter, KindJNI:
			s.CallCount++
		}
	}

	// Pick dominant module as TargetModule if not already set.
	if s.TargetModule == "" {
		bestMod := ""
		bestCnt := 0
		for mod, cnt := range modCounts {
			if cnt > bestCnt || (cnt == bestCnt && mod < bestMod) {
				bestMod = mod
				bestCnt = cnt
			}
		}
		s.TargetModule = bestMod
	}

	if s.Arch == "" {
		s.Arch = inferArch(events)
	}

	s.TotalEvents = len(events)
	s.UniquePCs = len(uniquePCs)
	s.Events = events
	s.Summary = AnalyzeSession(s)
}

func isInstructionEvent(ev TraceEvent) bool {
	switch ev.Kind {
	case KindInsn, KindCall, KindRet:
		return true
	case KindSyscall:
		return ev.Mnemonic != ""
	default:
		return false
	}
}

func classifyInsnKind(mnemonic, operands string) string {
	m := strings.ToLower(strings.TrimSpace(mnemonic))
	switch m {
	case "bl", "blr", "blx", "call", "callq", "jal", "jalr":
		return KindCall
	case "ret", "retaa", "retab", "retq", "iret", "iretq":
		return KindRet
	case "bx":
		if strings.EqualFold(strings.TrimSpace(operands), "lr") {
			return KindRet
		}
		return KindInsn
	case "svc", "syscall", "sysenter":
		return KindSyscall
	case "int":
		op := strings.ToLower(strings.TrimSpace(operands))
		if op == "0x80" || op == "128" {
			return KindSyscall
		}
		return KindInsn
	default:
		return KindInsn
	}
}

func splitInsn(text string) (mnemonic, operands string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ""
	}
	idx := strings.IndexAny(text, " \t")
	if idx < 0 {
		return strings.ToLower(text), ""
	}
	return strings.ToLower(strings.TrimSpace(text[:idx])), strings.TrimSpace(text[idx+1:])
}

func parseBeforeAfterRegs(text string) (before, after map[string]uint64) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	if arrow := strings.Index(text, "=>"); arrow >= 0 {
		b := parseRegMap(text[:arrow])
		a := parseRegMap(text[arrow+2:])
		return b, a
	}
	// When there is no "=>", registers printed inline after a semicolon or
	// instruction represent observed register state at this instruction.
	regs := parseRegMap(text)
	if len(regs) == 0 {
		return nil, nil
	}
	return regs, cloneRegMap(regs)
}

func parseRegMap(s string) map[string]uint64 {
	matches := reRegAssign.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(matches))
	for _, m := range matches {
		name := strings.ToLower(m[1])
		// Skip non-register metadata keys that happen to carry hex values.
		if name == "addr" || name == "size" || name == "value" || name == "val" {
			continue
		}
		if v, err := strconv.ParseUint(m[2], 16, 64); err == nil {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneRegMap(in map[string]uint64) map[string]uint64 {
	if len(in) == 0 {
		return nil
	}
	cp := make(map[string]uint64, len(in))
	for k, v := range in {
		cp[k] = v
	}
	return cp
}

func convertFlexRegs(in map[string]flexUint64) map[string]uint64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = uint64(v)
	}
	return out
}

func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty hex number")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return strconv.ParseUint(s, 16, 64)
}

func parseUintAuto(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty number")
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	if v, err := strconv.ParseUint(s, 10, 64); err == nil {
		return v, nil
	}
	return strconv.ParseUint(s, 16, 64)
}

func parseIntAuto(s string) (int, error) {
	v, err := parseUintAuto(s)
	if err != nil {
		return 0, err
	}
	if v > uint64(^uint(0)>>1) {
		return 0, errors.New("integer overflow")
	}
	return int(v), nil
}

func splitArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var args []string
	var cur strings.Builder
	depth := 0
	inQuote := byte(0)
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' && inQuote != 0 {
			cur.WriteByte(c)
			escaped = true
			continue
		}
		if inQuote != 0 {
			cur.WriteByte(c)
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
			cur.WriteByte(c)
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case ',':
			if depth == 0 {
				if tok := strings.TrimSpace(cur.String()); tok != "" {
					args = append(args, tok)
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
		args = append(args, tok)
	}
	return args
}

func inferIndentDepth(indent string) int {
	cols := 0
	for _, r := range indent {
		switch r {
		case '\t':
			cols += 2
		case ' ':
			cols++
		case '|', '│', '├', '└':
			cols++
		}
	}
	return cols / 2
}

func inferArch(events []TraceEvent) string {
	arm64Score, armScore, x64Score, x86Score, javaScore := 0, 0, 0, 0, 0
	limit := len(events)
	if limit > 200 {
		limit = 200
	}
	for i := 0; i < limit; i++ {
		ev := events[i]
		if ev.Kind == KindJavaEnter || ev.Kind == KindJavaExit {
			javaScore += 2
			continue
		}
		switch ev.Mnemonic {
		case "eor", "adrp", "cbz", "cbnz", "ldp", "stp", "blr", "movz", "movk":
			arm64Score += 2
		case "bx", "blx", "push", "pop":
			if strings.Contains(ev.Operands, "r0") || strings.Contains(ev.Operands, "lr") {
				armScore += 2
			}
		case "movq", "callq", "retq", "lea", "xor":
			x64Score++
		}
		checkReg := func(r string) {
			r = strings.ToLower(r)
			switch {
			case strings.HasPrefix(r, "x") && len(r) >= 2 && r[1] >= '0' && r[1] <= '9':
				arm64Score += 2
			case strings.HasPrefix(r, "w") && len(r) >= 2 && r[1] >= '0' && r[1] <= '9':
				arm64Score += 2
			case r == "rax" || r == "rbx" || r == "rcx" || r == "rdx" || r == "rsi" || r == "rdi" || r == "rsp" || r == "rbp" || r == "rip":
				x64Score += 3
			case r == "eax" || r == "ebx" || r == "ecx" || r == "edx" || r == "esi" || r == "edi" || r == "esp" || r == "ebp" || r == "eip":
				x86Score += 3
			case strings.HasPrefix(r, "r") && len(r) >= 2 && r[1] >= '0' && r[1] <= '9':
				armScore++
			}
		}
		for r := range ev.RegsBefore {
			checkReg(r)
		}
		for r := range ev.RegsAfter {
			checkReg(r)
		}
		for _, tok := range extractRegTokens(ev.Operands) {
			checkReg(tok)
		}
	}

	type scored struct {
		arch  string
		score int
	}
	candidates := []scored{
		{"arm64", arm64Score},
		{"x86_64", x64Score},
		{"arm", armScore},
		{"x86", x86Score},
		{"dalvik", javaScore},
	}
	best := "unknown"
	bestScore := 0
	for _, c := range candidates {
		if c.score > bestScore {
			bestScore = c.score
			best = c.arch
		}
	}
	return best
}
