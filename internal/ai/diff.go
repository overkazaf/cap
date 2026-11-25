package ai

import (
	"fmt"
	"strings"
)

const (
	unifiedDiffContext = 3
	maxLCSCells        = 2_000_000
)

type diffOpKind uint8

const (
	diffEqual diffOpKind = iota
	diffDelete
	diffInsert
)

type diffLine struct {
	kind diffOpKind
	text string
	oldN int // 1-based line number in oldText (0 if insert)
	newN int // 1-based line number in newText (0 if delete)
}

// ComputeUnifiedDiff computes a pure-Go LCS-based unified diff with @@ hunks
// between oldText and newText. Returns "" when both inputs are identical.
func ComputeUnifiedDiff(oldText, newText string) string {
	normOld := strings.ReplaceAll(oldText, "\r\n", "\n")
	normNew := strings.ReplaceAll(newText, "\r\n", "\n")
	if normOld == normNew {
		return ""
	}

	oldLines := splitLinesForDiff(normOld)
	newLines := splitLinesForDiff(normNew)

	ops := computeLineDiffOps(oldLines, newLines)
	if len(ops) == 0 {
		return ""
	}

	// Group changed operations into hunks with surrounding context lines.
	type hunkRange struct {
		start int
		end   int // exclusive index in ops
	}
	var hunks []hunkRange
	for i, op := range ops {
		if op.kind == diffEqual {
			continue
		}
		start := i - unifiedDiffContext
		if start < 0 {
			start = 0
		}
		end := i + unifiedDiffContext + 1
		if end > len(ops) {
			end = len(ops)
		}
		if len(hunks) > 0 && start <= hunks[len(hunks)-1].end {
			if end > hunks[len(hunks)-1].end {
				hunks[len(hunks)-1].end = end
			}
		} else {
			hunks = append(hunks, hunkRange{start: start, end: end})
		}
	}
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("--- a/code\n")
	b.WriteString("+++ b/code\n")
	for _, h := range hunks {
		slice := ops[h.start:h.end]
		oldStart, oldCount, newStart, newCount := computeHunkHeader(slice, ops, h.start)
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, op := range slice {
			switch op.kind {
			case diffEqual:
				b.WriteByte(' ')
				b.WriteString(op.text)
				b.WriteByte('\n')
			case diffDelete:
				b.WriteByte('-')
				b.WriteString(op.text)
				b.WriteByte('\n')
			case diffInsert:
				b.WriteByte('+')
				b.WriteString(op.text)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func splitLinesForDiff(s string) []string {
	if s == "" {
		return nil
	}
	trimmed := strings.TrimSuffix(s, "\n")
	return strings.Split(trimmed, "\n")
}

func computeLineDiffOps(oldLines, newLines []string) []diffLine {
	// Trim common prefix and suffix to keep the LCS table compact.
	prefix := 0
	for prefix < len(oldLines) && prefix < len(newLines) && oldLines[prefix] == newLines[prefix] {
		prefix++
	}
	oldEnd := len(oldLines)
	newEnd := len(newLines)
	for oldEnd > prefix && newEnd > prefix && oldLines[oldEnd-1] == newLines[newEnd-1] {
		oldEnd--
		newEnd--
	}

	var ops []diffLine
	for i := 0; i < prefix; i++ {
		ops = append(ops, diffLine{kind: diffEqual, text: oldLines[i], oldN: i + 1, newN: i + 1})
	}

	midOld := oldLines[prefix:oldEnd]
	midNew := newLines[prefix:newEnd]

	m := len(midOld)
	n := len(midNew)
	if m == 0 {
		for j := 0; j < n; j++ {
			ops = append(ops, diffLine{kind: diffInsert, text: midNew[j], newN: prefix + j + 1})
		}
	} else if n == 0 {
		for i := 0; i < m; i++ {
			ops = append(ops, diffLine{kind: diffDelete, text: midOld[i], oldN: prefix + i + 1})
		}
	} else if int64(m)*int64(n) > maxLCSCells {
		// Bounded-memory fallback for gigantic completely diverging files.
		for i := 0; i < m; i++ {
			ops = append(ops, diffLine{kind: diffDelete, text: midOld[i], oldN: prefix + i + 1})
		}
		for j := 0; j < n; j++ {
			ops = append(ops, diffLine{kind: diffInsert, text: midNew[j], newN: prefix + j + 1})
		}
	} else {
		// Classic DP LCS on middle slice: dp[i*(n+1)+j] = LCS(midOld[i:], midNew[j:]).
		cols := n + 1
		dp := make([]int, (m+1)*cols)
		for i := m - 1; i >= 0; i-- {
			row := i * cols
			nextRow := (i + 1) * cols
			for j := n - 1; j >= 0; j-- {
				if midOld[i] == midNew[j] {
					dp[row+j] = dp[nextRow+j+1] + 1
				} else if dp[nextRow+j] >= dp[row+j+1] {
					dp[row+j] = dp[nextRow+j]
				} else {
					dp[row+j] = dp[row+j+1]
				}
			}
		}

		i, j := 0, 0
		for i < m && j < n {
			if midOld[i] == midNew[j] {
				ops = append(ops, diffLine{
					kind: diffEqual,
					text: midOld[i],
					oldN: prefix + i + 1,
					newN: prefix + j + 1,
				})
				i++
				j++
			} else if dp[(i+1)*cols+j] >= dp[i*cols+j+1] {
				ops = append(ops, diffLine{kind: diffDelete, text: midOld[i], oldN: prefix + i + 1})
				i++
			} else {
				ops = append(ops, diffLine{kind: diffInsert, text: midNew[j], newN: prefix + j + 1})
				j++
			}
		}
		for i < m {
			ops = append(ops, diffLine{kind: diffDelete, text: midOld[i], oldN: prefix + i + 1})
			i++
		}
		for j < n {
			ops = append(ops, diffLine{kind: diffInsert, text: midNew[j], newN: prefix + j + 1})
			j++
		}
	}

	suffixLen := len(oldLines) - oldEnd
	for k := 0; k < suffixLen; k++ {
		ops = append(ops, diffLine{
			kind: diffEqual,
			text: oldLines[oldEnd+k],
			oldN: oldEnd + k + 1,
			newN: newEnd + k + 1,
		})
	}
	return ops
}

func computeHunkHeader(slice, all []diffLine, startIdx int) (oldStart, oldCount, newStart, newCount int) {
	for _, op := range slice {
		if op.kind != diffInsert {
			if oldStart == 0 {
				oldStart = op.oldN
			}
			oldCount++
		}
		if op.kind != diffDelete {
			if newStart == 0 {
				newStart = op.newN
			}
			newCount++
		}
	}
	if oldStart == 0 {
		// Pure insertion hunk: anchor to preceding old line number (or 0 if at BOF).
		for i := startIdx - 1; i >= 0; i-- {
			if all[i].oldN > 0 {
				oldStart = all[i].oldN
				break
			}
		}
	}
	if newStart == 0 {
		// Pure deletion hunk: anchor to preceding new line number (or 0 if at BOF).
		for i := startIdx - 1; i >= 0; i-- {
			if all[i].newN > 0 {
				newStart = all[i].newN
				break
			}
		}
	}
	return oldStart, oldCount, newStart, newCount
}
