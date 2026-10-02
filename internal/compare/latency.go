package compare

import (
	"fmt"
	"math"
)

// compareLatency builds a LatencyDiff from two flows' LatencyMs.
func compareLatency(a, b int64) LatencyDiff {
	ld := LatencyDiff{A: a, B: b, DiffMs: b - a}

	switch {
	case a == 0 && b == 0:
		ld.Percent = "0%"
	case a == 0:
		// A percentage change from a zero baseline is undefined; show the
		// direction of the change instead of a meaningless ratio.
		if b > 0 {
			ld.Percent = "+inf%"
		} else {
			ld.Percent = "-inf%"
		}
	default:
		pct := float64(b-a) / float64(a) * 100
		ld.Percent = formatPercent(pct)
	}

	return ld
}

// formatPercent renders pct rounded to the nearest whole percent with an
// explicit sign, e.g. 25.0 -> "+25%", -24.6 -> "-25%", 0.4 -> "0%" (rounds
// to zero, shown without a sign).
func formatPercent(pct float64) string {
	rounded := math.Round(pct)
	switch {
	case rounded > 0:
		return fmt.Sprintf("+%d%%", int64(rounded))
	case rounded < 0:
		return fmt.Sprintf("-%d%%", int64(-rounded))
	default:
		return "0%"
	}
}
