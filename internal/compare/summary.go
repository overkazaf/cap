package compare

import (
	"fmt"
	"strings"
)

// summarize builds the short, comma-separated description stored in
// Comparison.Summary, e.g. "3 header diffs, body changed, status same". It
// covers the three signals most useful at a glance — header diff count,
// whether either body changed, and whether the status changed; callers
// wanting the full picture should inspect the structured fields instead.
func summarize(c *Comparison) string {
	headerTotal := len(c.Headers.Added) + len(c.Headers.Removed) + len(c.Headers.Changed)
	bodyChanged := c.ReqBody.Type != "identical" || c.RespBody.Type != "identical"

	parts := []string{
		headerDiffClause(headerTotal),
		changeClause("body", bodyChanged),
		changeClause("status", c.Status.Changed),
	}
	return strings.Join(parts, ", ")
}

// headerDiffClause renders the header-count clause of the summary, handling
// the 0/1/many cases ("no header diffs", "1 header diff", "N header diffs").
func headerDiffClause(n int) string {
	switch n {
	case 0:
		return "no header diffs"
	case 1:
		return "1 header diff"
	default:
		return fmt.Sprintf("%d header diffs", n)
	}
}

// changeClause renders a "<label> changed"/"<label> same" clause.
func changeClause(label string, changed bool) string {
	if changed {
		return label + " changed"
	}
	return label + " same"
}
