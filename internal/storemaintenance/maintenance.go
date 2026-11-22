package storemaintenance

import (
	"context"
	"fmt"

	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

// ClearFlows deletes flows page-by-page until the filtered set is empty.
// Keeping each page in its own statement bounds transaction size and avoids
// holding every flow ID in memory.
func ClearFlows(ctx context.Context, st store.Store, filter types.FlowFilter) error {
	if st == nil {
		return fmt.Errorf("storemaintenance: store is nil")
	}
	const pageSize = 500
	filter.Limit = pageSize
	filter.Offset = 0

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("storemaintenance: clear canceled: %w", err)
		}
		flows, err := st.ListFlows(filter)
		if err != nil {
			return fmt.Errorf("storemaintenance: list flows: %w", err)
		}
		if len(flows) == 0 {
			return nil
		}
		for _, flow := range flows {
			if err := st.DeleteFlow(flow.ID); err != nil {
				return fmt.Errorf("storemaintenance: delete flow %q: %w", flow.ID, err)
			}
		}
	}
}
