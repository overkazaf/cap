package storemaintenance

import (
	"context"
	"testing"
	"time"

	"github.com/overkazaf/cap/internal/store/sqlite"
	"github.com/overkazaf/cap/internal/types"
)

func TestClearFlowsSQLite(t *testing.T) {
	st, err := sqlite.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	for index := range 1201 {
		flow := &types.Flow{
			ID:        "flow-" + time.Duration(index).String(),
			Timestamp: time.Now().Add(time.Duration(index) * time.Second),
		}
		if err := st.SaveFlow(flow); err != nil {
			t.Fatal(err)
		}
	}
	if err := ClearFlows(context.Background(), st, types.FlowFilter{}); err != nil {
		t.Fatal(err)
	}
	flows, err := st.ListFlows(types.FlowFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 0 {
		t.Fatalf("remaining flows = %d", len(flows))
	}
}
