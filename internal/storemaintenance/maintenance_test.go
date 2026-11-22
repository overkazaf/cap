package storemaintenance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

type memoryStore struct {
	store.Store
	flows []*types.Flow
}

func (s *memoryStore) SaveFlow(flow *types.Flow) error {
	s.flows = append(s.flows, flow)
	return nil
}

func (s *memoryStore) ListFlows(filter types.FlowFilter) ([]*types.Flow, error) {
	limit := len(s.flows)
	if filter.Limit > 0 && filter.Limit < limit {
		limit = filter.Limit
	}
	return append([]*types.Flow(nil), s.flows[:limit]...), nil
}

func (s *memoryStore) DeleteFlow(id string) error {
	for index, flow := range s.flows {
		if flow.ID == id {
			s.flows = append(s.flows[:index], s.flows[index+1:]...)
			return nil
		}
	}
	return errors.New("not found")
}

func TestClearFlows(t *testing.T) {
	st := &memoryStore{}
	for index := range 1201 {
		st.flows = append(st.flows, &types.Flow{ID: fmt.Sprint(index)})
	}
	if err := ClearFlows(context.Background(), st, types.FlowFilter{}); err != nil {
		t.Fatal(err)
	}
	if len(st.flows) != 0 {
		t.Fatalf("remaining flows = %d", len(st.flows))
	}
}

func TestClearFlowsRejectsNilStore(t *testing.T) {
	if err := ClearFlows(context.Background(), nil, types.FlowFilter{}); err == nil {
		t.Fatal("expected error")
	}
}
