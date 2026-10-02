package gui

import (
	"sync"

	"github.com/overkazaf/cap/internal/proxy"
	"github.com/overkazaf/cap/internal/store"
	"github.com/overkazaf/cap/internal/types"
)

type AppState struct {
	Store     store.Store
	Proxy     *proxy.Proxy
	FlowCh    chan *types.Flow
	Flows     []*types.Flow
	IsRunning bool

	OnFlowsChanged func()

	mu sync.Mutex
}

func NewAppState(st store.Store) *AppState {
	return &AppState{
		Store:  st,
		FlowCh: make(chan *types.Flow, 100),
	}
}

func (s *AppState) AddFlow(f *types.Flow) {
	s.mu.Lock()
	s.Flows = append([]*types.Flow{f}, s.Flows...)
	s.mu.Unlock()
	if s.OnFlowsChanged != nil {
		s.OnFlowsChanged()
	}
}

func (s *AppState) GetFlows() []*types.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]*types.Flow, len(s.Flows))
	copy(cp, s.Flows)
	return cp
}

func (s *AppState) GetFlow(id string) *types.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.Flows {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (s *AppState) ClearFlows() {
	s.mu.Lock()
	s.Flows = nil
	s.mu.Unlock()
	if s.OnFlowsChanged != nil {
		s.OnFlowsChanged()
	}
}
