package store

import "github.com/overkazaf/cap/internal/types"

type Store interface {
	SaveFlow(flow *types.Flow) error
	GetFlow(id string) (*types.Flow, error)
	ListFlows(filter types.FlowFilter) ([]*types.Flow, error)
	DeleteFlow(id string) error
	UpdateTags(id string, tags []string) error
	UpdateSourceRef(id string, ref *types.SourceRef) error
	Close() error
}
