package reverse

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features"
)

// Handler Reverser feature.
//
// xray:api:alpha
type Handler interface {
	common.Runnable
	common.Closable

	GetTag() string
	GetDomain() string
}

// Manager Manage Reverse Objects.
//
// xray:api:alpha
type Manager interface {
	features.Feature

	AddBridge(ctx context.Context, bridge Handler) error
	RemoveBridge(ctx context.Context, tag string) error
	GetBridges(ctx context.Context) (interface{}, error)
	GetBridge(ctx context.Context, tag string) (interface{}, error)
	AddPortal(ctx context.Context, portal Handler) error
	RemovePortal(ctx context.Context, tag string) error
	GetPortals(ctx context.Context) (interface{}, error)
	GetPortal(ctx context.Context, tag string) (interface{}, error)
}

// ManagerType returns the type of Manager interface. Can be used for implementing common.HasType.
//
// xray:api:alpha
func ManagerType() interface{} {
	return (*Manager)(nil)
}

// NoopManager is an implementation of Manager, which doesn't has actual functionalities.
type NoopManager struct{}

// Type implements common.HasType.
func (NoopManager) Type() interface{} {
	return ManagerType()
}

// Start implements common.Runnable.
func (NoopManager) Start() error { return nil }

// Close implements common.Closable.
func (NoopManager) Close() error { return nil }

func (NoopManager) AddBridge(ctx context.Context, bridge Handler) error { return nil }

func (NoopManager) RemoveBridge(ctx context.Context, tag string) error { return nil }

func (NoopManager) GetBridges(ctx context.Context) (interface{}, error) { return nil, nil }

func (NoopManager) GetBridge(ctx context.Context, tag string) (interface{}, error) { return nil, nil }

func (NoopManager) AddPortal(ctx context.Context, portal Handler) error { return nil }

func (NoopManager) RemovePortal(ctx context.Context, tag string) error { return nil }

func (NoopManager) GetPortals(ctx context.Context) (interface{}, error) { return nil, nil }

func (NoopManager) GetPortal(ctx context.Context, tag string) (interface{}, error) { return nil, nil }
