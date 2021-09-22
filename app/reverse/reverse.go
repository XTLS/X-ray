package reverse

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/reverse"
	"github.com/xtls/xray-core/features/routing"
)

const (
	internalDomain = "reverse.internal.example.com"
)

func isDomain(dest net.Destination, domain string) bool {
	return dest.Address.Family().IsDomain() && dest.Address.Domain() == domain
}

func isInternalDomain(dest net.Destination) bool {
	return isDomain(dest, internalDomain)
}

type Reverse struct {
	bridges []*Bridge
	portals []*Portal
	d       routing.Dispatcher
	ohm     outbound.Manager
}

func (r *Reverse) Init(config *Config, d routing.Dispatcher, ohm outbound.Manager) error {
	r.d = d
	r.ohm = ohm

	for _, bConfig := range config.BridgeConfig {
		b, err := NewBridge(bConfig, d)
		if err != nil {
			return err
		}
		r.bridges = append(r.bridges, b)
	}

	for _, pConfig := range config.PortalConfig {
		p, err := NewPortal(pConfig, ohm)
		if err != nil {
			return err
		}
		r.portals = append(r.portals, p)
	}

	return nil
}

func (r *Reverse) Type() interface{} {
	return reverse.ManagerType()
}

func (r *Reverse) Start() error {
	for _, b := range r.bridges {
		if err := b.Start(); err != nil {
			return err
		}
	}

	for _, p := range r.portals {
		if err := p.Start(); err != nil {
			return err
		}
	}

	return nil
}

func (r *Reverse) Close() error {
	var errs []error
	for _, b := range r.bridges {
		errs = append(errs, b.Close())
	}

	for _, p := range r.portals {
		errs = append(errs, p.Close())
	}

	return errors.Combine(errs...)
}

func (r *Reverse) addHandler(ctx context.Context, handler reverse.Handler) error {
	tag := handler.GetTag()
	domain := handler.GetDomain()
	if len(tag) == 0 || len(domain) == 0 {
		return newError("tag or domain is empty")
	}

	var h interface{}
	var err error

	// create object
	switch handler.(type) {
	case *BridgeConfig:
		{
			h, err = NewBridge(&BridgeConfig{
				Tag:    tag,
				Domain: domain,
			}, r.d)
		}
	case *PortalConfig:
		{
			h, err = NewPortal(&PortalConfig{
				Tag:    tag,
				Domain: domain,
			}, r.ohm)
		}
	}

	if err != nil {
		return err
	}

	// start bridge
	err = h.(reverse.Handler).Start()
	if err != nil {
		return err
	}

	// append slice
	switch handler.(type) {
	case *BridgeConfig:
		{
			r.bridges = append(r.bridges, h.(*Bridge))
		}
	case *PortalConfig:
		{
			r.portals = append(r.portals, h.(*Portal))
		}
	}

	return err
}

// findHandler Find the corresponding handler based on the tag and the specified type
func (r *Reverse) findHandler(tag string, config reverse.Handler) (handler reverse.Handler, index int, err error) {
	index = -1
	switch config.(type) {
	case *Bridge, *BridgeConfig:
		{
			for k, v := range r.bridges {
				if v.tag == tag {
					index = k
					handler = v
					return
				}
			}
		}
	case *Portal, *PortalConfig:
		{
			for k, v := range r.portals {
				if v.tag == tag {
					index = k
					handler = v
					return
				}
			}
		}
	}

	err = newError("The specified tag was not found")
	return
}

// AddBridge Implement the Manager interface.
func (r *Reverse) AddBridge(ctx context.Context, bridge reverse.Handler) error {
	tag := bridge.GetTag()
	_, idx, _ := r.findHandler(tag, bridge)
	if idx > -1 {
		err := newError("The tag[", tag, "] already exists")
		err.WriteToLog(session.ExportIDToError(ctx))
		return err
	}

	err := r.addHandler(ctx, bridge)
	if err != nil {
		return err
	}
	newError("The bridge has been added successfully through the API.[", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemoveBridge Implement the Manager interface.
func (r *Reverse) RemoveBridge(ctx context.Context, tag string) error {
	b, idx, err := r.findHandler(tag, &Bridge{})
	if err != nil {
		return err
	}
	err = b.Close()
	if err != nil {
		return err
	}

	r.bridges = append(r.bridges[:idx], r.bridges[idx+1:]...)
	newError("The bridge has been removed through the API. [", tag, "] ").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// GetBridges Implement the Manager interface.
func (r *Reverse) GetBridges(ctx context.Context) (interface{}, error) {
	if len(r.bridges) == 0 {
		err := newError("This bridges has no elements")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}
	configs := make([]*BridgeConfig, 0)
	for _, bridge := range r.bridges {
		configs = append(configs, &BridgeConfig{
			Tag:    bridge.tag,
			Domain: bridge.domain,
		})
	}

	return configs, nil
}

// GetBridge Implement the Manager interface.
func (r *Reverse) GetBridge(ctx context.Context, tag string) (interface{}, error) {
	if len(r.bridges) == 0 {
		err := newError("This bridges has no elements")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}
	bridge := &BridgeConfig{}
	handler, idx, err := r.findHandler(tag, bridge)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		err := newError("This tag does not exist. [", tag, "]")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}

	bridge.Tag = handler.GetTag()
	bridge.Domain = handler.GetDomain()

	return bridge, nil
}

// AddPortal Implement the Manager interface.
func (r *Reverse) AddPortal(ctx context.Context, portal reverse.Handler) error {
	tag := portal.GetTag()
	_, idx, _ := r.findHandler(tag, portal)
	if idx > -1 {
		err := newError("The tag[", tag, "] already exists")
		err.WriteToLog(session.ExportIDToError(ctx))
		return err
	}
	err := r.addHandler(ctx, portal)
	if err != nil {
		return err
	}
	newError("The portal has been added successfully through the API.[", tag, "]").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// RemovePortal Implement the Manager interface.
func (r *Reverse) RemovePortal(ctx context.Context, tag string) error {
	p, idx, err := r.findHandler(tag, &Portal{})
	if err != nil {
		return err
	}
	err = p.Close()
	if err != nil {
		return err
	}

	r.portals = append(r.portals[:idx], r.portals[idx+1:]...)
	newError("The bridge has been removed through the API. [", tag, "] ").WriteToLog(session.ExportIDToError(ctx))
	return nil
}

// GetPortals Implement the Manager interface.
func (r *Reverse) GetPortals(ctx context.Context) (interface{}, error) {
	if len(r.portals) == 0 {
		err := newError("This bridges has no elements")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}
	configs := make([]*PortalConfig, 0)
	for _, portal := range r.portals {
		configs = append(configs, &PortalConfig{
			Tag:    portal.tag,
			Domain: portal.domain,
		})
	}

	return configs, nil
}

// GetPortal Implement the Manager interface.
func (r *Reverse) GetPortal(ctx context.Context, tag string) (interface{}, error) {
	if len(r.portals) == 0 {
		err := newError("This portals has no elements")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}
	portal := &PortalConfig{}
	handler, idx, err := r.findHandler(tag, portal)
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		err := newError("This tag does not exist. [", tag, "]")
		err.WriteToLog(session.ExportIDToError(ctx))
		return nil, err
	}

	portal.Tag = handler.GetTag()
	portal.Domain = handler.GetDomain()

	return portal, nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		r := new(Reverse)
		if err := core.RequireFeatures(ctx, func(d routing.Dispatcher, om outbound.Manager) error {
			return r.Init(config.(*Config), d, om)
		}); err != nil {
			return nil, err
		}
		return r, nil
	}))
}
