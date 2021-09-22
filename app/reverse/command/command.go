package command

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	reverse2 "github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/reverse"
	"google.golang.org/grpc"
)

// reverseServer is an implementation of ReverseService.
type reverseServer struct {
	s       *core.Instance
	reverse reverse.Manager
}

func (s *reverseServer) AddBridge(ctx context.Context, request *AddBridgeRequest) (*AddBridgeResponse, error) {
	err := s.reverse.AddBridge(ctx, request.Config)
	return &AddBridgeResponse{}, err
}

func (s *reverseServer) RemoveBridge(ctx context.Context, request *RemoveBridgeRequest) (*RemoveBridgeResponse, error) {
	err := s.reverse.RemoveBridge(ctx, request.Tag)
	return &RemoveBridgeResponse{}, err
}

func (s *reverseServer) GetBridges(ctx context.Context, request *GetBridgesRequest) (*GetBridgesResponse, error) {
	resp := &GetBridgesResponse{}
	bridges, err := s.reverse.GetBridges(ctx)
	if err != nil {
		return resp, err
	}

	resp.Configs = bridges.([]*reverse2.BridgeConfig)
	return resp, nil
}

func (s *reverseServer) GetBridge(ctx context.Context, request *GetBridgeRequest) (*GetBridgeResponse, error) {
	resp := &GetBridgeResponse{}
	bridge, err := s.reverse.GetBridge(ctx, request.Tag)
	if err != nil {
		return nil, err
	}
	resp.Config = bridge.(*reverse2.BridgeConfig)
	return resp, nil
}

func (s *reverseServer) AddPortal(ctx context.Context, request *AddPortalRequest) (*AddPortalResponse, error) {
	err := s.reverse.AddPortal(ctx, request.Config)
	return &AddPortalResponse{}, err
}

func (s *reverseServer) RemovePortal(ctx context.Context, request *RemovePortalRequest) (*RemovePortalResponse, error) {
	err := s.reverse.RemovePortal(ctx, request.Tag)
	return &RemovePortalResponse{}, err
}

func (s *reverseServer) GetPortals(ctx context.Context, request *GetPortalsRequest) (*GetPortalsResponse, error) {
	resp := &GetPortalsResponse{}
	portals, err := s.reverse.GetPortals(ctx)
	if err != nil {
		return resp, err
	}

	resp.Configs = portals.([]*reverse2.PortalConfig)
	return resp, nil
}

func (s *reverseServer) GetPortal(ctx context.Context, request *GetPortalRequest) (*GetPortalResponse, error) {
	resp := &GetPortalResponse{}
	portal, err := s.reverse.GetPortal(ctx, request.Tag)
	if err != nil {
		return nil, err
	}
	resp.Config = portal.(*reverse2.PortalConfig)
	return resp, nil
}

func (s *reverseServer) mustEmbedUnimplementedReverseServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	m := &reverseServer{
		s:       s.v,
		reverse: nil,
	}

	common.Must(s.v.RequireFeatures(func(reverse reverse.Manager) {
		m.reverse = reverse
	}))

	RegisterReverseServiceServer(server, m)

	// For compatibility purposes
	vCoreDesc := ReverseService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.reverse.command.ReverseService"
	server.RegisterService(&vCoreDesc, m)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
