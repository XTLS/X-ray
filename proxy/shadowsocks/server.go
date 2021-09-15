package shadowsocks

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/udp"
)

type Server struct {
	config        *ServerConfig
	validator     *Validator
	policyManager policy.Manager
	cone          bool
}

// NewServer create a new Shadowsocks server.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := new(Validator)
	for _, user := range config.Users {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, newError("failed to get shadowsocks user").Base(err).AtError()
		}

		if err := validator.Add(u); err != nil {
			return nil, newError("failed to add user").Base(err).AtError()
		}
	}

	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	return s, nil
}

// AddUser implements proxy.UserManager.AddUser().
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (s *Server) RemoveUser(ctx context.Context, e string) error {
	return s.validator.Del(e)
}

func (s *Server) Network() []net.Network {
	list := s.config.Network
	if len(list) == 0 {
		list = append(list, net.Network_TCP)
	}
	return list
}

func (s *Server) Process(ctx context.Context, network net.Network, conn internet.Connection, dispatcher routing.Dispatcher) error {
	switch network {
	case net.Network_TCP:
		return s.handleConnection(ctx, conn, dispatcher)
	case net.Network_UDP:
		return s.handleUDPPayload(ctx, conn, dispatcher)
	default:
		return newError("unknown network: ", network)
	}
}

func (s *Server) handleUDPPayload(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		request := protocol.RequestHeaderFromContext(ctx)
		if request == nil {
			return
		}

		payload := packet.Payload

		if payload.UDP != nil {
			request = &protocol.RequestHeader{
				User:    request.User,
				Address: payload.UDP.Address,
				Port:    payload.UDP.Port,
			}
		}

		data, err := EncodeUDPPacket(request, payload.Bytes())
		payload.Release()
		if err != nil {
			newError("failed to encode UDP packet").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			return
		}
		defer data.Release()

		conn.Write(data.Bytes())
	})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}

	var dest *net.Destination

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			break
		}

		for _, payload := range mpayload {
			var request *protocol.RequestHeader
			var data *buf.Buffer
			var err error

			if inbound.User != nil {
				validator := new(Validator)
				validator.Add(inbound.User)
				request, data, err = DecodeUDPPacket(validator, payload)
			} else {
				request, data, err = DecodeUDPPacket(s.validator, payload)
				if err == nil {
					inbound.User = request.User
				}
			}

			if err != nil {
				if inbound.Source.IsValid() {
					newError("dropping invalid UDP packet from: ", inbound.Source).Base(err).WriteToLog(session.ExportIDToError(ctx))
					log.Record(&log.AccessMessage{
						From:   inbound.Source,
						To:     "",
						Status: log.AccessRejected,
						Reason: err,
					})
				}
				payload.Release()
				continue
			}

			destination := request.Destination()

			currentPacketCtx := ctx
			if inbound.Source.IsValid() {
				currentPacketCtx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
					From:   inbound.Source,
					To:     destination,
					Status: log.AccessAccepted,
					Reason: "",
					Email:  request.User.Email,
				})
			}
			newError("tunnelling request to ", destination).WriteToLog(session.ExportIDToError(currentPacketCtx))

			data.UDP = &destination

			if !s.cone || dest == nil {
				dest = &destination
			}

			currentPacketCtx = protocol.ContextWithRequestHeader(currentPacketCtx, request)
			udpServer.Dispatch(currentPacketCtx, *dest, data)
		}
	}

	return nil
}

func (s *Server) handleConnection(ctx context.Context, conn internet.Connection, dispatcher routing.Dispatcher) error {
	sessionPolicy := s.policyManager.ForLevel(0)
	if err := conn.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("unable to set read deadline").Base(err).AtWarning()
	}

	bufferedReader := buf.BufferedReader{Reader: buf.NewReader(conn)}
	request, bodyReader, err := ReadTCPSession(s.validator, &bufferedReader)
	if err != nil {
		log.Record(&log.AccessMessage{
			From:   conn.RemoteAddr(),
			To:     "",
			Status: log.AccessRejected,
			Reason: err,
		})
		return newError("failed to create request from: ", conn.RemoteAddr()).Base(err)
	}
	conn.SetReadDeadline(time.Time{})

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = request.User

	dest := request.Destination()
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  request.User.Email,
	})
	newError("tunnelling request to ", dest).WriteToLog(session.ExportIDToError(ctx))

	sessionPolicy = s.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		bufferedWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		responseWriter, err := WriteTCPResponse(request, bufferedWriter)
		if err != nil {
			return newError("failed to write response").Base(err)
		}

		{
			payload, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			if err := responseWriter.WriteMultiBuffer(payload); err != nil {
				return err
			}
		}

		if err := bufferedWriter.SetBuffered(false); err != nil {
			return err
		}

		if err := buf.Copy(link.Reader, responseWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		if err := buf.Copy(bodyReader, link.Writer, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	var requestDoneAndCloseWriter = task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}

	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
