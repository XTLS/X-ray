package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
)

type requestHandler struct {
	path             string
	ln               *Listener
	UsePathEarlyData bool
}

var replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")

var upgrader = &websocket.Upgrader{
	ReadBufferSize:   4 * 1024,
	WriteBufferSize:  4 * 1024,
	HandshakeTimeout: time.Second * 4,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (h *requestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var extraReader io.Reader
	var responseHeader = http.Header{}

	if !h.UsePathEarlyData {
		if request.URL.Path != h.path {
			writer.WriteHeader(http.StatusNotFound)
			return
		}

		if str := request.Header.Get("Sec-WebSocket-Protocol"); str != "" {
			if ed, err := base64.RawURLEncoding.DecodeString(replacer.Replace(str)); err == nil && len(ed) > 0 {
				extraReader = bytes.NewReader(ed)
				responseHeader.Set("Sec-WebSocket-Protocol", str)
			}
		}
	} else {
		if strings.HasPrefix(request.URL.RequestURI(), h.path) {
			if ed, err := base64.RawURLEncoding.DecodeString(request.URL.RequestURI()[len(h.path):]); err == nil && len(ed) > 0 {
				extraReader = bytes.NewReader(ed)
			}
		} else {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
	}

	conn, err := upgrader.Upgrade(writer, request, responseHeader)
	if err != nil {
		newError("failed to convert to WebSocket connection").Base(err).WriteToLog()
		return
	}

	forwardedAddrs := http_proto.ParseXForwardedFor(request.Header)
	remoteAddr := conn.RemoteAddr()
	if len(forwardedAddrs) > 0 && forwardedAddrs[0].Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddrs[0].IP(),
			Port: int(0),
		}
	}

	h.ln.addConn(newConnection(conn, remoteAddr, extraReader))
}

type Listener struct {
	sync.Mutex
	server   http.Server
	listener net.Listener
	config   *Config
	addConn  internet.ConnHandler
	locker   *internet.FileLocker // for unix domain socket
}

func ListenWS(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		addConn: addConn,
	}
	wsSettings := streamSettings.ProtocolSettings.(*Config)
	l.config = wsSettings
	if l.config != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol =
			l.config.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { //unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen unix domain socket(for WS) on ", address).Base(err)
		}
		newError("listening unix domain socket(for WS) on ", address).WriteToLog(session.ExportIDToError(ctx))
		locker := ctx.Value(address.Domain())
		if locker != nil {
			l.locker = locker.(*internet.FileLocker)
		}
	} else { //tcp
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen TCP(for WS) on ", address, ":", port).Base(err)
		}
		newError("listening TCP(for WS) on ", address, ":", port).WriteToLog(session.ExportIDToError(ctx))
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
	}

	if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
		if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
	}

	l.listener = listener

	l.server = http.Server{
		Handler: &requestHandler{
			path:             wsSettings.GetNormalizedPath(),
			ln:               l,
			UsePathEarlyData: wsSettings.UsePathEarlyData,
		},
		ReadHeaderTimeout: time.Second * 4,
		MaxHeaderBytes:    4096,
	}

	go func() {
		if err := l.server.Serve(l.listener); err != nil {
			newError("failed to serve http for WebSocket").Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
		}
	}()

	return l, err
}

// Addr implements net.Listener.Addr().
func (ln *Listener) Addr() net.Addr {
	return ln.listener.Addr()
}

// Close implements net.Listener.Close().
func (ln *Listener) Close() error {
	if ln.locker != nil {
		ln.locker.Release()
	}
	return ln.listener.Close()
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenWS))
}
