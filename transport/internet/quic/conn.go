package quic

import (
	"context"
	"time"

	"github.com/xtls/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type interConn struct {
	ctx      context.Context
	quicConn quic.Connection
	local    net.Addr
	remote   net.Addr
}

func (c *interConn) Read(b []byte) (int, error) {
	received, e := c.quicConn.ReceiveDatagram(c.ctx)
	if e != nil {
		return 0, e
	}
	nBytes := copy(b, received[:])
	return nBytes, nil
}

func (c *interConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *interConn) Write(b []byte) (int, error) {
	return len(b), c.quicConn.SendDatagram(b)
}

func (c *interConn) Close() error {
	return nil
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *interConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *interConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *interConn) SetWriteDeadline(t time.Time) error {
	return nil
}
