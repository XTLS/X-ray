package mixed

import (
	"bufio"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"time"
)

type BufferedConnection struct {
	reader *bufio.Reader
	conn   internet.Connection
}

func NewBufferedConnection(conn internet.Connection) BufferedConnection {
	return BufferedConnection{
		reader: bufio.NewReader(conn),
		conn:   conn,
	}
}

func (c BufferedConnection) Peek(n int) ([]byte, error) {
	return c.reader.Peek(n)
}

func (c BufferedConnection) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c BufferedConnection) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c BufferedConnection) Close() error {
	return c.conn.Close()
}

func (c BufferedConnection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c BufferedConnection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c BufferedConnection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c BufferedConnection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c BufferedConnection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
