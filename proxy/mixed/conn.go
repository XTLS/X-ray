// copy from glider https://github.com/nadoo/glider/blob/master/proxy/conn.go

package mixed

import (
	"bufio"
	"io"
	"net"
)

// Conn is a connection with buffered reader.
type Conn struct {
	r *bufio.Reader
	net.Conn
}

// NewConn returns a new conn.
func NewConn(c net.Conn) *Conn {
	if conn, ok := c.(*Conn); ok {
		return conn
	}
	return &Conn{bufio.NewReader(c), c}
}

// Reader returns the internal bufio.Reader.
func (c *Conn) Reader() *bufio.Reader      { return c.r }
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Peek returns the next n bytes without advancing the reader.
func (c *Conn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

// WriteTo implements io.WriterTo.
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) { return c.r.WriteTo(w) }
