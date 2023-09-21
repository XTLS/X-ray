package wireguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/sagernet/wireguard-go/conn"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

type netReadInfo struct {
	// status
	waiter sync.WaitGroup
	// param
	buff []byte
	// result
	bytes    int
	endpoint conn.Endpoint
	err      error
}

// reduce duplicated code
type netBind struct {
	dns       dns.Client
	dnsOption dns.IPOption

	workers   int
	readQueue chan *netReadInfo
}

// SetMark implements conn.Bind
func (bind *netBind) SetMark(mark uint32) error {
	return nil
}

// ParseEndpoint implements conn.Bind
func (n *netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ipStr, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	addr := xnet.ParseAddress(ipStr)
	if addr.Family() == xnet.AddressFamilyDomain {
		ips, err := n.dns.LookupIP(addr.Domain(), n.dnsOption)
		if err != nil {
			return nil, err
		} else if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		addr = xnet.IPAddress(ips[0])
	}

	dst := xnet.Destination{
		Address: addr,
		Port:    xnet.Port(portNum),
		Network: xnet.Network_UDP,
	}

	return &netEndpoint{
		dst: dst,
	}, nil
}

// Open implements conn.Bind
func (bind *netBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.readQueue = make(chan *netReadInfo)

	fun := func(buff []byte) (cap int, ep conn.Endpoint, err error) {
		defer func() {
			if r := recover(); r != nil {
				cap = 0
				ep = nil
				err = errors.New("channel closed")
			}
		}()

		r := &netReadInfo{
			buff: buff,
		}
		r.waiter.Add(1)
		bind.readQueue <- r
		r.waiter.Wait() // wait read goroutine done, or we will miss the result
		return r.bytes, r.endpoint, r.err
	}
	workers := bind.workers
	if workers <= 0 {
		workers = 1
	}
	arr := make([]conn.ReceiveFunc, workers)
	for i := 0; i < workers; i++ {
		arr[i] = fun
	}

	return arr, uint16(uport), nil
}

// Close implements conn.Bind
func (bind *netBind) Close() error {
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

type netBindClient struct {
	netBind

	dialer   internet.Dialer
	reserved []byte
}

func (bind *netBindClient) connectTo(endpoint *netEndpoint) error {
	c, err := bind.dialer.Dial(context.Background(), endpoint.dst)
	if err != nil {
		return err
	}
	endpoint.conn = c

	go func(readQueue <-chan *netReadInfo, endpoint *netEndpoint) {
		for {
			v, ok := <-readQueue
			if !ok {
				return
			}
			i, err := c.Read(v.buff)

			if i > 3 {
				v.buff[1] = 0
				v.buff[2] = 0
				v.buff[3] = 0
			}

			v.bytes = i
			v.endpoint = endpoint
			v.err = err
			v.waiter.Done()
			if err != nil && errors.Is(err, io.EOF) {
				endpoint.conn = nil
				return
			}
		}
	}(bind.readQueue, endpoint)

	return nil
}

func (bind *netBindClient) Send(buff []byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	if nend.conn == nil {
		err = bind.connectTo(nend)
		if err != nil {
			return err
		}
	}

	if len(buff) > 3 && len(bind.reserved) == 3 {
		copy(buff[1:], bind.reserved)
	}

	_, err = nend.conn.Write(buff)

	return err
}

type netBindServer struct {
	netBind
}

func (bind *netBindServer) Send(buff []byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	if nend.conn == nil {
		return newError("connection not open yet")
	}

	_, err = nend.conn.Write(buff)

	return err
}

type netEndpoint struct {
	dst  xnet.Destination
	conn net.Conn
}

func (netEndpoint) ClearSrc() {}

func (e netEndpoint) DstIP() netip.Addr {
	return netip.Addr{}
}

func (e netEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e netEndpoint) DstToBytes() []byte {
	var dat []byte
	if e.dst.Address.Family().IsIPv4() {
		dat = e.dst.Address.IP().To4()[:]
	} else {
		dat = e.dst.Address.IP().To16()[:]
	}
	dat = append(dat, byte(e.dst.Port), byte(e.dst.Port>>8))
	return dat
}

func (e netEndpoint) DstToString() string {
	return e.dst.NetAddr()
}

func (e netEndpoint) SrcToString() string {
	return ""
}
