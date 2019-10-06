package proxy

import (
	"net"

	"github.com/Code-Hex/socks5/address"
	"github.com/Code-Hex/socks5/internal/udputil"
)

var _ net.Conn = (*Conn)(nil)

type Conn struct {
	net.Conn
	UDPConn net.Conn

	targetHost address.Host
	targetPort int
	aTyp       address.Type
}

const maxBufferSize = 1024

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		frame := make([]byte, maxBufferSize)
		n, err := c.UDPConn.Read(frame)
		if err != nil {
			return 0, err
		}
		buf, _, err := udputil.ExtractData(frame[:n])
		if err != nil {
			return 0, err
		}
		copy(b, buf)
		return len(buf), nil
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		buf := udputil.CreateFrame(c.aTyp, c.targetPort, c.targetHost, b)
		return c.UDPConn.Write(buf)
	}
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	if c.UDPConn != nil {
		c.UDPConn.Close()
	}
	return c.Conn.Close()
}
