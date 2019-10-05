package proxy

import (
	"net"

	"github.com/Code-Hex/socks5/address"
	"github.com/Code-Hex/socks5/internal/udputil"
)

type Conn struct {
	net.Conn
	UDPConn net.Conn

	targetHost net.IP
	targetPort int
	aTyp       address.Type
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		n, _, err := udputil.ExtractDataFromConn(c.UDPConn, b)
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		//log.Println(c.targetPort, c.targetHost)
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
