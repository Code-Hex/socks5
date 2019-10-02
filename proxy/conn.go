package proxy

import (
	"net"
)

type Conn struct {
	net.Conn
	BindAddr net.Addr
}

func GetBindAddr(conn net.Conn) (net.Addr, bool) {
	c, ok := conn.(*Conn)
	if ok {
		return c.BindAddr, ok
	}
	return nil, false
}
