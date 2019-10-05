package proxy

import "net"

var _ net.Addr = (*Addr)(nil)

type Addr struct {
	Host string
	Port string
	Net  string
}

func newAddr(address, network string) net.Addr {
	host, port, _ := net.SplitHostPort(address)
	return &Addr{
		Host: host,
		Port: port,
		Net:  network,
	}
}

// String returns string such as "127.0.0.1:3000"
func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	return net.JoinHostPort(a.Host, a.Port)
}

// Network returns string such as "tcp", "udp"
func (a *Addr) Network() string {
	if a == nil {
		return "<nil>"
	}
	return a.Net
}
