package proxy

import (
	"net"
)

type listner struct {
	net.Listener
	dialer *Dialer
}

func (l *listner) Accept() (net.Conn, error) {
	addr := l.Listener.Addr()
	conn, err := l.dialer.Dial(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	if err := conn.Close(); err != nil {
		return nil, err
	}
	return l.Listener.Accept()
}

func (d *Dialer) Listen(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &listner{
		Listener: ln,
		dialer:   d,
	}, nil
}
