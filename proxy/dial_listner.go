package proxy

import (
	"net"
)

type Listner struct {
	net.Listener
	dialer *Dialer
}

func (l *Listner) Accept() (net.Conn, error) {
	addr := l.Listener.Addr()
	conn, err := l.dialer.Dial(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return l.Listener.Accept()
}

func (d *Dialer) Listen(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &Listner{
		Listener: ln,
		dialer:   d,
	}, nil
}
