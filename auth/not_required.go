package auth

import "net"

var _ Authenticator = (*NotRequired)(nil)

type NotRequired struct{}

func (n *NotRequired) Authenticate(conn net.Conn) error {
	_, err := conn.Write([]byte{
		socks5Version,
		byte(MethodNotRequired),
	})
	return err
}
