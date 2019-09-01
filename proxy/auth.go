package proxy

import (
	"io"

	"github.com/Code-Hex/socks5/auth"
)

var _ auth.Authenticator = (*NotRequired)(nil)

type NotRequired struct{}

func (n *NotRequired) Authenticate(conn io.ReadWriter) error {
	return nil
}
