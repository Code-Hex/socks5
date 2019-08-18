package auth

import "io"

var _ Authenticator = (*NotRequired)(nil)

type NotRequired struct{}

func (n *NotRequired) Authenticate(w io.Writer, _ io.Reader) error {
	_, err := w.Write([]byte{
		socks5Version,
		byte(MethodNotRequired),
	})
	return err
}
