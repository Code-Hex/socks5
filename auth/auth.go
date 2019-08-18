package auth

import "net"

const socks5Version = 5

const (
	// MethodNotRequired represents no authentication required.
	MethodNotRequired byte = iota // 0x00

	// MethodGSSAPI represents use GSSAPI.
	// This implements based on https://tools.ietf.org/html/rfc1961
	MethodGSSAPI

	// MethodUsernamePassword represents use username/password.
	// This implements based on https://tools.ietf.org/html/rfc1929
	MethodUsernamePassword

	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS

	// MethodNoAcceptableMethods represents no acceptable authentication methods.
	MethodNoAcceptableMethods byte = 0xff
)

type Authenticator interface {
	Authenticate(conn net.Conn) error
}
