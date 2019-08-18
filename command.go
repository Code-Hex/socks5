package socks5

import "fmt"

// A Command represents a SOCKS command.
// See: https://tools.ietf.org/html/rfc1928
type Command int

// See: Page 5 in https://tools.ietf.org/html/rfc1928
const (
	// CmdConnect represents CONNECT command.
	CmdConnect Command = iota + 1

	// CmdBind represents BIND command.
	CmdBind

	// CmdUDPAssociate represents UDP ASSOCIATE command.
	CmdUDPAssociate
)

func (cmd Command) String() string {
	switch cmd {
	case CmdConnect:
		return "socks connect"
	case CmdBind:
		return "socks bind"
	case CmdUDPAssociate:
		return "socks udp associate"
	default:
		return fmt.Sprintf("socks %d", cmd)
	}
}
