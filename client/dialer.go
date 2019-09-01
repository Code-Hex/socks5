package client

import (
	"github.com/Code-Hex/socks5"
)

// A Dialer holds SOCKS-specific options.
type Dialer struct {
	cmd socks5.Command // either CmdConnect or cmdBind

}
