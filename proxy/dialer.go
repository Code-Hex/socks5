package proxy

import (
	"context"
	"net"

	"github.com/Code-Hex/socks5"
)

// A Dialer holds SOCKS-specific options.
type Dialer struct {
	cmd socks5.Command // either CmdConnect or cmdBind

}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, nil
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
