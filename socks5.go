package socks5

import (
	"context"
	"net"

	"github.com/Code-Hex/socks5/auth"
)

type Config struct {
	AuthMethods map[byte]auth.Authenticator

	// Optional.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func New(c *Config) *Server {
	if c == nil {
		c = &Config{}
	}
	if len(c.AuthMethods) == 0 {
		c.AuthMethods = map[byte]auth.Authenticator{
			auth.MethodNotRequired: &auth.NotRequired{},
		}
	}
	if c.DialContext == nil {
		c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	return &Server{
		config:      c,
		shutdown:    make(chan struct{}),
		waitingDone: make(chan struct{}),
	}
}
