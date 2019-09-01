package server

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Code-Hex/socks5/auth"
)

var ErrServerClosed = errors.New("socks5: Server closed")

type Config struct {
	AuthMethods map[auth.Method]auth.Authenticator

	// Optional.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func New(c *Config) *Socks5 {
	if c == nil {
		c = &Config{}
	}
	if len(c.AuthMethods) == 0 {
		c.AuthMethods = map[auth.Method]auth.Authenticator{
			auth.MethodNotRequired: &NotRequired{},
		}
	}
	if c.DialContext == nil {
		c.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	return &Socks5{
		config:      c,
		shutdown:    make(chan struct{}),
		waitingDone: make(chan struct{}),
	}
}

type Socks5 struct {
	config *Config

	onceShutdown sync.Once
	shutdown     chan struct{}
	waitingDone  chan struct{}

	wg sync.WaitGroup
}

// ListenAndServe is used to create a listener and serve on it
func (s *Socks5) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Socks5) Serve(l net.Listener) error {
	ctx := context.Background()
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		select {
		case <-s.shutdown:
			return ErrServerClosed
		default:
		}

		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("socks5: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		go func() {
			if err := s.serveConn(ctx, conn); err != nil {
				log.Printf("socks5: error %v", err)
			}
			log.Println("done serve")
		}()
	}
}

func (s *Socks5) serveConn(ctx context.Context, conn net.Conn) error {
	s.wg.Add(1)
	defer func() {
		s.wg.Done()
		conn.Close()
	}()

	if err := s.authenticate(conn); err != nil {
		return err
	}

	req, err := s.newRequest(conn)
	if err != nil {
		return err
	}

	return req.do(ctx, conn)
}

func (s *Socks5) Shutdown(ctx context.Context) error {
	s.onceShutdown.Do(func() {
		close(s.shutdown)
		go func() {
			s.wg.Wait()
			close(s.waitingDone)
		}()
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.waitingDone:
	}
	return nil
}
