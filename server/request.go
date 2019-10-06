package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/Code-Hex/socks5/internal/udputil"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/address"
	"github.com/Code-Hex/socks5/internal/addrutil"
	"golang.org/x/sync/errgroup"
)

var ErrCommandNotSupported = errors.New("command not supported")

type Request struct {
	Version  int
	Command  socks5.Command
	DestAddr *address.Info

	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Listen      func(ctx context.Context, network, address string) (net.Listener, error)

	udpConn net.PacketConn
}

// NewRequest returns request
//
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
func (s *Socks5) newRequest(s5conn io.Reader, udpConn net.PacketConn) (*Request, error) {
	// read version, command, reserved.
	header := make([]byte, 3)
	if _, err := s5conn.Read(header); err != nil {
		return nil, fmt.Errorf("failed to get header information: %v", err)
	}
	// Ensure we are compatible
	if header[0] != socks5.Version {
		return nil, fmt.Errorf("unsupported version: %d", header[0])
	}

	addr, err := addrutil.Read(s5conn)
	if err != nil {
		return nil, err
	}

	return &Request{
		Version:  socks5.Version,
		Command:  socks5.Command(header[1]),
		DestAddr: addr,

		DialContext: s.config.DialContext,
		Listen:      s.config.Listen,
		udpConn:     udpConn,
	}, nil
}

func (r *Request) do(ctx context.Context, s5conn net.Conn) (err error) {
	switch r.Command {
	case socks5.CmdConnect:
		err = r.connect(ctx, s5conn)
	case socks5.CmdBind:
		err = r.bind(ctx, s5conn)
	case socks5.CmdUDPAssociate:
		err = r.udpAssociate(ctx, s5conn)
	default:
		err = ErrCommandNotSupported
	}

	if err != nil {
		status := replyStatusByErr(err)
		if err := reply(s5conn, status, nil); err != nil {
			return fmt.Errorf("failed to reply: %v", err)
		}
		return err
	}
	return nil
}

func replyStatusByErr(err error) socks5.Reply {
	switch err := err.(type) {
	case syscall.Errno:
		switch err {
		case syscall.ETIMEDOUT:
			return socks5.StatusTTLExpired
		case syscall.EPROTOTYPE,
			syscall.EPROTONOSUPPORT,
			syscall.EAFNOSUPPORT:
			return socks5.StatusAddrTypeNotSupported
		case syscall.ECONNREFUSED:
			return socks5.StatusConnectionRefused
		case syscall.ENETDOWN, syscall.ENETUNREACH:
			return socks5.StatusNetworkUnreachable
		case syscall.EHOSTUNREACH:
			return socks5.StatusHostUnreachable
		}
	default:
		if err == ErrCommandNotSupported {
			return socks5.StatusCommandNotSupported
		}
	}
	return socks5.StatusGeneralServerFailure
}

func reply(s5conn io.Writer, reply socks5.Reply, addr *address.Info) error {
	var (
		addrType address.Type
		addrPort int
		addrBody []byte
	)

	switch {
	case addr == nil:
		addrType = address.TypeIPv4
		addrPort = 0
		addrBody = make([]byte, 4)
	default:
		addrPort = addr.Port
		addrType = addr.Type
		if addrType == address.TypeFQDN {
			host := addr.Host
			addrBody = append(
				[]byte{
					byte(len(host)),
				},
				[]byte(host)...,
			)
		} else {
			addrBody = addr.Host
		}
	}

	// Page 4 in https://tools.ietf.org/html/rfc1928
	//
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+

	msg := make([]byte, 0, 6+len(addrBody))
	msg = append(msg,
		byte(socks5.Version),
		byte(reply),
		0,
		byte(addrType),
	)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))

	_, err := s5conn.Write(msg)

	return err
}

func (r *Request) connect(ctx context.Context, s5conn net.Conn) error {
	target, err := r.DialContext(ctx, "tcp", r.DestAddr.String())
	if err != nil {
		return err
	}
	defer target.Close()

	// TODO(codehex): it should pass the local address information?
	if err := reply(s5conn, socks5.StatusSucceeded, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	return transport(s5conn, target)
}

func (r *Request) bind(ctx context.Context, s5conn net.Conn) error {
	target, err := r.DialContext(ctx, "tcp", r.DestAddr.String())
	if err != nil {
		return err
	}
	defer target.Close()

	ln, err := r.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	hostStr, port, err := addrutil.SplitHostPort(ln.Addr().String())
	if err != nil {
		return err
	}

	aTyp, host, err := addrutil.GetAddressInfo(hostStr)
	if err != nil {
		return err
	}

	bind := &address.Info{
		Host: host,
		Port: port,
		Type: aTyp,
	}

	if err := reply(s5conn, socks5.StatusSucceeded, bind); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(1 * time.Second)
				continue
			}
			return err
		}
		return transport(target, c)
	}
}

func transport(dst, src io.ReadWriter) error {
	var eg errgroup.Group
	eg.Go(func() error {
		_, err := io.Copy(dst, src)
		return err
	})
	eg.Go(func() error {
		_, err := io.Copy(src, dst)
		return err
	})
	return eg.Wait()
}

const maxBufferSize = 1024

func (r *Request) udpAssociate(ctx context.Context, s5conn net.Conn) error {

	udpConnAddr := r.udpConn.LocalAddr()

	hostStr, port, err := addrutil.SplitHostPort(udpConnAddr.String())
	if err != nil {
		return err
	}

	aTyp, host, err := addrutil.GetAddressInfo(hostStr)
	if err != nil {
		return err
	}

	relay := &address.Info{
		Host: host,
		Port: port,
		Type: aTyp,
	}

	if err := reply(s5conn, socks5.StatusSucceeded, relay); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	for {
		r.udpConn.SetDeadline(time.Now().Add(5 * time.Second))

		frame := make([]byte, maxBufferSize)
		n, remoteAddr, err := r.udpConn.ReadFrom(frame)
		if err != nil {
			return err
		}

		buf, addr, err := udputil.ExtractData(frame[:n])
		if err != nil {
			return err
		}

		dst := make([]byte, maxBufferSize)
		nn, err := r.dialUDP(context.Background(), addr, buf, dst)
		if err != nil {
			return err
		}

		dest := udputil.CreateFrame(addr.Type, addr.Port, addr.Host, dst[:nn])
		if _, err := r.udpConn.WriteTo(dest, remoteAddr); err != nil {
			return err
		}
	}
}

func (r *Request) dialUDP(ctx context.Context, addr *address.Info, in, out []byte) (int, error) {
	targetConn, err := r.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return 0, err
	}
	defer targetConn.Close()
	targetConn.SetDeadline(time.Now().Add(time.Second * 5))

	if _, err := targetConn.Write(in); err != nil {
		return 0, err
	}

	n, err := targetConn.Read(out)
	if err != nil {
		return 0, err
	}
	return n, nil
}
