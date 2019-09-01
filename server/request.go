package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/internal/address"
	"golang.org/x/sync/errgroup"
)

var ErrCommandNotSupported = errors.New("command not supported")

type Request struct {
	Version  int
	Command  socks5.Command
	DestAddr *address.Addr

	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewRequest returns request
//
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
func (s *Socks5) newRequest(conn io.Reader) (*Request, error) {
	// read version, command, reserved.
	header := make([]byte, 3)
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		return nil, fmt.Errorf("failed to get header information: %v", err)
	}
	// Ensure we are compatible
	if header[0] != socks5.Version {
		return nil, fmt.Errorf("unsupported version: %d", header[0])
	}

	addr, err := address.Read(conn)
	if err != nil {
		return nil, err
	}

	return &Request{
		Version:  socks5.Version,
		Command:  socks5.Command(header[1]),
		DestAddr: addr,

		DialContext: s.config.DialContext,
	}, nil
}

func (r *Request) do(ctx context.Context, conn net.Conn) (err error) {
	switch r.Command {
	case socks5.CmdConnect:
		err = r.connect(ctx, conn)
	case socks5.CmdBind:
	case socks5.CmdUDPAssociate:
	default:
		err = ErrCommandNotSupported
	}

	if err != nil {
		status := replyStatusByErr(err)
		if err := r.reply(conn, status, nil); err != nil {
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

func (r *Request) reply(conn io.Writer, reply socks5.Reply, addr net.Addr) error {
	var (
		addrType, addrPort int
		addrBody           []byte
	)

	switch {
	case addr == nil:
		addrType = address.TypeIPv4
		addrPort = 0
		addrBody = make([]byte, 4)
	default:
		host, p, err := net.SplitHostPort(addr.String())
		if err != nil {
			return err
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return err
		}
		addrPort = port

		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				addrType = address.TypeIPv4
				addrBody = ip4
			} else if ip6 := ip.To16(); ip6 != nil {
				addrType = address.TypeIPv6
				addrBody = ip6
			} else {
				return errors.New("unknown address type")
			}
		} else {
			if len(host) > 255 {
				return errors.New("FQDN too long")
			}
			addrType = address.TypeFQDN
			addrBody = append(
				[]byte{
					byte(len(host)),
				},
				[]byte(host)...,
			)
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

	_, err := conn.Write(msg)

	return err
}

func (r *Request) connect(ctx context.Context, conn net.Conn) error {
	address := r.DestAddr.String()
	target, err := r.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer target.Close()

	// TODO(codehex): it should pass the local address information?
	if err := r.reply(conn, socks5.StatusSucceeded, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	return transport(conn, target)
}

func (r *Request) bind(ctx context.Context, conn net.Conn) error {
	// address := r.DestAddr.String()
	// addr, err := net.ResolveIPAddr("tcp", address)
	// if err != nil {
	// 	return err
	// }
	// ln, err := net.Listen("tcp", addr.String())
	// if err != nil {
	// 	return err
	// }

	// host, p, _ := net.SplitHostPort(ln.Addr().String())
	// port, _ := strconv.Atoi(p)
	// bind := &address.Addr{
	// 	Host: host,
	// 	Port: port,
	// }

	// // TODO(codehex): it should pass the local address information?
	// if err := r.reply(conn, socks5.StatusSucceeded, bind); err != nil {
	// 	return fmt.Errorf("failed to send reply: %v", err)
	// }

	// c, err := ln.Accept()
	// if err != nil {
	// 	return err
	// }

	// rConn, wConn := net.Pipe()

	// transport(rConn, c)
	// transport(wConn, conn)

	return nil
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
