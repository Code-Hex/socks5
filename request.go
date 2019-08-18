package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	"golang.org/x/sync/errgroup"
)

const socks5Version = 5

var ErrCommandNotSupported = errors.New("command not supported")

type Request struct {
	Version  int
	Command  Command
	DestAddr *Addr
	BufConn  io.Reader

	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewRequest returns request
//
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
func (s *Server) newRequest(conn io.Reader) (*Request, error) {
	// read version, command, reserved.
	header := make([]byte, 3)
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		return nil, fmt.Errorf("failed to get header information: %v", err)
	}
	// Ensure we are compatible
	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported version: %d", header[0])
	}

	addr, err := readAddress(conn)
	if err != nil {
		return nil, err
	}

	return &Request{
		Version:  socks5Version,
		Command:  Command(header[1]),
		DestAddr: addr,
		BufConn:  conn,

		DialContext: s.config.DialContext,
	}, nil
}

func (r *Request) do(ctx context.Context, conn io.Writer) (err error) {
	switch r.Command {
	case CmdConnect:
		err = r.connect(ctx, conn)
	case CmdBind:
	case CmdUDPAssociate:
	default:
		err = ErrCommandNotSupported
	}

	if err != nil {
		var status Reply
		switch err := err.(type) {
		case syscall.Errno:
			switch err {
			case syscall.ECONNREFUSED:
				status = StatusConnectionRefused
			case syscall.ENETUNREACH:
				status = StatusNetworkUnreachable
			}
		default:
			if err == ErrCommandNotSupported {
				status = StatusCommandNotSupported
			} else {
				status = StatusHostUnreachable
			}
		}
		if err := r.reply(conn, status, nil); err != nil {
			return fmt.Errorf("failed to reply: %v", err)
		}
		return err
	}
	return nil
}

func (r *Request) reply(conn io.Writer, reply Reply, addr *Addr) error {
	var (
		addrType, addrPort int
		addrBody           []byte
	)

	switch {
	case addr == nil:
		addrType = AddrTypeIPv4
		addrPort = 0
		addrBody = make([]byte, 4)
	default:
		addrType = addr.Type
		addrPort = addr.Port
		if addrType == AddrTypeFQDN {
			addrBody = append(
				[]byte{
					byte(len(addr.Host)),
				},
				[]byte(addr.Host)...,
			)
		} else {
			addrBody = []byte(addr.Host)
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
		byte(socks5Version),
		byte(reply),
		0,
		byte(addrType),
	)
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))

	_, err := conn.Write(msg)

	return err
}

func (r *Request) connect(ctx context.Context, conn io.Writer) error {
	address := r.DestAddr.String()
	target, err := r.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer target.Close()

	// TODO(codehex): it should pass the local address information?
	if err := r.reply(conn, StatusSucceeded, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	var eg errgroup.Group
	eg.Go(func() error {
		_, err := io.Copy(target, r.BufConn)
		return err
	})
	eg.Go(func() error {
		_, err := io.Copy(conn, target)
		return err
	})
	return eg.Wait()
}
