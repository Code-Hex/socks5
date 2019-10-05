package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/address"
	"github.com/Code-Hex/socks5/auth"
	"github.com/Code-Hex/socks5/internal/addrutil"
)

// A DialListener holds SOCKS-specific options.
type DialListener struct {
	cmd              socks5.Command // either CmdConnect or cmdBind
	network, address string         // these fields for socks5

	AuthMethods map[auth.Method]auth.Authenticator
	Dialer      net.Dialer
}

var ErrCommandUnimplemented = errors.New("command is unimplemented in proxy")

func Socks5(ctx context.Context, cmd socks5.Command, network, address string) (*DialListener, error) {
	switch cmd {
	case socks5.CmdConnect,
		socks5.CmdBind,
		socks5.CmdUDPAssociate:
	default:
		return nil, &net.OpError{
			Op:   cmd.String(),
			Net:  network,
			Addr: newAddr(address, network),
			Err:  ErrCommandUnimplemented,
		}
	}
	return &DialListener{
		cmd:     cmd,
		network: network,
		address: address,
	}, nil
}

func (d *DialListener) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *DialListener) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if len(d.AuthMethods) == 0 {
		d.AuthMethods = map[auth.Method]auth.Authenticator{
			auth.MethodNotRequired: &NotRequired{},
		}
	}

	socks5Conn, err := d.Dialer.DialContext(ctx, d.network, d.address)
	if err != nil {
		return nil, d.newError(err, network, address)
	}
	relayAddr, err := d.send(ctx, socks5Conn, address)
	if err != nil {
		return nil, d.newError(err, network, address)
	}

	var udpConn net.Conn
	switch network {
	case "udp", "udp4", "udp6":
		address := relayAddr.String()
		udpConn, err = d.Dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, d.newError(err, network, address)
		}
	}
	host, port, err := addrutil.SplitHostPort(address)
	if err != nil {
		return nil, d.newError(err, network, address)
	}
	aTyp, ip, err := addrutil.GetAddressInfo(host)
	if err != nil {
		return nil, d.newError(err, network, address)
	}

	return &Conn{
		Conn:       socks5Conn,
		UDPConn:    udpConn,
		targetHost: ip,
		targetPort: port,
		aTyp:       aTyp,
	}, nil
}

func (d *DialListener) send(ctx context.Context, conn net.Conn, address string) (*address.Info, error) {
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	host, port, err := addrutil.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	b := make([]byte, 0, 6+len(host)) // the size here is just an estimate
	if err := d.authenticate(conn, b); err != nil {
		return nil, err
	}
	return d.sendCommand(conn, b, host, port)
}

func (d *DialListener) sendCommand(c net.Conn, bytes []byte, host string, port int) (*address.Info, error) {
	bytes = bytes[:0]
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	bytes = append(bytes, socks5.Version, byte(d.cmd), 0)
	aTyp, addr, err := addrutil.GetAddressInfo(host)
	if err != nil {
		return nil, err
	}

	bytes = append(bytes, byte(aTyp))

	if aTyp == address.TypeFQDN {
		bytes = append(bytes, byte(len(host)))
		bytes = append(bytes, host...)
	} else {
		bytes = append(bytes, addr...)
	}

	bytes = append(bytes, byte(port>>8), byte(port))
	if _, err := c.Write(bytes); err != nil {
		return nil, err
	}

	// Reply from server like this format
	//
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	return d.readReply(c, bytes)
}

func (d *DialListener) readReply(c net.Conn, b []byte) (*address.Info, error) {
	if _, err := c.Read(b[:3]); err != nil {
		return nil, err
	}
	if b[0] != socks5.Version {
		return nil, fmt.Errorf("unexpected protocol version %d", b[0])
	}
	if status := socks5.Reply(b[1]); status != socks5.StatusSucceeded {
		return nil, errors.New(status.String())
	}
	if b[2] != 0 {
		return nil, errors.New("non-zero reserved field")
	}
	return addrutil.Read(c)
}

func (d *DialListener) authenticate(c net.Conn, bytes []byte) error {
	methodNum := len(d.AuthMethods)
	if methodNum > 255 {
		return errors.New("too many authentication methods")
	}
	bytes = append(bytes, byte(socks5.Version), byte(methodNum))
	for method := range d.AuthMethods {
		bytes = append(bytes, byte(method))
	}

	// write auth information to server
	if _, err := c.Write(bytes); err != nil {
		return err
	}

	// read response from server
	if _, err := io.ReadFull(c, bytes[:2]); err != nil {
		return err
	}

	// check version
	if bytes[0] != socks5.Version {
		return fmt.Errorf("unexpected protocol version %d", bytes[0])
	}

	return d.assignAuthMethod(c, auth.Method(bytes[1]))
}

func (d *DialListener) assignAuthMethod(c net.Conn, method auth.Method) error {
	if method == auth.MethodNoAcceptableMethods {
		return errors.New("no acceptable authentication methods")
	}

	authenticator, ok := d.AuthMethods[method]
	if !ok {
		return auth.ErrUnSupportedMethod
	}
	return authenticator.Authenticate(c)
}

func (d *DialListener) newError(err error, network, address string) error {
	if err == nil {
		return nil
	}
	return &net.OpError{
		Op:     d.cmd.String(),
		Net:    network,
		Source: newAddr(d.address, d.network),
		Addr:   newAddr(address, network),
		Err:    err,
	}
}
