package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/auth"
	"github.com/Code-Hex/socks5/internal/address"
)

// A DialListener holds SOCKS-specific options.
type DialListener struct {
	cmd              socks5.Command // either CmdConnect or cmdBind
	network, address string         // these fields for socks5

	AuthMethods map[auth.Method]auth.Authenticator
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
	var netDialer net.Dialer
	socks5Conn, err := netDialer.DialContext(ctx, d.network, d.address)
	if err != nil {
		return nil, d.newError(err, network, address)
	}
	destAddr, err := d.send(ctx, socks5Conn, address)
	if err != nil {
		return nil, d.newError(err, network, address)
	}
	var udpConn net.Conn
	switch network {
	case "udp", "udp4", "udp6":
		host := destAddr.ip.String()
		port := strconv.Itoa(destAddr.port)
		address := net.JoinHostPort(host, port)
		udpConn, err = netDialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, d.newError(err, network, address)
		}
	}
	host, port, _ := net.SplitHostPort(address)
	portNum, _ := strconv.Atoi(port)
	aTyp, ip, _ := addressType(host)

	return &Conn{
		Conn:       socks5Conn,
		udpConn:    udpConn,
		destAddr:   destAddr,
		targetHost: ip,
		targetPort: portNum,
		aTyp:       aTyp,
	}, nil
}

func (d *DialListener) send(ctx context.Context, conn net.Conn, address string) (*destAddr, error) {
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	b := make([]byte, 0, 6+len(host)) // the size here is just an estimate
	if err := d.authenticate(conn, b); err != nil {
		return nil, err
	}
	return d.sendCommand(conn, b, host, port)
}

func (d *DialListener) sendCommand(c net.Conn, bytes []byte, host string, port int) (*destAddr, error) {
	bytes = bytes[:0]
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	bytes = append(bytes, socks5.Version, byte(d.cmd), 0)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			bytes = append(bytes, address.TypeIPv4)
			bytes = append(bytes, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			bytes = append(bytes, address.TypeIPv6)
			bytes = append(bytes, ip6...)
		} else {
			return nil, errors.New("unknown address type")
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("FQDN is too long")
		}
		bytes = append(bytes, address.TypeFQDN)
		bytes = append(bytes, byte(len(host)))
		bytes = append(bytes, host...)
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

type destAddr struct {
	ip   net.IP
	aTyp int
	port int
}

func (d *DialListener) readReply(c net.Conn, b []byte) (*destAddr, error) {
	if _, err := io.ReadFull(c, b[:4]); err != nil {
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

	l := 2 // for port

	var ip net.IP
	var aTyp int
	switch aTyp = int(b[3]); aTyp {
	case address.TypeIPv4:
		l += net.IPv4len
		ip = make(net.IP, net.IPv4len)
	case address.TypeIPv6:
		l += net.IPv6len
		ip = make(net.IP, net.IPv6len)
	case address.TypeFQDN:
		// Read 2 bytes
		// First off, read length of the fqdn, then read fqdn string
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return nil, err
		}
		l += int(b[0])
	default:
		return nil, fmt.Errorf("unknown address type: %d", int(b[3]))
	}
	if cap(b) < l {
		b = make([]byte, l)
	} else {
		b = b[:l]
	}
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}

	if ip != nil {
		copy(ip, b)
	} else {
		copy(ip, b[:len(b)-2])
	}
	port := int(b[len(b)-2])<<8 | int(b[len(b)-1])

	return &destAddr{
		ip:   ip,
		aTyp: aTyp,
		port: port,
	}, nil
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

func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, fmt.Errorf("port number out of range: %d", portnum)
	}
	return host, portnum, nil
}
