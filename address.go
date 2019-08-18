package socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

type UnrecognizedAddress struct {
	Type int
}

func (u UnrecognizedAddress) Error() string {
	return fmt.Sprintf("unrecognized address type: %d", u.Type)
}

type Addr struct {
	Host string
	Port int
}

func (a *Addr) Network() string { return "tcp" }

func (a *Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

const (
	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04
)

func readAddress(conn io.Reader) (*Addr, error) {
	addrType := make([]byte, 1)
	if _, err := conn.Read(addrType); err != nil {
		return nil, err
	}
	host, err := readHost(conn, addrType[0])
	if err != nil {
		return nil, err
	}
	port, err := readPort(conn)
	if err != nil {
		return nil, err
	}
	return &Addr{
		Host: host,
		Port: port,
	}, nil
}

func readHost(conn io.Reader, typ byte) (string, error) {
	switch typ {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, addr, 4); err != nil {
			return "", err
		}
		ipv4 := net.IPv4(addr[0], addr[1], addr[2], addr[3])
		return ipv4.String(), nil
	case AddrTypeFQDN:
		fqdnLen := make([]byte, 1)
		if _, err := conn.Read(fqdnLen); err != nil {
			return "", err
		}
		len := int(fqdnLen[0])
		fqdn := make([]byte, len)
		if _, err := io.ReadAtLeast(conn, fqdn, len); err != nil {
			return "", err
		}
		return string(fqdn), nil
	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(conn, addr, 16); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	}
	return "", &UnrecognizedAddress{
		Type: int(typ),
	}
}

func readPort(conn io.Reader) (int, error) {
	// Read the port
	port := make([]byte, 2)
	_, err := io.ReadAtLeast(conn, port, 2)
	if err != nil {
		return 0, err
	}
	return (int(port[0]) << 8) | int(port[1]), nil
}
