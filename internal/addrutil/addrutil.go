package addrutil

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Code-Hex/socks5/address"
)

func GetAddressInfo(host string) (address.Type, []byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return address.TypeIPv4, ip4, nil
		}
		if ip6 := ip.To16(); ip6 != nil {
			return address.TypeIPv6, ip6, nil
		}
		return 0, nil, errors.New("unknown address type")
	}
	if len(host) > 255 {
		return 0, nil, errors.New("FQDN is too long")
	}
	return address.TypeFQDN, []byte(host), nil

}

func SplitHostPort(address string) (string, int, error) {
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

func Read(conn io.Reader) (*address.Info, error) {
	aTypBuf := make([]byte, 1)
	if _, err := conn.Read(aTypBuf); err != nil {
		return nil, err
	}
	aTyp := address.Type(aTypBuf[0])
	host, err := readHost(conn, aTyp)
	if err != nil {
		return nil, err
	}
	port, err := readPort(conn)
	if err != nil {
		return nil, err
	}
	return &address.Info{
		Host: host,
		Port: port,
		Type: aTyp,
	}, nil
}

func readHost(conn io.Reader, aTyp address.Type) ([]byte, error) {
	switch aTyp {
	case address.TypeIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := conn.Read(ip); err != nil {
			return nil, err
		}
		return ip, nil
	case address.TypeIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := conn.Read(ip); err != nil {
			return nil, err
		}
		return ip, nil
	case address.TypeFQDN:
		fqdnLen := make([]byte, 1)
		if _, err := conn.Read(fqdnLen); err != nil {
			return nil, err
		}
		len := int(fqdnLen[0])
		fqdn := make([]byte, len)
		if _, err := conn.Read(fqdn); err != nil {
			return nil, err
		}
		return fqdn, nil
	}
	return nil, &address.Unrecognized{Type: aTyp}
}

func readPort(conn io.Reader) (int, error) {
	// Read the port
	port := make([]byte, 2)
	_, err := conn.Read(port)
	if err != nil {
		return 0, err
	}
	return (int(port[0]) << 8) | int(port[1]), nil
}
