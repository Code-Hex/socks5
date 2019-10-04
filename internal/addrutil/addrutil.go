package addrutil

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Code-Hex/socks5/internal/address"
)

func GetAddressInfo(host string) (byte, []byte, error) {
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
