package address

import (
	"fmt"
	"net"
	"strconv"
)

type Unrecognized struct {
	Type Type
}

func (u Unrecognized) Error() string {
	return fmt.Sprintf("unrecognized address type: %d", u.Type)
}

type Host []byte

func (h Host) String() string { return string(h) }

type Info struct {
	Host Host
	Port int
	Type Type
}

func (i *Info) String() string {
	var host string
	switch i.Type {
	case TypeIPv4, TypeIPv6:
		host = net.IP(i.Host).String()
	case TypeFQDN:
		host = i.Host.String()
	default:
		host = "unknown"
	}
	return net.JoinHostPort(host, strconv.Itoa(i.Port))
}

const (
	TypeIPv4 Type = 0x01
	TypeFQDN Type = 0x03
	TypeIPv6 Type = 0x04
)

type Type byte

func (t Type) String() string {
	switch t {
	case TypeIPv4:
		return "ipv4"
	case TypeFQDN:
		return "fqdn"
	case TypeIPv6:
		return "ipv6"
	}
	return "unknown"
}
