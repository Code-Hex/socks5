package udputil

import (
	"fmt"
	"net"

	"github.com/Code-Hex/socks5/address"
)

// CreateFrame creates udp frame of socks5
//
// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func CreateFrame(aTyp address.Type, port int, ip net.IP, data []byte) []byte {
	buf := []byte{0, 0, 0, byte(aTyp)}
	if address.TypeFQDN == aTyp {
		host := ip.String()
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	} else {
		buf = append(buf, ip...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	buf = append(buf, data...)
	return buf
}

// ExtractData extracts data from udp frame of socks5
//
// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func ExtractData(frame []byte) ([]byte, *address.Info, error) {
	l := 2 + 1 + 1 + 2 // rsv + frag + atyp + port
	if l > len(frame) {
		return nil, nil, fmt.Errorf("unexpected data format: %v", frame)
	}

	// Implementation of fragmentation is optional; an implementation that
	// does not support fragmentation MUST drop any datagram whose FRAG
	// field is other than X'00'.
	fragmentation := frame[2]
	if fragmentation != 0 {
		return nil, nil, fmt.Errorf("unsupported fragmentation: %d", fragmentation)
	}

	aTyp := address.Type(frame[3])
	switch aTyp {
	case address.TypeIPv4:
		l += net.IPv4len
	case address.TypeIPv6:
		l += net.IPv6len
	case address.TypeFQDN:
		l += 1 + int(frame[4]) // size of length field + length of fqdn
	default:
		return nil, nil, &address.Unrecognized{
			Type: aTyp,
		}
	}

	// extract data
	return frame[l:], &address.Info{
		Host: frame[4 : l-2],
		Port: (int(frame[l-2]) << 8) | int(frame[l-1]),
		Type: aTyp,
	}, nil
}
