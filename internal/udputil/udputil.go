package udputil

import (
	"fmt"
	"io"
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

const maxBufferSize = 1024

// ExtractData extracts data from udp frame of socks5
//
// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func ExtractData(n int, frame, b []byte) (int, *address.Info, error) {
	l := 2 + 1 + 1 + 2 // rsv + frag + atyp + port
	if l > n {
		return 0, nil, fmt.Errorf("unexpected data format: %v", frame[:n])
	}

	// Implementation of fragmentation is optional; an implementation that
	// does not support fragmentation MUST drop any datagram whose FRAG
	// field is other than X'00'.
	fragmentation := frame[2]
	if fragmentation != 0 {
		return 0, nil, fmt.Errorf("unsupported fragmentation: %d", fragmentation)
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
		return 0, nil, &address.Unrecognized{
			Type: aTyp,
		}
	}

	copy(b, frame[l:n])

	// extract data
	return n - l, &address.Info{
		Host: frame[4 : l-2],
		Port: (int(frame[l-2]) << 8) | int(frame[l-1]),
		Type: aTyp,
	}, nil
}

func ExtractDataFromConn(conn io.Reader, b []byte) (int, *address.Info, error) {
	buf := make([]byte, maxBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	return ExtractData(n, buf, b)
}
