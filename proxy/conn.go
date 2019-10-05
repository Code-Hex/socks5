package proxy

import (
	"fmt"
	"io"
	"net"

	"github.com/Code-Hex/socks5/address"
)

type Conn struct {
	net.Conn
	UDPConn net.Conn

	targetHost net.IP
	targetPort int
	aTyp       address.Type
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		return extractUDPData(c.UDPConn, b)
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.UDPConn != nil {
		buf := createUDPFrame(c.aTyp, c.targetPort, c.targetHost, b)
		return c.UDPConn.Write(buf)
	}
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	if c.UDPConn != nil {
		c.UDPConn.Close()
	}
	return c.Conn.Close()
}

// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func createUDPFrame(aTyp address.Type, port int, ip net.IP, data []byte) []byte {
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

// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func extractUDPData(conn net.Conn, b []byte) (int, error) {
	buf := make([]byte, maxBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return n, err
	}

	l := 2 + 1 + 1 + 2 // rsv + frag + atyp + port
	if l > n {
		return 0, fmt.Errorf("unexpected data format: %v", buf[:n])
	}

	// Implementation of fragmentation is optional; an implementation that
	// does not support fragmentation MUST drop any datagram whose FRAG
	// field is other than X'00'.
	fragmentation := buf[2]
	if fragmentation != 0 {
		return 0, fmt.Errorf("unsupported fragmentation: %d", fragmentation)
	}

	switch address.Type(buf[3]) {
	case address.TypeIPv4:
		l += net.IPv4len
	case address.TypeIPv6:
		l += net.IPv6len
	case address.TypeFQDN:
		// Read 2 bytes
		// First off, read length of the fqdn, then read fqdn string
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return 0, err
		}
		l += int(buf[0])
	default:
		return 0, &address.Unrecognized{
			Type: address.Type(buf[3]),
		}
	}

	copy(b, buf[l:n])

	// extract data
	return n - l, nil
}
