package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Code-Hex/socks5/internal/address"
)

type Conn struct {
	net.Conn
	udpConn    net.Conn
	destAddr   *destAddr
	targetHost net.IP
	targetPort int
	aTyp       int
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.udpConn != nil {
		return extractUDPData(c.udpConn, b)
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.udpConn != nil {
		buf := createUDPFrame(c.aTyp, c.targetPort, c.targetHost, b)
		return c.udpConn.Write(buf)
	}
	return c.Conn.Write(b)
}

func (c *Conn) Close() error {
	if c.udpConn != nil {
		c.udpConn.Close()
	}
	return c.Conn.Close()
}

// +-----+------+------+-----------+---------+--------+
// | rsv | frag | atyp | dstaddr   | dstport | data   |
// +-----+------+------+-----------+---------+--------+
// | 00  | 0    | 1    | 127.0.0.1 | 1201    | ...(1) |
// +-----+------+------+-----------+---------+--------+
func createUDPFrame(aTyp, port int, ip net.IP, data []byte) []byte {
	buf := []byte{0, 0, 0, byte(aTyp)}
	if aTyp == address.TypeFQDN {
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
	switch buf[3] {
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
		return 0, fmt.Errorf("unknown address type: %d", int(buf[3]))
	}

	copy(b, buf[l:n])

	// extract data
	return n - l, nil
}

func addressType(host string) (int, net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return address.TypeIPv4, ip4, nil
		} else if ip6 := ip.To16(); ip6 != nil {
			return address.TypeIPv6, ip6, nil
		}
		return 0, nil, errors.New("unknown address type")
	}
	if len(host) > 255 {
		return 0, nil, errors.New("FQDN is too long")
	}
	return address.TypeFQDN, net.IP(host), nil
}
