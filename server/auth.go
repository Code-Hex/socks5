package server

import (
	"fmt"
	"io"
	"log"
	"net"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/auth"
)

var ErrUnSupportedMethod = fmt.Errorf("unsupported authentication method")

func (s *Socks5) authenticate(conn net.Conn) error {
	// Read the version byte
	header := make([]byte, 2)
	if _, err := conn.Read(header); err != nil {
		return fmt.Errorf("failed to get authenticate information: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5.Version {
		return fmt.Errorf("unsupported version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(conn, methods, numMethods); err != nil {
		return err
	}

	authenticator, err := s.methodAssign(methods)
	if err != nil {
		_, e := conn.Write([]byte{
			socks5.Version,
			byte(auth.MethodNoAcceptableMethods),
		})
		log.Println(e)
		return err
	}
	return authenticator.Authenticate(conn)
}

func (s *Socks5) methodAssign(methods []byte) (auth.Authenticator, error) {
	for _, method := range methods {
		if authenticator, ok := s.config.AuthMethods[method]; ok {
			return authenticator, nil
		}
	}
	return nil, ErrUnSupportedMethod
}
