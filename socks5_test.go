package socks5_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/proxy"
	"github.com/Code-Hex/socks5/server"
)

var addressCase = []string{
	"0.0.0.0:0",   // ipv4
	"[::1]:0",     // ipv6
	"localhost:0", // fqdn
}

func TestSocks5_UDPAssociate(t *testing.T) {
	for _, address := range addressCase {
		t.Run(address, func(t *testing.T) {
			socks5Ln := socks5Server(t, address)
			socks5Addr := socks5Ln.Addr()

			addr := echoUdpServer(t, address)
			ctx := context.Background()
			dialer, err := proxy.Socks5(ctx, socks5.CmdUDPAssociate, socks5Addr.Network(), socks5Addr.String())
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.Dial("udp", addr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			want := "OK"
			if _, err := conn.Write([]byte(want)); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 100)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}

			got := string(buf[:n])
			if want != got {
				t.Fatalf(`want %s, but got %s`, want, got)
			}
		})
	}
}

func TestSocks5_Connect(t *testing.T) {
	for _, address := range addressCase {
		t.Run(address, func(t *testing.T) {
			socks5Ln := socks5Server(t, address)
			echoLn := echoConnectServer(t, address)

			socks5Addr := socks5Ln.Addr()
			ctx := context.Background()
			p, err := proxy.Socks5(ctx, socks5.CmdConnect, socks5Addr.Network(), socks5Addr.String())
			if err != nil {
				t.Fatal(err)
			}

			echoAddr := echoLn.Addr()
			conn, err := p.Dial(echoAddr.Network(), echoAddr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			want := "OK"
			if _, err := conn.Write([]byte(want)); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 2)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}

			got := string(buf)
			if want != got {
				t.Fatalf(`want %s, but got %s`, want, got)
			}
		})
	}
}

func TestSocks5_Bind(t *testing.T) {
	for _, address := range addressCase {
		t.Run(address, func(t *testing.T) {
			socks5Ln := socks5Server(t, address)
			ctx := context.Background()
			socks5Addr := socks5Ln.Addr()

			dialer, err := proxy.Socks5(ctx, socks5.CmdConnect, socks5Addr.Network(), socks5Addr.String())
			if err != nil {
				t.Fatal(err)
			}

			echoLn, waitCh := echoBindServer(t, address)
			echoAddr := echoLn.Addr()
			conn1, err := dialer.Dial(echoAddr.Network(), echoAddr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn1.Close()

			dialer2, err := proxy.Socks5(ctx, socks5.CmdBind, socks5Addr.Network(), socks5Addr.String())
			if err != nil {
				t.Fatal(err)
			}

			ln, err := dialer2.Listen("tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr()
			_, err = conn1.Write([]byte(addr.String() + "\n"))
			if err != nil {
				t.Fatal(err)
			}

			// wait to dial tcp from echo bind server
			<-waitCh

			want := "OK"
			_, err = conn1.Write([]byte(want))
			if err != nil {
				t.Fatal(err)
			}

			conn2, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn2.Close()

			buf := make([]byte, 2)
			if _, err := conn2.Read(buf); err != nil {
				t.Fatal(err)
			}
			got := string(buf)
			if want != got {
				t.Fatalf("want %s, but got %s", want, got)
			}
		})
	}
}

func socks5Server(t *testing.T, address string) net.Listener {
	t.Helper()
	socks5Ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		if err := server.New(nil).Serve(socks5Ln); err != nil {
			panic(err)
		}
	}()
	return socks5Ln
}

func echoConnectServer(t *testing.T, address string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		if _, err := io.Copy(conn, conn); err != nil {
			panic(err)
		}
	}()
	return ln
}

func echoBindServer(t *testing.T, address string) (net.Listener, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}

	waitCh := make(chan struct{})
	go func() {
		conn1, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		defer conn1.Close()

		rdConn1 := bufio.NewReader(conn1)
		line, _, err := rdConn1.ReadLine()
		if err != nil {
			panic(err)
		}
		conn2, err := net.Dial("tcp", string(line))
		if err != nil {
			panic(err)
		}
		defer conn2.Close()

		close(waitCh)
		if _, err := io.Copy(conn2, conn1); err != nil {
			panic(err)
		}
	}()
	return ln, waitCh
}

func echoUdpServer(t *testing.T, address string) net.Addr {
	t.Helper()
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer conn.Close()

		buf := make([]byte, 10)
		nr, addr, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		nw, err := conn.WriteTo(buf[:nr], addr)
		if err != nil {
			panic(err)
		}
		if nw != nr {
			panic(
				fmt.Sprintf("received %d bytes but sent %d\n", nr, nw),
			)
		}
	}()
	return conn.LocalAddr()
}
