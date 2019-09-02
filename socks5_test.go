package socks5_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/proxy"
	"github.com/Code-Hex/socks5/server"
)

func TestSocks5_Connect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	go func() {
		if err := server.New(nil).Serve(ln); err != nil {
			panic(err)
		}
	}()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("OK"))
		})
		if err := http.Serve(httpLn, mux); err != nil {
			panic(err)
		}
	}()

	time.Sleep(time.Second)

	lAddr := ln.Addr()
	log.Println("socks", lAddr.String())
	ctx := context.Background()
	p, err := proxy.Socks5(ctx, socks5.CmdConnect, lAddr.Network(), lAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	client := http.DefaultClient
	client.Transport = &http.Transport{Dial: p.Dial}

	log.Println("target", fmt.Sprintf("http://%s/health", httpLn.Addr().String()))
	resp, err := client.Get(
		fmt.Sprintf("http://%s/health", httpLn.Addr().String()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "OK" {
		t.Fatalf(`got %s, but want "OK"`, buf.String())
	}
}

func TestA(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		ln2, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		addr := ln2.Addr()
		b := []byte(
			addr.Network() + "," + addr.String(),
		)
		if _, err := conn.Write(b); err != nil {
			panic(err)
		}

		conn2, err := ln2.Accept()
		if err != nil {
			panic(err)
		}
		if _, err := io.Copy(conn2, conn2); err != nil {
			panic(err)
		}

		conn.Close()
		conn2.Close()
	}()

	addr := ln.Addr()
	conn, err := net.Dial(addr.Network(), addr.String())
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 100)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatal(err)
	}

	addrSlice := strings.Split(string(b[:n]), ",")
	network, address := addrSlice[0], addrSlice[1]

	conn2, err := net.Dial(network, address)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn2.Write([]byte("OK")); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 2)
	n2, err := conn2.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp[:n2]); got != "OK" {
		t.Fatalf("got %s, but want `OK`", got)
	}
}

// func TestSocks5_Bind(t *testing.T) {
// 	ln, err := net.Listen("tcp", "127.0.0.1:0")
// 	if err != nil {
// 		t.Fatalf("err: %v", err)
// 	}
// 	go func() {
// 		if err := New(nil).Serve(ln); err != nil {
// 			panic(err)
// 		}
// 	}()

// 	lAddr := ln.Addr()
// 	log.Println("socks", lAddr.String())
// 	p, err := proxy.SOCKS5(lAddr.Network(), "127.0.0.1:9150", nil, proxy.Direct)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	addr := echoServerOnce(t)
// 	conn, err := p.Dial("tcp", addr.String())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if _, err := conn.Write([]byte("OK")); err != nil {
// 		t.Fatal(err)
// 	}
// 	if tcpConn, ok := conn.(*net.TCPConn); ok {
// 		tcpConn.CloseWrite()
// 	}
// 	var buf bytes.Buffer
// 	if _, err := io.Copy(&buf, conn); err != nil {
// 		t.Fatal(err)
// 	}
// 	if buf.String() != "OK" {
// 		t.Fatalf(`got %s, but want "OK"`, buf.String())
// 	}
// }

// func echoServerOnce(t *testing.T) net.Addr {
// 	t.Helper()
// 	ln, err := net.Listen("tcp", "127.0.0.1:0")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	go func() {
// 		conn, err := ln.Accept()
// 		if err != nil {
// 			panic(err)
// 		}
// 		if err := echo(conn); err != nil {
// 			panic(err)
// 		}
// 	}()

// 	return ln.Addr()
// }

// func echo(conn net.Conn) error {
// 	defer conn.Close()
// 	_, err := io.Copy(conn, conn)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
