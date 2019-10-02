package socks5_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
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
	p, err := proxy.Socks5(ctx, socks5.CmdConnect, lAddr.Network(), "127.0.0.1:1080")
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

	const (
		ftpAddr   = "127.0.0.1:21"
		ftpUser   = "user"
		ftpPass   = "password"
		socksAddr = "127.0.0.1:1080"
	)

	ctx := context.Background()
	p1, err := proxy.Socks5(ctx, socks5.CmdConnect, "tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	conn1, err := p1.Dial("tcp", ftpAddr)
	if err != nil {
		t.Fatal(err)
	}
	rdConn1 := bufio.NewReader(conn1)

	_, err = conn1.Write([]byte("USER " + ftpUser + "\015\012"))
	if err != nil {
		t.Fatal(err)
	}
	line1, _, err := rdConn1.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("line1:", string(line1))

	_, err = conn1.Write([]byte("PASS " + ftpPass + "\015\012"))
	if err != nil {
		t.Fatal(err)
	}
	line2, _, err := rdConn1.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("line2:", string(line2))

	p2, err := proxy.Socks5(ctx, socks5.CmdBind, "tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := p2.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	bindAddr := ln.Addr()
	fmt.Printf("%#v\n", bindAddr)

	host, port, _ := net.SplitHostPort(bindAddr.String())
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	block1, block2 := int(p>>8), int(p)

	joined := strings.Join(
		append(
			strings.Split(host, "."),
			fmt.Sprintf("%v,%v", byte(block1), byte(block2)),
		),
		",",
	)
	fmt.Println(joined)

	_, err = conn1.Write([]byte("PORT " + joined + "\015\012"))
	if err != nil {
		t.Fatal(err)
	}

	line3, _, err := rdConn1.ReadLine()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("line3:", string(line3))

	_, err = conn1.Write([]byte("LIST /\015\012"))
	if err != nil {
		t.Fatal(err)
	}

	conn2, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	rdConn2 := bufio.NewReader(conn2)

	for {
		line, _, err := rdConn2.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		fmt.Println(string(line))
	}

	// if got := string(line); got != "OK" {
	// 	t.Fatalf("%s", got)
	// }
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
