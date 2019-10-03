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
	"testing"
	"time"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/proxy"
	"github.com/Code-Hex/socks5/server"
)

func TestSocks5_Connect(t *testing.T) {
	socks5Ln := socks5Server(t)

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

	lAddr := socks5Ln.Addr()
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

func TestSocks5_Bind(t *testing.T) {
	socks5Ln := socks5Server(t)
	ctx := context.Background()
	socks5Addr := socks5Ln.Addr()

	dialer, err := proxy.Socks5(ctx, socks5.CmdConnect, socks5Addr.Network(), socks5Addr.String())
	if err != nil {
		t.Fatal(err)
	}

	echoLn, waitCh := echoBindServer(t)
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

	ln, err := dialer2.Listen("tcp", "127.0.0.1:0")
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
}

func socks5Server(t *testing.T) net.Listener {
	t.Helper()
	socks5Ln, err := net.Listen("tcp", "127.0.0.1:0")
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

func echoBindServer(t *testing.T) (net.Listener, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	<-time.After(time.Second)
	return ln, waitCh
}
