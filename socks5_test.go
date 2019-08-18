package socks5

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestSocks5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	go func() {
		if err := New(nil).Serve(ln); err != nil {
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
	p, err := proxy.SOCKS5(lAddr.Network(), lAddr.String(), nil, proxy.Direct)
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
