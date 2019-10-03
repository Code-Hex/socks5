package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/proxy"
)

func main() {
	const (
		socks5Addr = "127.0.0.1:1080"
	)

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("err: %v", err)
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

	ctx := context.Background()
	p, err := proxy.Socks5(ctx, socks5.CmdConnect, "tcp", socks5Addr)
	if err != nil {
		log.Fatal(err)
	}
	client := http.DefaultClient
	client.Transport = &http.Transport{Dial: p.Dial}

	log.Println("target", fmt.Sprintf("http://%s/health", httpLn.Addr().String()))
	resp, err := client.Get(
		fmt.Sprintf("http://%s/health", httpLn.Addr().String()),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		log.Fatal(err)
	}
	if buf.String() != "OK" {
		log.Fatalf(`got %s, but want "OK"`, buf.String())
	}
}
