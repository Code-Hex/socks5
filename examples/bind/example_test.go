package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/Code-Hex/socks5"
	"github.com/Code-Hex/socks5/proxy"
	"github.com/Code-Hex/socks5/server"
)

func main() {
	const (
		ftpAddr = "127.0.0.1:21"
		ftpUser = "user"
		ftpPass = "password"
	)
	socks5Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("err: %v", err)
	}
	socksAddr := socks5Ln.Addr().String()

	go func() {
		if err := server.New(nil).Serve(socks5Ln); err != nil {
			panic(err)
		}
	}()

	ctx := context.Background()
	p1, err := proxy.Socks5(ctx, socks5.CmdConnect, "tcp", socksAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn1, err := p1.Dial("tcp", ftpAddr)
	if err != nil {
		log.Fatal(err)
	}
	rdConn1 := bufio.NewReader(conn1)

	_, err = conn1.Write([]byte("USER " + ftpUser + "\015\012"))
	if err != nil {
		log.Fatal(err)
	}
	line1, _, err := rdConn1.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("line1:", string(line1))

	_, err = conn1.Write([]byte("PASS " + ftpPass + "\015\012"))
	if err != nil {
		log.Fatal(err)
	}
	line2, _, err := rdConn1.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("line2:", string(line2))

	p2, err := proxy.Socks5(ctx, socks5.CmdBind, "tcp", socksAddr)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := p2.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}

	bindAddr := ln.Addr()
	log.Printf("%#v\n", bindAddr)

	host, port, _ := net.SplitHostPort(bindAddr.String())
	p, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}

	joined := strings.Join(
		append(
			strings.Split(host, "."),
			fmt.Sprintf("%v,%v", byte(p>>8), byte(p)),
		),
		",",
	)
	log.Println(joined)

	_, err = conn1.Write([]byte("PORT " + joined + "\015\012"))
	if err != nil {
		log.Fatal(err)
	}

	line3, _, err := rdConn1.ReadLine()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("line3:", string(line3))

	_, err = conn1.Write([]byte("LIST /\015\012"))
	if err != nil {
		log.Fatal(err)
	}

	conn2, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept err: %v", err)
	}
	rdConn2 := bufio.NewReader(conn2)

	for {
		line, _, err := rdConn2.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		log.Println(string(line))
	}
}
