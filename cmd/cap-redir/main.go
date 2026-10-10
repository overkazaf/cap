//go:build linux

// cap-redir is a transparent-to-explicit proxy adapter for rooted Android
// devices. It accepts connections redirected by iptables REDIRECT, reads
// the original destination via SO_ORIGINAL_DST, and converts them into
// HTTP CONNECT requests to an upstream explicit HTTP proxy (cap).
//
// This gives the same "capture all traffic" effect as a VPN-based approach
// (like HTTP Toolkit) without needing an Android APK.
//
// Usage (on the Android device, via adb shell su):
//
//	cap-redir -proxy 10.221.71.30:8080 -listen :9999
//
// Then set up iptables:
//
//	iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 9999
//	iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 9999
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"encoding/binary"
	"syscall"
	"unsafe"
)

func main() {
	proxy := flag.String("proxy", "", "upstream HTTP proxy address (host:port)")
	listen := flag.String("listen", ":9999", "local listen address for redirected connections")
	flag.Parse()

	if *proxy == "" {
		fmt.Fprintln(os.Stderr, "usage: cap-redir -proxy <host:port> [-listen :9999]")
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("cap-redir: listening on %s, forwarding to proxy %s", ln.Addr(), *proxy)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("cap-redir: shutting down")
		ln.Close()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handle(conn, *proxy)
	}
}

func handle(client net.Conn, proxy string) {
	defer client.Close()

	origDst, err := getOriginalDst(client)
	if err != nil {
		log.Printf("getOriginalDst: %v", err)
		return
	}

	proxyConn, err := net.Dial("tcp", proxy)
	if err != nil {
		log.Printf("dial proxy %s: %v", proxy, err)
		return
	}
	defer proxyConn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origDst, origDst)
	if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
		log.Printf("write CONNECT: %v", err)
		return
	}

	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		log.Printf("read CONNECT response: %v", err)
		return
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9] != '2' {
		log.Printf("CONNECT %s failed: %s", origDst, resp[:min(len(resp), 60)])
		return
	}

	relay(client, proxyConn)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}

// getOriginalDst retrieves the original destination address from a
// connection that was redirected by iptables REDIRECT. It reads the
// SO_ORIGINAL_DST socket option (Linux-specific).
func getOriginalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr syscall.RawSockaddrInet4
	var addr6 syscall.RawSockaddrInet6
	var origDst string
	var syscallErr error

	err = raw.Control(func(fd uintptr) {
		// Try IPv4 first (SO_ORIGINAL_DST = 80)
		const SO_ORIGINAL_DST = 80
		addrLen := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno == 0 {
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, addr.Port)
			port := binary.BigEndian.Uint16(portBytes)
			ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
			origDst = fmt.Sprintf("%s:%d", ip, port)
			return
		}

		// Try IPv6 (IP6T_SO_ORIGINAL_DST = 80)
		const IP6T_SO_ORIGINAL_DST = 80
		addr6Len := uint32(unsafe.Sizeof(addr6))
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IPV6,
			IP6T_SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr6)),
			uintptr(unsafe.Pointer(&addr6Len)),
			0,
		)
		if errno == 0 {
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, addr6.Port)
			port := binary.BigEndian.Uint16(portBytes)
			ip := net.IP(addr6.Addr[:])
			origDst = fmt.Sprintf("[%s]:%d", ip, port)
			return
		}

		syscallErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %v", errno)
	})

	if err != nil {
		return "", err
	}
	if syscallErr != nil {
		return "", syscallErr
	}
	return origDst, nil
}
