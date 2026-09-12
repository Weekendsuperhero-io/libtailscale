// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// A Go c-archive of the tsnet package. See tailscale.h for details.
package main

//#include "errno.h"
//#include <stdint.h>
import "C"

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/socks5"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func main() {}

// servers tracks all the allocated *tsnet.Server objects.
var servers struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*server
}

type server struct {
	s       *tsnet.Server
	lastErr string
	started bool

	// mu guards the fields below, which are written by tailscale_socks5_listen
	// and tailscale_watch_ipn_bus and read by the goroutines they spawn.
	mu sync.Mutex

	// socksLn is the loopback SOCKS5 listener owned by
	// tailscale_socks5_listen. Each call replaces it, which is the whole
	// point: see that function's comment.
	socksLn net.Listener

	// busCancels stops every tailscale_watch_ipn_bus watcher when the server
	// closes, so a caller that never closes its read fd cannot leak one.
	busCancels []context.CancelFunc
}

// logf routes to the node's logger once one is installed (tailscale_set_logfd)
// and discards otherwise: tsnet.Server.Logf is nil until then.
func (s *server) logf(format string, args ...any) {
	if s.s.Logf != nil {
		s.s.Logf(format, args...)
	}
}

func getServer(sd C.int) *server {
	servers.mu.Lock()
	defer servers.mu.Unlock()
	return servers.m[sd]
}

// listeners tracks all the tsnet_listener objects allocated via tsnet_listen.
var listeners struct {
	mu sync.Mutex
	m  map[C.int]*listener
}

type listener struct {
	s  *server
	ln net.Listener
	fd int // go side fd of socketpair sent to C
	mu sync.Mutex
	m  map[C.int]net.Addr //maps fds to remote addresses for lookup
}

// conns tracks all the pipe(2)s allocated via tsnet_dial.
var conns struct {
	mu sync.Mutex
	m  map[C.int]*conn // keyed by the FD given to C (w)
}

type conn struct {
	s *tsnet.Server
	c net.Conn
	r *os.File // r is the local socket to the C client
}

func (s *server) recErr(err error) C.int {
	if err == nil {
		s.lastErr = ""
		return 0
	}
	s.lastErr = err.Error()
	return -1
}

//export TsnetNewServer
func TsnetNewServer() C.int {
	servers.mu.Lock()
	defer servers.mu.Unlock()

	if servers.m == nil {
		servers.m = map[C.int]*server{}
		hostinfo.SetApp("libtailscale")
	}
	if servers.next == 0 {
		servers.next = 42<<16 + 1
	}
	sd := servers.next
	servers.next++
	s := &server{s: &tsnet.Server{}}
	servers.m[sd] = s
	return (C.int)(sd)
}

//export TsnetStart
func TsnetStart(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	err := s.s.Start()
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetUp
func TsnetUp(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	_, err := s.s.Up(context.Background()) // cancellation is via TsnetClose
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetClose
func TsnetClose(sd C.int) C.int {
	servers.mu.Lock()
	s := servers.m[sd]
	if s != nil {
		delete(servers.m, sd)
	}
	servers.mu.Unlock()

	if s == nil {
		return C.EBADF
	}

	// Stop what this file owns before handing off to tsnet: the SOCKS5
	// listener from tailscale_socks5_listen and every tailscale_watch_ipn_bus
	// watcher, so neither outlives the node.
	s.mu.Lock()
	socksLn, busCancels := s.socksLn, s.busCancels
	s.socksLn, s.busCancels = nil, nil
	s.mu.Unlock()
	if socksLn != nil {
		socksLn.Close()
	}
	for _, cancel := range busCancels {
		cancel()
	}

	// TODO: cancel Up
	// TODO: close related listeners / conns.
	if !s.started {
		// Server was never started, nothing to close.
		return 0
	}
	if err := s.s.Close(); err != nil {
		s.s.Logf("tailscale_close: failed with %v", err)
		return -1
	}

	return 0
}

//export TsnetGetIps
func TsnetGetIps(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	ip4, ip6 := s.s.TailscaleIPs()
	joined := strings.Join([]string{ip4.String(), ip6.String()}, ",")
	n := copy(out, joined)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetErrmsg
func TsnetErrmsg(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}
	n := copy(out, s.lastErr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetListen
func TsnetListen(sd C.int, network, addr *C.char, listenerOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ln, err := s.s.Listen(C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	return bridgeListener(s, ln, listenerOut)
}

// TsnetListenService creates a listener that advertises this node as a host of
// a Tailscale Service (a VIP identified by `name`, e.g. "svc:example"). It is
// the service-hosting counterpart to TsnetListen and returns a listener the
// same way (one side of a socketpair; accept with tailscale_accept). `port`
// is the TCP port to advertise; when `terminate_tls` is non-zero the node
// terminates TLS (SNI must be the Service FQDN) and forwards plaintext.
//
// Note (per tsnet.ListenService): the node must be TAGGED, and advertising
// still requires admin/ACL approval before the Service goes live.
//
//export TsnetListenService
func TsnetListenService(sd C.int, name *C.char, port C.int, terminateTLS C.int, listenerOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	svcLn, err := s.s.ListenService(C.GoString(name), tsnet.ServiceModeTCP{
		Port:         uint16(port),
		TerminateTLS: terminateTLS != 0,
	})
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	// *ServiceListener embeds net.Listener, so the same bridge applies.
	return bridgeListener(s, svcLn, listenerOut)
}

// bridgeListener hands one side of a socketpair(2) to C for a net.Listener,
// accepting connections in a goroutine and passing each accepted connection's
// fd through via SCM_RIGHTS. Shared by TsnetListen and TsnetListenService.
func bridgeListener(s *server, ln net.Listener, listenerOut *C.int) C.int {
	// The tailscale_listener we return to C is one side of a socketpair(2).
	// We do this so we can proactively call ln.Accept in a goroutine and
	// feed an fd for the connection through the listener. This lets C use
	// epoll on the tailscale_listener to know if it should call
	// tailscale_accept, which avoids a blocking call on the far side.
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return s.recErr(err)
	}
	sp := fds[1]
	fdC := C.int(fds[0])

	listeners.mu.Lock()
	if listeners.m == nil {
		listeners.m = map[C.int]*listener{}
	}
	listener := &listener{s: s, ln: ln, fd: sp, m: map[C.int]net.Addr{}}
	listeners.m[fdC] = listener
	listeners.mu.Unlock()

	cleanup := func() {
		// If fdC is closed on the C side, then we end up calling
		// into cleanup twice. Be careful to avoid syscall.Close
		// twice as the FD may have been reallocated.
		listeners.mu.Lock()
		if tsLn, ok := listeners.m[fdC]; ok && tsLn.ln == ln {
			delete(listeners.m, fdC)
			syscall.Close(sp)
		}
		listeners.mu.Unlock()

		ln.Close()
	}
	go func() {
		// fdC is never written to, so trying to read from sp blocks
		// until fdC is closed. We use this as a signal that C is
		// done with the listener, and we can tear it down.
		//
		// TODO: would using os.NewFile avoid a locked up thread?
		var buf [256]byte
		syscall.Read(sp, buf[:])
		cleanup()
	}()
	go func() {
		defer cleanup()
		for {
			netConn, err := ln.Accept()
			if err != nil {
				return
			}
			var connFd C.int
			if err := newConn(s, netConn, &connFd); err != nil {
				if s.s.Logf != nil {
					s.s.Logf("libtailscale.accept: newConn: %v", err)
				}
				netConn.Close()
				continue
			}
			rights := syscall.UnixRights(int(connFd))
			err = syscall.Sendmsg(sp, nil, rights, nil, 0)
			if err != nil {
				// We handle sp being closed in the read goroutine above.
				if s.s.Logf != nil {
					s.s.Logf("libtailscale.accept: sendmsg failed: %v", err)
				}
				netConn.Close()
				// fallthrough to close connFd, then continue Accept()ing
			}

			// map the connection to the remote address
			listener.mu.Lock()
			listener.m[connFd] = netConn.RemoteAddr()
			listener.mu.Unlock()

			syscall.Close(int(connFd)) // now owned by recvmsg
		}
	}()

	*listenerOut = fdC
	return 0
}

//export TsnetAccept
func TsnetAccept(listenerFd C.int, connOut *C.int) C.int {
	listeners.mu.Lock()
	ln := listeners.m[listenerFd]
	listeners.mu.Unlock()

	if ln == nil {
		return C.EBADF
	}

	buf := make([]byte, unix.CmsgLen(int(unsafe.Sizeof((C.int)(0)))))
	_, oobn, _, _, err := syscall.Recvmsg(int(listenerFd), nil, buf, 0)
	if err != nil {
		return ln.s.recErr(err)
	}

	scms, err := syscall.ParseSocketControlMessage(buf[:oobn])
	if err != nil {
		return ln.s.recErr(err)
	}
	if len(scms) != 1 {
		return ln.s.recErr(fmt.Errorf("libtailscale: got %d control messages, want 1", len(scms)))
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil {
		return ln.s.recErr(err)
	}
	if len(fds) != 1 {
		return ln.s.recErr(fmt.Errorf("libtailscale: got %d FDs, want 1", len(fds)))
	}
	*connOut = (C.int)(fds[0])

	return 0
}

func newConn(s *server, netConn net.Conn, connOut *C.int) error {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	r := os.NewFile(uintptr(fds[1]), "socketpair-r")
	c := &conn{s: s.s, c: netConn, r: r}
	fdC := C.int(fds[0])

	conns.mu.Lock()
	if conns.m == nil {
		conns.m = make(map[C.int]*conn)
	}
	conns.m[fdC] = c
	conns.mu.Unlock()

	connCleanup := func() {
		var inCleanup bool
		conns.mu.Lock()
		if tsConn, ok := conns.m[fdC]; ok && tsConn.c == netConn {
			delete(conns.m, fdC)
			inCleanup = true
		}
		conns.mu.Unlock()

		if !inCleanup {
			return
		}

		r.Close()
		netConn.Close()
	}
	go func() {
		defer connCleanup()
		var b [1 << 16]byte
		io.CopyBuffer(r, netConn, b[:])
		syscall.Shutdown(int(r.Fd()), syscall.SHUT_WR)
		if cr, ok := netConn.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
	}()
	go func() {
		defer connCleanup()
		var b [1 << 16]byte
		io.CopyBuffer(netConn, r, b[:])
		syscall.Shutdown(int(r.Fd()), syscall.SHUT_RD)
		if cw, ok := netConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	*connOut = fdC
	return nil
}

//export TsnetGetRemoteAddr
func TsnetGetRemoteAddr(listener C.int, conn C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	listeners.mu.Lock()
	defer listeners.mu.Unlock()
	l := listeners.m[listener]
	if l == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	addr, ok := l.m[conn]
	if !ok {
		out[0] = '\x00'
		return C.EBADF
	}

	ip := extractIP(addr.String())

	n := copy(out, ip)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

// Strips the port from connection IPs
func extractIP(ipWithPort string) string {
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[([0-9a-fA-F:]+)\]`)
	match := re.FindString(ipWithPort)
	return match
}

//export TsnetDial
func TsnetDial(sd C.int, network, addr *C.char, connOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	netConn, err := s.s.Dial(context.Background(), C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	if err := newConn(s, netConn, connOut); err != nil {
		return s.recErr(err)
	}
	return 0
}

//export TsnetSetDir
func TsnetSetDir(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Dir = C.GoString(str)
	return 0
}

//export TsnetSetStateKey
func TsnetSetStateKey(sd C.int, key *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if s.started {
		return s.recErr(fmt.Errorf("tailscale_set_state_key must be called before the server starts"))
	}
	if s.s.Dir == "" {
		return s.recErr(fmt.Errorf("tailscale_set_state_key requires tailscale_set_dir first"))
	}
	store, err := newEncryptedFileStore(s.s.Dir, C.GoString(key))
	if err != nil {
		return s.recErr(err)
	}
	s.s.Store = store
	return 0
}

//export TsnetSetHostname
func TsnetSetHostname(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Hostname = C.GoString(str)
	return 0
}

//export TsnetSetAuthKey
func TsnetSetAuthKey(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.AuthKey = C.GoString(str)
	return 0
}

//export TsnetSetControlURL
func TsnetSetControlURL(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.ControlURL = C.GoString(str)
	return 0
}

//export TsnetSetEphemeral
func TsnetSetEphemeral(sd C.int, e int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if e == 0 {
		s.s.Ephemeral = false
	} else {
		s.s.Ephemeral = true
	}
	return 0
}

//export TsnetSetLogFD
func TsnetSetLogFD(sd, fd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if fd == -1 {
		s.s.Logf = logger.Discard
		return 0
	}
	f := os.NewFile(uintptr(fd), "logfd")
	s.s.Logf = func(format string, args ...any) {
		fmt.Fprintf(f, format, args...)
		fmt.Fprintf(f, "\n")
	}
	return 0
}

//export TsnetLoopback
func TsnetLoopback(sd C.int, addrOut *C.char, addrLen C.size_t, proxyOut *C.char, localOut *C.char) C.int {
	// Panic here to ensure we always leave the out values NUL-terminated.
	if addrOut == nil {
		panic("loopback_api passed nil addr_out")
	} else if addrLen == 0 {
		panic("loopback_api passed addrlen of 0")
	} else if proxyOut == nil {
		panic("loopback_api passed nil proxy_cred_out")
	} else if localOut == nil {
		panic("loopback_api passed nil local_api_cred_out")
	}

	// Start out NUL-termianted to cover error conditions.
	*addrOut = '\x00'
	*localOut = '\x00'
	*proxyOut = '\x00'

	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	addr, proxyCred, localAPICred, err := s.s.Loopback()
	if err != nil {
		return s.recErr(err)
	}
	if len(proxyCred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(proxyCred)=%d, want 32", len(proxyCred)))
	}
	if len(localAPICred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(localAPICred)=%d, want 32", len(localAPICred)))
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(addrOut)), addrLen)
	n := copy(out, addr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'

	// proxyOut and localOut are non-nil and 33 bytes long because
	// they are defined in C as char cred_out[static 33].
	out = unsafe.Slice((*byte)(unsafe.Pointer(proxyOut)), 33)
	copy(out, proxyCred)
	out[32] = '\x00'
	out = unsafe.Slice((*byte)(unsafe.Pointer(localOut)), 33)
	copy(out, localAPICred)
	out[32] = '\x00'

	return 0
}

//export TsnetStatusJSON
func TsnetStatusJSON(sd C.int, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("status_json passed nil json_out")
	}
	*jsonOut = nil
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	// LocalClient rides tsnet's in-memory LocalAPI listener — unlike
	// Loopback()'s TCP listener it cannot be reclaimed by the OS while
	// the process is suspended (iOS), so status reads keep working on
	// long-lived nodes.
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil {
		return s.recErr(err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return s.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return 0
}

// socksCredBytes is the entropy behind the SOCKS5 password: 16 bytes renders
// as 32 hex characters, matching tsnet's own proxy credential and the
// char cred_out[static 33] contract in tailscale.h.
const socksCredBytes = 16

// startSocks5 replaces sd's SOCKS5 proxy with one on a fresh loopback
// listener, returning its address and credential. See
// tailscale_socks5_listen's comment in tailscale.h for why every call builds a
// new listener rather than caching one.
func (s *server) startSocks5() (addr, cred string, err error) {
	var credBuf [socksCredBytes]byte
	if _, err := crand.Read(credBuf[:]); err != nil {
		return "", "", err
	}
	cred = hex.EncodeToString(credBuf[:])

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}

	s.mu.Lock()
	prev := s.socksLn
	s.socksLn = ln
	s.mu.Unlock()
	if prev != nil {
		// Ends the previous Serve loop; connections it already handed off are
		// unaffected.
		prev.Close()
	}

	// Dialer is the node's own user dialer, so the proxy resolves MagicDNS and
	// routes over the tailnet exactly as tsnet's own does. Server.Dial also
	// awaits Running, so a connection opened during bring-up waits for the
	// node rather than failing; the caller's own request timeout still applies.
	srv := &socks5.Server{
		Logf:     logger.WithPrefix(s.logf, "socks5: "),
		Dialer:   s.s.Dial,
		Username: "tsnet",
		Password: cred,
	}
	go func() {
		// A replaced or closed listener is the ordinary exit path.
		s.logf("tailscale_socks5_listen: SOCKS5 server exited: %v", srv.Serve(ln))
	}()

	return ln.Addr().String(), cred, nil
}

//export TsnetSocks5Listen
func TsnetSocks5Listen(sd C.int, addrOut *C.char, addrLen C.size_t, credOut *C.char) C.int {
	// Panic here to ensure we always leave the out values NUL-terminated.
	if addrOut == nil {
		panic("socks5_listen passed nil addr_out")
	} else if addrLen == 0 {
		panic("socks5_listen passed addrlen of 0")
	} else if credOut == nil {
		panic("socks5_listen passed nil cred_out")
	}

	// Start out NUL-terminated to cover error conditions.
	*addrOut = '\x00'
	*credOut = '\x00'

	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	addr, cred, err := s.startSocks5()
	if err != nil {
		return s.recErr(err)
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(addrOut)), addrLen)
	n := copy(out, addr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'

	// credOut is non-nil and 33 bytes long because it is defined in C as
	// char cred_out[static 33].
	out = unsafe.Slice((*byte)(unsafe.Pointer(credOut)), 33)
	copy(out, cred)
	out[32] = '\x00'

	return 0
}

// streamNotifies writes one JSON-encoded notification per line to w until
// next reports an error or the reader goes away, then closes w. Split out of
// TsnetWatchIPNBus so the framing and the shutdown paths are testable without
// a node.
func streamNotifies(w io.WriteCloser, next func() (ipn.Notify, error), logf logger.Logf) {
	defer w.Close()
	enc := json.NewEncoder(w)
	for {
		n, err := next()
		if err != nil {
			logf("tailscale_watch_ipn_bus: watch ended: %v", err)
			return
		}
		// Encode writes one line per value. A caller that has closed its read
		// end surfaces here as EPIPE, which is how a watch is cancelled; Go
		// reports it rather than raising SIGPIPE because the descriptor is
		// neither stdout nor stderr.
		if err := enc.Encode(n); err != nil {
			logf("tailscale_watch_ipn_bus: writer closed: %v", err)
			return
		}
	}
}

//export TsnetWatchIPNBus
func TsnetWatchIPNBus(sd C.int, mask C.uint64_t, fdOut *C.int) C.int {
	if fdOut == nil {
		panic("watch_ipn_bus passed nil fd_out")
	}
	*fdOut = -1

	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	// LocalClient rides tsnet's in-memory LocalAPI listener, so this watch
	// involves no socket and no HTTP client: unlike a watch opened over
	// Loopback()'s TCP listener it cannot be severed by the OS reclaiming
	// that socket, nor cut short by a client-side request timeout.
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w, err := lc.WatchIPNBus(ctx, ipn.NotifyWatchOpt(mask))
	if err != nil {
		cancel()
		return s.recErr(err)
	}

	// A pipe rather than a cgo callback: this ABI already hands out bare
	// descriptors (tailscale_conn), and newline-delimited JSON is what every
	// existing consumer of the LocalAPI bus already parses. syscall.Pipe
	// rather than os.Pipe because the read end belongs to the caller — an
	// *os.File would close it from a finalizer once Go lost the reference.
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		w.Close()
		cancel()
		return s.recErr(err)
	}
	wf := os.NewFile(uintptr(fds[1]), "ipn-bus")

	s.mu.Lock()
	s.busCancels = append(s.busCancels, cancel)
	s.mu.Unlock()

	go func() {
		defer func() {
			w.Close()
			cancel()
		}()
		streamNotifies(wf, w.Next, s.logf)
	}()

	*fdOut = C.int(fds[0])
	return 0
}

//export TsnetEnableFunnelToLocalhostPlaintextHttp1
func TsnetEnableFunnelToLocalhostPlaintextHttp1(sd C.int, localhostPort C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ctx := context.Background()
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}

	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return s.recErr(err)
	}
	domain := st.CertDomains[0]

	hp := ipn.HostPort(net.JoinHostPort(domain, strconv.Itoa(443)))
	tcpForward := fmt.Sprintf("127.0.0.1:%d", localhostPort)
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {
				TCPForward:   tcpForward,
				TerminateTLS: domain,
			},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			hp: true,
		},
	}

	lc.SetServeConfig(ctx, sc)
	if !sc.AllowFunnel[hp] {
		return s.recErr(fmt.Errorf("libtailscale: failed to enable funnel"))
	}

	return 0
}
