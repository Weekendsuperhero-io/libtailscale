// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// Test files cannot use cgo, so these exercise the helpers the exported
// tailscale_socks5_listen / tailscale_watch_ipn_bus shells delegate to. The
// shells themselves only marshal C out-params.

func dialable(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// The property the whole export exists for: a second call yields a working
// listener at a NEW address and retires the old one. tsnet's Loopback() cannot
// do this, which is why a node whose loopback socket the OS reclaimed could
// only be replaced wholesale.
func TestStartSocks5IsRecallable(t *testing.T) {
	s := &server{s: &tsnet.Server{}}

	addr1, cred1, err := s.startSocks5()
	if err != nil {
		t.Fatalf("first startSocks5: %v", err)
	}
	if !dialable(t, addr1) {
		t.Fatalf("first proxy %q does not accept connections", addr1)
	}

	addr2, cred2, err := s.startSocks5()
	if err != nil {
		t.Fatalf("second startSocks5: %v", err)
	}
	if addr2 == addr1 {
		t.Errorf("second call reused the address %q; it must build a fresh listener", addr1)
	}
	if cred2 == cred1 {
		t.Errorf("second call reused the credential; each listener gets its own")
	}
	if !dialable(t, addr2) {
		t.Fatalf("second proxy %q does not accept connections", addr2)
	}
	// The retired listener is closed, so the stale address a suspended-and-
	// resumed caller still holds fails fast instead of hanging.
	for i := 0; i < 50 && dialable(t, addr1); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if dialable(t, addr1) {
		t.Errorf("replaced proxy %q still accepts connections", addr1)
	}

	// Closing the server retires the survivor too.
	s.mu.Lock()
	ln := s.socksLn
	s.mu.Unlock()
	if ln == nil {
		t.Fatal("server did not retain the listener; TsnetClose could not close it")
	}
	ln.Close()
	for i := 0; i < 50 && dialable(t, addr2); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if dialable(t, addr2) {
		t.Errorf("closed proxy %q still accepts connections", addr2)
	}
}

// cred_out is declared char[static 33] in C: 32 hex characters plus the NUL
// the shell writes. A credential of any other length would be silently
// truncated into the caller's buffer.
func TestStartSocks5CredentialShape(t *testing.T) {
	s := &server{s: &tsnet.Server{}}
	_, cred, err := s.startSocks5()
	if err != nil {
		t.Fatalf("startSocks5: %v", err)
	}
	t.Cleanup(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.socksLn != nil {
			s.socksLn.Close()
		}
	})
	if len(cred) != 32 {
		t.Errorf("credential is %d chars, want 32 (char cred_out[static 33])", len(cred))
	}
	if _, err := hex.DecodeString(cred); err != nil {
		t.Errorf("credential %q is not hex: %v", cred, err)
	}
}

func TestStreamNotifiesFramesOnePerLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	want := []ipn.Notify{
		{Version: "one"},
		{Version: "two"},
		{Version: "three"},
	}
	sent := 0
	go streamNotifies(w, func() (ipn.Notify, error) {
		if sent == len(want) {
			return ipn.Notify{}, io.EOF
		}
		n := want[sent]
		sent++
		return n, nil
	}, t.Logf)

	sc := bufio.NewScanner(r)
	for i, wantN := range want {
		if !sc.Scan() {
			t.Fatalf("line %d: stream ended early: %v", i, sc.Err())
		}
		var got ipn.Notify
		if err := json.Unmarshal(sc.Bytes(), &got); err != nil {
			t.Fatalf("line %d: %v (raw %q)", i, err, sc.Bytes())
		}
		if got.Version != wantN.Version {
			t.Errorf("line %d: Version=%q, want %q", i, got.Version, wantN.Version)
		}
	}
	// next reporting an error closes the writer, which ends the scan — the
	// caller sees EOF rather than blocking for a notification that can never
	// arrive.
	if sc.Scan() {
		t.Errorf("stream continued past the watch error: %q", sc.Bytes())
	}
}

// A caller cancels a watch by closing its read end. That must terminate the
// writer goroutine rather than blocking it forever or killing the process with
// SIGPIPE.
func TestStreamNotifiesStopsWhenReaderCloses(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A notification every time it is asked, forever: only the closed
		// reader can end this.
		streamNotifies(w, func() (ipn.Notify, error) {
			return ipn.Notify{Version: "chatty"}, nil
		}, t.Logf)
	}()

	// Read one line so the stream is definitely flowing, then hang up.
	if _, err := bufio.NewReader(r).ReadString('\n'); err != nil {
		t.Fatalf("reading the first notification: %v", err)
	}
	r.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("streamNotifies did not return after the reader closed")
	}
}

func TestStreamNotifiesSurfacesWatchErrors(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var logged []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		streamNotifies(w, func() (ipn.Notify, error) {
			return ipn.Notify{}, errors.New("bus went away")
		}, func(format string, args ...any) { logged = append(logged, format) })
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("streamNotifies did not return on a watch error")
	}
	if len(logged) == 0 {
		t.Error("a watch error must be logged; it is the only signal the embedder gets")
	}
}
