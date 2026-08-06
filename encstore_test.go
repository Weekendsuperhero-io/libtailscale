// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
)

const testKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestEncryptedStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := newEncryptedFileStore(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState("k1", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState("k2", []byte{0, 1, 2}); err != nil {
		t.Fatal(err)
	}

	// A fresh store over the same file with the same key sees the data.
	s2, err := newEncryptedFileStore(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.ReadState("k1")
	if err != nil || string(got) != "v1" {
		t.Fatalf("ReadState(k1) = %q, %v", got, err)
	}

	// Deleting via nil removes the key.
	if err := s2.WriteState("k1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.ReadState("k1"); err != ipn.ErrStateNotExist {
		t.Fatalf("deleted key: got %v, want ErrStateNotExist", err)
	}
}

func TestEncryptedStoreOnDiskIsOpaque(t *testing.T) {
	dir := t.TempDir()
	s, err := newEncryptedFileStore(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("wireguard-private-key-material")
	if err := s.WriteState("_machinekey", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, sealedStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if containsSub(raw, secret) {
		t.Fatal("plaintext secret visible in sealed store")
	}
	// json marshals []byte as base64; that form must be absent too.
	if containsSub(raw, []byte("wireguard")) {
		t.Fatal("recognizable plaintext in sealed store")
	}
}

func TestWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := newEncryptedFileStore(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WriteState("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	otherKey := "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1eff"
	if _, err := newEncryptedFileStore(dir, otherKey); err == nil {
		t.Fatal("wrong key must fail closed, not start a fresh identity")
	}
}

func TestPlaintextMigrationVerifiesBeforeDelete(t *testing.T) {
	dir := t.TempDir()
	legacy := map[ipn.StateKey][]byte{
		"_machinekey": []byte("legacy-machine-key"),
		"_profiles":   []byte(`{"p":1}`),
	}
	blob, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(dir, plaintextStateFile)
	if err := os.WriteFile(legacyPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := newEncryptedFileStore(dir, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadState("_machinekey")
	if err != nil || string(got) != "legacy-machine-key" {
		t.Fatalf("migrated key = %q, %v", got, err)
	}
	// The plaintext original is gone ONLY because the sealed copy verified.
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatal("plaintext state still present after verified migration")
	}
	if _, err := os.Stat(filepath.Join(dir, sealedStateFile)); err != nil {
		t.Fatal("sealed state missing after migration")
	}
}

// Mirrors the exact check ipnlocal's stateEncrypted() performs on the
// backend's store (a type assertion, never a method call).
func TestMarkerInterfaceAssertion(t *testing.T) {
	s, err := newEncryptedFileStore(t.TempDir(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	var store ipn.StateStore = s
	if _, ok := store.(ipn.EncryptedStateStore); !ok {
		t.Fatal("store does not satisfy ipn.EncryptedStateStore")
	}
}

func TestBadKeyShapeRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := newEncryptedFileStore(dir, "nothex"); err == nil {
		t.Fatal("non-hex key accepted")
	}
	short := hex.EncodeToString([]byte("short"))
	if _, err := newEncryptedFileStore(dir, short); err == nil {
		t.Fatal("short key accepted")
	}
}

func containsSub(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
