// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// EDITH patch (edith/encrypted-state-store): an AES-256-GCM encrypted
// ipn.StateStore, so an embedded tsnet node's private key is not readable off
// disk. The caller owns key custody (the EDITH desktop keeps it in the OS
// keychain) and hands the key over the C ABI (tailscale_set_state_key) before
// start. Implements ipn.EncryptedStateStore, so on platforms whose
// stateEncrypted() consults the store the node truthfully reports
// Hostinfo.StateEncrypted; darwin needs the upstream fix to do the same.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"tailscale.com/ipn"
)

const (
	// The sealed store, beside (and eventually instead of) the plaintext
	// tailscaled.state that tsnet's default file store writes.
	sealedStateFile    = "tailscaled.state.sealed"
	plaintextStateFile = "tailscaled.state"
	// Format/version tag; doubles as the AEAD's additional data so a blob
	// can't be replayed under a future incompatible layout.
	sealMagic = "EDITHSS1"
)

// encryptedFileStore persists the whole state map as ONE sealed blob:
// magic || nonce || AES-256-GCM(json(map)). Single-blob (rather than
// per-key files) keeps the atomic-replace story trivial and hides even the
// set of state keys from a disk reader.
//
// ipn.EncryptedStateStore is a SEALED marker interface (unexported method,
// no implementers in v1.102.1), so we satisfy it by embedding the interface:
// the promoted stateStoreIsEncrypted has the right package identity for the
// type assertion in ipnlocal's stateEncrypted(), and upstream never calls
// the method (the nil embedded field is therefore never dereferenced).
type encryptedFileStore struct {
	ipn.EncryptedStateStore

	mu    sync.Mutex
	path  string
	aead  cipher.AEAD
	cache map[ipn.StateKey][]byte
}

var _ ipn.StateStore = (*encryptedFileStore)(nil)
var _ ipn.EncryptedStateStore = (*encryptedFileStore)(nil)

// newEncryptedFileStore opens (or creates) the sealed store in dir with a
// 32-byte hex key. A plaintext tailscaled.state left by a previous unencrypted
// run is migrated: sealed, READ BACK AND VERIFIED, and only then removed —
// a migration fault must never destroy the node's only identity.
func newEncryptedFileStore(dir, hexKey string) (*encryptedFileStore, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("state key is not hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("state key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &encryptedFileStore{
		path:  filepath.Join(dir, sealedStateFile),
		aead:  aead,
		cache: make(map[ipn.StateKey][]byte),
	}
	if err := s.load(dir); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *encryptedFileStore) load(dir string) error {
	sealed, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		plain, err := s.open(sealed)
		if err != nil {
			// Wrong key or corrupt blob: FAIL, never silently start a
			// fresh identity over an existing one.
			return fmt.Errorf("unseal %s: %w", s.path, err)
		}
		return json.Unmarshal(plain, &s.cache)
	case os.IsNotExist(err):
		// Fall through to migration / fresh start.
	default:
		return err
	}

	legacyPath := filepath.Join(dir, plaintextStateFile)
	legacy, err := os.ReadFile(legacyPath)
	if os.IsNotExist(err) {
		return nil // fresh node; nothing to migrate
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(legacy, &s.cache); err != nil {
		return fmt.Errorf("parse legacy plaintext state: %w", err)
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	// Verify-before-delete: prove the sealed copy round-trips before
	// removing the only prior copy of the node identity.
	resealed, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	plain, err := s.open(resealed)
	if err != nil {
		return fmt.Errorf("sealed state read-back failed: %w", err)
	}
	var check map[ipn.StateKey][]byte
	if err := json.Unmarshal(plain, &check); err != nil {
		return err
	}
	if len(check) != len(s.cache) {
		return errors.New("sealed state read-back mismatch")
	}
	for k, v := range s.cache {
		if !bytes.Equal(check[k], v) {
			return errors.New("sealed state read-back mismatch")
		}
	}
	return os.Remove(legacyPath)
}

func (s *encryptedFileStore) seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(sealMagic)+len(nonce)+len(plain)+s.aead.Overhead())
	out = append(out, sealMagic...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plain, []byte(sealMagic)), nil
}

func (s *encryptedFileStore) open(sealed []byte) ([]byte, error) {
	header := len(sealMagic) + s.aead.NonceSize()
	if len(sealed) < header || string(sealed[:len(sealMagic)]) != sealMagic {
		return nil, errors.New("not an EDITH sealed state blob")
	}
	nonce := sealed[len(sealMagic):header]
	return s.aead.Open(nil, nonce, sealed[header:], []byte(sealMagic))
}

// persistLocked seals the cache and atomically replaces the store file.
// Callers hold s.mu (or are pre-concurrency, in load).
func (s *encryptedFileStore) persistLocked() error {
	plain, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}
	sealed, err := s.seal(plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *encryptedFileStore) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bs, ok := s.cache[id]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bs, nil
}

func (s *encryptedFileStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bs == nil {
		delete(s.cache, id)
	} else {
		s.cache[id] = append([]byte(nil), bs...)
	}
	return s.persistLocked()
}
