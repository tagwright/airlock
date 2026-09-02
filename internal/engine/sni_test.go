// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"testing"
	"time"
)

func TestSNIStoreLookupWithinWindow(t *testing.T) {
	s := &sniStore{}
	now := time.Now()
	s.record("example.com", now)

	if name, ok := s.lookup(now.Add(sniWindow - time.Second)); !ok || name != "example.com" {
		t.Fatalf("expected a hit within the window, got %q ok=%v", name, ok)
	}
	if _, ok := s.lookup(now.Add(sniWindow + time.Second)); ok {
		t.Fatalf("expected a miss outside the window")
	}
}

func TestSNIStorePicksClosestOnMultipleRecent(t *testing.T) {
	s := &sniStore{}
	base := time.Now()
	s.record("older.example", base)
	s.record("newer.example", base.Add(2*time.Second))

	name, ok := s.lookup(base.Add(2100 * time.Millisecond))
	if !ok || name != "newer.example" {
		t.Fatalf("expected the temporally closest name, got %q ok=%v", name, ok)
	}
}

// TestSNIStoreLookupConsumesRecord pins the integration-pass-2 fix: a
// single SNI observation may satisfy at most one lookup, never a second,
// later one still within its window. See lookup's doc comment for the
// live misattribution this closes (a bare-IP connection fired moments
// after a real domain connection was silently downgraded from
// unresolved-ip to no-match by reusing the earlier connection's SNI).
func TestSNIStoreLookupConsumesRecord(t *testing.T) {
	s := &sniStore{}
	now := time.Now()
	s.record("example.com", now)

	name, ok := s.lookup(now.Add(100 * time.Millisecond))
	if !ok || name != "example.com" {
		t.Fatalf("expected the first lookup to hit, got %q ok=%v", name, ok)
	}
	if _, ok := s.lookup(now.Add(200 * time.Millisecond)); ok {
		t.Fatalf("expected the second lookup to miss: the record was already consumed by the first")
	}
}

func TestSNIStoreCapBoundsMemory(t *testing.T) {
	s := &sniStore{}
	now := time.Now()
	for i := 0; i < sniCapPerContainer+50; i++ {
		s.record("flood.example", now)
	}
	if len(s.recent) > sniCapPerContainer {
		t.Fatalf("expected at most %d entries, got %d", sniCapPerContainer, len(s.recent))
	}
}
