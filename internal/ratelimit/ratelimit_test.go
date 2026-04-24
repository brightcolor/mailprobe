package ratelimit

import (
	"testing"
	"time"
)

func TestAllowEnforcesWindowLimit(t *testing.T) {
	l := New(40*time.Millisecond, 2)

	if !l.Allow("ip:1") {
		t.Fatal("first hit should be allowed")
	}
	if !l.Allow("ip:1") {
		t.Fatal("second hit should be allowed")
	}
	if l.Allow("ip:1") {
		t.Fatal("third hit in window should be blocked")
	}

	time.Sleep(60 * time.Millisecond)
	if !l.Allow("ip:1") {
		t.Fatal("hit after window should be allowed again")
	}
}

func TestAllowIsPerKey(t *testing.T) {
	l := New(time.Minute, 1)

	if !l.Allow("a") {
		t.Fatal("first hit for key a should pass")
	}
	if l.Allow("a") {
		t.Fatal("second hit for key a should fail")
	}
	if !l.Allow("b") {
		t.Fatal("first hit for key b should still pass")
	}
}
