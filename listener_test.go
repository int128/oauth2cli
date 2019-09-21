package oauth2cli

import (
	"net"
	"testing"
)

func Test_newLocalhostListener(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		l, err := newLocalhostListener(nil)
		if err != nil {
			t.Fatalf("newLocalhostListener error: %s", err)
		}
		defer l.Close()
		if l.URL == "" {
			t.Errorf("URL wants a string but was empty")
		}
		t.Logf("URL is %s", l.URL)
	})

	t.Run("empty", func(t *testing.T) {
		l, err := newLocalhostListener(nil)
		if err != nil {
			t.Fatalf("newLocalhostListener error: %s", err)
		}
		defer l.Close()
		if l.URL == "" {
			t.Errorf("URL wants a string but was empty")
		}
		t.Logf("URL is %s", l.URL)
	})

	t.Run("singlePort", func(t *testing.T) {
		l, err := newLocalhostListener([]int{9000})
		if err != nil {
			t.Fatalf("newLocalhostListener error: %s", err)
		}
		defer l.Close()
		if w := "http://localhost:9000"; l.URL != w {
			t.Errorf("URL wants %s but was %s", w, l.URL)
		}
	})

	t.Run("multiplePortFallback", func(t *testing.T) {
		preListener, err := net.Listen("tcp", "localhost:9000")
		if err != nil {
			t.Fatalf("Could not listen: %s", err)
		}
		defer preListener.Close()

		l, err := newLocalhostListener([]int{9000, 9001})
		if err != nil {
			t.Fatalf("newLocalhostListener error: %s", err)
		}
		defer l.Close()
		if w := "http://localhost:9001"; l.URL != w {
			t.Errorf("URL wants %s but was %s", w, l.URL)
		}
	})

	t.Run("multiplePortFail", func(t *testing.T) {
		preListener1, err := net.Listen("tcp", "localhost:9001")
		if err != nil {
			t.Fatalf("Could not listen: %s", err)
		}
		defer preListener1.Close()
		preListener2, err := net.Listen("tcp", "localhost:9002")
		if err != nil {
			t.Fatalf("Could not listen: %s", err)
		}
		defer preListener2.Close()

		l, err := newLocalhostListener([]int{9001, 9002})
		if err == nil {
			l.Close()
			t.Fatalf("newLocalhostListener wants error but was nil")
		}
		t.Logf("expected error: %s", err)
	})
}
