package oauth2cli

import (
	"fmt"
	"testing"
)

func Test_newLocalhostListener(t *testing.T) {
	for _, testcase := range []struct {
		address string
	}{
		{},
		{address: "0.0.0.0"},
	} {
		t.Run(fmt.Sprintf("address=%s", testcase.address), func(t *testing.T) {
			t.Run("nil", func(t *testing.T) {
				l, err := newLocalhostListener(testcase.address, nil)
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l.Close()
				if l.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l.URL.Scheme)
				}
				if l.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l.URL.Hostname())
				}
				t.Logf("URL is %s", l.URL.String())
			})

			t.Run("empty", func(t *testing.T) {
				l, err := newLocalhostListener(testcase.address, []int{})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l.Close()
				if l.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l.URL.Scheme)
				}
				if l.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l.URL.Hostname())
				}
				t.Logf("URL is %s", l.URL.String())
			})

			t.Run("singlePort", func(t *testing.T) {
				l, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l.Close()
				if l.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l.URL.Scheme)
				}
				if l.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l.URL.Hostname())
				}
				if l.URL.Port() != "9000" {
					t.Errorf("Port wants 9000 but was %s", l.URL.Port())
				}
			})

			t.Run("multiplePortFallback", func(t *testing.T) {
				l1, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l1.Close()
				if l1.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l1.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l1.URL.Scheme)
				}
				if l1.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l1.URL.Hostname())
				}
				if l1.URL.Port() != "9000" {
					t.Errorf("Port wants 9000 but was %s", l1.URL.Port())
				}

				l2, err := newLocalhostListener(testcase.address, []int{9000, 9001})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l2.Close()
				if l2.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l2.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l2.URL.Scheme)
				}
				if l2.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l2.URL.Hostname())
				}
				if l2.URL.Port() != "9001" {
					t.Errorf("Port wants 9001 but was %s", l2.URL.Port())
				}
			})

			t.Run("multiplePortFail", func(t *testing.T) {
				l1, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l1.Close()
				if l1.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l1.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l1.URL.Scheme)
				}
				if l1.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l1.URL.Hostname())
				}
				if l1.URL.Port() != "9000" {
					t.Errorf("Port wants 9000 but was %s", l1.URL.Port())
				}

				l2, err := newLocalhostListener(testcase.address, []int{9001})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l2.Close()
				if l2.URL == nil {
					t.Errorf("URL wants a URL but was nil")
				}
				if l2.URL.Scheme != "http" {
					t.Errorf("Scheme wants http but was %s", l2.URL.Scheme)
				}
				if l2.URL.Hostname() != "localhost" {
					t.Errorf("Hostname wants localhost but was %s", l2.URL.Hostname())
				}
				if l2.URL.Port() != "9001" {
					t.Errorf("Port wants 9001 but was %s", l2.URL.Port())
				}

				l3, err := newLocalhostListener(testcase.address, []int{9000, 9001})
				if err == nil {
					l3.Close()
					t.Fatalf("newLocalhostListener wants error but was nil")
				}
				t.Logf("expected error: %s", err)
			})
		})
	}
}
