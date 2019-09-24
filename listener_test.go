package oauth2cli

import (
	"fmt"
	"strings"
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
				if l.URL.String() == "" {
					t.Errorf("URL wants a string but was empty")
				}
				if prefix := "http://localhost:"; !strings.HasPrefix(l.URL.String(), prefix) {
					t.Errorf("URL wants prefix `%s` but was not", prefix)
				}
				t.Logf("URL is %s", l.URL.String())
			})

			t.Run("empty", func(t *testing.T) {
				l, err := newLocalhostListener(testcase.address, []int{})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l.Close()
				if l.URL.String() == "" {
					t.Errorf("URL wants a string but was empty")
				}
				if prefix := "http://localhost:"; !strings.HasPrefix(l.URL.String(), prefix) {
					t.Errorf("URL wants prefix `%s` but was not", prefix)
				}
				t.Logf("URL is %s", l.URL.String())
			})

			t.Run("singlePort", func(t *testing.T) {
				l, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l.Close()
				if w := "http://localhost:9000"; l.URL.String() != w {
					t.Errorf("URL wants %s but was %s", w, l.URL.String())
				}
			})

			t.Run("multiplePortFallback", func(t *testing.T) {
				l1, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l1.Close()
				if w := "http://localhost:9000"; l1.URL.String() != w {
					t.Errorf("URL wants %s but was %s", w, l1.URL.String())
				}

				l2, err := newLocalhostListener(testcase.address, []int{9000, 9001})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l2.Close()
				if w := "http://localhost:9001"; l2.URL.String() != w {
					t.Errorf("URL wants %s but was %s", w, l2.URL.String())
				}
			})

			t.Run("multiplePortFail", func(t *testing.T) {
				l1, err := newLocalhostListener(testcase.address, []int{9000})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l1.Close()
				if w := "http://localhost:9000"; l1.URL.String() != w {
					t.Errorf("URL wants %s but was %s", w, l1.URL.String())
				}

				l2, err := newLocalhostListener(testcase.address, []int{9001})
				if err != nil {
					t.Fatalf("newLocalhostListener error: %s", err)
				}
				defer l2.Close()
				if w := "http://localhost:9001"; l2.URL.String() != w {
					t.Errorf("URL wants %s but was %s", w, l2.URL.String())
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
