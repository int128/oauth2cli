package internal

import (
	"net/http"
	"reflect"
	"testing"
)

func TestDefaultMiddleware(t *testing.T) {
	t.Run("same handler is returned", func(t *testing.T) {
		if got := DefaultMiddleware(http.DefaultServeMux); !reflect.DeepEqual(got, http.DefaultServeMux) {
			t.Errorf("DefaultMiddleware() = %v, want %v", got, http.DefaultServeMux)
		}
	})
}

func TestNewOAuth2State(t *testing.T) {
	t.Run("different results are returned", func(t *testing.T) {
		s1, err := NewOAuth2State()
		if err != nil {
			t.Errorf("unexpected error calling NewOAuth2State(): %v", err)
		}
		s2, err := NewOAuth2State()
		if err != nil {
			t.Errorf("unexpected error calling NewOAuth2State(): %v", err)
		}

		if s1 == s2 {
			t.Errorf("DefaultMiddleware() returned the same value on different invocations: %q", s1)
		}
	})
}

func TestExpandAddresses(t *testing.T) {
	type args struct {
		address string
		ports   []int
	}

	tests := []struct {
		name          string
		args          args
		wantAddresses []string
	}{
		{"one port", args{"0.0.0.0", []int{80}}, []string{"0.0.0.0:80"}},
		{"multiple ports port", args{"0.0.0.0", []int{80, 8080}}, []string{"0.0.0.0:80", "0.0.0.0:8080"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if gotAddresses := ExpandAddresses(tt.args.address, tt.args.ports); !reflect.DeepEqual(gotAddresses, tt.wantAddresses) {
				t.Errorf("ExpandAddresses() = %v, want %v", gotAddresses, tt.wantAddresses)
			}
		})
	}
}
