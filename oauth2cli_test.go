package oauth2cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestConfig_populateDeprecatedFields(t *testing.T) {
	t.Run("DefaultValue", func(t *testing.T) {
		var cfg Config
		cfg.populateDeprecatedFields()
		var want []string
		if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
			t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SinglePort", func(t *testing.T) {
		cfg := Config{
			LocalServerPort: []int{8000},
		}
		cfg.populateDeprecatedFields()
		want := []string{":8000"}
		if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
			t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("SinglePortWithAddress", func(t *testing.T) {
		cfg := Config{
			LocalServerAddress: "127.0.0.1",
			LocalServerPort:    []int{8000},
		}
		cfg.populateDeprecatedFields()
		want := []string{"127.0.0.1:8000"}
		if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
			t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("MultiplePort", func(t *testing.T) {
		cfg := Config{
			LocalServerPort: []int{8000, 18000},
		}
		cfg.populateDeprecatedFields()
		want := []string{":8000", ":18000"}
		if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
			t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("MultiplePortWithAddress", func(t *testing.T) {
		cfg := Config{
			LocalServerAddress: "127.0.0.1",
			LocalServerPort:    []int{8000, 18000},
		}
		cfg.populateDeprecatedFields()
		want := []string{"127.0.0.1:8000", "127.0.0.1:18000"}
		if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
			t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("PreserveOriginalValue", func(t *testing.T) {
		t.Run("DefaultValue", func(t *testing.T) {
			cfg := Config{
				LocalServerBindAddress: []string{"127.0.0.1:10000"},
			}
			cfg.populateDeprecatedFields()
			want := []string{"127.0.0.1:10000"}
			if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
				t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
			}
		})

		t.Run("SinglePort", func(t *testing.T) {
			cfg := Config{
				LocalServerBindAddress: []string{"127.0.0.1:10000"},
				LocalServerPort:        []int{8000},
			}
			cfg.populateDeprecatedFields()
			want := []string{"127.0.0.1:10000", ":8000"}
			if diff := cmp.Diff(want, cfg.LocalServerBindAddress); diff != "" {
				t.Errorf("LocalServerBindAddress mismatch (-want +got):\n%s", diff)
			}
		})
	})
}
