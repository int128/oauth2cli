package implicit

import (
	"net/url"
	"reflect"
	"testing"

	types "github.com/int128/oauth2cli/implicit"
)

func Test_localServerHandler_redirectURL(t *testing.T) {
	type fields struct {
		config        *types.ServerConfig
		nonce         string
		state         string
		responseTypes []string
	}
	tests := []struct {
		name   string
		fields fields
		vals   url.Values
	}{
		{
			"with redirect field",
			fields{
				config: &types.ServerConfig{Config: types.Config{
					ClientID:    "foo-client",
					RedirectURL: "https://localhost:8080/foo/bar",
					AuthURL:     "https://auth.local:334/oauth-bar",
					Scopes:      []string{"openid"},
				}},
				state:         "some-state",
				nonce:         "some-nonce",
				responseTypes: []string{"token", "id_token"},
			},
			url.Values{
				"client_id":     {"foo-client"},
				"redirect_uri":  {"https://localhost:8080/foo/bar"},
				"response_type": {"token id_token"},
				"state":         {"some-state"},
				"nonce":         {"some-nonce"},
				"scope":         {"openid"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &localServerHandler{
				config:        tt.fields.config,
				nonce:         tt.fields.nonce,
				state:         tt.fields.state,
				responseTypes: tt.fields.responseTypes,
			}
			u, err := url.Parse(h.redirectURL())
			if err != nil {
				t.Errorf("error when parsing url %v", err)
			}

			exected, err := url.Parse("https://auth.local:334/oauth-bar")
			if err != nil {
				t.Errorf("error when parsing url %v", err)
			}

			exected.RawQuery = tt.vals.Encode()

			if !reflect.DeepEqual(u, exected) {
				t.Errorf("expected url\n%+v but was\n%+v", exected, u)
			}
		})
	}
}
