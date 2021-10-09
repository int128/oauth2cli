package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var certPool = x509.NewCertPool()

func init() {
	data, err := ioutil.ReadFile("testdata/ca.crt")
	if err != nil {
		panic(err)
	}
	if !certPool.AppendCertsFromPEM(data) {
		panic("could not append certificate data")
	}
}

func Get(url string) (int, string, error) {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool}}}
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", fmt.Errorf("could not send a request: %w", err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("could not read response body: %w", err)
	}
	return resp.StatusCode, string(b), nil
}

func GetAndVerify(t *testing.T, url string, code int, body string) {
	gotCode, gotBody, err := Get(url)
	if err != nil {
		t.Errorf("could not open browser request: %s", err)
		return
	}
	if gotCode != code {
		t.Errorf("status wants %d but %d", code, gotCode)
	}
	if gotBody != body {
		t.Errorf("response body did not match: %s", cmp.Diff(gotBody, body))
	}
}
