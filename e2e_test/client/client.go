package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

var certPool = x509.NewCertPool()

func init() {
	data, err := ioutil.ReadFile("testdata/ca.pem")
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
