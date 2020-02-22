# oauth2cli example

This is an example application using oauth2cli.


## Getting Started

Setup your Google API access:

1. Open https://console.cloud.google.com/apis/credentials
1. Create an OAuth client ID where the application type is other.

Build and run the application:

```
% go build
% ./example -client-id xxx.apps.googleusercontent.com -client-secret xxxxxxxx
2019/10/03 00:01:35 Open http://localhost:53753
2019/10/03 00:01:40 You got a valid token until 2019-10-03 01:01:40.083238 +0900 JST m=+3604.526750517
```

It will automatically open the browser and you can log in to Google.

### Use a TLS certificate

You can set a certificate and key for the local server.

```sh
./example -client-id xxx.apps.googleusercontent.com -client-secret xxxxxxxx \
  -local-server-cert ../e2e_test/testdata/cert.pem -local-server-key ../e2e_test/testdata/cert-key.pem
```
