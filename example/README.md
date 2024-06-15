# oauth2cli example

This is an example application using oauth2cli.

To build this application,

```sh
go build
```

## Google

Create your OAuth client.

1. Open https://console.cloud.google.com/apis/credentials
1. Create an OAuth client ID where the application type is other.

Run this application.

```sh
./example -client-id xxx.apps.googleusercontent.com -client-secret xxxxxxxx
```

```console
2019/10/03 00:01:35 Open http://localhost:53753
...
2019/10/03 00:01:40 You got a valid token until 2019-10-03 01:01:40.083238 +0900 JST m=+3604.526750517
```

It will automatically open the browser and you can log in to Google.

### Use a TLS certificate

You can set a certificate and key for the local server.

```sh
./example -client-id xxx.apps.googleusercontent.com -client-secret xxxxxxxx \
  -local-server-cert ../e2e_test/testdata/cert.pem -local-server-key ../e2e_test/testdata/cert-key.pem
```

## GitHub

Create your OAuth App.
Set the callback URL to `http://localhost`.

Run this application.

```sh
./example -auth-url https://github.com/login/oauth/authorize -token-url https://github.com/login/oauth/access_token -client-id xxxxxxxx -client-secret xxxxxxxx
```

```console
09:52:45.384489 main.go:84: Open http://localhost:61865
09:52:45.384507 server.go:36: oauth2cli: starting a server at 127.0.0.1:61865
09:52:45.491072 server.go:135: oauth2cli: sending redirect to https://github.com/login/oauth/authorize?client_id=...
```

You can set `-scopes` flag to request the scopes.
See https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps.

It will automatically open the browser and you can log in to GitHub.
