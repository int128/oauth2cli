# oauth2cli example

This is an example application using oauth2cli.


## Getting Started

Setup your API access:

1. Open https://console.cloud.google.com/apis/credentials
1. Create an OAuth client ID where the application type is other.

Set the environment variables:

```sh
export GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=xxx
```

Run the application:

```
% go run main.go
2019/05/15 09:39:16 Open http://localhost:58806
2019/05/15 09:39:26 Got a token: &{AccessToken:... TokenType:Bearer RefreshToken:... scope:https://www.googleapis.com/auth/userinfo.email openid token_type:Bearer]}
2019/05/15 09:39:26 Your token is valid until 2019-05-15 10:39:26.720292 +0900 JST m=+3609.800317611
```

It will automatically open the browser and you can log in to Google.
