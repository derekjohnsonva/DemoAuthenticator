# Demo Authentication App

## To Run

In order to run the project, use the commands

```shell
./gradlew build
./gradlew bootRun
./gradlew test
```

## Okta Stuff

What have I done so far?

I created an application in Okta
It is calld `Basic Web App` and it has the following info

``` text
Client ID = 0oanj3bxeuT0fcQkD5d7
client secret = x8teF5RY5EudYBRe5m6Hm21Pqqb15VdqeuJrXorESdcNhH2Z2ytFRvi7gQhr74k5
type = web
grant type = authorization code and Refresh token
sign in redirect uri = http://localhost:5000/authorization-code/callback
sign out redirect uri = http://localhost:5000/logout
```

Next, I created an Identity Provider with the following info

``` text
name = SpringBootOIDC
IdP ID = 0oanj2pjxivnDLFrN5d7
Authroize URL = https://dev-50824006.okta.com/oauth2/v1/authorize?idp=0oanj2pjxivnDLFrN5d7&client_id={clientId}&response_type={responseType}&response_mode={responseMode}&scope={scopes}&redirect_uri={redirectUri}&state={state}&nonce={nonce}
Redirect URI = https://dev-50824006.okta.com/oauth2/v1/authorize/callback
scopes = email, openid, profile
Auth type = client secret
client ID = okta-client
client secret = okta-client-secret
```

One interesting thing about configuring the IDP is that you have to set https endpoints.
Since the server is running locally, I do not have https set up. To get around this, I
am using a service called ngrok to perform forwarding from my localhost to a random https
server that is managed by ngrok.

Right now, the IDP is configured to crete a new user using JIT if it can not find a user with the same
username.
It will assign the user to the `Demo Group`. This group is given access to `Basic Web App`

``` shell
https://dev-50824006.okta.com/oauth2/v1/authorize?idp=0oanj2pjxivnDLFrN5d7&client_id=0oanj3bxeuT0fcQkD5d7&response_type=code&response_mode=fragment&scope=openid%20profile%20email&redirect_uri=https%3A%2F%2F209f-73-143-30-151.ngrok-free.app%2Fauthorization-code%2Fcallback&state=1234s1t2a3t4e5&nonce=skjlkfds
```

on 2/26, I was able to get an access token using postman.
I needed to get an access token first and then could run this with the access token
The authorization: field is `base64(client_id:client_secret)`
Another weird thing that I needed to do to get this to work was to change the `ClientAuthenticationMethod` to `CLIENT_SECRET_BASIC`
There is some information on this [here](https://developer.okta.com/docs/api/openapi/okta-oauth/guides/client-auth/)

``` cURL
curl --location --request POST 'https://1606-73-143-30-151.ngrok-free.app/oauth2/token' \
--header 'Authorization: Basic b2t0YS1jbGllbnQ6b2t0YS1jbGllbnQtc2VjcmV0' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=7Cv44ZzuDUtcJ_AdRUoQpDbYYU_d5Yoe3yOB3_OFcQQRpFCIcNGe_xIQzWmLqufweC9mli9A5xYvUfsAxuxqRstI_IeWKoMGTuqinNN_ojp91YQLwtJqRmrcNhj1FJa0' \
--data-urlencode 'redirect_uri=https://dev-50824006.okta.com/oauth2/v1/authorize/callback'```

I got the following response

``` text
{"access_token":"eyJraWQiOiJjNDdhNDIzNi00ZjVlLTRjODMtODhmMy0wZmZmYTRiZDAyYTIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiYXVkIjoib2t0YS1jbGllbnQiLCJuYmYiOjE3NDA2MDIyOTQsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJpc3MiOiJodHRwOi8vY2NlYS03My0xNDMtMzAtMTUxLm5ncm9rLWZyZWUuYXBwIiwiZXhwIjoxNzQwNjAyNTk0LCJpYXQiOjE3NDA2MDIyOTQsImp0aSI6IjgwZWUyMDQ3LTc4ZWQtNGM1Mi1hYTM4LTU0MzUyODU1ZDNlNSJ9.jdxxZDXRsf_R7FpTezri5CWc6CvIuD1WpTgequ2jvfb-5RUSqxjjlxP3nxzIY_unaE4QZ9jLP85OzY1jPTqbPZiE5NSNNz3COppD2Urgkg5Ch3S5qMbZaW-mcNEtNXLKyvXfvTYuwTRpcD65J7aZ0LYsjAQwIhsPyVvdadzKfm9wc_eqKn2kUfCJYCN9QVXalmd1oWhPkpqUazWvhDwhLjfojC_TE-GAxoQzTAYHyA8cKwR3grrUQKifaL8GlqU0SOwjjjyfArlrKC_e5Wq13invGPRTALQvzVQdfoM0Tloo_-jot5wXyUA-3TDfPeTPzi8Ex_3K0RFx72KD-7tFrA","scope":"openid profile email","id_token":"eyJraWQiOiJjNDdhNDIzNi00ZjVlLTRjODMtODhmMy0wZmZmYTRiZDAyYTIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiYXVkIjoib2t0YS1jbGllbnQiLCJhenAiOiJva3RhLWNsaWVudCIsImF1dGhfdGltZSI6MTc0MDYwMjI3NSwiaXNzIjoiaHR0cDovL2NjZWEtNzMtMTQzLTMwLTE1MS5uZ3Jvay1mcmVlLmFwcCIsImV4cCI6MTc0MDYwNDA5NSwiaWF0IjoxNzQwNjAyMjk1LCJub25jZSI6ImlHMFFVN3JsWko5ZDlNa1JaMnJjaTJKMjFUMkJmcmtYIiwianRpIjoiNDkwNWQ5ZmYtOTNlYy00MmUzLThkYmUtNmFmNjIwYmU4MjVkIiwic2lkIjoiS1I5ZEhvQUkxTXVQYWRkdzZBZXVuaGZJcWVLVjVNY1NMci1vc1Z5amNBVSJ9.JmewQwEa8zvI8PwvlOt51Lh8jNvz8zdNCQz-I7ZmSlyxADYrVNkgwX978Qsd7Kmd5PAk4moPwfjmDISY9XaIxr_qnqgym56tnQE2VR19dHcjpQzR4Cr_MSbo88ESJv6mP3F8uO1Sw_bpdCgN3coK-p9IcZaby7B3_JvFcqhYmDxaoNnC8BO832eUCLqdSWvoPTxakCyVaHZPxxrBC0eX8i8HWhGWBvZ7wsSSEmALF5eObk0kbMwM07YFYSMd5aGyMpL0GWTxvp9Xf6GdbASberEOcRd6wnQPgbVHShPJOyGWarB1MH34wV3_JxABWnQilhjbZu6JqxhVXaNGNyBY4g","token_type":"Bearer","expires_in":299}
```
