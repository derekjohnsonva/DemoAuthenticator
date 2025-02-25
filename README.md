# Demo Authentication App

## To Run

In order to run the project, use the commands

```shell
./gradlew build
./gradlew bootRun
./gradlew test
```

Okta Stuff

idp-id = 0oanj2pjxivnDLFrN5d7

<https://dev-50824006.okta.com/oauth2/v1/authorize?idp=0oanj2pjxivnDLFrN5d7&client_id=0oanj3bxeuT0fcQkD5d7&response_type=code&response_mode=fragment&scope=openid> profile email &redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthorization-code%2Fcallback&state=M6D&nonce=YsG76jo

curl -X POST <https://dev-50824006.okta.com/oauth2/v1/token> \
 -d "grant_type=authorization_code" \
 -d "code=yZWk7H8PQeBF_SHdPfWObQltDX415-KVgbF4L8iezMe8iFXeS8DLLiPgIn88N9QxBgWuUeUY4Uz2hYKKrit2TGfYxrtHaT9lol_Ixkx1Nmvfny9CCqJMd_jjXUauxKn1" \
 -d "redirect_uri=<https://dev-50824006.okta.com/oauth2/v1/authorize/callback>" \
 -d "client_id=0oanj3bxeuT0fcQkD5d7" \
 -d "client_secret=x8teF5RY5EudYBRe5m6Hm21Pqqb15VdqeuJrXorESdcNhH2Z2ytFRvi7gQhr74k5"
