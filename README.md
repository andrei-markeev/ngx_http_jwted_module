# Nginx JWT validation with Ed25519

EdDSA algorithms are faster and more secure than traditional RSA and ESA.
This module uses OpenSSL implementation of Ed25519 algorithm for verifying JWT Bearer tokens from Authorization header.

## Compiling with Nginx

```bash
./configure --with-http_ssl_module --add-module=../ngx_http_auth_jwted_module
```

## Configuration

Example Nginx configuration:

```nginx
worker_processes 1;

events {
    worker_connections 768;
}

http {
    server {
        listen 127.0.0.1:80;
        server_name localhost;

        # This is a public key which will be used for verifying the JWT token
        auth_jwt_key 'Base64EncodedPublicKey==';

        location = /protected {
            # This location is protected
            auth_jwt on;
            content_by_lua_block {
                ngx.say('Protected endpoint')
            }
        }
    }
}
```

## How to generate keys and create JWT tokens

See [test/README.md](test/README.md).

## Claims verification

This module exposes claims part of the token in variable `$jwt_claims`. It doesn't parse the JSON and it doesn't verify any claims itself.

For example, for this location:
```nginx
location = /show-claims {
    auth_jwt on;
    content_by_lua_block {
        ngx.say('JWT claims: ' .. ngx.var.jwt_claims)
    }
}
```

It might show something like this:
```bash
$ curl -H "Authorization: Bearer $TOKEN" localhost/show-claims

JWT claims: {"sub":"test","exp":1649637133}
```

So if you want to check `exp`, you can do it like this:

```lua
local cjson = require("cjson")
local claims = cjson.decode(ngx.var.jwt_claims)

if (claims.exp < ngx.now()) then
    ngx.say("Token expired!")
    ngx.exit(ngx.HTTP_OK)
end
```

_Note_: JWT parsing works in access phase, so `$jwt_claims` variable is only available after that.

## Directives

### auth_jwt

**syntax**: _auth_jwt on|off_

**default**: _auth_jwt off_

**context**: location

Turns on JWT protection for the specific location.

Bearer-token from `Authorization` header will be verified against the public key specified by `auth_jwt_key` directive.
Verification of the token happens during access [phase](http://nginx.org/en/docs/dev/development_guide.html#http_phases).

If the public key was not specified, `401 Authorization Required` will be returned and the following error will be logged:

```
Public key was not specified! Please use `auth_jwt_key`
```

If the `Authorization` header is empty, contains invalid JWT token or the signature verification has failed, `401 Authorization Required` will be returned.

**Note**: This library doesn't parse the token payload and doesn't perform any claims checks, it only puts the claims JSON into `$jwt_claims` variable. For example, it doesn't validate `exp` claim, you have to do it yourself if needed.

**Note 2**: Only **EdDSA** algorithm with _Ed25519_ curve is supported and also enforced, value of `alg` specified in the header is ignored.

### auth_jwt_key

**syntax**: _auth_jwt_key '**(public-key-in-base64)**'_

**context**: http, server, location

Specifies public key to be used for JWT token verification. The JWT token should be signed by the corresponding private key.

If you have a private key in PEM format (i.e. starting with `-----BEGIN PRIVATE KEY-----`), you can generate a public key in the right format with the following command:

```bash
openssl pkey -in private_key.pem -noout -text_pub | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64
```

Notice that using a key encoded in DER ASN.1 format (i.e. starting with `-----BEGIN PUBLIC KEY-----`) is **not supported** with this directive. You need to use the _value_ of the public key, and encode it in _base64_ (it is often encoded in _hex_ format).


## Contributions

Contributions are welcome, however, it would be great to keep this module small, efficient and with no external dependencies 🙏.
Thank you!
