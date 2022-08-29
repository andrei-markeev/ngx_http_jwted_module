# Nginx JWT validation with Ed25519

EdDSA algorithms are fast and more secure than traditional RSA and ESA.
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

_Note_: even though Lua blocks are used in most configuration examples, this module is not dependent on Openresty.
You can use it with a bare Nginx as well.

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

## Token cache

Typically, JWT token is valid for at least one hour, so if we enable token caching, it can dramatically improve the verification performance in most real-world scenarios.

You can enable the caching by using `auth_jwt_cache` directive:

```nginx
http {
    auth_jwt_cache on;
    auth_jwt_key 'Base64EncodedPublicKey==';

    server {
        listen 127.0.0.1:80;
        server_name localhost;

        location = /admin {
            auth_jwt on;
            content_by_lua_block {
                ngx.say('Welcome to Admin area!')
            }
        }
    }
}
```

By default, 256KB of memory will be used for caching.
How many tokens it will fit into the cache, depends on how big your token is.

For example, for this header and payload:
```
Header: {"alg":"EdDSA","crv":"Ed25519","typ":"JWT"}
Payload: {"sub":"12345678-abcd-1234-dcba-1234567890ab","exp":1651000000000,"iss":"https://www.test.com"}
```

The token size will be 273 bytes, and we have to round that up to nearest power of 2 (in this case, to 512 bytes) because of Nginx memory allocation rules, so 256Kb will fit approximately 512 tokens of 512 bytes each. Usually you should calculate the size of the cache according to the expected amount of the logged in users.

You can modify cache settings by using `auth_jwt_cache` directive parameter `size`:

```nginx
auth_jwt_cache on size=1m;
```

## Directives

### auth_jwt

**syntax**: _auth_jwt on|**(expression)**|off_

**default**: _auth_jwt off_

**context**: location

Turns on JWT protection for the specific location.

If "on" value is provided, Bearer-token from `Authorization` header is used, otherwise, the token is  by evaluating the ***expression*** at the time of handling the request. For example, in order to get the token from `auth` cookie, use

```nginx
auth_jwt $cookie_auth;
```

Token will be verified against the public key specified by `auth_jwt_key` directive.
Verification of the token happens during the access [phase](http://nginx.org/en/docs/dev/development_guide.html#http_phases).

If the public key was not specified, `401 Authorization Required` will be returned and the following error will be logged:

```
Public key was not specified! Please use `auth_jwt_key`
```

If the `Authorization` header (or the value specified by ***expression***) is empty, contains invalid JWT token, or if the signature verification has failed, `401 Authorization Required` will be returned.

**Note**: This library doesn't parse the token payload and doesn't perform any claims checks, it only puts the claims JSON into `$jwt_claims` variable. For example, it doesn't validate `exp` claim, you have to do it yourself if needed.

**Note 2**: Only **EdDSA** algorithm with _Ed25519_ curve is currently supported and also enforced, value of `alg` specified in the header is ignored.

### auth_jwt_key

**syntax**: _auth_jwt_key '**(public-key-in-base64)**'_

**context**: http, server, location

Specifies public key to be used for JWT token verification. The JWT token should be signed by the corresponding private key.

If you have a private key in PEM format (i.e. starting with `-----BEGIN PRIVATE KEY-----`), you can generate a public key in the right format with the following command:

```bash
openssl pkey -in private_key.pem -noout -text_pub | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64
```

Notice that using a key encoded in DER ASN.1 format (i.e. starting with `-----BEGIN PUBLIC KEY-----`) is **not supported** with this directive. You need to use the _value_ of the public key, and encode it in _base64_ (it is often encoded in _hex_ format).

### auth_jwt_cache

**syntax**: _auth_jwt_cache on|off [size=**(size-in-bytes)**]_

**default**: _auth_jwt off size=256k_

**context**: http

Configures the token cache. If enabled, bearer tokens that were extracted from `Authorization` header, will be cached in order to improve verification performance.

`size` parameter specifies, how much memory will be used for cache in bytes. You can use `k` and `m` prefixes for convenience, e.g. `1k` = `1000` bytes. `size` must be more or equal to the size of one memory page, which is usually `4096` bytes.

**Note**: In addition to the requested `size`, at least 4 pages of memory (i.e. 16Kb) will be allocated because of the data structures overhead.

**Note 2**: At this point, only valid tokens are cached.

## Contributions

Contributions are welcome, however, it would be great to keep this module small, efficient and with no external dependencies 🙏.
Thank you!
