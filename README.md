## Nginx JWT validation with Ed25519

EdDSA algorithms are faster and more secure than traditional RSA and ESA.
This module uses OpenSSL implementation of Ed25519 algorithm for verifying JWT Bearer tokens from Authorization header.

### Compiling with Nginx

```bash
./configure --with-http_ssl_module --add-module=../ngx_http_auth_jwted_module
```

### Configuration

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
        location = /hello {
            content_by_lua_block {
                ngx.say('Hello world!')
            }
        }
    }
}
```

How to generate keys and create JWT tokens: see [test/README.md](test/README.md).

### Claims verification

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

### Contributions

Contributions are welcome, however, it would be great to keep this module small, efficient and with no external dependencies 🙏.
Thank you!
