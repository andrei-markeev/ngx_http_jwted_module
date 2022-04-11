## Keys generation

```bash
openssl genpkey -algorithm ed25519 -outform PEM -out test.pem
openssl pkey -in test/test.pem -noout -text_pub | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64  # put to nginx.conf
```

This will also produce `test.pem`, which is used for signing.

## Create a signed EdDSA JWT token

With Javascript:

```js
var jose = require("jose");
var fs = require("fs");
const pk = fs.readFileSync("test.pem", "utf-8");
const privateKey = await jose.importPKCS8(pk, "EdDSA");
const jwt = await new jose.SignJWT({"sub":"test","exp":1649637133})
  .setProtectedHeader({ alg: 'EdDSA', crv:"Ed25519", typ:"JWT" })
  .sign(privateKey);

console.log(jwt)
```

Alternatively, with OpenSSL (v3.0+ required, openresty ships with v1.1.1):

```bash
echo -n '{"alg":"EdDSA","crv":"Ed25519","typ":"JWT"}' | base64 -w 0 | sed s/\+/-/ | sed -E s/=+$/./ > jwt
echo -n '{"sub":"test","exp":1649637133}' | base64 -w 0 | sed s/\+/-/ | sed -E s/=+$// >> jwt
openssl pkeyutl -sign -inkey test.pem -out sig.dat -rawin -in jwt
```

### How to test

```bash
# put the real token instead of X.Y.Z
curl -H "Authorization: Bearer X.Y.Z" localhost/protected
```