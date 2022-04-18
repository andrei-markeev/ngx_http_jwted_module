## Keys generation

```bash
openssl genpkey -algorithm ed25519 -outform PEM -out test.pem
openssl pkey -in test.pem -noout -text_pub | sed 1,2d | tr -d '\n\r :' | xxd -r -p | base64
```

First command will produce `test.pem`, which is used for signing.

The second command will output the base64-encoded public key which you can use with `auth_jwt_key` directive.

## Create a signed EdDSA JWT token

Once you have the private key (generated to the `test.pem` file), you can create a signed JWT token.

With Node.js (e.g. you can use [Node.js online REPL](https://replit.com/languages/nodejs)):
```js
var crypto = require("crypto");

const pk = `-----BEGIN PRIVATE KEY-----
MC4...OfOt
-----END PRIVATE KEY-----
`;

const privateKey = crypto.createPrivateKey({key: pk});

const header = '{"alg":"EdDSA","crv":"Ed25519","typ":"JWT"}';
const claims = '{"sub":"test","exp":1649637133}';

const headerB64 = Buffer.from(header).toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]*$/,"");
const claimsB64 = Buffer.from(claims).toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]*$/,"");

const payload = headerB64 + "." + claimsB64;

const signature = crypto.sign(null, Buffer.from(payload), privateKey);

const signatureB64 = Buffer.from(signature).toString("base64").replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]*$/,"");

console.log(payload + "." + signatureB64);
```

Alternatively, you can use [jose](https://github.com/panva/jose) JWT library:

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

Alternatively, you can also generate the token with OpenSSL from command line

**Note**: OpenSSL v3.0+ required, at the time of writing openresty ships with v1.1.1, so it won't work.

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