// Bun's own HTTP/1.1, HTTP/2 and HTTP/3
//
// Bun.serve's `http2: true` is documented but negotiates no ALPN at all in
// 1.4.0 - openssl sees none and curl falls back - so HTTP/2 comes from
// node:http2, which Bun implements itself and which does negotiate. Both are
// Bun's code either way. `http3: true` works as documented.
const tls = { cert: Bun.file("/certs/cert.pem"), key: Bun.file("/certs/key.pem") };
const body = "hello, world!";

Bun.serve({
  port: 443,
  tls,
  http3: true,
  fetch: () => new Response(body, { headers: { "content-type": "text/plain" } }),
});

const http2 = require("node:http2");
const fs = require("node:fs");
http2
  .createSecureServer(
    {
      cert: fs.readFileSync("/certs/cert.pem"),
      key: fs.readFileSync("/certs/key.pem"),
      allowHTTP1: true,
    },
    (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(body);
    },
  )
  .listen(8443);

Bun.serve({ port: 8080, fetch: () => new Response(body) });
console.log("bun: 443 tls/h3, 8443 tls/h2, 8080 cleartext");
