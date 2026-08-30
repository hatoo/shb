// Node implements HTTP/2 itself rather than wrapping nghttp2, so this is a
// distinct decoder from every other server in the suite.
const http2 = require('node:http2');
const http = require('node:http');
const fs = require('node:fs');

const body = 'hello, world!';
const respond = (_req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(body);
};

http2.createSecureServer(
  { cert: fs.readFileSync('/conf/cert.pem'), key: fs.readFileSync('/conf/key.pem'), allowHTTP1: true },
  respond,
).listen(443);

// Cleartext h2c with prior knowledge, plus HTTP/1.1 on the same socket
http2.createServer(respond).listen(80);
http.createServer(respond).listen(8080);
