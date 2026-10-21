// Independent Node/nghttp2 decoding peer, unchanged between client variants.
const http2 = require('node:http2');
const fs = require('node:fs');
const expected = JSON.parse(fs.readFileSync(process.argv[3]))[process.argv[4]];
const server = http2.createServer({settings: {headerTableSize: 0, maxConcurrentStreams: 4096, maxHeaderListSize: 200000}});
let requests = 0, failures = 0, sessions = 0, closed = 0;
server.on('session', session => {
  sessions++;
  session.on('close', () => { closed++; console.log(JSON.stringify({requests, failures, sessions, closed})); });
});
server.on('sessionError', (e) => { failures++; console.error(e); });
server.on('stream', (stream, headers) => {
  let valid = headers[':method'] === 'GET' && headers[':path'] === '/' && headers[':scheme'] === 'http';
  const actual = Object.keys(headers).filter(k => !k.startsWith(':'));
  valid &&= actual.length === expected.length;
  for (const [key, value] of expected) {
    const got = key === 'set-cookie' ? headers[key]?.join('; ') : headers[key];
    valid &&= got === value;
  }
  if (!valid) failures++;
  requests++;
  stream.on('error', (e) => { failures++; console.error(e); });
  stream.respond({':status': valid ? 200 : 400, 'content-length': '13', 'content-type': 'text/plain'});
  stream.end('Hello, World!');
});
process.on('SIGTERM', () => { console.log(JSON.stringify({requests, failures, sessions, closed})); process.exit(failures ? 1 : 0); });
server.listen(Number(process.argv[2]), '127.0.0.1', () => console.log('ready'));
