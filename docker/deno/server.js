// Deno's HTTP server, which is hyper underneath. HTTP/2 is not in the
// Deno.serve documentation but is there: it negotiates h2 through ALPN over
// TLS, and takes the HTTP/2 preface on a cleartext socket. There is no
// HTTP/3 - Deno's QUIC API is raw transport with no HTTP/3 layer over it.
const body = "hello, world!";
const respond = () =>
  new Response(body, { headers: { "content-type": "text/plain" } });

Deno.serve(
  {
    port: 443,
    cert: Deno.readTextFileSync("/certs/cert.pem"),
    key: Deno.readTextFileSync("/certs/key.pem"),
    onListen: () => {},
  },
  respond,
);
Deno.serve({ port: 8080, onListen: () => {} }, respond);
console.log("deno: 443 tls, 8080 cleartext");
