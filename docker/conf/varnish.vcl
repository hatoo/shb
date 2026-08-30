vcl 4.1;
# Varnish is a cache, but it can answer on its own: this needs no backend
backend default none;
sub vcl_recv {
    return (synth(200));
}
sub vcl_synth {
    set resp.http.Content-Type = "text/plain";
    set resp.body = "hello, world!";
    return (deliver);
}
