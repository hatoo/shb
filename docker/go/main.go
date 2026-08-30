// Go implements HTTP/2 in the standard library rather than binding a C
// library, which makes it another independent decoder to answer to.
package main

import (
	"log"
	"net/http"
)

func main() {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello, world!"))
	})
	go func() { log.Fatal(http.ListenAndServe(":80", h)) }()
	// net/http negotiates h2 through ALPN when it serves TLS
	log.Fatal(http.ListenAndServeTLS(":443", "/conf/cert.pem", "/conf/key.pem", h))
}
