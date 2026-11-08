// Command tunnelecho stands in for the egress proxy in container tests, echoing each tunnel
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/bugnet-sh/bugnet-run/internal/wsframe"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: tunnelecho CERT KEY LISTEN")
		os.Exit(2)
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srv := &http.Server{
		Addr: os.Args[3],
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
		},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/tunnel" ||
				!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer bnt_") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			c, err := wsframe.Accept(w, r, "bugnet-tunnel.v1")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}),
	}
	fmt.Fprintln(os.Stderr, srv.ListenAndServeTLS("", ""))
	os.Exit(1)
}
