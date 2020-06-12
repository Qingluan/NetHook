package dnspack

import (
	"log"
	"net"
	"net/http"

	"flag"
	"os"
)

var dnsCachePath = flag.String("dnsCachee", os.TempDir(), "dns storage dir")

var listenIP = flag.String("listenip", "223.5.5.5", "dns forward ip")
var listenPort = flag.Int("listenport", 53, "dns forward port")

func StartServer() {
	flag.Parse()
	if err := os.MkdirAll(*dnsCachePath, 0666); err != nil {
		log.Println("create rwdirpath: %v error: %v", *dnsCachePath, err)
		return
	}
	log.Println("starting rind")
	dns := Start(*dnsCachePath, []net.UDPAddr{{IP: net.ParseIP(*listenIP), Port: *listenPort}})
	rest := RestService{Dn: dns}

	dnsHandler := func() http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				rest.Create(w, r)
			case http.MethodGet:
				rest.Read(w, r)
			case http.MethodPut:
				rest.Update(w, r)
			case http.MethodDelete:
				rest.Delete(w, r)
			}
		}
	}

	withAuth := func(h http.HandlerFunc) http.HandlerFunc {
		// authentication intercepting
		var _ = "intercept"
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r)
		}
	}

	http.Handle("/dns", withAuth(dnsHandler()))
	log.Fatal(http.ListenAndServe(":80", nil))
}
