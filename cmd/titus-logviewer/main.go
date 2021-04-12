package main

import (
	"crypto/tls"
	"net/http"

	log2 "github.com/Netflix/titus-executor/utils/log"
	titusTLS "github.com/Netflix/titus-executor/utils/tls"

	"github.com/Netflix/titus-executor/logviewer/api"
	"github.com/Netflix/titus-executor/logviewer/conf"
	log "github.com/sirupsen/logrus"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("pong")); err != nil {
		log.Error("Unable to respond with pong on ping handler: ", err)
	}
}

func listenOnHTTPSOptionally(r *http.ServeMux) {
	if conf.CertFile != "" && conf.KeyFile != "" {
		tlsConfig, err := getTLSConfig(conf.CertFile, conf.KeyFile)
		if err != nil {
			log.Fatal(err)
		}
		s := &http.Server{
			Addr:      ":8005",
			Handler:   r,
			TLSConfig: tlsConfig,
		}
		if err := s.ListenAndServeTLS("", ""); err != nil {
			log.Error("Error: HTTPS ListenAndServe: ", err)
		}
	} else {
		log.Print("TITUS_LOGVIEWER_CERT / TITUS_LOGVIEWER_KEY not set. Not serving HTTPS")
	}
}

func getTLSConfig(certificateFile string, privateKey string) (*tls.Config, error) {
	certLoader := &titusTLS.CachedCertificateLoader{
		CertPath: certificateFile,
		KeyPath:  privateKey,
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader.GetCertificate(tlsConfig.Time)
	}
	return tlsConfig, nil
}

func main() {
	log2.MaybeSetupLoggerIfOnJournaldAvailable()
	log.Println("Titus logviewer is starting")
	r := newMux()
	go listenOnHTTPSOptionally(r)
	if err := http.ListenAndServe(":8004", r); err != nil {
		log.Fatal("Error: HTTP ListenAndServe: ", err)
	}

}

func newMux() *http.ServeMux {
	r := http.NewServeMux()

	r.HandleFunc("/ping", pingHandler)

	if conf.ProxyMode {
		api.RegisterProxyHandlers(r)
		return r
	}

	api.RegisterHandlers(r)
	return r
}
