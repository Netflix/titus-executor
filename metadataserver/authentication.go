package metadataserver

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/auth"
	"github.com/Netflix/titus-executor/metadataserver/metrics"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (ms *MetadataServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-aws-ec2-metadata-token")
		if !ms.tokenRequired && len(token) == 0 {
			metrics.PublishIncrementCounter("auth.skipped.count")
			next.ServeHTTP(w, r)
			return
		}

		auth := auth.JWTAuthenticator{Key: ms.tokenKey, Audience: ms.titusTaskInstanceID}
		remaining, err := auth.VerifyToken(token)
		if err != nil {
			log.Error("Token invalid: ", err)
			metrics.PublishIncrementCounter("auth.failed.count")
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		metrics.PublishIncrementCounter("auth.success.count")
		w.Header().Add("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", fmt.Sprintf("%v", remaining))
		next.ServeHTTP(w, r)
	})
}

func (ms *MetadataServer) createAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.createToken.count")

	forwarded := r.Header.Get("x-forwarded-for")
	if len(forwarded) > 0 {
		log.Error("`x-forwarded-for` header present, blocking request`")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	auth := auth.JWTAuthenticator{Key: ms.tokenKey, Audience: ms.titusTaskInstanceID}
	ttlStr := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")

	ttlSec, err := strconv.Atoi(ttlStr)
	if err != nil {
		log.Error("Could not decode ttl: ", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if ttlSec < 0 || ttlSec > 21600 {
		log.Error("Invalid ttl: ", ttlSec)
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	token, err := auth.GenerateToken(time.Duration(ttlSec) * time.Second)
	if err != nil {
		log.Error("Could not generate token: ", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		// Not a Hijacker, just treat it as a normal ResponseWriter
		if _, err := fmt.Fprint(w, token); err != nil {
			log.Error("Unable to write token: ", err)
		}
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Error("Unable to hijack connection: ", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
		p := ipv4.NewConn(conn)
		_ = p.SetTTL(1)
	}

	if conn.RemoteAddr().(*net.TCPAddr).IP.To16() != nil {
		p := ipv6.NewConn(conn)
		_ = p.SetHopLimit(1)
	}

	_, err = bufrw.Write([]byte(token))
	if err != nil {
		log.Error("Unable to write token: ", err)
	}

	bufrw.Flush()
}
