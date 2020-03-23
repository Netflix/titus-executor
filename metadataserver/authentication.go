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
			log.WithError(err).Error("Token invalid")
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
		log.WithField("xForwardedFor", forwarded).Error("x-forwarded-for header present, blocking request")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	auth := auth.JWTAuthenticator{Key: ms.tokenKey, Audience: ms.titusTaskInstanceID}
	ttlStr := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")

	ttlSec, err := strconv.Atoi(ttlStr)
	if err != nil {
		log.WithError(err).Error("Could not decode ttl")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if ttlSec < 0 || ttlSec > int((6*time.Hour).Seconds()) {
		log.WithField("tokenTTL", ttlSec).Error("Invalid ttl")
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	token, err := auth.GenerateToken(time.Duration(ttlSec) * time.Second)
	if err != nil {
		log.WithError(err).Error("Could not generate token")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		// Not a Hijacker, just treat it as a normal ResponseWriter
		if _, err := fmt.Fprint(w, token); err != nil {
			log.WithError(err).Error("Unable to write token")
		}
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.WithError(err).Error("Unable to hijack connection")
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
		p := ipv4.NewConn(conn)
		_ = p.SetTTL(1)
	} else if conn.RemoteAddr().(*net.TCPAddr).IP.To16() != nil {
		p := ipv6.NewConn(conn)
		_ = p.SetHopLimit(1)
	} else {
		log.Warn("Could not determine connection protocol type to set packet TTL")
	}

	httpResHeader := fmt.Sprintf(tokenHTTPResponseHeaderFormatString, ttlStr, len([]byte(token)))
	_, err = bufrw.Write([]byte(httpResHeader))
	if err != nil {
		log.WithError(err).Error("Unable to write token HTTP response headers")
	}

	_, err = bufrw.Write([]byte(token))
	if err != nil {
		log.WithError(err).Error("Unable to write token")
	}

	bufrw.Flush()
}

// nolint: gosec
const tokenHTTPResponseHeaderFormatString = `HTTP/1.1 200 OK
Accept-Ranges: none
Server: EC2ws
Connection: close
X-aws-ec2-metadata-token-ttl-seconds: %v
Content-Length: %v

`
