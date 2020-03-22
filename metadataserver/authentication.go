package metadataserver

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/auth"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (ms *MetadataServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-aws-ec2-metadata-token")
		if !ms.tokenRequired && len(token) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		auth := auth.JWTAuthenticator{Key: ms.tokenKey, Audience: ms.titusTaskInstanceID}
		valid, remaining := auth.VerifyToken(token)
		if !valid {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		w.Header().Add("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", fmt.Sprintf("%v", remaining))
		next.ServeHTTP(w, r)
	})
}

func (ms *MetadataServer) createAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Header.Get("x-forwarded-for")
	if len(forwarded) > 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	auth := auth.JWTAuthenticator{Key: ms.tokenKey, Audience: ms.titusTaskInstanceID}
	ttlStr := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")

	ttlSec, err := strconv.Atoi(ttlStr)
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	if ttlSec < 0 || ttlSec > 21600 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	token, err := auth.GenerateToken(time.Duration(ttlSec) * time.Second)
	if err != nil {
		// handle me
		panic(err)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
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

	_, _ = bufrw.Write([]byte(token))
	bufrw.Flush()
}
