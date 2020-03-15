package metadataserver

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/auth"
	"golang.org/x/net/ipv4"
)

func (ms *MetadataServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-aws-ec2-metadata-token")
		if !ms.tokenRequired && len(token) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ms.signLock.RLock()
		signer := ms.signer
		ms.signLock.RUnlock()

		auth := auth.Authenticator{Signer: signer}
		if signer == nil || !auth.VerifyToken(token) {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (ms *MetadataServer) createAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	forwarded := r.Header.Get("x-forwarded-for")
	if len(forwarded) > 0 {
		http.Error(w, "", http.StatusForbidden)
		return
	}

	ms.signLock.RLock()
	signer := ms.signer
	ms.signLock.RUnlock()

	if signer == nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	auth := auth.Authenticator{Signer: signer}
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

	_, _ = bufrw.Write([]byte(token))
	bufrw.Flush()
}
