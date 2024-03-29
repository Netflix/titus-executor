package tls

import (
	"crypto/tls"
	"sync"
	"time"
)

type CachedCertificateLoader struct {
	CertPath    string
	KeyPath     string
	certificate *tls.Certificate
	nextReload  time.Time
	lock        sync.Mutex
}

// Get Certificate uses the cachedCertificateLoader struct
// to automatically reload the certificate from disk every hour
func (c *CachedCertificateLoader) GetCertificate(nowFunc func() time.Time) (*tls.Certificate, error) {
	var now time.Time
	if nowFunc == nil {
		now = time.Now()
	} else {
		now = nowFunc()
	}
	if now.After(c.nextReload) {
		c.lock.Lock()
		defer c.lock.Unlock()
		cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
		if err != nil {
			return nil, err
		}
		c.certificate = &cert
		c.nextReload = now.Add(1 * time.Hour)
	}
	return c.certificate, nil
}
