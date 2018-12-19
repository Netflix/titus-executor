package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	// Matches java.security.spec.PSSParameterSpec.DEFAULT.getSaltLen()
	saltLength      = 20
	defaultCertPath = "/run/metatron/certificates"
)

// Signer signs bytes using an x509 cert / key pair: in practice, this is the client cert
type Signer struct {
	Algorithm   titus.SignatureAlgorithm
	Certificate tls.Certificate
	Hash        crypto.Hash
	SignerOpts  crypto.SignerOpts
	Signer      crypto.Signer
}

// NewDefaultSigner creates a signer with the default certificate path to the client cert
func NewDefaultSigner() (*Signer, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(defaultCertPath, "client.crt"), filepath.Join(defaultCertPath, "client.key"))
	if err != nil {
		return nil, err
	}

	return NewSigner(cert)
}

// NewSigner creates a new signer with the passed in TLS certificate
func NewSigner(cert tls.Certificate) (*Signer, error) {
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("Private key doesn't implement crypto.Signer: %#v", cert.PrivateKey)
	}

	var algo titus.SignatureAlgorithm
	hash := crypto.SHA512
	var opts crypto.SignerOpts

	switch signer.Public().(type) {
	case *rsa.PublicKey:
		algo = titus.SignatureAlgorithm_SHA512withRSAandMGF1
		opts = &rsa.PSSOptions{
			Hash:       hash,
			SaltLength: saltLength,
		}
	case *ecdsa.PublicKey:
		algo = titus.SignatureAlgorithm_SHA512withECDSA
		opts = hash
	default:
		return nil, fmt.Errorf("Unsupported private key type: %T", cert.PrivateKey)
	}

	newSigner := &Signer{
		Algorithm:   algo,
		Certificate: cert,
		Hash:        hash,
		Signer:      signer,
		SignerOpts:  opts,
	}

	return newSigner, nil
}

func (s *Signer) signBytes(data []byte) ([]byte, error) {
	state := s.Hash.New()
	if _, err := state.Write(data); err != nil {
		return nil, err
	}

	hashed := state.Sum(nil)
	return s.Signer.Sign(rand.Reader, hashed, s.SignerOpts)
}

// Sign signs the bytes, returning a CertificateSignature suitable for binary encoding
func (s *Signer) Sign(data []byte) (*titus.CertificateSignature, error) {
	signed, err := s.signBytes(data)
	if err != nil {
		return nil, err
	}

	sig := &titus.CertificateSignature{
		Signature: signed,
		Algorithm: &s.Algorithm,
		CertChain: s.Certificate.Certificate,
	}

	return sig, nil
}

// SignString signs the bytes, returning a CertificateStringSignature suitable for JSON encoding
func (s *Signer) SignString(data []byte) (*titus.CertificateStringSignature, error) {
	signed, err := s.signBytes(data)
	if err != nil {
		return nil, err
	}

	b64Sig := base64.StdEncoding.EncodeToString(signed)
	var certChain []string
	for _, cert := range s.Certificate.Certificate {
		b64Cert := base64.StdEncoding.EncodeToString(cert)
		certChain = append(certChain, b64Cert)
	}

	sig := &titus.CertificateStringSignature{
		Signature: &b64Sig,
		Algorithm: &s.Algorithm,
		CertChain: certChain,
	}

	return sig, nil
}
