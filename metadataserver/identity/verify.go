package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

// Verify verify
func Verify(data []byte, sig *titus.CertificateSignature) bool {

	hash := crypto.SHA512
	hashed := computeHash(hash, data)

	cert, err := loadCert(sig)
	if err != nil {
		return false
	}

	switch sig.GetAlgorithm() {
	case titus.SignatureAlgorithm_SHA512withRSAandMGF1:
		return verifyRSA(hashed, hash, cert, sig)
	case titus.SignatureAlgorithm_SHA512withECDSA:
		return verifyECDSA(hashed, hash, cert, sig)
	}

	return false
}

func computeHash(hash crypto.Hash, data []byte) []byte {
	state := hash.New()
	if _, err := state.Write(data); err != nil {
		return nil
	}

	return state.Sum(nil)
}

func loadCert(sig *titus.CertificateSignature) (*x509.Certificate, error) {
	certBytes := sig.GetCertChain()
	if len(certBytes) == 0 {
		return nil, fmt.Errorf("invalid cert chain")
	}

	return x509.ParseCertificate(certBytes[0])
}

func verifyRSA(hashed []byte, hash crypto.Hash, cert *x509.Certificate, sig *titus.CertificateSignature) bool {

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	opts := &rsa.PSSOptions{
		Hash:       hash,
		SaltLength: saltLength,
	}
	err := rsa.VerifyPSS(pub, crypto.SHA512, hashed, sig.GetSignature(), opts)

	return err == nil
}

func verifyECDSA(hashed []byte, hash crypto.Hash, cert *x509.Certificate, sig *titus.CertificateSignature) bool {
	certBytes := sig.GetCertChain()
	if len(certBytes) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(certBytes[0])
	if err != nil {
		fmt.Println(err)
		return false
	}

	pub, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	ecdsaSig := struct{ R, S *big.Int }{}
	_, err = asn1.Unmarshal(sig.GetSignature(), &ecdsaSig)
	if err != nil {
		return false
	}

	return ecdsa.Verify(pub, hashed, ecdsaSig.R, ecdsaSig.S)
}
