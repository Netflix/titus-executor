package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const defaultHash = crypto.SHA512

// VerifyStringSig verify
func VerifyStringSig(data []byte, sig *titus.CertificateStringSignature) bool {
	certChainSig := sig.GetCertChain()
	var certChain [][]byte
	for _, cert := range certChainSig {
		certBytes, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return false
		}

		certChain = append(certChain, certBytes)
	}

	cert, err := loadCert(certChain)
	if err != nil {
		return false
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.GetSignature())
	if err != nil {
		return false
	}

	return doVerify(data, sig.GetAlgorithm(), defaultHash, cert, sigBytes)
}

// Verify verify
func Verify(data []byte, sig *titus.CertificateSignature) bool {
	cert, err := loadCert(sig.GetCertChain())
	if err != nil {
		return false
	}

	return doVerify(data, sig.GetAlgorithm(), defaultHash, cert, sig.GetSignature())
}

func doVerify(data []byte, algo titus.SignatureAlgorithm, hash crypto.Hash, cert *x509.Certificate, sig []byte) bool {
	hashed := computeHash(hash, data)

	switch algo {
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

func loadCert(certChain [][]byte) (*x509.Certificate, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("invalid cert chain")
	}

	return x509.ParseCertificate(certChain[0])
}

func verifyRSA(hashed []byte, hash crypto.Hash, cert *x509.Certificate, sig []byte) bool {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	opts := &rsa.PSSOptions{
		Hash:       hash,
		SaltLength: saltLength,
	}
	err := rsa.VerifyPSS(pub, crypto.SHA512, hashed, sig, opts)

	return err == nil
}

func verifyECDSA(hashed []byte, hash crypto.Hash, cert *x509.Certificate, sig []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	ecdsaSig := struct{ R, S *big.Int }{}
	_, err := asn1.Unmarshal(sig, &ecdsaSig)
	if err != nil {
		return false
	}

	return ecdsa.Verify(pub, hashed, ecdsaSig.R, ecdsaSig.S)
}
