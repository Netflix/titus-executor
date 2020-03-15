package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/identity"
)

// Authenticator generates and authenticates tokens
type Authenticator interface {
	GenerateToken(ttl time.Duration) (string, error)
	VerifyToken(token string) bool
}

type envelope struct {
	// Token token
	Token string

	// Expiration in nanoseconds
	Expiration int64
}

// HMACAuthenticator authenticates using hmac
type HMACAuthenticator struct {
	Key []byte
}

// GenerateToken token
func (a *HMACAuthenticator) GenerateToken(ttl time.Duration) (string, error) {
	tokenBytes := make([]byte, 16)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(tokenBytes)
	exp := time.Now().Add(ttl).UnixNano()
	env := envelope{Token: token, Expiration: exp}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	envEnc := base64.StdEncoding.EncodeToString(envJSON)
	mac := a.hmac(envEnc)
	sig := base64.StdEncoding.EncodeToString(mac)

	return envEnc + "." + sig, nil
}

func (a *HMACAuthenticator) hmac(item string) []byte {
	hmac := hmac.New(sha512.New, a.Key)
	hmac.Write([]byte(item))
	return hmac.Sum(nil)
}

// VerifyToken verifes a token
func (a *HMACAuthenticator) VerifyToken(token string) bool {
	comps := strings.Split(token, ".")
	if len(comps) != 2 {
		return false
	}

	envEnc, sigEnc := comps[0], comps[1]
	sig, err := base64.StdEncoding.DecodeString(sigEnc)
	if err != nil {
		return false
	}
	expectedSig := a.hmac(envEnc)

	if !hmac.Equal(sig, expectedSig) {
		return false
	}

	envStr, err := base64.StdEncoding.DecodeString(envEnc)
	if err != nil {
		return false
	}

	env := envelope{}
	err = json.Unmarshal(envStr, &env)
	if err != nil {
		return false
	}

	if time.Now().UnixNano() > env.Expiration {
		return false
	}

	return true
}

// CertificateAuthenticator generates and authenticates tokens
type CertificateAuthenticator struct {
	Signer *identity.Signer
}

// GenerateToken generates a token
func (a *CertificateAuthenticator) GenerateToken(ttl time.Duration) (string, error) {
	tokenBytes := make([]byte, 64)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(tokenBytes)
	exp := time.Now().Add(ttl).UnixNano()
	env := envelope{Token: token, Expiration: exp}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	envEnc := base64.StdEncoding.EncodeToString(envJSON)

	sig, err := a.Signer.SignString([]byte(envEnc))
	if err != nil {
		return "", err
	}

	return envEnc + "." + sig.GetSignature(), nil
}

// VerifyToken verifies that a token is valid and not expired
func (a *CertificateAuthenticator) VerifyToken(token string) bool {
	comps := strings.Split(token, ".")
	if len(comps) != 2 {
		return false
	}

	envEnc, sigEnc := comps[0], comps[1]
	sig, err := base64.StdEncoding.DecodeString(sigEnc)
	if err != nil {
		return false
	}

	pub := a.Signer.Certificate.PrivateKey.(crypto.Signer).Public()
	if !identity.VerifyWithPublicKey([]byte(envEnc), pub, sig) {
		return false
	}

	envStr, err := base64.StdEncoding.DecodeString(envEnc)
	if err != nil {
		return false
	}

	env := envelope{}
	err = json.Unmarshal(envStr, &env)
	if err != nil {
		return false
	}

	if time.Now().UnixNano() > env.Expiration {
		return false
	}

	return true
}
