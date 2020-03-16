package auth

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/identity"
	jwt "github.com/dgrijalva/jwt-go"
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

// JWTAuthenticator authenticates using JWT
type JWTAuthenticator struct {
	Key []byte
}

// GenerateToken token
func (a *JWTAuthenticator) GenerateToken(ttl time.Duration) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.Key)
}

// VerifyToken verifes a token
func (a *JWTAuthenticator) VerifyToken(token string) (bool, int64) {
	var claims jwt.StandardClaims
	jwtToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.Key, nil
	})

	if err != nil {
		return false, 0
	}

	if jwtToken.Valid && jwtToken.Claims.Valid() != nil {
		return false, 0
	}

	remaining := time.Until(time.Unix(claims.ExpiresAt, 0))
	return true, int64(remaining.Seconds())
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
	exp := time.Now().Add(ttl).Unix()
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
func (a *CertificateAuthenticator) VerifyToken(token string) (bool, int64) {
	comps := strings.Split(token, ".")
	if len(comps) != 2 {
		return false, 0
	}

	envEnc, sigEnc := comps[0], comps[1]
	sig, err := base64.StdEncoding.DecodeString(sigEnc)
	if err != nil {
		return false, 0
	}

	pub := a.Signer.Certificate.PrivateKey.(crypto.Signer).Public()
	if !identity.VerifyWithPublicKey([]byte(envEnc), pub, sig) {
		return false, 0
	}

	envStr, err := base64.StdEncoding.DecodeString(envEnc)
	if err != nil {
		return false, 0
	}

	env := envelope{}
	err = json.Unmarshal(envStr, &env)
	if err != nil {
		return false, 0
	}

	if time.Now().Unix() > env.Expiration {
		return false, 0
	}
	remaining := time.Until(time.Unix(env.Expiration, 0))
	return true, int64(remaining.Seconds())
}
