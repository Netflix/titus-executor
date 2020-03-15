package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
)

// Authenticator generates and authenticates tokens
type Authenticator struct {
	Signer *identity.Signer
}

type envelope struct {
	// Key key
	Key string

	// Expiration in nanoseconds
	Expiration int64
}

// GenerateToken generates a token
func (a *Authenticator) GenerateToken(ttl time.Duration) (string, error) {
	keyBytes := make([]byte, 64)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", err
	}

	key := base64.StdEncoding.EncodeToString(keyBytes)
	exp := time.Now().Add(ttl).UnixNano()
	env := envelope{Key: key, Expiration: exp}

	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	envEnc := base64.StdEncoding.EncodeToString(envJSON)

	sig, err := a.Signer.SignString([]byte(envEnc))
	if err != nil {
		return "", err
	}

	sigJSON, err := json.Marshal(sig)
	if err != nil {
		return "", err
	}
	sigEnc := base64.StdEncoding.EncodeToString(sigJSON)

	return envEnc + "." + sigEnc, nil
}

// VerifyToken verifies that a token is valid and not expired
func (a *Authenticator) VerifyToken(token string) bool {
	comps := strings.Split(token, ".")
	if len(comps) != 2 {
		return false
	}

	envEnc, sigEnc := comps[0], comps[1]
	sigStr, err := base64.StdEncoding.DecodeString(sigEnc)
	if err != nil {
		return false
	}

	sig := titus.CertificateStringSignature{}
	err = json.Unmarshal([]byte(sigStr), &sig)
	if err != nil {
		return false
	}

	if !identity.VerifyStringSig([]byte(envEnc), &sig) {
		return false
	}

	envStr, err := base64.StdEncoding.DecodeString(envEnc)
	if err != nil {
		return false
	}

	env := envelope{}
	err = json.Unmarshal([]byte(envStr), &env)
	if err != nil {
		return false
	}

	if time.Now().UnixNano() > env.Expiration {
		return false
	}

	return true
}
