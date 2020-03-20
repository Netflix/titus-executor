package auth

import (
	"crypto/rand"
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestHMACAuthenticatorToken(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assert.NilError(t, err)

	auth := JWTAuthenticator{Key: key}

	token, err := auth.GenerateToken(60 * time.Second)
	assert.NilError(t, err)

	valid, remaining := auth.VerifyToken(token)
	assert.Assert(t, valid)
	assert.Assert(t, remaining > 58 && remaining < 60)
}

func TestHMACAuthenticatorExpiredToken(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assert.NilError(t, err)

	auth := JWTAuthenticator{Key: key}

	token, err := auth.GenerateToken(0)
	assert.NilError(t, err)

	time.Sleep(1 * time.Second)

	valid, _ := auth.VerifyToken(token)
	assert.Assert(t, !valid)
}
