package auth

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// JWTAuthenticator authenticates using JWT
type JWTAuthenticator struct {
	Key      []byte
	Audience string
}

// GenerateToken token
func (a *JWTAuthenticator) GenerateToken(ttl time.Duration) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Audience:  a.Audience,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.Key)
}

// VerifyToken verifes a token
func (a *JWTAuthenticator) VerifyToken(token string) (bool, int64, error) {
	var claims jwt.StandardClaims
	jwtToken, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return a.Key, nil
	})

	if err != nil {
		return false, 0, errors.Wrap(err, "Token invalid")
	}

	if !jwtToken.Valid {
		return false, 0, errors.Wrap(err, "Token invalid")
	}

	if claims.Valid() != nil {
		return false, 0, errors.Wrap(err, "Token invalid")
	}

	if !claims.VerifyAudience(a.Audience, false) {
		return false, 0, errors.Wrap(err, "Token invalid")
	}

	remaining := time.Until(time.Unix(claims.ExpiresAt, 0))
	return true, int64(remaining.Seconds()), nil
}
