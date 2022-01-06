package token_manager

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTTokenManager struct {
	signingKey string
}

func NewJWTTokenManager(signingKey string) (*JWTTokenManager, error) {
	if signingKey == "" {
		return nil, errors.New("Empty signing key!")
	}

	return &JWTTokenManager{signingKey: signingKey}, nil
}

func (m *JWTTokenManager) NewAccessToken(value string, ttl time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(ttl).Unix(),
		Subject:   value,
	})

	return token.SignedString([]byte(m.signingKey))
}

func (m *JWTTokenManager) NewRefreshToken() (string, error) {
	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	_, err := r.Read(b)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", b), nil
}

func (m *JWTTokenManager) ParseAccessToken(accessToken string) (string, error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(m.signingKey), nil
	})
	if err != nil {
		return "", fmt.Errorf("Denied by access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("Error get entity claims from token")
	}

	return claims["sub"].(string), nil
}
