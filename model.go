package jwt

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt"
)

type Client interface {
	VerifyAccessToken(token string) (*JwtClaim, error)
	VerifyRefreshToken(token string) (*JwtClaim, error)
	GenerateAccessToken(req JwtReq) (*GenerateResult, error)
	GenerateRefreshToken(req JwtReq) (*GenerateResult, error)
}

type client struct {
	signMethod         jwt.SigningMethod
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	issuer             string
	refreshTokenExpire uint64
	accessTokenExpire  uint64
}

type Options struct {
	PublicKey          string
	PrivateKey         string
	SignMethod         string
	Issuer             string
	RefreshTokenExpire uint64
	AccessTokenExpire  uint64
}

type GenerateResult struct {
	Token     string
	ExpiredAt *time.Time
	Signal    string
}
