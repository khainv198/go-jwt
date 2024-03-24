package jwt

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var ErrInvalidToken = errors.New("InvalidToken")

type TokenType int8

const (
	AccessToken  TokenType = 1
	RefreshToken TokenType = 2
)

type JwtReq struct {
	ID *primitive.ObjectID
}

type JwtClaim struct {
	*jwt.StandardClaims
	ID   *primitive.ObjectID
	Type TokenType
}

func New(opts *Options) (Client, error) {
	privateKey, err := parsePrivateKey(opts.PrivateKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := parsePublicKey(opts.PublicKey)
	if err != nil {
		return nil, err
	}

	return &client{
		privateKey:         privateKey,
		publicKey:          publicKey,
		issuer:             opts.Issuer,
		signMethod:         jwt.GetSigningMethod(opts.SignMethod),
		accessTokenExpire:  opts.AccessTokenExpire,
		refreshTokenExpire: opts.RefreshTokenExpire,
	}, nil
}

func (c *client) verifyToken(tokenStr string, tokenType TokenType) (*JwtClaim, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return c.publicKey, nil
	}

	var result JwtClaim
	token, err := jwt.ParseWithClaims(tokenStr, &result, keyFunc)

	jwtErr, ok := err.(*jwt.ValidationError)
	if !ok {
		return nil, ErrInvalidToken
	}

	if jwtErr != nil && jwtErr.Errors == jwt.ValidationErrorExpired {
		return nil, ErrInvalidToken
	}

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	if result.Type != tokenType {
		return nil, ErrInvalidToken
	}

	return &result, nil
}

func (c *client) VerifyAccessToken(token string) (*JwtClaim, error) {
	return c.verifyToken(token, AccessToken)
}

func (c *client) VerifyRefreshToken(token string) (*JwtClaim, error) {
	return c.verifyToken(token, RefreshToken)
}

func (c *client) generateToken(req JwtReq, tokenType TokenType, expiredTime uint64) (*GenerateResult, error) {
	TTL := time.Second * time.Duration(expiredTime)
	expiredAt := time.Now().UTC().Add(TTL)
	jwtToken := jwt.New(c.signMethod)
	jwtClaim := JwtClaim{
		ID:   req.ID,
		Type: tokenType,
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: expiredAt.Unix(),
			Issuer:    c.issuer,
		},
	}
	jwtToken.Claims = jwtClaim
	tokenStr, err := jwtToken.SignedString(c.privateKey)
	if err != nil {
		return nil, err
	}

	return &GenerateResult{
		Token:     tokenStr,
		ExpiredAt: &expiredAt,
		Signal:    strings.Split(tokenStr, ".")[2],
		TTL:       TTL,
	}, nil
}

func (c *client) GenerateAccessToken(req JwtReq) (*GenerateResult, error) {
	return c.generateToken(req, AccessToken, c.accessTokenExpire)
}

func (c *client) GenerateRefreshToken(req JwtReq) (*GenerateResult, error) {
	return c.generateToken(req, RefreshToken, c.refreshTokenExpire)
}
