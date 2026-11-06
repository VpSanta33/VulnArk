package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"vulnark/internal/config"
)

type Claims struct {
	UserID       uint   `json:"user_id"`
	Username     string `json:"username"`
	RoleID       uint   `json:"role_id"`
	TokenVersion uint64 `json:"token_version"`
	Purpose      string `json:"purpose"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey  string
	expireTime time.Duration
	issuer     string
	clock      func() time.Time
}

// Invalid or missing production configuration never falls back to a default key.
func NewJWTManager() *JWTManager {
	if config.AppConfig == nil {
		return nil
	}
	cfg := config.AppConfig.JWT
	manager, _ := NewJWTManagerWithConfig(cfg.Secret, time.Duration(cfg.ExpireTime)*time.Second, "vulnark")
	return manager
}

func NewJWTManagerWithConfig(secret string, expiry time.Duration, issuer string) (*JWTManager, error) {
	if len(secret) < 32 || expiry <= 0 || issuer == "" {
		return nil, errors.New("invalid JWT configuration")
	}
	return &JWTManager{secretKey: secret, expireTime: expiry, issuer: issuer, clock: time.Now}, nil
}

func (j *JWTManager) GenerateAccessToken(id uint, username string, roleID uint, version uint64) (string, time.Time, error) {
	if j == nil {
		return "", time.Time{}, errors.New("authentication is not configured")
	}
	return j.generate(id, username, roleID, version, "access", j.expireTime)
}

func (j *JWTManager) GenerateRebindToken(id uint, username string, roleID uint, version uint64) (string, time.Time, error) {
	return j.generate(id, username, roleID, version, "mfa_rebind", 10*time.Minute)
}

func (j *JWTManager) generate(id uint, username string, roleID uint, version uint64, purpose string, expiry time.Duration) (string, time.Time, error) {
	if j == nil || id == 0 || version == 0 {
		return "", time.Time{}, errors.New("invalid authentication state")
	}
	now := j.clock()
	expires := now.Add(expiry)
	claims := &Claims{UserID: id, Username: username, RoleID: roleID, TokenVersion: version, Purpose: purpose,
		RegisteredClaims: jwt.RegisteredClaims{Issuer: j.issuer, Subject: username, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires)}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(j.secretKey))
	return token, expires, err
}

func (j *JWTManager) ParseToken(token string) (*Claims, error) {
	return j.ParsePurposeToken(token, "access")
}

func (j *JWTManager) ParsePurposeToken(token string, purposes ...string) (*Claims, error) {
	if j == nil {
		return nil, errors.New("authentication is not configured")
	}
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("invalid signing algorithm")
		}
		return []byte(j.secretKey), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(j.issuer), jwt.WithIssuedAt(), jwt.WithTimeFunc(j.clock))
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.NotBefore == nil || claims.UserID == 0 || claims.TokenVersion == 0 {
		return nil, errors.New("invalid authentication claims")
	}
	for _, purpose := range purposes {
		if claims.Purpose == purpose {
			return claims, nil
		}
	}
	return nil, errors.New("invalid token purpose")
}

func (j *JWTManager) ValidateToken(token string) bool {
	_, err := j.ParseToken(token)
	return err == nil
}
