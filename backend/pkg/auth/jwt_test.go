package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestJWTStrictClaims(t *testing.T) {
	secret := strings.Repeat("s", 32)
	manager, err := NewJWTManagerWithConfig(secret, time.Hour, "vulnark")
	require.NoError(t, err)
	now := time.Unix(1700000000, 0)
	manager.clock = func() time.Time { return now }
	token, _, err := manager.GenerateAccessToken(1, "alice", 2, 7)
	require.NoError(t, err)
	claims, err := manager.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, uint64(7), claims.TokenVersion)

	for _, name := range []string{"HS512", "issuer", "missing-exp", "expired", "purpose", "version"} {
		t.Run(name, func(t *testing.T) {
			candidate := *claims
			method := jwt.SigningMethodHS256
			switch name {
			case "HS512":
				method = jwt.SigningMethodHS512
			case "issuer":
				candidate.Issuer = "other"
			case "missing-exp":
				candidate.ExpiresAt = nil
			case "expired":
				candidate.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
			case "purpose":
				candidate.Purpose = "mfa_rebind"
			case "version":
				candidate.TokenVersion = 0
			}
			encoded, err := jwt.NewWithClaims(method, candidate).SignedString([]byte(secret))
			require.NoError(t, err)
			_, err = manager.ParseToken(encoded)
			require.Error(t, err)
		})
	}

	rebind, _, err := manager.GenerateRebindToken(1, "alice", 2, 7)
	require.NoError(t, err)
	_, err = manager.ParseToken(rebind)
	require.Error(t, err)
	_, err = manager.ParsePurposeToken(rebind, "access", "mfa_rebind")
	require.NoError(t, err)
}

func TestJWTRejectsMissingConfiguration(t *testing.T) {
	_, err := NewJWTManagerWithConfig("short", time.Hour, "vulnark")
	require.Error(t, err)
	_, err = NewJWTManagerWithConfig(strings.Repeat("s", 32), 0, "vulnark")
	require.Error(t, err)
	var manager *JWTManager
	_, err = manager.ParseToken("bad")
	require.Error(t, err)
}
