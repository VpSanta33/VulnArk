package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/auth"
	"vulnark/pkg/testutil"
	"vulnark/pkg/utils"
)

func authFixture(t *testing.T) (*gorm.DB, repository.UserRepository, *model.User, *MFAService, UserService) {
	t.Helper()
	db := testutil.NewTestDB(t)
	role := &model.Role{Name: "reader", Permissions: model.Permissions{"vuln:read"}}
	require.NoError(t, db.Create(role).Error)
	password, err := utils.HashPassword("original-password")
	require.NoError(t, err)
	user := &model.User{Username: "alice", Email: "alice@example.test", RealName: "Alice", PasswordHash: password, RoleID: role.ID, Status: 1, TokenVersion: 1, TwoFactorLastUsedStep: -1}
	require.NoError(t, db.Create(user).Error)
	repo := repository.NewUserRepository(db)
	mfa, err := NewMFAService(repo, strings.Repeat("m", 32))
	require.NoError(t, err)
	manager, err := auth.NewJWTManagerWithConfig(strings.Repeat("s", 32), time.Hour, "vulnark")
	require.NoError(t, err)
	service := NewUserServiceWithAuth(repo, repository.NewRoleRepository(db), manager, mfa)
	return db, repo, user, mfa, service
}

func activateMFA(t *testing.T, db *gorm.DB, user *model.User, mfa *MFAService) (*model.TwoFactorSetupResponse, []string, time.Time) {
	t.Helper()
	now := time.Now().Truncate(30 * time.Second)
	mfa.clock = func() time.Time { return now }
	setup, err := mfa.Setup(user.ID)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(setup.QRCodeDataURL, "data:image/png;base64,"))
	require.True(t, strings.HasPrefix(setup.OTPAuthURL, "otpauth://totp/"))
	var stored model.User
	require.NoError(t, db.First(&stored, user.ID).Error)
	require.NotEqual(t, setup.Secret, stored.TwoFactorPendingSecret)
	require.True(t, strings.HasPrefix(stored.TwoFactorPendingSecret, "v1:"))
	require.False(t, stored.TwoFactorEnabled)
	code, err := totp.GenerateCode(setup.Secret, now)
	require.NoError(t, err)
	codes, err := mfa.Confirm(user.ID, code)
	require.NoError(t, err)
	require.Len(t, codes, 8)
	require.NoError(t, db.First(&stored, user.ID).Error)
	require.Equal(t, uint64(2), stored.TokenVersion)
	require.NotContains(t, stored.TwoFactorRecoveryCodes, codes[0])
	return setup, codes, now
}

func TestMFASetupExpiryAndOTPVerification(t *testing.T) {
	db, _, user, mfa, _ := authFixture(t)
	setup, err := mfa.Setup(user.ID)
	require.NoError(t, err)
	_, err = mfa.Confirm(user.ID, "abcdef")
	require.Error(t, err)
	past := time.Now().Add(-time.Minute)
	require.NoError(t, db.Model(user).Update("two_factor_pending_expires_at", past).Error)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	require.NoError(t, err)
	_, err = mfa.Confirm(user.ID, code)
	require.ErrorContains(t, err, "过期")
	var stored model.User
	require.NoError(t, db.First(&stored, user.ID).Error)
	require.False(t, stored.TwoFactorEnabled)
}

func TestMFALoginChallengeReplayAndRecovery(t *testing.T) {
	db, _, user, mfa, service := authFixture(t)
	setup, codes, now := activateMFA(t, db, user, mfa)
	login := &model.UserLoginRequest{Username: user.Username, Password: "original-password"}
	challenge, err := service.Login(login)
	require.NoError(t, err)
	require.True(t, challenge.MFARequired)
	require.Empty(t, challenge.Token)
	code, err := totp.GenerateCode(setup.Secret, now)
	require.NoError(t, err)
	login.ChallengeToken, login.TOTPCode = challenge.ChallengeToken, code
	_, err = service.Login(login)
	require.ErrorContains(t, err, "已使用") // Enrollment already consumed this period.
	now = now.Add(30 * time.Second)
	mfa.clock = func() time.Time { return now }
	login.TOTPCode, err = totp.GenerateCode(setup.Secret, now)
	require.NoError(t, err)
	response, err := service.Login(login)
	require.NoError(t, err)
	require.NotEmpty(t, response.Token)
	_, err = service.Login(login)
	require.ErrorContains(t, err, "挑战")

	login.ChallengeToken, login.TOTPCode = "", ""
	challenge, err = service.Login(login)
	require.NoError(t, err)
	login.ChallengeToken, login.RecoveryCode = challenge.ChallengeToken, codes[0]
	_, err = service.Login(login)
	require.NoError(t, err)
	login.ChallengeToken = ""
	challenge, err = service.Login(login)
	require.NoError(t, err)
	login.ChallengeToken = challenge.ChallengeToken
	_, err = service.Login(login)
	require.ErrorContains(t, err, "恢复码")
	status, err := mfa.Status(user.ID)
	require.NoError(t, err)
	require.Equal(t, 7, status.RecoveryCodesRemaining)
}

func TestMFAChallengeExpiryAndAttemptLimit(t *testing.T) {
	db, _, user, mfa, service := authFixture(t)
	_, _, _ = activateMFA(t, db, user, mfa)
	login := &model.UserLoginRequest{Username: user.Username, Password: "original-password"}
	challenge, err := service.Login(login)
	require.NoError(t, err)
	login.ChallengeToken, login.TOTPCode = challenge.ChallengeToken, "abcdef"
	for i := 0; i < 5; i++ {
		_, err = service.Login(login)
		require.Error(t, err)
	}
	_, err = service.Login(login)
	require.ErrorContains(t, err, "挑战")
	login.ChallengeToken, login.TOTPCode = "", ""
	challenge, err = service.Login(login)
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.MFAChallenge{}).Where("token_hash = ?", mfaHash(challenge.ChallengeToken)).Update("expires_at", time.Now().Add(-time.Minute)).Error)
	login.ChallengeToken, login.TOTPCode = challenge.ChallengeToken, "123456"
	_, err = service.Login(login)
	require.ErrorContains(t, err, "挑战")
}

func TestMFADisableRevokesTokensAndRequiresProof(t *testing.T) {
	db, repo, user, mfa, _ := authFixture(t)
	_, codes, _ := activateMFA(t, db, user, mfa)
	require.Error(t, mfa.Disable(user.ID, "invalid"))
	require.NoError(t, mfa.Disable(user.ID, codes[0]))
	stored, err := repo.GetByID(user.ID)
	require.NoError(t, err)
	require.False(t, stored.TwoFactorEnabled)
	require.Equal(t, uint64(3), stored.TokenVersion)
	require.Empty(t, stored.TwoFactorSecret)
	require.Empty(t, stored.TwoFactorRecoveryCodes)
}

func TestLegacyMFAGetsRestrictedRebindOnly(t *testing.T) {
	db, _, user, _, service := authFixture(t)
	require.NoError(t, db.Model(user).Updates(map[string]interface{}{"two_factor_enabled": true, "two_factor_secret": "", "two_factor_needs_rebind": true}).Error)
	response, err := service.Login(&model.UserLoginRequest{Username: user.Username, Password: "original-password"})
	require.NoError(t, err)
	require.True(t, response.MFARebindRequired)
	require.Empty(t, response.Token)
	require.NotEmpty(t, response.RebindToken)
}

func TestMFAHashesAndSecretsNeverSerializeInUser(t *testing.T) {
	user := model.User{TwoFactorSecret: "sensitive-active", TwoFactorPendingSecret: "sensitive-pending", TwoFactorRecoveryCodes: "sensitive-recovery", TokenVersion: 17}
	encoded, err := json.Marshal(user)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "sensitive")
	require.NotContains(t, string(encoded), "token_version")
}

func TestPasswordConfirmationAndRevocation(t *testing.T) {
	_, repo, user, _, service := authFixture(t)
	err := service.ChangePassword(user.ID, &model.ChangePasswordRequest{CurrentPassword: "original-password", NewPassword: "new-password", ConfirmPassword: "different"})
	require.ErrorContains(t, err, "确认")
	require.NoError(t, service.ChangePassword(user.ID, &model.ChangePasswordRequest{CurrentPassword: "original-password", NewPassword: "new-password", ConfirmPassword: "new-password"}))
	stored, err := repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(2), stored.TokenVersion)
	require.True(t, utils.CheckPassword("new-password", stored.PasswordHash))
	require.NoError(t, service.RevokeAllSessions(user.ID))
	stored, err = repo.GetByID(user.ID)
	require.NoError(t, err)
	require.Equal(t, uint64(3), stored.TokenVersion)
}
