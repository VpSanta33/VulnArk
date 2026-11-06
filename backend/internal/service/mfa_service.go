package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"vulnark/internal/config"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

type MFAService struct {
	repo  repository.UserRepository
	aead  cipher.AEAD
	clock func() time.Time
}

func NewMFAService(repo repository.UserRepository, key string) (*MFAService, error) {
	if len(key) != 32 {
		return nil, errors.New("MFA encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MFAService{repo: repo, aead: aead, clock: time.Now}, nil
}

func configuredMFAService(repo repository.UserRepository) *MFAService {
	if config.AppConfig == nil || config.AppConfig.Security.MFAEncryptionKey == config.AppConfig.JWT.Secret {
		return nil
	}
	service, _ := NewMFAService(repo, config.AppConfig.Security.MFAEncryptionKey)
	return service
}

func needsRebind(user *model.User) bool {
	return user.TwoFactorNeedsRebind || (user.TwoFactorEnabled && !strings.HasPrefix(user.TwoFactorSecret, "v1:"))
}

func (m *MFAService) encrypt(secret string) (string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := m.aead.Seal(nonce, nonce, []byte(secret), []byte("vulnark:mfa:v1"))
	return "v1:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (m *MFAService) decrypt(encrypted string) (string, error) {
	if m == nil || !strings.HasPrefix(encrypted, "v1:") {
		return "", errors.New("MFA密钥不可用")
	}
	sealed, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(encrypted, "v1:"))
	if err != nil || len(sealed) < m.aead.NonceSize() {
		return "", errors.New("MFA密钥不可用")
	}
	nonce := sealed[:m.aead.NonceSize()]
	plain, err := m.aead.Open(nil, nonce, sealed[m.aead.NonceSize():], []byte("vulnark:mfa:v1"))
	if err != nil {
		return "", errors.New("MFA密钥不可用，请联系管理员恢复")
	}
	return string(plain), nil
}

func randomMFAValue() (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func mfaHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func recoveryHash(value string) string {
	return mfaHash(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", "")))
}

func (m *MFAService) Setup(userID uint) (*model.TwoFactorSetupResponse, error) {
	if m == nil {
		return nil, errors.New("双因素认证尚未配置")
	}
	user, err := m.repo.GetByID(userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return nil, errors.New("用户已禁用")
	}
	if user.TwoFactorEnabled && !needsRebind(user) {
		return nil, errors.New("请先验证并禁用现有双因素认证后重新绑定")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "VulnArk", AccountName: user.Username, SecretSize: 20, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return nil, err
	}
	encrypted, err := m.encrypt(key.Secret())
	if err != nil {
		return nil, err
	}
	expires := m.clock().Add(10 * time.Minute)
	if err = m.repo.Begin2FASetup(userID, user.TokenVersion, encrypted, expires); err != nil {
		return nil, err
	}
	image, err := key.Image(256, 256)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err = png.Encode(&buffer, image); err != nil {
		return nil, err
	}
	dataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buffer.Bytes())
	return &model.TwoFactorSetupResponse{Secret: key.Secret(), OTPAuthURL: key.URL(), QRCodeURL: dataURL, QRCodeDataURL: dataURL, ExpiresAt: expires}, nil
}

func totpStep(secret, code string, now time.Time) (int64, error) {
	if len(code) != 6 {
		return -1, errors.New("验证码无效")
	}
	// Match each accepted period explicitly so the exact period can be consumed.
	for _, offset := range []int64{0, -1, 1} {
		at := now.Add(time.Duration(offset) * 30 * time.Second)
		ok, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return at.Unix() / 30, nil
		}
	}
	return -1, errors.New("验证码无效或已过期")
}

func (m *MFAService) Confirm(userID uint, code string) ([]string, error) {
	if m == nil {
		return nil, errors.New("双因素认证尚未配置")
	}
	user, err := m.repo.GetByID(userID)
	if err != nil {
		return nil, err
	}
	if user.TwoFactorPendingExpiresAt == nil || !user.TwoFactorPendingExpiresAt.After(m.clock()) {
		return nil, errors.New("绑定请求已过期，请重新设置")
	}
	secret, err := m.decrypt(user.TwoFactorPendingSecret)
	if err != nil {
		return nil, err
	}
	step, err := totpStep(secret, code, m.clock())
	if err != nil {
		return nil, err
	}
	codes, hashes := make([]string, 8), make([]string, 8)
	for i := range codes {
		value := make([]byte, 16)
		if _, err = io.ReadFull(rand.Reader, value); err != nil {
			return nil, err
		}
		codes[i] = strings.ToUpper(hex.EncodeToString(value))
		hashes[i] = recoveryHash(codes[i])
	}
	if err = m.repo.Complete2FASetup(userID, user.TokenVersion, user.TwoFactorPendingSecret, hashes, step); err != nil {
		return nil, err
	}
	return codes, nil
}

func (m *MFAService) Status(userID uint) (*model.TwoFactorStatusResponse, error) {
	user, err := m.repo.GetByID(userID)
	if err != nil {
		return nil, err
	}
	var codes []string
	if user.TwoFactorRecoveryCodes != "" {
		if err = json.Unmarshal([]byte(user.TwoFactorRecoveryCodes), &codes); err != nil {
			return nil, err
		}
	}
	return &model.TwoFactorStatusResponse{Enabled: user.TwoFactorEnabled && !needsRebind(user), NeedsRebind: needsRebind(user), Pending: user.TwoFactorPendingExpiresAt != nil && user.TwoFactorPendingExpiresAt.After(m.clock()), RecoveryCodesRemaining: len(codes)}, nil
}

func (m *MFAService) IssueChallenge(user *model.User) (*model.UserLoginResponse, error) {
	if m == nil {
		return nil, errors.New("双因素认证尚未配置")
	}
	value, err := randomMFAValue()
	if err != nil {
		return nil, err
	}
	expires := m.clock().Add(5 * time.Minute)
	challenge := &model.MFAChallenge{ID: mfaHash(value), UserID: user.ID, TokenHash: mfaHash(value), TokenVersion: user.TokenVersion, ExpiresAt: expires}
	if err = m.repo.CreateMFAChallenge(challenge); err != nil {
		return nil, err
	}
	return &model.UserLoginResponse{MFARequired: true, ChallengeToken: value, ExpiresAt: expires}, nil
}

func (m *MFAService) VerifyLogin(user *model.User, challengeToken, code, recovery string) error {
	if m == nil {
		return errors.New("双因素认证尚未配置")
	}
	if challengeToken == "" {
		return errors.New("请完成二次认证挑战")
	}
	hash := mfaHash(challengeToken)
	challenge, err := m.repo.GetMFAChallenge(hash)
	if err != nil || challenge.UserID != user.ID || challenge.TokenVersion != user.TokenVersion || challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(m.clock()) || challenge.Attempts >= 5 {
		return errors.New("挑战已过期或无效，请重新登录")
	}
	if err = m.repo.IncrementMFAChallengeAttempt(hash); err != nil {
		return err
	}
	step, recoveryDigest, err := m.proof(user, code, recovery)
	if err != nil {
		return err
	}
	return m.repo.UseMFAProof(user.ID, user.TokenVersion, hash, step, recoveryDigest, false)
}

func (m *MFAService) proof(user *model.User, code, recovery string) (int64, string, error) {
	if (code == "") == (recovery == "") {
		return -1, "", errors.New("请提供一个验证码或恢复码")
	}
	if recovery != "" {
		return -1, recoveryHash(recovery), nil
	}
	secret, err := m.decrypt(user.TwoFactorSecret)
	if err != nil {
		return -1, "", err
	}
	step, err := totpStep(secret, code, m.clock())
	return step, "", err
}

func (m *MFAService) Disable(userID uint, code string) error {
	if m == nil {
		return errors.New("双因素认证尚未配置")
	}
	user, err := m.repo.GetByID(userID)
	if err != nil {
		return err
	}
	if !user.TwoFactorEnabled || needsRebind(user) {
		return errors.New("请先完成双因素认证绑定")
	}
	recovery := ""
	if len(code) != 6 {
		recovery, code = code, ""
	}
	step, digest, err := m.proof(user, code, recovery)
	if err != nil {
		return err
	}
	return m.repo.UseMFAProof(user.ID, user.TokenVersion, "", step, digest, true)
}
