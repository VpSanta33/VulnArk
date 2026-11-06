package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

// UserRepository 用户仓储接口
type UserRepository interface {
	Create(user *model.User) error
	GetByID(id uint) (*model.User, error)
	GetByUsername(username string) (*model.User, error)
	GetByEmail(email string) (*model.User, error)
	Update(id uint, req *model.UserUpdateRequest) error
	UpdateProfile(id uint, req *model.UserProfileUpdateRequest) error
	UpdatePassword(id uint, passwordHash string) error
	IncrementTokenVersion(id uint) error
	Begin2FASetup(id uint, version uint64, encryptedSecret string, expiresAt time.Time) error
	Complete2FASetup(id uint, version uint64, encryptedSecret string, recoveryHashes []string, usedStep int64) error
	UseMFAProof(id uint, version uint64, challengeHash string, step int64, recoveryHash string, disable bool) error
	CreateMFAChallenge(challenge *model.MFAChallenge) error
	GetMFAChallenge(hash string) (*model.MFAChallenge, error)
	IncrementMFAChallengeAttempt(hash string) error
	// CleanupMFAChallenges deletes at most batchSize expired/consumed challenge rows.
	CleanupMFAChallenges(ctx context.Context, before time.Time, batchSize int) (int64, error)
	Delete(id uint) error
	List(req *model.SearchRequest) ([]*model.User, int64, error)
	UpdateLastLogin(id uint) error
}

// userRepository 用户仓储实现
type userRepository struct {
	db *gorm.DB
}

// NewUserRepository 创建用户仓储
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

// Create 创建用户
func (r *userRepository) Create(user *model.User) error {
	return r.db.Create(user).Error
}

// GetByID 根据ID获取用户
func (r *userRepository) GetByID(id uint) (*model.User, error) {
	var user model.User
	err := r.db.Preload("Role").First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, err
	}
	return &user, nil
}

// GetByUsername 根据用户名获取用户
func (r *userRepository) GetByUsername(username string) (*model.User, error) {
	var user model.User
	err := r.db.Preload("Role").Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, err
	}
	return &user, nil
}

// GetByEmail 根据邮箱获取用户
func (r *userRepository) GetByEmail(email string) (*model.User, error) {
	var user model.User
	err := r.db.Preload("Role").Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, err
	}
	return &user, nil
}

// Update 更新用户
func (r *userRepository) Update(id uint, req *model.UserUpdateRequest) error {
	updates := map[string]interface{}{}
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.RealName != "" {
		updates["real_name"] = req.RealName
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}
	if req.Department != "" {
		updates["department"] = req.Department
	}
	if req.RoleID != 0 {
		updates["role_id"] = req.RoleID
		updates["token_version"] = gorm.Expr("token_version + 1")
	}
	if req.Status != nil {
		updates["status"] = *req.Status
		updates["token_version"] = gorm.Expr("token_version + 1")
	}
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error
}

func (r *userRepository) UpdateProfile(id uint, req *model.UserProfileUpdateRequest) error {
	updates := map[string]interface{}{"phone": req.Phone, "department": req.Department}
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.RealName != "" {
		updates["real_name"] = req.RealName
	}
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error
}

// UpdatePassword 更新用户密码
func (r *userRepository) UpdatePassword(id uint, passwordHash string) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(map[string]interface{}{
		"password_hash": passwordHash,
		"token_version": gorm.Expr("token_version + 1"),
	}).Error
}

func (r *userRepository) IncrementTokenVersion(id uint) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("token_version", gorm.Expr("token_version + 1")).Error
}

func (r *userRepository) Begin2FASetup(id uint, version uint64, encryptedSecret string, expiresAt time.Time) error {
	result := r.db.Model(&model.User{}).Where("id = ? AND token_version = ? AND (two_factor_enabled = ? OR two_factor_needs_rebind = ? OR two_factor_secret NOT LIKE ?)", id, version, false, true, "v1:%").Updates(map[string]interface{}{
		"two_factor_pending_secret":     encryptedSecret,
		"two_factor_pending_expires_at": expiresAt,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("认证状态已变化")
	}
	return nil
}

func (r *userRepository) Complete2FASetup(id uint, version uint64, encryptedSecret string, recoveryHashes []string, usedStep int64) error {
	hashes, err := json.Marshal(recoveryHashes)
	if err != nil {
		return err
	}
	return r.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&model.User{}).Where("id = ? AND token_version = ? AND two_factor_pending_secret = ? AND two_factor_pending_expires_at > ?", id, version, encryptedSecret, time.Now()).Updates(map[string]interface{}{
			"two_factor_enabled":            true,
			"two_factor_secret":             encryptedSecret,
			"two_factor_pending_secret":     "",
			"two_factor_pending_expires_at": nil,
			"two_factor_recovery_codes":     string(hashes),
			"two_factor_last_used_step":     usedStep,
			"two_factor_needs_rebind":       false,
			"token_version":                 gorm.Expr("token_version + 1"),
		})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return errors.New("MFA setup expired or changed")
		}
		return nil
	})
}

// UseMFAProof consumes a login challenge and factor in the same transaction.
// The user row lock serializes recovery-code consumption and TOTP replay checks.
func (r *userRepository) UseMFAProof(id uint, version uint64, challengeHash string, step int64, recoveryHash string, disable bool) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&user, id).Error; err != nil {
			return err
		}
		if !user.IsActive() || user.TokenVersion != version || !user.TwoFactorEnabled {
			return errors.New("认证状态已变化")
		}
		updates := map[string]interface{}{}
		if recoveryHash != "" {
			var hashes []string
			if err := json.Unmarshal([]byte(user.TwoFactorRecoveryCodes), &hashes); err != nil {
				return errors.New("恢复码无效")
			}
			found := false
			for i, hash := range hashes {
				if hash == recoveryHash {
					hashes = append(hashes[:i], hashes[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				return errors.New("恢复码无效或已使用")
			}
			encoded, err := json.Marshal(hashes)
			if err != nil {
				return err
			}
			updates["two_factor_recovery_codes"] = string(encoded)
		} else {
			if step < 0 || step <= user.TwoFactorLastUsedStep {
				return errors.New("验证码无效或已使用")
			}
			updates["two_factor_last_used_step"] = step
		}
		if disable {
			updates = map[string]interface{}{"two_factor_enabled": false, "two_factor_secret": "", "two_factor_pending_secret": "", "two_factor_pending_expires_at": nil, "two_factor_recovery_codes": "", "two_factor_last_used_step": int64(-1), "two_factor_needs_rebind": false, "token_version": gorm.Expr("token_version + 1")}
		}
		result := tx.Model(&model.User{}).Where("id = ? AND token_version = ? AND two_factor_last_used_step = ? AND two_factor_recovery_codes = ?", id, version, user.TwoFactorLastUsedStep, user.TwoFactorRecoveryCodes).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("认证状态已变化")
		}
		if challengeHash != "" {
			now := time.Now()
			result = tx.Model(&model.MFAChallenge{}).Where("token_hash = ? AND user_id = ? AND token_version = ? AND consumed_at IS NULL AND expires_at > ? AND attempts <= ?", challengeHash, id, version, now, 5).Update("consumed_at", now)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return errors.New("挑战已过期或无效")
			}
		}
		return nil
	})
}

func (r *userRepository) CreateMFAChallenge(challenge *model.MFAChallenge) error {
	return r.db.Create(challenge).Error
}

func (r *userRepository) GetMFAChallenge(hash string) (*model.MFAChallenge, error) {
	var challenge model.MFAChallenge
	err := r.db.Where("token_hash = ?", hash).First(&challenge).Error
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (r *userRepository) IncrementMFAChallengeAttempt(hash string) error {
	result := r.db.Model(&model.MFAChallenge{}).Where("token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND attempts < ?", hash, time.Now(), 5).Update("attempts", gorm.Expr("attempts + 1"))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("挑战已过期或无效")
	}
	return nil
}

// CleanupMFAChallenges removes a bounded batch of expired or already consumed challenges.
func (r *userRepository) CleanupMFAChallenges(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	if batchSize <= 0 {
		return 0, errors.New("MFA challenge cleanup batch size must be positive")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var ids []string
	query := r.db.WithContext(ctx).Model(&model.MFAChallenge{}).
		Where("(expires_at < ? OR consumed_at IS NOT NULL)", before).
		Order("expires_at ASC").Limit(batchSize).Pluck("id", &ids)
	if query.Error != nil {
		return 0, query.Error
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := r.db.WithContext(ctx).Where("id IN ?", ids).Delete(&model.MFAChallenge{})
	return result.RowsAffected, result.Error
}

// Delete 删除用户
func (r *userRepository) Delete(id uint) error {
	return r.db.Delete(&model.User{}, id).Error
}

// List 获取用户列表
func (r *userRepository) List(req *model.SearchRequest) ([]*model.User, int64, error) {
	var users []*model.User
	var total int64

	query := r.db.Model(&model.User{}).Preload("Role")

	// 搜索条件
	if req.Keyword != "" {
		query = query.Where("username LIKE ? OR real_name LIKE ? OR email LIKE ?",
			"%"+req.Keyword+"%", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}

	// 获取总数
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页
	offset := (req.Page - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// UpdateLastLogin 更新最后登录时间
func (r *userRepository) UpdateLastLogin(id uint) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("last_login_at", time.Now()).Error
}

// RoleRepository 角色仓储接口
type RoleRepository interface {
	Create(role *model.Role) error
	GetByID(id uint) (*model.Role, error)
	GetByName(name string) (*model.Role, error)
	Update(role *model.Role) error
	Delete(id uint) error
	List() ([]*model.Role, error)
}

// roleRepository 角色仓储实现
type roleRepository struct {
	db *gorm.DB
}

// NewRoleRepository 创建角色仓储
func NewRoleRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{
		db: db,
	}
}

// Create 创建角色
func (r *roleRepository) Create(role *model.Role) error {
	return r.db.Create(role).Error
}

// GetByID 根据ID获取角色
func (r *roleRepository) GetByID(id uint) (*model.Role, error) {
	var role model.Role
	err := r.db.First(&role, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("角色不存在")
		}
		return nil, err
	}
	return &role, nil
}

// GetByName 根据名称获取角色
func (r *roleRepository) GetByName(name string) (*model.Role, error) {
	var role model.Role
	err := r.db.Where("name = ?", name).First(&role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("角色不存在")
		}
		return nil, err
	}
	return &role, nil
}

// Update 更新角色
func (r *roleRepository) Update(role *model.Role) error {
	updates := map[string]interface{}{}
	if role.Name != "" {
		updates["name"] = role.Name
	}
	if role.Description != "" {
		updates["description"] = role.Description
	}
	if role.Permissions != nil {
		updates["permissions"] = role.Permissions
	}
	if len(updates) == 0 {
		return nil
	}
	result := r.db.Model(&model.Role{}).Where("id = ?", role.ID).Updates(updates)
	return result.Error
}

// Delete 删除角色
func (r *roleRepository) Delete(id uint) error {
	// 检查是否有用户使用该角色
	var count int64
	if err := r.db.Model(&model.User{}).Where("role_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return errors.New("该角色正在被使用，无法删除")
	}
	return r.db.Delete(&model.Role{}, id).Error
}

// List 获取角色列表
func (r *roleRepository) List() ([]*model.Role, error) {
	var roles []*model.Role
	err := r.db.Find(&roles).Error
	return roles, err
}
