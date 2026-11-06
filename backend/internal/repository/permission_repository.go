package repository

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

// PermissionRepository 权限仓储接口
type PermissionRepository interface {
	Create(permission *model.Permission) error
	GetByID(id uint) (*model.Permission, error)
	GetByName(name string) (*model.Permission, error)
	Update(permission *model.Permission) error
	Delete(id uint) error
	List() ([]*model.Permission, error)
	GetByModule(module string) ([]*model.Permission, error)
	GetUserPermissions(userID uint) ([]*model.Permission, error)
	CheckUserPermission(userID uint, permissionName string) (bool, error)
}

// permissionRepository 权限仓储实现
type permissionRepository struct {
	db *gorm.DB
}

// NewPermissionRepository 创建权限仓储
func NewPermissionRepository(db *gorm.DB) PermissionRepository {
	return &permissionRepository{
		db: db,
	}
}

// Create 创建权限
func (r *permissionRepository) Create(permission *model.Permission) error {
	return r.db.Create(permission).Error
}

// GetByID 根据ID获取权限
func (r *permissionRepository) GetByID(id uint) (*model.Permission, error) {
	var permission model.Permission
	err := r.db.First(&permission, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("权限不存在")
		}
		return nil, err
	}
	return &permission, nil
}

// GetByName 根据名称获取权限
func (r *permissionRepository) GetByName(name string) (*model.Permission, error) {
	var permission model.Permission
	err := r.db.Where("name = ?", name).First(&permission).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("权限不存在")
		}
		return nil, err
	}
	return &permission, nil
}

// Update 更新权限
func (r *permissionRepository) Update(permission *model.Permission) error {
	return r.db.Save(permission).Error
}

// Delete 删除权限
func (r *permissionRepository) Delete(id uint) error {
	return r.db.Delete(&model.Permission{}, id).Error
}

// List 获取权限列表
func (r *permissionRepository) List() ([]*model.Permission, error) {
	var permissions []*model.Permission
	err := r.db.Order("module, action, resource").Find(&permissions).Error
	return permissions, err
}

// GetByModule 根据模块获取权限列表
func (r *permissionRepository) GetByModule(module string) ([]*model.Permission, error) {
	var permissions []*model.Permission
	err := r.db.Where("module = ? AND is_active = ?", module, true).
		Order("action, resource").Find(&permissions).Error
	return permissions, err
}

// GetUserPermissions 获取用户权限列表
func (r *permissionRepository) GetUserPermissions(userID uint) ([]*model.Permission, error) {
	var user model.User
	if err := r.db.Preload("Role").First(&user, userID).Error; err != nil {
		return nil, err
	}
	if !user.IsActive() {
		return []*model.Permission{}, nil
	}
	return rolePermissionMetadata(r.db, user.Role.Permissions)
}

func (r *permissionRepository) CheckUserPermission(userID uint, permissionName string) (bool, error) {
	var user model.User
	if err := r.db.Preload("Role").First(&user, userID).Error; err != nil {
		return false, err
	}
	return user.IsActive() && model.PermissionGranted(user.Role.Permissions, permissionName), nil
}

func rolePermissionMetadata(db *gorm.DB, grants model.Permissions) ([]*model.Permission, error) {
	var catalog []*model.Permission
	if err := db.Order("module, action, resource").Find(&catalog).Error; err != nil {
		return nil, err
	}
	permissions := make([]*model.Permission, 0)
	for _, permission := range catalog {
		if model.PermissionGranted(grants, permission.Name) {
			permission.Name = model.NormalizePermission(permission.Name)
			permissions = append(permissions, permission)
		}
	}
	return permissions, nil
}

// RolePermissionRepository 角色权限仓储接口
type RolePermissionRepository interface {
	AssignPermissions(roleID uint, permissionIDs []uint) error
	RemovePermissions(roleID uint, permissionIDs []uint) error
	GetRolePermissions(roleID uint) ([]*model.Permission, error)
	ClearRolePermissions(roleID uint) error
}

// rolePermissionRepository 角色权限仓储实现
type rolePermissionRepository struct {
	db *gorm.DB
}

// NewRolePermissionRepository 创建角色权限仓储
func NewRolePermissionRepository(db *gorm.DB) RolePermissionRepository {
	return &rolePermissionRepository{
		db: db,
	}
}

// AssignPermissions 分配权限给角色
func (r *rolePermissionRepository) AssignPermissions(roleID uint, permissionIDs []uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var role model.Role
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&role, roleID).Error; err != nil {
			return err
		}
		grants := model.Permissions{}
		seen := map[string]bool{}
		for _, id := range permissionIDs {
			var permission model.Permission
			if err := tx.First(&permission, id).Error; err != nil {
				return errors.New("权限不存在")
			}
			name := model.NormalizePermission(permission.Name)
			if !seen[name] {
				grants = append(grants, name)
				seen[name] = true
			}
		}
		return tx.Model(&model.Role{}).Where("id = ?", roleID).Update("permissions", grants).Error
	})
}

func (r *rolePermissionRepository) RemovePermissions(roleID uint, permissionIDs []uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var role model.Role
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&role, roleID).Error; err != nil {
			return err
		}
		var removed []*model.Permission
		if err := tx.Where("id IN ?", permissionIDs).Find(&removed).Error; err != nil {
			return err
		}
		kept := model.Permissions{}
		for _, grant := range role.Permissions {
			remove := false
			for _, permission := range removed {
				if model.NormalizePermission(grant) == model.NormalizePermission(permission.Name) {
					remove = true
					break
				}
			}
			if !remove {
				kept = append(kept, grant)
			}
		}
		return tx.Model(&model.Role{}).Where("id = ?", roleID).Update("permissions", kept).Error
	})
}

func (r *rolePermissionRepository) GetRolePermissions(roleID uint) ([]*model.Permission, error) {
	var role model.Role
	if err := r.db.First(&role, roleID).Error; err != nil {
		return nil, err
	}
	return rolePermissionMetadata(r.db, role.Permissions)
}

func (r *rolePermissionRepository) ClearRolePermissions(roleID uint) error {
	return r.db.Model(&model.Role{}).Where("id = ?", roleID).Update("permissions", model.Permissions{}).Error
}

// SystemConfigRepository 系统配置仓储接口
type SystemConfigRepository interface {
	Create(config *model.SystemConfig) error
	GetByKey(key string) (*model.SystemConfig, error)
	Update(config *model.SystemConfig) error
	Delete(key string) error
	List() ([]*model.SystemConfig, error)
	GetByCategory(category string) ([]*model.SystemConfig, error)
	GetPublicConfigs() ([]*model.SystemConfig, error)
}

// systemConfigRepository 系统配置仓储实现
type systemConfigRepository struct {
	db *gorm.DB
}

// NewSystemConfigRepository 创建系统配置仓储
func NewSystemConfigRepository(db *gorm.DB) SystemConfigRepository {
	return &systemConfigRepository{
		db: db,
	}
}

// Create 创建系统配置
func (r *systemConfigRepository) Create(config *model.SystemConfig) error {
	return r.db.Create(config).Error
}

// GetByKey 根据键获取系统配置
func (r *systemConfigRepository) GetByKey(key string) (*model.SystemConfig, error) {
	var config model.SystemConfig
	err := r.db.Where("`key` = ?", key).First(&config).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("配置不存在")
		}
		return nil, err
	}
	return &config, nil
}

// Update 更新系统配置
func (r *systemConfigRepository) Update(config *model.SystemConfig) error {
	return r.db.Save(config).Error
}

// Delete 删除系统配置
func (r *systemConfigRepository) Delete(key string) error {
	return r.db.Where("`key` = ?", key).Delete(&model.SystemConfig{}).Error
}

// List 获取系统配置列表
func (r *systemConfigRepository) List() ([]*model.SystemConfig, error) {
	var configs []*model.SystemConfig
	err := r.db.Order("category, `key`").Find(&configs).Error
	return configs, err
}

// GetByCategory 根据分类获取系统配置列表
func (r *systemConfigRepository) GetByCategory(category string) ([]*model.SystemConfig, error) {
	var configs []*model.SystemConfig
	err := r.db.Where("category = ?", category).Order("`key`").Find(&configs).Error
	return configs, err
}

// GetPublicConfigs 获取公开配置列表
func (r *systemConfigRepository) GetPublicConfigs() ([]*model.SystemConfig, error) {
	var configs []*model.SystemConfig
	err := r.db.Where("is_public = ?", true).Order("category, `key`").Find(&configs).Error
	return configs, err
}

// AuditLogRepository 审计日志仓储接口
type AuditLogRepository interface {
	Create(log *model.AuditLog) error
	GetByID(id uint) (*model.AuditLog, error)
	List(req *model.AuditLogSearchRequest) ([]*model.AuditLog, int64, error)
	DeleteOldLogs(days int) error
	GetStats() (map[string]interface{}, error)
}

// ContextAuditLogRepository supports cancellable audit persistence without changing legacy callers.
type ContextAuditLogRepository interface {
	CreateContext(ctx context.Context, log *model.AuditLog) error
}

type ContextAuditLogCleanupRepository interface {
	DeleteOldLogsBatch(ctx context.Context, before time.Time, limit int) (int64, error)
}

// auditLogRepository 审计日志仓储实现
type auditLogRepository struct {
	db *gorm.DB
}

// NewAuditLogRepository 创建审计日志仓储
func NewAuditLogRepository(db *gorm.DB) AuditLogRepository {
	return &auditLogRepository{
		db: db,
	}
}

// Create 创建审计日志
func (r *auditLogRepository) Create(log *model.AuditLog) error {
	return r.CreateContext(context.Background(), log)
}

func (r *auditLogRepository) CreateContext(ctx context.Context, log *model.AuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

// GetByID 根据ID获取审计日志
func (r *auditLogRepository) GetByID(id uint) (*model.AuditLog, error) {
	var log model.AuditLog
	err := r.db.Preload("User").First(&log, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("审计日志不存在")
		}
		return nil, err
	}
	return &log, nil
}

// List 获取审计日志列表
func (r *auditLogRepository) List(req *model.AuditLogSearchRequest) ([]*model.AuditLog, int64, error) {
	var logs []*model.AuditLog
	var total int64

	query := r.db.Model(&model.AuditLog{}).Preload("User")

	// 搜索条件
	if req.Keyword != "" {
		query = query.Where("action LIKE ? OR resource LIKE ? OR path LIKE ?",
			"%"+req.Keyword+"%", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	if req.UserID != "" {
		if userID, err := strconv.ParseUint(req.UserID, 10, 32); err == nil {
			query = query.Where("user_id = ?", uint(userID))
		}
	}

	if req.Username != "" {
		query = query.Where("username LIKE ?", "%"+req.Username+"%")
	}

	if req.Action != "" {
		query = query.Where("action = ?", req.Action)
	}

	if req.Resource != "" {
		query = query.Where("resource = ?", req.Resource)
	}

	if req.Method != "" {
		query = query.Where("method = ?", strings.ToUpper(req.Method))
	}

	if req.Status != "" {
		if status, err := strconv.Atoi(req.Status); err == nil {
			query = query.Where("status = ?", status)
		}
	}

	if req.IP != "" {
		query = query.Where("ip = ?", req.IP)
	}

	// 日期范围
	if req.StartDate != "" {
		if startDate, err := time.Parse("2006-01-02", req.StartDate); err == nil {
			query = query.Where("created_at >= ?", startDate)
		}
	}

	if req.EndDate != "" {
		if endDate, err := time.Parse("2006-01-02", req.EndDate); err == nil {
			query = query.Where("created_at <= ?", endDate.Add(24*time.Hour))
		}
	}

	// 获取总数
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页
	offset := (req.Page - 1) * req.PageSize
	if err := query.Offset(offset).Limit(req.PageSize).Order("created_at DESC").Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

// DeleteOldLogs 删除旧日志
func (r *auditLogRepository) DeleteOldLogs(days int) error {
	cutoffDate := time.Now().AddDate(0, 0, -days)
	return r.db.Where("created_at < ?", cutoffDate).Delete(&model.AuditLog{}).Error
}

// Select a bounded set first: MySQL and SQLite both support this without a
// dialect-specific DELETE LIMIT. Concurrent workers can safely delete the same IDs.
func (r *auditLogRepository) DeleteOldLogsBatch(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	var ids []uint
	db := r.db.WithContext(ctx)
	if err := db.Model(&model.AuditLog{}).Where("created_at < ?", before).Order("created_at, id").Limit(limit).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := db.Where("id IN ? AND created_at < ?", ids, before).Delete(&model.AuditLog{})
	return result.RowsAffected, result.Error
}

// GetStats 获取审计日志统计
func (r *auditLogRepository) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 总数
	var total int64
	if err := r.db.Model(&model.AuditLog{}).Count(&total).Error; err != nil {
		return nil, err
	}
	stats["total"] = total

	// 今日数量
	today := time.Now().Truncate(24 * time.Hour)
	var todayCount int64
	if err := r.db.Model(&model.AuditLog{}).Where("created_at >= ?", today).Count(&todayCount).Error; err != nil {
		return nil, err
	}
	stats["today"] = todayCount

	// 按动作统计
	var actionStats []struct {
		Action string
		Count  int64
	}
	if err := r.db.Model(&model.AuditLog{}).
		Select("action, COUNT(*) as count").
		Group("action").
		Order("count DESC").
		Limit(10).
		Scan(&actionStats).Error; err != nil {
		return nil, err
	}
	stats["by_action"] = actionStats

	// 按状态统计
	var statusStats []struct {
		Status string
		Count  int64
	}
	if err := r.db.Model(&model.AuditLog{}).
		Select("CASE WHEN status >= 200 AND status < 300 THEN 'success' WHEN status >= 400 THEN 'error' ELSE 'other' END as status, COUNT(*) as count").
		Group("status").
		Scan(&statusStats).Error; err != nil {
		return nil, err
	}
	stats["by_status"] = statusStats

	// 最活跃用户
	var userStats []struct {
		Username string
		Count    int64
	}
	if err := r.db.Model(&model.AuditLog{}).
		Select("username, COUNT(*) as count").
		Where("username != ''").
		Group("username").
		Order("count DESC").
		Limit(10).
		Scan(&userStats).Error; err != nil {
		return nil, err
	}
	stats["top_users"] = userStats

	return stats, nil
}
