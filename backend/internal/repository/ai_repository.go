package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"vulnark/internal/model"
)

// AIRepository AI仓储接口
type AIRepository interface {
	// AI配置管理
	GetAIConfiguration(userID uint) (*model.AIConfiguration, error)
	SaveAIConfiguration(config *model.AIConfiguration) error
	UpdateAIConfiguration(userID uint, config *model.AIConfigurationRequest) error
	DeleteAIConfiguration(userID uint) error

	// AI对话管理
	CreateConversation(userID uint, title string) (*model.AIConversation, error)
	GetConversation(userID uint, sessionID string) (*model.AIConversation, error)
	GetUserConversations(userID uint, limit, offset int) ([]model.AIConversation, int64, error)
	AcquireConversation(ctx context.Context, userID uint, sessionID string, lease time.Duration) (*model.AIConversation, error)
	CommitConversation(ctx context.Context, userID uint, sessionID, token string, version uint64, messages []model.AIMessage, tokensUsed int) error
	ReleaseConversation(ctx context.Context, userID uint, sessionID, token string, version uint64) error
	DeleteConversation(userID uint, sessionID string) error
	ArchiveConversation(userID uint, sessionID string) error

	// AI使用统计
	GetUsageStats(userID uint) (*model.AIUsageStats, error)
}

// aiRepository AI仓储实现
type aiRepository struct {
	db *gorm.DB
}

// generateSessionID 生成会话ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate random identifier: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// NewAIRepository 创建AI仓储
func NewAIRepository(db *gorm.DB) AIRepository {
	return &aiRepository{
		db: db,
	}
}

// GetAIConfiguration 获取用户AI配置
func (r *aiRepository) GetAIConfiguration(userID uint) (*model.AIConfiguration, error) {
	var config model.AIConfiguration
	err := r.db.Where("user_id = ?", userID).First(&config).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // 返回nil表示未配置
		}
		return nil, err
	}
	return &config, nil
}

// SaveAIConfiguration 保存AI配置
func (r *aiRepository) SaveAIConfiguration(config *model.AIConfiguration) error {
	return r.db.Save(config).Error
}

// UpdateAIConfiguration 更新AI配置
func (r *aiRepository) UpdateAIConfiguration(userID uint, req *model.AIConfigurationRequest) error {
	// 查找现有配置
	var config model.AIConfiguration
	err := r.db.Where("user_id = ?", userID).First(&config).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 创建新配置
			config = model.AIConfiguration{
				UserID:      userID,
				Provider:    req.Provider,
				APIKey:      req.APIKey,
				APIURL:      req.APIURL,
				Model:       req.Model,
				MaxTokens:   req.MaxTokens,
				Temperature: req.Temperature,
				Timeout:     req.Timeout,
				Enabled:     req.Enabled,
			}
			return r.db.Create(&config).Error
		}
		return err
	}

	// Omit an unchanged secret from the SQL update so a concurrent key rotation
	// cannot be overwritten by a settings form that left the key blank.
	updates := map[string]interface{}{
		"provider": req.Provider, "api_url": req.APIURL, "model": req.Model,
		"max_tokens": req.MaxTokens, "temperature": req.Temperature,
		"timeout": req.Timeout, "enabled": req.Enabled,
	}
	if req.ClearAPIKey {
		updates["api_key"] = ""
	} else if req.APIKey != "" {
		updates["api_key"] = req.APIKey
	}
	return r.db.Model(&model.AIConfiguration{}).Where("id = ? AND user_id = ?", config.ID, userID).Updates(updates).Error
}

// DeleteAIConfiguration 删除AI配置
func (r *aiRepository) DeleteAIConfiguration(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.AIConfiguration{}).Error
}

// CreateConversation 创建新对话
func (r *aiRepository) CreateConversation(userID uint, title string) (*model.AIConversation, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	conversation := &model.AIConversation{
		UserID:    userID,
		SessionID: sessionID,
		Title:     title,
		Messages:  "[]", // 空的JSON数组
		Status:    "active",
	}

	err = r.db.Create(conversation).Error
	if err != nil {
		return nil, err
	}

	return conversation, nil
}

// GetConversation 获取对话
func (r *aiRepository) GetConversation(userID uint, sessionID string) (*model.AIConversation, error) {
	var conversation model.AIConversation
	err := r.db.Where("user_id = ? AND session_id = ?", userID, sessionID).First(&conversation).Error
	if err != nil {
		return nil, err
	}
	return &conversation, nil
}

// GetUserConversations 获取用户对话列表
func (r *aiRepository) GetUserConversations(userID uint, limit, offset int) ([]model.AIConversation, int64, error) {
	var conversations []model.AIConversation
	var total int64

	// 获取总数
	err := r.db.Model(&model.AIConversation{}).Where("user_id = ? AND status != ?", userID, "deleted").Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// 获取分页数据
	err = r.db.Where("user_id = ? AND status != ?", userID, "deleted").
		Order("updated_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&conversations).Error

	return conversations, total, err
}

var (
	ErrAIConversationBusy     = errors.New("AI会话正在处理其他消息，请稍后重试")
	ErrAIConversationInactive = errors.New("AI会话已删除或归档")
	ErrAILeaseLost            = errors.New("AI会话处理租约已失效，请重新发送")
)

// databaseNow keeps lease expiry decisions on one clock across application processes.
func databaseNow(db *gorm.DB) (time.Time, error) {
	if db.Dialector.Name() == "mysql" {
		var value sql.NullTime
		if err := db.Raw("SELECT CURRENT_TIMESTAMP(6)").Row().Scan(&value); err != nil {
			return time.Time{}, err
		}
		if !value.Valid {
			return time.Time{}, errors.New("database returned no clock value")
		}
		return value.Time, nil
	}
	return time.Now().UTC(), nil
}

// AcquireConversation atomically reserves a history snapshot. No transaction stays
// open while the provider is called; every claim advances the fencing version.
func (r *aiRepository) AcquireConversation(ctx context.Context, userID uint, sessionID string, lease time.Duration) (*model.AIConversation, error) {
	if lease <= 0 || lease > 3*time.Minute {
		return nil, errors.New("invalid AI lease duration")
	}
	token, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	db := r.db.WithContext(ctx)
	now, err := databaseNow(db)
	if err != nil {
		return nil, err
	}
	result := db.Model(&model.AIConversation{}).
		Where("user_id = ? AND session_id = ? AND status = ?", userID, sessionID, "active").
		Where("lease_until IS NULL OR lease_until <= ?", now).
		Updates(map[string]interface{}{
			"lease_token": token, "lease_until": now.Add(lease),
			"version": gorm.Expr("version + 1"),
		})
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected != 1 {
		var conversation model.AIConversation
		if err := db.Where("user_id = ? AND session_id = ?", userID, sessionID).First(&conversation).Error; err != nil {
			return nil, err
		}
		if conversation.Status != "active" {
			return nil, ErrAIConversationInactive
		}
		return nil, ErrAIConversationBusy
	}
	var conversation model.AIConversation
	if err := db.Where("user_id = ? AND session_id = ? AND lease_token = ? AND status = ?", userID, sessionID, token, "active").First(&conversation).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAILeaseLost, err)
	}
	return &conversation, nil
}

func databaseClockExpression(db *gorm.DB, fallback time.Time) interface{} {
	if db.Dialector.Name() == "mysql" {
		return gorm.Expr("CURRENT_TIMESTAMP(6)")
	}
	return fallback
}

// CommitConversation fences stale, cancelled and deleted/archived work and adds
// usage atomically instead of writing an earlier read of the token total.
func (r *aiRepository) CommitConversation(ctx context.Context, userID uint, sessionID, token string, version uint64, messages []model.AIMessage, tokensUsed int) error {
	if token == "" || tokensUsed < 0 {
		return ErrAILeaseLost
	}
	messagesJSON, err := json.Marshal(messages)
	if err != nil {
		return err
	}
	db := r.db.WithContext(ctx)
	now, err := databaseNow(db)
	if err != nil {
		return err
	}
	result := db.Model(&model.AIConversation{}).
		Where("user_id = ? AND session_id = ? AND status = ? AND version = ? AND lease_token = ? AND lease_until > ?", userID, sessionID, "active", version, token, databaseClockExpression(db, now)).
		Updates(map[string]interface{}{
			"messages": string(messagesJSON), "tokens_used": gorm.Expr("tokens_used + ?", tokensUsed),
			"lease_token": "", "lease_until": nil, "version": gorm.Expr("version + 1"),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrAILeaseLost
	}
	return nil
}

func (r *aiRepository) ReleaseConversation(ctx context.Context, userID uint, sessionID, token string, version uint64) error {
	return r.db.WithContext(ctx).Model(&model.AIConversation{}).
		Where("user_id = ? AND session_id = ? AND lease_token = ? AND version = ?", userID, sessionID, token, version).
		Updates(map[string]interface{}{"lease_token": "", "lease_until": nil}).Error
}

func (r *aiRepository) changeConversationStatus(userID uint, sessionID, status string) error {
	result := r.db.Model(&model.AIConversation{}).Where("user_id = ? AND session_id = ? AND status != ?", userID, sessionID, "deleted").
		Updates(map[string]interface{}{"status": status, "version": gorm.Expr("version + 1"), "lease_token": "", "lease_until": nil})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *aiRepository) DeleteConversation(userID uint, sessionID string) error {
	return r.changeConversationStatus(userID, sessionID, "deleted")
}

func (r *aiRepository) ArchiveConversation(userID uint, sessionID string) error {
	return r.changeConversationStatus(userID, sessionID, "archived")
}

// GetUsageStats 获取使用统计
func (r *aiRepository) GetUsageStats(userID uint) (*model.AIUsageStats, error) {
	var stats model.AIUsageStats

	// 总对话数
	var totalConversations int64
	err := r.db.Model(&model.AIConversation{}).
		Where("user_id = ? AND status != ?", userID, "deleted").
		Count(&totalConversations).Error
	if err != nil {
		return nil, err
	}
	stats.TotalConversations = int(totalConversations)

	// 活跃会话数
	var activeSessions int64
	err = r.db.Model(&model.AIConversation{}).
		Where("user_id = ? AND status = ?", userID, "active").
		Count(&activeSessions).Error
	if err != nil {
		return nil, err
	}
	stats.ActiveSessions = int(activeSessions)

	// 总消息数和token数（需要解析JSON）
	var conversations []model.AIConversation
	err = r.db.Select("messages, tokens_used").
		Where("user_id = ? AND status != ?", userID, "deleted").
		Find(&conversations).Error
	if err != nil {
		return nil, err
	}

	for _, conv := range conversations {
		var messages []model.AIMessage
		if err := json.Unmarshal([]byte(conv.Messages), &messages); err == nil {
			stats.TotalMessages += len(messages)
		}
		stats.TotalTokens += conv.TokensUsed
	}

	return &stats, nil
}
