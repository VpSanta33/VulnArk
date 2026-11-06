package service

import (
	"errors"
	"fmt"
	"reflect"

	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/utils"
)

// SettingsService 设置服务接口
type SettingsService interface {
	// 用户资料
	UpdateProfile(userID uint, req *model.UserProfileUpdateRequest) error
	ChangePassword(userID uint, req *model.ChangePasswordRequest) error

	// 双因素认证
	Setup2FA(userID uint) (*model.TwoFactorSetupResponse, error)
	Verify2FA(userID uint, code string) ([]string, error)
	Disable2FA(userID uint, code string) error
	Get2FAStatus(userID uint) (*model.TwoFactorStatusResponse, error)

	// 系统设置
	GetSystemSettings(userID uint) (*model.SystemSettings, error)
	UpdateSystemSettings(userID uint, req *model.SystemSettingsRequest) error

	// 通知设置
	GetNotificationSettings(userID uint) (*model.NotificationSettings, error)
	UpdateNotificationSettings(userID uint, req *model.NotificationSettingsRequest) error

	// 数据管理
	ExportUserData(userID uint, dataType string) ([]byte, error)
	ImportUserData(userID uint, data []byte, dataType string) error
	ClearCache(userID uint) error
	OptimizeDatabase(userID uint) error
}

// settingsService 设置服务实现
type settingsService struct {
	userRepo     repository.UserRepository
	settingsRepo repository.SettingsRepository
	mfa          *MFAService
}

// NewSettingsService 创建设置服务
func NewSettingsService(userRepo repository.UserRepository, settingsRepo repository.SettingsRepository, mfas ...*MFAService) SettingsService {
	mfa := configuredMFAService(userRepo)
	if len(mfas) > 0 {
		mfa = mfas[0]
	}
	return &settingsService{
		userRepo:     userRepo,
		settingsRepo: settingsRepo,
		mfa:          mfa,
	}
}

// UpdateProfile 更新用户资料
func (s *settingsService) UpdateProfile(userID uint, req *model.UserProfileUpdateRequest) error {
	return updateUserProfile(s.userRepo, userID, req)
}

func (s *settingsService) ChangePassword(userID uint, req *model.ChangePasswordRequest) error {
	return changeUserPassword(s.userRepo, userID, req)
}

// GetSystemSettings 获取系统设置
func (s *settingsService) GetSystemSettings(userID uint) (*model.SystemSettings, error) {
	return s.settingsRepo.GetSystemSettings(userID)
}

// UpdateSystemSettings 更新系统设置
func (s *settingsService) UpdateSystemSettings(userID uint, req *model.SystemSettingsRequest) error {
	// 获取当前设置
	currentSettings, err := s.settingsRepo.GetSystemSettings(userID)
	if err != nil {
		return err
	}

	// 更新非空字段
	if req.Theme != "" {
		currentSettings.Theme = req.Theme
	}
	if req.Language != "" {
		currentSettings.Language = req.Language
	}
	if req.Timezone != "" {
		currentSettings.Timezone = req.Timezone
	}
	if req.DateFormat != "" {
		currentSettings.DateFormat = req.DateFormat
	}
	if req.TimeFormat != "" {
		currentSettings.TimeFormat = req.TimeFormat
	}

	return s.settingsRepo.UpdateSystemSettings(userID, currentSettings)
}

// GetNotificationSettings 获取通知设置
func (s *settingsService) GetNotificationSettings(userID uint) (*model.NotificationSettings, error) {
	return s.settingsRepo.GetNotificationSettings(userID)
}

// UpdateNotificationSettings 更新通知设置
func (s *settingsService) UpdateNotificationSettings(userID uint, req *model.NotificationSettingsRequest) error {
	// 获取当前设置
	currentSettings, err := s.settingsRepo.GetNotificationSettings(userID)
	if err != nil {
		return err
	}

	// 使用反射更新非nil字段
	reqValue := reflect.ValueOf(req).Elem()
	settingsValue := reflect.ValueOf(currentSettings).Elem()
	reqType := reflect.TypeOf(req).Elem()

	for i := 0; i < reqValue.NumField(); i++ {
		field := reqValue.Field(i)
		fieldType := reqType.Field(i)

		// 跳过nil指针
		if field.IsNil() {
			continue
		}

		// 获取对应的设置字段
		settingsField := settingsValue.FieldByName(fieldType.Name)
		if settingsField.IsValid() && settingsField.CanSet() {
			settingsField.SetBool(field.Elem().Bool())
		}
	}

	return s.settingsRepo.UpdateNotificationSettings(userID, currentSettings)
}

// ExportUserData 导出用户数据
func (s *settingsService) ExportUserData(userID uint, dataType string) ([]byte, error) {
	// TODO: 实现数据导出逻辑
	// 这里可以根据dataType导出不同类型的数据
	// 例如：assets, vulnerabilities, reports, all

	switch dataType {
	case "profile":
		// 导出用户资料
		user, err := s.userRepo.GetByID(userID)
		if err != nil {
			return nil, err
		}
		return utils.ToJSON(user)
	case "settings":
		// 导出设置数据；任何一部分读取失败都必须显式失败，不能导出半份数据。
		systemSettings, err := s.settingsRepo.GetSystemSettings(userID)
		if err != nil {
			return nil, fmt.Errorf("读取系统设置失败: %w", err)
		}
		notificationSettings, err := s.settingsRepo.GetNotificationSettings(userID)
		if err != nil {
			return nil, fmt.Errorf("读取通知设置失败: %w", err)
		}

		data := map[string]interface{}{
			"system_settings":       systemSettings,
			"notification_settings": notificationSettings,
		}
		return utils.ToJSON(data)
	default:
		return nil, errors.New("不支持的数据类型")
	}
}

// ImportUserData 导入用户数据
func (s *settingsService) ImportUserData(userID uint, data []byte, dataType string) error {
	// TODO: 实现数据导入逻辑
	// 这里需要解析数据并更新相应的设置
	return errors.New("功能开发中")
}

// ClearCache 清理缓存
func (s *settingsService) ClearCache(userID uint) error {
	return errors.New("清理缓存功能尚未实现")
}

// OptimizeDatabase 优化数据库
func (s *settingsService) OptimizeDatabase(userID uint) error {
	return errors.New("数据库优化功能尚未实现")
}

func (s *settingsService) Setup2FA(userID uint) (*model.TwoFactorSetupResponse, error) {
	return s.mfa.Setup(userID)
}
func (s *settingsService) Verify2FA(userID uint, code string) ([]string, error) {
	return s.mfa.Confirm(userID, code)
}
func (s *settingsService) Disable2FA(userID uint, code string) error {
	return s.mfa.Disable(userID, code)
}
func (s *settingsService) Get2FAStatus(userID uint) (*model.TwoFactorStatusResponse, error) {
	if s.mfa == nil {
		return nil, errors.New("双因素认证尚未配置")
	}
	return s.mfa.Status(userID)
}
