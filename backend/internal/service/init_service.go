package service

import (
	"fmt"

	"vulnark/internal/repository"
	"vulnark/pkg/database"
)

// InitService validates runtime readiness; provisioning is an explicit deployment
// action so a production restart never performs DDL or creates accounts.
type InitService interface {
	InitializeSystem() error
	CreateDefaultAdminUser() (string, error)
	ResetAdminPassword() (string, error)
}

type initService struct {
	userRepo repository.UserRepository
}

func NewInitService(userRepo repository.UserRepository) InitService {
	return &initService{userRepo: userRepo}
}

func (s *initService) InitializeSystem() error {
	if err := database.CheckMigrations(); err != nil {
		return fmt.Errorf("系统数据库未就绪: %w", err)
	}
	return nil
}

// Retained for source compatibility. First administrator provisioning belongs to
// the versioned migration, which writes exclusive 0600 credentials exactly once.
func (s *initService) CreateDefaultAdminUser() (string, error) {
	return "", fmt.Errorf("请显式执行 -migrate 初始化空库管理员；现有用户不会被覆盖")
}

func (s *initService) ResetAdminPassword() (string, error) {
	return "", fmt.Errorf("请使用经认证的密码修改或管理员恢复流程")
}
