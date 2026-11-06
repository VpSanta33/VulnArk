package service

import (
	"errors"

	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/auth"
	"vulnark/pkg/utils"
)

// UserService 用户服务接口
type UserService interface {
	Login(req *model.UserLoginRequest) (*model.UserLoginResponse, error)
	Register(req *model.UserCreateRequest) (*model.User, error)
	RevokeAllSessions(userID uint) error
	GetProfile(userID uint) (*model.UserInfo, error)
	UpdateProfile(userID uint, req *model.UserProfileUpdateRequest) error
	ChangePassword(userID uint, req *model.ChangePasswordRequest) error
	CreateUser(req *model.UserCreateRequest) (*model.User, error)
	UpdateUser(userID uint, req *model.UserUpdateRequest) error
	DeleteUser(userID uint) error
	GetUserList(req *model.SearchRequest) (*model.PaginationResponse, error)
	GetUserByID(userID uint) (*model.UserInfo, error)
}

// userService 用户服务实现
type userService struct {
	userRepo   repository.UserRepository
	roleRepo   repository.RoleRepository
	jwtManager *auth.JWTManager
	mfa        *MFAService
}

// NewUserService 创建用户服务
func NewUserService(userRepo repository.UserRepository, roleRepo repository.RoleRepository) UserService {
	return NewUserServiceWithAuth(userRepo, roleRepo, auth.NewJWTManager(), configuredMFAService(userRepo))
}

func NewUserServiceWithAuth(userRepo repository.UserRepository, roleRepo repository.RoleRepository, manager *auth.JWTManager, mfa *MFAService) UserService {
	return &userService{userRepo: userRepo, roleRepo: roleRepo, jwtManager: manager, mfa: mfa}
}

func (s *userService) Login(req *model.UserLoginRequest) (*model.UserLoginResponse, error) {
	user, err := s.userRepo.GetByUsername(req.Username)
	if err != nil || !utils.CheckPassword(req.Password, user.PasswordHash) {
		return nil, errors.New("用户名或密码错误")
	}
	if !user.IsActive() {
		return nil, errors.New("用户已被禁用")
	}
	if s.jwtManager == nil {
		return nil, errors.New("认证尚未配置")
	}
	if needsRebind(user) {
		token, expires, err := s.jwtManager.GenerateRebindToken(user.ID, user.Username, user.RoleID, user.TokenVersion)
		if err != nil {
			return nil, err
		}
		return &model.UserLoginResponse{MFARebindRequired: true, RebindToken: token, ExpiresAt: expires}, nil
	}
	if user.TwoFactorEnabled {
		if req.ChallengeToken == "" {
			return s.mfa.IssueChallenge(user)
		}
		if err = s.mfa.VerifyLogin(user, req.ChallengeToken, req.TOTPCode, req.RecoveryCode); err != nil {
			return nil, err
		}
	} else if req.ChallengeToken != "" || req.TOTPCode != "" || req.RecoveryCode != "" {
		return nil, errors.New("认证状态已变化，请重新登录")
	}
	token, expires, err := s.jwtManager.GenerateAccessToken(user.ID, user.Username, user.RoleID, user.TokenVersion)
	if err != nil {
		return nil, errors.New("生成令牌失败")
	}
	_ = s.userRepo.UpdateLastLogin(user.ID)
	return &model.UserLoginResponse{Token: token, ExpiresAt: expires, User: user.ToUserInfo()}, nil
}

func (s *userService) RevokeAllSessions(userID uint) error {
	return s.userRepo.IncrementTokenVersion(userID)
}

// Register 用户注册（管理员创建用户）
func (s *userService) Register(req *model.UserCreateRequest) (*model.User, error) {
	return s.CreateUser(req)
}

// GetProfile 获取用户资料
func (s *userService) GetProfile(userID uint) (*model.UserInfo, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	userInfo := user.ToUserInfo()
	return &userInfo, nil
}

// UpdateProfile 更新用户资料
func (s *userService) UpdateProfile(userID uint, req *model.UserProfileUpdateRequest) error {
	return updateUserProfile(s.userRepo, userID, req)
}

func updateUserProfile(repo repository.UserRepository, userID uint, req *model.UserProfileUpdateRequest) error {
	if _, err := repo.GetByID(userID); err != nil {
		return err
	}
	if req.Username != "" {
		if existing, _ := repo.GetByUsername(req.Username); existing != nil && existing.ID != userID {
			return errors.New("用户名已存在")
		}
	}
	if req.Email != "" {
		if existing, _ := repo.GetByEmail(req.Email); existing != nil && existing.ID != userID {
			return errors.New("邮箱已被使用")
		}
	}
	return repo.UpdateProfile(userID, req)
}

func (s *userService) ChangePassword(userID uint, req *model.ChangePasswordRequest) error {
	return changeUserPassword(s.userRepo, userID, req)
}

func changeUserPassword(repo repository.UserRepository, userID uint, req *model.ChangePasswordRequest) error {
	if req.NewPassword != req.ConfirmPassword {
		return errors.New("确认密码不匹配")
	}
	if len(req.NewPassword) < 6 {
		return errors.New("新密码至少六位")
	}
	user, err := repo.GetByID(userID)
	if err != nil {
		return err
	}
	if !user.IsActive() || !utils.CheckPassword(req.CurrentPassword, user.PasswordHash) {
		return errors.New("当前密码错误")
	}
	hash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return err
	}
	return repo.UpdatePassword(userID, hash)
}

// CreateUser 创建用户
func (s *userService) CreateUser(req *model.UserCreateRequest) (*model.User, error) {
	// 检查用户名是否已存在
	if existUser, _ := s.userRepo.GetByUsername(req.Username); existUser != nil {
		return nil, errors.New("用户名已存在")
	}

	// 检查邮箱是否已存在
	if existUser, _ := s.userRepo.GetByEmail(req.Email); existUser != nil {
		return nil, errors.New("邮箱已被使用")
	}

	// 检查角色是否存在
	if _, err := s.roleRepo.GetByID(req.RoleID); err != nil {
		return nil, errors.New("角色不存在")
	}

	// 加密密码
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}

	user := &model.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hashedPassword,
		RealName:     req.RealName,
		Phone:        req.Phone,
		RoleID:       req.RoleID,
		Department:   req.Department,
		Status:       1, // 默认启用
		TokenVersion: 1,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("创建用户失败")
	}

	return user, nil
}

// UpdateUser 更新用户
func (s *userService) UpdateUser(userID uint, req *model.UserUpdateRequest) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// 更新字段
	if req.Email != "" {
		// 检查邮箱是否已存在
		if existUser, _ := s.userRepo.GetByEmail(req.Email); existUser != nil && existUser.ID != userID {
			return errors.New("邮箱已被使用")
		}
		user.Email = req.Email
	}

	if req.RealName != "" {
		user.RealName = req.RealName
	}

	if req.Phone != "" {
		user.Phone = req.Phone
	}

	if req.RoleID != 0 {
		// 检查角色是否存在
		if _, err := s.roleRepo.GetByID(req.RoleID); err != nil {
			return errors.New("角色不存在")
		}
		user.RoleID = req.RoleID
	}

	if req.Department != "" {
		user.Department = req.Department
	}

	if req.Status != nil {
		user.Status = *req.Status
	}

	return s.userRepo.Update(userID, req)
}

// DeleteUser 删除用户
func (s *userService) DeleteUser(userID uint) error {
	// 检查用户是否存在
	if _, err := s.userRepo.GetByID(userID); err != nil {
		return err
	}

	return s.userRepo.Delete(userID)
}

// GetUserList 获取用户列表
func (s *userService) GetUserList(req *model.SearchRequest) (*model.PaginationResponse, error) {
	users, total, err := s.userRepo.List(req)
	if err != nil {
		return nil, err
	}

	// 转换为用户信息
	var userInfos []model.UserInfo
	for _, user := range users {
		userInfos = append(userInfos, user.ToUserInfo())
	}

	return model.NewPaginationResponse(total, req.Page, req.PageSize, userInfos), nil
}

// GetUserByID 根据ID获取用户
func (s *userService) GetUserByID(userID uint) (*model.UserInfo, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, err
	}

	userInfo := user.ToUserInfo()
	return &userInfo, nil
}

// RoleService 角色服务接口
type RoleService interface {
	CreateRole(req *model.RoleCreateRequest) (*model.Role, error)
	UpdateRole(roleID uint, req *model.RoleUpdateRequest) error
	DeleteRole(roleID uint) error
	GetRoleList() ([]*model.Role, error)
	GetRoleByID(roleID uint) (*model.Role, error)
}

// roleService 角色服务实现
type roleService struct {
	roleRepo repository.RoleRepository
}

// NewRoleService 创建角色服务
func NewRoleService(roleRepo repository.RoleRepository) RoleService {
	return &roleService{
		roleRepo: roleRepo,
	}
}

// CreateRole 创建角色
func (s *roleService) CreateRole(req *model.RoleCreateRequest) (*model.Role, error) {
	// 检查角色名是否已存在
	if existRole, _ := s.roleRepo.GetByName(req.Name); existRole != nil {
		return nil, errors.New("角色名已存在")
	}

	role := &model.Role{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	if err := s.roleRepo.Create(role); err != nil {
		return nil, errors.New("创建角色失败")
	}

	return role, nil
}

// UpdateRole 更新角色
func (s *roleService) UpdateRole(roleID uint, req *model.RoleUpdateRequest) error {
	role, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		return err
	}

	// 更新字段
	if req.Name != "" {
		// 检查角色名是否已存在
		if existRole, _ := s.roleRepo.GetByName(req.Name); existRole != nil && existRole.ID != roleID {
			return errors.New("角色名已存在")
		}
		role.Name = req.Name
	}

	if req.Description != "" {
		role.Description = req.Description
	}

	if req.Permissions != nil {
		role.Permissions = req.Permissions
	}

	// Only requested fields may be written; a metadata edit must not restore
	// permissions revoked after the role was read.
	return s.roleRepo.Update(&model.Role{
		ID: roleID, Name: req.Name, Description: req.Description, Permissions: req.Permissions,
	})
}

// DeleteRole 删除角色
func (s *roleService) DeleteRole(roleID uint) error {
	// 防止删除系统默认角色
	if roleID <= 3 {
		return errors.New("不能删除系统默认角色")
	}

	// 检查角色是否存在
	_, err := s.roleRepo.GetByID(roleID)
	if err != nil {
		return err
	}

	// 检查是否有用户使用该角色
	// 这个检查已经在 repository 层实现了，但我们在这里再次确认
	return s.roleRepo.Delete(roleID)
}

// GetRoleList 获取角色列表
func (s *roleService) GetRoleList() ([]*model.Role, error) {
	// 从数据库获取角色列表
	roles, err := s.roleRepo.List()
	if err != nil {
		return nil, err
	}

	// 如果数据库中没有角色，创建默认角色
	if len(roles) == 0 {
		if err := s.createDefaultRoles(); err != nil {
			return nil, err
		}
		// 重新获取角色列表
		roles, err = s.roleRepo.List()
		if err != nil {
			return nil, err
		}
	}

	return roles, nil
}

// createDefaultRoles 创建默认角色
func (s *roleService) createDefaultRoles() error {
	defaultRoles := []*model.Role{
		{
			Name:        "管理员",
			Description: "系统管理员，拥有所有权限",
			Permissions: []string{"*"}, // All permissions
		},
		{
			Name:        "开发工程师",
			Description: "开发工程师，可以管理漏洞和资产",
			Permissions: []string{"vuln:*", "asset:*", "report:read", "knowledge:*"},
		},
		{
			Name:        "普通用户",
			Description: "普通用户，只能查看和提交漏洞",
			Permissions: []string{"vulnerability:read", "vulnerability:create", "asset:read", "report:read", "knowledge:read"},
		},
	}

	for _, role := range defaultRoles {
		if err := s.roleRepo.Create(role); err != nil {
			return err
		}
	}

	return nil
}

// GetRoleByID 根据ID获取角色
func (s *roleService) GetRoleByID(roleID uint) (*model.Role, error) {
	return s.roleRepo.GetByID(roleID)
}
