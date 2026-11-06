package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// MockUserRepository Mock用户仓储
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *model.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id uint) (*model.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (*model.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*model.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockUserRepository) Update(id uint, req *model.UserUpdateRequest) error {
	args := m.Called(id, req)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(id uint, passwordHash string) error {
	args := m.Called(id, passwordHash)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) List(req *model.SearchRequest) ([]*model.User, int64, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Get(1).(int64), args.Error(2)
	}
	return args.Get(0).([]*model.User), args.Get(1).(int64), args.Error(2)
}

func (m *MockUserRepository) UpdateLastLogin(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockRoleRepository Mock角色仓储
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) Create(role *model.Role) error {
	args := m.Called(role)
	return args.Error(0)
}

func (m *MockRoleRepository) GetByID(id uint) (*model.Role, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Role), args.Error(1)
}

func (m *MockRoleRepository) GetByName(name string) (*model.Role, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Role), args.Error(1)
}

func (m *MockRoleRepository) Update(role *model.Role) error {
	args := m.Called(role)
	return args.Error(0)
}

func (m *MockRoleRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRoleRepository) List() ([]*model.Role, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*model.Role), args.Error(1)
}

var _ repository.UserRepository = (*MockUserRepository)(nil)
var _ repository.RoleRepository = (*MockRoleRepository)(nil)

func (m *MockUserRepository) UpdateProfile(id uint, req *model.UserProfileUpdateRequest) error {
	return m.Called(id, req).Error(0)
}
func (m *MockUserRepository) IncrementTokenVersion(id uint) error { return m.Called(id).Error(0) }
func (m *MockUserRepository) Begin2FASetup(id uint, version uint64, secret string, expires time.Time) error {
	return m.Called(id, version, secret, expires).Error(0)
}
func (m *MockUserRepository) Complete2FASetup(id uint, version uint64, secret string, hashes []string, step int64) error {
	return m.Called(id, version, secret, hashes, step).Error(0)
}
func (m *MockUserRepository) UseMFAProof(id uint, version uint64, challenge string, step int64, recovery string, disable bool) error {
	return m.Called(id, version, challenge, step, recovery, disable).Error(0)
}
func (m *MockUserRepository) CreateMFAChallenge(challenge *model.MFAChallenge) error {
	return m.Called(challenge).Error(0)
}
func (m *MockUserRepository) GetMFAChallenge(hash string) (*model.MFAChallenge, error) {
	args := m.Called(hash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.MFAChallenge), args.Error(1)
}
func (m *MockUserRepository) IncrementMFAChallengeAttempt(hash string) error {
	return m.Called(hash).Error(0)
}
func (m *MockUserRepository) CleanupMFAChallenges(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	args := m.Called(ctx, before, batchSize)
	return args.Get(0).(int64), args.Error(1)
}
