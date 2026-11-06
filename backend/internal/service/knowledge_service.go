package service

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// KnowledgeService 知识库服务接口
type KnowledgeService interface {
	// 知识库管理
	CreateKnowledge(req *model.KnowledgeCreateRequest, authorID uint) (*model.KnowledgeBase, error)
	GetKnowledgeByID(id uint) (*model.KnowledgeBase, error)
	UpdateKnowledge(id uint, req *model.KnowledgeUpdateRequest) error
	DeleteKnowledge(id uint) error
	GetKnowledgeList(req *model.KnowledgeSearchRequest) (*model.PaginationResponse, error)
	GetKnowledgeStats() (*model.KnowledgeStats, error)

	// 知识库操作
	ViewKnowledge(id uint) error
	LikeKnowledge(id uint) error
	PublishKnowledge(id uint, reviewerID uint) error
	ArchiveKnowledge(id uint) error

	// 搜索和推荐
	SearchKnowledge(keyword string, limit int) ([]*model.KnowledgeBase, error)
	GetPopularKnowledge(limit int) ([]*model.KnowledgeBase, error)
	GetRecentKnowledge(limit int) ([]*model.KnowledgeBase, error)
	GetRelatedKnowledge(id uint, limit int) ([]*model.KnowledgeBase, error)
}

// knowledgeService 知识库服务实现
type knowledgeService struct {
	db            *gorm.DB
	knowledgeRepo repository.KnowledgeRepository
	tagRepo       repository.TagRepository
	userRepo      repository.UserRepository
}

// NewKnowledgeService 创建知识库服务
func NewKnowledgeService(db *gorm.DB, knowledgeRepo repository.KnowledgeRepository, tagRepo repository.TagRepository, userRepo repository.UserRepository) KnowledgeService {
	return &knowledgeService{
		db:            db,
		knowledgeRepo: knowledgeRepo,
		tagRepo:       tagRepo,
		userRepo:      userRepo,
	}
}

// CreateKnowledge 创建知识库
func (s *knowledgeService) CreateKnowledge(req *model.KnowledgeCreateRequest, authorID uint) (*model.KnowledgeBase, error) {
	// 验证作者是否存在
	if _, err := s.userRepo.GetByID(authorID); err != nil {
		return nil, errors.New("作者不存在")
	}

	knowledge := &model.KnowledgeBase{
		Title:    req.Title,
		Content:  req.Content,
		Summary:  req.Summary,
		Category: req.Category,
		Type:     req.Type,
		Severity: req.Severity,
		Status:   model.KBStatusDraft,
		AuthorID: authorID,
		Metadata: req.Metadata,
	}

	knowledge.Tags = strings.Join(normalizeKnowledgeTags(req.Tags), ",")
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		txService := s.withKnowledgeTransaction(tx)
		if err := txService.knowledgeRepo.Create(knowledge); err != nil {
			return fmt.Errorf("创建知识库失败: %w", err)
		}
		return txService.handleKnowledgeTags(knowledge, req.Tags, authorID)
	}); err != nil {
		return nil, err
	}
	return knowledge, nil
}

// GetKnowledgeByID 根据ID获取知识库
func (s *knowledgeService) GetKnowledgeByID(id uint) (*model.KnowledgeBase, error) {
	return s.knowledgeRepo.GetByID(id)
}

// UpdateKnowledge 更新知识库
func (s *knowledgeService) UpdateKnowledge(id uint, req *model.KnowledgeUpdateRequest) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.withKnowledgeTransaction(tx).updateKnowledge(id, req)
	})
}

func (s *knowledgeService) updateKnowledge(id uint, req *model.KnowledgeUpdateRequest) error {
	knowledge, err := s.knowledgeRepo.GetByIDForUpdate(id)
	if err != nil {
		return err
	}

	// 更新字段
	if req.Title != "" {
		knowledge.Title = req.Title
	}
	if req.Content != "" {
		knowledge.Content = req.Content
	}
	if req.Summary != "" {
		knowledge.Summary = req.Summary
	}
	if req.Category != "" {
		knowledge.Category = req.Category
	}
	if req.Type != "" {
		knowledge.Type = req.Type
	}
	if req.Severity != "" {
		knowledge.Severity = req.Severity
	}
	if req.Status != "" {
		knowledge.Status = req.Status
	}
	if req.Metadata != nil {
		knowledge.Metadata = req.Metadata
	}

	// 未提供标签时保留原值，空数组则清空；正文先写入，任一步失败整笔回滚。
	if err := s.knowledgeRepo.Update(knowledge); err != nil {
		return err
	}
	if req.Tags != nil {
		return s.handleKnowledgeTags(knowledge, req.Tags, knowledge.AuthorID)
	}
	return nil
}

// DeleteKnowledge 删除知识库
func (s *knowledgeService) DeleteKnowledge(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		txRepo := repository.NewKnowledgeRepository(tx)
		if _, err := txRepo.GetByIDForUpdate(id); err != nil {
			return err
		}
		if err := txRepo.SetKnowledgeTags(id, nil); err != nil {
			return err
		}
		return txRepo.Delete(id)
	})
}

// GetKnowledgeList 获取知识库列表
func (s *knowledgeService) GetKnowledgeList(req *model.KnowledgeSearchRequest) (*model.PaginationResponse, error) {
	knowledges, total, err := s.knowledgeRepo.List(req)
	if err != nil {
		return nil, err
	}

	return model.NewPaginationResponse(total, req.Page, req.PageSize, knowledges), nil
}

// GetKnowledgeStats 获取知识库统计
func (s *knowledgeService) GetKnowledgeStats() (*model.KnowledgeStats, error) {
	return s.knowledgeRepo.GetStats()
}

// ViewKnowledge 浏览知识库
func (s *knowledgeService) ViewKnowledge(id uint) error {
	// 检查知识库是否存在
	if _, err := s.knowledgeRepo.GetByID(id); err != nil {
		return err
	}

	return s.knowledgeRepo.IncrementViewCount(id)
}

// LikeKnowledge 点赞知识库
func (s *knowledgeService) LikeKnowledge(id uint) error {
	// 检查知识库是否存在
	if _, err := s.knowledgeRepo.GetByID(id); err != nil {
		return err
	}

	return s.knowledgeRepo.IncrementLikeCount(id)
}

// PublishKnowledge 发布知识库
func (s *knowledgeService) PublishKnowledge(id uint, reviewerID uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return s.withKnowledgeTransaction(tx).publishKnowledge(id, reviewerID)
	})
}

func (s *knowledgeService) publishKnowledge(id uint, reviewerID uint) error {
	knowledge, err := s.knowledgeRepo.GetByIDForUpdate(id)
	if err != nil {
		return err
	}

	// 验证审核人是否存在
	if _, err := s.userRepo.GetByID(reviewerID); err != nil {
		return errors.New("审核人不存在")
	}

	now := time.Now()
	knowledge.Status = model.KBStatusPublished
	knowledge.ReviewerID = &reviewerID
	knowledge.ReviewedAt = &now
	knowledge.PublishedAt = &now

	return s.knowledgeRepo.Update(knowledge)
}

// ArchiveKnowledge 归档知识库
func (s *knowledgeService) ArchiveKnowledge(id uint) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		txRepo := repository.NewKnowledgeRepository(tx)
		knowledge, err := txRepo.GetByIDForUpdate(id)
		if err != nil {
			return err
		}
		knowledge.Status = model.KBStatusArchived
		return txRepo.Update(knowledge)
	})
}

// SearchKnowledge 搜索知识库
func (s *knowledgeService) SearchKnowledge(keyword string, limit int) ([]*model.KnowledgeBase, error) {
	return s.knowledgeRepo.Search(keyword, limit)
}

// GetPopularKnowledge 获取热门知识库
func (s *knowledgeService) GetPopularKnowledge(limit int) ([]*model.KnowledgeBase, error) {
	return s.knowledgeRepo.GetPopular(limit)
}

// GetRecentKnowledge 获取最新知识库
func (s *knowledgeService) GetRecentKnowledge(limit int) ([]*model.KnowledgeBase, error) {
	return s.knowledgeRepo.GetRecent(limit)
}

// GetRelatedKnowledge 获取相关知识库
func (s *knowledgeService) GetRelatedKnowledge(id uint, limit int) ([]*model.KnowledgeBase, error) {
	// 获取当前知识库
	knowledge, err := s.knowledgeRepo.GetByID(id)
	if err != nil {
		return nil, err
	}

	// 基于分类和标签查找相关知识库
	req := &model.KnowledgeSearchRequest{
		Category: knowledge.Category,
		Status:   model.KBStatusPublished,
		PaginationRequest: model.PaginationRequest{
			Page:     1,
			PageSize: limit,
		},
	}

	knowledges, _, err := s.knowledgeRepo.List(req)
	if err != nil {
		return nil, err
	}

	// 过滤掉当前知识库
	var related []*model.KnowledgeBase
	for _, kb := range knowledges {
		if kb.ID != id {
			related = append(related, kb)
		}
	}

	return related, nil
}

func (s *knowledgeService) withKnowledgeTransaction(tx *gorm.DB) *knowledgeService {
	return &knowledgeService{
		db:            tx,
		knowledgeRepo: repository.NewKnowledgeRepository(tx),
		tagRepo:       repository.NewTagRepository(tx),
		userRepo:      repository.NewUserRepository(tx),
	}
}

// normalizeKnowledgeTags 对旧逗号文本字段使用相同的规范化，避免文本与关联不一致。
func normalizeKnowledgeTags(tagNames []string) []string {
	seen := make(map[string]bool)
	var names []string
	for _, input := range tagNames {
		for _, name := range strings.Split(input, ",") {
			name = strings.TrimSpace(name)
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// handleKnowledgeTags 所有错误必须传回正文事务；使用次数由关联差量统一维护。
func (s *knowledgeService) handleKnowledgeTags(knowledge *model.KnowledgeBase, tagNames []string, creatorID uint) error {
	names := normalizeKnowledgeTags(tagNames)
	orderedNames := append([]string(nil), names...)
	sort.Strings(orderedNames)
	tagsByName := make(map[string]*model.Tag, len(names))
	for _, name := range orderedNames {
		tag, err := s.tagRepo.GetOrCreate(name, creatorID)
		if err != nil {
			return err
		}
		tagsByName[name] = tag
	}
	var tagIDs []uint
	var canonicalNames []string
	seen := make(map[uint]bool)
	for _, name := range names {
		tag := tagsByName[name]
		if !seen[tag.ID] {
			seen[tag.ID] = true
			tagIDs = append(tagIDs, tag.ID)
			canonicalNames = append(canonicalNames, tag.Name)
		}
	}
	if err := s.knowledgeRepo.SetKnowledgeTags(knowledge.ID, tagIDs); err != nil {
		return err
	}
	knowledge.Tags = strings.Join(canonicalNames, ",")
	return nil
}

// TagService 标签服务接口
type TagService interface {
	CreateTag(req *model.TagCreateRequest, creatorID uint) (*model.Tag, error)
	GetTagByID(id uint) (*model.Tag, error)
	UpdateTag(id uint, req *model.TagUpdateRequest) error
	DeleteTag(id uint) error
	GetTagList() ([]*model.Tag, error)
	GetTagsByCategory(category string) ([]*model.Tag, error)
	GetPopularTags(limit int) ([]*model.Tag, error)
}

// tagService 标签服务实现
type tagService struct {
	tagRepo repository.TagRepository
}

// NewTagService 创建标签服务
func NewTagService(tagRepo repository.TagRepository) TagService {
	return &tagService{
		tagRepo: tagRepo,
	}
}

// CreateTag 创建标签
func (s *tagService) CreateTag(req *model.TagCreateRequest, creatorID uint) (*model.Tag, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("标签名称不能为空")
	}
	if _, err := s.tagRepo.GetByName(name); err == nil {
		return nil, errors.New("标签名称已存在")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	tag := &model.Tag{
		Name:        name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Color:       req.Color,
		Category:    req.Category,
		CreatorID:   creatorID,
	}

	if tag.Color == "" {
		tag.Color = "#007bff"
	}

	if err := s.tagRepo.Create(tag); err != nil {
		return nil, errors.New("创建标签失败")
	}

	return tag, nil
}

// GetTagByID 根据ID获取标签
func (s *tagService) GetTagByID(id uint) (*model.Tag, error) {
	return s.tagRepo.GetByID(id)
}

// UpdateTag 更新标签
func (s *tagService) UpdateTag(id uint, req *model.TagUpdateRequest) error {
	tag, err := s.tagRepo.GetByID(id)
	if err != nil {
		return err
	}

	// 更新字段
	if req.DisplayName != "" {
		tag.DisplayName = req.DisplayName
	}
	if req.Description != "" {
		tag.Description = req.Description
	}
	if req.Color != "" {
		tag.Color = req.Color
	}
	if req.Category != "" {
		tag.Category = req.Category
	}

	return s.tagRepo.Update(tag)
}

// DeleteTag 删除标签
func (s *tagService) DeleteTag(id uint) error {
	// 检查标签是否存在
	if _, err := s.tagRepo.GetByID(id); err != nil {
		return err
	}

	return s.tagRepo.Delete(id)
}

// GetTagList 获取标签列表
func (s *tagService) GetTagList() ([]*model.Tag, error) {
	return s.tagRepo.List()
}

// GetTagsByCategory 根据分类获取标签列表
func (s *tagService) GetTagsByCategory(category string) ([]*model.Tag, error) {
	return s.tagRepo.GetByCategory(category)
}

// GetPopularTags 获取热门标签
func (s *tagService) GetPopularTags(limit int) ([]*model.Tag, error) {
	return s.tagRepo.GetPopular(limit)
}

// TemplateService 模板服务接口
type TemplateService interface {
	CreateTemplate(req *model.TemplateCreateRequest, creatorID uint) (*model.Template, error)
	GetTemplateByID(id uint) (*model.Template, error)
	GetTemplateByName(name string) (*model.Template, error)
	UpdateTemplate(id uint, req *model.TemplateUpdateRequest) error
	DeleteTemplate(id uint) error
	GetTemplateList() ([]*model.Template, error)
	GetTemplatesByType(templateType string) ([]*model.Template, error)
	GetTemplatesByCategory(category string) ([]*model.Template, error)
	UseTemplate(id uint) error
}

// templateService 模板服务实现
type templateService struct {
	templateRepo repository.TemplateRepository
}

// NewTemplateService 创建模板服务
func NewTemplateService(templateRepo repository.TemplateRepository) TemplateService {
	return &templateService{
		templateRepo: templateRepo,
	}
}

// CreateTemplate 创建模板
func (s *templateService) CreateTemplate(req *model.TemplateCreateRequest, creatorID uint) (*model.Template, error) {
	// 检查模板名称是否已存在
	if _, err := s.templateRepo.GetByName(req.Name); err == nil {
		return nil, errors.New("模板名称已存在")
	}

	template := &model.Template{
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Type:        req.Type,
		Category:    req.Category,
		Content:     req.Content,
		Variables:   req.Variables,
		CreatorID:   creatorID,
	}

	if err := s.templateRepo.Create(template); err != nil {
		return nil, errors.New("创建模板失败")
	}

	return template, nil
}

// GetTemplateByID 根据ID获取模板
func (s *templateService) GetTemplateByID(id uint) (*model.Template, error) {
	return s.templateRepo.GetByID(id)
}

// GetTemplateByName 根据名称获取模板
func (s *templateService) GetTemplateByName(name string) (*model.Template, error) {
	return s.templateRepo.GetByName(name)
}

// UpdateTemplate 更新模板
func (s *templateService) UpdateTemplate(id uint, req *model.TemplateUpdateRequest) error {
	template, err := s.templateRepo.GetByID(id)
	if err != nil {
		return err
	}

	// 更新字段
	if req.DisplayName != "" {
		template.DisplayName = req.DisplayName
	}
	if req.Description != "" {
		template.Description = req.Description
	}
	if req.Content != "" {
		template.Content = req.Content
	}
	if req.Variables != "" {
		template.Variables = req.Variables
	}
	if req.IsActive != nil {
		template.IsActive = *req.IsActive
	}

	return s.templateRepo.Update(template)
}

// DeleteTemplate 删除模板
func (s *templateService) DeleteTemplate(id uint) error {
	// 检查模板是否存在
	if _, err := s.templateRepo.GetByID(id); err != nil {
		return err
	}

	return s.templateRepo.Delete(id)
}

// GetTemplateList 获取模板列表
func (s *templateService) GetTemplateList() ([]*model.Template, error) {
	return s.templateRepo.List()
}

// GetTemplatesByType 根据类型获取模板列表
func (s *templateService) GetTemplatesByType(templateType string) ([]*model.Template, error) {
	return s.templateRepo.GetByType(templateType)
}

// GetTemplatesByCategory 根据分类获取模板列表
func (s *templateService) GetTemplatesByCategory(category string) ([]*model.Template, error) {
	return s.templateRepo.GetByCategory(category)
}

// UseTemplate 使用模板
func (s *templateService) UseTemplate(id uint) error {
	// 检查模板是否存在
	if _, err := s.templateRepo.GetByID(id); err != nil {
		return err
	}

	return s.templateRepo.IncrementUsageCount(id)
}
