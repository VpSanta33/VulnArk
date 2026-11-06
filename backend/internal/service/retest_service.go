package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/storage"
)

var (
	ErrRetestPermissionDenied = errors.New("缺少漏洞复测权限")
	ErrRetestAccessDenied     = errors.New("无权查看该漏洞复测记录")
	ErrRetestValidation       = errors.New("复测参数无效")
)

func invalidRetest(message string) error { return fmt.Errorf("%w: %s", ErrRetestValidation, message) }

// VulnerabilityRetestService owns verification and private evidence access.
type VulnerabilityRetestService interface {
	CreateRetest(vulnerabilityID, testerID uint, req *model.VulnerabilityRetestRequest) (*model.VulnerabilityRetestInfo, error)
	GetRetests(vulnerabilityID, requesterID uint) ([]model.VulnerabilityRetestInfo, error)
	GetRetestEvidence(vulnerabilityID, retestID uint, index int, requesterID uint) (*model.VulnerabilityRetestEvidence, error)
	QueueFileCleanup(paths []string) error
}

type vulnerabilityRetestService struct {
	retestRepo        repository.VulnerabilityRetestRepository
	vulnerabilityRepo repository.VulnerabilityRepository
	permissionService PermissionService
}

func NewVulnerabilityRetestService(retestRepo repository.VulnerabilityRetestRepository, vulnerabilityRepo repository.VulnerabilityRepository, permissionService PermissionService) VulnerabilityRetestService {
	return &vulnerabilityRetestService{retestRepo: retestRepo, vulnerabilityRepo: vulnerabilityRepo, permissionService: permissionService}
}

func NewRetestService(retestRepo repository.VulnerabilityRetestRepository, vulnerabilityRepo repository.VulnerabilityRepository, permissionService PermissionService) VulnerabilityRetestService {
	return NewVulnerabilityRetestService(retestRepo, vulnerabilityRepo, permissionService)
}

func (s *vulnerabilityRetestService) CreateRetest(vulnerabilityID, testerID uint, req *model.VulnerabilityRetestRequest) (*model.VulnerabilityRetestInfo, error) {
	if testerID == 0 || s.permissionService == nil {
		return nil, ErrRetestPermissionDenied
	}
	allowed, err := s.permissionService.CheckUserPermission(testerID, "vuln:verify")
	if err != nil {
		return nil, errors.New("复测权限检查失败")
	}
	if !allowed {
		return nil, ErrRetestPermissionDenied
	}
	if vulnerabilityID == 0 || req == nil {
		return nil, invalidRetest("复测参数无效")
	}
	if req.Result != model.RetestResultPass && req.Result != model.RetestResultFail {
		return nil, invalidRetest("复测结果必须为pass或fail")
	}
	summary := strings.TrimSpace(req.Summary)
	if summary == "" || utf8.RuneCountInString(summary) > 10000 {
		return nil, invalidRetest("复测摘要不能为空且不能超过10000个字符")
	}
	maxSize, maxFiles, _ := storage.UploadLimits()
	if len(req.EvidenceAttachments) > maxFiles {
		return nil, invalidRetest("复测证据数量超过限制")
	}
	evidence := make(model.VulnerabilityRetestEvidenceList, 0, len(req.EvidenceAttachments))
	var total int64
	for _, item := range req.EvidenceAttachments {
		// Only trusted upload metadata is accepted by the service. The public
		// controller ignores client paths and creates this metadata via Storage.
		if !filepath.IsLocal(item.Path) || !strings.HasPrefix(item.Path, "attachments/") || strings.Contains(item.Path, "\\") || strings.Contains(item.Path, "../") {
			return nil, invalidRetest("复测证据无效")
		}
		if item.FileSize <= 0 || item.FileSize > maxSize || len(item.Filename) > 255 || len(item.OriginalName) > 255 {
			return nil, invalidRetest("复测证据大小或文件名无效")
		}
		total += item.FileSize
		if total > storage.MaxScreenshotTotalSize {
			return nil, invalidRetest("复测证据总大小超过限制")
		}
		evidence = append(evidence, model.VulnerabilityRetestEvidence{
			Filename: item.Filename, OriginalName: item.OriginalName, FilePath: item.Path,
			FileSize: item.FileSize, FileType: item.FileType, MimeType: item.MimeType,
		})
	}
	// A verification grant alone does not assign this finding to the tester.
	// Authorize the same resource scope used for private history before writing.
	if _, err := s.authorizedRetests(vulnerabilityID, testerID); err != nil {
		return nil, err
	}
	global := false
	for _, permission := range []string{"vuln:manage", "system:audit"} {
		allowed, err := s.permissionService.CheckUserPermission(testerID, permission)
		if err != nil {
			return nil, errors.New("复测权限检查失败")
		}
		global = global || allowed
	}
	result := &model.VulnerabilityRetest{VulnerabilityID: vulnerabilityID, TesterID: testerID, Result: req.Result, Summary: summary, EvidenceAttachments: evidence}
	if err := s.retestRepo.CreateRetestAndTransition(result, repository.RetestAccess{Global: global}); err != nil {
		return nil, err
	}
	info := result.ToInfo()
	return &info, nil
}

// authorizedRetests requires vuln:read plus participation in this vulnerability
// (assignee, discoverer, or previous tester), or explicit management/audit access.
func (s *vulnerabilityRetestService) authorizedRetests(vulnerabilityID, requesterID uint) ([]*model.VulnerabilityRetest, error) {
	if requesterID == 0 || s.permissionService == nil {
		return nil, ErrRetestPermissionDenied
	}
	readAllowed, err := s.permissionService.CheckUserPermission(requesterID, "vuln:read")
	if err != nil {
		return nil, errors.New("复测读取权限检查失败")
	}
	if !readAllowed {
		return nil, ErrRetestPermissionDenied
	}
	if vulnerabilityID == 0 || s.vulnerabilityRepo == nil {
		return nil, invalidRetest("复测参数无效")
	}
	vulnerability, err := s.vulnerabilityRepo.GetByID(vulnerabilityID)
	if err != nil {
		return nil, err
	}
	items, err := s.retestRepo.ListRetests(vulnerabilityID)
	if err != nil {
		return nil, err
	}
	participant := (vulnerability.AssigneeID != nil && *vulnerability.AssigneeID == requesterID) ||
		(vulnerability.DiscovererID != nil && *vulnerability.DiscovererID == requesterID) ||
		(vulnerability.Asset.OwnerID != nil && *vulnerability.Asset.OwnerID == requesterID)
	for _, item := range items {
		if item != nil && (item.TesterID == requesterID || (item.FixerID != nil && *item.FixerID == requesterID)) {
			participant = true
		}
	}
	if !participant {
		for _, permission := range []string{"vuln:manage", "system:audit"} {
			allowed, err := s.permissionService.CheckUserPermission(requesterID, permission)
			if err != nil {
				return nil, errors.New("复测读取权限检查失败")
			}
			if allowed {
				participant = true
				break
			}
		}
	}
	if !participant {
		return nil, ErrRetestAccessDenied
	}
	return items, nil
}

func (s *vulnerabilityRetestService) GetRetests(vulnerabilityID, requesterID uint) ([]model.VulnerabilityRetestInfo, error) {
	items, err := s.authorizedRetests(vulnerabilityID, requesterID)
	if err != nil {
		return nil, err
	}
	result := make([]model.VulnerabilityRetestInfo, 0, len(items))
	for _, item := range items {
		if item != nil {
			result = append(result, item.ToInfo())
		}
	}
	return result, nil
}

func (s *vulnerabilityRetestService) GetRetestEvidence(vulnerabilityID, retestID uint, index int, requesterID uint) (*model.VulnerabilityRetestEvidence, error) {
	items, err := s.authorizedRetests(vulnerabilityID, requesterID)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item != nil && item.ID == retestID && index >= 0 && index < len(item.EvidenceAttachments) {
			evidence := item.EvidenceAttachments[index]
			return &evidence, nil
		}
	}
	return nil, repository.ErrRetestNotFound
}

func (s *vulnerabilityRetestService) QueueFileCleanup(paths []string) error {
	if s.vulnerabilityRepo == nil {
		return errors.New("附件清理服务不可用")
	}
	return s.vulnerabilityRepo.QueueFileCleanup(paths)
}
