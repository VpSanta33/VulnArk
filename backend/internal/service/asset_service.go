package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// AssetService 资产服务接口
type AssetService interface {
	CreateAsset(req *model.AssetCreateRequest) (*model.Asset, error)
	GetAssetByID(id uint) (*model.AssetInfo, error)
	UpdateAsset(id uint, req *model.AssetUpdateRequest) error
	DeleteAsset(id uint) error
	GetAssetList(req *model.AssetSearchRequest) (*model.PaginationResponse, error)
	GetAssetStats() (*model.AssetStats, error)
	ImportAssets(req *model.AssetImportRequest) ([]string, error)
	ValidateAsset(req *model.AssetCreateRequest) error
}

// ConfigureAssetRisk lets asset edits refresh the risk score of the
// vulnerabilities on that asset.
func ConfigureAssetRisk(a AssetService, risk RiskService) {
	if implementation, ok := a.(*assetService); ok {
		implementation.risk = risk
	}
}

// assetService 资产服务实现
type assetService struct {
	assetRepo repository.AssetRepository
	userRepo  repository.UserRepository
	risk      RiskService
}

// NewAssetService 创建资产服务
func NewAssetService(assetRepo repository.AssetRepository, userRepo repository.UserRepository) AssetService {
	return &assetService{
		assetRepo: assetRepo,
		userRepo:  userRepo,
	}
}

// CreateAsset 创建资产
func (s *assetService) CreateAsset(req *model.AssetCreateRequest) (*model.Asset, error) {
	// 验证资产数据
	if err := s.ValidateAsset(req); err != nil {
		return nil, err
	}

	// 检查资产名称是否已存在
	if existAsset, err := s.assetRepo.GetByName(req.Name); err != nil {
		return nil, err
	} else if existAsset != nil {
		return nil, errors.New("资产名称已存在")
	}

	// 检查IP地址是否已存在（如果提供了IP地址）
	if req.IPAddress != "" {
		if existAsset, err := s.assetRepo.GetByIPAddress(req.IPAddress); err != nil {
			return nil, err
		} else if existAsset != nil {
			return nil, errors.New("IP地址已被使用")
		}
	}

	// 验证负责人是否存在
	if req.OwnerID != nil {
		if _, err := s.userRepo.GetByID(*req.OwnerID); err != nil {
			return nil, errors.New("指定的负责人不存在")
		}
	}

	asset := &model.Asset{
		Name:            req.Name,
		Type:            req.Type,
		Category:        req.Category,
		IPAddress:       req.IPAddress,
		Domain:          req.Domain,
		Port:            req.Port,
		OS:              req.OS,
		Version:         req.Version,
		Department:      req.Department,
		OwnerID:         req.OwnerID,
		BusinessLine:    req.BusinessLine,
		ImportanceLevel: req.ImportanceLevel,
		Description:     req.Description,
		Status:          1, // 默认正常状态
		InternetFacing:  req.InternetFacing,
		NetworkZone:     req.NetworkZone,
	}
	if asset.NetworkZone == "" {
		asset.NetworkZone = model.NetworkZoneInternal
	}

	// 设置默认重要性等级
	if asset.ImportanceLevel == 0 {
		asset.ImportanceLevel = model.ImportanceLevelLow
	}

	if err := s.assetRepo.Create(asset); err != nil {
		return nil, errors.New("创建资产失败")
	}

	return asset, nil
}

// GetAssetByID 根据ID获取资产
func (s *assetService) GetAssetByID(id uint) (*model.AssetInfo, error) {
	asset, err := s.assetRepo.GetByID(id)
	if err != nil {
		return nil, err
	}

	info := asset.ToAssetInfo()
	return &info, nil
}

// UpdateAsset 更新资产
func (s *assetService) UpdateAsset(id uint, req *model.AssetUpdateRequest) error {
	asset, err := s.assetRepo.GetByID(id)
	if err != nil {
		return err
	}
	previousImportance := asset.ImportanceLevel

	// 更新字段
	if req.Name != "" {
		// 检查名称是否已存在（排除当前资产）
		if existAsset, err := s.assetRepo.GetByName(req.Name); err != nil {
			return err
		} else if existAsset != nil && existAsset.ID != id {
			return errors.New("资产名称已存在")
		}
		asset.Name = req.Name
	}

	if req.Type != "" {
		asset.Type = req.Type
	}

	if req.Category != "" {
		asset.Category = req.Category
	}

	if req.IPAddress != "" {
		// 检查IP地址是否已存在（排除当前资产）
		if existAsset, err := s.assetRepo.GetByIPAddress(req.IPAddress); err != nil {
			return err
		} else if existAsset != nil && existAsset.ID != id {
			return errors.New("IP地址已被使用")
		}
		asset.IPAddress = req.IPAddress
	}

	if req.Domain != "" {
		asset.Domain = req.Domain
	}

	if req.Port != "" {
		asset.Port = req.Port
	}

	if req.OS != "" {
		asset.OS = req.OS
	}

	if req.Version != "" {
		asset.Version = req.Version
	}

	if req.Department != "" {
		asset.Department = req.Department
	}

	if req.OwnerID != nil {
		// 验证负责人是否存在
		if _, err := s.userRepo.GetByID(*req.OwnerID); err != nil {
			return errors.New("指定的负责人不存在")
		}
		asset.OwnerID = req.OwnerID
	}

	if req.BusinessLine != "" {
		asset.BusinessLine = req.BusinessLine
	}

	if req.ImportanceLevel != nil {
		asset.ImportanceLevel = *req.ImportanceLevel
	}

	if req.Description != "" {
		asset.Description = req.Description
	}

	if req.Status != nil {
		asset.Status = *req.Status
	}

	riskInputsChanged := asset.ImportanceLevel != previousImportance
	if req.InternetFacing != nil && asset.InternetFacing != *req.InternetFacing {
		asset.InternetFacing = *req.InternetFacing
		riskInputsChanged = true
	}
	if req.NetworkZone != "" && asset.EffectiveNetworkZone() != req.NetworkZone {
		asset.NetworkZone = req.NetworkZone
		riskInputsChanged = true
	}

	if err := s.assetRepo.Update(asset); err != nil {
		return err
	}
	if riskInputsChanged && s.risk != nil {
		// The asset is already saved; a scoring failure is repaired by the
		// next rescoring pass and must not fail the edit.
		if _, err := s.risk.Rescore(context.Background(), repository.RiskRescoreScope{AssetID: id}, time.Now()); err != nil {
			logrus.WithError(err).Warn("资产变更后的风险评分暂未刷新")
		}
	}
	return nil
}

// DeleteAsset 删除资产
func (s *assetService) DeleteAsset(id uint) error {
	// 检查资产是否存在
	if _, err := s.assetRepo.GetByID(id); err != nil {
		return err
	}

	// 仓储在锁定资产的事务中检查关联漏洞并拒绝删除。
	return s.assetRepo.Delete(id)
}

// GetAssetList 获取资产列表
func (s *assetService) GetAssetList(req *model.AssetSearchRequest) (*model.PaginationResponse, error) {
	assets, total, err := s.assetRepo.List(req)
	if err != nil {
		return nil, err
	}

	// 转换为资产信息
	var assetInfos []model.AssetInfo
	for _, asset := range assets {
		assetInfos = append(assetInfos, asset.ToAssetInfo())
	}

	return model.NewPaginationResponse(total, req.Page, req.PageSize, assetInfos), nil
}

// GetAssetStats 获取资产统计
func (s *assetService) GetAssetStats() (*model.AssetStats, error) {
	return s.assetRepo.GetStats()
}

// ImportAssets 批量导入资产
func (s *assetService) ImportAssets(req *model.AssetImportRequest) ([]string, error) {
	var errors []string
	var validAssets []*model.Asset

	// 验证每个资产
	for i, assetReq := range req.Assets {
		if err := s.ValidateAsset(&assetReq); err != nil {
			errors = append(errors, fmt.Sprintf("第%d行: %s", i+1, err.Error()))
			continue
		}

		// 检查资产名称是否已存在
		if existAsset, _ := s.assetRepo.GetByName(assetReq.Name); existAsset != nil {
			errors = append(errors, fmt.Sprintf("第%d行: 资产名称'%s'已存在", i+1, assetReq.Name))
			continue
		}

		// 检查IP地址是否已存在（如果提供了IP地址）
		if assetReq.IPAddress != "" {
			if existAsset, _ := s.assetRepo.GetByIPAddress(assetReq.IPAddress); existAsset != nil {
				errors = append(errors, fmt.Sprintf("第%d行: IP地址'%s'已被使用", i+1, assetReq.IPAddress))
				continue
			}
		}

		// 验证负责人是否存在
		if assetReq.OwnerID != nil {
			if _, err := s.userRepo.GetByID(*assetReq.OwnerID); err != nil {
				errors = append(errors, fmt.Sprintf("第%d行: 指定的负责人不存在", i+1))
				continue
			}
		}

		asset := &model.Asset{
			Name:            assetReq.Name,
			Type:            assetReq.Type,
			Category:        assetReq.Category,
			IPAddress:       assetReq.IPAddress,
			Domain:          assetReq.Domain,
			Port:            assetReq.Port,
			OS:              assetReq.OS,
			Version:         assetReq.Version,
			Department:      assetReq.Department,
			OwnerID:         assetReq.OwnerID,
			BusinessLine:    assetReq.BusinessLine,
			ImportanceLevel: assetReq.ImportanceLevel,
			Description:     assetReq.Description,
			Status:          1, // 默认正常状态
			InternetFacing:  assetReq.InternetFacing,
			NetworkZone:     assetReq.NetworkZone,
		}
		if asset.NetworkZone == "" {
			asset.NetworkZone = model.NetworkZoneInternal
		}

		// 设置默认重要性等级
		if asset.ImportanceLevel == 0 {
			asset.ImportanceLevel = model.ImportanceLevelLow
		}

		validAssets = append(validAssets, asset)
	}

	// 如果有有效的资产，则批量创建
	if len(validAssets) > 0 {
		if err := s.assetRepo.BatchCreate(validAssets); err != nil {
			errors = append(errors, "批量创建资产失败: "+err.Error())
		}
	}

	return errors, nil
}

// ValidateAsset 验证资产数据
func (s *assetService) ValidateAsset(req *model.AssetCreateRequest) error {
	if req.Name == "" {
		return errors.New("资产名称不能为空")
	}

	if req.Type == "" {
		return errors.New("资产类型不能为空")
	}

	// 验证资产类型
	validTypes := []string{model.AssetTypeServer, model.AssetTypeDatabase, model.AssetTypeApplication, model.AssetTypeNetwork}
	isValidType := false
	for _, validType := range validTypes {
		if req.Type == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return errors.New("无效的资产类型")
	}

	// 验证重要性等级
	if req.ImportanceLevel != 0 {
		if req.ImportanceLevel < 1 || req.ImportanceLevel > 3 {
			return errors.New("无效的重要性等级")
		}
	}

	switch req.NetworkZone {
	case "", model.NetworkZoneInternal, model.NetworkZoneDMZ, model.NetworkZoneProduction, model.NetworkZoneOT, model.NetworkZoneTest:
	default:
		return errors.New("无效的网络区域")
	}

	return nil
}
