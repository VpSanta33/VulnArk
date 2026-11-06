package repository

import (
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"vulnark/internal/model"
)

// ReportRepository 报告仓储接口
type ReportRepository interface {
	Create(report *model.Report) error
	GetByID(id uint) (*model.Report, error)
	Update(report *model.Report) error
	Delete(id uint) error
	List(req *model.ReportSearchRequest) ([]*model.Report, int64, error)
	GetStats() (*model.ReportStats, error)
	UpdateStatus(id uint, status string) error
	GetByUploaderID(uploaderID uint) ([]*model.Report, error)
	QueueFileCleanup(paths []string) error
}

// reportRepository 报告仓储实现
type reportRepository struct {
	db *gorm.DB
}

// NewReportRepository 创建报告仓储
func NewReportRepository(db *gorm.DB) ReportRepository {
	return &reportRepository{
		db: db,
	}
}

// Create 创建报告
func (r *reportRepository) Create(report *model.Report) error {
	return r.db.Create(report).Error
}

// GetByID 根据ID获取报告
func (r *reportRepository) GetByID(id uint) (*model.Report, error) {
	var report model.Report
	err := r.db.Preload("Uploader").Preload("Reviewer").First(&report, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("报告不存在")
		}
		return nil, err
	}
	return &report, nil
}

// Update 更新报告
func (r *reportRepository) Update(report *model.Report) error {
	// Save falls back to INSERT when a concurrent delete wins. An UPDATE cannot
	// resurrect report metadata after its file was queued for cleanup.
	result := r.db.Model(&model.Report{}).Where("id = ?", report.ID).
		Select("title", "description", "type", "severity", "status", "asset_ids", "tags", "test_date", "reviewer_id", "review_notes", "updated_at").
		Updates(report)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// Delete 删除报告
func (r *reportRepository) Delete(id uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var report model.Report
		// Comment/attachment creation must lock the same parent row before
		// inserting, so nothing can be attached after this deletion commits.
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&report, id).Error; err != nil {
			return err
		}
		var commentIDs []uint
		if err := tx.Model(&model.ReportComment{}).Clauses(clause.Locking{Strength: "UPDATE"}).Where("report_id = ?", id).Pluck("id", &commentIDs).Error; err != nil {
			return err
		}
		attachments := tx.Model(&model.FileAttachment{}).Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("entity_type = ? AND entity_id = ?", model.EntityTypeReport, id)
		if report.FilePath != "" {
			attachments = attachments.Or("file_path = ?", report.FilePath)
		}
		if len(commentIDs) > 0 {
			attachments = attachments.Or("entity_type = ? AND entity_id IN ?", "report_comment", commentIDs)
		}
		var files []model.FileAttachment
		if err := attachments.Find(&files).Error; err != nil {
			return err
		}
		paths := []string{report.FilePath}
		ids := make([]uint, 0, len(files))
		for _, file := range files {
			paths = append(paths, file.FilePath)
			ids = append(ids, file.ID)
		}
		if err := EnqueueFileCleanup(tx, paths...); err != nil {
			return err
		}
		if len(ids) > 0 {
			if err := tx.Delete(&model.FileAttachment{}, ids).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("report_id = ?", id).Delete(&model.ReportComment{}).Error; err != nil {
			return err
		}
		return tx.Delete(&report).Error
	})
}

func (r *reportRepository) QueueFileCleanup(paths []string) error {
	return EnqueueFileCleanup(r.db, paths...)
}

// List 获取报告列表
func (r *reportRepository) List(req *model.ReportSearchRequest) ([]*model.Report, int64, error) {
	var reports []*model.Report
	var total int64

	query := r.db.Model(&model.Report{}).Preload("Uploader").Preload("Reviewer")

	// 搜索条件
	if req.Keyword != "" {
		query = query.Where("title LIKE ? OR description LIKE ?", "%"+req.Keyword+"%", "%"+req.Keyword+"%")
	}

	if req.Type != "" {
		query = query.Where("type = ?", req.Type)
	}

	if req.Severity != "" {
		query = query.Where("severity = ?", req.Severity)
	}

	if req.Status != "" {
		query = query.Where("status = ?", req.Status)
	}

	if req.UploaderID != "" {
		if uploaderID, err := strconv.ParseUint(req.UploaderID, 10, 32); err == nil {
			query = query.Where("uploader_id = ?", uint(uploaderID))
		}
	}

	if req.AssetID != "" {
		if assetID, err := strconv.ParseUint(req.AssetID, 10, 32); err == nil {
			query = query.Where("JSON_CONTAINS(asset_ids, ?)", assetID)
		}
	}

	if req.Tag != "" {
		query = query.Where("JSON_CONTAINS(tags, ?)", `"`+req.Tag+`"`)
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
	if err := query.Offset(offset).Limit(req.PageSize).Order("created_at DESC").Find(&reports).Error; err != nil {
		return nil, 0, err
	}

	return reports, total, nil
}

// GetStats 获取报告统计
func (r *reportRepository) GetStats() (*model.ReportStats, error) {
	stats := &model.ReportStats{
		ByType:     make(map[string]int64),
		BySeverity: make(map[string]int64),
		ByStatus:   make(map[string]int64),
	}

	// 总数
	if err := r.db.Model(&model.Report{}).Count(&stats.Total).Error; err != nil {
		return nil, err
	}

	// 按类型统计
	var typeStats []struct {
		Type  string
		Count int64
	}
	if err := r.db.Model(&model.Report{}).
		Select("type, COUNT(*) as count").
		Group("type").
		Scan(&typeStats).Error; err != nil {
		return nil, err
	}
	for _, stat := range typeStats {
		stats.ByType[stat.Type] = stat.Count
	}

	// 按严重程度统计
	var severityStats []struct {
		Severity string
		Count    int64
	}
	if err := r.db.Model(&model.Report{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityStats).Error; err != nil {
		return nil, err
	}
	for _, stat := range severityStats {
		stats.BySeverity[stat.Severity] = stat.Count
	}

	// 按状态统计
	var statusStats []struct {
		Status string
		Count  int64
	}
	if err := r.db.Model(&model.Report{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Scan(&statusStats).Error; err != nil {
		return nil, err
	}
	for _, stat := range statusStats {
		stats.ByStatus[stat.Status] = stat.Count
	}

	// 总文件大小
	var totalSize struct {
		TotalSize int64
	}
	if err := r.db.Model(&model.Report{}).
		Select("SUM(file_size) as total_size").
		Scan(&totalSize).Error; err != nil {
		return nil, err
	}
	stats.TotalSize = totalSize.TotalSize

	// 最近报告
	var recentReports []model.ReportSummary
	if err := r.db.Table("reports r").
		Select("r.id, r.title, r.type, r.severity, r.status, r.file_size, r.created_at, u.real_name as uploader_name").
		Joins("LEFT JOIN users u ON r.uploader_id = u.id").
		Order("r.created_at DESC").
		Limit(10).
		Scan(&recentReports).Error; err != nil {
		return nil, err
	}
	stats.RecentReports = recentReports

	return stats, nil
}

// UpdateStatus 更新报告状态
func (r *reportRepository) UpdateStatus(id uint, status string) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}

	// 根据状态设置相应的时间戳
	switch status {
	case model.ReportStatusSubmitted:
		updates["submitted_at"] = time.Now()
	case model.ReportStatusReviewing:
		// 不需要额外时间戳
	case model.ReportStatusApproved, model.ReportStatusRejected:
		updates["reviewed_at"] = time.Now()
	}

	return r.db.Model(&model.Report{}).Where("id = ?", id).Updates(updates).Error
}

// GetByUploaderID 根据上传者ID获取报告列表
func (r *reportRepository) GetByUploaderID(uploaderID uint) ([]*model.Report, error) {
	var reports []*model.Report
	err := r.db.Preload("Uploader").Preload("Reviewer").
		Where("uploader_id = ?", uploaderID).
		Order("created_at DESC").
		Find(&reports).Error
	return reports, err
}

// ReportCommentRepository 报告评论仓储接口
type ReportCommentRepository interface {
	Create(comment *model.ReportComment) error
	GetByID(id uint) (*model.ReportComment, error)
	GetByReportID(reportID uint) ([]*model.ReportComment, error)
	Delete(id uint) error
	DeleteOwned(id uint, userID uint) error
}

// reportCommentRepository 报告评论仓储实现
type reportCommentRepository struct {
	db *gorm.DB
}

// NewReportCommentRepository 创建报告评论仓储
func NewReportCommentRepository(db *gorm.DB) ReportCommentRepository {
	return &reportCommentRepository{
		db: db,
	}
}

// Create 创建评论
func (r *reportCommentRepository) Create(comment *model.ReportComment) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var report model.Report
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&report, comment.ReportID).Error; err != nil {
			return err
		}
		return tx.Omit(clause.Associations).Create(comment).Error
	})
}

func (r *reportCommentRepository) GetByID(id uint) (*model.ReportComment, error) {
	var comment model.ReportComment
	if err := r.db.Preload("User").First(&comment, id).Error; err != nil {
		return nil, err
	}
	return &comment, nil
}

// GetByReportID 根据报告ID获取评论列表
func (r *reportCommentRepository) GetByReportID(reportID uint) ([]*model.ReportComment, error) {
	var comments []*model.ReportComment
	err := r.db.Preload("User").
		Where("report_id = ?", reportID).
		Order("created_at ASC").
		Find(&comments).Error
	return comments, err
}

// Delete 删除评论
func (r *reportCommentRepository) Delete(id uint) error {
	return r.delete(id, 0)
}

func (r *reportCommentRepository) DeleteOwned(id uint, userID uint) error {
	if userID == 0 {
		return errors.New("无权删除评论")
	}
	return r.delete(id, userID)
}

func (r *reportCommentRepository) delete(id uint, userID uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var comment model.ReportComment
		if err := tx.First(&comment, id).Error; err != nil {
			return err
		}
		var report model.Report
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&report, comment.ReportID).Error; err != nil {
			return err
		}
		query := tx.Clauses(clause.Locking{Strength: "UPDATE"})
		if userID != 0 {
			query = query.Where("user_id = ?", userID)
		}
		if err := query.First(&comment, id).Error; err != nil {
			return err
		}
		var paths []string
		attachments := tx.Model(&model.FileAttachment{}).Clauses(clause.Locking{Strength: "UPDATE"}).Where("entity_type = ? AND entity_id = ?", "report_comment", id)
		if err := attachments.Pluck("file_path", &paths).Error; err != nil {
			return err
		}
		if err := EnqueueFileCleanup(tx, paths...); err != nil {
			return err
		}
		if err := tx.Where("entity_type = ? AND entity_id = ?", "report_comment", id).Delete(&model.FileAttachment{}).Error; err != nil {
			return err
		}
		return tx.Delete(&comment).Error
	})
}

// FileAttachmentRepository 文件附件仓储接口
type FileAttachmentRepository interface {
	Create(attachment *model.FileAttachment) error
	GetByID(id uint) (*model.FileAttachment, error)
	GetByEntityID(entityType string, entityID uint) ([]*model.FileAttachment, error)
	Delete(id uint) error
	DeleteByFilePath(filePath string) error
}

// fileAttachmentRepository 文件附件仓储实现
type fileAttachmentRepository struct {
	db *gorm.DB
}

// NewFileAttachmentRepository 创建文件附件仓储
func NewFileAttachmentRepository(db *gorm.DB) FileAttachmentRepository {
	return &fileAttachmentRepository{
		db: db,
	}
}

// Create 创建文件附件
func (r *fileAttachmentRepository) Create(attachment *model.FileAttachment) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		switch attachment.EntityType {
		case model.EntityTypeReport:
			var report model.Report
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&report, attachment.EntityID).Error; err != nil {
				return err
			}
		case "report_comment":
			var comment model.ReportComment
			if err := tx.First(&comment, attachment.EntityID).Error; err != nil {
				return err
			}
			var report model.Report
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&report, comment.ReportID).Error; err != nil {
				return err
			}
			// Re-read under a current locking read after taking the parent lock.
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&model.ReportComment{}, attachment.EntityID).Error; err != nil {
				return err
			}
		}
		return tx.Omit(clause.Associations).Create(attachment).Error
	})
}

// GetByID 根据ID获取文件附件
func (r *fileAttachmentRepository) GetByID(id uint) (*model.FileAttachment, error) {
	var attachment model.FileAttachment
	err := r.db.Preload("Uploader").First(&attachment, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("文件不存在")
		}
		return nil, err
	}
	return &attachment, nil
}

// GetByEntityID 根据实体ID获取文件附件列表
func (r *fileAttachmentRepository) GetByEntityID(entityType string, entityID uint) ([]*model.FileAttachment, error) {
	var attachments []*model.FileAttachment
	err := r.db.Preload("Uploader").
		Where("entity_type = ? AND entity_id = ?", entityType, entityID).
		Order("created_at DESC").
		Find(&attachments).Error
	return attachments, err
}

// Delete 删除文件附件
func (r *fileAttachmentRepository) Delete(id uint) error {
	return r.delete("id = ?", id)
}

// DeleteByFilePath 根据文件路径删除文件附件
func (r *fileAttachmentRepository) DeleteByFilePath(filePath string) error {
	return r.delete("file_path = ?", filePath)
}

func (r *fileAttachmentRepository) delete(condition string, value interface{}) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var attachments []model.FileAttachment
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(condition, value).Find(&attachments).Error; err != nil {
			return err
		}
		paths := make([]string, 0, len(attachments))
		ids := make([]uint, 0, len(attachments))
		for _, attachment := range attachments {
			paths = append(paths, attachment.FilePath)
			ids = append(ids, attachment.ID)
		}
		if err := EnqueueFileCleanup(tx, paths...); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		return tx.Delete(&model.FileAttachment{}, ids).Error
	})
}
