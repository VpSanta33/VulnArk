package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

const (
	RetestResultPass = "pass"
	RetestResultFail = "fail"
)

// VulnerabilityRetest stores an independent verification attempt. Evidence
// paths are private storage metadata and are omitted from JSON responses.
type VulnerabilityRetest struct {
	ID                  uint                            `json:"id" gorm:"primarykey"`
	CreatedAt           time.Time                       `json:"created_at"`
	VulnerabilityID     uint                            `json:"vulnerability_id" gorm:"not null;index"`
	TesterID            uint                            `json:"tester_id" gorm:"not null;index"`
	FixerID             *uint                           `json:"fixer_id,omitempty" gorm:"index"`
	Result              string                          `json:"result" gorm:"size:10;not null"`
	Summary             string                          `json:"summary" gorm:"type:text;not null"`
	EvidenceAttachments VulnerabilityRetestEvidenceList `json:"evidence_attachments,omitempty" gorm:"type:json"`
	PreviousStatus      string                          `json:"previous_status" gorm:"size:20;not null"`
	NewStatus           string                          `json:"new_status" gorm:"size:20;not null"`

	Vulnerability Vulnerability `json:"-" gorm:"foreignKey:VulnerabilityID"`
	Tester        User          `json:"-" gorm:"foreignKey:TesterID"`
}

// TableName specifies the retest table name.
func (VulnerabilityRetest) TableName() string { return "vulnerability_retests" }

// VulnerabilityRetestEvidence is private metadata for an evidence object.
type VulnerabilityRetestEvidence struct {
	Filename     string `json:"filename,omitempty"`
	OriginalName string `json:"original_name,omitempty"`
	FilePath     string `json:"-"`
	FileSize     int64  `json:"file_size,omitempty"`
	FileType     string `json:"file_type,omitempty"`
	MimeType     string `json:"mime_type,omitempty"`
}

// VulnerabilityRetestEvidenceList persists display metadata and the private
// storage path in one JSON column while keeping the path response-safe.
type VulnerabilityRetestEvidenceList []VulnerabilityRetestEvidence

func (e VulnerabilityRetestEvidenceList) Value() (driver.Value, error) {
	type persistedEvidence struct {
		Filename     string `json:"filename,omitempty"`
		OriginalName string `json:"original_name,omitempty"`
		FilePath     string `json:"path,omitempty"`
		FileSize     int64  `json:"file_size,omitempty"`
		FileType     string `json:"file_type,omitempty"`
		MimeType     string `json:"mime_type,omitempty"`
	}
	items := make([]persistedEvidence, 0, len(e))
	for _, item := range e {
		items = append(items, persistedEvidence{
			Filename: item.Filename, OriginalName: item.OriginalName,
			FilePath: item.FilePath, FileSize: item.FileSize,
			FileType: item.FileType, MimeType: item.MimeType,
		})
	}
	if len(items) == 0 {
		return "[]", nil
	}
	return json.Marshal(items)
}

func (e *VulnerabilityRetestEvidenceList) Scan(value interface{}) error {
	if value == nil {
		*e = VulnerabilityRetestEvidenceList{}
		return nil
	}
	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return errors.New("复测证据必须为string或[]byte")
	}
	type persistedEvidence struct {
		Filename     string `json:"filename,omitempty"`
		OriginalName string `json:"original_name,omitempty"`
		FilePath     string `json:"path,omitempty"`
		FileSize     int64  `json:"file_size,omitempty"`
		FileType     string `json:"file_type,omitempty"`
		MimeType     string `json:"mime_type,omitempty"`
	}
	var items []persistedEvidence
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	result := make(VulnerabilityRetestEvidenceList, 0, len(items))
	for _, item := range items {
		result = append(result, VulnerabilityRetestEvidence{
			Filename: item.Filename, OriginalName: item.OriginalName,
			FilePath: item.FilePath, FileSize: item.FileSize,
			FileType: item.FileType, MimeType: item.MimeType,
		})
	}
	*e = result
	return nil
}

// VulnerabilityRetestEvidenceRequest carries trusted upload metadata from the
// controller to the service. Path is never decoded from a public JSON request.
type VulnerabilityRetestEvidenceRequest struct {
	Filename     string `json:"filename,omitempty"`
	OriginalName string `json:"original_name,omitempty"`
	Path         string `json:"-"`
	FileSize     int64  `json:"file_size,omitempty"`
	FileType     string `json:"file_type,omitempty"`
	MimeType     string `json:"mime_type,omitempty"`
}

// VulnerabilityRetestRequest is the POST /vulnerabilities/:id/retest body.
type VulnerabilityRetestRequest struct {
	Result              string                               `json:"result" binding:"required,oneof=pass fail"`
	Summary             string                               `json:"summary" binding:"required,min=1,max=10000"`
	EvidenceAttachments []VulnerabilityRetestEvidenceRequest `json:"evidence_attachments,omitempty"`
}

// VulnerabilityRetestEvidenceInfo is safe response metadata; it has no path.
type VulnerabilityRetestEvidenceInfo struct {
	Filename     string `json:"filename,omitempty"`
	OriginalName string `json:"original_name,omitempty"`
	FileSize     int64  `json:"file_size,omitempty"`
	FileType     string `json:"file_type,omitempty"`
	MimeType     string `json:"mime_type,omitempty"`
}

// VulnerabilityRetestInfo is the response representation of a retest.
type VulnerabilityRetestInfo struct {
	ID                  uint                              `json:"id"`
	CreatedAt           time.Time                         `json:"created_at"`
	VulnerabilityID     uint                              `json:"vulnerability_id"`
	TesterID            uint                              `json:"tester_id"`
	TesterName          string                            `json:"tester_name,omitempty"`
	FixerID             *uint                             `json:"fixer_id,omitempty"`
	Result              string                            `json:"result"`
	Summary             string                            `json:"summary"`
	EvidenceAttachments []VulnerabilityRetestEvidenceInfo `json:"evidence_attachments,omitempty"`
	PreviousStatus      string                            `json:"previous_status"`
	NewStatus           string                            `json:"new_status"`
}

func (r *VulnerabilityRetest) ToInfo() VulnerabilityRetestInfo {
	info := VulnerabilityRetestInfo{
		ID: r.ID, CreatedAt: r.CreatedAt, VulnerabilityID: r.VulnerabilityID,
		TesterID: r.TesterID, TesterName: r.Tester.RealName, FixerID: r.FixerID, Result: r.Result, Summary: r.Summary,
		PreviousStatus: r.PreviousStatus, NewStatus: r.NewStatus,
		EvidenceAttachments: make([]VulnerabilityRetestEvidenceInfo, 0, len(r.EvidenceAttachments)),
	}
	for _, item := range r.EvidenceAttachments {
		info.EvidenceAttachments = append(info.EvidenceAttachments, VulnerabilityRetestEvidenceInfo{
			Filename: item.Filename, OriginalName: item.OriginalName,
			FileSize: item.FileSize, FileType: item.FileType, MimeType: item.MimeType,
		})
	}
	return info
}
