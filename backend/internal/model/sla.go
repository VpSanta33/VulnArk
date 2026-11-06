package model

import (
	"encoding/json"
	"time"
)

// SLAPolicy defines response and fix budgets for a severity. AssetID and
// Department are optional overrides; the most specific enabled policy wins.
type SLAPolicy struct {
	ID            uint      `json:"id" gorm:"primarykey"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Name          string    `json:"name" gorm:"size:100;not null"`
	SeverityLevel int       `json:"severity_level" gorm:"not null;index"`
	AssetID       *uint     `json:"asset_id" gorm:"index"`
	Department    string    `json:"department" gorm:"size:100;index"`
	ResponseHours int       `json:"response_hours" gorm:"not null"`
	FixHours      int       `json:"fix_hours" gorm:"not null"`
	Enabled       bool      `json:"enabled" gorm:"index"`
}

func (SLAPolicy) TableName() string { return "sla_policies" }

type SLAPolicyCreateRequest struct {
	Name          string `json:"name" binding:"required,min=1,max=100"`
	SeverityLevel int    `json:"severity_level" binding:"required,oneof=1 2 3 4"`
	AssetID       *uint  `json:"asset_id"`
	Department    string `json:"department" binding:"max=100"`
	ResponseHours int    `json:"response_hours" binding:"required,min=1"`
	FixHours      int    `json:"fix_hours" binding:"required,min=1"`
	Enabled       *bool  `json:"enabled"`
}

type SLAPolicyUpdateRequest struct {
	Name          string `json:"name" binding:"omitempty,min=1,max=100"`
	SeverityLevel *int   `json:"severity_level" binding:"omitempty,oneof=1 2 3 4"`
	AssetID       *uint  `json:"asset_id"`
	Department    string `json:"department" binding:"max=100"`
	ResponseHours *int   `json:"response_hours" binding:"omitempty,min=1"`
	FixHours      *int   `json:"fix_hours" binding:"omitempty,min=1"`
	Enabled       *bool  `json:"enabled"`
	AssetIDSet    bool   `json:"-"`
	DepartmentSet bool   `json:"-"`
}

func (r *SLAPolicyUpdateRequest) UnmarshalJSON(data []byte) error {
	type plain SLAPolicyUpdateRequest
	var value plain
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = SLAPolicyUpdateRequest(value)
	_, r.AssetIDSet = fields["asset_id"]
	_, r.DepartmentSet = fields["department"]
	return nil
}

type SLAPolicySearchRequest struct {
	SeverityLevel string `json:"severity_level" form:"severity_level"`
	AssetID       string `json:"asset_id" form:"asset_id"`
	Department    string `json:"department" form:"department"`
	Enabled       string `json:"enabled" form:"enabled"`
	PaginationRequest
}

type SLAPolicyMatch struct {
	PolicyID      uint   `json:"policy_id"`
	PolicyName    string `json:"policy_name"`
	ResponseHours int    `json:"response_hours"`
	FixHours      int    `json:"fix_hours"`
}

type SLAState struct {
	Status                   string     `json:"sla_status"`
	SLAPolicyID              *uint      `json:"sla_policy_id"`
	SLAPolicyName            string     `json:"sla_policy_name"`
	SLACycle                 int        `json:"sla_cycle"`
	ResponseDueAt            *time.Time `json:"response_due_at"`
	FixDueAt                 *time.Time `json:"fix_due_at"`
	FirstResponseAt          *time.Time `json:"first_response_at"`
	PausedSeconds            int64      `json:"paused_seconds"`
	PauseStartedAt           *time.Time `json:"pause_started_at"`
	PauseEndedAt             *time.Time `json:"pause_ended_at"`
	ResponseOverdue          bool       `json:"response_overdue"`
	FixOverdue               bool       `json:"fix_overdue"`
	ResponseOverdueLevel     int        `json:"response_overdue_level"`
	FixOverdueLevel          int        `json:"fix_overdue_level"`
	ResponseRemainingSeconds *int64     `json:"response_remaining_seconds"`
	FixRemainingSeconds      *int64     `json:"fix_remaining_seconds"`
}

type SLAPauseRequest struct {
	Reason string `json:"reason" binding:"max=500"`
}

type SLAScanResult struct {
	Processed int `json:"processed"`
	Created   int `json:"created"`
}
