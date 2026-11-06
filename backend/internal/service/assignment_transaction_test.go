package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

func newAssignmentTransactionService(db *gorm.DB) AssignmentService {
	return NewAssignmentService(db, repository.NewAssignmentRepository(db), repository.NewAssignmentRuleRepository(db), repository.NewTimelineRepository(db), repository.NewVulnerabilityRepository(db), repository.NewUserRepository(db), repository.NewAssetRepository(db))
}

func TestAssignmentEmptyConditionsRoundTrip(t *testing.T) {
	db := newBusinessTestDB(t)
	rule := &model.AssignmentRule{Name: "Empty conditions", RuleType: model.RuleTypeAssetType, AssigneeID: 3, IsActive: true}
	require.NoError(t, db.Create(rule).Error)
	stored, err := repository.NewAssignmentRuleRepository(db).GetByID(rule.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Conditions)
	require.Empty(t, stored.Conditions)
}

func TestAssignmentTransactionRollback(t *testing.T) {
	for _, table := range []string{"vulnerability_assignments", "vulnerability_timeline"} {
		t.Run(table, func(t *testing.T) {
			db := newBusinessTestDB(t)
			vulnerability := seedBusinessVulnerability(t, db, table)
			failBusinessCreate(t, db, table)
			err := newAssignmentTransactionService(db).AssignVulnerability(vulnerability.ID, &model.VulnerabilityAssignRequest{AssigneeID: 3}, 1)
			require.ErrorContains(t, err, "injected")
			var stored model.Vulnerability
			require.NoError(t, db.First(&stored, vulnerability.ID).Error)
			require.Equal(t, vulnerability.AssigneeID, stored.AssigneeID)
			require.Equal(t, model.StatusNew, stored.Status)
			require.Nil(t, stored.AssignedAt)
			require.Zero(t, businessRowCount(t, db, &model.VulnerabilityAssignment{}))
			require.Zero(t, businessRowCount(t, db, &model.VulnerabilityTimeline{}))
		})
	}
}

func TestAssignmentReassignAndBatchPartialSuccess(t *testing.T) {
	db := newBusinessTestDB(t)
	svc := newAssignmentTransactionService(db)
	vulnerability := seedBusinessVulnerability(t, db, "reassign")
	require.NoError(t, svc.ReassignVulnerability(vulnerability.ID, 3, 1, "handoff"))
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, vulnerability.ID).Error)
	require.Equal(t, uint(3), *stored.AssigneeID)
	require.Equal(t, model.StatusProcessing, stored.Status)
	require.NotNil(t, stored.AssignedAt)
	var timeline model.VulnerabilityTimeline
	require.NoError(t, db.First(&timeline).Error)
	require.Equal(t, model.TimelineActionReassigned, timeline.Action)
	require.Equal(t, "Old owner", timeline.OldValue)
	require.Equal(t, "New owner", timeline.NewValue)

	second := seedBusinessVulnerability(t, db, "batch")
	third := seedBusinessVulnerability(t, db, "batch failure")
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:batch-timeline", func(tx *gorm.DB) {
		if timeline, ok := tx.Statement.Dest.(*model.VulnerabilityTimeline); ok && timeline.VulnerabilityID == third.ID {
			tx.AddError(errors.New("injected batch timeline failure"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Create().Remove("test:batch-timeline")) })
	errorList, err := svc.BatchAssignVulnerabilities(&model.BatchAssignRequest{VulnerabilityIDs: []uint{third.ID, second.ID, 99999}, AssigneeID: 3}, 1)
	require.NoError(t, err)
	require.Len(t, errorList, 2)
	require.Contains(t, errorList[0], "injected batch timeline failure")
	require.Contains(t, errorList[1], "99999")
	var failed model.Vulnerability
	require.NoError(t, db.First(&failed, third.ID).Error)
	require.Equal(t, uint(2), *failed.AssigneeID)
	require.Equal(t, model.StatusNew, failed.Status)
	require.EqualValues(t, 2, businessRowCount(t, db, &model.VulnerabilityAssignment{}))
	require.EqualValues(t, 2, businessRowCount(t, db, &model.VulnerabilityTimeline{}))
}

func TestAutoAssignmentTransactionAndSkip(t *testing.T) {
	db := newBusinessTestDB(t)
	svc := newAssignmentTransactionService(db)
	vulnerability := seedBusinessVulnerability(t, db, "auto")
	rule := &model.AssignmentRule{Name: "server rule", RuleType: model.RuleTypeAssetType, Conditions: model.AssignmentConditions{"asset_type": model.AssetTypeServer}, AssigneeID: 3, IsActive: true}
	require.NoError(t, db.Create(rule).Error)
	errorList, err := svc.AutoAssignVulnerabilities(&model.AutoAssignRequest{VulnerabilityIDs: []uint{vulnerability.ID}})
	require.NoError(t, err)
	require.Empty(t, errorList)
	require.Zero(t, businessRowCount(t, db, &model.VulnerabilityAssignment{}))

	failTimeline := true
	require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:auto-timeline", func(tx *gorm.DB) {
		if failTimeline && tx.Statement.Table == "vulnerability_timeline" {
			tx.AddError(errors.New("injected timeline failure"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Create().Remove("test:auto-timeline")) })
	errorList, err = svc.AutoAssignVulnerabilities(&model.AutoAssignRequest{VulnerabilityIDs: []uint{vulnerability.ID}, ForceReassign: true})
	require.NoError(t, err)
	require.Len(t, errorList, 1)
	require.Contains(t, errorList[0], "injected")
	var stored model.Vulnerability
	require.NoError(t, db.First(&stored, vulnerability.ID).Error)
	require.Equal(t, uint(2), *stored.AssigneeID)
	require.Equal(t, model.StatusNew, stored.Status)
	require.Zero(t, businessRowCount(t, db, &model.VulnerabilityAssignment{}))

	failTimeline = false
	errorList, err = svc.AutoAssignVulnerabilities(&model.AutoAssignRequest{VulnerabilityIDs: []uint{vulnerability.ID}, ForceReassign: true})
	require.NoError(t, err)
	require.Empty(t, errorList)
	var assignment model.VulnerabilityAssignment
	require.NoError(t, db.First(&assignment).Error)
	require.Equal(t, model.AssignmentTypeAuto, assignment.AssignmentType)
	require.Equal(t, rule.Name, assignment.AssignmentReason)
	require.EqualValues(t, 1, businessRowCount(t, db, &model.VulnerabilityTimeline{}))
}

func TestAssignmentUserLookupFailureHasNoWrites(t *testing.T) {
	db := newBusinessTestDB(t)
	vulnerability := seedBusinessVulnerability(t, db, "lookup")
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("test:user-error", func(tx *gorm.DB) {
		if tx.Statement.Table == "users" {
			tx.AddError(errors.New("lookup failure"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Query().Remove("test:user-error")) })
	err := newAssignmentTransactionService(db).AssignVulnerability(vulnerability.ID, &model.VulnerabilityAssignRequest{AssigneeID: 3}, 1)
	require.ErrorContains(t, err, "lookup failure")
	require.Zero(t, businessRowCount(t, db, &model.VulnerabilityAssignment{}))
}
