package repository

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/pkg/testutil"
)

func riskFloat(value float64) *float64 { return &value }

func TestVulnerabilityListSortsAndFiltersByRisk(t *testing.T) {
	db := testutil.NewTestDB(t)
	require.NoError(t, db.Create(&model.Asset{ID: 1, Name: "asset", Type: model.AssetTypeServer, Status: 1}).Error)
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rows := []model.Vulnerability{
		{ID: 1, Title: "medium", RiskScore: riskFloat(55.5), RiskPriority: model.RiskPriorityP3, CreatedAt: base},
		{ID: 2, Title: "unscored legacy", CreatedAt: base.Add(5 * time.Hour)},
		{ID: 3, Title: "kev", RiskScore: riskFloat(96.4), RiskPriority: model.RiskPriorityP1, RiskKEV: true, CreatedAt: base.Add(time.Hour)},
		{ID: 4, Title: "high", RiskScore: riskFloat(71), RiskPriority: model.RiskPriorityP2, CreatedAt: base.Add(2 * time.Hour)},
		{ID: 5, Title: "tie older", RiskScore: riskFloat(71), RiskPriority: model.RiskPriorityP2, CreatedAt: base.Add(time.Hour)},
		{ID: 6, Title: "low", RiskScore: riskFloat(12.3), RiskPriority: model.RiskPriorityP4, CreatedAt: base.Add(4 * time.Hour)},
	}
	for i := range rows {
		rows[i].AssetID, rows[i].SeverityLevel, rows[i].Status = 1, model.SeverityMedium, model.StatusNew
		require.NoError(t, db.Create(&rows[i]).Error)
	}
	repo := NewVulnerabilityRepository(db)
	ids := func(req model.VulnerabilitySearchRequest) []uint {
		t.Helper()
		if req.Page == 0 {
			req.Page, req.PageSize = 1, 50
		}
		items, total, err := repo.List(&req)
		require.NoError(t, err)
		result := make([]uint, 0, len(items))
		for _, item := range items {
			result = append(result, item.ID)
		}
		if req.PageSize == 50 {
			require.EqualValues(t, len(result), total)
		}
		return result
	}

	// The default order is unchanged: newest first (equal timestamps by newest ID).
	require.Equal(t, []uint{2, 6, 4, 5, 3, 1}, ids(model.VulnerabilitySearchRequest{}))
	require.Equal(t, []uint{1, 3, 5, 4, 6, 2}, ids(model.VulnerabilitySearchRequest{SortOrder: "asc"}))
	// Highest risk first, ties by newest, unscored rows last in both directions.
	require.Equal(t, []uint{3, 4, 5, 1, 6, 2}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score"}))
	require.Equal(t, []uint{3, 4, 5, 1, 6, 2}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score", SortOrder: "desc"}))
	require.Equal(t, []uint{6, 1, 4, 5, 3, 2}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score", SortOrder: "asc"}))
	// Pagination follows the same stable order.
	require.Equal(t, []uint{5, 1}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score", PaginationRequest: model.PaginationRequest{Page: 2, PageSize: 2}}))

	require.Equal(t, []uint{4, 5}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score", RiskPriority: model.RiskPriorityP2}))
	require.Equal(t, []uint{3}, ids(model.VulnerabilitySearchRequest{KEVOnly: "true"}))
	require.Equal(t, []uint{3}, ids(model.VulnerabilitySearchRequest{KEVOnly: "1"}))
	require.Len(t, ids(model.VulnerabilitySearchRequest{KEVOnly: "false"}), 6)
	require.Equal(t, []uint{3, 4, 5}, ids(model.VulnerabilitySearchRequest{SortBy: "risk_score", MinRiskScore: "60"}))
	require.Equal(t, []uint{3}, ids(model.VulnerabilitySearchRequest{MinRiskScore: "71.5", RiskPriority: model.RiskPriorityP1}))

	for _, invalid := range []string{"abc", "-1", "101", "NaN"} {
		_, _, err := repo.List(&model.VulnerabilitySearchRequest{MinRiskScore: invalid, PaginationRequest: model.PaginationRequest{Page: 1, PageSize: 10}})
		require.Error(t, err, invalid)
	}
}

func TestRiskRepositoryCachesAndSyncState(t *testing.T) {
	db := testutil.NewTestDB(t)
	repo := NewRiskRepository(db)
	now := time.Date(2026, 11, 10, 8, 0, 0, 123456789, time.UTC)

	state, err := repo.GetSyncState(model.ThreatIntelSourceKEV)
	require.NoError(t, err)
	require.Equal(t, model.ThreatIntelSourceKEV, state.Source)
	require.Nil(t, state.LastSuccessAt)
	state.LastSuccessAt, state.RecordCount = &now, 2
	require.NoError(t, repo.SaveSyncState(state))
	state.ConsecutiveFailures, state.LastError = 1, "boom"
	require.NoError(t, repo.SaveSyncState(state))
	reloaded, err := repo.GetSyncState(model.ThreatIntelSourceKEV)
	require.NoError(t, err)
	require.Equal(t, "boom", reloaded.LastError)
	require.Equal(t, 2, reloaded.RecordCount)
	var states int64
	require.NoError(t, db.Model(&model.ThreatIntelSyncState{}).Count(&states).Error)
	require.EqualValues(t, 1, states)

	require.Error(t, repo.ReplaceKEV(nil, now))
	require.NoError(t, repo.ReplaceKEV([]model.KEVEntry{{CVEID: "CVE-2021-44228"}, {CVEID: "CVE-2020-00001"}}, now))
	// The same timestamp must not delete rows written by the same replacement.
	count, err := repo.CountKEV()
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	require.NoError(t, repo.ReplaceKEV([]model.KEVEntry{{CVEID: "CVE-2021-44228", Product: "Log4j2"}, {CVEID: "CVE-2026-10000"}}, now.Add(time.Hour)))
	entries, err := repo.GetKEV([]string{"CVE-2021-44228", "CVE-2020-00001", "CVE-2026-10000"})
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "Log4j2", entries["CVE-2021-44228"].Product)

	require.NoError(t, repo.UpsertEPSS(nil))
	require.NoError(t, repo.UpsertEPSS([]model.EPSSScore{{CVEID: "CVE-2021-44228", Found: true, EPSS: 0.5, FetchedAt: now}, {CVEID: "CVE-2026-77777", FetchedAt: now}}))
	require.NoError(t, repo.UpsertEPSS([]model.EPSSScore{{CVEID: "CVE-2021-44228", Found: true, EPSS: 0.94358, Percentile: 0.99962, ScoreDate: "2026-11-09", FetchedAt: now.Add(time.Hour)}}))
	scores, err := repo.GetEPSS([]string{"CVE-2021-44228", "CVE-2026-77777", "CVE-1999-0001"})
	require.NoError(t, err)
	require.Len(t, scores, 2)
	require.InDelta(t, 0.94358, scores["CVE-2021-44228"].EPSS, 1e-9)
	require.False(t, scores["CVE-2026-77777"].Found)

	config, err := repo.GetConfig()
	require.NoError(t, err)
	require.Nil(t, config)
	saved, err := repo.SaveConfig(`{"a":1}`, 7)
	require.NoError(t, err)
	again, err := repo.SaveConfig(`{"a":2}`, 0)
	require.NoError(t, err)
	require.Equal(t, saved.ID, again.ID)
	require.Nil(t, again.UpdatedBy)
	config, err = repo.GetConfig()
	require.NoError(t, err)
	require.Equal(t, `{"a":2}`, config.Config)

	require.NoError(t, db.Create(&model.Asset{ID: 1, Name: "asset", Type: model.AssetTypeServer, Status: 1}).Error)
	for _, cve := range []string{"CVE-2021-44228", "CVE-2021-44228", "", "N/A"} {
		require.NoError(t, db.Create(&model.Vulnerability{Title: "v", CVEID: cve, AssetID: 1, SeverityLevel: 3, Status: model.StatusNew}).Error)
	}
	ids, err := repo.ListVulnerabilityCVEIDs(100)
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2021-44228", "N/A"}, ids)
	withCVE, err := repo.ListVulnerabilitiesAfter(0, 10, RiskRescoreScope{OnlyWithCVE: true})
	require.NoError(t, err)
	require.Len(t, withCVE, 3)
	require.Equal(t, "asset", withCVE[0].Asset.Name)
	_, err = repo.GetVulnerability(9999)
	require.ErrorIs(t, err, ErrRiskVulnerabilityNotFound)
}
