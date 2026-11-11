package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/testutil"
)

type riskFixture struct {
	db     *gorm.DB
	repo   repository.RiskRepository
	risk   RiskService
	vulns  VulnerabilityService
	assets AssetService
	now    time.Time
}

// Assets: 10 = exposed production crown jewel, 11 = internal medium, 12 = internal test box.
func newRiskFixture(t *testing.T) *riskFixture {
	t.Helper()
	db := testutil.NewTestDB(t)
	testutil.SeedTestData(db)
	for _, asset := range []model.Asset{
		{ID: 10, Name: "payment-gateway", Type: model.AssetTypeApplication, ImportanceLevel: model.ImportanceLevelHigh, InternetFacing: true, NetworkZone: model.NetworkZoneProduction, Status: 1},
		{ID: 11, Name: "hr-portal", Type: model.AssetTypeApplication, ImportanceLevel: model.ImportanceLevelMedium, NetworkZone: model.NetworkZoneInternal, Status: 1},
		{ID: 12, Name: "build-box", Type: model.AssetTypeServer, ImportanceLevel: model.ImportanceLevelLow, NetworkZone: model.NetworkZoneTest, Status: 1},
	} {
		require.NoError(t, db.Create(&asset).Error)
	}
	fixture := &riskFixture{db: db, repo: repository.NewRiskRepository(db), now: time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)}
	fixture.risk = NewRiskService(fixture.repo)
	assetRepo := repository.NewAssetRepository(db)
	fixture.vulns = NewVulnerabilityService(repository.NewVulnerabilityRepository(db), assetRepo, repository.NewUserRepository(db), repository.NewOWASPCategoryRepository(db))
	ConfigureVulnerabilityRisk(fixture.vulns, fixture.risk)
	fixture.assets = NewAssetService(assetRepo, repository.NewUserRepository(db))
	ConfigureAssetRisk(fixture.assets, fixture.risk)
	return fixture
}

// seedIntel fills the caches the way a successful synchronization would.
func (f *riskFixture) seedIntel(t *testing.T) {
	t.Helper()
	require.NoError(t, f.repo.UpsertEPSS([]model.EPSSScore{
		{CVEID: "CVE-2021-44228", Found: true, EPSS: 0.94358, Percentile: 0.99962, ScoreDate: "2026-11-09", FetchedAt: f.now},
		{CVEID: "CVE-2024-00001", Found: true, EPSS: 0.0004, Percentile: 0.12, ScoreDate: "2026-11-09", FetchedAt: f.now},
	}))
	require.NoError(t, f.repo.ReplaceKEV([]model.KEVEntry{{CVEID: "CVE-2021-44228", DateAdded: "2021-12-10", DueDate: "2021-12-24", KnownRansomwareUse: "Known"}}, f.now))
	require.NoError(t, f.repo.SaveSyncState(&model.ThreatIntelSyncState{Source: model.ThreatIntelSourceKEV, LastAttemptAt: &f.now, LastSuccessAt: &f.now, RecordCount: 1}))
}

func (f *riskFixture) create(t *testing.T, title, cve string, cvss float64, severity int, assetID uint) *model.Vulnerability {
	t.Helper()
	created, err := f.vulns.CreateVulnerability(&model.VulnerabilityCreateRequest{Title: title, CVEID: cve, CVSSScore: &cvss, SeverityLevel: severity, AssetID: assetID}, 1, nil)
	require.NoError(t, err)
	return created
}

func (f *riskFixture) stored(t *testing.T, id uint) model.Vulnerability {
	t.Helper()
	var vulnerability model.Vulnerability
	require.NoError(t, f.db.First(&vulnerability, id).Error)
	return vulnerability
}

func TestCreatedVulnerabilitiesAreScoredAndRankedByRisk(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	unlikely := f.create(t, "critical but unlikely", "CVE-2024-00001", 9.8, model.SeverityCritical, 11)
	pentest := f.create(t, "IDOR found in pentest", "", 7.5, model.SeverityHigh, 10)
	kev := f.create(t, "Log4Shell", "cve-2021-44228", 10, model.SeverityCritical, 10)

	storedKEV, storedPentest, storedUnlikely := f.stored(t, kev.ID), f.stored(t, pentest.ID), f.stored(t, unlikely.ID)
	require.NotNil(t, storedKEV.RiskScore)
	require.Equal(t, model.RiskPriorityP1, storedKEV.RiskPriority)
	require.True(t, storedKEV.RiskKEV)
	require.InDelta(t, 0.94358, *storedKEV.RiskEPSS, 1e-5)
	require.NotNil(t, storedKEV.RiskScoredAt)
	require.False(t, storedPentest.RiskKEV)
	require.Nil(t, storedPentest.RiskEPSS)
	require.Equal(t, model.RiskPriorityP3, storedUnlikely.RiskPriority)

	list, err := f.vulns.GetVulnerabilityList(&model.VulnerabilitySearchRequest{SortBy: "risk_score", PaginationRequest: model.PaginationRequest{Page: 1, PageSize: 10}})
	require.NoError(t, err)
	items := list.Data.([]model.VulnerabilityInfo)
	require.Len(t, items, 3)
	// Creation order was unlikely, pentest, kev; risk order is the reverse.
	require.Equal(t, []uint{kev.ID, pentest.ID, unlikely.ID}, []uint{items[0].ID, items[1].ID, items[2].ID})
	require.Equal(t, "紧急", items[0].RiskPriorityText)
	require.Greater(t, *items[0].RiskScore, *items[1].RiskScore)
	require.Greater(t, *items[1].RiskScore, *items[2].RiskScore)
}

func TestScoringWorksWithEmptyThreatIntelCaches(t *testing.T) {
	f := newRiskFixture(t)
	withCVE := f.create(t, "no intel yet", "CVE-2021-44228", 10, model.SeverityCritical, 10)
	stored := f.stored(t, withCVE.ID)
	require.NotNil(t, stored.RiskScore)
	require.False(t, stored.RiskKEV)
	require.Nil(t, stored.RiskEPSS)
	risk, err := f.risk.GetVulnerabilityRisk(withCVE.ID, f.now)
	require.NoError(t, err)
	require.False(t, riskFactor(t, risk.RiskAssessment, model.RiskFactorEPSS).Applicable)
	require.False(t, riskFactor(t, risk.RiskAssessment, model.RiskFactorKEV).Applicable)
	require.InDelta(t, 98.2, risk.Score, 0.05)
}

func TestEditsToScoreInputsRescore(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	vulnerability := f.create(t, "editable", "", 5.0, model.SeverityMedium, 12)
	before := *f.stored(t, vulnerability.ID).RiskScore

	raised := 9.0
	require.NoError(t, f.vulns.UpdateVulnerability(vulnerability.ID, &model.VulnerabilityUpdateRequest{CVSSScore: &raised}))
	afterCVSS := *f.stored(t, vulnerability.ID).RiskScore
	require.Greater(t, afterCVSS, before)

	require.NoError(t, f.vulns.UpdateVulnerability(vulnerability.ID, &model.VulnerabilityUpdateRequest{CVEID: "CVE-2021-44228"}))
	afterCVE := f.stored(t, vulnerability.ID)
	require.True(t, afterCVE.RiskKEV)
	require.NotNil(t, afterCVE.RiskEPSS)

	// A title edit does not touch the snapshot.
	scoredAt := *afterCVE.RiskScoredAt
	require.NoError(t, f.vulns.UpdateVulnerability(vulnerability.ID, &model.VulnerabilityUpdateRequest{Title: "renamed"}))
	require.True(t, scoredAt.Equal(*f.stored(t, vulnerability.ID).RiskScoredAt))

	exposed, high := true, model.ImportanceLevelHigh
	require.NoError(t, f.assets.UpdateAsset(12, &model.AssetUpdateRequest{InternetFacing: &exposed, NetworkZone: model.NetworkZoneOT, ImportanceLevel: &high}))
	afterAsset := f.stored(t, vulnerability.ID)
	require.Greater(t, *afterAsset.RiskScore, *afterCVE.RiskScore)
	var asset model.Asset
	require.NoError(t, f.db.First(&asset, 12).Error)
	require.True(t, asset.InternetFacing)
	require.Equal(t, model.NetworkZoneOT, asset.NetworkZone)

	require.Error(t, f.assets.ValidateAsset(&model.AssetCreateRequest{Name: "x", Type: model.AssetTypeServer, NetworkZone: "moon"}))
}

func TestUpdateConfigPersistsAndRescoresEverything(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	unlikely := f.create(t, "critical but unlikely", "CVE-2024-00001", 9.8, model.SeverityCritical, 11)
	require.Equal(t, model.RiskPriorityP3, f.stored(t, unlikely.ID).RiskPriority)

	initial, err := f.risk.GetConfig()
	require.NoError(t, err)
	require.Equal(t, model.DefaultRiskConfig(), initial.Config)
	require.Nil(t, initial.UpdatedAt)

	invalid := model.DefaultRiskConfig()
	invalid.Thresholds.P1 = 10
	_, err = f.risk.UpdateConfig(context.Background(), &invalid, 1, f.now)
	require.Error(t, err)

	cvssFirst := model.DefaultRiskConfig()
	cvssFirst.Weights = model.RiskWeights{CVSS: 100}
	result, err := f.risk.UpdateConfig(context.Background(), &cvssFirst, 1, f.now)
	require.NoError(t, err)
	require.Equal(t, 1, result.Rescored)
	rescored := f.stored(t, unlikely.ID)
	require.InDelta(t, 98, *rescored.RiskScore, 0.05)
	require.Equal(t, model.RiskPriorityP1, rescored.RiskPriority)

	saved, err := f.risk.GetConfig()
	require.NoError(t, err)
	require.Equal(t, cvssFirst, saved.Config)
	require.NotNil(t, saved.UpdatedBy)
	require.EqualValues(t, 1, *saved.UpdatedBy)
	var rows int64
	require.NoError(t, f.db.Model(&model.RiskScoringConfig{}).Count(&rows).Error)
	_, err = f.risk.UpdateConfig(context.Background(), &cvssFirst, 1, f.now)
	require.NoError(t, err)
	var rowsAfter int64
	require.NoError(t, f.db.Model(&model.RiskScoringConfig{}).Count(&rowsAfter).Error)
	require.EqualValues(t, 1, rows)
	require.Equal(t, rows, rowsAfter)

	// A damaged row must not stop scoring: the defaults take over.
	require.NoError(t, f.db.Model(&model.RiskScoringConfig{}).Where("1 = 1").Update("config", "{not json").Error)
	fallback, err := f.risk.GetConfig()
	require.NoError(t, err)
	require.Equal(t, model.DefaultRiskConfig(), fallback.Config)
	require.NoError(t, f.risk.RescoreVulnerability(unlikely.ID, f.now))
	require.Equal(t, model.RiskPriorityP3, f.stored(t, unlikely.ID).RiskPriority)
}

func TestVulnerabilityRiskExplainsScoreAndComparesSLA(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	discovered := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	laterDue := discovered.Add(720 * time.Hour)
	score := ptrFloat(10)
	vulnerability := &model.Vulnerability{Title: "Log4Shell", CVEID: "CVE-2021-44228", CVSSScore: score, SeverityLevel: model.SeverityCritical, AssetID: 10, Status: model.StatusNew, DiscoveredAt: discovered, FixDueAt: &laterDue}
	require.NoError(t, f.db.Create(vulnerability).Error)

	risk, err := f.risk.GetVulnerabilityRisk(vulnerability.ID, f.now)
	require.NoError(t, err)
	require.Equal(t, model.RiskPriorityP1, risk.Priority)
	require.Len(t, risk.Factors, 5)
	require.True(t, risk.KEVListed)
	require.Equal(t, "2021-12-24", risk.KEV.DueDate)
	require.Equal(t, discovered.Add(24*time.Hour), risk.RecommendedFixDueAt.UTC())
	require.Equal(t, "later", risk.SLAAlignment)
	require.Equal(t, model.DefaultRiskConfig().Thresholds, risk.Thresholds)
	// Reading the explanation refreshes a missing snapshot.
	require.NotNil(t, f.stored(t, vulnerability.ID).RiskScore)

	// Equal budgets stored at different precisions still count as aligned.
	sameDue := discovered.Add(24*time.Hour + 750*time.Millisecond)
	require.NoError(t, f.db.Model(vulnerability).Update("fix_due_at", sameDue).Error)
	risk, err = f.risk.GetVulnerabilityRisk(vulnerability.ID, f.now)
	require.NoError(t, err)
	require.Equal(t, "aligned", risk.SLAAlignment)

	earlierDue := discovered.Add(12 * time.Hour)
	require.NoError(t, f.db.Model(vulnerability).Update("fix_due_at", earlierDue).Error)
	risk, err = f.risk.GetVulnerabilityRisk(vulnerability.ID, f.now)
	require.NoError(t, err)
	require.Equal(t, "aligned", risk.SLAAlignment)
	require.NoError(t, f.db.Model(vulnerability).Update("fix_due_at", nil).Error)
	risk, err = f.risk.GetVulnerabilityRisk(vulnerability.ID, f.now)
	require.NoError(t, err)
	require.Equal(t, "none", risk.SLAAlignment)

	_, err = f.risk.GetVulnerabilityRisk(99999, f.now)
	require.ErrorIs(t, err, repository.ErrRiskVulnerabilityNotFound)
}

func TestRescoreBackfillsLegacyRowsWithoutTouchingUpdatedAt(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	updated := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < riskRescoreBatch+5; i++ {
		legacy := &model.Vulnerability{Title: "legacy", SeverityLevel: model.SeverityHigh, AssetID: 11, Status: model.StatusNew, UpdatedAt: updated}
		require.NoError(t, f.db.Create(legacy).Error)
	}
	scored := f.create(t, "already scored", "", 5, model.SeverityMedium, 12)
	scoredAt := *f.stored(t, scored.ID).RiskScoredAt

	evaluated, err := f.risk.Rescore(context.Background(), repository.RiskRescoreScope{OnlyUnscored: true}, f.now)
	require.NoError(t, err)
	require.Equal(t, riskRescoreBatch+5, evaluated)
	var unscored int64
	require.NoError(t, f.db.Model(&model.Vulnerability{}).Where("risk_scored_at IS NULL").Count(&unscored).Error)
	require.Zero(t, unscored)
	var legacy model.Vulnerability
	require.NoError(t, f.db.Where("title = ?", "legacy").First(&legacy).Error)
	require.True(t, updated.Equal(legacy.UpdatedAt))
	require.True(t, scoredAt.Equal(*f.stored(t, scored.ID).RiskScoredAt))

	again, err := f.risk.Rescore(context.Background(), repository.RiskRescoreScope{OnlyUnscored: true}, f.now)
	require.NoError(t, err)
	require.Zero(t, again)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.risk.Rescore(cancelled, repository.RiskRescoreScope{}, f.now)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRequestIntelNudgesOnlyForUncachedValidCVE(t *testing.T) {
	f := newRiskFixture(t)
	f.seedIntel(t)
	nudges := 0
	ConfigureRiskIntelNudge(f.risk, func() { nudges++ })
	f.risk.RequestIntel("CVE-2021-44228")
	f.risk.RequestIntel("N/A")
	f.risk.RequestIntel("")
	require.Zero(t, nudges)
	f.risk.RequestIntel("CVE-2026-55555")
	require.Equal(t, 1, nudges)
	f.create(t, "new cve", "CVE-2026-66666", 6, model.SeverityMedium, 11)
	require.Equal(t, 2, nudges)
}
