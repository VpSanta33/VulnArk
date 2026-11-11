package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

// fakeFeeds stands in for api.first.org and cisa.gov.
type fakeFeeds struct {
	mu           sync.Mutex
	server       *httptest.Server
	kevStatus    int
	kevBody      string
	epssStatus   int
	epssScores   map[string][2]string
	epssRequests []string
	kevRequests  int
}

func newFakeFeeds(t *testing.T) *fakeFeeds {
	t.Helper()
	feeds := &fakeFeeds{
		kevStatus: http.StatusOK, epssStatus: http.StatusOK,
		kevBody: `{"catalogVersion":"2026.11.09","count":2,"vulnerabilities":[
			{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"},
			{"cveID":"CVE-2023-99999","vendorProject":"Other","product":"Thing","vulnerabilityName":"Other","dateAdded":"2023-01-01","dueDate":"2023-01-22","knownRansomwareCampaignUse":"Unknown"},
			{"cveID":"not-a-cve"}]}`,
		epssScores: map[string][2]string{"CVE-2021-44228": {"0.943580000", "0.999620000"}, "CVE-2024-00001": {"0.000400000", "0.120000000"}},
	}
	feeds.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		feeds.mu.Lock()
		defer feeds.mu.Unlock()
		switch r.URL.Path {
		case "/kev.json":
			feeds.kevRequests++
			w.WriteHeader(feeds.kevStatus)
			_, _ = w.Write([]byte(feeds.kevBody))
		case "/epss":
			feeds.epssRequests = append(feeds.epssRequests, r.URL.Query().Get("cve"))
			if feeds.epssStatus != http.StatusOK {
				w.WriteHeader(feeds.epssStatus)
				return
			}
			rows := make([]map[string]string, 0)
			for _, id := range strings.Split(r.URL.Query().Get("cve"), ",") {
				if score, ok := feeds.epssScores[id]; ok {
					rows = append(rows, map[string]string{"cve": id, "epss": score[0], "percentile": score[1], "date": "2026-11-09"})
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "OK", "data": rows})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(feeds.server.Close)
	return feeds
}

func (f *fakeFeeds) set(change func(*fakeFeeds)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeFeeds) counts() (kev, epss int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kevRequests, len(f.epssRequests)
}

type intelFixture struct {
	*riskFixture
	feeds  *fakeFeeds
	intel  ThreatIntelService
	clock  time.Time
	errors []error
}

func newIntelFixture(t *testing.T) *intelFixture {
	t.Helper()
	fixture := &intelFixture{riskFixture: newRiskFixture(t), feeds: newFakeFeeds(t)}
	fixture.clock = fixture.now
	fixture.intel = NewThreatIntelService(fixture.repo, fixture.risk, ThreatIntelOptions{
		Enabled: true, EPSSAPIURL: fixture.feeds.server.URL + "/epss", KEVFeedURL: fixture.feeds.server.URL + "/kev.json",
		SyncInterval: 24 * time.Hour, PollInterval: 10 * time.Minute, RequestTimeout: 5 * time.Second,
		Client: fixture.feeds.server.Client(), Now: func() time.Time { return fixture.clock },
		OnError: func(err error) { fixture.errors = append(fixture.errors, err) },
	})
	return fixture
}

func (f *intelFixture) source(t *testing.T, source string) model.ThreatIntelSourceStatus {
	t.Helper()
	status, err := f.intel.Status()
	require.NoError(t, err)
	for _, item := range status.Sources {
		if item.Source == source {
			return item
		}
	}
	t.Fatalf("source %s missing", source)
	return model.ThreatIntelSourceStatus{}
}

func TestThreatIntelSyncCachesFeedsAndRescores(t *testing.T) {
	f := newIntelFixture(t)
	kev := f.create(t, "Log4Shell", "CVE-2021-44228", 10, model.SeverityCritical, 10)
	unlikely := f.create(t, "critical but unlikely", "CVE-2024-00001", 9.8, model.SeverityCritical, 11)
	unknown := f.create(t, "too new for EPSS", "CVE-2026-77777", 8, model.SeverityHigh, 11)
	f.create(t, "free text id", "N/A", 5, model.SeverityMedium, 11)
	f.create(t, "pentest finding", "", 7.5, model.SeverityHigh, 10)
	before := f.stored(t, unlikely.ID)
	require.Nil(t, before.RiskEPSS)

	result, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	require.Empty(t, result.Errors)
	require.Equal(t, 2, result.KEVEntries)
	require.Equal(t, 3, result.EPSSUpdated)
	// Every row with a non-empty identifier is re-evaluated, including "N/A".
	require.Equal(t, 4, result.Rescored)

	// Only well-formed CVE IDs ever leave the platform.
	require.Equal(t, []string{"CVE-2021-44228,CVE-2024-00001,CVE-2026-77777"}, f.feeds.epssRequests)

	storedKEV := f.stored(t, kev.ID)
	require.True(t, storedKEV.RiskKEV)
	require.InDelta(t, 0.94358, *storedKEV.RiskEPSS, 1e-5)
	require.Equal(t, model.RiskPriorityP1, storedKEV.RiskPriority)
	after := f.stored(t, unlikely.ID)
	require.InDelta(t, 0.0004, *after.RiskEPSS, 1e-5)
	require.Less(t, *after.RiskScore, *before.RiskScore)
	require.Equal(t, model.RiskPriorityP3, after.RiskPriority)
	require.Nil(t, f.stored(t, unknown.ID).RiskEPSS)

	cached, err := f.repo.GetEPSS([]string{"CVE-2026-77777"})
	require.NoError(t, err)
	require.False(t, cached["CVE-2026-77777"].Found)

	kevStatus, epssStatus := f.source(t, model.ThreatIntelSourceKEV), f.source(t, model.ThreatIntelSourceEPSS)
	require.Equal(t, 2, kevStatus.RecordCount)
	require.Equal(t, "2026.11.09", kevStatus.SourceVersion)
	require.NotNil(t, kevStatus.LastSuccessAt)
	require.False(t, kevStatus.Stale)
	require.Equal(t, 2, epssStatus.RecordCount)
	require.Equal(t, "2026-11-09", epssStatus.SourceVersion)
	require.Empty(t, epssStatus.LastError)
}

func TestThreatIntelOutageKeepsCacheAndPlatformUsable(t *testing.T) {
	f := newIntelFixture(t)
	kev := f.create(t, "Log4Shell", "CVE-2021-44228", 10, model.SeverityCritical, 10)
	_, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	scoreBefore := *f.stored(t, kev.ID).RiskScore

	f.feeds.set(func(feeds *fakeFeeds) {
		feeds.kevStatus, feeds.epssStatus = http.StatusBadGateway, http.StatusServiceUnavailable
	})
	f.clock = f.clock.Add(25 * time.Hour)
	result, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Errors, 2)
	require.Zero(t, result.KEVEntries)

	count, err := f.repo.CountKEV()
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	kevStatus := f.source(t, model.ThreatIntelSourceKEV)
	require.Equal(t, 1, kevStatus.ConsecutiveFailures)
	require.Contains(t, kevStatus.LastError, "502")
	require.Equal(t, 2, kevStatus.RecordCount)
	require.Equal(t, "2026.11.09", kevStatus.SourceVersion)
	require.True(t, kevStatus.LastSuccessAt.Before(*kevStatus.LastAttemptAt))
	require.Equal(t, 1, f.source(t, model.ThreatIntelSourceEPSS).ConsecutiveFailures)

	// Scores keep using the last good cache, and new work is unaffected.
	require.InDelta(t, scoreBefore, *f.stored(t, kev.ID).RiskScore, 1e-9)
	created := f.create(t, "second Log4Shell instance", "CVE-2021-44228", 10, model.SeverityCritical, 11)
	stored := f.stored(t, created.ID)
	require.True(t, stored.RiskKEV)
	require.NotNil(t, stored.RiskEPSS)
	risk, err := f.risk.GetVulnerabilityRisk(created.ID, f.clock)
	require.NoError(t, err)
	require.True(t, risk.KEVListed)

	// A feed that is completely unreachable behaves the same way.
	f.feeds.server.Close()
	f.clock = f.clock.Add(25 * time.Hour)
	result, err = f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	require.Len(t, result.Errors, 2)
	require.Equal(t, 2, f.source(t, model.ThreatIntelSourceKEV).ConsecutiveFailures)
	count, err = f.repo.CountKEV()
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	require.True(t, f.source(t, model.ThreatIntelSourceKEV).Stale)
}

func TestThreatIntelRejectsDamagedKEVFeed(t *testing.T) {
	f := newIntelFixture(t)
	entries := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		entries = append(entries, fmt.Sprintf(`{"cveID":"CVE-2020-%05d","dateAdded":"2020-01-01"}`, i))
	}
	f.feeds.set(func(feeds *fakeFeeds) {
		feeds.kevBody = `{"catalogVersion":"full","vulnerabilities":[` + strings.Join(entries, ",") + `]}`
	})
	_, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)

	for name, body := range map[string]string{
		"truncated": `{"catalogVersion":"cut","vulnerabilities":[{"cveID":"CVE-2020-00001"}]}`,
		"empty":     `{"catalogVersion":"empty","vulnerabilities":[]}`,
		"html":      `<html>maintenance</html>`,
	} {
		f.feeds.set(func(feeds *fakeFeeds) { feeds.kevBody = body })
		result, err := f.intel.SyncNow(context.Background())
		require.NoError(t, err, name)
		require.Len(t, result.Errors, 1, name)
		count, err := f.repo.CountKEV()
		require.NoError(t, err)
		require.EqualValues(t, 10, count, name)
		require.Equal(t, "full", f.source(t, model.ThreatIntelSourceKEV).SourceVersion, name)
	}

	// A legitimately updated catalog replaces the cache and drops removed entries.
	f.feeds.set(func(feeds *fakeFeeds) {
		feeds.kevBody = `{"catalogVersion":"next","vulnerabilities":[` + strings.Join(entries[2:], ",") + `,{"cveID":"CVE-2026-10000"}]}`
	})
	f.clock = f.clock.Add(time.Hour)
	result, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	require.Empty(t, result.Errors)
	listed, err := f.repo.GetKEV([]string{"CVE-2020-00000", "CVE-2020-00005", "CVE-2026-10000"})
	require.NoError(t, err)
	require.Len(t, listed, 2)
	require.NotContains(t, listed, "CVE-2020-00000")
	require.Equal(t, "next", f.source(t, model.ThreatIntelSourceKEV).SourceVersion)
}

func TestThreatIntelSyncDueHonoursIntervalAndBackoff(t *testing.T) {
	f := newIntelFixture(t)
	f.create(t, "Log4Shell", "CVE-2021-44228", 10, model.SeverityCritical, 10)

	_, err := f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	kev, epss := f.feeds.counts()
	require.Equal(t, [2]int{1, 1}, [2]int{kev, epss})

	// Nothing is due inside the interval.
	f.clock = f.clock.Add(time.Hour)
	_, err = f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	kev, epss = f.feeds.counts()
	require.Equal(t, [2]int{1, 1}, [2]int{kev, epss})

	// A newly recorded CVE is fetched on the next pass without refreshing the rest.
	f.create(t, "new cve", "CVE-2024-00001", 9.8, model.SeverityCritical, 11)
	result, err := f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, result.EPSSUpdated)
	require.Equal(t, "CVE-2024-00001", f.feeds.epssRequests[1])
	kev, _ = f.feeds.counts()
	require.Equal(t, 1, kev)

	// After the interval both feeds refresh; a failure then backs off.
	f.feeds.set(func(feeds *fakeFeeds) {
		feeds.kevStatus, feeds.epssStatus = http.StatusInternalServerError, http.StatusInternalServerError
	})
	f.clock = f.clock.Add(24 * time.Hour)
	_, err = f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	kev, epss = f.feeds.counts()
	require.Equal(t, [2]int{2, 3}, [2]int{kev, epss})
	f.clock = f.clock.Add(time.Minute)
	_, err = f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	kevAgain, epssAgain := f.feeds.counts()
	require.Equal(t, [2]int{kev, epss}, [2]int{kevAgain, epssAgain})

	// Once the backoff has elapsed and the feeds are back, the cache recovers.
	f.feeds.set(func(feeds *fakeFeeds) { feeds.kevStatus, feeds.epssStatus = http.StatusOK, http.StatusOK })
	f.clock = f.clock.Add(10 * time.Minute)
	result, err = f.intel.SyncDue(context.Background())
	require.NoError(t, err)
	require.Empty(t, result.Errors)
	require.Zero(t, f.source(t, model.ThreatIntelSourceKEV).ConsecutiveFailures)
	require.Zero(t, f.source(t, model.ThreatIntelSourceEPSS).ConsecutiveFailures)
}

func TestThreatIntelBatchesEPSSRequests(t *testing.T) {
	f := newIntelFixture(t)
	total := epssRequestBatch*2 + 5
	for i := 0; i < total; i++ {
		vulnerability := &model.Vulnerability{Title: "bulk", CVEID: fmt.Sprintf("CVE-2025-%05d", i), SeverityLevel: model.SeverityMedium, AssetID: 11, Status: model.StatusNew}
		require.NoError(t, f.db.Create(vulnerability).Error)
	}
	result, err := f.intel.SyncNow(context.Background())
	require.NoError(t, err)
	require.Empty(t, result.Errors)
	require.Equal(t, total, result.EPSSUpdated)
	require.Len(t, f.feeds.epssRequests, 3)
	for _, request := range f.feeds.epssRequests {
		require.LessOrEqual(t, len(strings.Split(request, ",")), epssRequestBatch)
	}
}

func TestThreatIntelDisabledNeverCallsFeeds(t *testing.T) {
	f := newIntelFixture(t)
	disabled := NewThreatIntelService(f.repo, f.risk, ThreatIntelOptions{EPSSAPIURL: f.feeds.server.URL + "/epss", KEVFeedURL: f.feeds.server.URL + "/kev.json", Client: f.feeds.server.Client()})
	_, err := disabled.SyncNow(context.Background())
	require.ErrorIs(t, err, ErrThreatIntelDisabled)
	status, err := disabled.Status()
	require.NoError(t, err)
	require.False(t, status.Enabled)
	require.Len(t, status.Sources, 2)
	require.False(t, status.Sources[0].Stale)
	kev, epss := f.feeds.counts()
	require.Zero(t, kev+epss)
}

func TestThreatIntelRunBackfillsSyncsAndStops(t *testing.T) {
	f := newIntelFixture(t)
	legacy := &model.Vulnerability{Title: "legacy Log4Shell", CVEID: "CVE-2021-44228", SeverityLevel: model.SeverityCritical, AssetID: 10, Status: model.StatusNew}
	require.NoError(t, f.db.Create(legacy).Error)
	require.Nil(t, f.stored(t, legacy.ID).RiskScore)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.intel.Run(ctx) }()
	require.Eventually(t, func() bool {
		stored := f.stored(t, legacy.ID)
		return stored.RiskScore != nil && stored.RiskKEV
	}, 5*time.Second, 20*time.Millisecond)

	// A nudge triggers a pass well before the ten-minute poll.
	require.NoError(t, f.db.Create(&model.Vulnerability{Title: "nudged", CVEID: "CVE-2024-00001", SeverityLevel: model.SeverityHigh, AssetID: 11, Status: model.StatusNew}).Error)
	f.intel.Nudge()
	require.Eventually(t, func() bool {
		cached, err := f.repo.GetEPSS([]string{"CVE-2024-00001"})
		return err == nil && cached["CVE-2024-00001"].Found
	}, 5*time.Second, 20*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("threat intel loop did not stop")
	}
	require.Empty(t, f.errors)
}

func TestThreatIntelRunScoresLegacyRowsEvenWhenDisabledOrDown(t *testing.T) {
	f := newIntelFixture(t)
	f.feeds.server.Close()
	legacy := &model.Vulnerability{Title: "legacy", SeverityLevel: model.SeverityHigh, AssetID: 10, Status: model.StatusNew}
	require.NoError(t, f.db.Create(legacy).Error)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.intel.Run(ctx) }()
	require.Eventually(t, func() bool { return f.stored(t, legacy.ID).RiskScore != nil }, 5*time.Second, 20*time.Millisecond)

	var remaining int64
	require.NoError(t, f.db.Model(&model.Vulnerability{}).Where("risk_scored_at IS NULL").Count(&remaining).Error)
	require.Zero(t, remaining)
	_, err := f.risk.Rescore(context.Background(), repository.RiskRescoreScope{}, f.now)
	require.NoError(t, err)
}
