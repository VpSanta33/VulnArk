package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"vulnark/internal/model"
	"vulnark/internal/repository"
	"vulnark/pkg/outbound"
)

var (
	ErrThreatIntelDisabled = errors.New("威胁情报同步已在配置中禁用")
	ErrThreatIntelBusy     = errors.New("威胁情报同步正在进行，请稍后再试")
)

const (
	DefaultEPSSAPIURL  = "https://api.first.org/data/v1/epss"
	DefaultKEVFeedURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssRequestBatch   = 80
	epssResponseLimit  = 4 << 20
	kevResponseLimit   = 32 << 20
	threatIntelCVECap  = 50000
	threatIntelPassMax = 5 * time.Minute
)

// ThreatIntelOptions configures the EPSS/KEV synchronization.
type ThreatIntelOptions struct {
	Enabled        bool
	EPSSAPIURL     string
	KEVFeedURL     string
	SyncInterval   time.Duration
	PollInterval   time.Duration
	RequestTimeout time.Duration
	Client         *http.Client
	Now            func() time.Time
	OnError        func(error)
}

// ThreatIntelService keeps local copies of FIRST EPSS scores (for the CVEs in
// use) and the CISA KEV catalog. All failures are recorded and retried later;
// the previous cache stays in place and nothing here runs on a request path
// except the explicit manual sync.
type ThreatIntelService interface {
	Status() (*model.ThreatIntelStatus, error)
	SyncNow(ctx context.Context) (*model.ThreatIntelSyncResult, error)
	SyncDue(ctx context.Context) (*model.ThreatIntelSyncResult, error)
	Run(ctx context.Context) error
	Nudge()
}

type threatIntelService struct {
	repo  repository.RiskRepository
	risk  RiskService
	opts  ThreatIntelOptions
	mu    sync.Mutex
	nudge chan struct{}
}

// NewThreatIntelHTTPClient restricts the sync to the two configured feed hosts.
// Private mirrors must be authorized through security.outbound_private_origins.
func NewThreatIntelHTTPClient(timeout time.Duration, privateOrigins []string, feedURLs ...string) *http.Client {
	hosts := make([]string, 0, len(feedURLs))
	for _, raw := range feedURLs {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			hosts = append(hosts, parsed.Hostname())
		}
	}
	return outbound.NewClient(timeout, outbound.Policy{AllowedHosts: hosts, PrivateOrigins: privateOrigins})
}

func NewThreatIntelService(repo repository.RiskRepository, risk RiskService, opts ThreatIntelOptions) ThreatIntelService {
	if opts.EPSSAPIURL == "" {
		opts.EPSSAPIURL = DefaultEPSSAPIURL
	}
	if opts.KEVFeedURL == "" {
		opts.KEVFeedURL = DefaultKEVFeedURL
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = 24 * time.Hour
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 10 * time.Minute
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 30 * time.Second
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.RequestTimeout}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &threatIntelService{repo: repo, risk: risk, opts: opts, nudge: make(chan struct{}, 1)}
}

// Nudge requests an early pass, for example after a vulnerability with an
// uncached CVE was recorded. It never blocks.
func (s *threatIntelService) Nudge() {
	select {
	case s.nudge <- struct{}{}:
	default:
	}
}

func (s *threatIntelService) Status() (*model.ThreatIntelStatus, error) {
	status := &model.ThreatIntelStatus{Enabled: s.opts.Enabled, SyncIntervalHours: int(s.opts.SyncInterval / time.Hour)}
	now := s.opts.Now()
	for _, source := range []struct{ key, name string }{{model.ThreatIntelSourceKEV, "CISA KEV 目录"}, {model.ThreatIntelSourceEPSS, "FIRST EPSS"}} {
		state, err := s.repo.GetSyncState(source.key)
		if err != nil {
			return nil, err
		}
		status.Sources = append(status.Sources, model.ThreatIntelSourceStatus{
			Source: source.key, Name: source.name, LastAttemptAt: state.LastAttemptAt, LastSuccessAt: state.LastSuccessAt,
			LastError: state.LastError, ConsecutiveFailures: state.ConsecutiveFailures, RecordCount: state.RecordCount, SourceVersion: state.SourceVersion,
			Stale: s.opts.Enabled && (state.LastSuccessAt == nil || now.Sub(*state.LastSuccessAt) > 2*s.opts.SyncInterval),
		})
	}
	return status, nil
}

func (s *threatIntelService) SyncNow(ctx context.Context) (*model.ThreatIntelSyncResult, error) {
	return s.sync(ctx, true)
}

func (s *threatIntelService) SyncDue(ctx context.Context) (*model.ThreatIntelSyncResult, error) {
	return s.sync(ctx, false)
}

// retryAllowed applies exponential backoff after failures, capped at the
// regular interval, so an unreachable feed is not hammered on every poll.
func (s *threatIntelService) retryAllowed(state *model.ThreatIntelSyncState, now time.Time) bool {
	if state.ConsecutiveFailures == 0 || state.LastAttemptAt == nil {
		return true
	}
	delay := s.opts.PollInterval
	for i := 1; i < state.ConsecutiveFailures && delay < s.opts.SyncInterval; i++ {
		delay *= 2
	}
	if delay > s.opts.SyncInterval {
		delay = s.opts.SyncInterval
	}
	return !now.Before(state.LastAttemptAt.Add(delay))
}

func (s *threatIntelService) sync(ctx context.Context, force bool) (*model.ThreatIntelSyncResult, error) {
	if !s.opts.Enabled {
		return nil, ErrThreatIntelDisabled
	}
	if !s.mu.TryLock() {
		return nil, ErrThreatIntelBusy
	}
	defer s.mu.Unlock()
	now := s.opts.Now()
	result := &model.ThreatIntelSyncResult{Errors: []string{}}
	changed := false

	kevState, err := s.repo.GetSyncState(model.ThreatIntelSourceKEV)
	if err != nil {
		return nil, err
	}
	kevDue := kevState.LastSuccessAt == nil || now.Sub(*kevState.LastSuccessAt) >= s.opts.SyncInterval
	if force || (kevDue && s.retryAllowed(kevState, now)) {
		count, version, err := s.syncKEV(ctx, now)
		s.recordOutcome(kevState, now, err, count, version)
		if err != nil {
			result.Errors = append(result.Errors, "KEV: "+err.Error())
		} else {
			result.KEVEntries, changed = count, true
		}
	}

	epssState, err := s.repo.GetSyncState(model.ThreatIntelSourceEPSS)
	if err != nil {
		return nil, err
	}
	if force || s.retryAllowed(epssState, now) {
		outcome, err := s.syncEPSS(ctx, now, force)
		// A pass with nothing due still confirms the cache is current, but is
		// only written once per interval to avoid a row update on every poll.
		if outcome.attempted || force || err != nil || epssState.LastSuccessAt == nil || now.Sub(*epssState.LastSuccessAt) >= s.opts.SyncInterval {
			s.recordOutcome(epssState, now, err, outcome.cached, outcome.version)
		}
		updated := outcome.updated
		result.EPSSUpdated = updated
		if err != nil {
			result.Errors = append(result.Errors, "EPSS: "+err.Error())
		}
		changed = changed || updated > 0
	}

	if changed {
		rescored, err := s.risk.Rescore(ctx, repository.RiskRescoreScope{OnlyWithCVE: true}, now)
		result.Rescored = rescored
		if err != nil {
			result.Errors = append(result.Errors, "重新评分: "+err.Error())
		}
	}
	return result, nil
}

// recordOutcome persists the attempt. Counts and versions are only replaced on
// success, so the status page keeps describing the cache that is still served.
func (s *threatIntelService) recordOutcome(state *model.ThreatIntelSyncState, now time.Time, syncErr error, count int, version string) {
	attempt := now
	state.LastAttemptAt = &attempt
	if syncErr != nil {
		state.ConsecutiveFailures++
		state.LastError = truncateRunes(syncErr.Error(), 500)
	} else {
		state.ConsecutiveFailures, state.LastError, state.LastSuccessAt = 0, "", &attempt
		state.RecordCount = count
		if version != "" {
			state.SourceVersion = truncateRunes(version, 64)
		}
	}
	if err := s.repo.SaveSyncState(state); err != nil && s.opts.OnError != nil {
		s.opts.OnError(err)
	}
}

func truncateRunes(value string, limit int) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	return string([]rune(value)[:limit])
}

func (s *threatIntelService) fetch(ctx context.Context, target string, limit int64) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, s.opts.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("情报源地址无效")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "VulnArk-ThreatIntel/1.0")
	response, err := s.opts.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("请求情报源失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("情报源返回状态 %d", response.StatusCode)
	}
	return outbound.ReadBody(response.Body, limit)
}

type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID              string `json:"cveID"`
		VendorProject      string `json:"vendorProject"`
		Product            string `json:"product"`
		VulnerabilityName  string `json:"vulnerabilityName"`
		DateAdded          string `json:"dateAdded"`
		DueDate            string `json:"dueDate"`
		KnownRansomwareUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

func (s *threatIntelService) syncKEV(ctx context.Context, now time.Time) (int, string, error) {
	body, err := s.fetch(ctx, s.opts.KEVFeedURL, kevResponseLimit)
	if err != nil {
		return 0, "", err
	}
	var feed kevFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return 0, "", errors.New("KEV 目录不是有效的 JSON")
	}
	seen := make(map[string]bool, len(feed.Vulnerabilities))
	entries := make([]model.KEVEntry, 0, len(feed.Vulnerabilities))
	for _, item := range feed.Vulnerabilities {
		id := model.NormalizeCVEID(item.CVEID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		entries = append(entries, model.KEVEntry{
			CVEID: id, VendorProject: truncateRunes(item.VendorProject, 255), Product: truncateRunes(item.Product, 255),
			VulnerabilityName: truncateRunes(item.VulnerabilityName, 500), DateAdded: truncateRunes(item.DateAdded, 10),
			DueDate: truncateRunes(item.DueDate, 10), KnownRansomwareUse: truncateRunes(item.KnownRansomwareUse, 20),
		})
	}
	if len(entries) == 0 {
		return 0, "", errors.New("KEV 目录中没有有效条目，已保留本地缓存")
	}
	existing, err := s.repo.CountKEV()
	if err != nil {
		return 0, "", err
	}
	// The catalog only grows in practice. A feed that lost most of its entries
	// is far more likely truncated than genuine, so the cache is kept.
	if existing > 0 && int64(len(entries))*2 < existing {
		return 0, "", fmt.Errorf("KEV 目录条目数异常减少（%d → %d），已保留本地缓存", existing, len(entries))
	}
	if err := s.repo.ReplaceKEV(entries, now); err != nil {
		return 0, "", err
	}
	return len(entries), feed.CatalogVersion, nil
}

// flexibleFloat accepts the quoted decimals FIRST returns as well as numbers.
type flexibleFloat float64

func (f *flexibleFloat) UnmarshalJSON(data []byte) error {
	value, err := strconv.ParseFloat(strings.Trim(string(data), `"`), 64)
	if err != nil {
		return err
	}
	*f = flexibleFloat(value)
	return nil
}

type epssResponse struct {
	Data []struct {
		CVE        string        `json:"cve"`
		EPSS       flexibleFloat `json:"epss"`
		Percentile flexibleFloat `json:"percentile"`
		Date       string        `json:"date"`
	} `json:"data"`
}

type epssOutcome struct {
	updated   int    // cache rows written in this pass
	cached    int    // CVEs in use that now have a score
	version   string // newest score date seen
	attempted bool   // whether a request was necessary
}

// syncEPSS refreshes scores for the CVEs recorded in vulnerabilities whose
// cache entry is missing or older than the sync interval. Batches already
// stored survive a later failure.
func (s *threatIntelService) syncEPSS(ctx context.Context, now time.Time, force bool) (outcome epssOutcome, err error) {
	raw, err := s.repo.ListVulnerabilityCVEIDs(threatIntelCVECap)
	if err != nil {
		return outcome, err
	}
	seen := make(map[string]bool, len(raw))
	ids := make([]string, 0, len(raw))
	for _, value := range raw {
		if id := model.NormalizeCVEID(value); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	cached, err := s.repo.GetEPSS(ids)
	if err != nil {
		return outcome, err
	}
	due := make([]string, 0, len(ids))
	for _, id := range ids {
		if entry, ok := cached[id]; force || !ok || now.Sub(entry.FetchedAt) >= s.opts.SyncInterval {
			due = append(due, id)
		}
	}
	sort.Strings(due)
	outcome.attempted = len(due) > 0
	for start := 0; start < len(due); start += epssRequestBatch {
		if err := ctx.Err(); err != nil {
			return outcome, err
		}
		batch := due[start:min(start+epssRequestBatch, len(due))]
		scores, err := s.fetchEPSS(ctx, batch, now)
		if err != nil {
			return outcome, err
		}
		if err := s.repo.UpsertEPSS(scores); err != nil {
			return outcome, err
		}
		outcome.updated += len(scores)
		for _, score := range scores {
			cached[score.CVEID] = score
		}
	}
	for _, score := range cached {
		if score.Found {
			outcome.cached++
			if score.ScoreDate > outcome.version {
				outcome.version = score.ScoreDate
			}
		}
	}
	return outcome, nil
}

func (s *threatIntelService) fetchEPSS(ctx context.Context, batch []string, now time.Time) ([]model.EPSSScore, error) {
	target, err := url.Parse(s.opts.EPSSAPIURL)
	if err != nil {
		return nil, errors.New("EPSS 接口地址无效")
	}
	query := target.Query()
	query.Set("cve", strings.Join(batch, ","))
	target.RawQuery = query.Encode()
	body, err := s.fetch(ctx, target.String(), epssResponseLimit)
	if err != nil {
		return nil, err
	}
	var response epssResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, errors.New("EPSS 响应不是有效的 JSON")
	}
	requested := make(map[string]bool, len(batch))
	for _, id := range batch {
		requested[id] = true
	}
	found := make(map[string]model.EPSSScore, len(batch))
	for _, item := range response.Data {
		id := model.NormalizeCVEID(item.CVE)
		score, percentile := float64(item.EPSS), float64(item.Percentile)
		// Only accept rows that were asked for and are valid probabilities.
		if !requested[id] || score < 0 || score > 1 || percentile < 0 || percentile > 1 {
			continue
		}
		found[id] = model.EPSSScore{CVEID: id, Found: true, EPSS: score, Percentile: percentile, ScoreDate: truncateRunes(item.Date, 10), FetchedAt: now}
	}
	scores := make([]model.EPSSScore, 0, len(batch))
	for _, id := range batch {
		if score, ok := found[id]; ok {
			scores = append(scores, score)
		} else {
			// Remember that FIRST has no score so the CVE is not re-requested on every pass.
			scores = append(scores, model.EPSSScore{CVEID: id, FetchedAt: now})
		}
	}
	return scores, nil
}

func (s *threatIntelService) runOnce(ctx context.Context) {
	pass, cancel := context.WithTimeout(ctx, threatIntelPassMax)
	defer cancel()
	report := func(err error) {
		if err != nil && ctx.Err() == nil && s.opts.OnError != nil {
			s.opts.OnError(err)
		}
	}
	// Vulnerabilities that predate the risk columns are scored here, with or
	// without threat intelligence.
	_, err := s.risk.Rescore(pass, repository.RiskRescoreScope{OnlyUnscored: true}, s.opts.Now())
	report(err)
	if !s.opts.Enabled {
		return
	}
	result, err := s.SyncDue(pass)
	if errors.Is(err, ErrThreatIntelBusy) {
		return
	}
	report(err)
	if result != nil && len(result.Errors) > 0 {
		report(errors.New(strings.Join(result.Errors, "; ")))
	}
}

// Run performs a pass at start-up, then on every poll interval or nudge, until
// the context is cancelled.
func (s *threatIntelService) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.opts.PollInterval)
	defer ticker.Stop()
	for {
		s.runOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-s.nudge:
		}
	}
}
