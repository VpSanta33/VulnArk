import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { apiClient } from './src/services/api';
import { riskService } from './src/services/risk';
import { vulnerabilitiesService } from './src/services/vulnerabilities';
import { assetsService } from './src/services/assets';
import { vulnerabilityDetailURL } from './src/lib/roadmap';
import { formatEPSS, formatSLAHours, networkZoneLabel, riskPriorityMeta, validateRiskConfig, weightShare } from './src/lib/risk';
import type { RiskConfig } from './src/types/risk';

const client = apiClient.getClient();
const originalAdapter = client.defaults.adapter;
const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
let requests: InternalAxiosRequestConfig[];
let responseData: unknown;
beforeEach(() => {
  requests = []; responseData = null;
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'contract-token' } });
  const adapter: AxiosAdapter = async config => {
    requests.push(config);
    return { config, status: 200, statusText: 'OK', headers: {}, data: { code: 200, message: 'success', data: responseData } };
  };
  client.defaults.adapter = adapter;
});
afterEach(() => {
  client.defaults.adapter = originalAdapter;
  if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
  else Reflect.deleteProperty(globalThis, 'localStorage');
});

const defaults = (): RiskConfig => ({
  weights: { cvss: 30, epss: 20, kev: 15, asset_importance: 20, exposure: 15 },
  thresholds: { p1: 80, p2: 60, p3: 40 },
  sla_hours: { p1: 24, p2: 72, p3: 168, p4: 720 },
  kev_min_priority: 'P2',
});

describe('risk prioritization wire contracts', () => {
  test('sorts and filters the existing paginated list by risk', async () => {
    responseData = { total: 0, page: 1, page_size: 10, total_pages: 0, data: [] };
    await vulnerabilitiesService.getVulnerabilities({ page: 1, sort_by: 'risk_score', sort_order: 'desc', risk_priority: 'P1', kev_only: true, min_risk_score: 60 });
    const query = new URLSearchParams(String(requests[0].url).split('?')[1]);
    expect(Object.fromEntries(query)).toEqual({ page: '1', sort_by: 'risk_score', sort_order: 'desc', risk_priority: 'P1', kev_only: 'true', min_risk_score: '60' });
    // An unchecked KEV filter and an empty tier are omitted rather than sent as false/empty.
    await vulnerabilitiesService.getVulnerabilities({ kev_only: undefined, risk_priority: '', sort_by: 'created_at' });
    expect(requests[1].url).toBe('/vulnerabilities?sort_by=created_at');
  });
  test('reads the score explanation and the model, and saves the model unchanged', async () => {
    responseData = { vulnerability_id: 7, score: 96.4, priority: 'P1', factors: [{ key: 'kev', contribution: 15 }], adjustments: [] };
    const risk = await riskService.vulnerabilityRisk(7);
    expect(risk.factors[0].contribution).toBe(15);
    responseData = { config: defaults(), defaults: defaults(), updated_at: null, updated_by: null };
    expect((await riskService.config()).config.kev_min_priority).toBe('P2');
    responseData = { rescored: 12 };
    const config = { ...defaults(), kev_min_priority: '' as const, weights: { ...defaults().weights, epss: 0 } };
    expect(await riskService.saveConfig(config)).toBe(12);
    expect(await riskService.recalculate()).toBe(12);
    expect(requests.map(request => [request.method, request.url])).toEqual([
      ['get', '/vulnerabilities/7/risk'], ['get', '/risk/config'], ['put', '/risk/config'], ['post', '/risk/recalculate'],
    ]);
    expect(JSON.parse(requests[2].data)).toEqual(config);
    expect(requests[2].headers.Authorization).toBe('Bearer contract-token');
  });
  test('reports cache status and surfaces partial sync failures to the caller', async () => {
    responseData = { enabled: true, sync_interval_hours: 24, sources: [{ source: 'kev', record_count: 1773, last_error: '', stale: false }] };
    expect((await riskService.intelStatus()).sources[0].record_count).toBe(1773);
    responseData = { kev_entries: 0, epss_updated: 3, rescored: 3, errors: ['KEV: 情报源返回状态 502'] };
    const result = await riskService.syncIntel();
    expect(result.errors).toHaveLength(1); expect(result.epss_updated).toBe(3);
    expect(requests.map(request => [request.method, request.url])).toEqual([['get', '/risk/intel/status'], ['post', '/risk/intel/sync']]);
  });
  test('sends asset exposure including an explicit false', async () => {
    await assetsService.updateAsset(4, { internet_facing: false, network_zone: 'ot' });
    expect(JSON.parse(requests[0].data)).toEqual({ internet_facing: false, network_zone: 'ot' });
  });
  test('deep links to the score explanation', () => {
    expect(vulnerabilityDetailURL(15, 'risk')).toBe('/vulnerabilities?detail=15&section=risk');
  });
});

describe('risk model helpers mirror the server rules', () => {
  test('accepts the defaults and relative weights that do not sum to 100', () => {
    expect(validateRiskConfig(defaults())).toBe('');
    expect(validateRiskConfig({ ...defaults(), weights: { cvss: 3, epss: 2, kev: 1.5, asset_importance: 2, exposure: 1.5 } })).toBe('');
    expect(validateRiskConfig({ ...defaults(), weights: { cvss: 50, epss: 0, kev: 0, asset_importance: 30, exposure: 20 }, kev_min_priority: '' })).toBe('');
  });
  test('rejects what the server rejects', () => {
    const invalid: Array<(config: RiskConfig) => void> = [
      config => { config.weights.cvss = -1; },
      config => { config.weights.epss = 101; },
      config => { config.weights.kev = NaN; },
      config => { config.weights.cvss = 0; config.weights.asset_importance = 0; config.weights.exposure = 0; },
      config => { config.thresholds.p2 = config.thresholds.p1; },
      config => { config.thresholds.p3 = 0; },
      config => { config.thresholds.p1 = 100.5; },
      config => { config.sla_hours.p1 = 0; },
      config => { config.sla_hours.p2 = 12; },
      config => { config.sla_hours.p3 = 100.5; },
      config => { (config as { kev_min_priority: string }).kev_min_priority = 'P4'; },
    ];
    for (const change of invalid) {
      const config = defaults();
      change(config);
      expect(validateRiskConfig(config)).not.toBe('');
    }
  });
  test('formats probabilities, deadlines, tiers and zones for display', () => {
    expect(formatEPSS(0.94358)).toBe('94.36%');
    expect(formatEPSS(0.00004)).toBe('<0.01%');
    expect(formatEPSS(0)).toBe('0.00%');
    expect(formatEPSS(null)).toBe('—');
    expect(formatSLAHours(24)).toBe('24 小时');
    expect(formatSLAHours(72)).toBe('3 天');
    expect(formatSLAHours(100)).toBe('4.2 天');
    expect(formatSLAHours(NaN)).toBe('—');
    expect(riskPriorityMeta('P1')?.variant).toBe('destructive');
    expect(riskPriorityMeta('')).toBeUndefined();
    expect(networkZoneLabel('ot')).toBe('OT/工控网段');
    expect(networkZoneLabel(undefined)).toBe('内部办公网段');
    expect(weightShare(defaults(), 'cvss')).toBeCloseTo(30);
    expect(weightShare({ ...defaults(), weights: { cvss: 1, epss: 0, kev: 0, asset_importance: 1, exposure: 0 } }, 'cvss')).toBeCloseTo(50);
  });
});
