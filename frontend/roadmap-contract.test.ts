import { afterEach, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import type { AxiosAdapter, InternalAxiosRequestConfig } from 'axios';
import { apiClient } from './src/services/api';
import { roadmapService } from './src/services/roadmap';
import { reportsService } from './src/services/reports';
import { vulnerabilitiesService } from './src/services/vulnerabilities';
import { permissionGranted } from './src/lib/permissions';
import { buildRetestForm, createOnce, notificationPreferences, notificationTarget, ordinaryStatusChange, vulnerabilityDetailURL } from './src/lib/roadmap';
import type { NotificationSettings } from './src/services/settings';
import type { InboxNotification } from './src/types/roadmap';

const client = apiClient.getClient();
const originalAdapter = client.defaults.adapter;
const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
let requests: InternalAxiosRequestConfig[];
let responseData: unknown;
let respond: ((config: InternalAxiosRequestConfig) => unknown) | undefined;
beforeEach(() => {
  requests = []; responseData = null; respond = undefined;
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'contract-token' } });
  const adapter: AxiosAdapter = async config => {
    requests.push(config);
    return { config, status: 200, statusText: 'OK', headers: {}, data: { code: 200, message: 'success', data: respond ? respond(config) : responseData } };
  };
  client.defaults.adapter = adapter;
});
afterEach(() => {
  client.defaults.adapter = originalAdapter;
  if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
  else Reflect.deleteProperty(globalThis, 'localStorage');
});

describe('permission parity with the backend', () => {
  test('matches aliases, wildcard modules and exact permissions without broadening access', () => {
    expect(permissionGranted(['*'], 'sla:manage')).toBe(true);
    expect(permissionGranted(['vulnerability:*'], 'vuln:verify')).toBe(true);
    expect(permissionGranted(['vuln:update'], 'vulnerability:update')).toBe(true);
    expect(permissionGranted(['vuln:read'], 'vuln:update')).toBe(false);
    expect(permissionGranted(['vuln:*'], 'sla:manage')).toBe(false);
    expect(permissionGranted(['vuln:*'], 'vulns:read')).toBe(false);
    expect(permissionGranted(undefined, 'vuln:read')).toBe(false);
  });
  test('ordinary edits never directly verify or close a vulnerability', () => {
    expect(ordinaryStatusChange('verified', 'fixed')).toEqual({});
    expect(ordinaryStatusChange('closed', 'fixed')).toEqual({});
    expect(ordinaryStatusChange('processing', 'new')).toEqual({ status: 'processing' });
    expect(ordinaryStatusChange('fixed', 'fixed')).toEqual({});
  });
});

describe('SLA wire contracts', () => {
  test('loads every policy page using the server maximum page size', async () => {
    respond = config => ({ total: 51, total_pages: 2, page: config.params.page, page_size: 50, data: [{ id: config.params.page }] });
    const result = await roadmapService.policies();
    expect(result.data.map(item => item.id)).toEqual([1, 2]);
    expect(requests.map(request => [request.url, request.params])).toEqual([
      ['/sla-policies', { page: 1, page_size: 50 }], ['/sla-policies', { page: 2, page_size: 50 }],
    ]);
  });
  test('sends disabled=false and nullable asset scope unchanged', async () => {
    await roadmapService.savePolicy({ name: '默认', severity_level: 2, asset_id: null, department: '', response_hours: 4, fix_hours: 72, enabled: false }, 9);
    expect(requests[0].url).toBe('/sla-policies/9'); expect(requests[0].method).toBe('put');
    expect(JSON.parse(requests[0].data)).toMatchObject({ enabled: false, asset_id: null, department: '' });
    await roadmapService.sla(5); await roadmapService.pauseSLA(5); await roadmapService.resumeSLA(5);
    expect(requests.slice(1).map(request => [request.method, request.url])).toEqual([
      ['get', '/vulnerabilities/5/sla'], ['post', '/vulnerabilities/5/sla/pause'], ['post', '/vulnerabilities/5/sla/resume'],
    ]);
  });
  test('passes overdue filtering to the existing paginated list', async () => {
    responseData = { total: 0, page: 1, page_size: 10, total_pages: 0, data: [] };
    await vulnerabilitiesService.getVulnerabilities({ sla_status: 'overdue', page: 1 });
    expect(requests[0].url).toContain('sla_status=overdue');
  });
});

describe('independent retest and evidence contract', () => {
  test('serializes only result and summary into data with repeated evidence files', async () => {
    const first = new File(['evidence-a'], 'a.txt', { type: 'text/plain' });
    const second = new File(['evidence-b'], 'b.png', { type: 'image/png' });
    const form = buildRetestForm('fail', '仍能复现', [first, second]);
    expect(JSON.parse(String(form.get('data')))).toEqual({ result: 'fail', summary: '仍能复现' });
    expect(form.getAll('evidence').map(file => (file as File).name)).toEqual(['a.txt', 'b.png']);
    responseData = { id: 42, tester_id: 8, result: 'fail', previous_status: 'fixed', new_status: 'processing' };
    expect((await roadmapService.retest(7, 'fail', '仍能复现', [first])).id).toBe(42);
    expect(requests[0].url).toBe('/vulnerabilities/7/retest'); expect(requests[0].method).toBe('post');
    expect(requests[0].data).toBeInstanceOf(FormData);
    expect(requests[0].headers.Authorization).toBe('Bearer contract-token');
  });
  test('fetches records as an array and downloads evidence by zero-based index', async () => {
    responseData = [{ id: 22, tester_id: 3 }];
    expect(await roadmapService.retests(7)).toEqual([{ id: 22, tester_id: 3 }]);
    const download = spyOn(apiClient, 'download').mockResolvedValue(undefined);
    try {
      await roadmapService.downloadRetestEvidence(7, 22, 0, '复测.txt');
      expect(download).toHaveBeenCalledWith('/vulnerabilities/7/retests/22/evidence/0/download', '复测.txt');
    } finally { download.mockRestore(); }
  });
});

describe('duplicate lifecycle contracts', () => {
  test('retains a successfully created ID across simultaneous submits and failed link retries', async () => {
    let creates = 0;
    const create = createOnce(async (title: string) => { creates++; return { id: 99, title }; });
    const [first, second] = await Promise.all([create('new'), create('new')]);
    expect(first.id).toBe(99); expect(second.id).toBe(99); expect(creates).toBe(1);
    const link = spyOn(roadmapService, 'linkDuplicate').mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce(undefined);
    try {
      await expect(roadmapService.linkDuplicate(first.id, 2)).rejects.toThrow('network');
      const existing = await create('new');
      await roadmapService.linkDuplicate(existing.id, 2);
      expect(creates).toBe(1); expect(link).toHaveBeenLastCalledWith(99, 2);
    } finally { link.mockRestore(); }
  });
  test('allows a failed create to be retried instead of caching the error forever', async () => {
    let attempts = 0;
    const create = createOnce(async () => { if (++attempts === 1) throw new Error('offline'); return { id: 100 }; });
    await expect(create()).rejects.toThrow('offline');
    expect((await create()).id).toBe(100); expect(attempts).toBe(2);
  });
  test('sends the watched query including self-exclusion ID and keeps suggestions advisory', async () => {
    responseData = [{ id: 2, title: 'similar', score: 80, reasons: ['同一资产'] }];
    const query = { asset_id: 1, vulnerability_id: 99, title: 'SQL injection', cve_id: 'CVE-2026-1', impact_scope: '/login' };
    expect((await roadmapService.candidates(query))[0].reasons).toEqual(['同一资产']);
    expect(requests[0].params).toEqual(query);
    expect(requests[0].url).toBe('/vulnerabilities/duplicates/candidates');
    expect(requests).toHaveLength(1);
  });
  test('uses confirmed link and ignore endpoints independently of vulnerability creation', async () => {
    await roadmapService.linkDuplicate(99, 2, '人工确认');
    await roadmapService.unlinkDuplicate(99, 2, '解除');
    await roadmapService.ignoreDuplicate(99, 2, '非重复');
    await roadmapService.restoreDuplicate(99, 2);
    expect(requests.map(request => [request.method, request.url])).toEqual([
      ['post', '/vulnerabilities/99/duplicates/2/link'], ['delete', '/vulnerabilities/99/duplicates/2/link'],
      ['post', '/vulnerabilities/99/duplicates/2/ignore'], ['delete', '/vulnerabilities/99/duplicates/2/ignore'],
    ]);
    expect(JSON.parse(requests[0].data)).toEqual({ relation_type: 'duplicate', reason: '人工确认' });
    responseData = [{ other: { id: 2, title: 'similar' }, state: 'ignored', occurred_at: '2026-10-28T00:00:00Z' }];
    expect((await roadmapService.duplicates(99))[0].other.id).toBe(2);
  });
});

test('report previews fetch private bytes through the authenticated download endpoint', async () => {
  const original = client.defaults.adapter;
  try {
    client.defaults.adapter = async config => {
      requests.push(config);
      return { config, status: 200, statusText: 'OK', headers: {}, data: new Blob(['%PDF-private'], { type: 'application/pdf' }) };
    };
    const blob = await reportsService.getReportBlob(8);
    expect(await blob.text()).toBe('%PDF-private');
    expect(requests[0].url).toBe('/reports/8/download');
    expect(requests[0].responseType).toBe('blob');
    expect(requests[0].headers.Authorization).toBe('Bearer contract-token');
  } finally { client.defaults.adapter = original; }
});

describe('notification persistence and internal deep links', () => {
  test('preserves all eighteen real fields including false values', () => {
    const input = { id: 7, user_id: 3, vuln_new_email: false, vuln_new_push: true, vuln_assigned_sms: false, system_push: false } as NotificationSettings;
    const result = notificationPreferences(input);
    expect(Object.keys(result)).toHaveLength(18);
    expect(result.vuln_new_email).toBe(false); expect(result.vuln_new_push).toBe(true);
    expect(result.system_push).toBe(false); expect(result.vuln_assigned_sms).toBe(false);
    expect(result).not.toHaveProperty('new_vulnerability_email');
    expect(result).not.toHaveProperty('sla_enabled');
  });
  test('links SLA notifications from actual stage data and rejects unsafe arbitrary routes', () => {
    const notification = { entity_type: 'vulnerability', entity_id: 15, data: { stage: 'fix', overdue_level: 24 } } as InboxNotification;
    expect(notificationTarget(notification)).toBe('/vulnerabilities?detail=15&section=sla');
    expect(vulnerabilityDetailURL(15, 'retests')).toBe('/vulnerabilities?detail=15&section=retests');
    expect(notificationTarget({ ...notification, entity_id: -1 })).toBeUndefined();
    expect(notificationTarget({ ...notification, data: { section: 'https://evil.example' } })).toBe('/vulnerabilities?detail=15');
  });
  test('uses personal inbox, stats, read and read-all APIs without admin listing', async () => {
    responseData = [];
    expect(await roadmapService.notifications()).toEqual([]);
    await roadmapService.notificationStats(); await roadmapService.readNotification(10); await roadmapService.readAllNotifications();
    expect(requests.map(request => request.url)).toEqual(['/notifications/my', '/notifications/stats', '/notifications/10/read', '/notifications/read-all']);
  });
});
