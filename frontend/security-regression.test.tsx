import { afterEach, expect, test } from 'bun:test';
import { act, cleanup, renderHook } from '@testing-library/react';
import { useState } from 'react';
import { sanitizeHTML } from './src/lib/sanitizeHTML';
import { useLatestRequest, useSearchKeyword } from './src/hooks/useListSearch';
import { apiClient } from './src/services/api';
import { AuthService } from './src/services/auth';
import { vulnerabilitiesService } from './src/services/vulnerabilities';
import { assetsService } from './src/services/assets';
import { reportsService } from './src/services/reports';
import { usersService } from './src/services/users';
import { aiService } from './src/services/aiService';

afterEach(() => { cleanup(); localStorage.clear(); });

test('historical HTML strips executable content and preserves formatted text', () => {
 const cleaned = sanitizeHTML('<h2>Title</h2><p><strong>text</strong><a href="javascript:alert(1)" onclick="alert(1)">link</a><img src="x" onerror="alert(1)"></p><script>alert(1)</script><svg onload="alert(1)"></svg><iframe srcdoc="evil"></iframe><form><input name="token"></form>');
 const element = document.createElement('div'); element.innerHTML = cleaned;
 expect(element.querySelector('h2')?.textContent).toBe('Title');
 expect(element.querySelector('strong')?.textContent).toBe('text');
 expect(element.querySelector('script,svg,iframe,form,input')).toBeNull();
 expect(element.querySelector('[onclick],[onerror],[onload]')).toBeNull();
 expect(element.querySelector('a')?.hasAttribute('href')).toBe(false);
});

test('search coalesces keystrokes and resets the page once', async () => {
 const { result } = renderHook(() => {
  const [params, setParams] = useState({ page: 4, keyword: '' });
  const [keyword, setKeyword] = useSearchKeyword(setParams, 25);
  return { params, keyword, setKeyword };
 });
 act(() => result.current.setKeyword('a'));
 act(() => result.current.setKeyword('ab'));
 expect(result.current.keyword).toBe('ab');
 expect(result.current.params).toEqual({ page: 4, keyword: '' });
 await act(async () => { await new Promise(resolve => setTimeout(resolve, 45)); });
 expect(result.current.params).toEqual({ page: 1, keyword: 'ab' });
});

test('late results cannot replace a newer result, and unmount invalidates requests', async () => {
 const { result, unmount } = renderHook(useLatestRequest);
 let first!: ReturnType<typeof result.current.begin>;
 let second!: ReturnType<typeof result.current.begin>;
 act(() => { first = result.current.begin(); });
 act(() => { second = result.current.begin(); });
 expect(first.signal.aborted).toBe(true);
 let shown = '';
 await Promise.resolve('new').then(value => { if (second.isCurrent()) shown = value; });
 await Promise.resolve('old').then(value => { if (first.isCurrent()) shown = value; });
 expect(shown).toBe('new');
 unmount();
 expect(second.signal.aborted).toBe(true);
 expect(second.isCurrent()).toBe(false);
});

test('logout sends the token before clearing it and clears it on failure', async () => {
 const client = apiClient.getClient();
 const originalAdapter = client.defaults.adapter;
 try {
  const service = new AuthService();
  apiClient.setToken('logout-token');
  let complete!: () => void;
  let started!: () => void;
  const entered = new Promise<void>(resolve => { started = resolve; });
  client.defaults.adapter = async config => {
   expect(config.url).toBe('/logout'); expect(config.method).toBe('post');
   expect(config.headers.Authorization).toBe('Bearer logout-token');
   expect(localStorage.getItem('vulnark_token')).toBe('logout-token');
   await new Promise<void>(resolve => { complete = resolve; started(); });
   return { data: { success: true }, status: 200, statusText: 'OK', headers: {}, config };
  };
  const pending = service.logout();
  await entered;
  expect(localStorage.getItem('vulnark_token')).toBe('logout-token');
  complete(); await pending;
  expect(localStorage.getItem('vulnark_token')).toBeNull();
  apiClient.setToken('failed-token');
  client.defaults.adapter = async () => { throw new Error('offline'); };
  await expect(service.logout()).rejects.toMatchObject({ message: 'offline' });
  expect(localStorage.getItem('vulnark_token')).toBeNull();
 } finally { client.defaults.adapter = originalAdapter; }
});


test('all four list services pass request cancellation through to HTTP', async () => {
 const client = apiClient.getClient(); const originalAdapter = client.defaults.adapter;
 const controller = new AbortController(); let calls = 0;
 try {
  client.defaults.adapter = async config => {
   expect(config.signal).toBe(controller.signal); calls++;
   return { data: { data: { items: [], total: 0 } }, status: 200, statusText: 'OK', headers: {}, config };
  };
  await vulnerabilitiesService.getVulnerabilities({}, controller.signal);
  await assetsService.getAssets({}, controller.signal);
  await reportsService.getReports({}, controller.signal);
  await usersService.getUsers({}, controller.signal);
  expect(calls).toBe(4);
 } finally { client.defaults.adapter = originalAdapter; }
});

test('AI settings allow a saved key to be kept and require explicit safe deletion', () => {
 const settings = { provider: 'openai', api_key: '', model: 'model', max_tokens: 2000, temperature: 0.7, timeout: 30, enabled: true };
 expect(aiService.validateConfiguration(settings, true)).toEqual([]);
 expect(aiService.validateConfiguration(settings, false).length).toBeGreaterThan(0);
 expect(aiService.validateConfiguration({ ...settings, clear_api_key: true }, true).length).toBeGreaterThan(0);
});

test('logout treats an already expired session as logged out', async () => {
 const client = apiClient.getClient(); const originalAdapter = client.defaults.adapter;
 try {
  apiClient.setToken('expired-token');
  client.defaults.adapter = async config => {
   expect(config.validateStatus?.(401)).toBe(true);
   return { data: {}, status: 401, statusText: 'Unauthorized', headers: {}, config };
  };
  await new AuthService().logout();
  expect(localStorage.getItem('vulnark_token')).toBeNull();
 } finally { client.defaults.adapter = originalAdapter; }
});
