import type { InboxNotification, RetestRecord } from '../types/roadmap';
import type { NotificationSettings, NotificationSettingsRequest } from '../services/settings';

export const notificationCategories = [
  { key: 'vuln_new', label: '新漏洞发现' },
  { key: 'vuln_assigned', label: '漏洞分配' },
  { key: 'vuln_fixed', label: '漏洞修复' },
  { key: 'report', label: '报告通知' },
  { key: 'system', label: '系统通知与 SLA 安全提醒' },
  { key: 'social', label: '团队活动' },
] as const;
export type NotificationCategory = typeof notificationCategories[number]['key'];
export type NotificationChannel = 'email' | 'push' | 'sms';
export type NotificationPreferenceKey = `${NotificationCategory}_${NotificationChannel}`;

export function notificationPreferenceKey(category: NotificationCategory, channel: NotificationChannel): NotificationPreferenceKey {
  return `${category}_${channel}`;
}
export function notificationPreferences(settings: NotificationSettings): NotificationSettingsRequest {
  return Object.fromEntries(notificationCategories.flatMap(({ key }) => (['email', 'push', 'sms'] as const).map(channel => {
    const field = notificationPreferenceKey(key, channel);
    return [field, settings[field]];
  })));
}

export function vulnerabilityDetailURL(id: number, section?: string): string {
  const query = new URLSearchParams({ detail: String(id) });
  if (section && ['risk', 'sla', 'retests', 'duplicates'].includes(section)) query.set('section', section);
  return `/vulnerabilities?${query}`;
}
export function notificationTarget(notification: InboxNotification): string | undefined {
  const data = notification.data || {};
  const id = Number(notification.entity_id || data.vulnerability_id);
  if (!Number.isSafeInteger(id) || id <= 0) return undefined;
  if (notification.entity_type === 'vulnerability' || notification.entity_type === 'vuln' || data.vulnerability_id) {
    const section = typeof data.section === 'string' ? data.section : data.stage || data.overdue_level != null || notification.type.includes('sla') ? 'sla' : data.retest_id ? 'retests' : undefined;
    return vulnerabilityDetailURL(id, section);
  }
  return undefined;
}

export function buildRetestForm(result: RetestRecord['result'], summary: string, evidence: File[]): FormData {
  const data = new FormData();
  data.append('data', JSON.stringify({ result, summary }));
  evidence.forEach(file => data.append('evidence', file));
  return data;
}
/** Cache a successful create (including simultaneous submits), but allow a failed request to be retried. */
export function createOnce<Args extends unknown[], Result>(create: (...args: Args) => Promise<Result>): (...args: Args) => Promise<Result> {
  let pending: Promise<Result> | undefined;
  return (...args) => {
    if (!pending) pending = create(...args).catch(error => { pending = undefined; throw error; });
    return pending;
  };
}

export function ordinaryStatusChange(status: string, previous?: string): { status?: string } {
  return ['new', 'processing', 'fixed'].includes(status) && status !== previous ? { status } : {};
}
