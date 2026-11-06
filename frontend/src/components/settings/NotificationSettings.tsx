import { useCallback, useEffect, useState } from 'react';
import { Bell, Save } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { settingsService, NotificationSettingsRequest } from '../../services/settings';
import { notificationCategories, notificationPreferenceKey, notificationPreferences } from '../../lib/roadmap';
import { getErrorMessage } from '../../lib/utils';

export function NotificationSettings() {
  const [settings, setSettings] = useState<NotificationSettingsRequest>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const load = useCallback(async () => {
    setError('');
    try { setSettings(notificationPreferences(await settingsService.getNotificationSettings())); }
    catch (err) { setError(getErrorMessage(err, '加载通知设置失败')); }
  }, []);
  useEffect(() => { void load(); }, [load]);
  const save = async () => {
    if (!settings) return;
    setBusy(true); setError(''); setSuccess('');
    try { await settingsService.updateNotificationSettings(settings); setSuccess('通知偏好已保存'); }
    catch (err) { setError(getErrorMessage(err, '保存通知设置失败')); }
    finally { setBusy(false); }
  };
  return <Card><CardHeader><CardTitle className="flex gap-2 items-center"><Bell className="h-5 w-5" />通知设置</CardTitle></CardHeader><CardContent className="space-y-5">
    <p className="text-sm text-gray-600">站内提醒显示在通知收件箱。系统通知设置同时控制 SLA 安全提醒；新功能默认启用站内提醒。邮件和短信仅显示已保存的渠道偏好，当前新增的 SLA 与复测事件不发送邮件或短信。</p>
    {error && <div role="alert" className="text-red-600">{error} <Button size="sm" variant="outline" onClick={load}>重试</Button></div>}
    {success && <p role="status" className="text-green-700">{success}</p>}
    {!settings && !error && <p role="status">正在加载通知偏好…</p>}
    {settings && <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b"><th className="text-left p-3">通知类别</th><th className="p-3">站内提醒</th><th className="p-3">邮件偏好</th><th className="p-3">短信偏好</th></tr></thead><tbody>
      {notificationCategories.map(({ key, label }) => <tr key={key} className="border-b"><th className="text-left p-3 font-medium">{label}</th>{(['push', 'email', 'sms'] as const).map(channel => {
        const field = notificationPreferenceKey(key, channel);
        return <td key={channel} className="p-3 text-center"><input type="checkbox" aria-label={`${label} ${channel === 'push' ? '站内提醒' : channel === 'email' ? '邮件偏好' : '短信偏好'}`} checked={settings[field] ?? false} disabled={busy} onChange={event => { setSuccess(''); setSettings(previous => ({ ...previous, [field]: event.target.checked })); }} /></td>;
      })}</tr>)}
    </tbody></table></div>}
    <div className="flex justify-end"><Button disabled={!settings || busy} loading={busy} onClick={save}><Save className="h-4 w-4 mr-2" />保存设置</Button></div>
  </CardContent></Card>;
}
