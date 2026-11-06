import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bell } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Card, CardContent } from '../components/ui/Card';
import { roadmapService } from '../services/roadmap';
import { notificationTarget } from '../lib/roadmap';
import { getErrorMessage } from '../lib/utils';
import { useAuth } from '../contexts/AuthContext';
import type { InboxNotification, NotificationStats } from '../types/roadmap';

export function Notifications() {
  const { hasPermission } = useAuth();
  const [notifications, setNotifications] = useState<InboxNotification[]>([]);
  const [stats, setStats] = useState<NotificationStats>();
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [unreadOnly, setUnreadOnly] = useState(false);
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { const [items, totals] = await Promise.all([roadmapService.notifications(limit), roadmapService.notificationStats()]); setNotifications(items); setStats(totals); }
    catch (err) { setError(getErrorMessage(err, '加载通知收件箱失败')); }
    finally { setLoading(false); }
  }, [limit]);
  useEffect(() => { void load(); }, [load]);
  const act = async (action: () => Promise<void>) => {
    setBusy(true); setError('');
    try { await action(); await load(); }
    catch (err) { setError(getErrorMessage(err, '更新通知失败')); }
    finally { setBusy(false); }
  };
  const visible = notifications.filter(item => !unreadOnly || !item.is_read);
  return <div className="space-y-6">
    <div className="flex flex-wrap justify-between gap-3"><div><h1 className="text-3xl font-bold flex gap-2 items-center"><Bell />站内通知</h1><p className="text-sm text-gray-600 mt-2">{stats ? `共 ${stats.total} 条，${stats.unread} 条未读` : '接收漏洞、复测和 SLA 提醒'}</p></div><div className="flex gap-2 items-center"><Button variant="outline" disabled={busy || loading} onClick={load}>刷新</Button><Button disabled={busy || !stats?.unread} onClick={() => act(() => roadmapService.readAllNotifications())}>全部标为已读</Button></div></div>
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={unreadOnly} onChange={event => setUnreadOnly(event.target.checked)} />仅显示未读</label>
    {error && <p role="alert" className="text-red-600">{error}</p>}
    {loading && <p role="status">正在加载通知…</p>}
    {!loading && !visible.length && <Card><CardContent className="p-8 text-center text-gray-500">暂无{unreadOnly ? '未读' : ''}通知</CardContent></Card>}
    <ul className="space-y-3">{visible.map(item => {
      const target = hasPermission('vuln:read') ? notificationTarget(item) : undefined;
      return <li key={item.id}><Card className={item.is_read ? '' : 'border-blue-300'}><CardContent className="p-5 space-y-3"><div className="flex justify-between gap-3"><h2 className="font-semibold">{!item.is_read && <span className="text-blue-600 mr-2">未读</span>}{item.title}</h2><time className="text-xs text-gray-500">{new Date(item.created_at).toLocaleString('zh-CN')}</time></div><p className="text-sm whitespace-pre-wrap break-words">{item.content}</p><div className="flex gap-3 items-center">{target && <Link className="text-sm text-blue-600 hover:underline" to={target} onClick={() => { if (!item.is_read) void act(() => roadmapService.readNotification(item.id)); }}>查看关联漏洞</Link>}{!item.is_read && <Button size="sm" variant="outline" disabled={busy} onClick={() => act(() => roadmapService.readNotification(item.id))}>标为已读</Button>}<Button size="sm" variant="ghost" disabled={busy} onClick={() => act(() => roadmapService.deleteNotification(item.id))}>删除</Button></div></CardContent></Card></li>;
    })}</ul>
    {notifications.length >= limit && <Button variant="outline" disabled={loading} onClick={() => setLimit(value => value + 50)}>加载更多</Button>}
  </div>;
}
