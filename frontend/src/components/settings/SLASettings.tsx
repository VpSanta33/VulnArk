import { useCallback, useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { roadmapService } from '../../services/roadmap';
import { vulnerabilitiesService } from '../../services/vulnerabilities';
import { getErrorMessage } from '../../lib/utils';
import type { SLAPolicy, SLAPolicyInput } from '../../types/roadmap';
import type { VulnerabilityAssetOption } from '../../types/api';

const emptyPolicy: SLAPolicyInput = { name: '', severity_level: 3, department: '', asset_id: null, response_hours: 24, fix_hours: 168, enabled: true };
export function SLASettings() {
  const [policies, setPolicies] = useState<SLAPolicy[]>([]);
  const [assets, setAssets] = useState<VulnerabilityAssetOption[]>([]);
  const [draft, setDraft] = useState<SLAPolicyInput>(emptyPolicy);
  const [editingId, setEditingId] = useState<number>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try { setPolicies((await roadmapService.policies()).data || []); }
    catch (err) { setError(getErrorMessage(err, '加载 SLA 策略失败')); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); vulnerabilitiesService.getAssetOptions().then(setAssets).catch(() => { /* Asset ID input remains available without vuln option permissions. */ }); }, [load]);
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(''); setSuccess('');
    try {
      await roadmapService.savePolicy({ ...draft, name: draft.name.trim(), department: draft.department.trim() }, editingId);
      setDraft(emptyPolicy); setEditingId(undefined); await load(); setSuccess('SLA 策略已保存，新建漏洞将按匹配策略计算期限。');
    } catch (err) { setError(getErrorMessage(err, '保存 SLA 策略失败')); }
    finally { setBusy(false); }
  };
  const remove = async (id: number) => {
    if (!confirm('确定删除此 SLA 策略吗？已有漏洞期限不会因此重算。')) return;
    setBusy(true); setError('');
    try { await roadmapService.deletePolicy(id); await load(); if (id === editingId) { setEditingId(undefined); setDraft(emptyPolicy); } }
    catch (err) { setError(getErrorMessage(err, '删除策略失败')); }
    finally { setBusy(false); }
  };
  return <div className="space-y-5"><Card><CardHeader><CardTitle>SLA 策略</CardTitle></CardHeader><CardContent className="space-y-4">
    <p className="text-sm text-gray-600">按严重程度、资产和部门配置响应与修复期限。策略应用于新建漏洞，修改策略不会回填历史逾期。</p>
    {error && <p role="alert" className="text-red-600">{error} <Button size="sm" variant="outline" onClick={load}>重试</Button></p>}{success && <p role="status" className="text-green-700">{success}</p>}
    {loading ? <p>正在加载策略…</p> : <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left"><th className="p-2">策略 / 范围</th><th className="p-2">响应 / 修复</th><th className="p-2">状态</th><th className="p-2">操作</th></tr></thead><tbody>{policies.map(policy => <tr key={policy.id} className="border-b"><td className="p-2"><p className="font-medium">{policy.name}</p><p className="text-gray-500">{vulnerabilitiesService.getSeverityLevels().find(level => level.value === policy.severity_level)?.label} · {policy.asset_id ? `资产 #${policy.asset_id}` : '全部资产'} · {policy.department || '全部部门'}</p></td><td className="p-2">{policy.response_hours}h / {policy.fix_hours}h</td><td className="p-2">{policy.enabled ? '启用' : '停用'}</td><td className="p-2 whitespace-nowrap"><Button size="sm" variant="outline" disabled={busy} onClick={() => { setEditingId(policy.id); setDraft({ name: policy.name, severity_level: policy.severity_level, asset_id: policy.asset_id, department: policy.department, response_hours: policy.response_hours, fix_hours: policy.fix_hours, enabled: policy.enabled }); setSuccess(''); }}>编辑</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => remove(policy.id)}>删除</Button></td></tr>)}</tbody></table>{!policies.length && <p className="p-4 text-gray-500">暂无策略</p>}</div>}
  </CardContent></Card><Card><CardHeader><CardTitle>{editingId ? '编辑策略' : '新增策略'}</CardTitle></CardHeader><CardContent><form onSubmit={save} className="space-y-4"><div className="grid grid-cols-1 md:grid-cols-2 gap-4">
    <label className="text-sm space-y-1"><span>策略名称</span><Input required maxLength={100} value={draft.name} onChange={event => setDraft(previous => ({ ...previous, name: event.target.value }))} /></label>
    <label className="text-sm space-y-1"><span>严重程度</span><Select value={draft.severity_level} options={vulnerabilitiesService.getSeverityLevels()} onChange={event => setDraft(previous => ({ ...previous, severity_level: Number(event.target.value) }))} /></label>
    <label className="text-sm space-y-1"><span>资产范围（留空匹配全部）</span>{assets.length ? <Select value={draft.asset_id || ''} options={[{ value: '', label: '全部资产' }, ...assets.map(asset => ({ value: asset.id, label: asset.name }))]} onChange={event => setDraft(previous => ({ ...previous, asset_id: event.target.value ? Number(event.target.value) : null }))} /> : <Input type="number" min="1" placeholder="资产 ID，可留空" value={draft.asset_id || ''} onChange={event => setDraft(previous => ({ ...previous, asset_id: event.target.value ? Number(event.target.value) : null }))} />}</label>
    <label className="text-sm space-y-1"><span>部门（留空匹配全部）</span><Input maxLength={100} value={draft.department} onChange={event => setDraft(previous => ({ ...previous, department: event.target.value }))} /></label>
    <label className="text-sm space-y-1"><span>响应期限（小时）</span><Input required type="number" min="1" step="1" value={draft.response_hours} onChange={event => setDraft(previous => ({ ...previous, response_hours: Number(event.target.value) }))} /></label>
    <label className="text-sm space-y-1"><span>修复期限（小时）</span><Input required type="number" min="1" step="1" value={draft.fix_hours} onChange={event => setDraft(previous => ({ ...previous, fix_hours: Number(event.target.value) }))} /></label>
  </div><label className="flex gap-2 text-sm"><input type="checkbox" checked={draft.enabled} onChange={event => setDraft(previous => ({ ...previous, enabled: event.target.checked }))} />启用策略</label><div className="flex justify-end gap-2">{editingId && <Button type="button" variant="outline" onClick={() => { setEditingId(undefined); setDraft(emptyPolicy); }}>取消编辑</Button>}<Button loading={busy} type="submit">保存策略</Button></div></form></CardContent></Card></div>;
}
