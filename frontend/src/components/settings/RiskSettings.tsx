import { useCallback, useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Badge } from '../ui/Badge';
import { riskService } from '../../services/risk';
import { getErrorMessage } from '../../lib/utils';
import { formatSLAHours, riskFactorKeys, riskFactorLabels, riskPriorities, validateRiskConfig, weightShare } from '../../lib/risk';
import type { RiskConfig, RiskConfigResponse, ThreatIntelStatus } from '../../types/risk';

const time = (value: string | null) => value ? new Date(value).toLocaleString('zh-CN') : '从未';
const tiers = ['p1', 'p2', 'p3', 'p4'] as const;
type ThresholdTier = 'p1' | 'p2' | 'p3';
const numeric = (value: string) => value === '' ? NaN : Number(value);
const shown = (value: number) => Number.isFinite(value) ? value : '';

export function RiskSettings() {
  const [saved, setSaved] = useState<RiskConfigResponse>();
  const [draft, setDraft] = useState<RiskConfig>();
  const [status, setStatus] = useState<ThreatIntelStatus>();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<'' | 'save' | 'sync' | 'recalculate'>('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const loadStatus = useCallback(async () => {
    try { setStatus(await riskService.intelStatus()); }
    catch (err) { setError(getErrorMessage(err, '加载情报同步状态失败')); }
  }, []);
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const response = await riskService.config();
      setSaved(response); setDraft(response.config);
    } catch (err) { setError(getErrorMessage(err, '加载风险评分配置失败')); }
    finally { setLoading(false); }
    await loadStatus();
  }, [loadStatus]);
  useEffect(() => { void load(); }, [load]);

  const problem = draft ? validateRiskConfig(draft) : '';
  const run = async (kind: 'save' | 'sync' | 'recalculate', action: () => Promise<string>) => {
    setBusy(kind); setError(''); setSuccess('');
    try { setSuccess(await action()); }
    catch (err) { setError(getErrorMessage(err, '操作失败')); }
    finally { setBusy(''); }
  };
  const save = (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft || problem) return;
    void run('save', async () => {
      const rescored = await riskService.saveConfig(draft);
      const response = await riskService.config();
      setSaved(response); setDraft(response.config);
      return `评分模型已保存，并按新模型重算了 ${rescored} 条漏洞。`;
    });
  };
  const sync = () => void run('sync', async () => {
    const result = await riskService.syncIntel();
    await loadStatus();
    if (result.errors.length) throw new Error(`部分数据源同步失败，已保留原有缓存：${result.errors.join('；')}`);
    return `同步完成：KEV 目录 ${result.kev_entries} 条，更新 EPSS ${result.epss_updated} 条，重算 ${result.rescored} 条漏洞。`;
  });
  const recalculate = () => void run('recalculate', async () => `已按当前模型重算 ${await riskService.recalculate()} 条漏洞。`);

  if (loading) return <p role="status">正在加载风险评分配置…</p>;
  return (
    <div className="space-y-5">
      {error && <p role="alert" className="text-red-600">{error}</p>}
      {success && <p role="status" className="text-green-700">{success}</p>}
      {draft && <Card><CardHeader><CardTitle>风险评分模型</CardTitle></CardHeader><CardContent>
        <form onSubmit={save} className="space-y-6">
          <p className="text-sm text-gray-600">风险评分（0-100）是各因子取值按权重加权的结果。没有数据的因子（例如无 CVE 编号的渗透测试发现项没有 EPSS 和 KEV）不参与计分，其权重按比例分配给其余因子。保存后会立即重算全部漏洞。</p>
          <fieldset className="space-y-3">
            <legend className="font-medium">因子权重</legend>
            <p className="text-xs text-gray-500">权重是相对值，不要求合计 100；右侧为各因子在全部因子都有数据时的占比。</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {riskFactorKeys.map(key => <label key={key} className="text-sm space-y-1">
                <span className="flex justify-between"><span>{riskFactorLabels[key]}</span><span className="text-gray-500 tabular-nums">占比 {weightShare(draft, key).toFixed(1)}%</span></span>
                <Input type="number" min="0" max="100" step="any" required value={shown(draft.weights[key])} onChange={event => setDraft(previous => previous && ({ ...previous, weights: { ...previous.weights, [key]: numeric(event.target.value) } }))} />
              </label>)}
            </div>
          </fieldset>
          <fieldset className="space-y-3">
            <legend className="font-medium">优先级档位与建议修复期限</legend>
            <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left"><th className="p-2">档位</th><th className="p-2">最低评分</th><th className="p-2">建议修复期限（小时）</th></tr></thead><tbody>
              {tiers.map((tier, index) => <tr key={tier} className="border-b">
                <td className="p-2 whitespace-nowrap"><Badge variant={riskPriorities[index].variant}>{riskPriorities[index].value} {riskPriorities[index].label}</Badge></td>
                <td className="p-2">{tier === 'p4' ? <span className="text-gray-500">低于 P3 阈值</span> : <Input aria-label={`${riskPriorities[index].value} 最低评分`} type="number" min="0" max="100" step="any" required value={shown(draft.thresholds[tier as ThresholdTier])} onChange={event => setDraft(previous => previous && ({ ...previous, thresholds: { ...previous.thresholds, [tier]: numeric(event.target.value) } }))} />}</td>
                <td className="p-2"><div className="flex items-center gap-2"><Input aria-label={`${riskPriorities[index].value} 建议修复期限`} type="number" min="1" step="1" required value={shown(draft.sla_hours[tier])} onChange={event => setDraft(previous => previous && ({ ...previous, sla_hours: { ...previous.sla_hours, [tier]: numeric(event.target.value) } }))} /><span className="whitespace-nowrap text-gray-500">{formatSLAHours(draft.sla_hours[tier])}</span></div></td>
              </tr>)}
            </tbody></table></div>
            <p className="text-xs text-gray-500">建议期限显示在漏洞详情中并与现行 SLA 期限对比，不会自动改写已有 SLA 期限。</p>
          </fieldset>
          <label className="block text-sm space-y-1 md:max-w-sm">
            <span className="font-medium">KEV 保底档位</span>
            <Select value={draft.kev_min_priority} onChange={event => setDraft(previous => previous && ({ ...previous, kev_min_priority: event.target.value as RiskConfig['kev_min_priority'] }))} options={[{ value: '', label: '不设保底' }, { value: 'P1', label: '至少 P1' }, { value: 'P2', label: '至少 P2' }, { value: 'P3', label: '至少 P3' }]} />
            <span className="block text-xs text-gray-500">已收录于 CISA KEV（存在在野利用）的漏洞，无论评分多少都不低于该档位。</span>
          </label>
          {problem && <p role="alert" className="text-sm text-red-600">{problem}</p>}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={!!busy || !!problem}>{busy === 'save' ? '保存并重算中…' : '保存并重算'}</Button>
            <Button type="button" variant="outline" disabled={!!busy} onClick={() => saved && setDraft(saved.defaults)}>填入默认值</Button>
            <Button type="button" variant="ghost" disabled={!!busy} onClick={() => saved && setDraft(saved.config)}>撤销修改</Button>
          </div>
          <p className="text-xs text-gray-500">{saved?.updated_at ? `上次保存于 ${time(saved.updated_at)}` : '当前使用内置默认模型，尚未保存过自定义配置。'}</p>
        </form>
      </CardContent></Card>}

      <Card><CardHeader><CardTitle>威胁情报缓存</CardTitle></CardHeader><CardContent className="space-y-4">
        <p className="text-sm text-gray-600">EPSS 分数和 CISA KEV 目录由后台定时同步到本地缓存，评分只读取缓存。外部接口不可用时保留上一次的数据并稍后重试，不影响平台使用。</p>
        {status && <>
          {!status.enabled && <p className="text-sm text-amber-700">情报同步已在部署配置中禁用（risk_intel.enabled），评分仅使用 CVSS、资产重要性和暴露面。</p>}
          <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left"><th className="p-2">数据源</th><th className="p-2">缓存</th><th className="p-2">最近成功</th><th className="p-2">状态</th></tr></thead><tbody>
            {status.sources.map(source => <tr key={source.source} className="border-b align-top">
              <td className="p-2 font-medium">{source.name}</td>
              <td className="p-2">{source.record_count} 条{source.source_version && <span className="block text-xs text-gray-500">版本 {source.source_version}</span>}</td>
              <td className="p-2">{time(source.last_success_at)}<span className="block text-xs text-gray-500">最近尝试 {time(source.last_attempt_at)}</span></td>
              <td className="p-2">{source.last_error ? <><Badge variant="warning">同步失败</Badge><span className="block text-xs text-red-600 break-all mt-1">{source.last_error}（连续 {source.consecutive_failures} 次，缓存已保留）</span></> : source.stale ? <Badge variant="secondary">{source.last_success_at ? '数据较旧' : '尚未同步'}</Badge> : <Badge variant="success">正常</Badge>}</td>
            </tr>)}
          </tbody></table></div>
          <p className="text-xs text-gray-500">同步周期 {status.sync_interval_hours || '—'} 小时。EPSS 只查询已录入漏洞的 CVE 编号。</p>
        </>}
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={!!busy || !status?.enabled} onClick={sync}>{busy === 'sync' ? '同步中…' : '立即同步'}</Button>
          <Button variant="outline" disabled={!!busy} onClick={recalculate}>{busy === 'recalculate' ? '重算中…' : '重新计算全部评分'}</Button>
          <Button variant="ghost" disabled={!!busy} onClick={() => void loadStatus()}>刷新状态</Button>
        </div>
      </CardContent></Card>
    </div>
  );
}
