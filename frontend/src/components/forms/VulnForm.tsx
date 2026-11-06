import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect, useRef } from 'react';
import { useForm, useWatch } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import { roadmapService } from '../../services/roadmap';
import { createOnce, ordinaryStatusChange, vulnerabilityDetailURL } from '../../lib/roadmap';
import type { DuplicateCandidate } from '../../types/roadmap';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { X, Upload, Image, Trash2 } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/Dialog';
import { vulnerabilitiesService } from '../../services/vulnerabilities';
import { Vulnerability, VulnerabilityAssetOption, AssigneeOption, OWASPCategory } from '../../types/api';

const optionalNumber = (value: string) => value === '' ? undefined : Number(value);
const MAX_FILES = 5;
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const MAX_TOTAL_SIZE = 20 * 1024 * 1024;

const vulnSchema = z.object({
  title: z.string().min(1, '漏洞标题不能为空').max(255, '漏洞标题不能超过255个字符'),
  description: z.string().optional(),
  cve_id: z.string().optional(),
  cnvd_id: z.string().optional(),
  owasp_category_id: z.number().int().positive().optional(),
  severity_level: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  cvss_score: z.number().min(0).max(10).optional(),
  asset_id: z.number().min(1, '请选择影响资产'),
  assignee_id: z.number().int().positive().optional(),
  status: z.string(),
  impact_scope: z.string().optional(),
  reproduction_steps: z.string().optional(),
  fix_suggestion: z.string().optional(),
});

type VulnFormData = z.infer<typeof vulnSchema>;

interface VulnFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  vulnerability?: Vulnerability | null;
}

export function VulnForm({ isOpen, onClose, onSuccess, vulnerability }: VulnFormProps) {
  const { hasPermission } = useAuth();
  const [loading, setLoading] = useState(false);
  const [candidates, setCandidates] = useState<DuplicateCandidate[]>([]);
  const [candidateLoading, setCandidateLoading] = useState(false);
  const [candidateError, setCandidateError] = useState('');
  const [selectedCandidate, setSelectedCandidate] = useState<number>();
  const [createdId, setCreatedId] = useState<number>();
  const [assets, setAssets] = useState<VulnerabilityAssetOption[]>([]);
  const [users, setUsers] = useState<AssigneeOption[]>([]);
  const [owaspCategories, setOWASPCategories] = useState<OWASPCategory[]>([]);
  const [error, setError] = useState<string>('');
  const [screenshots, setScreenshots] = useState<File[]>([]);
  const [previewUrls, setPreviewUrls] = useState<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const createRequest = useRef(createOnce(vulnerabilitiesService.createVulnerability.bind(vulnerabilitiesService)));

  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<VulnFormData>({
    resolver: zodResolver(vulnSchema),
    defaultValues: {
      severity_level: 3,
      status: 'new',
    },
  });

  const [watchedAsset, watchedTitle, watchedCVE, watchedCNVD, watchedScope] = useWatch({ control, name: ['asset_id', 'title', 'cve_id', 'cnvd_id', 'impact_scope'] });
  useEffect(() => {
    if (createdId) { setCandidateLoading(false); return; }
    if (!isOpen || !hasPermission('vuln:read') || !watchedAsset || !(watchedTitle?.trim() || watchedCVE?.trim() || watchedCNVD?.trim() || watchedScope?.trim())) {
      setCandidates([]); setCandidateLoading(false); return;
    }
    const abort = new AbortController();
    let active = true;
    setCandidateLoading(true); setCandidateError(''); setCandidates([]); setSelectedCandidate(undefined);
    const timer = window.setTimeout(() => {
      roadmapService.candidates({ asset_id: watchedAsset, title: watchedTitle, cve_id: watchedCVE, cnvd_id: watchedCNVD, impact_scope: watchedScope, vulnerability_id: vulnerability?.id }, abort.signal)
        .then(data => { if (active) setCandidates(data); })
        .catch(err => { if (active) setCandidateError(getErrorMessage(err, '候选检查失败，仍可正常创建')); })
        .finally(() => { if (active) setCandidateLoading(false); });
    }, 450);
    return () => { active = false; abort.abort(); window.clearTimeout(timer); };
  }, [isOpen, watchedAsset, watchedTitle, watchedCVE, watchedCNVD, watchedScope, vulnerability?.id, createdId, hasPermission]);

  useEffect(() => {
    if (!isOpen) return;
    let active = true;
    Promise.all([
      vulnerabilitiesService.getAssetOptions(),
      vulnerabilitiesService.getAssigneeOptions(),
      vulnerabilitiesService.getOWASPCategories(),
    ]).then(([assetData, assignees, categories]) => {
      if (!active) return;
      setAssets(assetData);
      setUsers(assignees);
      setOWASPCategories(categories);
    }).catch(() => { if (active) setError('加载资产、负责人或分类选项失败，请重新打开表单重试'); });
    return () => { active = false; };
  }, [isOpen]);

  // Reset form when dialog opens/closes
  useEffect(() => {
    if (isOpen) {
      if (vulnerability) {
        // Edit mode - populate form with vulnerability data
        reset({
          title: vulnerability.title,
          description: vulnerability.description || '',
          cve_id: vulnerability.cve_id || '',
          cnvd_id: vulnerability.cnvd_id || '',
          owasp_category_id: vulnerability.owasp_category_id ?? undefined,
          severity_level: vulnerability.severity_level || 3,
          cvss_score: vulnerability.cvss_score ?? undefined,
          asset_id: vulnerability.asset_id,
          assignee_id: vulnerability.assignee_id ?? undefined,
          status: vulnerability.status || 'new',
          impact_scope: vulnerability.impact_scope || '',
          reproduction_steps: vulnerability.reproduction_steps || '',
          fix_suggestion: vulnerability.fix_suggestion || '',
        });
      } else {
        // Create mode - reset to defaults
        reset({
          title: '',
          description: '',
          cve_id: '',
          cnvd_id: '',
          owasp_category_id: undefined,
          severity_level: 3,
          cvss_score: undefined,
          asset_id: 0,
          assignee_id: undefined,
          status: 'new',
          impact_scope: '',
          reproduction_steps: '',
          fix_suggestion: '',
        });
      }
      setError('');
      setCreatedId(undefined); setSelectedCandidate(undefined); setCandidates([]); setCandidateError('');
      createRequest.current = createOnce(vulnerabilitiesService.createVulnerability.bind(vulnerabilitiesService));
      // 重置截图状态
      setScreenshots([]);
    } else {
      setScreenshots([]);
    }
  }, [isOpen, vulnerability, reset]);

  // Each screenshot revision owns all of its URLs. A removal must not revoke
  // URLs that the next render continues to use.
  useEffect(() => {
    const urls = screenshots.map(file => URL.createObjectURL(file));
    setPreviewUrls(urls);
    return () => urls.forEach(url => URL.revokeObjectURL(url));
  }, [screenshots]);

  // 处理文件选择
  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    const selected = Array.from(files);
    const combined = [...screenshots, ...selected];
    if (combined.length > MAX_FILES || combined.reduce((sum, file) => sum + file.size, 0) > MAX_TOTAL_SIZE) {
      setError('最多上传5张截图，总大小不能超过20 MiB');
    } else if (selected.some(file => !['image/png', 'image/jpeg', 'image/gif'].includes(file.type) || file.size === 0 || file.size > MAX_FILE_SIZE)) {
      setError('仅支持PNG、JPEG和GIF，每张截图不能超过5 MiB');
    } else {
      setError('');
      setScreenshots(combined);
    }
    
    // 清空input以便可以重复选择相同文件
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // 删除截图
  const handleRemoveScreenshot = (index: number) => {
    setScreenshots(prev => prev.filter((_, i) => i !== index));
  };

  const onSubmit = async (data: VulnFormData) => {
    try {
      setLoading(true);
      setError('');

      if (createdId) return;
      const { status, asset_id, ...fields } = data;
      if (vulnerability) {
        const updates = { ...fields };
        delete updates.assignee_id;
        await vulnerabilitiesService.updateVulnerability(vulnerability.id, {
          ...updates,
          ...ordinaryStatusChange(status, vulnerability.status),
        });
        onSuccess(); onClose();
      } else {
        const created = await createRequest.current({ ...fields, asset_id }, screenshots.length > 0 ? screenshots : undefined);
        setCreatedId(created.id);
        onSuccess();
        if (!selectedCandidate || !hasPermission('vuln:update')) onClose();
      }
    } catch (err: unknown) {
      setError(getErrorMessage(err, '操作失败'));
    } finally {
      setLoading(false);
    }
  };

  const linkCreated = async () => {
    if (!createdId || !selectedCandidate || loading) return;
    setLoading(true); setError('');
    try { await roadmapService.linkDuplicate(createdId, selectedCandidate); onSuccess(); onClose(); }
    catch (err) { setError(getErrorMessage(err, '漏洞已创建，关联失败。可重试关联或稍后在详情处理，不会重复创建。')); }
    finally { setLoading(false); }
  };

  const severityLevels = [
    { value: 1, label: '严重', color: 'red' },
    { value: 2, label: '高危', color: 'orange' },
    { value: 3, label: '中危', color: 'yellow' },
    { value: 4, label: '低危', color: 'blue' },
  ];

  const statusOptions = [
    { value: 'new', label: '新建' },
    { value: 'processing', label: '处理中' },
    { value: 'fixed', label: '已修复' },
  ];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            {vulnerability ? '编辑漏洞' : '新建漏洞'}
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="h-6 w-6 p-0"
            >
              <X className="h-4 w-4" />
            </Button>
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md">
              {error}
            </div>
          )}

          {createdId && <div role="status" className="rounded border border-green-200 bg-green-50 p-4 text-sm space-y-3"><p>漏洞 #{createdId} 已创建。确认后可将其关联至候选 #{selectedCandidate}，关联失败可安全重试。</p><div className="flex gap-2"><Button type="button" onClick={linkCreated} disabled={loading}>确认关联</Button><Button type="button" variant="outline" onClick={onClose}>稍后处理</Button><Link to={vulnerabilityDetailURL(createdId, 'duplicates')} onClick={onClose} className="text-blue-600 self-center">查看已创建漏洞</Link></div></div>}
          <fieldset disabled={loading || !!createdId} className="space-y-6">
          {/* Basic Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-900">基本信息</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  漏洞标题 <span className="text-red-500">*</span>
                </label>
                <Input
                  {...register('title')}
                  placeholder="请输入漏洞标题"
                  error={errors.title?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  CVE编号
                </label>
                <Input
                  {...register('cve_id')}
                  placeholder="CVE-YYYY-NNNN"
                  error={errors.cve_id?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  CNVD编号
                </label>
                <Input
                  {...register('cnvd_id')}
                  placeholder="CNVD-YYYY-NNNN"
                  error={errors.cnvd_id?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  严重程度 <span className="text-red-500">*</span>
                </label>
                <Select
                  {...register('severity_level', { valueAsNumber: true })}
                  options={severityLevels}
                  placeholder="请选择严重程度"
                  error={errors.severity_level?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  CVSS评分
                </label>
                <Input
                  {...register('cvss_score', { setValueAs: optionalNumber })}
                  type="number"
                  min="0"
                  max="10"
                  step="0.1"
                  placeholder="0.0 - 10.0"
                  error={errors.cvss_score?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  OWASP分类
                </label>
                <Select
                  {...register('owasp_category_id', { setValueAs: optionalNumber })}
                  options={[{ value: '', label: '不指定分类' }, ...owaspCategories.map(category => ({ value: category.id, label: `${category.code} - ${category.name}` }))]}
                  placeholder="请选择OWASP分类"
                  error={errors.owasp_category_id?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  影响资产 <span className="text-red-500">*</span>
                </label>
                {vulnerability ? <>
                  <input type="hidden" {...register('asset_id', { valueAsNumber: true })} />
                  <p className="py-2 text-sm text-gray-600">{vulnerability.asset?.name || `资产 #${vulnerability.asset_id}`}</p>
                </> : <Select
                  {...register('asset_id', { valueAsNumber: true })}
                  options={assets.map(asset => ({
                    value: asset.id,
                    label: `${asset.name} (${asset.ip_address || asset.domain || '未设置地址'})`,
                  }))}
                  placeholder="请选择影响资产"
                  error={errors.asset_id?.message}
                />}
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  负责人
                </label>
                <Select
                  {...register('assignee_id', { setValueAs: optionalNumber })}
                  disabled={!!vulnerability}
                  options={[{ value: '', label: '不指定负责人' }, ...users.map(user => ({
                    value: user.id,
                    label: `${user.real_name} (${user.username})`,
                  }))]}
                  placeholder="请选择负责人"
                  error={errors.assignee_id?.message}
                />
                {vulnerability && <p className="mt-1 text-xs text-gray-500">负责人请通过漏洞分配操作修改。</p>}
              </div>

              {vulnerability && !['verified', 'closed'].includes(vulnerability.status || '') && <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  状态
                </label>
                <Select
                  {...register('status')}
                  options={statusOptions}
                  placeholder="请选择状态"
                  error={errors.status?.message}
                />
              </div>}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                漏洞描述
              </label>
              <textarea
                {...register('description')}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="请详细描述漏洞情况"
              />
              {errors.description && (
                <p className="mt-1 text-sm text-red-600">{errors.description.message}</p>
              )}
            </div>
          </div>

          {/* Detailed Information */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-900">详细信息</h3>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                影响范围
              </label>
              <textarea
                {...register('impact_scope')}
                rows={2}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="请描述漏洞的影响范围"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                复现步骤
              </label>
              <textarea
                {...register('reproduction_steps')}
                rows={4}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="请详细描述漏洞复现步骤"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                修复建议
              </label>
              <textarea
                {...register('fix_suggestion')}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="请提供修复建议"
              />
            </div>
          </div>

          {/* Screenshot Upload - Only show in create mode */}
          {!vulnerability && (
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-gray-900">漏洞截图</h3>
              
              <div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileSelect}
                  accept="image/png,image/jpeg,image/gif"
                  multiple
                  className="hidden"
                  id="screenshot-upload"
                />
                <label
                  htmlFor="screenshot-upload"
                  className="flex items-center justify-center w-full px-4 py-6 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:border-blue-500 hover:bg-blue-50 transition-colors"
                >
                  <div className="text-center">
                    <Upload className="h-8 w-8 mx-auto text-gray-400 mb-2" />
                    <p className="text-sm text-gray-600">点击上传截图</p>
                    <p className="text-xs text-gray-400 mt-1">PNG、JPEG、GIF；最多5张，单张5 MiB，总计20 MiB；最长边8192像素且不超过2000万像素</p>
                  </div>
                </label>
              </div>

              {/* Preview uploaded screenshots */}
              {previewUrls.length > 0 && (
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                  {previewUrls.map((url, index) => (
                    <div key={index} className="relative group">
                      <div className="aspect-video rounded-lg overflow-hidden border border-gray-200">
                        <img
                          src={url}
                          alt={`截图 ${index + 1}`}
                          className="w-full h-full object-cover"
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveScreenshot(index)}
                        className="absolute -top-2 -right-2 p-1 bg-red-500 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity shadow-md hover:bg-red-600"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                      <div className="mt-1 flex items-center text-xs text-gray-500">
                        <Image className="h-3 w-3 mr-1" />
                        <span className="truncate">{screenshots[index]?.name}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              
              {screenshots.length > 0 && (
                <p className="text-sm text-gray-500">
                  已选择 {screenshots.length} 个文件
                </p>
              )}
            </div>
          )}

          </fieldset>
          {!vulnerability && !createdId && hasPermission('vuln:read') && <section className="rounded border border-gray-200 p-4 space-y-2"><h3 className="font-medium">重复候选检查</h3><p className="text-xs text-gray-500">相似候选仅供参考，不阻止创建。勾选后先创建漏洞，再单独人工确认关联。</p>{candidateLoading && <p role="status" className="text-sm text-gray-500">正在检查相似漏洞…</p>}{candidateError && <p className="text-sm text-amber-700">{candidateError}</p>}<ul className="space-y-2">{candidates.map(candidate => <li key={candidate.id} className="rounded border p-2 text-sm"><label className="flex gap-2 items-start">{hasPermission('vuln:update') && <input type="checkbox" checked={selectedCandidate === candidate.id} onChange={event => setSelectedCandidate(event.target.checked ? candidate.id : undefined)} />}<span><span className="font-medium">#{candidate.id} {candidate.title}</span><span className="block text-xs text-gray-500">评分 {candidate.score} · {candidate.reasons.join('、')}</span></span></label><Link to={vulnerabilityDetailURL(candidate.id)} target="_blank" rel="noreferrer" className="text-blue-600 text-xs">查看候选详情</Link></li>)}</ul>{!candidateLoading && !candidateError && !candidates.length && <p className="text-sm text-gray-500">选择资产并填写标题或漏洞编号后检查候选，暂无匹配也可继续创建。</p>}</section>}
          {!createdId && <div className="flex justify-end space-x-3 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={loading}
            >
              取消
            </Button>
            <Button
              type="submit"
              loading={loading}
            >
              {vulnerability ? '更新' : '创建'}
            </Button>
          </div>}
        </form>
      </DialogContent>
    </Dialog>
  );
}
