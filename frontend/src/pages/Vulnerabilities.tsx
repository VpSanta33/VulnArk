import { useLatestRequest, useSearchKeyword } from '../hooks/useListSearch';
import { getErrorMessage } from '../lib/utils';
import { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Plus, Search, Edit, Trash2, AlertTriangle, User, Shield, Eye } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/Table';
import { Pagination } from '../components/ui/Pagination';
import { vulnerabilitiesService } from '../services/vulnerabilities';
import { Vulnerability, PaginatedResponse, VulnerabilitySearchParams } from '../types/api';
const VulnForm = lazy(() => import('../components/forms/VulnForm').then(m => ({ default: m.VulnForm })));
const VulnerabilityDetail = lazy(() => import('../components/VulnerabilityDetail').then(m => ({ default: m.VulnerabilityDetail })));

export function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState<PaginatedResponse<Vulnerability> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [showVulnForm, setShowVulnForm] = useState(false);
  const { hasPermission } = useAuth();
  const [urlParams, setURLParams] = useSearchParams();
  const rawDetail = Number(urlParams.get('detail'));
  const detailId = Number.isSafeInteger(rawDetail) && rawDetail > 0 ? rawDetail : null;
  const setDetailId = (id: number | null) => {
    const next = new URLSearchParams(urlParams);
    if (id) next.set('detail', String(id));
    else { next.delete('detail'); next.delete('section'); }
    setURLParams(next);
  };
  const [editingVuln, setEditingVuln] = useState<Vulnerability | null>(null);
  
  // Search and filter states
  const [searchParams, setSearchParams] = useState<VulnerabilitySearchParams>({
    page: 1,
    page_size: 10,
    keyword: '',
    severity_level: undefined,
    status: '',
    asset_id: undefined,
    assignee_id: undefined,
  });

  const severityLevels = vulnerabilitiesService.getSeverityLevels();

  const [keyword, handleSearch] = useSearchKeyword(setSearchParams);
  const { begin, cancel } = useLatestRequest();

  const fetchVulnerabilities = useCallback(async () => {
    const request = begin();
    try {
      setLoading(true);
      setError('');
      const vulnData = await vulnerabilitiesService.getVulnerabilities(searchParams, request.signal);
      if (request.isCurrent()) setVulnerabilities(vulnData);
    } catch (err: unknown) {
      if (request.isCurrent()) setError(getErrorMessage(err, '获取漏洞列表失败'));
    } finally {
      if (request.isCurrent()) setLoading(false);
    }
  }, [searchParams, begin]);

  useEffect(() => {
    void fetchVulnerabilities();
    return cancel;
  }, [fetchVulnerabilities, cancel]);

  const handleFilterChange = <K extends keyof VulnerabilitySearchParams>(key: K, value: VulnerabilitySearchParams[K]) => {
    setSearchParams((prev: VulnerabilitySearchParams) => ({ ...prev, [key]: value, page: 1 }));
  };

  const handlePageChange = (page: number) => {
    setSearchParams((prev: VulnerabilitySearchParams) => ({ ...prev, page }));
  };

  const handleCreateVuln = () => {
    setEditingVuln(null);
    setShowVulnForm(true);
  };

  const handleEditVuln = (vuln: Vulnerability) => {
    setEditingVuln(vuln);
    setShowVulnForm(true);
  };

  const handleCloseVulnForm = () => {
    setShowVulnForm(false);
    setEditingVuln(null);
  };

  const handleVulnFormSuccess = () => {
    fetchVulnerabilities(); // Refresh the list
  };

  const handleDeleteVulnerability = async (id: number) => {
    if (!confirm('确定要删除这个漏洞吗？')) return;
    
    try {
      await vulnerabilitiesService.deleteVulnerability(id);
      fetchVulnerabilities();
    } catch (err: unknown) {
      alert(getErrorMessage(err, '删除漏洞失败'));
    }
  };

  const getSeverityBadge = (level: number) => {
    const severity = severityLevels.find(s => s.value === level);
    let variant: 'destructive' | 'warning' | 'secondary' | 'default';
    
    switch (level) {
      case 1:
        variant = 'destructive';
        break;
      case 2:
        variant = 'warning';
        break;
      case 3:
        variant = 'secondary';
        break;
      default:
        variant = 'default';
    }
    
    return (
      <Badge variant={variant}>
        <AlertTriangle className="h-3 w-3 mr-1" />
        {severity?.label || '未知'}
      </Badge>
    );
  };

  const getCvssScoreBadge = (score?: number) => {
    if (score == null) return null;
    
    const color = vulnerabilitiesService.getCvssScoreColor(score);
    let variant: 'destructive' | 'warning' | 'secondary' | 'success' = 'secondary';
    
    switch (color) {
      case 'red':
        variant = 'destructive';
        break;
      case 'orange':
        variant = 'warning';
        break;
      case 'yellow':
        variant = 'secondary';
        break;
      case 'green':
        variant = 'success';
        break;
    }
    
    return (
      <Badge variant={variant}>
        CVSS: {score.toFixed(1)}
      </Badge>
    );
  };

  if (loading && !vulnerabilities) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">漏洞管理</h1>
        </div>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">漏洞管理</h1>
          <p className="mt-2 text-sm text-gray-600">管理系统安全漏洞和修复进度</p>
        </div>
        {hasPermission('vuln:create') && <Button onClick={handleCreateVuln}>
          <Plus className="h-4 w-4 mr-2" />
          新增漏洞
        </Button>}
      </div>

      {/* Search and Filters */}
      <Card>
        <CardHeader>
          <CardTitle>搜索和筛选</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                搜索漏洞
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="漏洞标题、CVE编号"
                  value={keyword}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                严重程度
              </label>
              <Select
                placeholder="选择严重程度"
                value={searchParams.severity_level !== undefined ? searchParams.severity_level : ''}
                onChange={(e) => handleFilterChange('severity_level', e.target.value !== '' ? Number(e.target.value) : undefined)}
                options={[
                  { value: '', label: '全部级别' },
                  ...severityLevels.map(level => ({ value: level.value, label: level.label }))
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                状态
              </label>
              <Select
                placeholder="选择状态"
                value={searchParams.status || ''}
                onChange={(e) => handleFilterChange('status', e.target.value)}
                options={[
                  { value: '', label: '全部状态' },
                  { value: 'new', label: '新建' },
                  { value: 'processing', label: '处理中' },
                  { value: 'fixed', label: '已修复' },
                  { value: 'verified', label: '已验证' },
                  { value: 'closed', label: '已关闭' },
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">SLA 期限</label>
              <Select value={searchParams.sla_status || ''} onChange={event => handleFilterChange('sla_status', event.target.value as VulnerabilitySearchParams['sla_status'])} options={[{ value: '', label: '全部期限' }, { value: 'overdue', label: '已逾期' }, { value: 'paused', label: '已暂停' }, { value: 'within', label: '期限内' }]} />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                负责人
              </label>
              <Select
                placeholder="选择负责人"
                value={searchParams.assignee_id || ''}
                onChange={(e) => handleFilterChange('assignee_id', e.target.value ? Number(e.target.value) : undefined)}
                options={[
                  { value: '', label: '全部负责人' },
                  // TODO: Load from users API
                ]}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6 text-center text-red-600">
              <p>{error}</p>
              <Button variant="outline" onClick={fetchVulnerabilities} className="mt-2">
                重试
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>漏洞信息</TableHead>
                    <TableHead>严重程度</TableHead>
                    <TableHead>影响资产</TableHead>
                    <TableHead>负责人</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>SLA 期限</TableHead>
                    <TableHead>创建时间</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vulnerabilities?.data?.length ? (
                    vulnerabilities.data.map((vuln) => (
                    <TableRow key={vuln.id}>
                      <TableCell>
                        <div>
                          <button type="button" className="font-medium text-left text-blue-600 hover:underline" onClick={() => setDetailId(vuln.id)}>{vuln.title}</button>
                          <div className="text-sm text-gray-500 line-clamp-2">
                            {vuln.description}
                          </div>
                          <div className="flex items-center space-x-2 mt-1">
                            {vuln.cve_id && (
                              <Badge variant="outline" className="text-xs">
                                {vuln.cve_id}
                              </Badge>
                            )}
                            {vuln.cnvd_id && (
                              <Badge variant="outline" className="text-xs">
                                {vuln.cnvd_id}
                              </Badge>
                            )}
                            {getCvssScoreBadge(vuln.cvss_score)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        {getSeverityBadge(vuln.severity_level)}
                      </TableCell>
                      <TableCell>
                        {vuln.asset ? (
                          <div>
                            <div className="font-medium">{vuln.asset.name}</div>
                            <div className="text-sm text-gray-500">{vuln.asset.type}</div>
                          </div>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                      <TableCell>
                        {vuln.assignee ? (
                          <div className="flex items-center">
                            <User className="h-4 w-4 mr-1 text-gray-400" />
                            <span className="text-sm">{vuln.assignee.real_name}</span>
                          </div>
                        ) : (
                          <span className="text-gray-500">未分配</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {vuln.status || '待处理'}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="text-xs space-y-1 min-w-40">
                          <p className={vuln.response_overdue ? 'text-red-600' : 'text-gray-600'}>响应：{vuln.response_due_at ? new Date(vuln.response_due_at).toLocaleString('zh-CN') : '—'}</p>
                          <p className={vuln.fix_overdue ? 'text-red-600' : 'text-gray-600'}>修复：{vuln.fix_due_at ? new Date(vuln.fix_due_at).toLocaleString('zh-CN') : '—'}</p>
                          {vuln.pause_started_at ? <Badge variant="warning">已暂停</Badge> : (vuln.response_overdue || vuln.fix_overdue) && <Badge variant="destructive">已逾期</Badge>}
                        </div>
                      </TableCell>
                      <TableCell>
                        {vuln.created_at 
                          ? new Date(vuln.created_at).toLocaleString('zh-CN')
                          : '-'
                        }
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <Button variant="ghost" size="sm" aria-label="查看漏洞详情" onClick={() => setDetailId(vuln.id)}><Eye className="h-4 w-4" /></Button>
                          {hasPermission('vuln:update') && <Button variant="ghost" size="sm" aria-label="编辑漏洞" onClick={() => handleEditVuln(vuln)}><Edit className="h-4 w-4" /></Button>}
                          {hasPermission('vuln:delete') && <Button variant="ghost" size="sm" aria-label="删除漏洞" onClick={() => handleDeleteVulnerability(vuln.id)}><Trash2 className="h-4 w-4" /></Button>}
                        </div>
                      </TableCell>
                    </TableRow>
                    ))
                  ) : (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-8">
                        <div className="text-gray-500">
                          <Shield className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                          <p className="text-lg font-medium">暂无漏洞数据</p>
                          <p className="text-sm">系统中还没有发现任何漏洞</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>

              {vulnerabilities && vulnerabilities.total > 0 && (
                <div className="p-4 border-t">
                  <Pagination
                    currentPage={vulnerabilities.page}
                    totalPages={vulnerabilities.total_pages}
                    onPageChange={handlePageChange}
                    totalItems={vulnerabilities.total}
                    itemsPerPage={vulnerabilities.page_size}
                  />
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Suspense fallback={<p role="status" className="text-sm text-gray-500">正在加载漏洞窗口…</p>}>
        {detailId !== null && <VulnerabilityDetail key={detailId} id={detailId} section={urlParams.get('section') || undefined} onSectionChange={section => { const next = new URLSearchParams(urlParams); next.set('section', section); setURLParams(next, { replace: true }); }} onChanged={fetchVulnerabilities} onClose={() => setDetailId(null)} />}
        {showVulnForm && <VulnForm isOpen onClose={handleCloseVulnForm} onSuccess={handleVulnFormSuccess} vulnerability={editingVuln} />}
      </Suspense>
    </div>
  );
}
