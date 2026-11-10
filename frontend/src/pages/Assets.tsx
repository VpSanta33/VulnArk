import { networkZoneLabel } from '../lib/risk';
import { useLatestRequest, useSearchKeyword } from '../hooks/useListSearch';
import { getErrorMessage } from '../lib/utils';
import { useState, useEffect, useCallback } from 'react';
import { Plus, Search, Edit, Trash2, Upload, Download } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/Table';
import { Pagination } from '../components/ui/Pagination';
import { assetsService, AssetSearchParams } from '../services/assets';
import { Asset, PaginatedResponse } from '../types/api';
import { AssetForm } from '../components/forms/AssetForm';

export function Assets() {
  const [assets, setAssets] = useState<PaginatedResponse<Asset> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [showAssetForm, setShowAssetForm] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  
  // Search and filter states
  const [searchParams, setSearchParams] = useState<AssetSearchParams>({
    page: 1,
    page_size: 10,
    keyword: '',
    type: '',
    importance_level: undefined,
    owner_id: undefined,
  });


  const importanceLevels = assetsService.getImportanceLevels();

  const [keyword, handleSearch] = useSearchKeyword(setSearchParams);
  const { begin, cancel } = useLatestRequest();

  const fetchAssets = useCallback(async () => {
    const request = begin();
    try {
      setLoading(true);
      setError('');
      const assetsData = await assetsService.getAssets(searchParams, request.signal);
      if (request.isCurrent()) setAssets(assetsData);
    } catch (err: unknown) {
      if (request.isCurrent()) setError(getErrorMessage(err, '获取资产列表失败'));
    } finally {
      if (request.isCurrent()) setLoading(false);
    }
  }, [searchParams, begin]);

  useEffect(() => {
    void fetchAssets();
    return cancel;
  }, [fetchAssets, cancel]);

  const handleFilterChange = <K extends keyof AssetSearchParams>(key: K, value: AssetSearchParams[K]) => {
    setSearchParams((prev: AssetSearchParams) => ({ ...prev, [key]: value, page: 1 }));
  };

  const handlePageChange = (page: number) => {
    setSearchParams((prev: AssetSearchParams) => ({ ...prev, page }));
  };

  const handleCreateAsset = () => {
    setEditingAsset(null);
    setShowAssetForm(true);
  };

  const handleEditAsset = (asset: Asset) => {
    setEditingAsset(asset);
    setShowAssetForm(true);
  };

  const handleCloseAssetForm = () => {
    setShowAssetForm(false);
    setEditingAsset(null);
  };

  const handleAssetFormSuccess = () => {
    fetchAssets(); // Refresh the list
  };

  const handleDeleteAsset = async (id: number) => {
    if (!confirm('确定要删除这个资产吗？')) return;
    
    try {
      await assetsService.deleteAsset(id);
      fetchAssets();
    } catch (err: unknown) {
      alert(getErrorMessage(err, '删除资产失败'));
    }
  };

  const getAssetTypeBadge = (type: string) => {
    const typeLabels: Record<string, string> = {
      server: '服务器',
      database: '数据库',
      application: '应用',
      network: '网络设备',
    };

    return (
      <Badge variant="secondary">
        {typeLabels[type] || type}
      </Badge>
    );
  };

  const getImportanceBadge = (level: number) => {
    const importance = importanceLevels.find(i => i.value === level);
    const variant = level === 1 ? 'destructive' : level === 2 ? 'warning' : 'secondary';
    
    return (
      <Badge variant={variant}>
        {importance?.label || '未知'}
      </Badge>
    );
  };

  if (loading && !assets) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">资产管理</h1>
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
          <h1 className="text-3xl font-bold text-gray-900">资产管理</h1>
          <p className="mt-2 text-sm text-gray-600">管理系统资产信息和配置</p>
        </div>
        <div className="flex space-x-2">
          <Button variant="outline">
            <Upload className="h-4 w-4 mr-2" />
            导入资产
          </Button>
          <Button onClick={handleCreateAsset}>
            <Plus className="h-4 w-4 mr-2" />
            新增资产
          </Button>
        </div>
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
                搜索资产
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="资产名称、IP地址或域名"
                  value={keyword}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                资产类型
              </label>
              <Select
                placeholder="选择类型"
                value={searchParams.type || ''}
                onChange={(e) => handleFilterChange('type', e.target.value)}
                options={[
                  { value: '', label: '全部类型' },
                  { value: 'server', label: '服务器' },
                  { value: 'database', label: '数据库' },
                  { value: 'application', label: '应用' },
                  { value: 'network', label: '网络设备' },
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                重要程度
              </label>
              <Select
                placeholder="选择重要程度"
                value={searchParams.importance_level !== undefined ? searchParams.importance_level : ''}
                onChange={(e) => handleFilterChange('importance_level', e.target.value !== '' ? Number(e.target.value) : undefined)}
                options={[
                  { value: '', label: '全部级别' },
                  ...importanceLevels.map(level => ({ value: level.value, label: level.label }))
                ]}
              />
            </div>

            <div className="flex items-end">
              <Button variant="outline" className="w-full">
                <Download className="h-4 w-4 mr-2" />
                导出数据
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Assets Table */}
      <Card>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6 text-center text-red-600">
              <p>{error}</p>
              <Button variant="outline" onClick={fetchAssets} className="mt-2">
                重试
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>资产信息</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>网络信息</TableHead>
                    <TableHead>重要程度</TableHead>
                    <TableHead>负责人</TableHead>
                    <TableHead>更新时间</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets?.data?.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell>
                        <div>
                          <div className="font-medium">{asset.name}</div>
                          {asset.description && (
                            <div className="text-sm text-gray-500">{asset.description}</div>
                          )}
                          {asset.business_line && (
                            <div className="text-sm text-gray-500">业务线: {asset.business_line}</div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {getAssetTypeBadge(asset.type)}
                        {asset.category && (
                          <div className="text-sm text-gray-500 mt-1">{asset.category}</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          {asset.ip_address && (
                            <div className="text-sm">IP: {asset.ip_address}</div>
                          )}
                          {asset.domain && (
                            <div className="text-sm">域名: {asset.domain}</div>
                          )}
                          {asset.port && (
                            <div className="text-sm">端口: {asset.port}</div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {getImportanceBadge(asset.importance_level)}
                        <div className="text-xs text-gray-500 mt-1">{asset.internet_facing ? '对外暴露' : '不对外'} · {networkZoneLabel(asset.network_zone)}</div>
                      </TableCell>
                      <TableCell>
                        {asset.department || '-'}
                      </TableCell>
                      <TableCell>
                        {asset.updated_at 
                          ? new Date(asset.updated_at).toLocaleString('zh-CN')
                          : '-'
                        }
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEditAsset(asset)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="sm"
                            onClick={() => handleDeleteAsset(asset.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {assets && assets.total > 0 && (
                <div className="p-4 border-t">
                  <Pagination
                    currentPage={assets.page}
                    totalPages={assets.total_pages}
                    onPageChange={handlePageChange}
                    totalItems={assets.total}
                    itemsPerPage={assets.page_size}
                  />
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <AssetForm
        isOpen={showAssetForm}
        onClose={handleCloseAssetForm}
        onSuccess={handleAssetFormSuccess}
        asset={editingAsset}
      />
    </div>
  );
}
