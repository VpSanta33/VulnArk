import { useLatestRequest, useSearchKeyword } from '../hooks/useListSearch';
import { getErrorMessage } from '../lib/utils';
import { useState, useEffect, useCallback } from 'react';
import { Search, Download, Upload, FileText, Trash2, Eye } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/Table';
import { Pagination } from '../components/ui/Pagination';
import { reportsService, ReportSearchParams } from '../services/reports';
import { Report, PaginatedResponse } from '../types/api';
import { ReportForm } from '../components/forms/ReportForm';
import { ReportViewer } from '../components/viewer/ReportViewer';

export function Reports() {
  const [reports, setReports] = useState<PaginatedResponse<Report> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [showReportForm, setShowReportForm] = useState(false);
  const [editingReport, setEditingReport] = useState<Report | null>(null);
  const [viewingReport, setViewingReport] = useState<Report | null>(null);
  
  // Search and filter states
  const [searchParams, setSearchParams] = useState<ReportSearchParams>({
    page: 1,
    page_size: 10,
    keyword: '',
    type: '',
    severity: '',
  });

  const reportTypes = reportsService.getReportTypes();
  const severityLevels = reportsService.getSeverityLevels();

  const [keyword, handleSearch] = useSearchKeyword(setSearchParams);
  const { begin, cancel } = useLatestRequest();

  const fetchReports = useCallback(async () => {
    const request = begin();
    try {
      setLoading(true);
      setError('');
      const reportsData = await reportsService.getReports(searchParams, request.signal);
      if (request.isCurrent()) setReports(reportsData);
    } catch (err: unknown) {
      if (request.isCurrent()) setError(getErrorMessage(err, '获取报告列表失败'));
    } finally {
      if (request.isCurrent()) setLoading(false);
    }
  }, [searchParams, begin]);

  useEffect(() => {
    void fetchReports();
    return cancel;
  }, [fetchReports, cancel]);

  const handleFilterChange = <K extends keyof ReportSearchParams>(key: K, value: ReportSearchParams[K]) => {
    setSearchParams((prev: ReportSearchParams) => ({ ...prev, [key]: value, page: 1 }));
  };

  const handlePageChange = (page: number) => {
    setSearchParams((prev: ReportSearchParams) => ({ ...prev, page }));
  };

  const handleCreateReport = () => {
    setEditingReport(null);
    setShowReportForm(true);
  };

  // const handleEditReport = (report: Report) => {
  //   setEditingReport(report);
  //   setShowReportForm(true);


  const handleCloseReportForm = () => {
    setShowReportForm(false);
    setEditingReport(null);
  };

  const handleReportFormSuccess = () => {
    fetchReports(); // Refresh the list
  };

  const handleDeleteReport = async (id: number) => {
    if (!confirm('确定要删除这个报告吗？')) return;
    
    try {
      await reportsService.deleteReport(id);
      fetchReports();
    } catch (err: unknown) {
      alert(getErrorMessage(err, '删除报告失败'));
    }
  };

  const handleDownloadReport = async (id: number, filename?: string) => {
    try {
      await reportsService.downloadReport(id, filename);
    } catch (err: unknown) {
      alert(getErrorMessage(err, '下载报告失败'));
    }
  };

  const handleViewReport = (report: Report) => {
    setViewingReport(report);
  };

  const getReportTypeBadge = (type: string) => {
    const reportType = reportTypes.find(t => t.value === type);
    return (
      <Badge variant="secondary">
        {reportType?.label || type}
      </Badge>
    );
  };

  const getSeverityBadge = (severity: string) => {
    const severityInfo = severityLevels.find(s => s.value === severity);
    let variant: 'destructive' | 'warning' | 'secondary' | 'default';
    
    switch (severity) {
      case 'critical':
        variant = 'destructive';
        break;
      case 'high':
        variant = 'warning';
        break;
      case 'medium':
        variant = 'secondary';
        break;
      default:
        variant = 'default';
    }
    
    return (
      <Badge variant={variant}>
        {severityInfo?.label || severity}
      </Badge>
    );
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return '-';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  if (loading && !reports) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">报告管理</h1>
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
          <h1 className="text-3xl font-bold text-gray-900">报告管理</h1>
          <p className="mt-2 text-sm text-gray-600">管理安全测试报告和文档</p>
        </div>
        <Button onClick={handleCreateReport}>
          <Upload className="h-4 w-4 mr-2" />
          上传报告
        </Button>
      </div>

      {/* Search and Filters */}
      <Card>
        <CardHeader>
          <CardTitle>搜索和筛选</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                搜索报告
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="报告标题或描述"
                  value={keyword}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                报告类型
              </label>
              <Select
                placeholder="选择类型"
                value={searchParams.type || ''}
                onChange={(e) => handleFilterChange('type', e.target.value)}
                options={[
                  { value: '', label: '全部类型' },
                  ...reportTypes.map(type => ({ value: type.value, label: type.label }))
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                严重程度
              </label>
              <Select
                placeholder="选择严重程度"
                value={searchParams.severity || ''}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                options={[
                  { value: '', label: '全部级别' },
                  ...severityLevels.map(level => ({ value: level.value, label: level.label }))
                ]}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reports Table */}
      <Card>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6 text-center text-red-600">
              <p>{error}</p>
              <Button variant="outline" onClick={fetchReports} className="mt-2">
                重试
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>报告信息</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>严重程度</TableHead>
                    <TableHead>文件信息</TableHead>
                    <TableHead>测试日期</TableHead>
                    <TableHead>创建时间</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reports?.data.map((report) => (
                    <TableRow key={report.id}>
                      <TableCell>
                        <div>
                          <div className="font-medium flex items-center">
                            <FileText className="h-4 w-4 mr-2 text-gray-400" />
                            {report.title}
                          </div>
                          {report.description && (
                            <div className="text-sm text-gray-500 mt-1 line-clamp-2">
                              {report.description}
                            </div>
                          )}
                          {report.tags && report.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {report.tags.map((tag, index) => (
                                <Badge key={index} variant="outline" className="text-xs">
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {getReportTypeBadge(report.type)}
                      </TableCell>
                      <TableCell>
                        {getSeverityBadge(report.severity)}
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          {report.file_name && (
                            <div className="text-sm font-medium">{report.file_name}</div>
                          )}
                          <div className="text-sm text-gray-500">
                            {formatFileSize(report.file_size)}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        {report.test_date 
                          ? new Date(report.test_date).toLocaleDateString('zh-CN')
                          : '-'
                        }
                      </TableCell>
                      <TableCell>
                        {report.created_at 
                          ? new Date(report.created_at).toLocaleString('zh-CN')
                          : '-'
                        }
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleViewReport(report)}
                            title="查看报告"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDownloadReport(report.id, report.file_name)}
                            title="下载报告"
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteReport(report.id)}
                            title="删除报告"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {reports && reports.total > 0 && (
                <div className="p-4 border-t">
                  <Pagination
                    currentPage={reports.page}
                    totalPages={reports.total_pages}
                    onPageChange={handlePageChange}
                    totalItems={reports.total}
                    itemsPerPage={reports.page_size}
                  />
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <ReportForm
        isOpen={showReportForm}
        onClose={handleCloseReportForm}
        onSuccess={handleReportFormSuccess}
        report={editingReport}
      />

      {/* Report Viewer Modal */}
      {viewingReport && (
        <ReportViewer
          isOpen={!!viewingReport}
          onClose={() => setViewingReport(null)}
          report={{
            id: viewingReport.id,
            title: viewingReport.title,
            type: viewingReport.type,
            format: viewingReport.file_name?.split('.').pop()?.toLowerCase() || viewingReport.file_type || 'pdf',
            file_size: viewingReport.file_size || 0,
            generated_at: viewingReport.created_at || new Date().toISOString(),
            generated_by: 'System', // Default value since creator info is not available
            description: viewingReport.description,
            metadata: {}, // Default empty metadata
          }}
        />
      )}
    </div>
  );
}
