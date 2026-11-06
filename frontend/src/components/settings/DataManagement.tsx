import { getErrorMessage } from '../../lib/utils';
import { useState } from 'react';
import { 
  Database, 
  Download, 
  Upload, 
  HardDrive, 
  RefreshCw, 

  FileText,
  Archive,
  AlertTriangle,
  CheckCircle,
  X,

  BarChart3
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Progress } from '../ui/Progress';
import { Badge } from '../ui/Badge';
import { settingsService } from '../../services/settings';

export function DataManagement() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [exportProgress, setExportProgress] = useState(0);
  const [importProgress, setImportProgress] = useState(0);

  // Mock data statistics
  const dataStats = {
    totalAssets: 1247,
    totalVulnerabilities: 856,
    totalReports: 234,
    totalUsers: 45,
    databaseSize: '2.3 GB',
    lastBackup: '2024-01-20 02:00:00',
    cacheSize: '156 MB',
  };

  const handleExportData = async (type: string) => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');
      setExportProgress(0);

      // Simulate export progress
      const interval = setInterval(() => {
        setExportProgress(prev => {
          if (prev >= 90) {
            clearInterval(interval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      // 实际导出API调用
      const exportType = type === 'assets' ? 'profile' :
                        type === 'vulnerabilities' ? 'settings' :
                        type === 'reports' ? 'settings' : 'all';

      const blob = await settingsService.exportData(exportType as 'profile' | 'settings' | 'all');

      // 完成进度
      setExportProgress(100);
      clearInterval(interval);

      // 下载文件
      const filename = `vulnark_${type}_export_${new Date().toISOString().split('T')[0]}.json`;
      settingsService.downloadFile(blob, filename);

      setSuccess(`${type}数据导出完成！`);
    } catch (err: unknown) {
      setError(getErrorMessage(err, '导出失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  const handleImportData = async (file: File) => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');
      setImportProgress(0);

      // Simulate import progress
      const interval = setInterval(() => {
        setImportProgress(prev => {
          if (prev >= 90) {
            clearInterval(interval);
            return 90;
          }
          return prev + 8;
        });
      }, 300);

      // 实际导入API调用
      await settingsService.importData(file, 'settings');

      // 完成进度
      setImportProgress(100);
      clearInterval(interval);

      setSuccess('数据导入完成！');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '导入失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  const handleClearCache = async () => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      await settingsService.clearCache();

      setSuccess('缓存清理完成！');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '清理失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  const handleDatabaseOptimization = async () => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      await settingsService.optimizeDatabase();

      setSuccess('数据库优化完成！');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '优化失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Status Messages */}
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md flex items-center gap-2">
          <X className="h-4 w-4" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 border border-green-200 text-green-600 px-4 py-3 rounded-md flex items-center gap-2">
          <CheckCircle className="h-4 w-4" />
          {success}
        </div>
      )}

      {/* Data Statistics */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-blue-500" />
            数据统计
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{dataStats.totalAssets}</div>
              <div className="text-sm text-blue-800">资产数量</div>
            </div>
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">{dataStats.totalVulnerabilities}</div>
              <div className="text-sm text-red-800">漏洞数量</div>
            </div>
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{dataStats.totalReports}</div>
              <div className="text-sm text-green-800">报告数量</div>
            </div>
            <div className="text-center p-4 bg-purple-50 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">{dataStats.totalUsers}</div>
              <div className="text-sm text-purple-800">用户数量</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Export */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5 text-green-500" />
            数据导出
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {exportProgress > 0 && exportProgress < 100 && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>导出进度</span>
                <span>{exportProgress}%</span>
              </div>
              <Progress value={exportProgress} variant="success" />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Button
              onClick={() => handleExportData('assets')}
              disabled={loading}
              variant="outline"
              className="justify-start gap-2 h-auto p-4"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <HardDrive className="h-5 w-5 text-blue-600" />
                </div>
                <div className="text-left">
                  <div className="font-medium">导出资产数据</div>
                  <div className="text-sm text-gray-500">包含所有资产信息</div>
                </div>
              </div>
            </Button>

            <Button
              onClick={() => handleExportData('vulnerabilities')}
              disabled={loading}
              variant="outline"
              className="justify-start gap-2 h-auto p-4"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-100 rounded-lg">
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                </div>
                <div className="text-left">
                  <div className="font-medium">导出漏洞数据</div>
                  <div className="text-sm text-gray-500">包含所有漏洞记录</div>
                </div>
              </div>
            </Button>

            <Button
              onClick={() => handleExportData('reports')}
              disabled={loading}
              variant="outline"
              className="justify-start gap-2 h-auto p-4"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-100 rounded-lg">
                  <FileText className="h-5 w-5 text-green-600" />
                </div>
                <div className="text-left">
                  <div className="font-medium">导出报告数据</div>
                  <div className="text-sm text-gray-500">包含所有安全报告</div>
                </div>
              </div>
            </Button>

            <Button
              onClick={() => handleExportData('all')}
              disabled={loading}
              variant="outline"
              className="justify-start gap-2 h-auto p-4"
            >
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 rounded-lg">
                  <Archive className="h-5 w-5 text-purple-600" />
                </div>
                <div className="text-left">
                  <div className="font-medium">导出全部数据</div>
                  <div className="text-sm text-gray-500">完整数据备份</div>
                </div>
              </div>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Data Import */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5 text-orange-500" />
            数据导入
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {importProgress > 0 && importProgress < 100 && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>导入进度</span>
                <span>{importProgress}%</span>
              </div>
              <Progress value={importProgress} variant="warning" />
            </div>
          )}

          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
            <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">上传数据文件</h3>
            <p className="text-sm text-gray-600 mb-4">
              支持 JSON、CSV、Excel 格式的数据文件
            </p>
            <input
              type="file"
              accept=".json,.csv,.xlsx,.xls"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleImportData(file);
              }}
              className="hidden"
              id="import-file"
              disabled={loading}
            />
            <label
              htmlFor="import-file"
              className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 cursor-pointer"
            >
              选择文件
            </label>
          </div>

          <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
              <div className="text-sm text-yellow-800">
                <p className="font-medium mb-1">导入注意事项：</p>
                <ul className="list-disc list-inside space-y-1">
                  <li>导入前请备份现有数据</li>
                  <li>确保文件格式正确</li>
                  <li>大文件导入可能需要较长时间</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* System Maintenance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-purple-500" />
            系统维护
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 border border-gray-200 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-medium text-gray-900">数据库大小</h4>
                <Badge variant="outline">{dataStats.databaseSize}</Badge>
              </div>
              <p className="text-sm text-gray-600 mb-3">
                最后备份: {dataStats.lastBackup}
              </p>
              <Button
                onClick={handleDatabaseOptimization}
                disabled={loading}
                size="sm"
                className="w-full gap-2"
              >
                <Database className="h-4 w-4" />
                优化数据库
              </Button>
            </div>

            <div className="p-4 border border-gray-200 rounded-lg">
              <div className="flex items-center justify-between mb-3">
                <h4 className="font-medium text-gray-900">缓存大小</h4>
                <Badge variant="outline">{dataStats.cacheSize}</Badge>
              </div>
              <p className="text-sm text-gray-600 mb-3">
                清理缓存可以释放存储空间
              </p>
              <Button
                onClick={handleClearCache}
                disabled={loading}
                size="sm"
                variant="outline"
                className="w-full gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                清理缓存
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
