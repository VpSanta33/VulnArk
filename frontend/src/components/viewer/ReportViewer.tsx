import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import {
  X,
  Download,
  Share2,
  Printer,
  FileText,
  BarChart3,
  Calendar,
  User,
  AlertCircle,
  Loader2
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Badge } from '../ui/Badge';
import { reportsService } from '../../services/reports';
import { sanitizeHTML } from '../../lib/sanitizeHTML';

export interface ReportData {
  id: number;
  title: string;
  type: string;
  format: string;
  file_size: number;
  generated_at: string;
  generated_by: string;
  description?: string;
  metadata?: Record<string, unknown>;
}

export interface ReportViewerProps {
  isOpen: boolean;
  onClose: () => void;
  report: ReportData;
}

export function ReportViewer({ isOpen, onClose, report }: ReportViewerProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reportContent, setReportContent] = useState<string>('');
  const [previewURL, setPreviewURL] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    const abort = new AbortController();
    let active = true;
    let objectURL: string | undefined;
    setLoading(true); setError(''); setPreviewURL(''); setReportContent('');
    const load = async () => {
      try {
        if (report.format.toLowerCase() === 'pdf') {
          const blob = await reportsService.getReportBlob(report.id, abort.signal);
          if (active) {
            objectURL = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
            setPreviewURL(objectURL);
          }
        } else if (report.format.toLowerCase() === 'html') {
          const content = await reportsService.getReportContent(report.id);
          if (active) setReportContent(content);
        }
      } catch (err: unknown) {
        if (active) setError(getErrorMessage(err, '报告加载失败'));
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; abort.abort(); if (objectURL) URL.revokeObjectURL(objectURL); };
  }, [isOpen, report.id, report.format]);

  const handleDownload = async () => {
    try { await reportsService.downloadReport(report.id, `${report.title}.${report.format.toLowerCase()}`); }
    catch (err: unknown) { setError(getErrorMessage(err, '下载报告失败')); }
  };

  const handlePrint = () => {
    if (report.format.toLowerCase() === 'html') {
      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.opener = null;
        printWindow.document.write(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https: http: data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">${sanitizeHTML(reportContent)}`);
        printWindow.document.close();
        printWindow.print();
      }
    } else {
      window.print();
    }
  };

  const handleShare = () => {
    if (navigator.share) {
      navigator.share({
        title: report.title,
        text: report.description || '查看报告',
        url: window.location.href,
      });
    } else {
      // Fallback: copy to clipboard
      navigator.clipboard.writeText(window.location.href);
      // You could show a toast notification here
    }
  };

  const getReportTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      vulnerability: 'bg-red-100 text-red-800',
      asset: 'bg-blue-100 text-blue-800',
      security: 'bg-green-100 text-green-800',
      compliance: 'bg-purple-100 text-purple-800',
      summary: 'bg-yellow-100 text-yellow-800',
    };
    return colors[type.toLowerCase()] || 'bg-gray-100 text-gray-800';
  };

  const renderReportContent = () => {
    const format = report.format.toLowerCase();

    if (format === 'html') {
      return (
        <div className="w-full h-full">
          <iframe
            srcDoc={sanitizeHTML(reportContent)}
            className="w-full h-full border-0 bg-white"
            title={report.title}
            sandbox=""
          />
        </div>
      );
    }

    if (format === 'pdf') {
      return (
        <div className="w-full h-full">
          <iframe
            src={`${previewURL}#toolbar=1&navpanes=1&scrollbar=1`}
            className="w-full h-full border-0"
            title={report.title}
          />
        </div>
      );
    }

    if (format === 'xlsx' || format === 'xls') {
      return (
        <div className="flex flex-col items-center justify-center h-full text-gray-500">
          <BarChart3 className="h-16 w-16 mb-4 text-green-600" />
          <p className="text-lg font-medium mb-2">Excel 报告</p>
          <p className="text-sm mb-4 text-center max-w-md">
            Excel 文件无法在浏览器中直接预览，请下载后使用 Excel 或兼容软件打开。
          </p>
          <div className="flex gap-2">
            <Button onClick={handleDownload} className="flex items-center gap-2">
              <Download className="h-4 w-4" />
              下载 Excel 文件
            </Button>
          </div>
        </div>
      );
    }

    // Default fallback
    return (
      <div className="flex flex-col items-center justify-center h-full text-gray-500">
        <FileText className="h-16 w-16 mb-4" />
        <p className="text-lg font-medium mb-2">无法预览此报告格式</p>
        <p className="text-sm mb-4">格式: {report.format.toUpperCase()}</p>
        <Button onClick={handleDownload} className="flex items-center gap-2">
          <Download className="h-4 w-4" />
          下载报告
        </Button>
      </div>
    );
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <Card className="w-full h-full max-w-7xl max-h-[95vh] flex flex-col bg-white">
        {/* Header */}
        <CardHeader className="border-b bg-gray-50 pb-4">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <FileText className="h-6 w-6 text-blue-600" />
                <CardTitle className="text-xl">{report.title}</CardTitle>
                <Badge className={getReportTypeColor(report.type)}>
                  {report.type}
                </Badge>
                <Badge variant="outline">
                  {report.format.toUpperCase()}
                </Badge>
              </div>
              
              {report.description && (
                <p className="text-gray-600 mb-3">{report.description}</p>
              )}
              
              <div className="flex items-center gap-6 text-sm text-gray-500">
                <div className="flex items-center gap-1">
                  <User className="h-4 w-4" />
                  {report.generated_by}
                </div>
                <div className="flex items-center gap-1">
                  <Calendar className="h-4 w-4" />
                  {new Date(report.generated_at).toLocaleString('zh-CN')}
                </div>
                <div className="flex items-center gap-1">
                  <FileText className="h-4 w-4" />
                  {(report.file_size / 1024 / 1024).toFixed(2)} MB
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 ml-4">
              <Button
                variant="outline"
                size="sm"
                onClick={handleShare}
                className="flex items-center gap-2"
              >
                <Share2 className="h-4 w-4" />
                分享
              </Button>
              
              <Button
                variant="outline"
                size="sm"
                onClick={handlePrint}
                className="flex items-center gap-2"
              >
                <Printer className="h-4 w-4" />
                打印
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={handleDownload}
                className="flex items-center gap-2"
              >
                <Download className="h-4 w-4" />
                下载
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={onClose}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        {/* Content */}
        <CardContent className="flex-1 p-0 relative overflow-hidden">
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-gray-50">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
                <p className="text-gray-600">加载报告中...</p>
              </div>
            </div>
          )}

          {error && (
            <div className="absolute inset-0 flex items-center justify-center bg-gray-50">
              <div className="flex flex-col items-center gap-3 text-red-600">
                <AlertCircle className="h-8 w-8" />
                <p className="text-lg font-medium">报告加载失败</p>
                <p className="text-sm">{error}</p>
                <Button onClick={handleDownload} variant="outline">
                  <Download className="h-4 w-4 mr-2" />
                  下载报告
                </Button>
              </div>
            </div>
          )}

          {!loading && !error && renderReportContent()}
        </CardContent>
      </Card>
    </div>
  );
}
