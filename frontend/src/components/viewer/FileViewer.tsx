import { useState, useEffect } from 'react';
import { 
  X, 
  Download, 
  ZoomIn, 
  ZoomOut, 
  RotateCw, 
  FileText,
  Image,
  File,
  AlertCircle,
  Loader2
} from 'lucide-react';
import { Button } from '../ui/Button';
import { Card } from '../ui/Card';

export interface FileViewerProps {
  isOpen: boolean;
  onClose: () => void;
  file: {
    name: string;
    url: string;
    type: string;
    size?: number;
  };
  title?: string;
}

export function FileViewer({ isOpen, onClose, file, title }: FileViewerProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [zoom, setZoom] = useState(100);
  const [rotation, setRotation] = useState(0);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      setError('');
      setZoom(100);
      setRotation(0);
    }
  }, [isOpen, file.url]);

  if (!isOpen) return null;

  const handleDownload = () => {
    const link = document.createElement('a');
    link.href = file.url;
    link.download = file.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getFileIcon = () => {
    const type = file.type.toLowerCase();
    if (type.includes('image')) return <Image className="h-6 w-6" />;
    if (type.includes('pdf')) return <FileText className="h-6 w-6" />;
    return <File className="h-6 w-6" />;
  };

  const renderContent = () => {
    const type = file.type.toLowerCase();

    if (type.includes('image')) {
      return (
        <div className="flex items-center justify-center h-full">
          <img
            src={file.url}
            alt={file.name}
            className="max-w-full max-h-full object-contain transition-transform duration-200"
            style={{
              transform: `scale(${zoom / 100}) rotate(${rotation}deg)`,
            }}
            onLoad={() => setLoading(false)}
            onError={() => {
              setError('图片加载失败');
              setLoading(false);
            }}
          />
        </div>
      );
    }

    if (type.includes('pdf')) {
      return (
        <div className="w-full h-full">
          <iframe
            src={`${file.url}#toolbar=1&navpanes=1&scrollbar=1`}
            className="w-full h-full border-0"
            title={file.name}
            onLoad={() => setLoading(false)}
            onError={() => {
              setError('PDF加载失败');
              setLoading(false);
            }}
          />
        </div>
      );
    }

    if (type.includes('text') || type.includes('json') || type.includes('xml')) {
      return (
        <div className="w-full h-full p-4 overflow-auto">
          <iframe
            src={file.url}
            className="w-full h-full border-0"
            title={file.name}
            onLoad={() => setLoading(false)}
            onError={() => {
              setError('文件加载失败');
              setLoading(false);
            }}
          />
        </div>
      );
    }

    // For other file types, show download option
    return (
      <div className="flex flex-col items-center justify-center h-full text-gray-500">
        <File className="h-16 w-16 mb-4" />
        <p className="text-lg font-medium mb-2">无法预览此文件类型</p>
        <p className="text-sm mb-4">文件类型: {file.type}</p>
        <Button onClick={handleDownload} className="flex items-center gap-2">
          <Download className="h-4 w-4" />
          下载文件
        </Button>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <Card className="w-full h-full max-w-7xl max-h-[95vh] flex flex-col bg-white">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b bg-gray-50">
          <div className="flex items-center gap-3">
            {getFileIcon()}
            <div>
              <h3 className="font-semibold text-gray-900">
                {title || file.name}
              </h3>
              <p className="text-sm text-gray-600">
                {file.type} {file.size && `• ${(file.size / 1024 / 1024).toFixed(2)} MB`}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Zoom controls for images */}
            {file.type.toLowerCase().includes('image') && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setZoom(Math.max(25, zoom - 25))}
                  disabled={zoom <= 25}
                >
                  <ZoomOut className="h-4 w-4" />
                </Button>
                <span className="text-sm text-gray-600 min-w-[60px] text-center">
                  {zoom}%
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setZoom(Math.min(400, zoom + 25))}
                  disabled={zoom >= 400}
                >
                  <ZoomIn className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setRotation((rotation + 90) % 360)}
                >
                  <RotateCw className="h-4 w-4" />
                </Button>
              </>
            )}

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

        {/* Content */}
        <div className="flex-1 relative overflow-hidden">
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-gray-50">
              <div className="flex flex-col items-center gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
                <p className="text-gray-600">加载中...</p>
              </div>
            </div>
          )}

          {error && (
            <div className="absolute inset-0 flex items-center justify-center bg-gray-50">
              <div className="flex flex-col items-center gap-3 text-red-600">
                <AlertCircle className="h-8 w-8" />
                <p>{error}</p>
                <Button onClick={handleDownload} variant="outline">
                  <Download className="h-4 w-4 mr-2" />
                  下载文件
                </Button>
              </div>
            </div>
          )}

          {!loading && !error && renderContent()}
        </div>
      </Card>
    </div>
  );
}
