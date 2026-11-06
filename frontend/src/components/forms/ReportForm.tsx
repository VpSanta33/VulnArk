import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { X, Upload, File } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/Dialog';
import { reportsService } from '../../services/reports';
import { assetsService } from '../../services/assets';
import { Report, Asset } from '../../types/api';

const reportSchema = z.object({
  title: z.string().min(1, '报告标题不能为空').max(255, '报告标题不能超过255个字符'),
  description: z.string().optional(),
  type: z.string().min(1, '请选择报告类型'),
  severity: z.string().min(1, '请选择严重程度'),
  asset_ids: z.array(z.number()).optional(),
  tags: z.array(z.string()).optional(),
  test_date: z.string().optional(),
});

type ReportFormData = z.infer<typeof reportSchema>;

interface ReportFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  report?: Report | null;
}

export function ReportForm({ isOpen, onClose, onSuccess, report }: ReportFormProps) {
  const [loading, setLoading] = useState(false);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState<string[]>([]);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
    setValue,
  } = useForm<ReportFormData>({
    resolver: zodResolver(reportSchema),
    defaultValues: {
      severity: 'medium',
      tags: [],
      asset_ids: [],
    },
  });

  // Load assets
  useEffect(() => {
    const loadAssets = async () => {
      try {
        const response = await assetsService.getAssets();
        setAssets(response.data || []);
      } catch (err) {
        console.error('Failed to load assets:', err);
      }
    };

    if (isOpen) {
      loadAssets();
    }
  }, [isOpen]);

  // Reset form when dialog opens/closes
  useEffect(() => {
    if (isOpen) {
      if (report) {
        // Edit mode - populate form with report data
        const reportTags = Array.isArray(report.tags) ? report.tags : [];
        const reportAssetIds = Array.isArray(report.asset_ids) ? report.asset_ids : [];
        
        reset({
          title: report.title,
          description: report.description || '',
          type: report.type,
          severity: report.severity || 'medium',
          asset_ids: reportAssetIds,
          tags: reportTags,
          test_date: report.test_date ? new Date(report.test_date).toISOString().split('T')[0] : '',
        });
        setTags(reportTags);
      } else {
        // Create mode - reset to defaults
        reset({
          title: '',
          description: '',
          type: '',
          severity: 'medium',
          asset_ids: [],
          tags: [],
          test_date: '',
        });
        setTags([]);
      }
      setError('');
      setSelectedFile(null);
      setTagInput('');
    }
  }, [isOpen, report, reset]);

  const onSubmit = async (data: ReportFormData) => {
    try {
      setLoading(true);
      setError('');

      // Prepare form data for file upload
      const formData = new FormData();
      formData.append('title', data.title);
      formData.append('description', data.description || '');
      formData.append('type', data.type);
      formData.append('severity', data.severity);
      formData.append('tags', JSON.stringify(tags));
      formData.append('asset_ids', JSON.stringify(data.asset_ids || []));
      if (data.test_date) {
        formData.append('test_date', data.test_date);
      }

      if (selectedFile) {
        formData.append('file', selectedFile);
      }

      if (report) {
        // Update existing report - convert FormData to object
        const updateData: Partial<Report> = {
          title: data.title,
          description: data.description,
          type: data.type as Report['type'],
          severity: data.severity,
          tags: tags,
          asset_ids: data.asset_ids || [],
          test_date: data.test_date,
        };
        await reportsService.updateReport(report.id, updateData);
      } else {
        // Create new report
        if (!selectedFile) {
          setError('请选择要上传的报告文件');
          return;
        }
        await reportsService.createReport(formData);
      }

      onSuccess();
      onClose();
    } catch (err: unknown) {
      setError(getErrorMessage(err, '操作失败'));
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      // Check file size (max 50MB)
      if (file.size > 50 * 1024 * 1024) {
        setError('文件大小不能超过50MB');
        return;
      }
      setSelectedFile(file);
      setError('');
    }
  };

  const handleAddTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      const newTags = [...tags, tagInput.trim()];
      setTags(newTags);
      setValue('tags', newTags);
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    const newTags = tags.filter(tag => tag !== tagToRemove);
    setTags(newTags);
    setValue('tags', newTags);
  };

  const reportTypes = [
    { value: 'penetration_test', label: '渗透测试报告' },
    { value: 'vulnerability_assessment', label: '漏洞评估报告' },
    { value: 'security_audit', label: '安全审计报告' },
    { value: 'code_review', label: '代码审计报告' },
    { value: 'compliance_check', label: '合规检查报告' },
    { value: 'incident_response', label: '应急响应报告' },
    { value: 'risk_assessment', label: '风险评估报告' },
    { value: 'other', label: '其他报告' },
  ];

  const severityLevels = [
    { value: 'critical', label: '严重' },
    { value: 'high', label: '高危' },
    { value: 'medium', label: '中危' },
    { value: 'low', label: '低危' },
    { value: 'info', label: '信息' },
  ];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            {report ? '编辑报告' : '上传报告'}
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

          {/* File Upload */}
          {!report && (
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                报告文件 <span className="text-red-500">*</span>
              </label>
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-gray-400 transition-colors">
                <input
                  type="file"
                  onChange={handleFileChange}
                  accept=".pdf,.doc,.docx,.txt,.md"
                  className="hidden"
                  id="file-upload"
                />
                <label htmlFor="file-upload" className="cursor-pointer">
                  <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-sm text-gray-600">
                    点击选择文件或拖拽文件到此处
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    支持 PDF、Word、文本文件，最大 50MB
                  </p>
                </label>
              </div>
              {selectedFile && (
                <div className="flex items-center space-x-2 text-sm text-gray-600">
                  <File className="h-4 w-4" />
                  <span>{selectedFile.name}</span>
                  <span className="text-gray-400">
                    ({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Basic Information */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                报告标题 <span className="text-red-500">*</span>
              </label>
              <Input
                {...register('title')}
                placeholder="请输入报告标题"
                error={errors.title?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                报告类型 <span className="text-red-500">*</span>
              </label>
              <Select
                {...register('type')}
                options={reportTypes}
                placeholder="请选择报告类型"
                error={errors.type?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                严重程度
              </label>
              <Select
                {...register('severity')}
                options={severityLevels}
                placeholder="请选择严重程度"
                error={errors.severity?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                测试日期
              </label>
              <Input
                {...register('test_date')}
                type="date"
                error={errors.test_date?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                关联资产
              </label>
              <Select
                {...register('asset_ids')}
                options={assets.map(asset => ({
                  value: asset.id,
                  label: `${asset.name} (${asset.ip_address || asset.domain})`,
                }))}
                placeholder="请选择关联资产"
                multiple
                error={errors.asset_ids?.message}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              报告描述
            </label>
            <textarea
              {...register('description')}
              rows={4}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="请输入报告描述"
            />
            {errors.description && (
              <p className="mt-1 text-sm text-red-600">{errors.description.message}</p>
            )}
          </div>

          {/* Tags */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              标签
            </label>
            <div className="flex space-x-2 mb-2">
              <Input
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                placeholder="输入标签"
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddTag();
                  }
                }}
              />
              <Button
                type="button"
                variant="outline"
                onClick={handleAddTag}
                disabled={!tagInput.trim()}
              >
                添加
              </Button>
            </div>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {tags.map((tag, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                  >
                    {tag}
                    <button
                      type="button"
                      onClick={() => handleRemoveTag(tag)}
                      className="ml-1 text-blue-600 hover:text-blue-800"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end space-x-3 pt-4">
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
              {report ? '更新' : '上传'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
