import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { X } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/Dialog';
import { assetsService } from '../../services/assets';
import { usersService } from '../../services/users';
import { Asset, User } from '../../types/api';
import { networkZones } from '../../lib/risk';

const assetSchema = z.object({
  name: z.string().min(1, '资产名称不能为空').max(100, '资产名称不能超过100个字符'),
  type: z.enum(['server', 'database', 'application', 'network']),
  category: z.string().optional(),
  ip_address: z.string().optional(),
  domain: z.string().optional(),
  port: z.string().optional(),
  os: z.string().optional(),
  version: z.string().optional(),
  department: z.string().optional(),
  owner_id: z.number().optional(),
  business_line: z.string().optional(),
  importance_level: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  description: z.string().optional(),
  internet_facing: z.boolean(),
  network_zone: z.enum(['internal', 'dmz', 'production', 'ot', 'test']),
});

type AssetFormData = z.infer<typeof assetSchema>;

interface AssetFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  asset?: Asset | null;
}

export function AssetForm({ isOpen, onClose, onSuccess, asset }: AssetFormProps) {
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string>('');

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<AssetFormData>({
    resolver: zodResolver(assetSchema),
    defaultValues: {
      importance_level: 3,
      internet_facing: false,
      network_zone: 'internal',
    },
  });

  // Load users for owner selection
  useEffect(() => {
    const loadUsers = async () => {
      try {
        const response = await usersService.getUsers();
        setUsers(response.data || []);
      } catch (err) {
        console.error('Failed to load users:', err);
      }
    };

    if (isOpen) {
      loadUsers();
    }
  }, [isOpen]);

  // Reset form when dialog opens/closes
  useEffect(() => {
    if (isOpen) {
      if (asset) {
        // Edit mode - populate form with asset data
        reset({
          name: asset.name,
          type: asset.type,
          category: asset.category || '',
          ip_address: asset.ip_address || '',
          domain: asset.domain || '',
          port: asset.port || '',
          os: asset.os || '',
          version: asset.version || '',
          department: asset.department || '',
          owner_id: asset.owner?.id,
          business_line: asset.business_line || '',
          importance_level: asset.importance_level || 3,
          description: asset.description || '',
          internet_facing: !!asset.internet_facing,
          network_zone: asset.network_zone || 'internal',
        });
      } else {
        // Create mode - reset to defaults
        reset({
          name: '',
          type: 'server', // Default to first valid option
          category: '',
          ip_address: '',
          domain: '',
          port: '',
          os: '',
          version: '',
          department: '',
          owner_id: undefined,
          business_line: '',
          importance_level: 3,
          description: '',
          internet_facing: false,
          network_zone: 'internal',
        });
      }
      setError('');
    }
  }, [isOpen, asset, reset]);

  const onSubmit = async (data: AssetFormData) => {
    try {
      setLoading(true);
      setError('');

      if (asset) {
        // Update existing asset
        await assetsService.updateAsset(asset.id, data);
      } else {
        // Create new asset
        await assetsService.createAsset(data);
      }

      onSuccess();
      onClose();
    } catch (err: unknown) {
      setError(getErrorMessage(err, '操作失败'));
    } finally {
      setLoading(false);
    }
  };

  const assetTypes = [
    { value: 'server', label: '服务器' },
    { value: 'database', label: '数据库' },
    { value: 'application', label: '应用系统' },
    { value: 'network', label: '网络设备' },
  ];

  const importanceLevels = [
    { value: 1, label: '高' },
    { value: 2, label: '中' },
    { value: 3, label: '低' },
  ];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            {asset ? '编辑资产' : '新建资产'}
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

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                资产名称 <span className="text-red-500">*</span>
              </label>
              <Input
                {...register('name')}
                placeholder="请输入资产名称"
                error={errors.name?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                资产类型 <span className="text-red-500">*</span>
              </label>
              <Select
                {...register('type')}
                options={assetTypes}
                placeholder="请选择资产类型"
                error={errors.type?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                资产分类
              </label>
              <Input
                {...register('category')}
                placeholder="请输入资产分类"
                error={errors.category?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                IP地址
              </label>
              <Input
                {...register('ip_address')}
                placeholder="请输入IP地址"
                error={errors.ip_address?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                域名
              </label>
              <Input
                {...register('domain')}
                placeholder="请输入域名"
                error={errors.domain?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                端口
              </label>
              <Input
                {...register('port')}
                placeholder="请输入端口号"
                error={errors.port?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                操作系统
              </label>
              <Input
                {...register('os')}
                placeholder="请输入操作系统"
                error={errors.os?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                版本
              </label>
              <Input
                {...register('version')}
                placeholder="请输入版本信息"
                error={errors.version?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                所属部门
              </label>
              <Input
                {...register('department')}
                placeholder="请输入所属部门"
                error={errors.department?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                负责人
              </label>
              <Select
                {...register('owner_id', { valueAsNumber: true })}
                options={users.map(user => ({
                  value: user.id,
                  label: `${user.real_name} (${user.username})`,
                }))}
                placeholder="请选择负责人"
                error={errors.owner_id?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                业务线
              </label>
              <Input
                {...register('business_line')}
                placeholder="请输入业务线"
                error={errors.business_line?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                重要程度
              </label>
              <Select
                {...register('importance_level', { valueAsNumber: true })}
                options={importanceLevels}
                placeholder="请选择重要程度"
                error={errors.importance_level?.message}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                网络区域
              </label>
              <Select
                {...register('network_zone')}
                options={networkZones}
                error={errors.network_zone?.message}
              />
            </div>

            <div className="flex items-end pb-2">
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700">
                <input type="checkbox" {...register('internet_facing')} />
                对外暴露（互联网可访问）
              </label>
            </div>
          </div>
          <p className="text-xs text-gray-500">重要程度、网络区域和对外暴露会计入该资产上漏洞的风险评分，保存后自动重算。</p>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              资产描述
            </label>
            <textarea
              {...register('description')}
              rows={3}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="请输入资产描述"
            />
            {errors.description && (
              <p className="mt-1 text-sm text-red-600">{errors.description.message}</p>
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
              {asset ? '更新' : '创建'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
