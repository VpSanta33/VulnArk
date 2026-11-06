import { getErrorMessage } from '../../lib/utils';
import { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { User, Camera, Save, X } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/Card';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Select } from '../ui/Select';
import { Badge } from '../ui/Badge';
import { useAuth } from '../../contexts/AuthContext';
import { settingsService, UserProfileUpdateRequest } from '../../services/settings';

const profileSchema = z.object({
  username: z.string().min(1, '用户名不能为空'),
  real_name: z.string().min(1, '真实姓名不能为空'),
  email: z.string().email('请输入有效的邮箱地址'),
  phone: z.string().optional(),
  department: z.string().optional(),
});

type ProfileFormData = z.infer<typeof profileSchema>;

export function ProfileSettings() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isDirty },
  } = useForm<ProfileFormData>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      username: user?.username || '',
      real_name: user?.real_name || '',
      email: user?.email || '',
      phone: user?.phone || '',
      department: user?.department || '',
    },
  });

  useEffect(() => {
    if (user) {
      reset({
        username: user.username,
        real_name: user.real_name,
        email: user.email,
        phone: user.phone || '',
        department: user.department || '',
      });
    }
  }, [user, reset]);

  const onSubmit = async (data: ProfileFormData) => {
    try {
      setLoading(true);
      setError('');
      setSuccess('');

      const updateData: UserProfileUpdateRequest = {
        username: data.username,
        real_name: data.real_name,
        email: data.email,
        phone: data.phone || undefined,
        department: data.department || undefined,
      };

      await settingsService.updateProfile(updateData);

      setSuccess('个人资料更新成功！');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '更新失败，请重试'));
    } finally {
      setLoading(false);
    }
  };

  const handleAvatarChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setAvatarPreview(e.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const departments = [
    '技术部',
    '安全部',
    '运维部',
    '产品部',
    '市场部',
    '人事部',
    '财务部',
  ];

  return (
    <div className="space-y-6">
      {/* Profile Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5 text-blue-500" />
            个人资料
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-start gap-6">
            {/* Avatar Section */}
            <div className="flex flex-col items-center space-y-4">
              <div className="relative">
                <div className="w-24 h-24 rounded-full bg-gray-200 flex items-center justify-center overflow-hidden">
                  {avatarPreview || user?.avatar ? (
                    <img
                      src={avatarPreview || user?.avatar}
                      alt="Avatar"
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <User className="h-12 w-12 text-gray-400" />
                  )}
                </div>
                <label className="absolute -bottom-2 -right-2 bg-blue-600 text-white p-2 rounded-full cursor-pointer hover:bg-blue-700 transition-colors">
                  <Camera className="h-4 w-4" />
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleAvatarChange}
                    className="hidden"
                  />
                </label>
              </div>
              <div className="text-center">
                <p className="font-medium text-gray-900">{user?.real_name}</p>
                <p className="text-sm text-gray-500">@{user?.username}</p>
                <Badge variant="success" className="mt-1">
                  {user?.role?.name || '用户'}
                </Badge>
              </div>
            </div>

            {/* Profile Form */}
            <div className="flex-1">
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                {error && (
                  <div className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-md flex items-center gap-2">
                    <X className="h-4 w-4" />
                    {error}
                  </div>
                )}

                {success && (
                  <div className="bg-green-50 border border-green-200 text-green-600 px-4 py-3 rounded-md flex items-center gap-2">
                    <Save className="h-4 w-4" />
                    {success}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      用户名 <span className="text-red-500">*</span>
                    </label>
                    <Input
                      {...register('username')}
                      error={errors.username?.message}
                      disabled={loading}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      真实姓名 <span className="text-red-500">*</span>
                    </label>
                    <Input
                      {...register('real_name')}
                      error={errors.real_name?.message}
                      disabled={loading}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      邮箱地址 <span className="text-red-500">*</span>
                    </label>
                    <Input
                      type="email"
                      {...register('email')}
                      error={errors.email?.message}
                      disabled={loading}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      手机号码
                    </label>
                    <Input
                      {...register('phone')}
                      error={errors.phone?.message}
                      disabled={loading}
                      placeholder="请输入手机号码"
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      所属部门
                    </label>
                    <Select
                      {...register('department')}
                      options={departments.map(dept => ({ value: dept, label: dept }))}
                      placeholder="请选择部门"
                      error={errors.department?.message}
                      disabled={loading}
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-4">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => reset()}
                    disabled={loading || !isDirty}
                  >
                    重置
                  </Button>
                  <Button
                    type="submit"
                    disabled={loading || !isDirty}
                    className="gap-2"
                  >
                    <Save className="h-4 w-4" />
                    {loading ? '保存中...' : '保存更改'}
                  </Button>
                </div>
              </form>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Account Information */}
      <Card>
        <CardHeader>
          <CardTitle>账户信息</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-gray-600">账户创建时间:</span>
              <span className="ml-2 font-medium">
                {user?.created_at ? new Date(user.created_at).toLocaleString('zh-CN') : '未知'}
              </span>
            </div>
            <div>
              <span className="text-gray-600">最后登录时间:</span>
              <span className="ml-2 font-medium">
                {user?.last_login_at ? new Date(user.last_login_at).toLocaleString('zh-CN') : '未知'}
              </span>
            </div>
            <div>
              <span className="text-gray-600">账户状态:</span>
              <Badge variant={user?.status === 1 ? 'success' : 'destructive'} className="ml-2">
                {user?.status === 1 ? '正常' : '禁用'}
              </Badge>
            </div>
            <div>
              <span className="text-gray-600">用户角色:</span>
              <Badge variant="outline" className="ml-2">
                {user?.role?.name || '未知'}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
