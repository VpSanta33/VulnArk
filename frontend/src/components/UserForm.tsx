import { getErrorMessage } from '../lib/utils';
import { useState, useEffect } from 'react';
import { useForm, Resolver } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Select } from './ui/Select';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogClose } from './ui/Dialog';
import { usersService, CreateUserRequest, UpdateUserRequest } from '../services/users';
import { User, Role } from '../types/api';

const createUserSchema = z.object({
  username: z.string().min(1, '请输入用户名').min(3, '用户名至少3个字符'),
  real_name: z.string().min(1, '请输入真实姓名'),
  email: z.string().min(1, '请输入邮箱').email('请输入有效的邮箱地址'),
  phone: z.string().optional(),
  department: z.string().optional(),
  password: z.string().min(6, '密码至少6个字符'),
  confirmPassword: z.string().min(1, '请确认密码'),
  role_id: z.number().min(1, '请选择角色'),
}).refine((data) => data.password === data.confirmPassword, {
  message: '两次输入的密码不一致',
  path: ['confirmPassword'],
});

const updateUserSchema = z.object({
  real_name: z.string().min(1, '请输入真实姓名'),
  email: z.string().min(1, '请输入邮箱').email('请输入有效的邮箱地址'),
  phone: z.string().optional(),
  department: z.string().optional(),
  role_id: z.number().min(1, '请选择角色'),
});

type CreateUserFormData = z.infer<typeof createUserSchema>;
type UpdateUserFormData = z.infer<typeof updateUserSchema>;

interface UserFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user?: User | null;
  onSuccess: () => void;
}

export function UserForm({ open, onOpenChange, user, onSuccess }: UserFormProps) {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  const isEditing = !!user;
  const departments = usersService.getDepartments();

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
    setValue,
  } = useForm<CreateUserFormData, unknown, CreateUserFormData | UpdateUserFormData>({
    resolver: zodResolver(isEditing ? updateUserSchema : createUserSchema) as unknown as Resolver<
      CreateUserFormData,
      unknown,
      CreateUserFormData | UpdateUserFormData
    >,
  });

  useEffect(() => {
    const fetchRoles = async () => {
      try {
        const rolesData = await usersService.getRoles();
        setRoles(rolesData);
      } catch (err: unknown) {
        setError(getErrorMessage(err, '获取角色列表失败'));
      }
    };

    if (open) {
      fetchRoles();
      
      if (isEditing && user) {
        // Populate form with user data
        setValue('real_name', user.real_name);
        setValue('email', user.email);
        setValue('phone', user.phone || '');
        setValue('department', user.department || '');
        setValue('role_id', user.role.id);
      } else {
        reset();
      }
    }
  }, [open, isEditing, user, setValue, reset]);

  const onSubmit = async (data: CreateUserFormData | UpdateUserFormData) => {
    try {
      setLoading(true);
      setError('');

      if (isEditing && user) {
        await usersService.updateUser(user.id, data as UpdateUserRequest);
      } else {
        await usersService.createUser(data as CreateUserRequest);
      }

      onSuccess();
      onOpenChange(false);
      reset();
    } catch (err: unknown) {
      setError(getErrorMessage(err, `${isEditing ? '更新' : '创建'}用户失败`));
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    onOpenChange(false);
    reset();
    setError('');
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogClose onClose={handleClose} />
        <DialogHeader>
          <DialogTitle>{isEditing ? '编辑用户' : '新增用户'}</DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}

          {!isEditing && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                用户名 *
              </label>
              <Input
                {...register('username')}
                placeholder="请输入用户名"
                error={errors.username?.message}
              />
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              真实姓名 *
            </label>
            <Input
              {...register('real_name')}
              placeholder="请输入真实姓名"
              error={errors.real_name?.message}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              邮箱 *
            </label>
            <Input
              type="email"
              {...register('email')}
              placeholder="请输入邮箱地址"
              error={errors.email?.message}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              手机号
            </label>
            <Input
              {...register('phone')}
              placeholder="请输入手机号"
              error={errors.phone?.message}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              部门
            </label>
            <Select
              {...register('department')}
              placeholder="请选择部门"
              options={[
                { value: '', label: '请选择部门' },
                ...departments.map(dept => ({ value: dept, label: dept }))
              ]}
              error={errors.department?.message}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              角色 *
            </label>
            <Select
              {...register('role_id', { valueAsNumber: true })}
              placeholder="请选择角色"
              options={[
                { value: '', label: '请选择角色' },
                ...roles.map(role => ({ value: role.id, label: role.name }))
              ]}
              error={errors.role_id?.message}
            />
          </div>

          {!isEditing && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  密码 *
                </label>
                <Input
                  type="password"
                  {...register('password')}
                  placeholder="请输入密码"
                  error={errors.password?.message}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  确认密码 *
                </label>
                <Input
                  type="password"
                  {...register('confirmPassword')}
                  placeholder="请再次输入密码"
                  error={errors.confirmPassword?.message}
                />
              </div>
            </>
          )}

          <div className="flex justify-end space-x-2 pt-4">
            <Button type="button" variant="outline" onClick={handleClose}>
              取消
            </Button>
            <Button type="submit" loading={loading}>
              {isEditing ? '更新' : '创建'}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
