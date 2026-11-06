import { useLatestRequest, useSearchKeyword } from '../hooks/useListSearch';
import { getErrorMessage } from '../lib/utils';
import { useState, useEffect, useCallback, useRef } from 'react';
import { Plus, Search, Edit, Trash2, UserCheck, UserX } from 'lucide-react';
import { UserForm } from '../components/UserForm';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/Table';
import { Pagination } from '../components/ui/Pagination';
import { usersService, UserSearchParams } from '../services/users';
import { User, Role, PaginatedResponse } from '../types/api';

export function Users() {
  const [users, setUsers] = useState<PaginatedResponse<User> | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const rolesRef = useRef<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  // Form states
  const [showUserForm, setShowUserForm] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  
  // Search and filter states
  const [searchParams, setSearchParams] = useState<UserSearchParams>({
    page: 1,
    page_size: 10,
    keyword: '',
    role_id: undefined,
    department: '',
    status: undefined,
  });

  const departments = usersService.getDepartments();
  const statusOptions = usersService.getUserStatusOptions();

  const [keyword, handleSearch] = useSearchKeyword(setSearchParams);
  const { begin, cancel } = useLatestRequest();

  const fetchUsers = useCallback(async () => {
    const request = begin();
    try {
      setLoading(true);
      setError('');
      const [usersData, rolesData] = await Promise.all([
        usersService.getUsers(searchParams, request.signal),
        rolesRef.current.length === 0 ? usersService.getRoles() : Promise.resolve(rolesRef.current),
      ]);
      if (!request.isCurrent()) return;
      setUsers(usersData);
      if (rolesRef.current.length === 0) {
        rolesRef.current = rolesData;
        setRoles(rolesData);
      }
    } catch (err: unknown) {
      if (request.isCurrent()) setError(getErrorMessage(err, '获取用户列表失败'));
    } finally {
      if (request.isCurrent()) setLoading(false);
    }
  }, [searchParams, begin]);

  useEffect(() => {
    void fetchUsers();
    return cancel;
  }, [fetchUsers, cancel]);

  const handleFilterChange = <K extends keyof UserSearchParams>(key: K, value: UserSearchParams[K]) => {
    setSearchParams(prev => ({ ...prev, [key]: value, page: 1 }));
  };

  const handlePageChange = (page: number) => {
    setSearchParams(prev => ({ ...prev, page }));
  };

  const handleDeleteUser = async (id: number) => {
    if (!confirm('确定要删除这个用户吗？')) return;

    try {
      await usersService.deleteUser(id);
      fetchUsers();
    } catch (err: unknown) {
      alert(getErrorMessage(err, '删除用户失败'));
    }
  };

  const handleToggleUserStatus = async (user: User) => {
    const newStatus = user.status === 1 ? 0 : 1;
    const action = newStatus === 1 ? '启用' : '禁用';

    if (!confirm(`确定要${action}用户 "${user.real_name}" 吗？`)) return;

    try {
      await usersService.updateUser(user.id, { status: newStatus });
      fetchUsers();
    } catch (err: unknown) {
      alert(getErrorMessage(err, `${action}用户失败`));
    }
  };

  const handleCreateUser = () => {
    setEditingUser(null);
    setShowUserForm(true);
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setShowUserForm(true);
  };

  const handleUserFormSuccess = () => {
    fetchUsers();
  };

  const getRoleName = (roleId: number) => {
    const role = roles.find(r => r.id === roleId);
    return role?.name || '未知角色';
  };

  const getStatusBadge = (status: number) => {
    const statusInfo = statusOptions.find(s => s.value === status);
    return (
      <Badge variant={status === 1 ? 'success' : 'destructive'}>
        {statusInfo?.label || '未知'}
      </Badge>
    );
  };

  if (loading && !users) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">用户管理</h1>
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
          <h1 className="text-3xl font-bold text-gray-900">用户管理</h1>
          <p className="mt-2 text-sm text-gray-600">管理系统用户账号和权限</p>
        </div>
        <Button onClick={handleCreateUser}>
          <Plus className="h-4 w-4 mr-2" />
          新增用户
        </Button>
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
                搜索用户
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="用户名、姓名或邮箱"
                  value={keyword}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                角色
              </label>
              <Select
                placeholder="选择角色"
                value={searchParams.role_id || ''}
                onChange={(e) => handleFilterChange('role_id', e.target.value ? Number(e.target.value) : undefined)}
                options={[
                  { value: '', label: '全部角色' },
                  ...roles.map(role => ({ value: role.id, label: role.name }))
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                部门
              </label>
              <Select
                placeholder="选择部门"
                value={searchParams.department || ''}
                onChange={(e) => handleFilterChange('department', e.target.value)}
                options={[
                  { value: '', label: '全部部门' },
                  ...departments.map(dept => ({ value: dept, label: dept }))
                ]}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                状态
              </label>
              <Select
                placeholder="选择状态"
                value={searchParams.status !== undefined ? searchParams.status : ''}
                onChange={(e) => handleFilterChange('status', e.target.value !== '' ? Number(e.target.value) : undefined)}
                options={[
                  { value: '', label: '全部状态' },
                  ...statusOptions.map(status => ({ value: status.value, label: status.label }))
                ]}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6 text-center text-red-600">
              <p>{error}</p>
              <Button variant="outline" onClick={fetchUsers} className="mt-2">
                重试
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>用户信息</TableHead>
                    <TableHead>角色</TableHead>
                    <TableHead>部门</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead>最后登录</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users?.data.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <div>
                          <div className="font-medium">{user.real_name}</div>
                          <div className="text-sm text-gray-500">
                            {user.username} • {user.email}
                          </div>
                          {user.phone && (
                            <div className="text-sm text-gray-500">{user.phone}</div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {getRoleName(user.role.id)}
                        </Badge>
                      </TableCell>
                      <TableCell>{user.department || '-'}</TableCell>
                      <TableCell>{getStatusBadge(user.status || 0)}</TableCell>
                      <TableCell>
                        {user.last_login_at 
                          ? new Date(user.last_login_at).toLocaleString('zh-CN')
                          : '从未登录'
                        }
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleToggleUserStatus(user)}
                            title={user.status === 1 ? '禁用用户' : '启用用户'}
                            className={user.status === 1 ? 'text-orange-600 hover:text-orange-700' : 'text-green-600 hover:text-green-700'}
                          >
                            {user.status === 1 ? <UserX className="h-4 w-4" /> : <UserCheck className="h-4 w-4" />}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEditUser(user)}
                            title="编辑用户"
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteUser(user.id)}
                            title="删除用户"
                            className="text-red-600 hover:text-red-700"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              {users && users.total > 0 && (
                <div className="p-4 border-t">
                  <Pagination
                    currentPage={users.page}
                    totalPages={users.total_pages}
                    onPageChange={handlePageChange}
                    totalItems={users.total}
                    itemsPerPage={users.page_size}
                  />
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      {/* User Form Dialog */}
      <UserForm
        open={showUserForm}
        onOpenChange={setShowUserForm}
        user={editingUser}
        onSuccess={handleUserFormSuccess}
      />
    </div>
  );
}
