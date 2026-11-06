import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '../contexts/AuthContext';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import { LoginRequest } from '../types/api';
import { getAuthError, isExpiredLoginChallengeError, isLoginChallenge, isLoginRebindRequired, LoginChallenge, LoginRebindRequired, TwoFactorSetup } from '../types/auth';
import { settingsService } from '../services/settings';
import { systemService, ClientConfig } from '../services/system';
import { AlertTriangle, Info, Key, User, ArrowLeft } from 'lucide-react';

const loginSchema = z.object({
  username: z.string().min(1, '请输入用户名'),
  password: z.string().min(1, '请输入密码'),
});

type LoginFormData = z.infer<typeof loginSchema>;

export function Login() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [notice, setNotice] = useState<string>('');
  const [clientConfig, setClientConfig] = useState<ClientConfig | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [challenge, setChallenge] = useState<LoginChallenge | null>(null);
  const [rebind, setRebind] = useState<(LoginRebindRequired & { setup?: TwoFactorSetup }) | null>(null);
  const [credentials, setCredentials] = useState<LoginRequest | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [rebindRecoveryCodes, setRebindRecoveryCodes] = useState<string[]>([]);
  const [showRebindRecoveryCodes, setShowRebindRecoveryCodes] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/';
  const loginNotice = location.state?.message;

  // 获取客户端配置
  useEffect(() => {
    const fetchClientConfig = async () => {
      try {
        const config = await systemService.getClientConfig();
        setClientConfig(config);
      } catch (error) {
        console.error('获取客户端配置失败:', error);
      } finally {
        setConfigLoading(false);
      }
    };

    fetchClientConfig();
  }, []);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  const onSubmit = async (data: LoginFormData) => {
    try {
      setIsLoading(true);
      setError('');
      setNotice('');
      setChallenge(null);
      setRebind(null);
      setCredentials(null);
      const result = await login(data);
      if (isLoginChallenge(result)) {
        setCredentials(data);
        setRebind(null);
        setChallenge(result);
        setVerificationCode('');
        return;
      }
      if (isLoginRebindRequired(result)) {
        setRebind(result);
        setVerificationCode('');
        await beginRebind(result.rebind_token);
        return;
      }

      navigate(from, { replace: true });
    } catch (error: unknown) {
      setError(getAuthError(error, '登录失败，请检查用户名和密码').message);
    } finally {
      setIsLoading(false);
    }
  };

  const beginRebind = async (token: string) => {
    try {
      setIsLoading(true);
      setError('');
      const setup = await settingsService.setup2FA(token);
      setRebind((current) => current ? { ...current, setup } : current);
    } catch (error: unknown) {
      setError(getAuthError(error, '无法开始双因素认证重新绑定').message);
    } finally {
      setIsLoading(false);
    }
  };

  const onVerifyRebind = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!rebind || !rebind.setup) return;
    if (Date.parse(rebind.setup.expires_at) <= Date.now()) {
      setError('身份验证器绑定已过期，请重新输入用户名和密码');
      setRebind(null);
      setCredentials(null);
      setChallenge(null);
      return;
    }

    try {
      setIsLoading(true);
      setError('');
      const result = await settingsService.verify2FA(verificationCode.trim(), rebind.rebind_token);
      setRebind(null);
      setCredentials(null);
      setChallenge(null);
      setVerificationCode('');
      setRebindRecoveryCodes(result.recovery_codes);
      setShowRebindRecoveryCodes(true);
      setNotice('身份验证器已重新绑定，请保存恢复码后重新登录');
    } catch (error: unknown) {
      setError(getAuthError(error, '验证码错误或绑定已过期，请重试').message);
    } finally {
      setIsLoading(false);
    }
  };

  const onVerifyMfa = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!challenge || !credentials) return;

    if (Date.parse(challenge.expires_at) <= Date.now()) {
      setError('登录验证已过期，请返回重新登录');
      setChallenge(null);
      setCredentials(null);
      return;
    }

    try {
      setIsLoading(true);
      setError('');
      const result = await login(credentials, {
        challengeToken: challenge.challenge_token,
        ...(useRecoveryCode ? { recoveryCode: verificationCode.trim() } : { totpCode: verificationCode.trim() }),
      });
      if (isLoginChallenge(result)) {
        setChallenge(result);
        setVerificationCode('');
        return;
      }
      if (isLoginRebindRequired(result)) {
        setChallenge(null);
        setCredentials(null);
        setRebind(result);
        setVerificationCode('');
        return;
      }

      navigate(from, { replace: true });
    } catch (error: unknown) {
      const message = getAuthError(error, '验证码无效，请重试').message;
      if (isExpiredLoginChallengeError(message)) {
        setError('登录验证已过期或无效，请返回重新登录');
        setChallenge(null);
        setCredentials(null);
      } else {
        setError(message);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-6">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-gray-900">
            {clientConfig?.system_name || 'VulnArk'}
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            漏洞管理平台 {clientConfig?.version && `v${clientConfig.version}`}
          </p>
        </div>

        {/* 首次部署提示 */}
        {!configLoading && clientConfig?.login_tips?.show_first_deploy_tip && (
          <Card className="border-blue-200 bg-blue-50">
            <CardContent className="pt-6">
              <div className="flex items-start space-x-3">
                <Info className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
                <div className="flex-1">
                  <h3 className="text-sm font-medium text-blue-900 mb-2">
                    🎉 欢迎使用 VulnArk！
                  </h3>
                  <div className="text-sm text-blue-800 space-y-2">
                    <p>这是系统首次部署，已为您创建默认管理员账号：</p>
                    <div className="bg-white/60 rounded-md p-3 space-y-1">
                      <div className="flex items-center space-x-2">
                        <User className="h-4 w-4" />
                        <span className="font-mono font-medium">
                          {clientConfig.login_tips.admin_username}
                        </span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Key className="h-4 w-4" />
                        <span className="text-xs">
                          密码请查看服务器根目录下的 <code className="bg-gray-100 px-1 rounded">
                            {clientConfig.login_tips.credential_file}
                          </code> 文件
                        </span>
                      </div>
                    </div>
                    <div className="flex items-start space-x-2 mt-3">
                      <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 flex-shrink-0" />
                      <p className="text-xs text-amber-800">
                        <strong>安全提醒：</strong>请登录后立即修改默认密码，并删除凭证文件以确保系统安全。
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>{rebind ? '重新绑定身份验证器' : challenge ? '双因素验证' : '登录'}</CardTitle>
            <CardDescription>
              {rebind
                ? '旧版双因素认证需要重新绑定。完成后请重新登录。'
                : challenge ? '请输入身份验证器验证码以继续登录' : '请输入您的用户名和密码以访问系统'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {(loginNotice || notice) && !challenge && !rebind && (
              <div className="mb-4 rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-800">
                {notice || loginNotice}
              </div>
            )}
            {error && (
              <div className="mb-4 bg-destructive/15 text-destructive text-sm p-3 rounded-md flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {rebind ? (
              rebind.setup ? (
                <form onSubmit={onVerifyRebind} className="space-y-4">
                  <p className="text-sm text-gray-600">
                    扫描二维码后输入验证码。绑定有效期至 {new Date(rebind.setup.expires_at).toLocaleTimeString()}。
                  </p>
                  <div className="flex justify-center rounded-md border bg-white p-4">
                    <img src={rebind.setup.qr_code_data_url} alt="身份验证器绑定二维码" className="h-48 w-48" />
                  </div>
                  <p className="break-all text-xs font-mono text-gray-600">密钥：{rebind.setup.secret}</p>
                  <label htmlFor="rebind-code" className="block text-sm font-medium text-gray-700">身份验证器验证码</label>
                  <Input
                    id="rebind-code"
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    value={verificationCode}
                    onChange={(event) => setVerificationCode(event.target.value)}
                    placeholder="请输入6位验证码"
                    maxLength={6}
                    required
                  />
                  <Button type="submit" className="w-full" loading={isLoading} disabled={isLoading || verificationCode.length !== 6}>
                    {isLoading ? '绑定中...' : '完成重新绑定'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full gap-2"
                    disabled={isLoading}
                    onClick={() => {
                      setRebind(null);
                      setCredentials(null);
                      setVerificationCode('');
                    }}
                  >
                    <ArrowLeft className="h-4 w-4" />
                    返回登录
                  </Button>
                </form>
              ) : (
                <Button type="button" onClick={() => beginRebind(rebind.rebind_token)} loading={isLoading}>
                  开始重新绑定
                </Button>
              )
            ) : !challenge ? (
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">用户名</label>
                  <Input
                    id="username"
                    type="text"
                    placeholder="请输入用户名"
                    error={errors.username?.message}
                    defaultValue={clientConfig?.login_tips?.show_first_deploy_tip ? 'admin' : ''}
                    {...register('username')}
                  />
                </div>

                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">密码</label>
                  <Input
                    id="password"
                    type="password"
                    placeholder={clientConfig?.login_tips?.show_first_deploy_tip
                      ? '请查看 admin_credentials.txt 文件获取密码'
                      : '请输入密码'}
                    error={errors.password?.message}
                    {...register('password')}
                  />
                </div>

                <Button type="submit" className="w-full" loading={isLoading} disabled={isLoading}>
                  {isLoading ? '登录中...' : '登录'}
                </Button>
              </form>
            ) : (
              <form onSubmit={onVerifyMfa} className="space-y-4">
                <p className="text-sm text-gray-600">
                  验证有效期至 {new Date(challenge.expires_at).toLocaleTimeString()}
                </p>
                <div>
                  <label htmlFor="mfa-code" className="block text-sm font-medium text-gray-700 mb-1">
                    {useRecoveryCode ? '恢复码' : '身份验证器验证码'}
                  </label>
                  <Input
                    id="mfa-code"
                    autoComplete="one-time-code"
                    inputMode={useRecoveryCode ? 'text' : 'numeric'}
                    value={verificationCode}
                    onChange={(event) => setVerificationCode(event.target.value)}
                    placeholder={useRecoveryCode ? '请输入一个未使用的恢复码' : '请输入6位验证码'}
                    maxLength={useRecoveryCode ? 64 : 6}
                    required
                  />
                </div>
                <button
                  type="button"
                  className="text-sm text-blue-600 hover:text-blue-700"
                  onClick={() => {
                    setUseRecoveryCode((current) => !current);
                    setVerificationCode('');
                    setError('');
                  }}
                >
                  {useRecoveryCode ? '使用身份验证器验证码' : '使用恢复码'}
                </button>
                <Button type="submit" className="w-full" loading={isLoading} disabled={isLoading || !verificationCode.trim()}>
                  {isLoading ? '验证中...' : '验证并登录'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="w-full gap-2"
                  disabled={isLoading}
                  onClick={() => {
                    setChallenge(null);
                    setCredentials(null);
                    setVerificationCode('');
                    setError('');
                  }}
                >
                  <ArrowLeft className="h-4 w-4" />
                  返回登录
                </Button>
              </form>
            )}

            {!challenge && clientConfig?.login_tips?.show_first_deploy_tip && (
              <div className="mt-4 p-3 bg-gray-50 rounded-md">
                <p className="text-xs text-gray-600 text-center">
                  💡 提示：首次登录后，请前往"设置"页面修改密码并启用双因素认证
                </p>
              </div>
            )}
          </CardContent>
        </Card>
        {showRebindRecoveryCodes && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
            <Card className="w-full max-w-md">
              <CardHeader><CardTitle>保存恢复码</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-gray-700">这些恢复码仅显示这一次。请先保存，再重新登录。</p>
                <div className="grid grid-cols-2 gap-2 rounded-md border bg-gray-50 p-3 text-sm font-mono">
                  {rebindRecoveryCodes.map((code) => <div key={code} className="break-all">{code}</div>)}
                </div>
                <div className="flex justify-end gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(rebindRecoveryCodes.join('\\n'));
                      } catch {
                        setError('无法访问剪贴板，请手动保存恢复码');
                      }
                    }}
                  >复制恢复码</Button>
                  <Button
                    type="button"
                    onClick={() => {
                      setShowRebindRecoveryCodes(false);
                      setRebindRecoveryCodes([]);
                      setNotice('身份验证器已重新绑定，请重新输入用户名和密码登录');
                    }}
                  >我已保存</Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
