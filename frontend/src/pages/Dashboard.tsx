import { getErrorMessage } from '../lib/utils';
import { useEffect, useState, useMemo } from 'react';
import {
  Shield,
  Server,
  FileText,
  Users,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  RefreshCw,
  Play,
  Pause
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatsGrid } from '../components/dashboard/StatCard';
import { VulnerabilityTrendChart } from '../components/charts/VulnerabilityTrendChart';
import { SeverityDistributionChart, SeverityLegend } from '../components/charts/SeverityDistributionChart';
import { SeverityBadge } from '../components/ui/Badge';
import { Progress } from '../components/ui/Progress';
import { Skeleton, StatGridSkeleton, ChartSkeleton } from '../components/ui/Skeleton';
import { DashboardStats } from '../types/api';
import { analyticsService } from '../services/analytics';

// Utility function to calculate percentage change
const calculatePercentageChange = (current: number, previous: number): { value: number; trend: 'up' | 'down' | 'neutral' } => {
  if (previous === 0) {
    return { value: current > 0 ? 100 : 0, trend: current > 0 ? 'up' : 'neutral' as const };
  }

  const change = ((current - previous) / previous) * 100;
  return {
    value: Math.abs(change),
    trend: change > 0 ? 'up' : change < 0 ? 'down' : 'neutral'
  };
};



export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [isAutoRefresh, setIsAutoRefresh] = useState(true);

  const fetchStats = async (showLoading = true) => {
    try {
      if (showLoading) setLoading(true);
      const data = await analyticsService.getDashboardStats();



      setStats(data);
      setLastUpdated(new Date());
      setError('');
    } catch (err: unknown) {
      setError(getErrorMessage(err, '获取统计数据失败'));
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    if (!isAutoRefresh) return;

    const interval = setInterval(() => {
      fetchStats(false); // Don't show loading spinner for auto-refresh
    }, 60000); // 60 seconds

    return () => clearInterval(interval);
  }, [isAutoRefresh]);

  // Prepare stats data for enhanced components with real percentage calculations
  const statsData = useMemo(() => [
    {
      title: '总资产数',
      value: stats?.total_assets || 0,
      icon: Server,
      color: 'text-blue-600',
      description: '系统中管理的所有资产',
      ...(() => {
        if (stats?.asset_time_stats) {
          const change = calculatePercentageChange(stats.asset_time_stats.this_month, stats.asset_time_stats.last_month);
          return { trend: change.trend, trendValue: change.value };
        }
        return { trend: 'neutral' as const, trendValue: 0 };
      })(),
    },
    {
      title: '漏洞总数',
      value: stats?.total_vulnerabilities || 0,
      icon: Shield,
      color: 'text-red-600',
      description: '发现的安全漏洞总数',
      ...(() => {
        if (stats?.vulnerability_time_stats) {
          const change = calculatePercentageChange(stats.vulnerability_time_stats.this_month, stats.vulnerability_time_stats.last_month);
          return { trend: change.trend, trendValue: change.value };
        }
        return { trend: 'neutral' as const, trendValue: 0 };
      })(),
    },
    {
      title: '用户总数',
      value: stats?.total_users || 0,
      icon: Users,
      color: 'text-green-600',
      description: '系统注册用户数量',
      ...(() => {
        if (stats?.user_time_stats) {
          const change = calculatePercentageChange(stats.user_time_stats.this_month, stats.user_time_stats.last_month);
          return { trend: change.trend, trendValue: change.value };
        }
        return { trend: 'neutral' as const, trendValue: 0 };
      })(),
    },
    {
      title: '报告总数',
      value: stats?.total_reports || 0,
      icon: FileText,
      color: 'text-purple-600',
      description: '生成的安全报告数量',
      ...(() => {
        if (stats?.report_time_stats) {
          const change = calculatePercentageChange(stats.report_time_stats.this_month, stats.report_time_stats.last_month);
          return { trend: change.trend, trendValue: change.value };
        }
        return { trend: 'neutral' as const, trendValue: 0 };
      })(),
    },
  ], [stats]);

  if (loading) {
    return (
      <div className="space-y-8 animate-in fade-in-0 duration-500">
        <div className="space-y-2">
          <Skeleton className="h-8 w-32" />
          <Skeleton className="h-4 w-48" />
        </div>

        <StatGridSkeleton />

        <div className="grid gap-6 md:grid-cols-2">
          <ChartSkeleton />
          <ChartSkeleton />
        </div>

        <ChartSkeleton />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-8 animate-in fade-in-0 duration-500">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">仪表板</h1>
          <p className="mt-2 text-sm text-gray-600">系统概览和关键指标</p>
        </div>

        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3 text-red-600">
              <AlertTriangle className="h-5 w-5" />
              <div>
                <p className="font-medium">数据加载失败</p>
                <p className="text-sm text-red-500">{error}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in-0 duration-700">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <Activity className="h-8 w-8 text-blue-600" />
            仪表板
          </h1>
          <p className="text-gray-600">
            系统概览和关键指标 • 最后更新: {lastUpdated.toLocaleString('zh-CN')}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <div className={`w-2 h-2 rounded-full ${isAutoRefresh ? 'bg-green-500' : 'bg-gray-400'}`} />
            {isAutoRefresh ? '自动刷新已开启' : '自动刷新已暂停'}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchStats()}
            disabled={loading}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            刷新
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsAutoRefresh(!isAutoRefresh)}
            className="flex items-center gap-2"
          >
            {isAutoRefresh ? (
              <>
                <Pause className="h-4 w-4" />
                暂停
              </>
            ) : (
              <>
                <Play className="h-4 w-4" />
                开启
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Enhanced Stats Grid */}
      <StatsGrid stats={statsData} />

      {/* Severity Distribution */}
      {stats?.severity_stats && stats.severity_stats.length > 0 && (
        <div className="grid gap-6 md:grid-cols-2">
          {/* Severity Chart */}
          <Card className="animate-in slide-in-from-left-4 duration-500 delay-200">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
                漏洞严重程度分布
              </CardTitle>
            </CardHeader>
            <CardContent>
              <SeverityDistributionChart
                data={stats.severity_stats}
                height={250}
                variant="pie"
              />
              <div className="mt-4">
                <SeverityLegend data={stats.severity_stats} />
              </div>
            </CardContent>
          </Card>

          {/* Severity Summary Cards */}
          <Card className="animate-in slide-in-from-right-4 duration-500 delay-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-red-500" />
                严重程度概览
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {stats.severity_stats.map((item) => {
                  const total = stats.severity_stats.reduce((sum, s) => sum + s.count, 0);
                  const percentage = total > 0 ? (item.count / total) * 100 : 0;

                  return (
                    <div key={item.severity} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <SeverityBadge level={
                          item.severity === 'critical' ? 1 :
                          item.severity === 'high' ? 2 :
                          item.severity === 'medium' ? 3 : 4
                        } />
                        <span className="text-sm font-medium text-gray-900">
                          {item.count} ({percentage.toFixed(1)}%)
                        </span>
                      </div>
                      <Progress
                        value={percentage}
                        variant={
                          item.severity === 'critical' ? 'destructive' :
                          item.severity === 'high' ? 'warning' :
                          item.severity === 'medium' ? 'default' : 'success'
                        }
                        className="h-2"
                      />
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Vulnerability Trend Chart */}
      {stats?.recent_trends?.vulnerability_trend && (
        <Card className="animate-in slide-in-from-bottom-4 duration-500 delay-400">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              漏洞发现趋势
            </CardTitle>
            <p className="text-sm text-gray-600 mt-1">
              最近 {stats.recent_trends.vulnerability_trend.length} 天的漏洞发现情况
            </p>
          </CardHeader>
          <CardContent>
            <VulnerabilityTrendChart
              data={stats.recent_trends.vulnerability_trend}
              height={300}
              variant="area"
            />
          </CardContent>
        </Card>
      )}

      {/* Quick Actions & System Status */}
      <div className="grid gap-6 md:grid-cols-3">
        <Card className="animate-in slide-in-from-left-4 duration-500 delay-500">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              系统状态
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">API 服务</span>
                <span className="flex items-center gap-1 text-green-600 text-sm font-medium">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  正常
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">数据库</span>
                <span className="flex items-center gap-1 text-green-600 text-sm font-medium">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  正常
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">缓存服务</span>
                <span className="flex items-center gap-1 text-green-600 text-sm font-medium">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  正常
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="animate-in slide-in-from-bottom-4 duration-500 delay-600">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-blue-500" />
              最近活动
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3 text-sm">
              <div className="flex items-start gap-2">
                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                <div>
                  <p className="text-gray-900">新增漏洞报告</p>
                  <p className="text-gray-500 text-xs">2 分钟前</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <div className="w-2 h-2 bg-green-500 rounded-full mt-2"></div>
                <div>
                  <p className="text-gray-900">漏洞已修复</p>
                  <p className="text-gray-500 text-xs">15 分钟前</p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <div className="w-2 h-2 bg-orange-500 rounded-full mt-2"></div>
                <div>
                  <p className="text-gray-900">新用户注册</p>
                  <p className="text-gray-500 text-xs">1 小时前</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="animate-in slide-in-from-right-4 duration-500 delay-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-purple-500" />
              性能指标
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">CPU 使用率</span>
                  <span className="font-medium">23%</span>
                </div>
                <Progress value={23} variant="success" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">内存使用率</span>
                  <span className="font-medium">67%</span>
                </div>
                <Progress value={67} variant="warning" />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">磁盘使用率</span>
                  <span className="font-medium">45%</span>
                </div>
                <Progress value={45} variant="default" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
