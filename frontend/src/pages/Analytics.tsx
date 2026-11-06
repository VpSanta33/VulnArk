import { getErrorMessage } from '../lib/utils';
import { useState, useEffect } from 'react';
import { Download, TrendingUp, Shield, Server, FileText, Users } from 'lucide-react';
import { Button } from '../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { analyticsService } from '../services/analytics';
import { DashboardStats } from '../types/api';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Area,
  AreaChart,
} from 'recharts';

interface StatCardProps {
  title: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  change?: number;
}

function StatCard({ title, value, icon: Icon, color, change }: StatCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className={`h-4 w-4 ${color}`} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value.toLocaleString()}</div>
        {change !== undefined && (
          <p className={`text-xs ${change >= 0 ? 'text-green-600' : 'text-red-600'} flex items-center mt-1`}>
            <TrendingUp className="h-3 w-3 mr-1" />
            {change >= 0 ? '+' : ''}{change}% 较上月
          </p>
        )}
      </CardContent>
    </Card>
  );
}

// Consistent severity colors matching the dashboard and vulnerability management
const SEVERITY_COLORS = {
  'critical': '#ef4444', // 严重 - 红色
  'high': '#f97316',     // 高危 - 橙色
  'medium': '#eab308',   // 中危 - 黄色
  'low': '#3b82f6',      // 低危 - 蓝色
};



export function Analytics() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [monthlyTrends, setMonthlyTrends] = useState<Array<{
    month: string;
    vulnerabilities: number;
    resolved: number;
  }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const [statsData, trendsData] = await Promise.all([
        analyticsService.getDashboardStats(),
        analyticsService.getMonthlyVulnerabilityTrends()
      ]);
      setStats(statsData);
      setMonthlyTrends(trendsData);
    } catch (err: unknown) {
      setError(getErrorMessage(err, '获取分析数据失败'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const handleExport = async () => {
    try {
      await analyticsService.exportData({
        type: 'dashboard',
        format: 'csv',
      });
    } catch (err: unknown) {
      alert(getErrorMessage(err, '导出数据失败'));
    }
  };

  // Prepare chart data
  const severityData = stats?.severity_stats?.map((item) => {
    // Map severity strings to Chinese labels
    const severityMap: { [key: string]: string } = {
      'critical': '严重',
      'high': '高危',
      'medium': '中危',
      'low': '低危'
    };

    return {
      name: severityMap[item.severity] || item.severity,
      value: item.count,
      color: SEVERITY_COLORS[item.severity as string as keyof typeof SEVERITY_COLORS] || '#6b7280',
    };
  }) || [];

  const trendData = stats?.recent_trends?.vulnerability_trend?.slice(-7).map(item => ({
    date: new Date(item.date).toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' }),
    vulnerabilities: item.count,
  })) || [];

  // Real asset type data from backend
  const assetTypeData = stats?.asset_type_stats?.map((item, index) => {
    const colors = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#f97316'];
    return {
      name: item.type || '未知类型',
      value: item.count,
      color: colors[index % colors.length],
    };
  }) || [];

  // Use real monthly trend data from backend
  const monthlyTrendData = monthlyTrends;

  // Calculate real percentage changes based on time range statistics
  const calculatePercentageChange = (current: number, previous: number): number => {
    if (previous === 0) return current > 0 ? 100 : 0;
    return Math.round(((current - previous) / previous) * 100);
  };

  const assetChange = stats?.asset_time_stats ?
    calculatePercentageChange(stats.asset_time_stats.this_month, stats.asset_time_stats.last_month) : 0;

  const vulnerabilityChange = stats?.vulnerability_time_stats ?
    calculatePercentageChange(stats.vulnerability_time_stats.this_month, stats.vulnerability_time_stats.last_month) : 0;

  const reportChange = stats?.report_time_stats ?
    calculatePercentageChange(stats.report_time_stats.this_month, stats.report_time_stats.last_month) : 0;

  const userChange = stats?.user_time_stats ?
    calculatePercentageChange(stats.user_time_stats.this_month, stats.user_time_stats.last_month) : 0;

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-gray-900">统计分析</h1>
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
          <h1 className="text-3xl font-bold text-gray-900">统计分析</h1>
          <p className="mt-2 text-sm text-gray-600">全量指标与分布；近期趋势为最近7天，月度对比为最近6个月。</p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" onClick={handleExport}>
            <Download className="h-4 w-4 mr-2" />
            导出全量CSV
          </Button>
        </div>
      </div>

      {error && (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center text-red-600">
              <p>{error}</p>
              <Button variant="outline" onClick={fetchAnalytics} className="mt-2">
                重试
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="总资产数"
          value={stats?.total_assets || 0}
          icon={Server}
          color="text-blue-600"
          change={assetChange}
        />
        <StatCard
          title="总漏洞数"
          value={stats?.total_vulnerabilities || 0}
          icon={Shield}
          color="text-red-600"
          change={vulnerabilityChange}
        />
        <StatCard
          title="总报告数"
          value={stats?.total_reports || 0}
          icon={FileText}
          color="text-green-600"
          change={reportChange}
        />
        <StatCard
          title="总用户数"
          value={stats?.total_users || 0}
          icon={Users}
          color="text-purple-600"
          change={userChange}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Vulnerability Severity Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>漏洞严重程度分布</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${((percent || 0) * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Asset Type Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>资产类型分布</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={assetTypeData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Trend Charts */}
      <div className="grid gap-6 md:grid-cols-1 lg:grid-cols-2">
        {/* Recent Vulnerability Trend */}
        <Card>
          <CardHeader>
            <CardTitle>近期漏洞趋势（最近7天）</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="vulnerabilities"
                  stroke="#ef4444"
                  fill="#ef4444"
                  fillOpacity={0.3}
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Monthly Comparison */}
        <Card>
          <CardHeader>
            <CardTitle>月度漏洞处理对比（最近6个月）</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={monthlyTrendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="vulnerabilities"
                  stroke="#ef4444"
                  strokeWidth={2}
                  name="发现漏洞"
                />
                <Line
                  type="monotone"
                  dataKey="resolved"
                  stroke="#10b981"
                  strokeWidth={2}
                  name="已解决"
                />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Summary Table */}
      <Card>
        <CardHeader>
          <CardTitle>关键指标汇总</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {severityData.find(s => s.name === '严重')?.value || 0}
              </div>
              <div className="text-sm text-red-600">严重漏洞</div>
            </div>
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">
                {monthlyTrendData[monthlyTrendData.length - 1]?.resolved || 0}
              </div>
              <div className="text-sm text-green-600">本月已解决</div>
            </div>
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {stats?.total_assets || 0}
              </div>
              <div className="text-sm text-blue-600">受保护资产</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
