import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';

interface SeverityData {
  severity: number | string;
  count: number;
}

interface SeverityDistributionChartProps {
  data: SeverityData[];
  height?: number;
  variant?: 'pie' | 'bar';
}

const SEVERITY_COLORS = {
  1: '#ef4444', // 严重 - 红色 (Critical=red)
  2: '#f97316', // 高危 - 橙色 (High=orange)
  3: '#eab308', // 中危 - 黄色 (Medium=yellow)
  4: '#3b82f6', // 低危 - 蓝色 (Low=blue)
};

const SEVERITY_LABELS = {
  1: '严重',
  2: '高危',
  3: '中危',
  4: '低危',
};

// Map string severity values to numbers
const SEVERITY_STRING_TO_NUMBER = {
  'critical': 1,
  'high': 2,
  'medium': 3,
  'low': 4,
};

export function SeverityDistributionChart({ 
  data, 
  height = 300, 
  variant = 'pie' 
}: SeverityDistributionChartProps) {
  // Format data for better display
  const formattedData = data.map(item => {
    // Convert string severity to number if needed
    const severityNum = typeof item.severity === 'string'
      ? SEVERITY_STRING_TO_NUMBER[item.severity as keyof typeof SEVERITY_STRING_TO_NUMBER] || 1
      : item.severity;

    return {
      ...item,
      severity: severityNum,
      name: SEVERITY_LABELS[severityNum as keyof typeof SEVERITY_LABELS] || `级别 ${severityNum}`,
      color: SEVERITY_COLORS[severityNum as keyof typeof SEVERITY_COLORS] || '#6b7280',
    };
  });

  const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: Array<{ payload: { name: string; color: string; count: number } }> }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      const total = formattedData.reduce((sum, item) => sum + item.count, 0);
      return (
        <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
          <p className="text-sm font-medium text-gray-900">{data.name}</p>
          <p className="text-sm" style={{ color: data.color }}>
            {`数量: ${data.count}`}
          </p>
          <p className="text-xs text-gray-500">
            {`占比: ${((data.count / total) * 100).toFixed(1)}%`}
          </p>
        </div>
      );
    }
    return null;
  };

  if (variant === 'pie') {
    return (
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={formattedData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={2}
            dataKey="count"
          >
            {formattedData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
        </PieChart>
      </ResponsiveContainer>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={formattedData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
        <XAxis 
          dataKey="name" 
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 12, fill: '#64748b' }}
        />
        <YAxis 
          axisLine={false}
          tickLine={false}
          tick={{ fontSize: 12, fill: '#64748b' }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {formattedData.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// Legend component for the charts
export function SeverityLegend({ data }: { data: SeverityData[] }) {
  const formattedData = data.map(item => {
    const severityNum = typeof item.severity === 'string'
      ? SEVERITY_STRING_TO_NUMBER[item.severity as keyof typeof SEVERITY_STRING_TO_NUMBER] || 1
      : item.severity;

    return {
      ...item,
      name: SEVERITY_LABELS[severityNum as keyof typeof SEVERITY_LABELS] || `级别 ${severityNum}`,
      color: SEVERITY_COLORS[severityNum as keyof typeof SEVERITY_COLORS] || '#6b7280',
    };
  });

  const total = formattedData.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="flex flex-wrap gap-4 justify-center">
      {formattedData.map((item, index) => (
        <div key={index} className="flex items-center gap-2">
          <div 
            className="w-3 h-3 rounded-full" 
            style={{ backgroundColor: item.color }}
          />
          <span className="text-sm text-gray-900 font-medium">
            {item.name}: {item.count} ({((item.count / total) * 100).toFixed(1)}%)
          </span>
        </div>
      ))}
    </div>
  );
}
