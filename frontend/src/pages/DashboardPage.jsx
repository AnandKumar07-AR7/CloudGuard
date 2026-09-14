import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, Area, AreaChart } from 'recharts'
import { getDashboardSummary, getServiceBreakdown, getRiskTrend } from '../api/client'

const SEVERITY_COLORS = {
  critical: '#ff4757',
  high: '#ff6b35',
  medium: '#ffa502',
  low: '#2ed573',
}

function RiskGauge({ score }) {
  const radius = 75
  const circumference = 2 * Math.PI * radius
  const normalizedScore = Math.max(0, Math.min(100, score))
  const dashOffset = circumference - (normalizedScore / 100) * circumference

  const getColor = (s) => {
    if (s >= 80) return '#2ed573'
    if (s >= 60) return '#ffa502'
    if (s >= 30) return '#ff6b35'
    return '#ff4757'
  }

  return (
    <div className="risk-gauge">
      <div className="risk-gauge-ring">
        <svg width="180" height="180" viewBox="0 0 180 180">
          <circle className="ring-bg" cx="90" cy="90" r={radius} />
          <motion.circle
            className="ring-fill"
            cx="90"
            cy="90"
            r={radius}
            stroke={getColor(normalizedScore)}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: dashOffset }}
            transition={{ duration: 1.5, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 8px ${getColor(normalizedScore)}60)` }}
          />
        </svg>
        <div className="risk-gauge-value">
          <motion.span
            className="score"
            style={{ color: getColor(normalizedScore) }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            {Math.round(normalizedScore)}
          </motion.span>
          <span className="label">Security Score</span>
        </div>
      </div>
    </div>
  )
}

function SeverityCard({ severity, count, delay }) {
  return (
    <motion.div
      className={`card severity-card ${severity}`}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
    >
      <div className="severity-count">{count}</div>
      <div className="severity-label">{severity}</div>
    </motion.div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(12, 12, 36, 0.95)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '8px',
      padding: '10px 14px',
      fontSize: '0.8rem',
    }}>
      <p style={{ color: '#f0f0f8', fontWeight: 600 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export default function DashboardPage() {
  const [summary, setSummary] = useState(null)
  const [services, setServices] = useState([])
  const [trend, setTrend] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const [summaryRes, servicesRes, trendRes] = await Promise.all([
        getDashboardSummary(),
        getServiceBreakdown(),
        getRiskTrend(),
      ])
      setSummary(summaryRes.data)
      setServices(servicesRes.data)
      setTrend(trendRes.data)
    } catch (err) {
      console.error('Failed to load dashboard:', err)
      // Set demo data if API is not available
      setSummary({
        overall_risk_score: 67.5,
        total_findings: 23,
        open_findings: 18,
        remediated_findings: 5,
        severity_counts: { critical: 3, high: 5, medium: 7, low: 3 },
        services_affected: ['s3', 'iam', 'ec2', 'rds'],
        last_scan_at: new Date().toISOString(),
        is_scanning: false,
      })
      setServices([
        { service: 'S3', total: 8, critical: 2, high: 2, medium: 3, low: 1 },
        { service: 'IAM', total: 6, critical: 1, high: 2, medium: 2, low: 1 },
        { service: 'EC2', total: 5, critical: 0, high: 1, medium: 3, low: 1 },
        { service: 'RDS', total: 4, critical: 0, high: 0, medium: 2, low: 2 },
      ])
      setTrend([
        { date: 'Scan 1', risk_score: 45, total_findings: 28 },
        { date: 'Scan 2', risk_score: 52, total_findings: 24 },
        { date: 'Scan 3', risk_score: 58, total_findings: 22 },
        { date: 'Scan 4', risk_score: 63, total_findings: 20 },
        { date: 'Scan 5', risk_score: 67, total_findings: 18 },
      ])
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="empty-state">
        <div className="spinner"></div>
        <h3 style={{ marginTop: '16px' }}>Loading dashboard...</h3>
      </div>
    )
  }

  const pieData = summary ? [
    { name: 'Critical', value: summary.severity_counts.critical, color: SEVERITY_COLORS.critical },
    { name: 'High', value: summary.severity_counts.high, color: SEVERITY_COLORS.high },
    { name: 'Medium', value: summary.severity_counts.medium, color: SEVERITY_COLORS.medium },
    { name: 'Low', value: summary.severity_counts.low, color: SEVERITY_COLORS.low },
  ].filter(d => d.value > 0) : []

  return (
    <div className="dashboard-grid">
      {/* Top Row: Risk Gauge + Severity Cards */}
      <div className="top-row">
        <motion.div
          className="card"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
        >
          <RiskGauge score={summary?.overall_risk_score || 0} />
          <div style={{ textAlign: 'center', marginTop: '8px' }}>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              {summary?.open_findings || 0} open findings • {summary?.remediated_findings || 0} fixed
            </p>
          </div>
        </motion.div>

        <div>
          <div className="severity-cards">
            <SeverityCard severity="critical" count={summary?.severity_counts?.critical || 0} delay={0.1} />
            <SeverityCard severity="high" count={summary?.severity_counts?.high || 0} delay={0.2} />
            <SeverityCard severity="medium" count={summary?.severity_counts?.medium || 0} delay={0.3} />
            <SeverityCard severity="low" count={summary?.severity_counts?.low || 0} delay={0.4} />
          </div>

          {/* Stats row */}
          <motion.div
            className="card"
            style={{ marginTop: '16px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
          >
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--color-accent-light)' }}>
                {summary?.total_findings || 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Total Findings
              </div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--color-low)' }}>
                {summary?.remediated_findings || 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Remediated
              </div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                {summary?.services_affected?.length || 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Services
              </div>
            </div>
          </motion.div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        {/* Severity Distribution */}
        <motion.div
          className="card"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.6 }}
        >
          <div className="card-title">Severity Distribution</div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} style={{ filter: `drop-shadow(0 0 6px ${entry.color}50)` }} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: '40px' }}>
              <p>No findings to display</p>
            </div>
          )}
        </motion.div>

        {/* Service Breakdown */}
        <motion.div
          className="card"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.7 }}
        >
          <div className="card-title">Findings by Service</div>
          {services.length > 0 ? (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={services} layout="vertical">
                <XAxis type="number" tick={{ fill: '#5a5a7a', fontSize: 12 }} axisLine={false} />
                <YAxis type="category" dataKey="service" tick={{ fill: '#8888a8', fontSize: 12 }} width={60} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="critical" stackId="a" fill={SEVERITY_COLORS.critical} radius={[0, 0, 0, 0]} />
                <Bar dataKey="high" stackId="a" fill={SEVERITY_COLORS.high} />
                <Bar dataKey="medium" stackId="a" fill={SEVERITY_COLORS.medium} />
                <Bar dataKey="low" stackId="a" fill={SEVERITY_COLORS.low} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: '40px' }}>
              <p>No service data yet</p>
            </div>
          )}
        </motion.div>
      </div>

      {/* Trend Chart */}
      <div className="bottom-row">
        <motion.div
          className="card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <div className="card-title">Security Score Trend</div>
          {trend.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c5cff" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#7c5cff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#5a5a7a', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#5a5a7a', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="risk_score" name="Score" stroke="#7c5cff" fill="url(#scoreGradient)" strokeWidth={2} dot={{ fill: '#7c5cff', r: 4 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: '40px' }}>
              <p>Run a scan to see trend data</p>
            </div>
          )}
        </motion.div>
      </div>
    </div>
  )
}
