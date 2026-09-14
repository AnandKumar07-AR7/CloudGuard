import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { getScanHistory } from '../api/client'

export default function ScanHistoryPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadHistory()
  }, [])

  const loadHistory = async () => {
    try {
      const res = await getScanHistory()
      setScans(res.data.scans)
    } catch (err) {
      // Demo data
      setScans([
        { id: 5, started_at: new Date(Date.now() - 1800000).toISOString(), completed_at: new Date().toISOString(), status: 'completed', total_findings: 18, critical_count: 3, high_count: 5, medium_count: 7, low_count: 3, scan_type: 'full' },
        { id: 4, started_at: new Date(Date.now() - 7200000).toISOString(), completed_at: new Date(Date.now() - 5400000).toISOString(), status: 'completed', total_findings: 20, critical_count: 4, high_count: 5, medium_count: 8, low_count: 3, scan_type: 'full' },
        { id: 3, started_at: new Date(Date.now() - 86400000).toISOString(), completed_at: new Date(Date.now() - 84600000).toISOString(), status: 'completed', total_findings: 22, critical_count: 5, high_count: 6, medium_count: 7, low_count: 4, scan_type: 'full' },
        { id: 2, started_at: new Date(Date.now() - 172800000).toISOString(), completed_at: new Date(Date.now() - 171000000).toISOString(), status: 'completed', total_findings: 24, critical_count: 6, high_count: 6, medium_count: 8, low_count: 4, scan_type: 'quick' },
        { id: 1, started_at: new Date(Date.now() - 259200000).toISOString(), completed_at: new Date(Date.now() - 257400000).toISOString(), status: 'completed', total_findings: 28, critical_count: 8, high_count: 7, medium_count: 9, low_count: 4, scan_type: 'full' },
      ])
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateStr) => {
    if (!dateStr) return '-'
    return new Date(dateStr).toLocaleString()
  }

  const getDuration = (start, end) => {
    if (!start || !end) return '-'
    const diff = Math.round((new Date(end) - new Date(start)) / 1000)
    if (diff < 60) return `${diff}s`
    return `${Math.floor(diff / 60)}m ${diff % 60}s`
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Scan History</h2>
          <p className="subtitle">Past security scan results</p>
        </div>
      </div>

      {loading ? (
        <div className="empty-state"><div className="spinner"></div></div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <div className="icon">📋</div>
          <h3>No scans yet</h3>
          <p>Run your first scan to see results here.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Type</th>
                  <th>Started</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Critical</th>
                  <th>High</th>
                  <th>Medium</th>
                  <th>Low</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan, i) => (
                  <motion.tr
                    key={scan.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.05 }}
                  >
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>#{scan.id}</td>
                    <td style={{ textTransform: 'capitalize', fontSize: '0.85rem' }}>{scan.scan_type}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{formatDate(scan.started_at)}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{getDuration(scan.started_at, scan.completed_at)}</td>
                    <td>
                      <span style={{
                        fontSize: '0.75rem',
                        padding: '2px 10px',
                        borderRadius: '12px',
                        fontWeight: 600,
                        background: scan.status === 'completed' ? 'var(--color-low-bg)' :
                                   scan.status === 'running' ? 'var(--color-medium-bg)' :
                                   scan.status === 'failed' ? 'var(--color-critical-bg)' : 'rgba(255,255,255,0.05)',
                        color: scan.status === 'completed' ? 'var(--color-low)' :
                              scan.status === 'running' ? 'var(--color-medium)' :
                              scan.status === 'failed' ? 'var(--color-critical)' : 'var(--text-muted)',
                      }}>
                        {scan.status}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700 }}>{scan.total_findings}</td>
                    <td style={{ color: 'var(--color-critical)', fontWeight: 600 }}>{scan.critical_count}</td>
                    <td style={{ color: 'var(--color-high)', fontWeight: 600 }}>{scan.high_count}</td>
                    <td style={{ color: 'var(--color-medium)', fontWeight: 600 }}>{scan.medium_count}</td>
                    <td style={{ color: 'var(--color-low)', fontWeight: 600 }}>{scan.low_count}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
