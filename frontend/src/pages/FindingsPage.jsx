import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { getFindings, getFinding, analyzeFinding, applyRemediation, updateFindingStatus } from '../api/client'

function RiskBadge({ severity }) {
  return (
    <span className={`risk-badge ${severity}`}>
      <span className="dot"></span>
      {severity}
    </span>
  )
}

function FindingDetail({ finding, onClose, onRemediate }) {
  const [analyzing, setAnalyzing] = useState(false)
  const [fixing, setFixing] = useState(false)
  const [analysis, setAnalysis] = useState(null)

  if (!finding) return null

  let remediationSteps = []
  try {
    if (finding.ai_remediation) {
      remediationSteps = JSON.parse(finding.ai_remediation)
    }
  } catch (e) {
    remediationSteps = [finding.ai_remediation]
  }

  const handleAnalyze = async (provider) => {
    setAnalyzing(true)
    try {
      const res = await analyzeFinding(finding.id, provider)
      setAnalysis(res.data)
    } catch (err) {
      console.error('Analysis failed:', err)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleFix = async () => {
    setFixing(true)
    try {
      await applyRemediation(finding.id)
      onRemediate(finding.id)
    } catch (err) {
      alert('Remediation failed: ' + (err.response?.data?.detail || err.message))
    } finally {
      setFixing(false)
    }
  }

  return (
    <motion.div
      className="finding-detail"
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
    >
      <div className="finding-detail-header">
        <div>
          <RiskBadge severity={finding.severity} />
          <h3 style={{ marginTop: '12px', fontSize: '1rem', fontWeight: 600 }}>{finding.title}</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {finding.service.toUpperCase()} • {finding.resource_id}
          </p>
        </div>
        <button className="btn btn-ghost" onClick={onClose} style={{ fontSize: '1.2rem' }}>✕</button>
      </div>

      <div className="finding-detail-body">
        {/* Risk Score */}
        <div className="finding-detail-section">
          <h3>Risk Score</h3>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
          }}>
            <div style={{
              fontSize: '2rem',
              fontWeight: 800,
              color: finding.risk_score >= 70 ? 'var(--color-critical)' :
                     finding.risk_score >= 40 ? 'var(--color-medium)' : 'var(--color-low)',
            }}>
              {Math.round(finding.risk_score)}
            </div>
            <div style={{
              flex: 1,
              height: '8px',
              background: 'rgba(255,255,255,0.05)',
              borderRadius: '4px',
              overflow: 'hidden',
            }}>
              <div style={{
                height: '100%',
                width: `${finding.risk_score}%`,
                background: finding.risk_score >= 70 ? 'var(--color-critical)' :
                           finding.risk_score >= 40 ? 'var(--color-medium)' : 'var(--color-low)',
                borderRadius: '4px',
                transition: 'width 0.5s ease',
              }} />
            </div>
          </div>
        </div>

        {/* AI Explanation */}
        <div className="finding-detail-section">
          <h3>AI Analysis</h3>
          <p>{analysis?.explanation || finding.ai_analysis || finding.description}</p>
        </div>

        {/* Impact */}
        {(analysis?.impact || finding.ai_impact) && (
          <div className="finding-detail-section">
            <h3>Impact</h3>
            <p>{analysis?.impact || finding.ai_impact}</p>
          </div>
        )}

        {/* Remediation Steps */}
        <div className="finding-detail-section">
          <h3>Remediation Steps</h3>
          <ul className="remediation-steps">
            {(analysis?.remediation_steps || remediationSteps).map((step, i) => (
              <li key={i}>
                <span className="step-number">{i + 1}</span>
                {step}
              </li>
            ))}
          </ul>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {finding.is_remediable && finding.status !== 'remediated' && (
            <button className="btn btn-fix" onClick={handleFix} disabled={fixing}>
              {fixing ? 'Applying...' : '🔧 One-Click Fix'}
            </button>
          )}

          <button className="btn btn-primary btn-sm" onClick={() => handleAnalyze('gemini')} disabled={analyzing}>
            {analyzing ? 'Analyzing...' : '✨ Gemini Analysis'}
          </button>

          <button className="btn btn-outline btn-sm" onClick={() => handleAnalyze('claude')} disabled={analyzing}>
            🧠 Deep Analysis (Claude)
          </button>

          {finding.status === 'open' && (
            <button className="btn btn-ghost btn-sm" onClick={() => {
              updateFindingStatus(finding.id, 'ignored')
              onClose()
            }}>
              Ignore
            </button>
          )}
        </div>
      </div>
    </motion.div>
  )
}

export default function FindingsPage() {
  const [findings, setFindings] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [filters, setFilters] = useState({ severity: '', service: '', status: 'open', search: '', page: 1 })

  useEffect(() => {
    loadFindings()
  }, [filters])

  const loadFindings = async () => {
    setLoading(true)
    try {
      const res = await getFindings(filters)
      setFindings(res.data.findings)
      setTotal(res.data.total)
    } catch (err) {
      console.error('Failed to load findings:', err)
      // Demo data
      setFindings([
        { id: 1, title: "S3 Bucket 'my-data' has no Public Access Block", severity: 'critical', service: 's3', resource_id: 'my-data-bucket', risk_score: 93, status: 'open', is_remediable: true, description: 'No public access block configured.', ai_analysis: 'This bucket is fully exposed to the internet.', ai_impact: 'Anyone can access your data.', ai_remediation: '["Enable Block Public Access","Verify settings"]', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
        { id: 2, title: "Root account does not have MFA enabled", severity: 'critical', service: 'iam', resource_id: 'root-account', risk_score: 98, status: 'open', is_remediable: false, description: 'Root account has no MFA.', ai_analysis: 'Your root account is the highest-privilege account.', ai_impact: 'Complete account takeover risk.', ai_remediation: '["Enable MFA on root account"]', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
        { id: 3, title: "Security Group 'sg-abc123' exposes SSH to internet", severity: 'critical', service: 'ec2', resource_id: 'sg-abc123', risk_score: 88, status: 'open', is_remediable: true, description: 'Port 22 open to 0.0.0.0/0', ai_analysis: 'SSH is accessible from anywhere.', ai_impact: 'Brute force attacks possible.', ai_remediation: '["Restrict SSH to specific IPs"]', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
        { id: 4, title: "IAM user 'developer' has access key older than 90 days", severity: 'medium', service: 'iam', resource_id: 'developer', risk_score: 45, status: 'open', is_remediable: true, description: 'Access key is 142 days old.', ai_analysis: 'Old access keys increase credential compromise risk.', ai_impact: 'Compromised key gives prolonged access.', ai_remediation: '["Rotate access key","Deactivate old key"]', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
        { id: 5, title: "S3 Bucket 'logs-bucket' versioning disabled", severity: 'low', service: 's3', resource_id: 'logs-bucket', risk_score: 15, status: 'open', is_remediable: true, description: 'No versioning enabled.', ai_analysis: 'Deleted objects cannot be recovered.', ai_impact: 'Accidental data loss risk.', ai_remediation: '["Enable versioning"]', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() },
      ])
      setTotal(5)
    } finally {
      setLoading(false)
    }
  }

  const handleRemediate = (findingId) => {
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: 'remediated' } : f))
    setSelectedFinding(null)
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Security Findings</h2>
          <p className="subtitle">{total} findings found</p>
        </div>
      </div>

      {/* Filters */}
      <div className="filters-bar" style={{ marginBottom: '24px' }}>
        <input
          className="filter-input"
          type="text"
          placeholder="🔍 Search findings..."
          value={filters.search}
          onChange={(e) => setFilters(f => ({ ...f, search: e.target.value, page: 1 }))}
          style={{ minWidth: '250px' }}
        />
        <select
          className="filter-select"
          value={filters.severity}
          onChange={(e) => setFilters(f => ({ ...f, severity: e.target.value, page: 1 }))}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          className="filter-select"
          value={filters.service}
          onChange={(e) => setFilters(f => ({ ...f, service: e.target.value, page: 1 }))}
        >
          <option value="">All Services</option>
          <option value="s3">S3</option>
          <option value="iam">IAM</option>
          <option value="ec2">EC2</option>
          <option value="rds">RDS</option>
          <option value="cloudtrail">CloudTrail</option>
          <option value="ebs">EBS</option>
          <option value="vpc">VPC</option>
        </select>
        <select
          className="filter-select"
          value={filters.status}
          onChange={(e) => setFilters(f => ({ ...f, status: e.target.value, page: 1 }))}
        >
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="remediated">Remediated</option>
          <option value="ignored">Ignored</option>
        </select>
      </div>

      {/* Findings Table */}
      {loading ? (
        <div className="empty-state"><div className="spinner"></div></div>
      ) : findings.length === 0 ? (
        <div className="empty-state">
          <div className="icon">🎉</div>
          <h3>No findings!</h3>
          <p>Your cloud is secure. Run a scan to check.</p>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Service</th>
                  <th>Resource</th>
                  <th>Risk Score</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding, i) => (
                  <motion.tr
                    key={finding.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    style={{ cursor: 'pointer' }}
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <td><RiskBadge severity={finding.severity} /></td>
                    <td style={{ maxWidth: '350px' }}>
                      <div style={{ fontWeight: 500, fontSize: '0.85rem' }}>{finding.title}</div>
                    </td>
                    <td style={{ textTransform: 'uppercase', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      {finding.service}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {finding.resource_id}
                    </td>
                    <td>
                      <span style={{
                        fontWeight: 700,
                        color: finding.risk_score >= 70 ? 'var(--color-critical)' :
                               finding.risk_score >= 40 ? 'var(--color-medium)' : 'var(--color-low)',
                      }}>
                        {Math.round(finding.risk_score)}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontSize: '0.75rem',
                        padding: '2px 8px',
                        borderRadius: '12px',
                        background: finding.status === 'remediated' ? 'var(--color-low-bg)' :
                                   finding.status === 'ignored' ? 'rgba(255,255,255,0.05)' : 'var(--color-critical-bg)',
                        color: finding.status === 'remediated' ? 'var(--color-low)' :
                              finding.status === 'ignored' ? 'var(--text-muted)' : 'var(--color-critical)',
                      }}>
                        {finding.status}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {finding.is_remediable && finding.status === 'open' && (
                        <button className="btn btn-fix btn-sm" onClick={() => setSelectedFinding(finding)}>
                          🔧 Fix
                        </button>
                      )}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Finding Detail Panel */}
      <AnimatePresence>
        {selectedFinding && (
          <>
            <motion.div
              style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 199 }}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedFinding(null)}
            />
            <FindingDetail
              finding={selectedFinding}
              onClose={() => setSelectedFinding(null)}
              onRemediate={handleRemediate}
            />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
