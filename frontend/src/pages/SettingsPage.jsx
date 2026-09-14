import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { getSettings, testConnection } from '../api/client'

export default function SettingsPage() {
  const [settings, setSettings] = useState(null)
  const [connectionResult, setConnectionResult] = useState(null)
  const [testing, setTesting] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const res = await getSettings()
      setSettings(res.data)
    } catch (err) {
      setSettings({
        aws_configured: false,
        aws_region: 'us-east-1',
        gemini_configured: false,
        claude_configured: false,
        scan_interval_minutes: 30,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleTestConnection = async () => {
    setTesting(true)
    try {
      const res = await testConnection()
      setConnectionResult(res.data)
    } catch (err) {
      setConnectionResult({
        connected: false,
        message: 'Failed to test connection. Is the backend running?',
      })
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <div className="empty-state"><div className="spinner"></div></div>
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Settings</h2>
          <p className="subtitle">Configure AWS credentials and API keys</p>
        </div>
      </div>

      <div style={{ display: 'grid', gap: '24px', maxWidth: '700px' }}>
        {/* AWS Configuration */}
        <motion.div
          className="card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="card-title">AWS Configuration</div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <span className={`status-dot ${settings?.aws_configured ? 'online' : 'offline'}`} 
              style={{ animation: 'none' }}></span>
            <span style={{ fontSize: '0.9rem' }}>
              {settings?.aws_configured ? 'AWS credentials configured' : 'AWS credentials not configured'}
            </span>
          </div>

          <div className="settings-form">
            <div className="form-group">
              <label>Region</label>
              <input type="text" value={settings?.aws_region || 'us-east-1'} readOnly />
              <span className="help-text">Set via AWS_DEFAULT_REGION in backend .env file</span>
            </div>

            <div style={{ 
              padding: '16px', 
              background: 'rgba(124, 92, 255, 0.08)', 
              borderRadius: '10px', 
              border: '1px solid rgba(124, 92, 255, 0.15)' 
            }}>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                <strong style={{ color: 'var(--color-accent-light)' }}>ℹ️ How to configure:</strong><br />
                1. Copy <code style={{ color: 'var(--color-accent-light)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>.env.example</code> to <code style={{ color: 'var(--color-accent-light)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>.env</code> in the backend directory<br />
                2. Set your <code style={{ color: 'var(--color-accent-light)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>AWS_ACCESS_KEY_ID</code> and <code style={{ color: 'var(--color-accent-light)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>AWS_SECRET_ACCESS_KEY</code><br />
                3. Restart the backend server
              </p>
            </div>

            <button className="btn btn-primary" onClick={handleTestConnection} disabled={testing}>
              {testing ? 'Testing...' : '🔌 Test Connection'}
            </button>

            {connectionResult && (
              <div className={`connection-status ${connectionResult.connected ? 'connected' : 'disconnected'}`}>
                {connectionResult.connected ? '✅' : '❌'} {connectionResult.message}
                {connectionResult.account_id && (
                  <span style={{ marginLeft: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    Account: {connectionResult.account_id}
                  </span>
                )}
              </div>
            )}
          </div>
        </motion.div>

        {/* AI Configuration */}
        <motion.div
          className="card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <div className="card-title">AI Configuration</div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className={`status-dot ${settings?.gemini_configured ? 'online' : 'offline'}`}
                style={{ animation: 'none' }}></span>
              <span style={{ fontSize: '0.9rem' }}>
                Google Gemini: {settings?.gemini_configured ? 'Configured ✨' : 'Not configured'}
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className={`status-dot ${settings?.claude_configured ? 'online' : 'offline'}`}
                style={{ animation: 'none' }}></span>
              <span style={{ fontSize: '0.9rem' }}>
                Anthropic Claude: {settings?.claude_configured ? 'Configured 🧠' : 'Not configured'}
              </span>
            </div>

            <div style={{ 
              padding: '16px', 
              background: 'rgba(255, 165, 2, 0.08)', 
              borderRadius: '10px', 
              border: '1px solid rgba(255, 165, 2, 0.15)',
              fontSize: '0.85rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.7,
            }}>
              <strong style={{ color: 'var(--color-medium)' }}>💡 Note:</strong> Set <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>GEMINI_API_KEY</code> and <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>ANTHROPIC_API_KEY</code> in the backend <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>.env</code> file. At least one is required for AI analysis. Gemini Flash is used for bulk analysis, Claude for deep dives.
            </div>
          </div>
        </motion.div>

        {/* Scan Settings */}
        <motion.div
          className="card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="card-title">Scan Settings</div>

          <div className="settings-form">
            <div className="form-group">
              <label>Scan Interval</label>
              <input type="text" value={`${settings?.scan_interval_minutes || 30} minutes`} readOnly />
              <span className="help-text">Set via SCAN_INTERVAL_MINUTES in .env</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
