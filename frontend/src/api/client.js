import axios from 'axios'

// Use env variable in production (set VITE_API_URL on Vercel)
// Falls back to localhost for local development
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// Dashboard
export const getDashboardSummary = () => api.get('/api/dashboard/summary')
export const getServiceBreakdown = () => api.get('/api/dashboard/services')
export const getRiskTrend = () => api.get('/api/dashboard/trend')

// Scans
export const triggerScan = (scanType = 'full') => api.post('/api/scans/trigger', { scan_type: scanType })
export const getScanHistory = (page = 1) => api.get(`/api/scans/history?page=${page}`)
export const getScanResults = (scanId) => api.get(`/api/scans/${scanId}/results`)

// Findings
export const getFindings = (params = {}) => {
  const query = new URLSearchParams()
  if (params.severity) query.set('severity', params.severity)
  if (params.service) query.set('service', params.service)
  if (params.status) query.set('status', params.status)
  if (params.search) query.set('search', params.search)
  if (params.page) query.set('page', params.page)
  return api.get(`/api/findings?${query.toString()}`)
}
export const getFinding = (id) => api.get(`/api/findings/${id}`)
export const analyzeFinding = (id, provider = 'gemini') => api.post(`/api/findings/${id}/analyze`, { provider })
export const updateFindingStatus = (id, status) => api.patch(`/api/findings/${id}/status?new_status=${status}`)

// Remediation
export const previewRemediation = (findingId) => api.get(`/api/remediation/${findingId}/preview`)
export const applyRemediation = (findingId) => api.post(`/api/remediation/${findingId}/fix`)
export const getRemediationLogs = (findingId) => api.get(`/api/remediation/${findingId}/logs`)

// Settings
export const getSettings = () => api.get('/api/settings')
export const testConnection = () => api.post('/api/settings/test-connection')
export const healthCheck = () => api.get('/api/settings/health')

export default api
