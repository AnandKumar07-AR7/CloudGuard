import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import Sidebar from './components/Layout/Sidebar'
import Header from './components/Layout/Header'
import DashboardPage from './pages/DashboardPage'
import FindingsPage from './pages/FindingsPage'
import ScanHistoryPage from './pages/ScanHistoryPage'
import SettingsPage from './pages/SettingsPage'
import { useWebSocket } from './hooks/useWebSocket'
import { triggerScan, getDashboardSummary } from './api/client'

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/findings': 'Security Findings',
  '/history': 'Scan History',
  '/settings': 'Settings',
}

function AppContent() {
  const location = useLocation()
  const { isConnected, lastMessage, scanProgress } = useWebSocket()
  const [isScanning, setIsScanning] = useState(false)
  const [criticalCount, setCriticalCount] = useState(0)

  useEffect(() => {
    // Load initial critical count
    getDashboardSummary()
      .then(res => setCriticalCount(res.data.severity_counts?.critical || 0))
      .catch(() => setCriticalCount(3)) // Demo fallback
  }, [])

  useEffect(() => {
    if (lastMessage) {
      if (lastMessage.type === 'scan_started') setIsScanning(true)
      if (lastMessage.type === 'scan_completed' || lastMessage.type === 'scan_failed') {
        setIsScanning(false)
        // Refresh critical count
        getDashboardSummary()
          .then(res => setCriticalCount(res.data.severity_counts?.critical || 0))
          .catch(() => {})
      }
    }
  }, [lastMessage])

  const handleScan = async () => {
    setIsScanning(true)
    try {
      await triggerScan('full')
    } catch (err) {
      if (err.response?.status === 409) {
        alert('A scan is already in progress.')
      } else {
        alert('Failed to start scan. Is the backend running?')
      }
      setIsScanning(false)
    }
  }

  const pageTitle = PAGE_TITLES[location.pathname] || 'CloudGuard'

  return (
    <div className="app-layout">
      <Sidebar isScanning={isScanning} criticalCount={criticalCount} />
      <Header
        title={pageTitle}
        isConnected={isConnected}
        onScan={handleScan}
        isScanning={isScanning}
      />
      <main className="main-content">
        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2 }}
          >
            <Routes location={location}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/history" element={<ScanHistoryPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  )
}
