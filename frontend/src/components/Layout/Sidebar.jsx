import { NavLink, useLocation } from 'react-router-dom'

export default function Sidebar({ isScanning, criticalCount }) {
  const location = useLocation()

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <h1>CloudGuard</h1>
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">📊</span>
          Dashboard
        </NavLink>

        <NavLink to="/findings" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">🔍</span>
          Findings
          {criticalCount > 0 && <span className="nav-badge">{criticalCount}</span>}
        </NavLink>

        <NavLink to="/history" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">📋</span>
          Scan History
        </NavLink>

        <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
          <span className="nav-icon">⚙️</span>
          Settings
        </NavLink>
      </nav>

      <div className="sidebar-status">
        <span className={`status-dot ${isScanning ? 'scanning' : 'online'}`}></span>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          {isScanning ? 'Scanning...' : 'Monitoring Active'}
        </span>
      </div>
    </aside>
  )
}
