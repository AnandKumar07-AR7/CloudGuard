export default function Header({ title, isConnected, onScan, isScanning }) {
  return (
    <header className="header">
      <div>
        <h2 className="header-title">{title}</h2>
      </div>

      <div className="header-actions">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <span className={`status-dot ${isConnected ? 'online' : 'offline'}`} style={{ animation: isConnected ? 'pulse 2s infinite' : 'none' }}></span>
          {isConnected ? 'Live' : 'Offline'}
        </div>

        <button
          className="btn btn-primary"
          onClick={onScan}
          disabled={isScanning}
        >
          {isScanning ? (
            <>
              <span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }}></span>
              Scanning...
            </>
          ) : (
            <>🔍 Run Scan</>
          )}
        </button>
      </div>
    </header>
  )
}
