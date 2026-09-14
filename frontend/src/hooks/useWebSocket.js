import { useState, useEffect, useRef, useCallback } from 'react'

// Derive WebSocket URL from the API URL env variable
// e.g. https://cloudguard-api.onrender.com → wss://cloudguard-api.onrender.com/ws/scan-updates
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS_URL = API_BASE.replace(/^http/, 'ws') + '/ws/scan-updates'

export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState(null)
  const [scanProgress, setScanProgress] = useState(null)
  const ws = useRef(null)
  const reconnectTimeout = useRef(null)

  const connect = useCallback(() => {
    try {
      ws.current = new WebSocket(WS_URL)

      ws.current.onopen = () => {
        setIsConnected(true)
        console.log('[WS] Connected to', WS_URL)
      }

      ws.current.onclose = () => {
        setIsConnected(false)
        console.log('[WS] Disconnected, reconnecting in 3s...')
        reconnectTimeout.current = setTimeout(connect, 3000)
      }

      ws.current.onerror = () => {
        setIsConnected(false)
      }

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          setLastMessage(data)

          if (data.type === 'scan_progress') {
            setScanProgress(data.data)
          } else if (data.type === 'scan_completed' || data.type === 'scan_failed') {
            setScanProgress(null)
          }
        } catch (e) {
          console.error('[WS] Failed to parse message:', e)
        }
      }
    } catch (e) {
      console.error('[WS] Connection error:', e)
      reconnectTimeout.current = setTimeout(connect, 3000)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (ws.current) ws.current.close()
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
    }
  }, [connect])

  return { isConnected, lastMessage, scanProgress }
}
