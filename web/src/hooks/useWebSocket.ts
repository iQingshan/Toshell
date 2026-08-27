import { useEffect, useRef, useState, useCallback } from 'react'

export interface WSEvent {
  type: string
  payload: Record<string, unknown>
  time: number
}

interface UseWebSocketOptions {
  maxReconnect?: number
  reconnectDelay?: number
}

export function useWebSocket(
  url: string,
  onMessage: (event: WSEvent) => void,
  options: UseWebSocketOptions = {}
) {
  const { maxReconnect = 5, reconnectDelay = 3000 } = options

  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectCountRef = useRef(0)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const onMessageRef = useRef(onMessage)

  // Keep onMessage ref current without re-triggering effect
  onMessageRef.current = onMessage

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    reconnectCountRef.current = maxReconnect // prevent reconnection
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setConnected(false)
  }, [maxReconnect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(typeof data === 'string' ? data : JSON.stringify(data))
    }
  }, [])

  useEffect(() => {
    let destroyed = false
    reconnectCountRef.current = 0

    const connect = () => {
      if (destroyed || reconnectCountRef.current >= maxReconnect) return

      // Clean up previous connection
      if (wsRef.current) {
        wsRef.current.onopen = null
        wsRef.current.onclose = null
        wsRef.current.onmessage = null
        wsRef.current.onerror = null
        if (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING) {
          wsRef.current.close()
        }
        wsRef.current = null
      }

      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        if (destroyed) {
          ws.close()
          return
        }
        reconnectCountRef.current = 0
        setConnected(true)
      }

      ws.onmessage = (event: MessageEvent) => {
        if (destroyed) return
        try {
          const parsed = JSON.parse(event.data as string) as WSEvent
          onMessageRef.current(parsed)
        } catch {
          // ignore non-JSON messages
        }
      }

      ws.onclose = () => {
        if (destroyed) return
        setConnected(false)
        reconnectCountRef.current++
        if (reconnectCountRef.current < maxReconnect) {
          reconnectTimerRef.current = setTimeout(() => {
            if (!destroyed) {
              connect()
            }
          }, reconnectDelay)
        }
      }

      ws.onerror = () => {
        // onclose will fire after onerror, reconnect handled there
      }
    }

    connect()

    return () => {
      destroyed = true
      disconnect()
    }
  }, [url, maxReconnect, reconnectDelay, disconnect])

  return { connected, send, disconnect }
}
