import { useState, useEffect, useRef, type CSSProperties } from 'react'
import { MonitorPlay, Play, Square, ZoomIn, ZoomOut, Maximize, Minimize } from 'lucide-react'
import type { Session } from '../types'
import { sessionApi } from '../api'

interface ScreenStreamPanelProps {
  session: Session
}

interface StreamFrame {
  image: string
  format: string
}

export function ScreenStreamPanel({ session }: ScreenStreamPanelProps) {
  const [streaming, setStreaming] = useState(false)
  const [frame, setFrame] = useState<StreamFrame | null>(null)
  const [error, setError] = useState('')
  const [zoom, setZoom] = useState(1)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data as string)
        if (event.type === 'screen_frame' && event.payload?.session_id === session.id) {
          // 植入端回传的错误帧（无交互桌面/锁屏等）：展示提示而不是尝试渲染
          if (event.payload.error) {
            setError(String(event.payload.error))
            return
          }
          setFrame({ image: event.payload.image, format: event.payload.format || 'png' })
        }
      } catch {
        // ignore non-JSON / malformed frames
      }
    }
    const onFsChange = () => setIsFullscreen(!!document.fullscreenElement)
    document.addEventListener('fullscreenchange', onFsChange)
    return () => {
      ws.close()
      wsRef.current = null
      document.removeEventListener('fullscreenchange', onFsChange)
    }
  }, [session.id])

  const start = async () => {
    setError('')
    try {
      await sessionApi.screenStream(session.id, 'start')
      setStreaming(true)
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || '启动失败')
    }
  }

  const stop = async () => {
    try {
      await sessionApi.screenStream(session.id, 'stop')
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.message || '停止失败')
    } finally {
      setStreaming(false)
    }
  }

  const zoomIn = () => setZoom((z) => Math.min(z + 0.25, 4))
  const zoomOut = () => setZoom((z) => Math.max(z - 0.25, 0.5))
  const zoomReset = () => setZoom(1)

  const toggleFullscreen = () => {
    const el = stageRef.current
    if (!el) return
    if (document.fullscreenElement) {
      document.exitFullscreen()
    } else {
      el.requestFullscreen?.()
    }
  }

  const toolbarStyle: CSSProperties = { display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }
  const stageStyle: CSSProperties = {
    position: 'relative',
    overflow: 'auto',
    maxHeight: isFullscreen ? '100vh' : 560,
    background: '#0a0a10',
    border: '1px solid var(--border, #3a3a4a)',
    borderRadius: 6,
  }
  const imgStyle: CSSProperties = {
    display: 'block',
    width: `${zoom * 100}%`,
    maxWidth: zoom === 1 ? '100%' : 'none',
    height: 'auto',
  }
  const placeholderStyle: CSSProperties = {
    width: '100%',
    height: 320,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'var(--text-dim, #9a9aab)',
    background: 'var(--bg-deep, #12121a)',
    border: '1px dashed var(--border, #3a3a4a)',
    borderRadius: 6,
    fontSize: 13,
  }
  const iconBtn: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 5,
    padding: '6px 10px',
    borderRadius: 6,
    border: '1px solid var(--border, #3a3a4a)',
    background: 'var(--bg-elevated, #1e1e2a)',
    color: 'var(--text, #e5e5ea)',
    cursor: 'pointer',
    fontSize: 12,
  }

  return (
    <div>
      <div style={toolbarStyle}>
        <MonitorPlay size={18} color="#4f9cff" />
        <span style={{ fontWeight: 600 }}>实时屏幕流 — {session.hostname}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn-primary" onClick={start} disabled={streaming} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Play size={14} /> 开始
          </button>
          <button className="btn-small danger" onClick={stop} disabled={!streaming} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Square size={14} /> 停止
          </button>
        </div>
      </div>

      {frame && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <button style={iconBtn} onClick={zoomIn} title="放大"><ZoomIn size={14} /> 放大</button>
          <button style={iconBtn} onClick={zoomOut} title="缩小"><ZoomOut size={14} /> 缩小</button>
          <button style={iconBtn} onClick={zoomReset} title="适应窗口">适应</button>
          <button style={iconBtn} onClick={toggleFullscreen} title="全屏">
            {isFullscreen ? <Minimize size={14} /> : <Maximize size={14} />}
            {isFullscreen ? '退出全屏' : '全屏'}
          </button>
          <span style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>{Math.round(zoom * 100)}%</span>
        </div>
      )}

      {error && <p style={{ color: 'var(--danger, #ff6b6b)', fontSize: 12 }}>{error}</p>}

      {frame ? (
        <div ref={stageRef} style={stageStyle}>
          <img
            src={`data:image/${frame.format};base64,${frame.image}`}
            alt="screen stream"
            style={imgStyle}
          />
        </div>
      ) : (
        <div style={placeholderStyle}>
          {streaming ? '等待画面...' : '点击「开始」启动实时屏幕流（约 1.25 fps，Windows）'}
        </div>
      )}
    </div>
  )
}
