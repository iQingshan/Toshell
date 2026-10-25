import { useState, useEffect, useRef, type CSSProperties } from 'react'
import { MonitorPlay, Play, Square, ZoomIn, ZoomOut, Maximize, Minimize, Settings2 } from 'lucide-react'
import type { Session } from '../types'
import { sessionApi } from '../api'

interface ScreenStreamPanelProps {
  session: Session
  /**
   * 面板是否可见。详情面板切走后本组件**不会被卸载**（只 display:none），
   * 所以由这里主动停流：隐藏时停止服务端拉流（省带宽/编码），
   * 但 frame/zoom/params 都还在，切回来立刻还能看到最近一帧。
   * 缺省 true（其他调用方不传时行为不变）。
   */
  visible?: boolean
}

interface StreamFrame {
  image: string
  format: string
  width?: number
  height?: number
}

/** 屏幕流参数（服务端会校验并钳制；植入端按带宽预算自适应画质） */
interface StreamParams {
  fps: number
  quality: number
  max_kbps: number
  monitor: number
  max_width: number
}

const DEFAULT_PARAMS: StreamParams = { fps: 2, quality: 70, max_kbps: 0, monitor: 0, max_width: 0 }

/** 参数名标签样式：把接口字段名（fps/quality/...）显著标出，避免只看中文名不知对应字段 */
const paramKeyStyle: CSSProperties = {
  fontFamily: 'var(--font-mono, monospace)',
  fontSize: 11,
  padding: '1px 5px',
  borderRadius: 3,
  background: 'var(--bg-deep, #12121a)',
  border: '1px solid var(--border, #3a3a4a)',
  color: 'var(--text-dim, #9a9aab)',
}

export function ScreenStreamPanel({ session, visible = true }: ScreenStreamPanelProps) {
  const [streaming, setStreaming] = useState(false)
  const [frame, setFrame] = useState<StreamFrame | null>(null)
  const [error, setError] = useState('')
  const [zoom, setZoom] = useState(1)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [params, setParams] = useState<StreamParams>(DEFAULT_PARAMS)
  const [showParams, setShowParams] = useState(false)
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
          // 收到正常帧时清掉上一次的错误提示（例如锁屏后解锁）
          setError('')
          setFrame({
            image: event.payload.image,
            format: event.payload.format || 'png',
            width: event.payload.width,
            height: event.payload.height,
          })
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
      await sessionApi.screenStream(session.id, 'start', params)
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

  // 切到别的 tab（visible=false）就主动停流：服务端不再编码/推帧。
  // 组件没有卸载，最近一帧（frame）仍在，切回来立刻可见；要恢复实时看画面
  // 重新点"开始推流"即可（与旧行为一致——旧版切走会整个卸载）。
  useEffect(() => {
    if (!visible && streaming) void stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, streaming])

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
          <button style={iconBtn} onClick={() => setShowParams((v) => !v)} title="帧率/画质/带宽/显示器">
            <Settings2 size={14} /> 画质参数
          </button>
          <button className="btn-primary" onClick={start} disabled={streaming} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Play size={14} /> 开始
          </button>
          <button className="btn-small danger" onClick={stop} disabled={!streaming} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Square size={14} /> 停止
          </button>
        </div>
      </div>

      {showParams && (
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 12, padding: '10px 12px', border: '1px solid var(--border, #3a3a4a)', borderRadius: 6, background: 'var(--bg-elevated, #1e1e2a)', fontSize: 12 }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            帧率 <code style={paramKeyStyle}>fps</code> (1-10)
            <input type="number" min={1} max={10} value={params.fps}
              onChange={(e) => setParams((p) => ({ ...p, fps: Number(e.target.value) || 1 }))}
              style={{ width: 72, padding: '4px 6px' }} />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            JPEG 画质 <code style={paramKeyStyle}>quality</code> (20-95)
            <input type="number" min={20} max={95} value={params.quality}
              onChange={(e) => setParams((p) => ({ ...p, quality: Number(e.target.value) || 70 }))}
              style={{ width: 72, padding: '4px 6px' }} />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }} title="0 = 不限；超限时植入端自动降画质/降帧">
            带宽上限 <code style={paramKeyStyle}>max_kbps</code> (KB/s)
            <input type="number" min={0} value={params.max_kbps}
              onChange={(e) => setParams((p) => ({ ...p, max_kbps: Number(e.target.value) || 0 }))}
              style={{ width: 90, padding: '4px 6px' }} />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }} title="0 = 全部显示器拼接；N = 第 N 个显示器（1 通常是主显示器）">
            显示器 <code style={paramKeyStyle}>monitor</code> (0=全部)
            <input type="number" min={0} max={16} value={params.monitor}
              onChange={(e) => setParams((p) => ({ ...p, monitor: Number(e.target.value) || 0 }))}
              style={{ width: 72, padding: '4px 6px' }} />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }} title="0 = 原始分辨率；如 1280 可大幅降低带宽">
            缩放宽度 <code style={paramKeyStyle}>max_width</code> (0=原始)
            <input type="number" min={0} value={params.max_width}
              onChange={(e) => setParams((p) => ({ ...p, max_width: Number(e.target.value) || 0 }))}
              style={{ width: 90, padding: '4px 6px' }} />
          </label>
          <span style={{ color: 'var(--text-dim, #9a9aab)' }}>开始前设置；运行中修改需先停止再开始</span>
        </div>
      )}

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
          {frame.width && frame.height ? (
            <span style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>
              {frame.width}×{frame.height} {frame.format}
            </span>
          ) : null}
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
          {streaming ? '等待画面...' : '点击「开始」启动实时屏幕流（Windows；帧率/画质/带宽可在「画质参数」中设置）'}
        </div>
      )}
    </div>
  )
}
