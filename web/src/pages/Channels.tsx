import { useState, useEffect, useCallback, useRef } from 'react'
import { RefreshCw, Radio, Globe, MessageSquare, Wifi, ArrowUpRight } from 'lucide-react'
import { channelsApi } from '../api'
import type { ChannelHealth } from '../api'
import './Channels.css'

const channelMeta: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  tcp: { label: 'TCP', icon: <Radio size={18} />, color: '#6366f1' },
  http: { label: 'HTTP', icon: <Globe size={18} />, color: '#f59e0b' },
  websocket: { label: 'WebSocket', icon: <MessageSquare size={18} />, color: '#22c55e' },
  mqtt: { label: 'MQTT', icon: <Wifi size={18} />, color: '#3b82f6' },
}

/** 通道健康仪表板：TCP/HTTP/WS/MQTT 四通道在线数 + 监听器状态 */
export function Channels() {
  const [channels, setChannels] = useState<ChannelHealth[]>([])
  const [totalOnline, setTotalOnline] = useState(0)
  const [totalSession, setTotalSession] = useState(0)
  const [loading, setLoading] = useState(true)
  const wsRef = useRef<WebSocket | null>(null)

  const fetchHealth = useCallback(async () => {
    try {
      const res = await channelsApi.health()
      setChannels(res.data?.channels || [])
      setTotalOnline(res.data?.total_online ?? 0)
      setTotalSession(res.data?.total_session ?? 0)
    } catch (e) {
      console.error('Failed to fetch channel health:', e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchHealth()
    // 实时刷新：订阅事件流，会话上线/下线即重拉
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        if (ev.type === 'session_online' || ev.type === 'session_offline') fetchHealth()
      } catch { /* ignore */ }
    }
    const interval = setInterval(fetchHealth, 5000)
    return () => {
      clearInterval(interval)
      ws?.close()
    }
  }, [fetchHealth])

  return (
    <div className="channels-page">
      <div className="channels-header">
        <div className="channels-title">
          <h1>通道健康</h1>
          <span className="channels-total">{totalOnline} 在线 · {totalSession} 总会话</span>
          <button className="channels-refresh" onClick={fetchHealth} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> 刷新
          </button>
        </div>
      </div>

      <div className="channels-grid">
        {channels.map((ch) => {
          const meta = channelMeta[ch.type] || { label: ch.type, icon: <Radio size={18} />, color: '#71717a' }
          return (
            <div key={ch.type} className={`channel-card ${ch.running ? 'running' : 'stopped'}`}>
              <div className="channel-head">
                <div className="channel-icon" style={{ background: `${meta.color}1f`, color: meta.color }}>
                  {meta.icon}
                </div>
                <span className="channel-type">{meta.label}</span>
                <span className={`channel-status ${ch.running ? 'ok' : 'off'}`}>
                  {ch.running ? '运行中' : '已停止'}
                </span>
              </div>
              <div className="channel-body">
                <div className="channel-online">{loading ? '—' : ch.online}</div>
                <div className="channel-label">在线会话</div>
              </div>
              <div className="channel-meta">
                <span>总会话 {ch.total_session}</span>
                <span>监听器 {ch.listeners}</span>
              </div>
            </div>
          )
        })}
        {loading && channels.length === 0 && (
          <div className="channels-empty"><RefreshCw size={18} className="spin" /> 加载中...</div>
        )}
      </div>

      <div className="channels-note">
        <ArrowUpRight size={14} />
        四通道在线数实时统计，停止/启动监听器即时反映。
      </div>
    </div>
  )
}
