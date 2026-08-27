import { useState, type CSSProperties } from 'react'
import { Share2, Play, Square, Info } from 'lucide-react'
import type { Session } from '../types'
import { sessionApi } from '../api'

interface RelayPanelProps {
  session: Session
}

/** 轮询任务结果，最多 60 秒 */
async function pollTaskResult(taskId: number): Promise<string> {
  const token = localStorage.getItem('toshell-token')
  const intervals = [0, 200, 300, 500, 1000, 2000]
  for (let i = 0; i < 60; i++) {
    try {
      const resp = await fetch(`/api/v1/tasks/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const task = await resp.json()
      if (task.status === 'completed') return task.output || '（无输出）'
      if (task.status === 'failed') return '失败: ' + (task.error || '任务执行失败')
    } catch {
      // ignore network errors during polling
    }
    await new Promise((r) => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
  }
  return '执行超时 (60s)'
}

export function RelayPanel({ session }: RelayPanelProps) {
  const [addr, setAddr] = useState('0.0.0.0:9999')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const isRelay = session.listener === 'relay'

  const run = async (action: 'start' | 'stop' | 'status', a?: string) => {
    setBusy(true)
    setMsg('')
    try {
      const resp = await sessionApi.relay(session.id, action, a)
      const taskId = resp.data?.task_id
      if (!taskId) {
        setMsg('未返回 task_id')
        return
      }
      setMsg(`任务已下发 (task_id=${taskId})，等待执行结果...`)
      const result = await pollTaskResult(taskId)
      setMsg(result)
    } catch (err: any) {
      setMsg('请求失败: ' + (err?.response?.data?.error || err?.message || String(err)))
    } finally {
      setBusy(false)
    }
  }

  const inputStyle: CSSProperties = {
    width: 220,
    padding: '8px 10px',
    borderRadius: 6,
    border: '1px solid var(--border, #3a3a4a)',
    background: 'var(--bg-elevated, #1e1e2a)',
    color: 'var(--text, #e5e5ea)',
    fontSize: 13,
  }
  const hintStyle: CSSProperties = { fontSize: 12, color: 'var(--text-dim, #9a9aab)', lineHeight: 1.8 }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <Share2 size={18} color="#8c5aff" />
        <span style={{ fontWeight: 600 }}>中继（Beacon Mesh）— {session.hostname}</span>
      </div>

      {isRelay && (
        <p style={{ fontSize: 12, color: '#b48cff', marginBottom: 8 }}>
          该会话本身经中继链回连（子节点）；若要把它作为中继转发其它会话，请选直连出口主机会话。
        </p>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13 }}>监听地址</span>
        <input
          type="text"
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          placeholder="0.0.0.0:9999"
          style={inputStyle}
        />
        <button className="btn-primary" onClick={() => run('start', addr.trim())} disabled={busy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Play size={14} /> 启动中继
        </button>
        <button className="btn-small danger" onClick={() => run('stop')} disabled={busy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Square size={14} /> 停止
        </button>
        <button className="btn-small" onClick={() => run('status')} disabled={busy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Info size={14} /> 状态
        </button>
      </div>

      {msg && (
        <pre style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)', background: 'var(--bg-deep, #12121a)', border: '1px solid var(--border, #3a3a4a)', borderRadius: 6, padding: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-all', marginBottom: 8 }}>
          {msg}
        </pre>
      )}

      <div style={{ background: 'var(--bg-deep, #12121a)', border: '1px solid var(--border, #3a3a4a)', borderRadius: 6, padding: 12 }}>
        <p style={{ ...hintStyle, marginBottom: 4, fontWeight: 600 }}>使用步骤</p>
        <p style={{ ...hintStyle, margin: 0 }}>
          ① 选一台<b>直连出口主机</b>的会话，填监听端口（如 9999），点「启动中继」，等结果提示「now listening」。<br />
          ② 到「载荷」页给内网主机构建载荷，把其「服务器地址」填为该中继主机的 <b>IP:9999</b>（例如 192.168.1.10:9999）。<br />
          ③ 内网主机运行载荷后，会话列表会出现带紫色「中继」徽标的会话，任务/Shell/隧道均经中继转发（支持多跳）。
        </p>
      </div>
    </div>
  )
}
