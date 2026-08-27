import { useState, useEffect, useRef } from 'react'
import { RefreshCw, Copy } from 'lucide-react'
import { sessionApi } from '../api'
import type { Session } from '../types'
import { getSessionState, updateSessionState } from '../stores/sessionState'

interface ProcInfo { pid: number; name: string; cpu: string; memory: string }

export function ProcessList({ session }: { session: Session }) {
  const [processes, setProcesses] = useState<ProcInfo[]>(() => getSessionState(session.id).processes || [])
  const [loading, setLoading] = useState(false)
  const loadedRef = useRef(false)
  const sidRef = useRef(session.id)

  useEffect(() => { if (sidRef.current !== session.id) { const st = getSessionState(session.id); setProcesses(st.processes || []); sidRef.current = session.id } }, [session.id])
  useEffect(() => { updateSessionState(session.id, { processes }) }, [processes, session.id])

  const pollTask = async (taskId: number): Promise<string | null> => {
    // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
    const intervals = [0, 200, 300, 500, 1000, 2000]
    for (let i = 0; i < 30; i++) {
      try { const r = await fetch(`/api/v1/tasks/${taskId}`, { headers: { Authorization: `Bearer ${localStorage.getItem('toshell-token')}` } }); const t = await r.json(); if (t.status === 'completed') return t.output; if (t.status === 'failed') return null } catch (e) {}
      await new Promise(r => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
    }
    return null
  }

  const parseList = (output: string): ProcInfo[] => {
    const result: ProcInfo[] = []
    for (const line of output.split('\n')) {
      const t = line.trim(); if (!t || t.startsWith('PID') || t.startsWith('---')) continue
      const m = t.match(/^(\d+)\s+(.+)$/); if (m) result.push({ pid: parseInt(m[1]) || 0, name: m[2].trim(), cpu: '-', memory: '-' })
    }
    return result
  }

  const fetchProcesses = async () => { setLoading(true); try { const r = await sessionApi.listProcesses(session.id); if (r?.data?.task_id) { const o = await pollTask(r.data.task_id); if (o) setProcesses(parseList(o)) } } catch (e) { console.error(e) } setLoading(false) }

  const killProcess = async (pid: number) => { if (!confirm(`确定终止进程 ${pid}?`)) return; try { const r = await sessionApi.killProcess(session.id, pid); if (r?.data?.task_id) { await pollTask(r.data.task_id); await fetchProcesses() } } catch (e) { console.error(e) } }

  const copyList = () => navigator.clipboard.writeText(processes.map(p => `${p.pid}\t${p.name}`).join('\n'))

  useEffect(() => { if (!loadedRef.current) { loadedRef.current = true; fetchProcesses() } }, [])

  return (
    <div className="process-tab">
      <div className="process-toolbar">
        <button className="btn-small" onClick={fetchProcesses} disabled={loading}><RefreshCw size={14} className={loading ? 'spin' : ''} /> 刷新</button>
        <button className="btn-small" onClick={copyList} disabled={processes.length === 0}><Copy size={14} /> 复制列表</button>
      </div>
      <div className="process-list">
        <table><thead><tr><th>PID</th><th>名称</th><th>操作</th></tr></thead>
          <tbody>
            {processes.map(p => (
              <tr key={p.pid}>
                <td className="mono">{p.pid}</td><td>{p.name}</td>
                <td><div className="process-actions"><button className="btn-small danger" onClick={() => killProcess(p.pid)}>终止</button></div></td>
              </tr>
            ))}
          </tbody></table>
        {processes.length === 0 && !loading && <div className="empty-state" style={{ padding: '20px' }}><p>无进程数据</p></div>}
      </div>
    </div>
  )
}
