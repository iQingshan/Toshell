import { useState, useEffect, useRef, useCallback } from 'react'
import {
  RefreshCw, Eye, Download, Upload, X, Folder, File, Home, ChevronRight,
} from 'lucide-react'
import { sessionApi } from '../api'
import './ShellFileBrowser.css'

interface FileItem { name: string; size: number; isDir: boolean; modTime: string }

interface FileNode {
  name: string
  path: string
  isDir: boolean
  size: number
  modTime: string
}

// ============ utility ============

function formatSize(bytes: number): string {
  if (bytes <= 0) return '-'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function getBreadcrumbs(path: string, isWindows: boolean): { name: string; path: string }[] {
  if (!path) return [{ name: '/', path: '/' }]
  // Windows 根目录（"\"）→ 显示"此电脑"（列出所有盘符）
  if (isWindows && (path === '\\' || path === '/')) return [{ name: '此电脑', path: '\\' }]
  if (path === (isWindows ? 'C:\\' : '/')) return [{ name: path, path }]
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean)
  if (isWindows) {
    const root = parts[0] + '\\'
    const crumbs = [{ name: root, path: root }]
    let cur = root
    for (let i = 1; i < parts.length; i++) {
      cur += (cur.endsWith('\\') ? '' : '\\') + parts[i]
      crumbs.push({ name: parts[i], path: cur + '\\' })
    }
    return crumbs
  }
  const crumbs: { name: string; path: string }[] = [{ name: '/', path: '/' }]
  let cur = ''
  for (const p of parts) {
    cur += '/' + p
    crumbs.push({ name: p, path: cur })
  }
  return crumbs
}

function joinPath(base: string, name: string, isWindows: boolean): string {
  // Windows 盘符节点（如 C:）进入其根目录 C:\
  if (isWindows && /^[A-Za-z]:$/.test(name)) return name + '\\'
  const s = isWindows ? '\\' : '/'
  return base + (base.endsWith('\\') || base.endsWith('/') ? '' : s) + name
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result as string
      resolve(result.includes(',') ? result.split(',')[1] : result)
    }
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(blob)
  })
}

// ============ ShellFileBrowser ============

export interface ShellFileBrowserProps {
  sessionId: string
  isWindows: boolean
  /** 当前目录（由交互式 shell 的 CWD 驱动） */
  currentPath: string
  /** 用户导航到某目录（父组件据此向终端注入 cd 命令并更新 CWD） */
  onNavigate: (path: string) => void
}

export function ShellFileBrowser({ sessionId, isWindows, currentPath, onNavigate }: ShellFileBrowserProps) {
  const [items, setItems] = useState<FileNode[]>([])
  const [loading, setLoading] = useState(false)
  const [previewContent, setPreviewContent] = useState<string | null>(null)
  const [previewName, setPreviewName] = useState('')
  const [previewSize, setPreviewSize] = useState(0)
  const [previewTruncated, setPreviewTruncated] = useState(false)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<{ sent: number; total: number; pushing: boolean } | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const pathRef = useRef(currentPath)

  // ----- 面板宽度（可拖拽调整，localStorage 记忆） -----
  const [panelWidth, setPanelWidth] = useState(() => {
    const saved = localStorage.getItem('toshell-sfb-panel-width')
    const w = saved ? parseInt(saved, 10) : 264
    return isNaN(w) ? 264 : Math.min(520, Math.max(200, w))
  })
  const panelWidthRef = useRef(panelWidth)
  const dragRef = useRef<{ startX: number; startW: number } | null>(null)
  useEffect(() => { panelWidthRef.current = panelWidth }, [panelWidth])

  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    dragRef.current = { startX: e.clientX, startW: panelWidthRef.current }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    const onMove = (ev: MouseEvent) => {
      if (!dragRef.current) return
      const w = Math.min(520, Math.max(200, dragRef.current.startW + (ev.clientX - dragRef.current.startX)))
      setPanelWidth(w)
    }
    const onUp = () => {
      dragRef.current = null
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      localStorage.setItem('toshell-sfb-panel-width', String(panelWidthRef.current))
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }, [])

  useEffect(() => { pathRef.current = currentPath }, [currentPath])

  // ----- poll / parse -----

  const pollTask = useCallback(async (taskId: number, maxAttempts = 30): Promise<{ output: string; error: string }> => {
    // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
    const intervals = [0, 200, 300, 500, 1000, 2000]
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const r = await fetch(`/api/v1/tasks/${taskId}`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('toshell-token')}` }
        })
        const t = await r.json()
        if (t.status === 'completed' || t.status === 'failed') {
          return { output: t.output || '', error: t.error || '' }
        }
      } catch { /* retry */ }
      await new Promise(r => setTimeout(r, intervals[Math.min(i, intervals.length - 1)]))
    }
    return { output: '', error: '超时' }
  }, [])

  const parseDir = useCallback((output: string): FileItem[] => {
    const dirs: FileItem[] = [], fls: FileItem[] = []
    for (const line of output.split('\n')) {
      const m = line.trim().match(/^([d\-])\s+(\d+)\s+(.+)$/)
      if (m) {
        const item: FileItem = {
          name: m[3].trim(),
          size: parseInt(m[2]) || 0,
          isDir: m[1] === 'd',
          modTime: '-'
        }
        if (item.isDir) dirs.push(item)
        else fls.push(item)
      }
    }
    const byZh = (a: FileItem, b: FileItem) => a.name.localeCompare(b.name, 'zh-CN', { numeric: true })
    return [...dirs.sort(byZh), ...fls.sort(byZh)]
  }, [])

  const loadPath = useCallback(async (path: string): Promise<FileItem[]> => {
    try {
      const r = await sessionApi.listFiles(sessionId, path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id)
        if (p?.output) return parseDir(p.output)
      }
    } catch (e) { console.error(e) }
    return []
  }, [sessionId, pollTask, parseDir])

  // ----- load current dir -----

  const loadCurrent = useCallback(async (path: string) => {
    setLoading(true)
    setPreviewContent(null)
    const list = await loadPath(path)
    setItems(list.map(item => ({
      name: item.name,
      path: joinPath(path, item.name, isWindows),
      isDir: item.isDir,
      size: item.size,
      modTime: item.modTime,
    })))
    setLoading(false)
  }, [loadPath, isWindows])

  // 跟随 shell CWD（currentPath）刷新
  const loadedRef = useRef<string>('')
  useEffect(() => {
    if (loadedRef.current === currentPath) return
    loadedRef.current = currentPath
    loadCurrent(currentPath)
  }, [currentPath, loadCurrent])

  // 手动刷新
  const handleRefresh = () => loadCurrent(currentPath)

  // ----- navigate -----

  const handleEnterDir = (node: FileNode) => {
    if (node.isDir) onNavigate(node.path)
  }

  // ----- preview / download / delete -----

  const previewFile = useCallback(async (node: FileNode) => {
    if (node.isDir) return
    setPreviewLoading(true)
    setPreviewName(node.name)
    try {
      const r = await sessionApi.downloadFile(sessionId, node.path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id, 600)
        if (p?.error) { alert('预览失败: ' + p.error); return }
        if (p?.output) {
          if (p.output.trim().startsWith('{') && p.output.includes('transfer_id')) {
            setPreviewContent('[文件较大,已转服务端存储,请使用「下载」查看]')
            return
          }
          try {
            const bs = atob(p.output)
            setPreviewSize(bs.length)
            let bin = 0
            for (let i = 0; i < Math.min(bs.length, 2048); i++) {
              const c = bs.charCodeAt(i)
              if (c === 0 || (c < 9 && c !== 10 && c !== 13)) bin++
            }
            if (bin > Math.min(bs.length, 2048) * 0.1) {
              setPreviewContent('[二进制文件，无法预览]')
              return
            }
            const pl = Math.min(bs.length, 100 * 1024)
            const bytes = new Uint8Array(pl)
            for (let i = 0; i < pl; i++) bytes[i] = bs.charCodeAt(i)
            setPreviewContent(new TextDecoder().decode(bytes))
            setPreviewTruncated(bs.length > 100 * 1024)
          } catch { setPreviewContent('[二进制]') }
        }
      }
    } catch (e) { console.error(e) }
    finally { setPreviewLoading(false) }
  }, [sessionId, pollTask])

  const downloadFile = useCallback(async (node: FileNode) => {
    if (node.isDir) return
    try {
      const r = await sessionApi.downloadFile(sessionId, node.path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id, 600)
        if (p?.error) { alert('下载失败: ' + p.error); return }
        if (p?.output) {
          if (p.output.trim().startsWith('{') && p.output.includes('transfer_id')) {
            try {
              const meta = JSON.parse(p.output)
              if (meta.transfer_id) {
                const token = localStorage.getItem('toshell-token')
                const resp = await fetch(
                  `/api/v1/files/transfer?session_id=${encodeURIComponent(sessionId)}&transfer_id=${encodeURIComponent(meta.transfer_id)}`,
                  { headers: { Authorization: `Bearer ${token}` } }
                )
                if (!resp.ok) { alert('下载失败: ' + (await resp.text())); return }
                const blob = await resp.blob()
                const url = URL.createObjectURL(blob)
                const a = document.createElement('a')
                a.href = url
                a.download = node.name
                a.click()
                setTimeout(() => URL.revokeObjectURL(url), 1000)
                return
              }
            } catch { /* fall through to base64 */ }
          }

          if (p.output.length >= 10) {
            const bs = atob(p.output)
            const chunks: Uint8Array[] = []
            for (let o = 0; o < bs.length; o += 65536) {
              const e = Math.min(o + 65536, bs.length)
              const c = new Uint8Array(e - o)
              for (let i = o; i < e; i++) c[i - o] = bs.charCodeAt(i)
              chunks.push(c)
            }
            const blob = new Blob(chunks as BlobPart[])
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = node.name
            a.click()
            setTimeout(() => URL.revokeObjectURL(url), 1000)
          } else { alert('下载失败') }
        }
      }
    } catch (e) { console.error(e) }
  }, [sessionId, pollTask])

  const deleteFile = useCallback(async (node: FileNode) => {
    if (!confirm(`确定删除 ${node.name}?`)) return
    try {
      const r = await sessionApi.deleteFile(sessionId, node.path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id)
        if (p?.error) { alert('删除失败: ' + p.error); return }
        handleRefresh()
      }
    } catch (e) { console.error(e) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, pollTask, currentPath])

  // ----- upload -----

  const handleUploadFile = useCallback(async (file: File) => {
    if (!file) return
    const targetDir = pathRef.current
    const targetPath = joinPath(targetDir, file.name, isWindows)
    setUploading(true)
    setUploadProgress({ sent: 0, total: file.size, pushing: false })
    try {
      const uploadId = `${Date.now()}-${file.name}-${Math.random().toString(36).slice(2, 8)}`
      const chunkSize = 1024 * 1024
      const total = file.size
      let lastTaskId: number | null = null

      for (let offset = 0; offset < total; offset += chunkSize) {
        const slice = file.slice(offset, Math.min(offset + chunkSize, total))
        const b64 = await blobToBase64(slice)
        const done = offset + slice.size >= total
        const r = await sessionApi.uploadFile(sessionId, {
          upload_id: uploadId,
          filename: file.name,
          path: targetPath,
          size: total,
          offset,
          data: b64,
          done,
        })
        setUploadProgress({ sent: Math.min(offset + slice.size, total), total, pushing: false })
        if (done) lastTaskId = r?.data?.task_id ?? null
      }

      if (total === 0) {
        const r = await sessionApi.uploadFile(sessionId, {
          upload_id: uploadId,
          filename: file.name,
          path: targetPath,
          size: 0,
          offset: 0,
          data: '',
          done: true,
        })
        lastTaskId = r?.data?.task_id ?? null
        setUploadProgress({ sent: 0, total: 0, pushing: false })
      }

      if (lastTaskId) {
        setUploadProgress({ sent: total, total, pushing: true })
        const maxAttempts = Math.max(600, Math.ceil(total / (1024 * 1024)) * 4 + 120)
        const p = await pollTask(lastTaskId, maxAttempts)
        if (p?.error) { alert('上传失败: ' + p.error); return }
      }
      handleRefresh()
    } catch (e) {
      console.error(e)
      alert('上传失败')
    } finally {
      setUploading(false)
      setUploadProgress(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, isWindows, pollTask, currentPath])

  // ----- breadcrumb -----

  const breadcrumbs = getBreadcrumbs(currentPath, isWindows)

  // ============ render ============

  return (
    <div className="sfb-panel" style={{ width: panelWidth }}>
      <div className="sfb-resize-handle" onMouseDown={startResize} title="拖拽调整宽度" />
      {/* header */}
      <div className="sfb-header">
        <span className="sfb-title">文件目录</span>
        <button
          className="sfb-btn"
          onClick={handleRefresh}
          disabled={loading}
          title="刷新当前目录"
        >
          <RefreshCw size={13} className={loading ? 'spin' : ''} />
        </button>
      </div>

      {/* breadcrumb + upload */}
      <div className="sfb-toolbar">
        <div className="sfb-breadcrumb" title={currentPath}>
          <button className="sfb-home" title="根目录" onClick={() => onNavigate(isWindows ? '\\' : '/')}>
            <Home size={13} />
          </button>
          {breadcrumbs.map((bc, i) => (
            <span key={bc.path} className="sfb-crumb">
              <ChevronRight size={10} className="sfb-crumb-sep" />
              <span
                className={`sfb-crumb-item ${i === breadcrumbs.length - 1 ? 'sfb-crumb-item--active' : ''}`}
                onClick={() => onNavigate(bc.path)}
                title={bc.path}
              >
                {bc.name}
              </span>
            </span>
          ))}
        </div>
        <button className="sfb-btn sfb-btn-upload" onClick={() => fileInputRef.current?.click()} disabled={uploading} title="上传到当前目录(支持大文件分片直传)">
          <Upload size={13} /> {uploading ? '上传中' : '上传'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handleUploadFile(f) }}
        />
      </div>

      {/* upload progress */}
      {uploadProgress && (
        <div className="sfb-upload-progress">
          <div className="sfb-upload-bar">
            <div
              className="sfb-upload-fill"
              style={{ width: `${uploadProgress.total > 0 ? Math.min(100, (uploadProgress.sent / uploadProgress.total) * 100) : 100}%` }}
            />
          </div>
          <span className="sfb-upload-text">
            {uploadProgress.pushing
              ? '推送至目标主机...'
              : `${formatSize(uploadProgress.sent)} / ${formatSize(uploadProgress.total)}`}
          </span>
        </div>
      )}

      {/* file list */}
      <div className="sfb-list">
        {loading && items.length === 0 && (
          <div className="sfb-empty"><RefreshCw size={16} className="spin" /> 加载中...</div>
        )}
        {!loading && items.length === 0 && (
          <div className="sfb-empty">空目录</div>
        )}
        {items.map(node => (
          <div
            key={node.path}
            className="sfb-item"
            title={node.isDir ? `${node.name}（双击进入）` : node.name}
            onDoubleClick={() => handleEnterDir(node)}
          >
            {node.isDir
              ? <Folder size={15} className="sfb-icon sfb-icon-dir" />
              : <File size={15} className="sfb-icon sfb-icon-file" />}
            <span className="sfb-item-name">{node.name}</span>
            {!node.isDir && <span className="sfb-item-size">{formatSize(node.size)}</span>}
            {!node.isDir && (
              <span className="sfb-item-actions">
                <button className="sfb-btn-icon" title="预览" onClick={() => previewFile(node)}>
                  <Eye size={12} />
                </button>
                <button className="sfb-btn-icon" title="下载" onClick={() => downloadFile(node)}>
                  <Download size={12} />
                </button>
                <button className="sfb-btn-icon danger" title="删除" onClick={() => deleteFile(node)}>
                  <X size={12} />
                </button>
              </span>
            )}
          </div>
        ))}
      </div>

      {/* preview modal */}
      {(previewContent || previewLoading) && (
        <div className="modal-overlay" onClick={() => { setPreviewContent(null); setPreviewName('') }}>
          <div className="modal-preview" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>预览: {previewName}</h3>
              <div className="modal-header-actions">
                {previewTruncated && <span className="truncated-badge">仅100KB</span>}
                {previewSize > 0 && <span className="size-badge">{(previewSize / 1024).toFixed(1)} KB</span>}
<button className="btn-small" title="关闭" onClick={() => { setPreviewContent(null); setPreviewName('') }}>
  <span className="sfb-close-x">×</span>
</button>
              </div>
            </div>
            <div className="modal-body">
              {previewLoading
                ? <div className="loading-center"><RefreshCw size={24} className="spin" /> 加载中...</div>
                : <pre className="preview-content-scroll">{previewContent}</pre>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
