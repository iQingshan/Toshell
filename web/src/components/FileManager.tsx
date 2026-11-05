import { useState, useEffect, useRef, useCallback } from 'react'
import {
  RefreshCw, Eye, Download, Upload, X, ChevronRight, ChevronDown,
  Folder, FolderOpen, File as FileIcon, Home, Edit3, AlertTriangle
} from 'lucide-react'
import { sessionApi } from '../api'
import type { PreviewFileError } from '../api'
import type { Session } from '../types'
import { getSessionState, updateSessionState } from '../stores/sessionState'
import {
  decidePreview, ensurePreviewPolicy, getPreviewPolicy, humanBytes,
  type PreviewCategory, type PreviewDecision, type PreviewPolicy,
} from '../utils/previewPolicy'

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

function dirnameOf(path: string, isWindows: boolean): string {
  // 返回父目录；根目录（如 C:\ 或 /）返回自身
  const sep = isWindows ? '\\' : '/'
  if (path.endsWith(sep)) return path
  const i = path.lastIndexOf(sep)
  if (i <= 0) return path
  return path.slice(0, i)
}

/** 上传队列里的一项（v1.4.3 #15a-B：多选 + 断点续传） */
type UploadTaskState = 'queued' | 'uploading' | 'pushing' | 'done' | 'error'
interface UploadTask {
  key: string
  name: string
  size: number
  sent: number
  state: UploadTaskState
  /** 附加说明（如「已从断点 12 MB 继续」） */
  note?: string
  error?: string
}

/**
 * 稳定的 upload_id：同一份文件（名字 + 大小 + 修改时间）每次算出同一个字符串。
 *
 * 为什么不能用随机 id：断点续传靠它把"这次要传的文件"和"服务端暂存的那半截"
 * 对上。随机 id 每次都变，断线后只能从头传（这也是 #15 里"断点续传"缺的那块）。
 */
function stableUploadId(file: File): string {
  const name = file.name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 40) || 'file'
  const stamp = Math.floor((file.lastModified || 0) / 1000)
  return `${name}-${file.size}-${stamp}`
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

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// 前端兜底二进制探测（服务端已做二次校验；这里只防老服务端/异常响应）。
function isMostlyBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 2048)
  if (n === 0) return false
  let bad = 0
  for (let i = 0; i < n; i++) {
    const c = bytes[i]
    // 允许 TAB/LF/CR/ESC（ESC 常见于 ANSI 彩色日志）
    if (c === 0 || c < 9 || (c > 13 && c < 32 && c !== 27) || c === 127) bad++
  }
  return bad * 10 > n
}

// 预览失败/需要确认时的弹窗（不再用 alert 静默吞掉原因）。
interface PreviewNotice {
  title: string
  message: string
  node: FileNode
  /** true = 未识别后缀，弹窗给"仍要预览（前 N KB，只读）"选项 */
  confirmForce?: boolean
  /** true = 黑名单/超大/二进制，只给下载 */
  downloadOnly?: boolean
  /** confirmForce 时可预览的前缀字节数 */
  limitBytes?: number
  /** 服务端返回的机器可读错误码（展示用，便于排障） */
  code?: string
}

// ============ TreeNode ============

interface TreeNodeProps {
  node: FileNode
  depth: number
  expanded: Set<string>
  childMap: Map<string, FileNode[]>
  loadingPaths: Set<string>
  onToggle: (node: FileNode) => void
  onPreview: (node: FileNode) => void
  onDownload: (node: FileNode) => void
  onContextMenu: (e: React.MouseEvent, node: FileNode) => void
}

function TreeNode({
  node, depth, expanded, childMap, loadingPaths,
  onToggle, onPreview, onDownload, onContextMenu,
}: TreeNodeProps) {
  const isExpanded = expanded.has(node.path)
  const children = childMap.get(node.path)
  const isLoading = loadingPaths.has(node.path)

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (node.isDir) onToggle(node)
  }

  const handleClick = () => {
    if (node.isDir) onToggle(node)
    else onPreview(node)
  }

  return (
    <div className="tree-node-wrapper">
      <div
        className={`tree-node ${isExpanded && node.isDir ? 'tree-node--expanded' : ''}`}
        style={{ paddingLeft: depth * 16 + 4 }}
        onContextMenu={(e) => onContextMenu(e, node)}
      >
        <div className="tree-node-content" onClick={handleClick}>
          {/* expand/collapse toggle */}
          {node.isDir ? (
            <button className="tree-toggle" onClick={handleToggle} title={isExpanded ? '折叠' : '展开'}>
              {isLoading ? (
                <RefreshCw size={12} className="spin" />
              ) : isExpanded ? (
                <ChevronDown size={14} />
              ) : (
                <ChevronRight size={14} />
              )}
            </button>
          ) : (
            <span className="tree-toggle tree-toggle--placeholder" />
          )}

          {/* icon */}
          {node.isDir ? (
            isExpanded
              ? <FolderOpen size={16} className="tree-icon tree-icon--folder" />
              : <Folder size={16} className="tree-icon tree-icon--folder" />
          ) : (
            <FileIcon size={16} className="tree-icon tree-icon--file" />
          )}

          {/* name */}
          <span className={`tree-name ${node.isDir ? 'tree-name--dir' : ''}`}>
            {node.name}
          </span>

          {/* size */}
          <span className="tree-size">{formatSize(node.size)}</span>

          {/* actions (files only) */}
          {!node.isDir && (
            <span className="tree-actions">
              <button className="btn-icon" title="预览" onClick={(e) => { e.stopPropagation(); onPreview(node) }}>
                <Eye size={12} />
              </button>
              <button className="btn-icon" title="下载" onClick={(e) => { e.stopPropagation(); onDownload(node) }}>
                <Download size={12} />
              </button>
            </span>
          )}
        </div>
      </div>

      {/* children */}
      {isExpanded && children && children.length > 0 && (
        <div className="tree-children">
          {children.map((child) => (
            <TreeNode
              key={child.path}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              childMap={childMap}
              loadingPaths={loadingPaths}
              onToggle={onToggle}
              onPreview={onPreview}
              onDownload={onDownload}
              onContextMenu={onContextMenu}
            />
          ))}
        </div>
      )}
      {isExpanded && children && children.length === 0 && (
        <div className="tree-children">
          <div className="tree-node" style={{ paddingLeft: (depth + 1) * 16 + 4 }}>
            <div className="tree-node-content">
              <span className="tree-toggle tree-toggle--placeholder" />
              <span className="tree-name tree-name--empty">空目录</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ============ DirPicker（目录选择器）============

interface DirPickerProps {
  isWindows: boolean
  initialPath: string
  listDir: (path: string) => Promise<FileItem[]>
  onCancel: () => void
  onConfirm: (dir: string) => void
}

function DirPicker({ isWindows, initialPath, listDir, onCancel, onConfirm }: DirPickerProps) {
  const [path, setPath] = useState(initialPath)
  const [dirs, setDirs] = useState<FileItem[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<string>(initialPath)

  const navigate = useCallback(async (p: string) => {
    setLoading(true)
    setPath(p)
    setSelected(p)
    const items = await listDir(p)
    setDirs(items.filter(i => i.isDir))
    setLoading(false)
  }, [listDir])

  useEffect(() => { navigate(initialPath) }, [initialPath, navigate])

  const crumbs = getBreadcrumbs(path, isWindows)

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-dirpicker" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>选择上传目录</h3>
          <button className="modal-close" onClick={onCancel} title="关闭"><X size={16} /></button>
        </div>

        {/* breadcrumb 导航 */}
        <div className="file-breadcrumb">
          <span className="breadcrumb-home" title="根目录" onClick={() => navigate(isWindows ? '\\' : '/')}>
            <Home size={14} />
          </span>
          {crumbs.map((bc, i) => (
            <span key={bc.path} className="breadcrumb-segment">
              <span className="breadcrumb-sep">&gt;</span>
              <span
                className={`breadcrumb-item ${i === crumbs.length - 1 ? 'breadcrumb-item--active' : ''}`}
                onClick={() => navigate(bc.path)}
              >
                {bc.name}
              </span>
            </span>
          ))}
        </div>

        {/* 子目录列表 */}
        <div className="dirpicker-list">
          {loading && (
            <div className="loading-center"><RefreshCw size={18} className="spin" /> 加载中...</div>
          )}
          {!loading && dirs.length === 0 && (
            <div className="empty-state"><p>当前目录没有子目录</p></div>
          )}
          {!loading && dirs.map(d => {
            const full = joinPath(path, d.name, isWindows)
            return (
              <div
                key={full}
                className={`dirpicker-item ${selected === full ? 'dirpicker-item--selected' : ''}`}
                onClick={() => setSelected(full)}
                onDoubleClick={() => navigate(full)}
                title={`${d.name}（双击进入）`}
              >
                <Folder size={16} className="tree-icon tree-icon--folder" />
                <span className="dirpicker-item-name">{d.name}</span>
                <ChevronRight size={12} className="dirpicker-item-arrow" />
              </div>
            )
          })}
        </div>

        {/* footer */}
        <div className="dirpicker-footer">
          <span className="dirpicker-path" title={selected}>{selected}</span>
          <div className="dirpicker-actions">
            <button className="btn-small" onClick={onCancel}>取消</button>
            <button className="btn-small primary" onClick={() => onConfirm(selected)} disabled={loading}>
              上传到此目录
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ FileManager ============

export function FileManager({ session }: { session: Session }) {
  const isWindows = session.os?.toLowerCase() === 'windows'

  const [rootPath, setRootPath] = useState(() =>
    getSessionState(session.id).currentPath || (isWindows ? '\\' : '/'))
  // 上传目标目录（默认跟随当前浏览目录，右键目录可改）
  const uploadDirRef = useRef(rootPath)
  useEffect(() => { uploadDirRef.current = rootPath }, [rootPath])
  const [roots, setRoots] = useState<FileNode[]>([])
  const [childMap, setChildMap] = useState<Map<string, FileNode[]>>(new Map())
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [loadingPaths, setLoadingPaths] = useState<Set<string>>(new Set())
  const [previewContent, setPreviewContent] = useState<string | null>(null)
  // 图片预览用 data URL（MIME 由服务端按内容签名给，绝不按后缀猜）
  const [previewImage, setPreviewImage] = useState<string | null>(null)
  const [previewName, setPreviewName] = useState('')
  const [previewSize, setPreviewSize] = useState(0)
  const [previewTruncated, setPreviewTruncated] = useState(false)
  const [previewLimit, setPreviewLimit] = useState(0)
  const [previewCategory, setPreviewCategory] = useState<PreviewCategory | null>(null)
  // true = 未识别后缀的强制预览（只读，不允许编辑覆盖）
  const [previewReadOnly, setPreviewReadOnly] = useState(false)
  const [previewNotice, setPreviewNotice] = useState<PreviewNotice | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewPath, setPreviewPath] = useState('')
  const [policy, setPolicy] = useState<PreviewPolicy>(() => getPreviewPolicy())
  const [editing, setEditing] = useState(false)
  const [draftContent, setDraftContent] = useState('')
  const [saving, setSaving] = useState(false)
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; file: FileNode } | null>(null)
  const [uploading, setUploading] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerInit, setPickerInit] = useState('')
  // 上传队列（v1.4.3 #15a-B）：多选 + 断点续传，串行执行。
  const [uploadTasks, setUploadTasks] = useState<UploadTask[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  const loadedRef = useRef(false)
  const sidRef = useRef(session.id)

  // sync session switch
  useEffect(() => {
    if (sidRef.current !== session.id) {
      const st = getSessionState(session.id)
      const cached = st.currentPath
      // 缓存的路径与平台不匹配时（如 Linux 会话拿到缓存的 C:\）退回平台默认
      const compatible = cached && (isWindows ? (cached === '\\' || /^[A-Za-z]:\\/.test(cached)) : !cached.includes(':'))
      setRootPath(compatible ? cached : (isWindows ? '\\' : '/'))
      setRoots([])
      setChildMap(new Map())
      setExpanded(new Set())
      sidRef.current = session.id
      loadedRef.current = false
    }
  }, [session.id, isWindows])

  // dismiss context menu
  useEffect(() => {
    const h = () => setContextMenu(null)
    document.addEventListener('click', h)
    return () => document.removeEventListener('click', h)
  }, [])

  // 文件预览规则以服务端为准（拿不到时用 utils/previewPolicy.ts 的内置兜底）
  useEffect(() => {
    let alive = true
    ensurePreviewPolicy().then((p) => { if (alive) setPolicy(p) }).catch(() => { /* ignore */ })
    return () => { alive = false }
  }, [])

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
    // 中文习惯排序：目录在前、拼音排序、数字自然排序（2 在 10 前）
    const byZh = (a: FileItem, b: FileItem) => a.name.localeCompare(b.name, 'zh-CN', { numeric: true })
    return [
      ...dirs.sort(byZh),
      ...fls.sort(byZh)
    ]
  }, [])

  const itemsToNodes = useCallback((items: FileItem[], parentPath: string): FileNode[] => {
    return items.map(item => ({
      name: item.name,
      path: joinPath(parentPath, item.name, isWindows),
      isDir: item.isDir,
      size: item.size,
      modTime: item.modTime,
    }))
  }, [isWindows])

  const loadPath = useCallback(async (path: string): Promise<FileItem[]> => {
    try {
      const r = await sessionApi.listFiles(session.id, path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id)
        if (p?.output) return parseDir(p.output)
      }
    } catch (e) { console.error(e) }
    return []
  }, [session.id, pollTask, parseDir])

  // ----- load root -----

  const loadRoot = useCallback(async (path: string) => {
    setLoading(true)
    setPreviewContent(null)
    const items = await loadPath(path)
    setRoots(itemsToNodes(items, path))
    setChildMap(new Map())
    setExpanded(new Set())
    setRootPath(path)
    updateSessionState(session.id, { currentPath: path, files: items })
    setLoading(false)
  }, [loadPath, itemsToNodes, session.id])

  useEffect(() => {
    if (!loadedRef.current) {
      loadedRef.current = true
      loadRoot(rootPath)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // ----- toggle (expand / collapse) -----

  const toggleNode = useCallback(async (node: FileNode) => {
    if (!node.isDir) return

    if (expanded.has(node.path)) {
      // collapse
      setExpanded(prev => {
        const next = new Set(prev)
        next.delete(node.path)
        return next
      })
      return
    }

    // expand — lazy load if needed
    if (!childMap.has(node.path)) {
      setLoadingPaths(prev => new Set(prev).add(node.path))
      const items = await loadPath(node.path)
      const nodes = itemsToNodes(items, node.path)
      setChildMap(prev => new Map(prev).set(node.path, nodes))
      setLoadingPaths(prev => {
        const next = new Set(prev)
        next.delete(node.path)
        return next
      })
    }

    setExpanded(prev => new Set(prev).add(node.path))
  }, [expanded, childMap, loadPath, itemsToNodes])

  // ----- file operations -----

  const closePreview = useCallback(() => {
    setPreviewContent(null)
    setPreviewImage(null)
    setPreviewName('')
    setPreviewPath('')
    setPreviewSize(0)
    setPreviewTruncated(false)
    setPreviewLimit(0)
    setPreviewCategory(null)
    setPreviewReadOnly(false)
    setEditing(false)
    setPreviewLoading(false)
  }, [])

  // 老服务端没有 /files/preview 接口时的回退：沿用下载任务 + 前端判定，
  // 但仍然给出明确的弹窗（不再把 "[二进制文件，无法预览]" 当正文静默显示）。
  const legacyPreviewFile = useCallback(async (node: FileNode) => {
    try {
      const r = await sessionApi.downloadFile(session.id, node.path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id, 600)
        if (p?.error) {
          setPreviewNotice({ title: '预览失败', message: p.error, node, downloadOnly: true, code: 'preview_failed' })
          return
        }
        if (p?.output) {
          // 大文件直传模式：只提示改用下载（与现状一致）
          if (p.output.trim().startsWith('{') && p.output.includes('transfer_id')) {
            setPreviewNotice({
              title: '该文件较大',
              message: '文件已转服务端存储，内联预览不可用；请使用「下载」在本地查看。',
              node, downloadOnly: true, code: 'preview_too_large',
            })
            return
          }
          let bytes: Uint8Array
          try {
            bytes = base64ToBytes(p.output)
          } catch {
            setPreviewNotice({ title: '预览失败', message: '服务端返回的内容不是合法 base64。', node, downloadOnly: true, code: 'preview_failed' })
            return
          }
          if (isMostlyBinary(bytes)) {
            setPreviewNotice({
              title: '该文件不支持内联预览',
              message: '内容被判定为二进制（含 NUL/控制字符），已拒绝内联预览；请下载后在本地查看。',
              node, downloadOnly: true, code: 'preview_binary',
            })
            return
          }
          const limit = policy.oversize_preview_bytes
          const slice = bytes.subarray(0, Math.min(bytes.length, limit))
          setPreviewContent(new TextDecoder().decode(slice))
          setPreviewSize(bytes.length)
          setPreviewTruncated(bytes.length > limit)
          setPreviewLimit(limit)
          setPreviewCategory('text')
          setPreviewReadOnly(false)
        }
      }
    } catch (e) {
      console.error(e)
      setPreviewNotice({ title: '预览失败', message: String((e as Error)?.message || e), node, downloadOnly: true, code: 'preview_failed' })
    }
  }, [session.id, pollTask, policy.oversize_preview_bytes])

  // 真正请求预览：服务端二次校验；415/409/413 一律转成弹窗，不静默失败。
  const requestPreview = useCallback(async (node: FileNode, force: boolean, dec: PreviewDecision) => {
    setPreviewLoading(true)
    setPreviewName(node.name)
    setPreviewPath(node.path)
    setEditing(false)
    setPreviewContent(null)
    setPreviewImage(null)
    setPreviewSize(0)
    setPreviewTruncated(!!dec.truncated)
    setPreviewLimit(dec.previewBytes)
    setPreviewCategory(dec.category)
    setPreviewReadOnly(dec.category === 'unknown' || force)
    try {
      const r = await sessionApi.previewFile(session.id, node.path, node.size, force)
      const d = r.data
      const bytes = d.content_b64 ? base64ToBytes(d.content_b64) : new Uint8Array()
      if (d.category === 'image') {
        if (!d.mime || !d.content_b64) {
          setPreviewNotice({ title: '该文件不支持内联预览', message: '图片内容签名校验未通过；请下载查看。', node, downloadOnly: true, code: 'preview_bad_image' })
          return
        }
        setPreviewImage(`data:${d.mime};base64,${d.content_b64}`)
      } else {
        if (isMostlyBinary(bytes)) {
          setPreviewNotice({ title: '该文件不支持内联预览', message: '内容被判定为二进制（含 NUL/控制字符），已拒绝内联预览；请下载后在本地查看。', node, downloadOnly: true, code: 'preview_binary' })
          return
        }
        setPreviewContent(new TextDecoder().decode(bytes))
      }
      setPreviewSize(d.size || bytes.length)
      setPreviewTruncated(!!d.truncated)
      setPreviewLimit(d.preview_bytes || dec.previewBytes)
      setPreviewCategory(d.category)
    } catch (e: any) {
      const status = e?.response?.status
      const data = e?.response?.data as PreviewFileError | undefined
      // 老服务端没有该接口（404/405）→ 回退到旧预览链路
      if (!e?.response || status === 404 || status === 405) {
        await legacyPreviewFile(node)
        return
      }
      const code = data?.code
      const message = data?.message || data?.error || `预览请求失败（HTTP ${status}）`
      if (status === 409 || code === 'preview_unknown_ext') {
        setPreviewNotice({
          title: '该后缀不在预览白名单',
          message,
          node,
          confirmForce: true,
          limitBytes: data?.preview_bytes || dec.previewBytes,
          code,
        })
      } else if (status === 415 || code === 'preview_blocked' || code === 'preview_binary' || code === 'preview_bad_image') {
        setPreviewNotice({ title: '该文件不支持内联预览', message, node, downloadOnly: true, code })
      } else if (status === 413 || code === 'preview_too_large') {
        setPreviewNotice({ title: '文件过大，无法内联预览', message, node, downloadOnly: true, code })
      } else {
        setPreviewNotice({ title: '预览失败', message, node, downloadOnly: true, code })
      }
    } finally {
      setPreviewLoading(false)
    }
  }, [session.id, legacyPreviewFile])

  // 预览入口：先按服务端下发的清单做本地判定（命中黑名单/未识别直接弹窗），
  // 允许的再交给服务端二次校验。
  const previewFile = useCallback((node: FileNode) => {
    if (node.isDir) return
    const dec = decidePreview(node.name, node.size, false, policy)
    if (!dec.allowed) {
      if (dec.requiresConfirmation) {
        setPreviewNotice({
          title: '该后缀不在预览白名单',
          message: dec.message,
          node,
          confirmForce: true,
          limitBytes: dec.previewBytes,
          code: dec.code,
        })
      } else {
        setPreviewNotice({
          title: dec.code === 'preview_too_large' ? '文件过大，无法内联预览' : '该文件不支持内联预览',
          message: dec.message,
          node,
          downloadOnly: true,
          code: dec.code,
        })
      }
      return
    }
    void requestPreview(node, false, dec)
  }, [policy, requestPreview])

  // 操作员在弹窗里选择"仍要预览（前 N KB，只读）"
  const forcePreview = useCallback((node: FileNode) => {
    setPreviewNotice(null)
    const dec = decidePreview(node.name, node.size, true, policy)
    void requestPreview(node, true, dec)
  }, [policy, requestPreview])

  const downloadFile = useCallback(async (node: FileNode) => {
    if (node.isDir) return
    try {
      const r = await sessionApi.downloadFile(session.id, node.path)
      if (r?.data?.task_id) {
        // 大文件分块直传服务端磁盘,轮询放宽到 10 分钟
        const p = await pollTask(r.data.task_id, 600)
        if (p?.error) { alert('下载失败: ' + p.error); return }
        if (p?.output) {
          // 直传模式:输出为 {"transfer_id":...},从服务端流式下载
          if (p.output.trim().startsWith('{') && p.output.includes('transfer_id')) {
            try {
              const meta = JSON.parse(p.output)
              if (meta.transfer_id) {
                const token = localStorage.getItem('toshell-token')
                const resp = await fetch(
                  `/api/v1/files/transfer?session_id=${encodeURIComponent(session.id)}&transfer_id=${encodeURIComponent(meta.transfer_id)}`,
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
  }, [session.id, pollTask])

  // 删除成功后刷新目录树：只重载树根列表与被删节点父目录的缓存，
  // 保留其余已展开的目录状态（不再像 loadRoot 那样把整棵树折叠回根）。
  const refreshAfterDelete = useCallback(async (deletedPath: string) => {
    const sep = isWindows ? '\\' : '/'
    // 1) 重新加载树根列表（保持其余展开状态不变）
    const items = await loadPath(rootPath)
    setRoots(itemsToNodes(items, rootPath))
    // 2) 移除被删节点及其子孙路径的展开状态与子目录缓存
    setExpanded(prev => {
      const next = new Set<string>()
      for (const p of prev) {
        if (p !== deletedPath && !p.startsWith(deletedPath + sep)) next.add(p)
      }
      return next
    })
    setChildMap(prev => {
      const next = new Map<string, FileNode[]>()
      for (const [p, nodes] of prev) {
        if (p !== deletedPath && !p.startsWith(deletedPath + sep)) next.set(p, nodes)
      }
      return next
    })
    // 3) 被删节点所在目录若已展开过，刷新其子项缓存
    const parent = dirnameOf(deletedPath, isWindows)
    if (parent && parent !== rootPath) {
      const pItems = await loadPath(parent)
      setChildMap(prev => {
        if (!prev.has(parent)) return prev
        return new Map(prev).set(parent, itemsToNodes(pItems, parent))
      })
    }
    updateSessionState(session.id, { currentPath: rootPath, files: items })
  }, [loadPath, itemsToNodes, rootPath, isWindows, session.id])

  const deleteFile = useCallback(async (node: FileNode) => {
    if (!confirm(`确定删除 ${node.name}?`)) return
    // 原生 file_delete 任务：植入端直接用 os.RemoveAll 删除，不经过 shell
    try {
      const r = await sessionApi.deleteFile(session.id, node.path)
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id)
        if (p?.error) { alert('删除失败: ' + p.error); return }
        await refreshAfterDelete(node.path)
      }
    } catch (e) { console.error(e) }
  }, [session.id, pollTask, refreshAfterDelete])

  const renameFile = useCallback(async (node: FileNode) => {
    const nn = prompt('新名称:', node.name)
    if (!nn || nn === node.name) return
    const op = node.path
    const np = joinPath(rootPath, nn, isWindows)
    // 安全加固：文件名可能含引号/元字符，转义后拼接，防 shell 注入（`"; rm -rf /; #`）
    const esc = (s: string) => s.replace(/"/g, '\\"').replace(/\$/g, '\\$')
    const cmd = isWindows
      ? `ren "${esc(op)}" "${esc(nn)}"`
      : `mv "${esc(op)}" "${esc(np)}"`
    try {
      const r = await sessionApi.interact(session.id, cmd, 'command')
      if (r?.data?.task_id) {
        const p = await pollTask(r.data.task_id)
        if (p?.error) { alert('重命名失败: ' + p.error); return }
        loadRoot(rootPath)
      }
    } catch (e) { console.error(e) }
  }, [session.id, isWindows, pollTask, loadRoot, rootPath])

  // ----- upload -----

  // 选择上传目标目录（默认当前浏览目录），随后弹出文件选择器
  const handleChooseUploadDir = useCallback(() => {
    setPickerInit(uploadDirRef.current || rootPath)
    setPickerOpen(true)
  }, [rootPath])

  // 单文件上传（内部实现）：1MB 分片 + 断点续传 + 分片级重试。
  // 不负责刷新目录/收尾，由调用方（队列 / 预览保存）决定。
  const uploadOneFile = useCallback(async (file: File, taskKey: string, opts?: { targetPath?: string }) => {
    const targetDir = uploadDirRef.current || rootPath
    const targetPath = opts?.targetPath || joinPath(targetDir, file.name, isWindows)
    const patch = (p: Partial<UploadTask>) => {
      setUploadTasks(prev => prev.map(t => (t.key === taskKey ? { ...t, ...p } : t)))
    }

    // upload_id 由文件本身推导（名字+大小+mtime）：断线/刷新后再传同一个文件，
    // 服务端能认出"这就是刚才没传完的那次"，从而实现续传。
    const uploadId = stableUploadId(file)
    const chunkSize = 1024 * 1024 // 1MB
    const total = file.size

    // ① 先问服务端已收到多少字节（老服务端没有该接口 → 从头传）
    let start = 0
    try {
      const st = await sessionApi.getUploadStatus(session.id, uploadId)
      const received = Number(st?.data?.received ?? 0)
      if (received > 0 && received <= total) {
        start = received
        patch({ sent: start, note: start < total ? `已从断点 ${formatSize(start)} 继续` : undefined })
      }
    } catch {
      /* 忽略：按从头传处理 */
    }

    // ② 单个分片最多重试 3 次（同 offset 重放是幂等的：服务端按 offset 定位写入）
    const postChunk = async (offset: number, done: boolean, data: string) => {
      let lastErr: unknown = null
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          return await sessionApi.uploadFile(session.id, {
            upload_id: uploadId,
            filename: file.name,
            path: targetPath,
            size: total,
            offset,
            data,
            done,
          })
        } catch (e) {
          lastErr = e
          if (attempt < 3) {
            patch({ note: `第 ${attempt} 次失败，重试中…` })
            await new Promise(r => setTimeout(r, 600 * attempt))
          }
        }
      }
      throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))
    }

    let lastTaskId: number | null = null
    if (total === 0) {
      const r = await postChunk(0, true, '')
      lastTaskId = r?.data?.task_id ?? null
      patch({ sent: 0 })
    } else {
      for (let offset = start; offset < total; offset += chunkSize) {
        const slice = file.slice(offset, Math.min(offset + chunkSize, total))
        const b64 = await blobToBase64(slice)
        const done = offset + slice.size >= total
        const r = await postChunk(offset, done, b64)
        patch({ sent: Math.min(offset + slice.size, total), note: undefined })
        if (done) lastTaskId = r?.data?.task_id ?? null
      }
    }

    if (lastTaskId) {
      // 服务端暂存完成，进入推送/写盘阶段
      patch({ sent: total, state: 'pushing' })
      const maxAttempts = Math.max(600, Math.ceil(total / (1024 * 1024)) * 4 + 120)
      const p = await pollTask(lastTaskId, maxAttempts)
      if (p?.error) throw new Error(String(p.error))
    }
    patch({ sent: total, state: 'done', note: undefined })
  }, [session.id, rootPath, isWindows, pollTask])

  // 多文件上传（v1.4.3 #15a-B）：串行队列，逐个传，失败不阻塞后面的文件。
  const handleUploadFiles = useCallback(async (files: File[]) => {
    const list = files.filter(Boolean)
    if (list.length === 0) return
    const stamp = Date.now()
    const tasks: UploadTask[] = list.map((f, i) => ({
      key: `${stamp}-${i}-${f.name}`,
      name: f.name,
      size: f.size,
      sent: 0,
      state: 'queued',
    }))
    // 清掉上一轮已完成的条目，只保留失败项供查看
    setUploadTasks(prev => [...prev.filter(t => t.state === 'error'), ...tasks])
    setUploading(true)
    const targetDir = uploadDirRef.current || rootPath
    try {
      for (let i = 0; i < list.length; i++) {
        const t = tasks[i]
        setUploadTasks(prev => prev.map(x => (x.key === t.key ? { ...x, state: 'uploading' } : x)))
        try {
          await uploadOneFile(list[i], t.key)
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e)
          setUploadTasks(prev => prev.map(x => (x.key === t.key ? { ...x, state: 'error', error: msg, note: undefined } : x)))
        }
      }
      loadRoot(targetDir)
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }, [uploadOneFile, loadRoot, rootPath])

  // 单文件入口（预览编辑保存复用）：opt.targetPath 覆盖原文件
  const handleUploadFile = useCallback(async (file: File, opts?: { targetPath?: string }) => {
    if (!file) return
    const key = `single-${Date.now()}`
    setUploadTasks([{ key, name: file.name, size: file.size, sent: 0, state: 'uploading' }])
    setUploading(true)
    try {
      await uploadOneFile(file, key, opts)
      if (opts?.targetPath) {
        // 编辑保存：只刷新原文件所在目录缓存，不重置整个文件树
        const refreshPath = dirnameOf(opts.targetPath, isWindows) || rootPath
        const items = await loadPath(refreshPath)
        setChildMap(prev => new Map(prev).set(refreshPath, itemsToNodes(items, refreshPath)))
        setRoots(prev => (refreshPath === rootPath ? itemsToNodes(items, refreshPath) : prev))
        updateSessionState(session.id, { currentPath: rootPath, files: items })
      } else {
        loadRoot(uploadDirRef.current || rootPath)
      }
    } catch (e) {
      console.error(e)
      const msg = e instanceof Error ? e.message : String(e)
      setUploadTasks(prev => prev.map(x => (x.key === key ? { ...x, state: 'error', error: msg } : x)))
      alert('上传失败: ' + msg)
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }, [session.id, rootPath, isWindows, uploadOneFile, loadRoot, itemsToNodes, loadPath])

  // 预览编辑保存：用新内容覆盖原文件（复用分片上传链路）
  // 只读预览（未识别后缀强制预览）与截断预览禁止保存，避免把"前缀"写回原文件。
  const saveEditedFile = useCallback(async () => {
    if (!previewPath || draftContent === null) return
    if (previewReadOnly || previewTruncated || previewCategory !== 'text') {
      alert('当前预览为只读/已截断，不能直接保存；请下载后在本地修改。')
      return
    }
    setSaving(true)
    try {
      const blob = new Blob([draftContent], { type: 'text/plain;charset=utf-8' })
      const file = new File([blob], previewName, { type: 'text/plain;charset=utf-8' })
      await handleUploadFile(file, { targetPath: previewPath })
      setPreviewContent(draftContent)
      setPreviewSize(new TextEncoder().encode(draftContent).length)
      setEditing(false)
      setPreviewTruncated(false)
      alert('保存成功')
    } catch (e) {
      console.error(e)
      alert('保存失败')
    } finally {
      setSaving(false)
    }
  }, [previewPath, previewName, draftContent, handleUploadFile, previewReadOnly, previewTruncated, previewCategory])

  // ----- context menu -----

  const handleContextMenu = useCallback((e: React.MouseEvent, node: FileNode) => {
    e.preventDefault()
    setContextMenu({ x: e.clientX, y: e.clientY, file: node })
  }, [])

  // ----- breadcrumb -----

  const breadcrumbs = getBreadcrumbs(rootPath, isWindows)
  const handleBreadcrumbClick = (path: string) => {
    loadRoot(path)
  }

  // ============ render ============

  return (
    <div className="files-tab">
      {/* toolbar */}
      <div className="files-toolbar">
        <button className="btn-small" onClick={() => loadRoot(rootPath)} disabled={loading}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
        </button>
        <button className="btn-small primary" onClick={handleChooseUploadDir} disabled={uploading} title="选择目标目录后上传(支持大文件分片直传)">
          <Upload size={14} /> {uploading ? '上传中...' : '上传文件'}
        </button>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={(e) => {
            // v1.4.3 #15a-B：多选 → 串行队列；每个文件独立进度、失败不影响其余
            const files = e.target.files ? Array.from(e.target.files) : []
            if (files.length > 0) void handleUploadFiles(files)
          }}
        />
      </div>

      {/* breadcrumb */}
      <div className="file-breadcrumb">
        <span className="breadcrumb-home" title="根目录" onClick={() => handleBreadcrumbClick(isWindows ? '\\' : '/')}>
          <Home size={14} />
        </span>
        {breadcrumbs.map((bc, i) => (
          <span key={bc.path} className="breadcrumb-segment">
            <span className="breadcrumb-sep">&gt;</span>
            <span
              className={`breadcrumb-item ${i === breadcrumbs.length - 1 ? 'breadcrumb-item--active' : ''}`}
              onClick={() => handleBreadcrumbClick(bc.path)}
            >
              {bc.name}
            </span>
          </span>
        ))}
      </div>

      {/* preview modal */}
      {(previewContent !== null || previewImage !== null || previewLoading) && !previewNotice && (
        <div className="modal-overlay" onClick={closePreview}>
          <div className="modal-preview" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editing ? '编辑' : '预览'}: {previewName}</h3>
              <div className="modal-header-actions">
                {previewCategory === 'image' && <span className="size-badge">图片</span>}
                {previewReadOnly && <span className="size-badge">只读</span>}
                {previewTruncated && (
                  <span className="truncated-badge" title="只回传文件前缀，不是完整文件">
                    已截断 · 仅前 {humanBytes(previewLimit || policy.oversize_preview_bytes)}
                  </span>
                )}
                {previewSize > 0 && <span className="size-badge">{formatSize(previewSize)}</span>}
                {!editing && !previewLoading && previewCategory === 'text' && previewContent !== null
                  && !previewReadOnly && !previewTruncated && (
                  <button className="btn-small" onClick={() => { setDraftContent(previewContent); setEditing(true) }}>
                    <Edit3 size={14} /> 编辑
                  </button>
                )}
                {editing && (
                  <>
                    <button className="btn-small primary" onClick={saveEditedFile} disabled={saving}>
                      {saving ? '保存中...' : '保存'}
                    </button>
                    <button className="btn-small" onClick={() => setEditing(false)} disabled={saving}>
                      取消
                    </button>
                  </>
                )}
                <button className="btn-small" onClick={closePreview}>
                  <X size={16} />
                </button>
              </div>
            </div>
            <div className="modal-body">
              {previewLoading
                ? <div className="loading-center"><RefreshCw size={24} className="spin" /> 加载中...</div>
                : editing
                  ? <textarea
                      className="preview-edit-area"
                      value={draftContent}
                      onChange={e => setDraftContent(e.target.value)}
                      spellCheck={false}
                    />
                  : previewImage
                    ? <img className="preview-image" src={previewImage} alt={previewName} />
                    : <pre className="preview-content-scroll">{previewContent}</pre>}
            </div>
          </div>
        </div>
      )}

      {/* 预览限制弹窗：黑名单只给下载；未识别后缀给"仍要预览（前 N KB，只读）" */}
      {previewNotice && (
        <div className="modal-overlay" onClick={() => setPreviewNotice(null)}>
          <div className="modal-notice" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3><AlertTriangle size={16} /> {previewNotice.title}</h3>
              <button className="btn-small" onClick={() => setPreviewNotice(null)} title="关闭">
                <X size={16} />
              </button>
            </div>
            <div className="modal-body preview-notice-body">
              <p className="preview-notice-file" title={previewNotice.node.path}>{previewNotice.node.name}</p>
              <p className="preview-notice-message">{previewNotice.message}</p>
              {previewNotice.code && (
                <p className="preview-notice-code">code: {previewNotice.code}</p>
              )}
            </div>
            <div className="modal-footer preview-notice-actions">
              <button className="btn-small" onClick={() => setPreviewNotice(null)}>取消</button>
              {previewNotice.confirmForce && (
                <button className="btn-small" onClick={() => forcePreview(previewNotice.node)}>
                  仍要预览（前 {humanBytes(previewNotice.limitBytes || policy.max_unknown_preview_bytes)}，只读）
                </button>
              )}
              <button
                className="btn-small primary"
                onClick={() => { const node = previewNotice.node; setPreviewNotice(null); void downloadFile(node) }}
              >
                <Download size={14} /> 下载
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 上传队列（v1.4.3 #15a-B）：每个文件一行，含断点续传提示与失败原因 */}
      {uploadTasks.length > 0 && (
        <div className="upload-queue">
          {uploadTasks.map((t) => {
            const pct = t.size > 0 ? Math.min(100, Math.round((t.sent / t.size) * 100)) : (t.state === 'done' ? 100 : 0)
            return (
              <div key={t.key} className={`upload-queue-item ${t.state}`}>
                <div className="upload-queue-head">
                  <span className="upload-queue-name" title={t.name}>{t.name}</span>
                  <span className="upload-queue-size">{formatSize(t.sent)} / {formatSize(t.size)}</span>
                  <span className="upload-queue-state">
                    {t.state === 'queued' && '排队中'}
                    {t.state === 'uploading' && `${pct}%`}
                    {t.state === 'pushing' && '推送至目标主机…'}
                    {t.state === 'done' && '完成'}
                    {t.state === 'error' && '失败'}
                  </span>
                  {(t.state === 'done' || t.state === 'error') && (
                    <button
                      className="upload-queue-dismiss"
                      title="从列表移除"
                      onClick={() => setUploadTasks(prev => prev.filter(x => x.key !== t.key))}
                    >×</button>
                  )}
                </div>
                <div className="upload-progress-bar">
                  <div
                    className={`upload-progress-fill${t.state === 'error' ? ' error' : ''}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                {(t.note || t.error) && (
                  <div className={`upload-queue-note${t.error ? ' error' : ''}`}>{t.error || t.note}</div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* 目录选择器 */}
      {pickerOpen && (
        <DirPicker
          isWindows={isWindows}
          initialPath={pickerInit || rootPath}
          listDir={loadPath}
          onCancel={() => setPickerOpen(false)}
          onConfirm={(dir) => {
            setPickerOpen(false)
            uploadDirRef.current = dir
            fileInputRef.current?.click()
          }}
        />
      )}

      {/* tree */}
      <div className="file-tree">
        {roots.length === 0 && !loading && (
          <div className="empty-state" style={{ padding: '20px' }}><p>空目录</p></div>
        )}
        {roots.map((node) => (
          <TreeNode
            key={node.path}
            node={node}
            depth={0}
            expanded={expanded}
            childMap={childMap}
            loadingPaths={loadingPaths}
            onToggle={toggleNode}
            onPreview={previewFile}
            onDownload={downloadFile}
            onContextMenu={handleContextMenu}
          />
        ))}
      </div>

      {/* context menu */}
      {contextMenu && contextMenu.file && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={e => e.stopPropagation()}
        >
          {!contextMenu.file.isDir && (
            <div className="context-menu-item" onClick={() => { previewFile(contextMenu.file!); setContextMenu(null) }}>
              预览
            </div>
          )}
          {!contextMenu.file.isDir && (
            <div className="context-menu-item" onClick={() => { downloadFile(contextMenu.file!); setContextMenu(null) }}>
              下载
            </div>
          )}
          {contextMenu.file.isDir && (
            <div className="context-menu-item" onClick={() => {
              setContextMenu(null)
              setPickerInit(contextMenu.file!.path)
              setPickerOpen(true)
            }}>
              上传到此目录
            </div>
          )}
          <div className="context-menu-item" onClick={async () => {
            const file = contextMenu.file!
            try {
              await navigator.clipboard.writeText(file.path)
            } catch {
              // 剪贴板 API 不可用时的降级方案（兼容 http 非安全上下文等）
              const ta = document.createElement('textarea')
              ta.value = file.path
              document.body.appendChild(ta)
              ta.select()
              document.execCommand('copy')
              document.body.removeChild(ta)
            }
            setContextMenu(null)
          }}>
            复制完整路径
          </div>
          <div className="context-menu-item" onClick={() => { renameFile(contextMenu.file!); setContextMenu(null) }}>
            重命名
          </div>
          <div className="context-menu-item danger" onClick={() => { deleteFile(contextMenu.file!); setContextMenu(null) }}>
            删除
          </div>
        </div>
      )}
    </div>
  )
}
