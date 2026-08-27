export interface Session {
  id: string
  hostname: string
  username: string
  os: string
  arch: string
  pid: number
  process_name: string
  process_path: string
  ip_addresses: string[]
  mac_addresses: string[]
  domain: string
  first_seen: string
  last_seen: string
  status: string
  listener: string
  remote_addr: string
  parent_relay?: string
  comment?: string
}


export interface Task {
  id: number
  session_id: string
  command: string
  args: string[]
  execute_type: string
  status: string
  created_at: string
  sent_at?: string
  completed_at?: string
  output?: string
  error?: string
  exit_code?: number
  timeout: number
}

export interface TaskStats {
  total: number
  completed: number
  failed: number
  timeout: number
  pending: number
  running: number
}

export interface LogEntry {
  id: number
  timestamp: string
  level: string
  component: string
  message: string
  session_id?: string
  task_id?: number
  source_ip?: string
}


export interface TaskRequest {
  session_id: string
  command: string
  args?: string[]
  execute_type?: string
  timeout?: number
}

export interface ListenerInfo {
  id: string
  name: string
  type: string
  protocol: string
  bind_addr: string
  bind_port: number
  public_addr?: string
  status: string
  connections: number
  created_at: number
  options?: string
}
