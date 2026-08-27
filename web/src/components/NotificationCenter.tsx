import { useState, useEffect, useCallback } from 'react'
import {
  Bell, CheckCircle, AlertTriangle, XCircle, Info, X,
} from 'lucide-react'

export type NotifyType = 'info' | 'success' | 'warning' | 'error'

export interface Notification {
  id: string
  type: NotifyType
  title: string
  message: string
  timestamp: Date
  read: boolean
  sessionId?: string
}

interface NotificationCenterProps {
  maxDisplay?: number
}

/** 全局通知存储 - 允许外部推送事件 */
const listeners = new Set<(n: Notification) => void>()
let notifId = 0

export function pushNotification(
  type: NotifyType,
  title: string,
  message: string,
  sessionId?: string
) {
  const n: Notification = {
    id: `notif-${++notifId}`,
    type,
    title,
    message,
    timestamp: new Date(),
    read: false,
    sessionId,
  }
  listeners.forEach((fn) => fn(n))
}

/** 便捷方法：外部调用来推送 C2 事件 */
export const notify = {
  sessionOnline: (hostname: string, sessionId: string) =>
    pushNotification('success', '会话上线', `${hostname} 已上线`, sessionId),
  sessionOffline: (hostname: string, sessionId: string) =>
    pushNotification('warning', '会话离线', `${hostname} 已离线`, sessionId),
  taskCompleted: (taskId: number, sessionId: string) =>
    pushNotification('success', '任务完成', `任务 #${taskId} 已完成`, sessionId),
  taskFailed: (taskId: number, sessionId: string, err?: string) =>
    pushNotification('error', '任务失败', `任务 #${taskId} 失败${err ? ': ' + err : ''}`, sessionId),
  shellConnected: (sessionId: string) =>
    pushNotification('info', 'Shell 连接', `会话 ${sessionId.slice(0, 8)} Shell 已连接`, sessionId),
  implantBuilt: (name: string) =>
    pushNotification('success', 'Implant 编译完成', `${name} 编译成功`),
  tunnelCreated: (sessionId: string, port: number) =>
    pushNotification('success', '隧道创建', `SOCKS5 隧道: ${sessionId.slice(0, 8)} -> :${port}`, sessionId),
}

export function NotificationCenter({ maxDisplay = 50 }: NotificationCenterProps) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [isOpen, setIsOpen] = useState(false)

  const addNotification = useCallback((n: Notification) => {
    setNotifications((prev) => [n, ...prev].slice(0, maxDisplay))
  }, [maxDisplay])

  useEffect(() => {
    listeners.add(addNotification)
    return () => { listeners.delete(addNotification) }
  }, [addNotification])

  const markRead = (id: string) =>
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)))
  const markAllRead = () =>
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })))
  const remove = (id: string) =>
    setNotifications((prev) => prev.filter((n) => n.id !== id))
  const clearAll = () => setNotifications([])

  const unreadCount = notifications.filter((n) => !n.read).length

  const iconMap: Record<NotifyType, React.ReactNode> = {
    success: <CheckCircle size={16} />,
    warning: <AlertTriangle size={16} />,
    error: <XCircle size={16} />,
    info: <Info size={16} />,
  }

  return (
    <div className="notification-center">
      <button
        className="notification-toggle"
        onClick={() => setIsOpen(!isOpen)}
        title="通知中心"
      >
        <Bell size={18} />
        {unreadCount > 0 && <span className="notification-badge">{unreadCount}</span>}
      </button>

      {isOpen && (
        <div className="notification-dropdown">
          <div className="notification-header">
            <h4>通知中心</h4>
            <div className="notification-actions">
              {unreadCount > 0 && (
                <button onClick={markAllRead} className="notif-action-btn">
                  全部已读
                </button>
              )}
              {notifications.length > 0 && (
                <button onClick={clearAll} className="notif-action-btn danger">
                  清空
                </button>
              )}
            </div>
          </div>

          <div className="notification-list">
            {notifications.length === 0 ? (
              <div className="notification-empty">
                <Bell size={32} />
                <p>暂无通知</p>
              </div>
            ) : (
              notifications.map((n) => (
                <div
                  key={n.id}
                  className={`notification-item ${n.read ? 'read' : 'unread'} notif-${n.type}`}
                  onClick={() => markRead(n.id)}
                >
                  <span className="notif-icon">{iconMap[n.type]}</span>
                  <div className="notif-content">
                    <span className="notif-title">{n.title}</span>
                    <span className="notif-message">{n.message}</span>
                    {n.sessionId && (
                      <span className="notif-session">会话: {n.sessionId.slice(0, 12)}...</span>
                    )}
                    <span className="notif-time">
                      {n.timestamp.toLocaleTimeString()}
                    </span>
                  </div>
                  <button
                    className="notif-close"
                    onClick={(e) => {
                      e.stopPropagation()
                      remove(n.id)
                    }}
                  >
                    <X size={12} />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}


