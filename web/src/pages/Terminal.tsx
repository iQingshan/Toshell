import { useState, useEffect, useRef } from 'react'
import { Send, Trash2, Copy, Terminal as TerminalIcon, Users, RefreshCw } from 'lucide-react'
import { sessionApi, taskApi } from '../api'
import type { Session, Task } from '../types'
import './Terminal.css'

interface Message {
  id: string
  type: 'input' | 'output' | 'error' | 'system'
  content: string
  timestamp: Date
}

export function Terminal() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedSession, setSelectedSession] = useState<string>('')
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'system',
      content: 'ToShell Terminal v1.0.0 - 选择会话后可执行命令',
      timestamp: new Date(),
    },
  ])
  const [loading, setLoading] = useState(false)
  const [executing, setExecuting] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  // 轮询取消：切会话/卸载时中止进行中的任务轮询，防止旧结果写到新会话
  const pollAbortRef = useRef<AbortController | null>(null)
  // 当前展示归属的会话 ID（结果只追加到同一会话，防跨会话串扰）
  const sessionBoundRef = useRef('')

  const fetchSessions = async () => {
    setLoading(true)
    try {
      const response = await sessionApi.list()
      const sessionsData = response?.data?.sessions || []
      setSessions(Array.isArray(sessionsData) ? sessionsData : [])
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchSessions()
  }, [])

  useEffect(() => {
    if (sessions.length > 0 && !selectedSession) {
      setSelectedSession(sessions[0].id)
    }
  }, [sessions, selectedSession])

  // 切会话：中止旧轮询 + 清空消息 + 重置会话归属，防命令结果打到错误机器
  useEffect(() => {
    if (!selectedSession) return
    pollAbortRef.current?.abort()
    pollAbortRef.current = null
    sessionBoundRef.current = selectedSession
    setExecuting(false)
    setMessages([{
      id: Date.now().toString(),
      type: 'system',
      content: `已切换到会话 ${selectedSession}，可输入命令执行`,
      timestamp: new Date(),
    }])
  }, [selectedSession])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // 卸载时中止轮询（防组件销毁后继续 setState）
  useEffect(() => {
    return () => {
      pollAbortRef.current?.abort()
      pollAbortRef.current = null
    }
  }, [])

  const pollTaskResult = async (taskId: number) => {
    const maxAttempts = 30
    // 动态轮询间隔：前几次快速探测，之后拉长，减少无效请求
    const intervals = [0, 300, 500, 1000, 2000, 3000]
    // 绑定发起轮询时的会话：期间切换会话则直接放弃（结果属于旧会话）
    const boundSession = sessionBoundRef.current

    for (let i = 0; i < maxAttempts; i++) {
      // 切会话/卸载后不再写入（防旧会话结果污染新会话视图）
      if (sessionBoundRef.current !== boundSession) return
      try {
        const response = await taskApi.get(taskId)
        const task: Task = response?.data

        if (task && task.status === 'completed') {
          if (sessionBoundRef.current !== boundSession) return
          const output = task.output || '(无输出)'
          const exitCode = task.exit_code !== undefined ? `\n退出码: ${task.exit_code}` : ''
          setMessages(prev => [...prev, {
            id: Date.now().toString() + '_result',
            type: task.exit_code === 0 ? 'output' : 'error',
            content: output + exitCode,
            timestamp: new Date(),
          }])
          return
        } else if (task && task.status === 'failed') {
          if (sessionBoundRef.current !== boundSession) return
          setMessages(prev => [...prev, {
            id: Date.now().toString() + '_error',
            type: 'error',
            content: task.error || '命令执行失败',
            timestamp: new Date(),
          }])
          return
        }
      } catch (error) {
        console.error('Failed to poll task result:', error)
      }

      await new Promise(resolve => setTimeout(resolve, intervals[Math.min(i, intervals.length - 1)]))
    }

    if (sessionBoundRef.current !== boundSession) return
    setMessages(prev => [...prev, {
      id: Date.now().toString() + '_timeout',
      type: 'error',
      content: '命令执行超时',
      timestamp: new Date(),
    }])
  }

  const handleSend = async () => {
    if (!input.trim() || !selectedSession || executing) return

    const command = input.trim()
    setMessages(prev => [...prev, {
      id: Date.now().toString(),
      type: 'input',
      content: command,
      timestamp: new Date(),
    }])

    setInput('')
    setExecuting(true)

    try {
      const response = await sessionApi.interact(selectedSession, command)
      const data = response?.data

      if (data && data.task_id) {
        setMessages(prev => [...prev, {
          id: Date.now().toString() + '_sent',
          type: 'system',
          content: `任务 #${data.task_id} 已发送，等待执行结果...`,
          timestamp: new Date(),
        }])

        pollTaskResult(data.task_id)
      }
    } catch (error: any) {
      console.error('Failed to send command:', error)
      setMessages(prev => [...prev, {
        id: Date.now().toString() + '_error',
        type: 'error',
        content: `发送失败: ${error.response?.data?.error || error.message}`,
        timestamp: new Date(),
      }])
    } finally {
      setExecuting(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const clearTerminal = () => {
    setMessages([
      {
        id: Date.now().toString(),
        type: 'system',
        content: '终端已清空',
        timestamp: new Date(),
      },
    ])
  }

  const copyOutput = () => {
    const text = messages.map(m => m.content).join('\n')
    navigator.clipboard.writeText(text)
  }

  const selectedSessionInfo = sessions.find(s => s.id === selectedSession)

  return (
    <div className="terminal-page">
      <div className="terminal-sidebar">
        <div className="sidebar-header">
          <Users size={18} />
          <span>会话列表</span>
          <button className="refresh-btn-small" onClick={fetchSessions} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
          </button>
        </div>
        <div className="session-list">
          {sessions.map((session) => (
            <div
              key={session.id}
              className={`session-item ${selectedSession === session.id ? 'active' : ''}`}
              onClick={() => setSelectedSession(session.id)}
            >
              <div className="session-status" data-status={session.status} />
              <div className="session-info">
                <span className="session-hostname">{session.hostname}</span>
                <span className="session-user">{session.username}@{session.domain || 'LOCAL'}</span>
              </div>
            </div>
          ))}
          {sessions.length === 0 && (
            <div className="no-sessions">{loading ? '加载中...' : '无可用会话'}</div>
          )}
        </div>
      </div>

      <div className="terminal-main">
        <div className="terminal-toolbar">
          <div className="terminal-title">
            <TerminalIcon size={16} />
            <span>{selectedSessionInfo?.hostname || '终端'}</span>
            {selectedSessionInfo && (
              <span className="session-info-badge">
                {selectedSessionInfo.os} | {selectedSessionInfo.username}
              </span>
            )}
          </div>
          <div className="terminal-actions">
            <button className="toolbar-btn" onClick={copyOutput} title="复制">
              <Copy size={14} />
            </button>
            <button className="toolbar-btn" onClick={clearTerminal} title="清空">
              <Trash2 size={14} />
            </button>
          </div>
        </div>

        {selectedSessionInfo && (
          <div className="system-info-panel">
            <div className="system-info-item">
              <span className="system-info-label">主机名</span>
              <span className="system-info-value">{selectedSessionInfo.hostname}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">用户</span>
              <span className="system-info-value">{selectedSessionInfo.username}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">系统</span>
              <span className="system-info-value">{selectedSessionInfo.os} {selectedSessionInfo.arch}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">PID</span>
              <span className="system-info-value">{selectedSessionInfo.pid}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">状态</span>
              <span className="system-info-value">{selectedSessionInfo.status}</span>
            </div>
            <div className="system-info-item">
              <span className="system-info-label">最后在线</span>
              <span className="system-info-value">{new Date(selectedSessionInfo.last_seen).toLocaleString()}</span>
            </div>
          </div>
        )}

        <div className="system-description">
          <div className="system-description-title">使用说明</div>
          <div>输入命令后按回车执行。支持Windows命令(cmd)、PowerShell命令。使用 exit 退出会话。</div>
        </div>

        <div className="terminal-content">
          {messages.map((msg) => (
            <div key={msg.id} className={`terminal-message ${msg.type}`}>
              {msg.content}
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        <div className="terminal-input-container">
          <span className="input-prompt">$</span>
          <input
            type="text"
            className="terminal-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={selectedSession ? '输入命令...' : '请先选择一个会话'}
            disabled={!selectedSession || executing}
          />
          <button
            className="send-btn"
            onClick={handleSend}
            disabled={!selectedSession || !input.trim() || executing}
          >
            <Send size={16} />
          </button>
        </div>
      </div>
    </div>
  )
}
