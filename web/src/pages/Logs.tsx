import { useState, useEffect } from 'react'
import { Search, RefreshCw, Info, AlertTriangle, XCircle, Bug } from 'lucide-react'
import { format } from 'date-fns'
import { logApi } from '../api'
import type { LogEntry } from '../types'
import './Logs.css'

export function Logs() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [search, setSearch] = useState('')
  const [levelFilter, setLevelFilter] = useState('')
  const [loading, setLoading] = useState(false)

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const response = await logApi.list(100, levelFilter || undefined)
      const logsData = response?.data?.logs
      setLogs(Array.isArray(logsData) ? logsData : [])
    } catch (error) {
      console.error('Failed to fetch logs:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
  }, [levelFilter])

  const filteredLogs = Array.isArray(logs) ? logs.filter(log => {
    const matchSearch = log.message?.toLowerCase().includes(search.toLowerCase()) ||
      log.component?.toLowerCase().includes(search.toLowerCase())
    const matchLevel = !levelFilter || log.level === levelFilter
    return matchSearch && matchLevel
  }) : []

  const getLevelIcon = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'info': return <Info size={14} />
      case 'warning':
      case 'warn': return <AlertTriangle size={14} />
      case 'error': return <XCircle size={14} />
      case 'fatal': return <XCircle size={14} />
      case 'debug': return <Bug size={14} />
      default: return null
    }
  }

  return (
    <div className="logs-page">
      <div className="page-header">
        <div className="search-box">
          <Search size={18} className="search-icon" />
          <input
            type="text"
            placeholder="搜索日志消息..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="level-filter"
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
        >
          <option value="">全部级别</option>
          <option value="info">信息</option>
          <option value="warning">警告</option>
          <option value="error">错误</option>
          <option value="debug">调试</option>
        </select>
        <button className="refresh-btn" onClick={fetchLogs} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'spin' : ''} />
          刷新
        </button>
      </div>

      <div className="logs-table-container">
        <table className="logs-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>级别</th>
              <th>组件</th>
              <th>消息</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan={4} className="empty-state">
                  {loading ? '加载中...' : '暂无日志'}
                </td>
              </tr>
            ) : (
              filteredLogs.map((log, index) => (
                <tr key={index}>
                  <td className="log-time">
                    {log.timestamp ? format(new Date(log.timestamp), 'yyyy-MM-dd HH:mm:ss') : '-'}
                  </td>
                  <td>
                    <span className={`log-level ${log.level?.toLowerCase()}`}>
                      {getLevelIcon(log.level || '')}
                      {log.level}
                    </span>
                  </td>
                  <td className="log-component">{log.component}</td>
                  <td className="log-message">{log.message}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
