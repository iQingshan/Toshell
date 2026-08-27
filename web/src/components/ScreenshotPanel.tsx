import { useState, useCallback } from 'react'
import { Camera, Download, Trash2, Maximize2 } from 'lucide-react'
import type { Session } from '../types'
import { screenshotApi } from '../api'

interface ScreenshotEntry {
  taskId: number
  image: string  // base64
  format: string
  width: number
  height: number
  timestamp: number
}

interface ScreenshotPanelProps {
  session: Session
}

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

export function ScreenshotPanel({ session }: ScreenshotPanelProps) {
  const [screenshots, setScreenshots] = useState<ScreenshotEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [previewIndex, setPreviewIndex] = useState<number | null>(null)

  const handleTakeScreenshot = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const resp = await screenshotApi.take(session.id)
      const taskId = resp.data?.task_id
      if (!taskId) throw new Error('未返回 task_id')

      const result = await pollTaskResult(taskId)
      if (result.error) {
        setError(result.error)
        return
      }

      if (result.output) {
        try {
          const parsed = JSON.parse(result.output)
          const entry: ScreenshotEntry = {
            taskId,
            image: parsed.image || '',
            format: parsed.format || 'png',
            width: parsed.width || 0,
            height: parsed.height || 0,
            timestamp: Date.now(),
          }
          setScreenshots((prev) => [entry, ...prev])
        } catch {
          setError('解析截图数据失败')
        }
      }
    } catch (err: any) {
      const msg = err?.response?.data?.error || err.message || '请求失败'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [session.id])

  const handleDownload = useCallback((entry: ScreenshotEntry) => {
    const mime = entry.format === 'png' ? 'image/png' : 'image/jpeg'
    const byteString = atob(entry.image)
    const ab = new ArrayBuffer(byteString.length)
    const ia = new Uint8Array(ab)
    for (let i = 0; i < byteString.length; i++) {
      ia[i] = byteString.charCodeAt(i)
    }
    const blob = new Blob([ab], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `screenshot_${entry.timestamp}.${entry.format}`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [])

  const handleDelete = useCallback((index: number) => {
    setScreenshots((prev) => prev.filter((_, i) => i !== index))
    if (previewIndex === index) {
      setPreviewIndex(null)
    } else if (previewIndex !== null && previewIndex > index) {
      setPreviewIndex(previewIndex - 1)
    }
  }, [previewIndex])

  const handleClearAll = useCallback(() => {
    setScreenshots([])
    setPreviewIndex(null)
  }, [])

  const previewEntry = previewIndex !== null ? screenshots[previewIndex] : null

  return (
    <div className="screenshot-panel">
      {/* 工具栏 */}
      <div className="screenshot-toolbar">
        <div className="screenshot-info">
          <Camera size={18} />
          <span>屏幕截图 — {session.hostname}</span>
        </div>
        <div className="screenshot-actions">
          {screenshots.length > 0 && (
            <button className="btn-small danger" onClick={handleClearAll} title="清空所有截图">
              <Trash2 size={14} /> 清空
            </button>
          )}
          <button className="btn-small primary" onClick={handleTakeScreenshot} disabled={loading}>
            <Camera size={14} /> {loading ? '截图中...' : '截取屏幕'}
          </button>
        </div>
      </div>

      {/* 错误提示 */}
      {error && (
        <div className="screenshot-error">
          {error}
          <button onClick={() => setError('')} className="screenshot-error-close">×</button>
        </div>
      )}

      {/* 截图展示区域 */}
      <div className="screenshot-content">
        {screenshots.length === 0 ? (
          <div className="screenshot-empty">
            <Camera size={48} />
            <p>暂无截图</p>
            <span>点击「截取屏幕」获取目标桌面截图</span>
          </div>
        ) : (
          <>
            {/* 大图预览（最后一张或选中） */}
            <div className="screenshot-preview-area">
              {previewEntry ? (
                <div className="screenshot-preview">
                  <img
                    src={`data:image/${previewEntry.format};base64,${previewEntry.image}`}
                    alt="截图预览"
                    onClick={() => {
                      // create full-screen overlay
                      const overlay = document.createElement('div')
                      overlay.className = 'screenshot-fullscreen-overlay'
                      const fullImg = document.createElement('img')
                      fullImg.src = `data:image/${previewEntry.format};base64,${previewEntry.image}`
                      fullImg.className = 'screenshot-fullscreen-img'
                      overlay.appendChild(fullImg)
                      overlay.onclick = () => document.body.removeChild(overlay)
                      document.body.appendChild(overlay)
                    }}
                  />
                  <div className="screenshot-preview-info">
                    <span>{previewEntry.width} × {previewEntry.height}</span>
                    <span>{new Date(previewEntry.timestamp).toLocaleTimeString()}</span>
                    <div className="screenshot-preview-actions">
                      <button
                        className="btn-icon"
                        onClick={() => handleDownload(previewEntry)}
                        title="下载"
                      >
                        <Download size={16} />
                      </button>
                      <button
                        className="btn-icon"
                        onClick={() => {
                          const overlay = document.createElement('div')
                          overlay.className = 'screenshot-fullscreen-overlay'
                          const fullImg = document.createElement('img')
                          fullImg.src = `data:image/${previewEntry.format};base64,${previewEntry.image}`
                          fullImg.className = 'screenshot-fullscreen-img'
                          overlay.appendChild(fullImg)
                          overlay.onclick = () => document.body.removeChild(overlay)
                          document.body.appendChild(overlay)
                        }}
                        title="全屏查看"
                      >
                        <Maximize2 size={16} />
                      </button>
                      <button
                        className="btn-icon danger"
                        onClick={() => handleDelete(previewIndex!)}
                        title="删除"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="screenshot-preview-empty">
                  <Camera size={32} />
                  <span>点击下方缩略图查看大图</span>
                </div>
              )}
            </div>

            {/* 缩略图列表 */}
            <div className="screenshot-thumbnails">
              {screenshots.map((entry, index) => (
                <div
                  key={entry.taskId}
                  className={`screenshot-thumb ${previewIndex === index ? 'active' : ''}`}
                  onClick={() => setPreviewIndex(index)}
                >
                  <img
                    src={`data:image/${entry.format};base64,${entry.image}`}
                    alt={`截图 ${index + 1}`}
                  />
                  <div className="screenshot-thumb-overlay">
                    <span className="screenshot-thumb-time">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                    <button
                      className="btn-icon-small"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleDelete(index)
                      }}
                      title="删除"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
