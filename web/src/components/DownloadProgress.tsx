interface DownloadProgressProps {
  percent: number
  loaded: number
  total: number
  done?: boolean
}

// 载荷下载进度条：显示已下载字节数 / 总字节数 + 百分比。
// 服务器未返回 Content-Length（total 为 0）时，进度条走不确定动画，仅显示"正在下载"。
export function DownloadProgress({ percent, loaded, total, done }: DownloadProgressProps) {
  const fmt = (n: number): string => {
    if (n < 1024) return `${n} B`
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / (1024 * 1024)).toFixed(2)} MB`
  }
  const hasTotal = total > 0
  const pct = hasTotal ? Math.max(0, Math.min(100, percent)) : 0

  return (
    <div className="download-progress">
      <div className="download-progress-track">
        <div
          className={`download-progress-fill${!hasTotal ? ' indeterminate' : ''}${done ? ' done' : ''}`}
          style={hasTotal ? { width: `${pct}%` } : undefined}
        />
      </div>
      <div className="download-progress-text">
        {done
          ? '下载完成'
          : hasTotal
            ? `正在下载 ${fmt(loaded)} / ${fmt(total)} (${pct}%)`
            : '正在下载...'}
      </div>
    </div>
  )
}
