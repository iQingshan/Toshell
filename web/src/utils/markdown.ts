// 轻量、安全的 Markdown → HTML 渲染器（用于 AI 副驾驶消息展示）。
// 先对原文做 HTML 转义，再只把"受控"的 markdown 标记转成 html，杜绝原始 HTML 注入（XSS）。

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function inline(s: string): string {
  return s
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\[(.+?)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
}

function table(rows: string[]): string {
  // 去掉表头分隔行（|---|---|）
  const body = rows.filter((r, idx) => !(idx === 1 && /^\s*\|[\s:-]+\|/.test(r)))
  const tr = body
    .map((r) => {
      const cells = r.trim().replace(/^\||\|$/g, '').split('|').map((c) => inline(c.trim()))
      return `<tr>${cells.map((c) => `<td>${c}</td>`).join('')}</tr>`
    })
    .join('')
  return `<table>${tr}</table>`
}

export function markdown(src: string): string {
  if (!src) return ''
  try {
    const lines = esc(src).split('\n')
    let html = ''
    let inUl = false
    let inOl = false
    let inCode = false
    let codeBuf: string[] = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.startsWith('```')) {
      if (inCode) {
        html += `<pre><code>${codeBuf.join('\n')}</code></pre>`
        codeBuf = []
        inCode = false
      } else {
        inCode = true
      }
      continue
    }
    if (inCode) {
      codeBuf.push(line)
      continue
    }

    const h = line.match(/^(#{1,4})\s(.*)$/)
    if (h) {
      html += `<h${h[1].length + 2}>${inline(h[2])}</h${h[1].length + 2}>`
      continue
    }

    if (line.trimStart().startsWith('|')) {
      const tbl: string[] = []
      let j = i
      while (j < lines.length && lines[j].trimStart().startsWith('|')) {
        tbl.push(lines[j])
        j++
      }
      html += table(tbl)
      i = j - 1
      continue
    }

    if (/^\s*[-*]\s/.test(line)) {
      if (!inUl) {
        html += '<ul>'
        inUl = true
      }
      html += `<li>${inline(line.replace(/^\s*[-*]\s/, ''))}</li>`
      continue
    } else if (inUl) {
      html += '</ul>'
      inUl = false
    }

    if (/^\s*\d+[.)]\s/.test(line)) {
      if (!inOl) {
        html += '<ol>'
        inOl = true
      }
      html += `<li>${inline(line.replace(/^\s*\d+[.)]\s/, ''))}</li>`
      continue
    } else if (inOl) {
      html += '</ol>'
      inOl = false
    }

    if (line.trim() === '') {
      html += '<br/>'
      continue
    }
    html += `<p>${inline(line)}</p>`
  }

  if (inUl) html += '</ul>'
  if (inOl) html += '</ol>'
  if (inCode) html += `<pre><code>${codeBuf.join('\n')}</code></pre>`
  return html
  } catch {
    // 任何解析异常都回退为转义后的原文，绝不让页面白屏
    return esc(src)
  }
}
