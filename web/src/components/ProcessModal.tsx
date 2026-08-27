import { useState } from 'react'
import { X } from 'lucide-react'

interface ProcessModalProps {
  isOpen: boolean
  onClose: () => void
  onExecute: (config: any) => void
  targetPid?: number
}

export function ProcessModal({ isOpen, onClose, onExecute, targetPid }: ProcessModalProps) {
  const [method, setMethod] = useState('')
  const [shellcode, setShellcode] = useState('')
  const [dllPath, setDllPath] = useState('')

  if (!isOpen) return null

  const injectMethods = [
    { value: 'remote_thread', label: '远程线程注入', desc: '在目标进程中创建远程线程执行Shellcode。最常用但容易被检测。' },
    { value: 'apc', label: 'APC注入', desc: '将Shellcode排队到线程的APC队列。隐蔽性更好。' },
    { value: 'thread_hijack', label: '线程劫持', desc: '劫持目标进程中的现有线程执行Shellcode。' },
    { value: 'dll', label: 'DLL注入', desc: '通过LoadLibrary将DLL注入运行中的进程。' }
  ]

  const handleSubmit = () => {
    if (!method) {
      alert('请选择注入方法')
      return
    }

    if (!targetPid) {
      alert('目标进程PID是必需的')
      return
    }

    if (method !== 'dll' && !shellcode) {
      alert('Shellcode是必需的')
      return
    }

    if (method === 'dll' && !dllPath) {
      alert('DLL路径是必需的')
      return
    }

    const config = {
      method,
      targetPid,
      shellcode,
      dllPath
    }

    onExecute(config)
    onClose()
  }

  return (
    <div className="modal-overlay">
      <div className="modal">
        <div className="modal-header">
          <h3>进程注入</h3>
          <button onClick={onClose} className="modal-close">
            <X size={16} />
          </button>
        </div>
        
        <div className="modal-body">
          <div className="form-group">
            <label>注入方法：</label>
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
              <option value="">-- 请选择方法 --</option>
              {injectMethods.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label} ({m.value})
                </option>
              ))}
            </select>
            {method && (
              <div className="method-desc">
                {injectMethods.find(m => m.value === method)?.desc}
              </div>
            )}
          </div>

          <div className="form-group">
            <label>目标进程PID：</label>
            <input
              type="number"
              value={targetPid || ''}
              disabled
              style={{ backgroundColor: '#f5f5f5' }}
            />
          </div>

          {method === 'dll' ? (
            <div className="form-group">
              <label>DLL文件路径：</label>
              <input
                type="text"
                value={dllPath}
                onChange={(e) => setDllPath(e.target.value)}
                placeholder="C:\path\to\malicious.dll"
              />
            </div>
          ) : (
            <div className="form-group">
              <label>Shellcode (Base64)：</label>
              <textarea
                value={shellcode}
                onChange={(e) => setShellcode(e.target.value)}
                placeholder="请输入要注入的Shellcode的Base64编码"
                rows={6}
                style={{ fontFamily: 'monospace', fontSize: '12px' }}
              />
            </div>
          )}

          <div className="warning-box">
            <strong>⚠️ 警告：</strong>
            进程注入可能会导致目标进程崩溃或不稳定！
          </div>
        </div>

        <div className="modal-footer">
          <button onClick={onClose} className="btn-secondary">取消</button>
          <button onClick={handleSubmit} className="btn-primary">执行注入</button>
        </div>
      </div>
    </div>
  )
}
