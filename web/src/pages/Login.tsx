import { useState } from 'react'
import { Shell, Lock, User } from 'lucide-react'
import { useAuthStore } from '../stores/auth'
import { authApi } from '../api'
import './Login.css'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const login = useAuthStore((state) => state.login)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = await authApi.login(username, password)
      if (response.data.token) {
        login(username, response.data.token)
        localStorage.setItem('toshell-token', response.data.token)
        window.location.href = '/dashboard'
      }
    } catch (err: any) {
      if (err.response?.status === 401) {
        setError('用户名或密码错误')
      } else {
        setError('登录失败，请检查服务器连接')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-bg">
        <div className="login-bg-gradient" />
        <div className="login-bg-grid" />
      </div>
      
      <div className="login-container">
        <div className="login-card">
          <div className="login-header">
            <Shell size={48} className="login-logo" />
            <h1>ToShell</h1>
            <p>C2 命令控制平台</p>
          </div>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="form-group">
              <User size={18} className="form-icon" />
              <input
                type="text"
                placeholder="用户名"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <Lock size={18} className="form-icon" />
              <input
                type="password"
                placeholder="密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && <div className="error-message">{error}</div>}

            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? '登录中...' : '登录'}
            </button>
          </form>

          <div className="login-footer">
            <span>请输入服务器账户凭据</span>
          </div>
        </div>
      </div>
    </div>
  )
}
