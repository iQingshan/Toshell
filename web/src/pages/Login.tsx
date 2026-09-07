import { useState } from 'react'
import { Shell, Lock, User } from 'lucide-react'
import { useAuthStore } from '../stores/auth'
import { authApi } from '../api'
import { useI18n } from '../i18n'
import './Login.css'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const login = useAuthStore((state) => state.login)
  const { t, lang, setLang } = useI18n()

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
        setError(t('login.errBadCreds'))
      } else {
        setError(t('login.errConn'))
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
          <div className="login-card-top">
            <button className="lang-toggle" onClick={() => setLang(lang === 'zh' ? 'en' : 'zh')} title={lang === 'zh' ? 'English' : '中文'}>
              {lang === 'zh' ? 'EN' : '中'}
            </button>
          </div>
          <div className="login-header">
            <Shell size={48} className="login-logo" />
            <h1>ToShell</h1>
            <p>{t('login.subtitle')}</p>
          </div>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="form-group">
              <User size={18} className="form-icon" />
              <input
                type="text"
                placeholder={t('login.username')}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <Lock size={18} className="form-icon" />
              <input
                type="password"
                placeholder={t('login.password')}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {error && <div className="error-message">{error}</div>}

            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? t('login.submitting') : t('login.submit')}
            </button>
          </form>

          <div className="login-footer">
            <span>{t('login.footer')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}
