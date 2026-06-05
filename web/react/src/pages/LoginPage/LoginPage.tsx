import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { setToken } from '../../shared/auth/token'

export function LoginPage() {
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { token } = await api.login(login, password)
      if (!token) {
        setError('Ошибка входа')
        return
      }
      setToken(token)
      navigate('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка сети')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="loginPage">
      <form className="loginForm" onSubmit={handleSubmit}>
        <h2>Вход в систему</h2>
        {error && <div className="error">{error}</div>}
        <input
          type="text"
          placeholder="Логин"
          value={login}
          onChange={(e) => setLogin(e.target.value)}
          disabled={loading}
        />
        <input
          type="password"
          placeholder="Пароль"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
        />
        <button type="submit" disabled={loading}>{loading ? 'Вход...' : 'Войти'}</button>
      </form>
    </div>
  )
}