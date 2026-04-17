import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

export function LoginPage() {
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login, password }),
      })

      if (!res.ok) {
        const data = await res.json()
        setError(data.error || 'Ошибка входа')
        return
      }

      const data = await res.json()
      localStorage.setItem('token', data.token)
      navigate('/')
    } catch {
      setError('Ошибка сети')
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
        />
        <input
          type="password"
          placeholder="Пароль"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit">Войти</button>
      </form>
    </div>
  )
}