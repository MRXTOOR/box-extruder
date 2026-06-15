import { useState } from 'react'
import { api } from '../../../shared/api/api'
import { UserRow } from '../../../entities/CiToken/model/types'
import styles from '../Admin.module.css'

const ROLES = [
  { value: 'specialist', label: 'Специалист', hint: 'Сканы через UI, просмотр своих CI-ключей в ЛК' },
  { value: 'admin', label: 'Администратор', hint: 'Полный доступ: пользователи, CI-ключи, все сканы' },
] as const

interface Props {
  onClose: () => void
  onCreated: (user: UserRow) => void
}

export function CreateUserModal({ onClose, onCreated }: Props) {
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<'specialist' | 'admin'>('specialist')
  const [saving, setSaving] = useState(false)

  const selectedRole = ROLES.find((r) => r.value === role)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const user = await api.createUser({ login: login.trim(), password, role })
      onCreated(user)
      onClose()
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className={styles.modalBackdrop} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <h3 className={styles.title}>Создать пользователя</h3>
        <p className={styles.subtitle}>Выберите роль: специалист или администратор платформы.</p>
        <form onSubmit={submit}>
          <div className={styles.field}>
            <label htmlFor="user-login">Логин</label>
            <input
              id="user-login"
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              required
              autoComplete="off"
              placeholder="ivanov"
            />
          </div>
          <div className={styles.field}>
            <label htmlFor="user-password">Пароль</label>
            <input
              id="user-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              minLength={6}
            />
          </div>
          <div className={styles.field}>
            <label htmlFor="user-role">Роль</label>
            <select id="user-role" value={role} onChange={(e) => setRole(e.target.value as 'specialist' | 'admin')}>
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            {selectedRole && <span className={styles.subtitle}>{selectedRole.hint}</span>}
          </div>
          <div className={styles.actions}>
            <button type="button" className={styles.btn} onClick={onClose}>Отмена</button>
            <button type="submit" className={`${styles.btn} ${styles.btnPrimary}`} disabled={saving}>
              {saving ? 'Создание…' : 'Создать'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function roleLabel(role: string): string {
  return ROLES.find((r) => r.value === role)?.label ?? role
}
