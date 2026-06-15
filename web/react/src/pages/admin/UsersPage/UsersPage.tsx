import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../../shared/api/api'
import { UserRow } from '../../../entities/CiToken/model/types'
import { CreateUserModal, roleLabel } from '../components/CreateUserModal'
import styles from '../Admin.module.css'

export function UsersPage() {
  const [users, setUsers] = useState<UserRow[]>([])
  const [search, setSearch] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    return api.listUsers()
      .then(setUsers)
      .catch(alert)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const filtered = users.filter((u) => u.login.toLowerCase().includes(search.toLowerCase()))

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.headRow}>
          <div>
            <h2 className={styles.title}>Пользователи</h2>
            <p className={styles.subtitle}>Создание специалистов и администраторов платформы</p>
          </div>
          <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={() => setModalOpen(true)}>
            + Создать пользователя
          </button>
        </div>
        <div className={styles.field}>
          <input placeholder="Поиск по логину" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        {loading ? (
          <p className={styles.empty}>Загрузка…</p>
        ) : filtered.length === 0 ? (
          <p className={styles.empty}>Пользователи не найдены</p>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Логин</th>
                <th>Роль</th>
                <th>CI-ключей</th>
                <th>Создан</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <tr key={u.id}>
                  <td>{u.login}</td>
                  <td>
                    <span className={`${styles.badge} ${u.role === 'admin' ? styles.badgeActive : ''}`}>
                      {roleLabel(u.role)}
                    </span>
                  </td>
                  <td>{u.ciTokenCount ?? 0}</td>
                  <td>{new Date(u.createdAt).toLocaleDateString()}</td>
                  <td><Link to={`/admin/users/${u.id}`} className={styles.btn}>Открыть</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {modalOpen && (
        <CreateUserModal
          onClose={() => setModalOpen(false)}
          onCreated={() => load()}
        />
      )}
    </div>
  )
}
