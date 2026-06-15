import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { api } from '../../../shared/api/api'
import { CiTokenListItem, UserRow } from '../../../entities/CiToken/model/types'
import { CreateCiKeyModal } from '../components/CreateCiKeyModal'
import styles from '../Admin.module.css'
import { UserCiTokensSection } from './UserCiTokensSection'
import { UserRoleSection } from './UserRoleSection'

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [user, setUser] = useState<UserRow | null>(null)
  const [tokens, setTokens] = useState<CiTokenListItem[]>([])
  const [modalOpen, setModalOpen] = useState(false)
  const [role, setRole] = useState('')
  const [savingRole, setSavingRole] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const load = async () => {
    if (!id) return
    const data = await api.getUser(id)
    setUser(data.user)
    setRole(data.user.role)
    setTokens(data.ciTokens || [])
  }

  useEffect(() => {
    load().catch(alert)
  }, [id])

  const saveRole = async () => {
    if (!id || !user || role === user.role) return
    setSavingRole(true)
    try {
      const updated = await api.patchUserRole(id, role)
      setUser(updated)
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
      setRole(user.role)
    } finally {
      setSavingRole(false)
    }
  }

  const deleteUser = async () => {
    if (!id || !user) return
    if (!window.confirm(`Удалить пользователя «${user.login}»? Сканирования и CI-ключи сервисных учёток будут удалены.`)) return
    setDeleting(true)
    try {
      await api.deleteUser(id)
      navigate('/admin/users')
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
    } finally {
      setDeleting(false)
    }
  }

  if (!user) return <p className={styles.empty}>Загрузка…</p>

  return (
    <div className={styles.page}>
      <Link to="/admin/users" className={styles.backLink}>← Пользователи</Link>
      <div className={styles.card}>
        <UserRoleSection
          user={user}
          roleEditor={{ role, saving: savingRole, onChange: setRole, onSave: saveRole }}
          deleteAction={{ deleting, onDelete: deleteUser }}
        />
        <UserCiTokensSection tokens={tokens} onCreateKey={() => setModalOpen(true)} />
      </div>
      {modalOpen && id && (
        <CreateCiKeyModal scope="admin" defaultOwnerUserId={id} onClose={() => setModalOpen(false)} onCreated={load} />
      )}
    </div>
  )
}
