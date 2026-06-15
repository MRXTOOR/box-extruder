import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { CiTokenListItem } from '../../entities/CiToken/model/types'
import { CreateCiKeyModal } from '../admin/components/CreateCiKeyModal'
import styles from '../admin/Admin.module.css'

export function MyCiKeysPage() {
  const [tokens, setTokens] = useState<CiTokenListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)

  const load = () => {
    setLoading(true)
    return api.listMyCiTokens()
      .then(setTokens)
      .catch(alert)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const revoke = async (id: string, name: string) => {
    if (!confirm(`Отозвать ключ «${name}»? Jenkins-пайплайны с этим секретом перестанут работать.`)) return
    try {
      await api.revokeMyCiToken(id)
      await load()
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.headRow}>
          <div>
            <h2 className={styles.title}>Мои CI-ключи</h2>
            <p className={styles.subtitle}>Создавайте ключи для Jenkins и следите за сканированиями по каждому ключу</p>
          </div>
          <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={() => setModalOpen(true)}>
            + Создать ключ
          </button>
        </div>
        {loading ? (
          <p className={styles.empty}>Загрузка…</p>
        ) : tokens.length === 0 ? (
          <p className={styles.empty}>Ключей пока нет. Создайте ключ или попросите администратора назначить вам.</p>
        ) : (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Метка</th>
                <th>Статус</th>
                <th>Сканов</th>
                <th>Создал</th>
                <th>Последнее использование</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} className={t.status === 'revoked' ? styles.rowMuted : ''}>
                  <td>{t.name}</td>
                  <td>
                    <span className={`${styles.badge} ${t.status === 'active' ? styles.badgeActive : styles.badgeRevoked}`}>
                      {t.status}
                    </span>
                  </td>
                  <td>{t.scanCount}</td>
                  <td>{t.createdByLogin || '—'}</td>
                  <td>{t.lastUsedAt ? new Date(t.lastUsedAt).toLocaleString() : '—'}</td>
                  <td>
                    <div className={styles.actions}>
                      <Link to={`/ci-keys/${t.id}`} className={styles.btn}>Сканы</Link>
                      {t.status === 'active' && (
                        <button type="button" className={`${styles.btn} ${styles.btnDanger}`} onClick={() => revoke(t.id, t.name)}>
                          Отозвать
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {modalOpen && (
        <CreateCiKeyModal scope="self" onClose={() => setModalOpen(false)} onCreated={load} />
      )}
    </div>
  )
}
