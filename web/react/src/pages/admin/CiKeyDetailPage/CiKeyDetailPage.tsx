import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../../shared/api/api'
import { CiTokenListItem, ScanWithFindingsCount } from '../../../entities/CiToken/model/types'
import { CiKeyScanTable } from '../components/CiKeyScanTable'
import { ScanLogsDrawer } from '../components/ScanLogsDrawer'
import styles from '../Admin.module.css'

export function CiKeyDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [token, setToken] = useState<CiTokenListItem | null>(null)
  const [scans, setScans] = useState<ScanWithFindingsCount[]>([])
  const [tab, setTab] = useState<'info' | 'scans'>('info')
  const [logsScanId, setLogsScanId] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.getCiToken(id).then(setToken).catch(alert)
    api.listCiTokenScans(id).then(setScans).catch(alert)
  }, [id])

  const revoke = async () => {
    if (!id || !token || !confirm('Отозвать ключ?')) return
    await api.revokeCiToken(id)
    setToken(await api.getCiToken(id))
  }

  if (!token) return <p className={styles.empty}>Загрузка…</p>

  return (
    <div className={styles.page}>
      <Link to="/admin/ci-keys" className={styles.backLink}>← CI-ключи</Link>
      <div className={styles.card}>
        <h2 className={styles.title}>{token.name}</h2>
        <div className={styles.tabs}>
          <button type="button" className={`${styles.tab} ${tab === 'info' ? styles.tabActive : ''}`} onClick={() => setTab('info')}>Общие сведения</button>
          <button type="button" className={`${styles.tab} ${tab === 'scans' ? styles.tabActive : ''}`} onClick={() => setTab('scans')}>История сканов</button>
        </div>
        {tab === 'info' && (
          <>
            <p>ID: <code>{token.id}</code></p>
            <p>Статус: {token.status}</p>
            <p>Сервисный пользователь: {token.serviceUserLogin}</p>
            <p>Владелец: {token.ownerLogin || '—'}</p>
            <p>Jenkins credential: <code>{token.jenkinsCredentialId}</code></p>
            <pre className={styles.secretBox}>{`apiTokenCredentialId: '${token.jenkinsCredentialId}'`}</pre>
            {token.status === 'active' && (
              <button type="button" className={`${styles.btn} ${styles.btnDanger}`} onClick={revoke}>Отозвать ключ</button>
            )}
          </>
        )}
        {tab === 'scans' && (
          <CiKeyScanTable scans={scans} onOpenLogs={setLogsScanId} />
        )}
      </div>
      {logsScanId && <ScanLogsDrawer scanId={logsScanId} onClose={() => setLogsScanId(null)} />}
    </div>
  )
}
