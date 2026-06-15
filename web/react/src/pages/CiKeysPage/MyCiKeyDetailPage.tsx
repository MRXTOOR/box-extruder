import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { CiTokenListItem, ScanWithFindingsCount } from '../../entities/CiToken/model/types'
import { CiKeyScanTable } from '../admin/components/CiKeyScanTable'
import { ScanLogsDrawer } from '../admin/components/ScanLogsDrawer'
import styles from '../admin/Admin.module.css'

export function MyCiKeyDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [token, setToken] = useState<CiTokenListItem | null>(null)
  const [scans, setScans] = useState<ScanWithFindingsCount[]>([])
  const [logsScanId, setLogsScanId] = useState<string | null>(null)

  const refresh = async () => {
    if (!id) return
    setToken(await api.getMyCiToken(id))
    setScans(await api.listMyCiTokenScans(id))
  }

  useEffect(() => {
    refresh().catch(alert)
    const t = setInterval(refresh, 15000)
    return () => clearInterval(t)
  }, [id])

  if (!token) return <p className={styles.empty}>Загрузка…</p>

  return (
    <div className={styles.page}>
      <Link to="/ci-keys" className={styles.backLink}>← Мои ключи</Link>
      <div className={styles.card}>
        <h2 className={styles.title}>{token.name}</h2>
        <p className={styles.subtitle}>
          Статус: {token.status} · сканов: {token.scanCount}
          {token.createdByLogin && ` · создан: ${token.createdByLogin}`}
        </p>
        <CiKeyScanTable scans={scans} onOpenLogs={setLogsScanId} />
      </div>
      {logsScanId && <ScanLogsDrawer scanId={logsScanId} onClose={() => setLogsScanId(null)} />}
    </div>
  )
}
