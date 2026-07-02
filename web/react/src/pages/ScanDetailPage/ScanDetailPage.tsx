import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { isTerminalStatus, isRunningStatus } from '../../shared/lib/scanStatus'
import { useScanDetail } from './useScanDetail'
import { ScanDetailHeader } from './ScanDetailHeader'
import { FindingsSection } from './FindingsSection'
import { EndpointsModal } from './EndpointsModal'
import styles from './ScanDetailPage.module.css'

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { scan, statusInfo, referenceDurationSeconds, loading, canceling, handleCancel, handleRestart } = useScanDetail(id)
  const [endpointsOpen, setEndpointsOpen] = useState(false)

  if (loading) return <div className={styles.loading}>Загрузка...</div>
  if (!scan) return <div className={styles.error}>Скан не найден</div>

  const isTerminal = isTerminalStatus(scan.status)
  const isRunning = isRunningStatus(scan.status)
  const jobId = scan.jobId || scan.id

  return (
    <div className={styles.page}>
      <Link to="/" className={styles.back}>← Назад к сканам</Link>

      <ScanDetailHeader
        scan={scan}
        statusInfo={statusInfo}
        referenceDurationSeconds={referenceDurationSeconds}
        isRunning={isRunning}
        isTerminal={isTerminal}
        canceling={canceling}
        onCancel={handleCancel}
        onRestart={handleRestart}
        onOpenEndpoints={() => setEndpointsOpen(true)}
      />

      <FindingsSection
        key={`${scan.status}-${scan.finishedAt ?? ''}`}
        scanId={id || ''}
        totalHint={scan.findingsCount}
        isRunning={isRunning}
      />

      <EndpointsModal open={endpointsOpen} jobId={jobId} onClose={() => setEndpointsOpen(false)} />
    </div>
  )
}
