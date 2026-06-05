import {
  Download,
  List,
  Loader2,
  RefreshCw,
  Square,
  Trash2,
} from 'lucide-react'
import { Scan } from '../../entities/Scan/model/types'
import { getStatusClass } from '../../shared/lib/scanStatus'
import { ScanStatusBadge } from '../../shared/ui/ScanStatusBadge'
import styles from './ScansPage.module.css'

interface ScanHistorySidebarProps {
  scans: Scan[]
  loading: boolean
  refreshing: boolean
  cancelingIds: Set<string>
  onRefresh: () => void
  onView: (jobId: string) => void
  onCancel: (jobId: string, e: React.MouseEvent) => void
  onDownload: (jobId: string) => void
  onViewEndpoints: (jobId: string) => void
  onDelete: (jobId: string) => void
}

const RUNNING = ['QUEUED', 'RUNNING', 'WAITING_FOR_AUTH']

export function ScanHistorySidebar(props: ScanHistorySidebarProps) {
  const { scans, loading, refreshing, cancelingIds } = props

  return (
    <aside className={styles.sidebar}>
      <div className={styles.sidebarHeader}>
        <h3 className={styles.sidebarTitle}>История сканов</h3>
        <button
          className={`${styles.btnRefresh} ${refreshing ? styles.btnRefreshSpinning : ''}`}
          onClick={props.onRefresh}
          title="Обновить список"
          disabled={refreshing}
          type="button"
          aria-label="Обновить список"
        >
          <RefreshCw className={styles.uiIcon} size={18} strokeWidth={2} aria-hidden />
        </button>
      </div>
      <div className={styles.jobsList}>
        {loading ? (
          <div className={styles.jobsLoading}>Загрузка...</div>
        ) : scans.length === 0 ? (
          <div className={styles.jobsEmpty}>Нет сохранённых сканов</div>
        ) : (
          scans.map((scan) => {
            const jobId = scan.jobId || scan.id
            const canceling = cancelingIds.has(jobId)
            return (
              <div
                key={scan.id}
                className={styles.jobCard}
                onClick={() => props.onView(jobId)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    props.onView(jobId)
                  }
                }}
                role="button"
                tabIndex={0}
              >
                <div className={styles.jobCardHeader}>
                  <span className={styles.jobCardId}>#{jobId?.substring(0, 8)}</span>
                  <ScanStatusBadge
                    status={scan.status}
                    className={`${styles.jobStatusBadge} ${styles[getStatusClass(scan.status)]}`}
                  />
                </div>
                <div className={styles.jobCardTarget} title={scan.targetUrl}>{scan.targetUrl}</div>
                <div className={styles.jobCardDate}>
                  {new Date(scan.createdAt).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit' })}
                </div>
                <div className={styles.jobCardActions}>
                  {RUNNING.includes(scan.status) && (
                    <button
                      type="button"
                      className={styles.btnJobAction}
                      onClick={(e) => props.onCancel(jobId, e)}
                      disabled={canceling}
                      title="Отменить"
                    >
                      <span className={styles.actionIcon} aria-hidden>
                        {canceling ? (
                          <Loader2 className={`${styles.uiIcon} ${styles.spinIcon}`} size={16} strokeWidth={2} />
                        ) : (
                          <Square className={styles.uiIcon} size={16} strokeWidth={2} />
                        )}
                      </span>
                      <span className={styles.actionText}>Стоп</span>
                    </button>
                  )}
                  <button
                    type="button"
                    className={styles.btnJobAction}
                    onClick={(e) => { e.stopPropagation(); props.onDownload(jobId) }}
                    title="Скачать отчёт"
                  >
                    <span className={styles.actionIcon} aria-hidden>
                      <Download className={styles.uiIcon} size={16} strokeWidth={2} />
                    </span>
                    <span className={styles.actionText}>Отчёт</span>
                  </button>
                  <button
                    type="button"
                    className={styles.btnJobAction}
                    onClick={(e) => { e.stopPropagation(); props.onViewEndpoints(jobId) }}
                    title="Эндпоинты"
                  >
                    <span className={styles.actionIcon} aria-hidden>
                      <List className={styles.uiIcon} size={16} strokeWidth={2} />
                    </span>
                    <span className={styles.actionText}>URL</span>
                  </button>
                  <button
                    type="button"
                    className={`${styles.btnJobAction} ${styles.delete}`}
                    onClick={(e) => { e.stopPropagation(); props.onDelete(jobId) }}
                    title="Удалить"
                  >
                    <span className={styles.actionIcon} aria-hidden>
                      <Trash2 className={styles.uiIcon} size={16} strokeWidth={2} />
                    </span>
                    <span className={styles.actionText}>Удалить</span>
                  </button>
                </div>
              </div>
            )
          })
        )}
      </div>
    </aside>
  )
}
