import { FC, useState } from 'react'
import { Link } from 'react-router-dom'
import { Scan, ScanStatus } from '../../entities/Scan/model/types'
import styles from './ScanTable.module.css'

export interface ScanTableProps {
  scans: Scan[]
  onDelete: (id: string) => void
}

const statusLabels: Record<ScanStatus, string> = {
  QUEUED: 'В очереди',
  RUNNING: 'Выполняется',
  SUCCEEDED: 'Завершён',
  FAILED: 'Ошибка',
  PARTIAL_SUCCESS: 'Частично',
  WAITING_FOR_AUTH: 'Ожидание авторизации',
  PENDING: 'Приостановлен',
  CANCELLED: 'Отменён',
}

function getStatusClass(status: string): string {
  return status.toLowerCase().replace('_', '-')
}

export const ScanTable: FC<ScanTableProps> = ({ scans, onDelete }) => {
  const [downloadTarget, setDownloadTarget] = useState<string | null>(null)

  if (scans.length === 0) {
    return (
      <div className={styles.empty}>
        <p>Нет сохранённых сканов</p>
      </div>
    )
  }

  const handleDownload = (jobId: string) => {
    setDownloadTarget(jobId)
    window.open(`/api/v1/jobs/${jobId}/reports`, '_blank')
  }

  return (
    <table className={styles.table}>
      <thead>
        <tr>
          <th>Target</th>
          <th>Status</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id}>
            <td>
              <Link to={`/scans/${scan.id}`} className={styles.link}>
                {scan.targetUrl}
              </Link>
            </td>
            <td>
              <span className={`${styles.status} ${styles[getStatusClass(scan.status)]}`}>
                {statusLabels[scan.status] || scan.status}
              </span>
            </td>
            <td className={styles.date}>
              {new Date(scan.createdAt).toLocaleDateString('ru-RU', {
                day: '2-digit',
                month: '2-digit',
                year: '2-digit',
              })}
            </td>
            <td>
              <div className={styles.actions}>
                <button
                  className={styles.actionBtn}
                  onClick={() => handleDownload(scan.jobId)}
                  title="Скачать отчёт"
                >
                  📥
                </button>
                <button
                  className={`${styles.actionBtn} ${styles.delete}`}
                  onClick={() => onDelete(scan.jobId)}
                  title="Удалить"
                >
                  🗑
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}