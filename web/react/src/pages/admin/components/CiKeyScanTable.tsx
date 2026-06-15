import { Link } from 'react-router-dom'
import { ScanWithFindingsCount } from '../../../entities/CiToken/model/types'
import { isCiScan } from '../../../shared/lib/scanStatus'
import { ScanStatusBadge } from '../../../shared/ui/ScanStatusBadge'
import { downloadReport, downloadScanDump } from '../../../shared/lib/download'
import styles from '../Admin.module.css'

interface Props {
  scans: ScanWithFindingsCount[]
  onOpenLogs: (scanId: string) => void
  scanLinkPrefix?: string
}

export function CiKeyScanTable({ scans, onOpenLogs, scanLinkPrefix = '/scans/' }: Props) {
  if (scans.length === 0) {
    return <p className={styles.empty}>Сканов пока нет</p>
  }

  return (
    <table className={styles.table}>
      <thead>
        <tr>
          <th>Цель</th>
          <th>Статус</th>
          <th>Начало</th>
          <th>Находки</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {scans.map((s) => (
          <tr key={s.id}>
            <td>{s.targetUrl}</td>
            <td>
              <span className={styles.statusCell}>
                {isCiScan(s) && <span className={styles.ciBadge}>CI</span>}
                <ScanStatusBadge status={s.status} />
              </span>
            </td>
            <td>{new Date(s.createdAt).toLocaleString()}</td>
            <td>{s.findingsCount}</td>
            <td>
              <div className={styles.actions}>
                <Link to={`${scanLinkPrefix}${s.jobId}`} className={styles.btn}>Детали</Link>
                <button type="button" className={styles.btn} onClick={() => onOpenLogs(s.jobId)}>Журнал</button>
                <button type="button" className={styles.btn} onClick={() => downloadScanDump(s.jobId).catch(alert)}>Дамп</button>
                <button type="button" className={styles.btn} onClick={() => downloadReport(s.jobId, 'docx').catch(alert)}>Отчёт</button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
