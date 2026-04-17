import { FC } from 'react'
import { Link } from 'react-router-dom'
import { Scan, ScanStatus } from '../../entities/Scan/model/types'
import styles from './ScanTable.module.css'

export interface ScanTableProps {
  scans: Scan[]
  onDelete: (id: string) => void
}

const statusLabels: Record<ScanStatus, string> = {
  QUEUED: 'Queued',
  RUNNING: 'Running',
  SUCCEEDED: 'Succeeded',
  FAILED: 'Failed',
  PARTIAL_SUCCESS: 'Partial',
}

export const ScanTable: FC<ScanTableProps> = ({ scans, onDelete }) => {
  if (scans.length === 0) {
    return (
      <div className={styles.empty}>
        <p>No scans yet. Start your first scan above.</p>
      </div>
    )
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
              <span className={`${styles.status} ${styles[scan.status.toLowerCase()]}`}>
                {statusLabels[scan.status]}
              </span>
            </td>
            <td className={styles.date}>
              {new Date(scan.createdAt).toLocaleString()}
            </td>
            <td>
              <button
                className={styles.deleteBtn}
                onClick={() => onDelete(scan.jobId)}
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}