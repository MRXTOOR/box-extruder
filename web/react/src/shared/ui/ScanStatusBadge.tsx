import { statusLabelsPlain } from '../lib/scanStatus'
import { scanStatusIcon } from './scanStatusIcons'
import styles from './ScanStatusBadge.module.css'

interface ScanStatusBadgeProps {
  status: string
  className?: string
}

export function ScanStatusBadge({ status, className = '' }: ScanStatusBadgeProps) {
  const Icon = scanStatusIcon(status)
  const label = statusLabelsPlain[status] ?? status
  return (
    <span className={`${styles.badge} ${className}`.trim()}>
      <Icon className={styles.icon} size={14} strokeWidth={2} aria-hidden />
      <span>{label}</span>
    </span>
  )
}
