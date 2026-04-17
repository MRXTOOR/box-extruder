import { FC } from 'react'
import { Finding, FindingSeverity } from '../../entities/Scan/model/types'
import styles from './FindingCard.module.css'

export interface FindingCardProps {
  finding: Finding
}

const severityLabels: Record<FindingSeverity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
}

export const FindingCard: FC<FindingCardProps> = ({ finding }) => {
  return (
    <div className={`${styles.card} ${styles[finding.severity.toLowerCase()]}`}>
      <div className={styles.header}>
        <h4 className={styles.name}>{finding.name}</h4>
        <span className={`${styles.badge} ${styles[finding.severity.toLowerCase()]}`}>
          {severityLabels[finding.severity]}
        </span>
      </div>
      <p className={styles.description}>{finding.description}</p>
      {finding.evidence && (
        <div className={styles.evidence}>
          <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}