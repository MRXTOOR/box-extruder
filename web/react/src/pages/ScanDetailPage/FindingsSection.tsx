import { useMemo, useState } from 'react'
import { Finding } from '../../entities/Scan/model/types'
import { SEVERITY_ORDER } from '../../shared/lib/scanStatus'
import styles from './ScanDetailPage.module.css'

type SeverityFilter = 'ALL' | typeof SEVERITY_ORDER[number]

interface FindingsSectionProps {
  findings: Finding[]
  isRunning: boolean
}

export function FindingsSection({ findings, isRunning }: FindingsSectionProps) {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL')
  const [findingQuery, setFindingQuery] = useState('')

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityFilter, number> = { ALL: findings.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    findings.forEach((finding) => {
      const sev = (finding.severity || 'INFO').toUpperCase() as SeverityFilter
      if (sev in counts && sev !== 'ALL') counts[sev] += 1
    })
    return counts
  }, [findings])

  const filteredFindings = useMemo(() => {
    const query = findingQuery.trim().toLowerCase()
    return findings.filter((finding) => {
      const sev = (finding.severity || 'INFO').toUpperCase() as SeverityFilter
      if (severityFilter !== 'ALL' && sev !== severityFilter) return false
      if (!query) return true
      const name = (finding.name || '').toLowerCase()
      const desc = (finding.description || '').toLowerCase()
      return name.includes(query) || desc.includes(query)
    })
  }, [findings, severityFilter, findingQuery])

  return (
    <section className={styles.card}>
      <div className={styles.findingsHeader}>
        <h3 className={styles.sectionTitle}>Найденные уязвимости ({findings.length})</h3>
        <input
          type="search"
          className={styles.findingSearch}
          placeholder="Поиск по названию/описанию"
          value={findingQuery}
          onChange={(e) => setFindingQuery(e.target.value)}
        />
      </div>
      <div className={styles.severityFilters}>
        {(Object.keys(severityCounts) as SeverityFilter[]).map((severity) => (
          <button
            key={severity}
            type="button"
            className={`${styles.filterChip} ${severityFilter === severity ? styles.active : ''}`}
            onClick={() => setSeverityFilter(severity)}
          >
            {severity === 'ALL' ? 'Все' : severity} ({severityCounts[severity]})
          </button>
        ))}
      </div>
      <div className={styles.findings}>
        {filteredFindings.length === 0 ? (
          <p className={styles.empty}>
            {isRunning ? 'Сканирование продолжается...' : findings.length === 0 ? 'Уязвимости не обнаружены.' : 'Ничего не найдено по текущему фильтру.'}
          </p>
        ) : (
          filteredFindings.map((finding) => (
            <div key={finding.id} className={`${styles.finding} ${styles[finding.severity?.toLowerCase() || 'info']}`}>
              <div className={styles.findingName}>
                {finding.name}
                <span className={`${styles.findingSeverity} ${styles[finding.severity?.toLowerCase() || 'info']}`}>
                  {finding.severity}
                </span>
              </div>
              <p className={styles.findingDesc}>{finding.description}</p>
              {finding.endpointPath && (
                <p className={styles.findingEndpoint}>Endpoint: {finding.endpointPath}</p>
              )}
            </div>
          ))
        )}
      </div>
    </section>
  )
}
