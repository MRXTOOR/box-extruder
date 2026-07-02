import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../../shared/api/api'
import { Finding } from '../../entities/Scan/model/types'
import { SEVERITY_ORDER } from '../../shared/lib/scanStatus'
import styles from './ScanDetailPage.module.css'

type SeverityFilter = 'ALL' | typeof SEVERITY_ORDER[number]

const PAGE_SIZE = 50

interface FindingsSectionProps {
  scanId: string
  totalHint?: number
  isRunning: boolean
}

export function FindingsSection({ scanId, totalHint, isRunning }: FindingsSectionProps) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [total, setTotal] = useState(totalHint ?? 0)
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL')
  const [findingQuery, setFindingQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(findingQuery.trim()), 300)
    return () => clearTimeout(t)
  }, [findingQuery])

  useEffect(() => {
    setPage(1)
  }, [severityFilter, debouncedQuery])

  const loadCounts = useCallback(async () => {
    try {
      const counts = await api.getScanFindingsCounts(scanId)
      setSeverityCounts(counts)
      if (counts.ALL != null) setTotal(counts.ALL)
    } catch (err) {
      console.error(err)
    }
  }, [scanId])

  const loadFindings = useCallback(async () => {
    setLoading(true)
    try {
      const offset = (page - 1) * PAGE_SIZE
      const res = await api.getScanFindings(scanId, {
        limit: PAGE_SIZE,
        offset,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        q: debouncedQuery || undefined,
      })
      setFindings(res.items || [])
      setTotal(res.total ?? 0)
    } catch (err) {
      console.error(err)
      setFindings([])
    } finally {
      setLoading(false)
    }
  }, [scanId, page, severityFilter, debouncedQuery])

  useEffect(() => {
    loadCounts()
  }, [loadCounts, isRunning])

  useEffect(() => {
    loadFindings()
  }, [loadFindings, isRunning])

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const chipCounts = useMemo(() => {
    const counts: Record<SeverityFilter, number> = {
      ALL: severityCounts.ALL ?? total,
      CRITICAL: severityCounts.CRITICAL ?? 0,
      HIGH: severityCounts.HIGH ?? 0,
      MEDIUM: severityCounts.MEDIUM ?? 0,
      LOW: severityCounts.LOW ?? 0,
      INFO: severityCounts.INFO ?? 0,
    }
    return counts
  }, [severityCounts, total])

  return (
    <section className={styles.card}>
      <div className={styles.findingsHeader}>
        <h3 className={styles.sectionTitle}>Найденные уязвимости ({total})</h3>
        <input
          type="search"
          className={styles.findingSearch}
          placeholder="Поиск по названию/описанию"
          value={findingQuery}
          onChange={(e) => setFindingQuery(e.target.value)}
        />
      </div>
      <div className={styles.severityFilters}>
        {(Object.keys(chipCounts) as SeverityFilter[]).map((severity) => (
          <button
            key={severity}
            type="button"
            className={`${styles.filterChip} ${severityFilter === severity ? styles.active : ''}`}
            onClick={() => setSeverityFilter(severity)}
          >
            {severity === 'ALL' ? 'Все' : severity} ({chipCounts[severity]})
          </button>
        ))}
      </div>
      <div className={styles.findings}>
        {loading ? (
          <p className={styles.empty}>Загрузка...</p>
        ) : findings.length === 0 ? (
          <p className={styles.empty}>
            {isRunning ? 'Сканирование продолжается...' : total === 0 ? 'Уязвимости не обнаружены.' : 'Ничего не найдено по текущему фильтру.'}
          </p>
        ) : (
          findings.map((finding) => (
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
      {pageCount > 1 && (
        <div className={styles.pagination}>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            ←
          </button>
          <span className={styles.pageInfo}>
            {page} / {pageCount}
          </span>
          <button
            type="button"
            className={styles.pageBtn}
            disabled={page >= pageCount}
            onClick={() => setPage((p) => Math.min(pageCount, p + 1))}
          >
            →
          </button>
        </div>
      )}
    </section>
  )
}
