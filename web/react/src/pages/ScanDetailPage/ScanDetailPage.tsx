import { useEffect, useMemo, useState, useRef } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { Scan, Finding, ScanStatus, ScanStatusResponse } from '../../entities/Scan/model/types'
import styles from './ScanDetailPage.module.css'

const statusLabels: Record<ScanStatus, string> = {
  QUEUED: 'В очереди',
  RUNNING: 'Выполняется',
  SUCCEEDED: 'Завершён',
  FAILED: 'Ошибка',
  PARTIAL_SUCCESS: 'Частично',
  WAITING_FOR_AUTH: 'Ожидание авторизации',
  PENDING: 'Приостановлен',
  CANCELLED: 'Отменён',
  CANCELED: 'Отменён',
}

const STEPS = ['Katana', 'ZAP Baseline', 'Nuclei']

const TERMINAL_STATUSES = ['SUCCEEDED', 'FAILED', 'CANCELLED', 'CANCELED', 'PARTIAL_SUCCESS']
const RUNNING_STATUSES = ['QUEUED', 'RUNNING', 'WAITING_FOR_AUTH']
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
type SeverityFilter = 'ALL' | typeof SEVERITY_ORDER[number]

function getStatusClass(status: string): string {
  return status.toLowerCase().replace('_', '-')
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [statusInfo, setStatusInfo] = useState<ScanStatusResponse | null>(null)
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL')
  const [findingQuery, setFindingQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [canceling, setCanceling] = useState(false)
  const [copyingEndpoints, setCopyingEndpoints] = useState(false)
  const [endpointsModalOpen, setEndpointsModalOpen] = useState(false)
  const [endpointsList, setEndpointsList] = useState<string[]>([])
  const [endpointsLoading, setEndpointsLoading] = useState(false)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const endpointsLoadedJobIdRef = useRef<string | null>(null)

  useEffect(() => {
    if (!id) return
    setEndpointsModalOpen(false)
    setEndpointsList([])
    setEndpointsLoading(false)
    setSeverityFilter('ALL')
    setFindingQuery('')
    setStatusInfo(null)
    endpointsLoadedJobIdRef.current = null
    loadData()
    startPolling()
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [id])

  const startPolling = () => {
    if (!id) return
    if (pollingRef.current) clearInterval(pollingRef.current)
    const poll = async () => {
      try {
        const status = await api.getScanStatus(id)
        if (status && typeof status === 'object' && status.status) {
          const typedStatus = status as ScanStatusResponse
          setStatusInfo(typedStatus)
          setScan(prev => prev ? { ...prev, status: typedStatus.status as ScanStatus } : null)
          if (TERMINAL_STATUSES.includes(typedStatus.status)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
          }
        }
      } catch (err) {
        console.error('Polling error:', err)
      }
    }
    poll()
    pollingRef.current = setInterval(poll, 3000)
  }

  const loadData = async () => {
    try {
      const scanData = await api.getScan(id!)
      setScan(scanData)
      setFindings(scanData.findings || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const openEndpointsModal = async (jobId: string) => {
    setEndpointsModalOpen(true)
    if (endpointsLoadedJobIdRef.current === jobId) {
      return
    }
    setEndpointsLoading(true)
    try {
      const eps = await api.getScanEndpoints(jobId)
      setEndpointsList(eps)
      endpointsLoadedJobIdRef.current = jobId
    } catch (err) {
      console.error(err)
      setEndpointsList([])
    } finally {
      setEndpointsLoading(false)
    }
  }

  const closeEndpointsModal = () => {
    setEndpointsModalOpen(false)
  }

  const handleCancel = async () => {
    if (!id || canceling) return
    setCanceling(true)
    const prevStatus = scan?.status
    setScan(prev => prev ? { ...prev, status: 'CANCELLED' as ScanStatus } : null)
    if (pollingRef.current) clearInterval(pollingRef.current)
    try {
      await api.cancelScan(id)
    } catch (err) {
      console.error('Cancel error:', err)
      if (prevStatus) {
        setScan(prev => prev ? { ...prev, status: prevStatus } : null)
      }
      startPolling()
    } finally {
      setCanceling(false)
    }
  }

  const handleRestart = async () => {
    if (!id) return
    try {
      const newScan = await api.restartScan(id)
      navigate(`/scans/${newScan.id}`)
    } catch (err) {
      console.error('Restart error:', err)
    }
  }

  const severityCounts = useMemo(() => {
    const counts: Record<SeverityFilter, number> = {
      ALL: findings.length,
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    }
    findings.forEach((finding) => {
      const sev = (finding.severity || 'INFO').toUpperCase() as SeverityFilter
      if (sev in counts && sev !== 'ALL') {
        counts[sev] += 1
      }
    })
    return counts
  }, [findings])

  const filteredFindings = useMemo(() => {
    const query = findingQuery.trim().toLowerCase()
    return findings.filter((finding) => {
      const sev = (finding.severity || 'INFO').toUpperCase() as SeverityFilter
      const bySeverity = severityFilter === 'ALL' || sev === severityFilter
      if (!bySeverity) return false
      if (!query) return true
      const name = (finding.name || '').toLowerCase()
      const desc = (finding.description || '').toLowerCase()
      return name.includes(query) || desc.includes(query)
    })
  }, [findings, severityFilter, findingQuery])

  const stepItems = useMemo(() => {
    const steps = statusInfo?.steps || []
    if (steps.length === 0) {
      return STEPS.map((name) => ({ label: name, status: 'PENDING', kind: 'pending' }))
    }
    const seenNuclei = { count: 0 }
    return steps.map((step) => {
      const rawType = step.stepType || 'step'
      let label = rawType
      if (rawType === 'katana') label = 'Katana'
      if (rawType === 'zapBaseline') label = 'ZAP Baseline'
      if (rawType === 'nucleiTemplates' || rawType === 'nucleiCLI') {
        seenNuclei.count += 1
        label = seenNuclei.count > 1 ? `Nuclei #${seenNuclei.count}` : 'Nuclei'
      }
      const st = (step.status || 'PENDING').toUpperCase()
      const kind =
        st === 'SUCCEEDED' ? 'done' :
        st === 'RUNNING' ? 'active' :
        st === 'FAILED' ? 'failed' :
        st === 'SKIPPED' ? 'skipped' : 'pending'
      return { label, status: st, kind }
    })
  }, [statusInfo])

  const isTerminal = !!(scan?.status && TERMINAL_STATUSES.includes(scan.status))
  const isRunning = !!(scan?.status && RUNNING_STATUSES.includes(scan.status))

  const copyEndpointsToClipboard = async () => {
    if (!endpointsList.length || copyingEndpoints) return
    try {
      setCopyingEndpoints(true)
      await navigator.clipboard.writeText(endpointsList.join('\n'))
    } catch (err) {
      console.error('Clipboard error:', err)
    } finally {
      setCopyingEndpoints(false)
    }
  }

  const handleReportDownload = async (jobId: string, format: 'md' | 'html' | 'docx') => {
    try {
      const { blob, filename, contentType } = await api.getReport(jobId, format)
      const url = URL.createObjectURL(blob)
      if (contentType.includes('text/html')) {
        window.open(url, '_blank')
      } else {
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        a.remove()
      }
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      console.error(err)
    }
  }

  const handleEndpointsTextOpen = async (jobId: string) => {
    try {
      const { blob } = await api.getReport(jobId, 'endpoints')
      const url = URL.createObjectURL(blob)
      window.open(url, '_blank')
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      console.error(err)
    }
  }

  if (loading) return <div className={styles.loading}>Загрузка...</div>
  if (!scan) return <div className={styles.error}>Скан не найден</div>

  return (
    <div className={styles.page}>
      <Link to="/" className={styles.back}>← Назад к сканам</Link>
      
      <div className={styles.card}>
        <div className={styles.header}>
          <div>
            <h2 className={styles.target}>{scan.targetUrl}</h2>
            <div className={styles.meta}>
              <span className={`${styles.status} ${styles[getStatusClass(scan.status)]}`}>
                {statusLabels[scan.status] || scan.status}
              </span>
              <span className={styles.date} style={{ color: 'var(--dim)', fontSize: '0.8rem' }}>
                {new Date(scan.createdAt).toLocaleString('ru-RU')}
              </span>
            </div>
          </div>
          <div className={styles.actions}>
            {isRunning && (
              <button 
                className={styles.btnCancel} 
                onClick={handleCancel}
                disabled={canceling}
              >
                {canceling ? 'Отмена...' : 'Отменить'}
              </button>
            )}
            {isTerminal && (
              <button className={styles.btnRestart} onClick={handleRestart}>
                Перезапустить
              </button>
            )}
          </div>
        </div>

        {isRunning && (
          <div className={styles.steps}>
            {stepItems.map((step, idx) => (
              <div key={`${step.label}-${idx}`} className={`${styles.step} ${styles[step.kind]}`}>
                <div className={styles.stepDot}>
                  {step.kind === 'done' ? '✓' : step.kind === 'active' ? '●' : step.kind === 'failed' ? '✕' : step.kind === 'skipped' ? '⤼' : '○'}
                </div>
                <div className={styles.stepInfo}>
                  <span className={styles.stepLabel}>{step.label}</span>
                  <span className={styles.stepStatus}>{step.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
        
        <div className={styles.resources}>
          <div className={styles.resourcesGroup}>
            <span className={styles.resourcesLabel}>Отчёт</span>
            <button className={styles.resourceBtn} type="button" onClick={() => handleReportDownload(scan.jobId || scan.id, 'md')}>MD</button>
            <button className={styles.resourceBtn} type="button" onClick={() => handleReportDownload(scan.jobId || scan.id, 'html')}>HTML</button>
            <button className={styles.resourceBtn} type="button" onClick={() => handleReportDownload(scan.jobId || scan.id, 'docx')}>DOCX</button>
          </div>
          <div className={styles.resourcesGroup}>
            <span className={styles.resourcesLabel}>Эндпоинты</span>
            <button className={styles.resourceBtn} type="button" onClick={() => handleEndpointsTextOpen(scan.jobId || scan.id)}>TXT</button>
            <button className={styles.resourceBtn} type="button" onClick={() => openEndpointsModal(scan.jobId || scan.id)}>Просмотр</button>
          </div>
        </div>
      </div>

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
              </div>
            ))
          )}
        </div>
      </section>

      <div
        className={`${styles.modalOverlay} ${!endpointsModalOpen ? styles.modalHidden : ''}`}
        aria-hidden={!endpointsModalOpen}
        onClick={closeEndpointsModal}
      >
        <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
          <div className={styles.modalHeader}>
            <h3>Просканированные эндпоинты ({endpointsList.length})</h3>
            <button type="button" className={styles.btnClose} onClick={closeEndpointsModal}>&times;</button>
          </div>
          <div className={styles.modalBody}>
            {endpointsLoading ? (
              <p>Загрузка...</p>
            ) : endpointsList.length > 0 ? (
              <>
                <div className={styles.endpointsActions}>
                  <button
                    type="button"
                    className={styles.resourceBtn}
                    onClick={copyEndpointsToClipboard}
                    disabled={copyingEndpoints}
                  >
                    {copyingEndpoints ? 'Копирование...' : 'Скопировать список'}
                  </button>
                </div>
                <pre className={styles.endpointsList}>{endpointsList.join('\n')}</pre>
              </>
            ) : (
              <p>Эндпоинты не найдены</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}