import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanForm, ScanConfig } from '../../widgets/ScanForm/ScanForm'
import { api } from '../../shared/api/api'
import { Scan } from '../../entities/Scan/model/types'
import styles from './ScansPage.module.css'

const statusLabels: Record<string, string> = {
  SUCCEEDED: '✓ Завершён',
  FAILED: '✗ Ошибка',
  PARTIAL_SUCCESS: '⚠ Частично',
  RUNNING: '▶ Выполняется',
  QUEUED: '⏳ В очереди',
  WAITING_FOR_AUTH: '🔐 Ожидание авторизации',
  PENDING: '⏸ Приостановлен',
  CANCELLED: '🚫 Отменён',
}

function getStatusClass(status: string): string {
  return status.toLowerCase().replace('_', '-')
}

export function ScansPage() {
  const navigate = useNavigate()
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [autoDetectStatus, setAutoDetectStatus] = useState<'idle' | 'pending' | 'ok' | 'fail'>('idle')
  const [currentJobStatus, setCurrentJobStatus] = useState<string>('Нет активной задачи')
  const [currentJobKind, setCurrentJobKind] = useState<string>('')
  const [currentJobId, setCurrentJobId] = useState<string | null>(null)
  const [detectOpen, setDetectOpen] = useState(true)
  const [jobOpen, setJobOpen] = useState(true)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    loadScans()
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  const startStatusPolling = (jobId: string) => {
    setCurrentJobId(jobId)
    setCurrentJobStatus('Запуск...')
    setCurrentJobKind('run')
    
    if (pollingRef.current) clearInterval(pollingRef.current)
    
    pollingRef.current = setInterval(async () => {
      try {
        const status = await api.getScanStatus(jobId)
        if (status) {
          setCurrentJobStatus(typeof status === 'object' ? JSON.stringify(status, null, 2) : String(status))
          
          const statusStr = typeof status === 'object' ? status.status : String(status)
          const kind = statusKind(statusStr)
          setCurrentJobKind(kind)
          
          if (['SUCCEEDED', 'FAILED', 'PARTIAL_SUCCESS', 'CANCELLED'].includes(statusStr)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
            setAutoDetectStatus(statusStr === 'SUCCEEDED' ? 'ok' : statusStr === 'FAILED' ? 'fail' : 'idle')
          }
        }
      } catch (err) {
        console.error('Status polling error:', err)
      }
    }, 3000)
  }

  const statusKind = (st: string): string => {
    if (st === 'SUCCEEDED') return 'ok'
    if (st === 'FAILED') return 'bad'
    if (st === 'PARTIAL_SUCCESS') return 'partial'
    if (st === 'QUEUED' || st === 'RUNNING') return 'run'
    return ''
  }

  const loadScans = async () => {
    try {
      const data = await api.getScans()
      setScans(data || [])
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateScan = async (targetUrl: string, config?: ScanConfig) => {
    setAutoDetectStatus('pending')
    try {
      const scan = await api.createScan({ targetUrl, ...config })
      if (scan && scan.jobId) {
        setAutoDetectStatus('ok')
        loadScans()
        startStatusPolling(scan.jobId || scan.id)
      } else {
        setAutoDetectStatus('fail')
      }
    } catch (err) {
      console.error(err)
      setAutoDetectStatus('fail')
    }
  }

  const handleDeleteScan = async (jobId: string) => {
    await api.deleteScan(jobId)
    loadScans()
  }

  const handleDownload = (jobId: string) => {
    window.open(`/api/v1/scans/${jobId}/reports`, '_blank')
  }

  const handleViewEndpoints = (jobId: string) => {
    window.open(`/api/v1/scans/${jobId}/endpoints`, '_blank')
  }

  const handleViewScan = (jobId: string) => {
    navigate(`/scans/${jobId}`)
  }

  const handleCancelScan = async (jobId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await api.cancelScan(jobId)
      loadScans()
    } catch (err) {
      console.error('Cancel error:', err)
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.pageInner}>
        <div className={styles.mainContent}>
          <section className={styles.card} aria-labelledby="card-scan">
            <p className={styles.cardHead} id="card-scan">Настройка цели</p>
            <ScanForm onSubmit={handleCreateScan} />
          </section>

          <section className={styles.card}>
            <div className={styles.sectionTitleWrap}>
              <p className={styles.cardHead}>Автодетект</p>
              <button 
                className={`${styles.btnToggle} ${!detectOpen ? styles.collapsed : ''}`}
                onClick={() => setDetectOpen(!detectOpen)}
              >
                {detectOpen ? '−' : '+'}
              </button>
            </div>
            {detectOpen && (
              <div className={styles.detectContent}>
                <div className={styles.badgeRow}>
                  <span className={`${styles.badge} ${autoDetectStatus === 'idle' ? 'idle' : autoDetectStatus === 'pending' ? 'idle' : autoDetectStatus}`}>
                    <span className={styles.icon}>
                      {autoDetectStatus === 'idle' ? '○' : autoDetectStatus === 'pending' ? '…' : autoDetectStatus === 'ok' ? '✓' : '✕'}
                    </span>
                    {autoDetectStatus === 'idle' ? 'не запускался' : autoDetectStatus === 'pending' ? 'проверка…' : autoDetectStatus === 'ok' ? 'успех' : 'не удался'}
                  </span>
                </div>
              </div>
            )}
          </section>

          <section className={styles.card}>
            <div className={styles.sectionTitleWrap}>
              <h2 className={styles.sectionTitle}>Задача</h2>
              <button 
                className={`${styles.btnToggle} ${!jobOpen ? styles.collapsed : ''}`}
                onClick={() => setJobOpen(!jobOpen)}
              >
                {jobOpen ? '−' : '+'}
              </button>
            </div>
            {jobOpen && (
              <div className={styles.jobStatusWrapper}>
                <pre className={`${styles.jobStatus} ${styles[currentJobKind]}`}>{currentJobStatus}</pre>
                {currentJobId && (
                  <div className={styles.links}>
                    <a href={`/api/v1/scans/${currentJobId}/reports`} target="_blank" rel="noopener">Отчёт markdown</a>
                    <a href={`/api/v1/scans/${currentJobId}/reports?format=docx`} target="_blank" rel="noopener">Отчёт DOCX / HTML</a>
                    <a href={`/api/v1/scans/${currentJobId}/events`} target="_blank" rel="noopener">События JSONL</a>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>

        <aside className={styles.sidebar}>
          <div className={styles.sidebarHeader}>
            <h3 className={styles.sidebarTitle}>История сканов</h3>
            <button className={styles.btnRefresh} onClick={loadScans} title="Обновить список">↻</button>
          </div>
          <div className={styles.jobsList}>
            {loading ? (
              <div className={styles.jobsLoading}>Загрузка...</div>
            ) : scans.length === 0 ? (
              <div className={styles.jobsEmpty}>Нет сохранённых сканов</div>
            ) : (
              scans.map((scan) => (
                <div 
                  key={scan.id} 
                  className={styles.jobCard}
                  onClick={() => handleViewScan(scan.jobId || scan.id)}
                >
                  <div className={styles.jobCardHeader}>
                    <span className={styles.jobCardId}>#{scan.jobId?.substring(0, 8) || scan.id?.substring(0, 8)}</span>
                    <span className={`${styles.jobStatusBadge} ${styles[getStatusClass(scan.status)]}`}>
                      {statusLabels[scan.status] || scan.status}
                    </span>
                  </div>
                  <div className={styles.jobCardTarget} title={scan.targetUrl}>{scan.targetUrl}</div>
                  <div className={styles.jobCardDate}>
                    {new Date(scan.createdAt).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit' })}
                  </div>
                  <div className={styles.jobCardActions}>
                    {['QUEUED', 'RUNNING'].includes(scan.status) && (
                      <button 
                        className={styles.btnJobAction}
                        onClick={(e) => handleCancelScan(scan.jobId || scan.id, e)}
                        title="Отменить"
                      >
                        ⏹
                      </button>
                    )}
                    <button 
                      className={styles.btnJobAction}
                      onClick={(e) => { e.stopPropagation(); handleDownload(scan.jobId || scan.id) }}
                      title="Скачать отчёт"
                    >
                      📥
                    </button>
                    <button 
                      className={styles.btnJobAction}
                      onClick={(e) => { e.stopPropagation(); handleViewEndpoints(scan.jobId || scan.id) }}
                      title="Эндпоинты"
                    >
                      📋
                    </button>
                    <button 
                      className={`${styles.btnJobAction} ${styles.delete}`}
                      onClick={(e) => { e.stopPropagation(); handleDeleteScan(scan.jobId || scan.id) }}
                      title="Удалить"
                    >
                      🗑
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </aside>
      </div>
    </div>
  )
}