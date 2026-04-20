import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanForm, ScanConfig } from '../../widgets/ScanForm/ScanForm'
import { api } from '../../shared/api/api'
import { Scan, ScanStatusResponse } from '../../entities/Scan/model/types'
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
  const [downloadModalOpen, setDownloadModalOpen] = useState(false)
  const [downloadTargetJobId, setDownloadTargetJobId] = useState<string | null>(null)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    loadScans()
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const formatStatus = (status: ScanStatusResponse): string => {
    const lines: string[] = []
    lines.push(`Статус: ${statusLabels[status.status] || status.status}`)
    if (status.elapsedSeconds !== undefined) {
      lines.push(`Время: ${formatTime(status.elapsedSeconds)}`)
    }
    if (status.totalSteps && status.totalSteps > 0) {
      lines.push(`Прогресс: ${status.completedSteps}/${status.totalSteps} (${status.progress}%)`)
      if (status.steps && status.steps.length > 0) {
        lines.push('')
        status.steps.forEach((step, i) => {
          const stepName = step.stepType === 'katana' ? 'Katana' :
                        step.stepType === 'zapBaseline' ? 'ZAP' :
                        step.stepType === 'nucleiCLI' ? 'Nuclei' : step.stepType
          const stepStatus = step.status === 'SUCCEEDED' ? '✓' :
                            step.status === 'RUNNING' ? '…' :
                            step.status === 'FAILED' ? '✗' : '-'
          lines.push(`  ${stepStatus} ${stepName}`)
        })
      }
    }
    return lines.join('\n')
  }

  const startStatusPolling = (jobId: string) => {
    setCurrentJobId(jobId)
    setCurrentJobStatus('Запуск...')
    setCurrentJobKind('run')
    
    if (pollingRef.current) clearInterval(pollingRef.current)
    
    pollingRef.current = setInterval(async () => {
      try {
        const status = await api.getScanStatus(jobId)
        if (status && typeof status === 'object' && 'status' in status) {
          const typedStatus = status as ScanStatusResponse
          setCurrentJobStatus(formatStatus(typedStatus))
          
          const statusStr = typedStatus.status
          const kind = statusKind(statusStr)
          setCurrentJobKind(kind)
          
          if (['SUCCEEDED', 'FAILED', 'PARTIAL_SUCCESS', 'CANCELLED'].includes(statusStr)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
            setAutoDetectStatus(statusStr === 'SUCCEEDED' ? 'ok' : statusStr === 'FAILED' ? 'fail' : 'idle')
          }
        } else {
          setCurrentJobStatus(typeof status === 'object' ? JSON.stringify(status, null, 2) : String(status))
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
      const jobId = scan.jobId || scan.id
      if (jobId) {
        setAutoDetectStatus('ok')
        loadScans()
        startStatusPolling(jobId)
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

  const handleDownload = (jobId: string, format: string = 'md') => {
    window.open(`/api/v1/scans/${jobId}/reports?format=${format}`, '_blank')
  }

  const openDownloadModal = (jobId: string) => {
    setDownloadTargetJobId(jobId)
    setDownloadModalOpen(true)
  }

  const closeDownloadModal = () => {
    setDownloadModalOpen(false)
    setDownloadTargetJobId(null)
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
                    <a href={`/api/v1/scans/${currentJobId}/reports?format=md`} target="_blank" rel="noopener">Markdown</a>
                    <a href={`/api/v1/scans/${currentJobId}/reports?format=html`} target="_blank" rel="noopener">HTML</a>
                    <a href={`/api/v1/scans/${currentJobId}/reports?format=docx`} target="_blank" rel="noopener">DOCX</a>
                    <a href={`/api/v1/scans/${currentJobId}/events`} target="_blank" rel="noopener">JSONL</a>
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
                      onClick={(e) => { e.stopPropagation(); openDownloadModal(scan.jobId || scan.id) }}
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

      {downloadModalOpen && (
        <div className={styles.modalOverlay} onClick={closeDownloadModal}>
          <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            <div className={styles.modalHeader}>
              <h3>Скачать отчёт</h3>
              <button className={styles.btnClose} onClick={closeDownloadModal}>&times;</button>
            </div>
            <div className={styles.modalBody}>
              <div className={styles.downloadJobId}>#{downloadTargetJobId?.substring(0, 8)}</div>
              <div className={styles.downloadFormats}>
                <button className={styles.btnFormat} onClick={() => { handleDownload(downloadTargetJobId!, 'docx'); closeDownloadModal() }}>
                  <span className={styles.formatIcon}>📝</span>
                  <span className={styles.formatName}>Word (DOCX)</span>
                  <span className={styles.formatDesc}>Документ Word</span>
                </button>
                <button className={styles.btnFormat} onClick={() => { handleDownload(downloadTargetJobId!, 'md'); closeDownloadModal() }}>
                  <span className={styles.formatIcon}>📄</span>
                  <span className={styles.formatName}>Markdown</span>
                  <span className={styles.formatDesc}>.md файл</span>
                </button>
                <button className={styles.btnFormat} onClick={() => { handleDownload(downloadTargetJobId!, 'html'); closeDownloadModal() }}>
                  <span className={styles.formatIcon}>🌐</span>
                  <span className={styles.formatName}>HTML</span>
                  <span className={styles.formatDesc}>Красивый веб-отчёт</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}