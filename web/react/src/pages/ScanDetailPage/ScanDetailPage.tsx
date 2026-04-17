import { useEffect, useState, useRef } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { Scan, Finding, ScanStatus } from '../../entities/Scan/model/types'
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
}

const STEPS = ['Katana', 'ZAP Baseline', 'Nuclei']

function getStatusClass(status: string): string {
  return status.toLowerCase().replace('_', '-')
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [canceling, setCanceling] = useState(false)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!id) return
    loadData()
    startPolling()
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [id])

  const startPolling = () => {
    if (pollingRef.current) clearInterval(pollingRef.current)
    pollingRef.current = setInterval(async () => {
      try {
        const status = await api.getScanStatus(id!)
        if (status && typeof status === 'object' && status.status) {
          setScan(prev => prev ? { ...prev, status: status.status as ScanStatus } : null)
          if (['SUCCEEDED', 'FAILED', 'CANCELLED', 'PARTIAL_SUCCESS'].includes(status.status)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
          }
        }
      } catch (err) {
        console.error('Polling error:', err)
      }
    }, 3000)
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

  const handleCancel = async () => {
    if (!id || canceling) return
    setCanceling(true)
    try {
      await api.cancelScan(id)
      setScan(prev => prev ? { ...prev, status: 'CANCELLED' as ScanStatus } : null)
      if (pollingRef.current) clearInterval(pollingRef.current)
    } catch (err) {
      console.error('Cancel error:', err)
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

  const isTerminal = scan?.status && ['SUCCEEDED', 'FAILED', 'PARTIAL_SUCCESS', 'CANCELLED'].includes(scan.status)
  const isRunning = scan?.status && ['QUEUED', 'RUNNING', 'WAITING_FOR_AUTH'].includes(scan.status)

  const currentStep = () => {
    if (scan?.status === 'QUEUED') return 0
    if (scan?.status === 'RUNNING') return 1
    return -1
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
            {STEPS.map((step, idx) => (
              <div key={step} className={`${styles.step} ${idx < currentStep() ? styles.stepDone : idx === currentStep() ? styles.stepActive : ''}`}>
                <div className={styles.stepDot}>
                  {idx < currentStep() ? '✓' : idx === currentStep() ? '●' : '○'}
                </div>
                <span className={styles.stepLabel}>{step}</span>
              </div>
            ))}
          </div>
        )}
        
        <div className={styles.links}>
          <a href={`/api/v1/scans/${scan.jobId || scan.id}/reports`} target="_blank" rel="noopener">Отчёт markdown</a>
          <a href={`/api/v1/scans/${scan.jobId || scan.id}/endpoints`} target="_blank" rel="noopener">Эндпоинты</a>
        </div>
      </div>

      <section className={styles.card}>
        <h3 className={styles.sectionTitle}>
          Найденные уязвимости ({findings.length})
        </h3>
        <div className={styles.findings}>
          {findings.length === 0 ? (
            <p className={styles.empty}>
              {isRunning ? 'Сканирование продолжается...' : 'Уязвимости не обнаружены.'}
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
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  )
}