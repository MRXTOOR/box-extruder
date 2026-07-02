import { useMemo } from 'react'
import { Check, Circle, Clock, CornerDownRight, Loader2, X } from 'lucide-react'
import { Scan, ScanStatusResponse } from '../../entities/Scan/model/types'
import { estimateScanTime } from '../../shared/lib/estimateScanTime'
import { getStatusClass, stepLabel } from '../../shared/lib/scanStatus'
import { ScanStatusBadge } from '../../shared/ui/ScanStatusBadge'
import { downloadReport, openReportInNewTab } from '../../shared/lib/download'
import styles from './ScanDetailPage.module.css'

const STEPS = ['Katana', 'httpx', 'ZAP Baseline', 'Wapiti', 'Nuclei']

interface ScanDetailHeaderProps {
  scan: Scan
  statusInfo: ScanStatusResponse | null
  referenceDurationSeconds: number | null
  isRunning: boolean
  isTerminal: boolean
  canceling: boolean
  onCancel: () => void
  onRestart: () => void
  onOpenEndpoints: (jobId: string) => void
}

function buildStepItems(statusInfo: ScanStatusResponse | null) {
  const steps = statusInfo?.steps || []
  if (steps.length === 0) {
    return STEPS.map((name) => ({ label: name, status: 'PENDING', kind: 'pending' }))
  }
  let nucleiCount = 0
  return steps.map((step) => {
    const rawType = step.stepType || 'step'
    let label = stepLabel(rawType)
    if (rawType === 'nucleiTemplates' || rawType === 'nucleiCLI') {
      nucleiCount += 1
      label = nucleiCount > 1 ? `Nuclei #${nucleiCount}` : 'Nuclei'
    }
    const st = (step.status || 'PENDING').toUpperCase()
    const kind =
      st === 'SUCCEEDED' ? 'done' :
      st === 'RUNNING' ? 'active' :
      st === 'FAILED' ? 'failed' :
      st === 'SKIPPED' ? 'skipped' : 'pending'
    return { label, status: st, kind }
  })
}

function StepStateIcon({ kind }: { kind: string }) {
  const cls = styles.stepDotIcon
  if (kind === 'done') return <Check className={cls} size={14} strokeWidth={2.5} aria-hidden />
  if (kind === 'active') return <Loader2 className={`${cls} ${styles.stepSpin}`} size={14} strokeWidth={2} aria-hidden />
  if (kind === 'failed') return <X className={cls} size={14} strokeWidth={2.5} aria-hidden />
  if (kind === 'skipped') return <CornerDownRight className={cls} size={14} strokeWidth={2} aria-hidden />
  return <Circle className={cls} size={14} strokeWidth={2} aria-hidden />
}

export function ScanDetailHeader(props: ScanDetailHeaderProps) {
  const { scan, statusInfo, referenceDurationSeconds, isRunning, isTerminal, canceling } = props
  const stepItems = useMemo(() => buildStepItems(statusInfo), [statusInfo])
  const timeEstimate = useMemo(
    () => estimateScanTime(statusInfo, scan.status, referenceDurationSeconds),
    [statusInfo, scan.status, referenceDurationSeconds],
  )
  const jobId = scan.jobId || scan.id
  const progressPct = timeEstimate?.progressPercent ?? statusInfo?.progress ?? 0

  const reportDownload = async (format: 'html' | 'docx' | 'pdf') => {
    try {
      await downloadReport(jobId, format)
    } catch (err) {
      console.error(err)
    }
  }

  const endpointsTextOpen = async () => {
    try {
      await openReportInNewTab(jobId, 'endpoints')
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div>
          <h2 className={styles.target}>{scan.targetUrl}</h2>
          <div className={styles.meta}>
            <ScanStatusBadge
              status={scan.status}
              className={`${styles.status} ${styles[getStatusClass(scan.status)]}`}
            />
            <span className={styles.date}>
              {new Date(scan.createdAt).toLocaleString('ru-RU')}
            </span>
          </div>
          {timeEstimate && (
            <div className={styles.timeEstimate}>
              <Clock className={styles.timeEstimateIcon} size={16} strokeWidth={2} aria-hidden />
              <div className={styles.timeEstimateText}>
                <span className={styles.timeEstimateSummary}>{timeEstimate.summary}</span>
                {timeEstimate.detail && (
                  <span className={styles.timeEstimateDetail}>{timeEstimate.detail}</span>
                )}
              </div>
            </div>
          )}
          {isRunning && progressPct > 0 && (
            <div className={styles.progressBlock} role="progressbar" aria-valuenow={progressPct} aria-valuemin={0} aria-valuemax={100}>
              <div className={styles.progressTrack}>
                <div className={styles.progressFill} style={{ width: `${Math.min(100, progressPct)}%` }} />
              </div>
              <span className={styles.progressLabel}>{progressPct}%</span>
            </div>
          )}
        </div>
        <div className={styles.actions}>
          {isRunning && (
            <button className={styles.btnCancel} onClick={props.onCancel} disabled={canceling}>
              {canceling ? 'Отмена...' : 'Отменить'}
            </button>
          )}
          {isTerminal && (
            <button className={styles.btnRestart} onClick={props.onRestart}>
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
                  <StepStateIcon kind={step.kind} />
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
          <button className={styles.resourceBtn} type="button" onClick={() => reportDownload('docx')}>Word</button>
          <button className={styles.resourceBtn} type="button" onClick={() => reportDownload('pdf')}>PDF</button>
          <button className={styles.resourceBtn} type="button" onClick={() => reportDownload('html')}>HTML</button>
        </div>
        <div className={styles.resourcesGroup}>
          <span className={styles.resourcesLabel}>Эндпоинты</span>
          <button className={styles.resourceBtn} type="button" onClick={endpointsTextOpen}>TXT</button>
          <button className={styles.resourceBtn} type="button" onClick={() => props.onOpenEndpoints(jobId)}>Просмотр</button>
        </div>
      </div>
    </div>
  )
}
