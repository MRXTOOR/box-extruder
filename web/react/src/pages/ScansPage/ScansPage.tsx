import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Check, Circle, Loader2, X } from 'lucide-react'
import { ScanForm } from '../../widgets/ScanForm/ScanForm'
import { api } from '../../shared/api/api'
import { downloadReport } from '../../shared/lib/download'
import { useScans } from './useScans'
import { ScanHistorySidebar } from './ScanHistorySidebar'
import { DownloadReportModal, ReportFormat } from './DownloadReportModal'
import styles from './ScansPage.module.css'

export function ScansPage() {
  const navigate = useNavigate()
  const {
    scans,
    loading,
    refreshing,
    cancelingIds,
    autoDetectStatus,
    loadScans,
    handleCreateScan,
    handleDeleteScan,
    handleCancelScan,
  } = useScans()

  const [detectOpen, setDetectOpen] = useState(true)
  const [downloadModalOpen, setDownloadModalOpen] = useState(false)
  const [downloadTargetJobId, setDownloadTargetJobId] = useState<string | null>(null)

  const handleDownload = async (jobId: string, format: ReportFormat = 'docx') => {
    try {
      await downloadReport(jobId, format)
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
    }
  }

  const handleViewEndpoints = async (jobId: string) => {
    try {
      const endpoints = await api.getScanEndpoints(jobId)
      const blob = new Blob([endpoints.join('\n')], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      window.open(url, '_blank')
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
    }
  }

  const openDownloadModal = (jobId: string) => {
    setDownloadTargetJobId(jobId)
    setDownloadModalOpen(true)
  }

  const autoDetectBadgeClass =
    autoDetectStatus === 'ok'
      ? styles.badgeOk
      : autoDetectStatus === 'fail'
        ? styles.badgeFail
        : styles.badgeIdle

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
              <p className={styles.cardHead}>Создание скана</p>
              <button
                type="button"
                className={`${styles.btnToggle} ${!detectOpen ? styles.collapsed : ''}`}
                onClick={() => setDetectOpen(!detectOpen)}
                aria-expanded={detectOpen}
              >
                {detectOpen ? '−' : '+'}
              </button>
            </div>
            {detectOpen && (
              <div className={styles.detectContent}>
                <p className={styles.detectHint}>
                  Статус последней попытки отправить форму (проверка логина на сервере). Ход и результат скана — в «Истории сканов» справа или на странице деталей.
                </p>
                <div className={styles.badgeRow}>
                  <span className={`${styles.badge} ${autoDetectBadgeClass}`}>
                    <span className={styles.icon} aria-hidden>
                      {autoDetectStatus === 'idle' && <Circle className={styles.uiIcon} size={14} strokeWidth={2} />}
                      {autoDetectStatus === 'pending' && <Loader2 className={`${styles.uiIcon} ${styles.spinIcon}`} size={14} strokeWidth={2} />}
                      {autoDetectStatus === 'ok' && <Check className={styles.uiIcon} size={14} strokeWidth={2} />}
                      {autoDetectStatus === 'fail' && <X className={styles.uiIcon} size={14} strokeWidth={2} />}
                    </span>
                    {autoDetectStatus === 'idle' ? 'ещё не отправляли' : autoDetectStatus === 'pending' ? 'отправка…' : autoDetectStatus === 'ok' ? 'принято в очередь' : 'отклонено'}
                  </span>
                </div>
              </div>
            )}
          </section>
        </div>

        <ScanHistorySidebar
          scans={scans}
          loading={loading}
          refreshing={refreshing}
          cancelingIds={cancelingIds}
          onRefresh={() => loadScans({ silent: true })}
          onView={(jobId) => navigate(`/scans/${jobId}`)}
          onCancel={handleCancelScan}
          onDownload={openDownloadModal}
          onViewEndpoints={handleViewEndpoints}
          onDelete={handleDeleteScan}
        />
      </div>

      <DownloadReportModal
        open={downloadModalOpen}
        jobId={downloadTargetJobId}
        onClose={() => setDownloadModalOpen(false)}
        onDownload={handleDownload}
      />
    </div>
  )
}
