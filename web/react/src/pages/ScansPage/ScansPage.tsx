import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanForm } from '../../widgets/ScanForm/ScanForm'
import { api } from '../../shared/api/api'
import { downloadReport } from '../../shared/lib/download'
import { Toast } from '../../shared/ui/Toast'
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
    launchToast,
    dismissLaunchToast,
    loadScans,
    handleCreateScan,
    handleDeleteScan,
    handleCancelScan,
  } = useScans()

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

  return (
    <div className={styles.page}>
      <div className={styles.pageInner}>
        <div className={styles.mainContent}>
          <section className={styles.card} aria-labelledby="card-scan">
            <p className={styles.cardHead} id="card-scan">Настройка цели</p>
            <ScanForm onSubmit={handleCreateScan} />
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

      {launchToast && (
        <Toast
          variant={launchToast.variant}
          message={launchToast.message}
          durationMs={10_000}
          onClose={dismissLaunchToast}
        />
      )}

      <DownloadReportModal
        open={downloadModalOpen}
        jobId={downloadTargetJobId}
        onClose={() => setDownloadModalOpen(false)}
        onDownload={handleDownload}
      />
    </div>
  )
}
