import { FileType, FileDown, Globe } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import styles from './ScansPage.module.css'

export type ReportFormat = 'docx' | 'html' | 'pdf'

interface DownloadReportModalProps {
  open: boolean
  jobId: string | null
  onClose: () => void
  onDownload: (jobId: string, format: ReportFormat) => void
}

const FORMATS: { format: ReportFormat; Icon: LucideIcon; name: string; desc: string }[] = [
  { format: 'docx', Icon: FileType, name: 'Word', desc: 'Корпоративный отчёт (.docx)' },
  { format: 'pdf', Icon: FileDown, name: 'PDF', desc: 'Отчёт для печати и архива' },
  { format: 'html', Icon: Globe, name: 'HTML', desc: 'Просмотр в браузере' },
]

export function DownloadReportModal({ open, jobId, onClose, onDownload }: DownloadReportModalProps) {
  const pick = (format: ReportFormat) => {
    if (jobId) {
      onDownload(jobId, format)
      onClose()
    }
  }

  return (
    <div
      className={`${styles.modalOverlay} ${!open ? styles.modalHidden : ''}`}
      aria-hidden={!open}
      onClick={onClose}
    >
      <div className={styles.modalContent} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h3>Скачать отчёт</h3>
          <button type="button" className={styles.btnClose} onClick={onClose}>&times;</button>
        </div>
        <div className={styles.modalBody}>
          <div className={styles.downloadJobId}>#{jobId?.substring(0, 8)}</div>
          <div className={styles.downloadFormats}>
            {FORMATS.map((f) => (
              <button key={f.format} type="button" className={styles.btnFormat} onClick={() => pick(f.format)}>
                <span className={styles.formatIcon} aria-hidden>
                  <f.Icon className={styles.uiIcon} size={22} strokeWidth={1.75} />
                </span>
                <span className={styles.formatName}>{f.name}</span>
                <span className={styles.formatDesc}>{f.desc}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
