import { useEffect, useRef, useState } from 'react'
import { api } from '../../shared/api/api'
import styles from './ScanDetailPage.module.css'

interface EndpointsModalProps {
  open: boolean
  jobId: string | null
  onClose: () => void
}

export function EndpointsModal({ open, jobId, onClose }: EndpointsModalProps) {
  const [list, setList] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [copying, setCopying] = useState(false)
  const loadedJobIdRef = useRef<string | null>(null)

  useEffect(() => {
    if (!open || !jobId || loadedJobIdRef.current === jobId) return
    setLoading(true)
    api
      .getScanEndpoints(jobId)
      .then((eps) => {
        setList(eps)
        loadedJobIdRef.current = jobId
      })
      .catch((err) => {
        console.error(err)
        setList([])
      })
      .finally(() => setLoading(false))
  }, [open, jobId])

  const copyToClipboard = async () => {
    if (!list.length || copying) return
    try {
      setCopying(true)
      await navigator.clipboard.writeText(list.join('\n'))
    } catch (err) {
      console.error('Clipboard error:', err)
    } finally {
      setCopying(false)
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
          <h3>Обнаруженные URL ({list.length})</h3>
          <button type="button" className={styles.btnClose} onClick={onClose}>&times;</button>
        </div>
        <div className={styles.modalBody}>
          {loading ? (
            <p>Загрузка...</p>
          ) : list.length > 0 ? (
            <>
              <div className={styles.endpointsActions}>
                <button type="button" className={styles.resourceBtn} onClick={copyToClipboard} disabled={copying}>
                  {copying ? 'Копирование...' : 'Скопировать список'}
                </button>
              </div>
              <pre className={styles.endpointsList}>{list.join('\n')}</pre>
            </>
          ) : (
            <p>Эндпоинты не найдены</p>
          )}
        </div>
      </div>
    </div>
  )
}
