import { useEffect, useRef, useState } from 'react'
import { api } from '../../shared/api/api'
import styles from './ScanDetailPage.module.css'

const PAGE_SIZE = 100

interface EndpointsModalProps {
  open: boolean
  jobId: string | null
  onClose: () => void
}

export function EndpointsModal({ open, jobId, onClose }: EndpointsModalProps) {
  const [list, setList] = useState<string[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [copying, setCopying] = useState(false)

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query.trim()), 300)
    return () => clearTimeout(t)
  }, [query])

  useEffect(() => {
    setPage(1)
  }, [debouncedQuery, jobId])

  useEffect(() => {
    if (!open || !jobId) return
    setLoading(true)
    const offset = (page - 1) * PAGE_SIZE
    api
      .getScanEndpoints(jobId, { limit: PAGE_SIZE, offset, q: debouncedQuery || undefined })
      .then((res) => {
        setList(res.items || [])
        setTotal(res.total ?? 0)
      })
      .catch((err) => {
        console.error(err)
        setList([])
        setTotal(0)
      })
      .finally(() => setLoading(false))
  }, [open, jobId, page, debouncedQuery])

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const copyToClipboard = async () => {
    if (!jobId || copying) return
    try {
      setCopying(true)
      const res = await api.getScanEndpoints(jobId, { limit: total || PAGE_SIZE, offset: 0, q: debouncedQuery || undefined })
      await navigator.clipboard.writeText((res.items || []).join('\n'))
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
          <h3>Обнаруженные URL ({total})</h3>
          <button type="button" className={styles.btnClose} onClick={onClose}>&times;</button>
        </div>
        <div className={styles.modalBody}>
          <input
            type="search"
            className={styles.findingSearch}
            placeholder="Фильтр URL"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {loading ? (
            <p>Загрузка...</p>
          ) : list.length > 0 ? (
            <>
              <div className={styles.endpointsActions}>
                <button type="button" className={styles.resourceBtn} onClick={copyToClipboard} disabled={copying}>
                  {copying ? 'Копирование...' : 'Скопировать страницу'}
                </button>
              </div>
              <pre className={styles.endpointsList}>{list.join('\n')}</pre>
              {pageCount > 1 && (
                <div className={styles.pagination}>
                  <button type="button" className={styles.pageBtn} disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>←</button>
                  <span className={styles.pageInfo}>{page} / {pageCount}</span>
                  <button type="button" className={styles.pageBtn} disabled={page >= pageCount} onClick={() => setPage((p) => p + 1)}>→</button>
                </div>
              )}
            </>
          ) : (
            <p>Эндпоинты не найдены</p>
          )}
        </div>
      </div>
    </div>
  )
}
