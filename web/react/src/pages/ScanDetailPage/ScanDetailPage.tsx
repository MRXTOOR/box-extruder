import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { FindingCard } from '../../widgets/FindingCard/FindingCard'
import { api } from '../../shared/api/api'
import { Scan, Finding, ScanStatus } from '../../entities/Scan/model/types'
import styles from './ScanDetailPage.module.css'

const statusLabels: Record<ScanStatus, string> = {
  QUEUED: 'Queued',
  RUNNING: 'Running',
  SUCCEEDED: 'Succeeded',
  FAILED: 'Failed',
  PARTIAL_SUCCESS: 'Partial Success',
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    loadData()
  }, [id])

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

  const refreshStatus = async () => {
    if (!id) return
    try {
      const status = await api.getScanStatus(id)
      setScan(prev => prev ? { ...prev, status: status as ScanStatus } : null)
    } catch (err) {
      console.error(err)
    }
  }

  if (loading) return <div className={styles.loading}>Loading...</div>
  if (!scan) return <div className={styles.error}>Scan not found</div>

  return (
    <div className={styles.page}>
      <Link to="/" className={styles.back}>← Back to Scans</Link>
      
      <div className={styles.header}>
        <h2 className={styles.target}>{scan.targetUrl}</h2>
        <div className={styles.meta}>
          <span className={`${styles.status} ${styles[scan.status.toLowerCase()]}`}>
            {statusLabels[scan.status]}
          </span>
          <button className={styles.refresh} onClick={refreshStatus}>
            Refresh
          </button>
        </div>
      </div>

      <section className={styles.section}>
        <h3 className={styles.sectionTitle}>
          Findings ({findings.length})
        </h3>
        <div className={styles.findings}>
          {findings.length === 0 ? (
            <p className={styles.empty}>No findings detected.</p>
          ) : (
            findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))
          )}
        </div>
      </section>
    </div>
  )
}