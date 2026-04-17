import { useEffect, useState } from 'react'
import { ScanForm } from '../../widgets/ScanForm/ScanForm'
import { ScanTable } from '../../widgets/ScanTable/ScanTable'
import { ContainerStatusWidget } from '../../widgets/ContainerStatusWidget/ContainerStatusWidget'
import { api } from '../../shared/api/api'
import { Scan } from '../../entities/Scan/model/types'
import styles from './ScansPage.module.css'

export function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadScans()
  }, [])

  const loadScans = async () => {
    try {
      const data = await api.getScans()
      setScans(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateScan = async (targetUrl: string) => {
    await api.createScan({ targetUrl })
    loadScans()
  }

  const handleDeleteScan = async (jobId: string) => {
    await api.deleteScan(jobId)
    loadScans()
  }

  return (
    <div className={styles.page}>
      <h2 className={styles.title}>Dashboard</h2>
      <ContainerStatusWidget />
      <h2 className={styles.title}>Scans</h2>
      <ScanForm onSubmit={handleCreateScan} />
      {loading ? (
        <div className={styles.loading}>Loading...</div>
      ) : (
        <ScanTable scans={scans} onDelete={handleDeleteScan} />
      )}
    </div>
  )
}