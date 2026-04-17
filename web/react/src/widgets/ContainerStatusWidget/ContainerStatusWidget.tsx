import { FC, useEffect, useState } from 'react'
import { ContainerStatus } from '../../entities/Container/model/types'
import styles from './ContainerStatusWidget.module.css'

interface ContainerStatusWidgetProps {
  onRefresh?: () => void
}

export const ContainerStatusWidget: FC<ContainerStatusWidgetProps> = () => {
  const [containers, setContainers] = useState<ContainerStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadContainers()
    const interval = setInterval(loadContainers, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadContainers = async () => {
    try {
      const token = localStorage.getItem('token')
      const res = await fetch('/api/v1/containers', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!res.ok) throw new Error('Failed to load containers')
      const data = await res.json()
      setContainers(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  const unhealthyContainers = containers.filter(
    c => c.health === 'unhealthy' || c.health === 'dead' || c.health === 'restarting'
  )

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return '✓'
      case 'unhealthy': return '✕'
      case 'starting': return '◐'
      case 'stopped': return '○'
      case 'restarting': return '↻'
      case 'dead': return '☠'
      default: return '?'
    }
  }

  if (loading) return <div className={styles.loading}>Loading containers...</div>
  if (error) return <div className={styles.error}>{error}</div>

  return (
    <div className={styles.widget}>
      <div className={styles.header}>
        <h3>Container Status</h3>
        <button className={styles.refresh} onClick={loadContainers}>↻</button>
      </div>

      {unhealthyContainers.length > 0 && (
        <div className={styles.alert}>
          <span className={styles.alertIcon}>⚠</span>
          <span>{unhealthyContainers.length} container(s) have issues</span>
        </div>
      )}

      <div className={styles.list}>
        {containers.length === 0 ? (
          <div className={styles.empty}>No containers found</div>
        ) : (
          containers.map((c, i) => (
            <div key={i} className={`${styles.item} ${styles[c.health]}`}>
              <span className={styles.icon}>{getHealthIcon(c.health)}</span>
              <div className={styles.info}>
                <span className={styles.name}>{c.name}</span>
                <span className={styles.image}>{c.image}</span>
              </div>
              <span className={styles.status}>{c.status}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}