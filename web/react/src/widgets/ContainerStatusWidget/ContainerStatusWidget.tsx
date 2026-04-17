import { FC, useEffect, useState } from 'react'
import styles from './ContainerStatusWidget.module.css'

interface ContainerStatus {
  name: string
  image: string
  status: string
  health: string
}

export const ContainerStatusWidget: FC = () => {
  const [containers, setContainers] = useState<ContainerStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAll, setShowAll] = useState(false)

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
      setContainers(data || [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load')
      setContainers([])
    } finally {
      setLoading(false)
    }
  }

  const unhealthyContainers = containers.filter(
    c => c.health === 'unhealthy' || c.health === 'dead' || c.health === 'restarting'
  )

  const displayedContainers = showAll ? containers : containers.slice(0, 5)

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

  if (loading) return <div className={styles.widget}>
    <div className={styles.header}>
      <h3>Контейнеры</h3>
    </div>
    <div className={styles.loading}>Загрузка...</div>
  </div>

  return (
    <div className={styles.widget}>
      <div className={styles.header}>
        <h3>Контейнеры</h3>
        <button className={styles.refresh} onClick={loadContainers}>↻</button>
      </div>

      {error && (
        <div className={styles.alert}>
          <span className={styles.alertIcon}>⚠</span>
          <span>Контейнеры недоступны</span>
        </div>
      )}

      {!error && unhealthyContainers.length > 0 && (
        <div className={styles.alert}>
          <span className={styles.alertIcon}>⚠</span>
          <span>{unhealthyContainers.length} контейнер(ов) с проблемами</span>
        </div>
      )}

      <div className={styles.list}>
        {!error && containers.length === 0 ? (
          <div className={styles.empty}>Контейнеры не найдены</div>
        ) : !error && displayedContainers.map((c, i) => (
          <div key={i} className={`${styles.item} ${styles[c.health]}`}>
            <span className={styles.icon}>{getHealthIcon(c.health)}</span>
            <div className={styles.info}>
              <span className={styles.name}>{c.name}</span>
              <span className={styles.image}>{c.image}</span>
            </div>
            <span className={styles.status}>{c.status}</span>
          </div>
        ))}
      </div>

      {!error && containers.length > 5 && (
        <button 
          className={styles.showMore}
          onClick={() => setShowAll(!showAll)}
        >
          {showAll ? 'Свернуть' : `Показать ещё ${containers.length - 5}`}
        </button>
      )}
    </div>
  )
}