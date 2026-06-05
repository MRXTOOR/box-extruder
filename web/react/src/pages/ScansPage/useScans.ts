import { useEffect, useState } from 'react'
import { ScanConfig } from '../../widgets/ScanForm/ScanForm'
import { api } from '../../shared/api/api'
import { Scan } from '../../entities/Scan/model/types'
import { useJobPolling } from './useJobPolling'

export type AutoDetectStatus = 'idle' | 'pending' | 'ok' | 'fail'

export function useScans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [cancelingIds, setCancelingIds] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [autoDetectStatus, setAutoDetectStatus] = useState<AutoDetectStatus>('idle')
  const { startStatusPolling } = useJobPolling()

  const loadScans = async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) setLoading(true)
    setRefreshing(true)
    try {
      const data = await api.getScans()
      setScans([...(data || [])].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()))
    } catch (err) {
      console.error(err)
    } finally {
      if (!opts?.silent) setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    loadScans()
    const timer = setInterval(() => loadScans({ silent: true }), 10000)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleCreateScan = async (targetUrl: string, config?: ScanConfig) => {
    setAutoDetectStatus('pending')
    try {
      const scan = await api.createScan({ targetUrl, ...config })
      const jobId = scan.jobId || scan.id
      if (!jobId) {
        setAutoDetectStatus('fail')
        return
      }
      setAutoDetectStatus('ok')
      loadScans({ silent: true })
      startStatusPolling(jobId, () => loadScans({ silent: true }))
    } catch (err) {
      console.error(err)
      setAutoDetectStatus('fail')
      alert(err instanceof Error ? err.message : String(err))
    }
  }

  const handleDeleteScan = async (jobId: string) => {
    await api.deleteScan(jobId)
    loadScans()
  }

  const handleCancelScan = async (jobId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (cancelingIds.has(jobId)) return
    const prev = scans.find((s) => s.jobId === jobId || s.id === jobId)?.status
    setCancelingIds((p) => new Set(p).add(jobId))
    // Optimistic UI: show cancelled immediately without waiting for poll.
    setScans((p) => p.map((s) => (s.jobId === jobId || s.id === jobId ? { ...s, status: 'CANCELLED' as Scan['status'] } : s)))
    try {
      await api.cancelScan(jobId)
      loadScans()
    } catch (err) {
      console.error('Cancel error:', err)
      if (prev) setScans((p) => p.map((s) => (s.jobId === jobId || s.id === jobId ? { ...s, status: prev } : s)))
    } finally {
      setCancelingIds((p) => {
        const next = new Set(p)
        next.delete(jobId)
        return next
      })
    }
  }

  return {
    scans,
    loading,
    refreshing,
    cancelingIds,
    autoDetectStatus,
    loadScans,
    handleCreateScan,
    handleDeleteScan,
    handleCancelScan,
  }
}
