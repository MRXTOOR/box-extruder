import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../../shared/api/api'
import { Scan, ScanStatus, ScanStatusResponse } from '../../entities/Scan/model/types'
import { isTerminalStatus } from '../../shared/lib/scanStatus'
import { findReferenceDurationSeconds } from '../../shared/lib/estimateScanTime'

export function useScanDetail(id?: string) {
  const navigate = useNavigate()
  const [scan, setScan] = useState<Scan | null>(null)
  const [statusInfo, setStatusInfo] = useState<ScanStatusResponse | null>(null)
  const [referenceDurationSeconds, setReferenceDurationSeconds] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [canceling, setCanceling] = useState(false)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadData = async () => {
    if (!id) return
    try {
      const [scanData, allScans] = await Promise.all([api.getScan(id), api.getScans()])
      setScan(scanData)
      setReferenceDurationSeconds(findReferenceDurationSeconds(allScans || [], scanData))
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  const startPolling = useCallback(() => {
    if (!id) return
    if (pollingRef.current) clearInterval(pollingRef.current)
    const poll = async () => {
      try {
        const status = await api.getScanStatus(id)
        if (status && typeof status === 'object' && status.status) {
          const typed = status as ScanStatusResponse
          setStatusInfo(typed)
          setScan((prev) => (prev ? { ...prev, status: typed.status as ScanStatus } : null))
          if (isTerminalStatus(typed.status)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
            loadData()
          }
        }
      } catch (err) {
        console.error('Polling error:', err)
      }
    }
    poll()
    pollingRef.current = setInterval(poll, 3000)
  }, [id])

  useEffect(() => {
    if (!id) return
    setStatusInfo(null)
    loadData()
    startPolling()
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [id, startPolling])

  const handleCancel = async () => {
    if (!id || canceling) return
    setCanceling(true)
    const prevStatus = scan?.status
    setScan((prev) => (prev ? { ...prev, status: 'CANCELLED' as ScanStatus } : null))
    if (pollingRef.current) clearInterval(pollingRef.current)
    try {
      await api.cancelScan(id)
    } catch (err) {
      console.error('Cancel error:', err)
      if (prevStatus) setScan((prev) => (prev ? { ...prev, status: prevStatus } : null))
      startPolling()
    } finally {
      setCanceling(false)
    }
  }

  const handleRestart = async () => {
    if (!id) return
    try {
      const newScan = await api.restartScan(id)
      navigate(`/scans/${newScan.id}`)
    } catch (err) {
      console.error('Restart error:', err)
    }
  }

  return { scan, statusInfo, referenceDurationSeconds, loading, canceling, handleCancel, handleRestart, reloadScan: loadData }
}
