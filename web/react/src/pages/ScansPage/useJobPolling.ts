import { useEffect, useRef } from 'react'
import { api } from '../../shared/api/api'
import { ScanStatusResponse } from '../../entities/Scan/model/types'
import { isTerminalStatus } from '../../shared/lib/scanStatus'

/** Polls scan status until terminal, then calls onTerminal (e.g. refresh sidebar list). */
export function useJobPolling() {
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => () => {
    if (pollingRef.current) clearInterval(pollingRef.current)
  }, [])

  const startStatusPolling = (jobId: string, onTerminal: () => void) => {
    if (pollingRef.current) clearInterval(pollingRef.current)
    pollingRef.current = setInterval(async () => {
      try {
        const status = await api.getScanStatus(jobId)
        if (status && typeof status === 'object' && 'status' in status) {
          const typed = status as ScanStatusResponse
          if (isTerminalStatus(typed.status)) {
            if (pollingRef.current) clearInterval(pollingRef.current)
            onTerminal()
          }
        }
      } catch (err) {
        console.error('Status polling error:', err)
      }
    }, 3000)
  }

  return { startStatusPolling }
}
