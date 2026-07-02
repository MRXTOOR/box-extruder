import { Scan, ScanStatusResponse } from '../../entities/Scan/model/types'
import { isTerminalStatus } from './scanStatus'

export interface ScanTimeEstimate {
  elapsedSeconds: number
  remainingSeconds: number | null
  totalSeconds: number | null
  progressPercent: number | null
  summary: string
  detail: string | null
}

const REFERENCE_TERMINAL = new Set(['SUCCEEDED', 'PARTIAL_SUCCESS'])

/** Same origin as backend scope base: scheme://host */
export function normalizeTargetKey(rawUrl: string): string {
  try {
    const u = new URL(rawUrl.trim())
    if (!u.protocol || !u.host) return rawUrl.trim().toLowerCase()
    return `${u.protocol}//${u.host.toLowerCase()}`
  } catch {
    return rawUrl.trim().toLowerCase()
  }
}

export function scanDurationSeconds(scan: Scan): number | null {
  if (!scan.finishedAt) return null
  const start = new Date(scan.createdAt).getTime()
  const end = new Date(scan.finishedAt).getTime()
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null
  return Math.round((end - start) / 1000)
}

/** Duration of the most recent completed scan of the same target (excluding current). */
export function findReferenceDurationSeconds(scans: Scan[], current: Scan): number | null {
  const key = normalizeTargetKey(current.targetUrl)
  const currentIds = new Set([current.id, current.jobId].filter(Boolean))

  let bestDuration: number | null = null
  let bestFinishedAt = 0

  for (const s of scans) {
    if (currentIds.has(s.id) || currentIds.has(s.jobId)) continue
    if (normalizeTargetKey(s.targetUrl) !== key) continue
    if (!REFERENCE_TERMINAL.has(s.status)) continue
    const dur = scanDurationSeconds(s)
    if (!dur || dur <= 0) continue
    const finished = s.finishedAt ? new Date(s.finishedAt).getTime() : 0
    if (finished >= bestFinishedAt) {
      bestFinishedAt = finished
      bestDuration = dur
    }
  }
  return bestDuration
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) {
    return `${s} сек`
  }
  const mins = Math.floor(s / 60)
  if (mins < 60) {
    return `${mins} мин`
  }
  const hours = Math.floor(mins / 60)
  const rem = mins % 60
  return rem > 0 ? `${hours} ч ${rem} мин` : `${hours} ч`
}

/**
 * Estimates scan time only when a prior completed scan of the same target exists.
 * Returns null on first scan — UI must hide the time card.
 */
export function estimateScanTime(
  statusInfo: ScanStatusResponse | null,
  scanStatus: string | undefined,
  referenceDurationSeconds: number | null | undefined,
): ScanTimeEstimate | null {
  if (!statusInfo || referenceDurationSeconds == null || referenceDurationSeconds <= 0) {
    return null
  }

  const elapsed = statusInfo.elapsedSeconds ?? 0
  const total = referenceDurationSeconds
  const progress = total > 0 ? Math.min(99, Math.round((elapsed / total) * 100)) : null

  if (scanStatus && isTerminalStatus(scanStatus)) {
    if (elapsed <= 0) return null
    return {
      elapsedSeconds: elapsed,
      remainingSeconds: 0,
      totalSeconds: elapsed,
      progressPercent: 100,
      summary: `завершён за ${formatDuration(elapsed)}`,
      detail: `ориентир ~${formatDuration(total)}`,
    }
  }

  const remaining = Math.max(0, Math.round(total - elapsed))
  return {
    elapsedSeconds: elapsed,
    remainingSeconds: remaining,
    totalSeconds: total,
    progressPercent: progress,
    summary: remaining > 0 ? `~${formatDuration(remaining)} осталось` : 'завершается…',
    detail: `прошло ${formatDuration(elapsed)} · всего ~${formatDuration(total)}`,
  }
}
