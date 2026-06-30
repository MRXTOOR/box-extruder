import { ScanStatusResponse } from '../../entities/Scan/model/types'
import { isTerminalStatus } from './scanStatus'

export interface ScanTimeEstimate {
  elapsedSeconds: number
  remainingSeconds: number | null
  totalSeconds: number | null
  progressPercent: number | null
  /** Short line for the detail header, e.g. "~25 мин осталось" */
  summary: string
  /** Secondary line, e.g. "прошло 12 мин · всего ~45 мин" */
  detail: string | null
}

const DEFAULT_PLAN_SECONDS = 180 + 900 + 300 // katana + wapiti + nuclei (ZAP временно отключён)

const STEP_SECONDS: Record<string, number> = {
  katana: 180,
  zapBaseline: 15 * 60 + 180,
  wapiti: 900,
  nucleiTemplates: 300,
  nucleiCLI: 300,
}

function stepSeconds(stepType: string): number {
  if (stepType === 'nucleiTemplates' || stepType === 'nucleiCLI') {
    return STEP_SECONDS.nucleiTemplates
  }
  return STEP_SECONDS[stepType] ?? 120
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

function estimateFromSteps(status: ScanStatusResponse, elapsed: number): ScanTimeEstimate {
  const steps = status.steps ?? []
  let doneWeight = 0
  let remainingWeight = 0

  for (const step of steps) {
    const w = stepSeconds(step.stepType || '')
    const st = (step.status || 'PENDING').toUpperCase()
    if (st === 'SUCCEEDED' || st === 'FAILED' || st === 'SKIPPED') {
      doneWeight += w
    } else if (st === 'RUNNING') {
      doneWeight += w * 0.45
      remainingWeight += w * 0.55
    } else {
      remainingWeight += w
    }
  }

  const total = Math.max(elapsed + remainingWeight, doneWeight + remainingWeight, DEFAULT_PLAN_SECONDS)
  const remaining = Math.max(0, Math.round(total - elapsed))

  return {
    elapsedSeconds: elapsed,
    remainingSeconds: remaining,
    totalSeconds: Math.round(total),
    progressPercent: total > 0 ? Math.min(99, Math.round((elapsed / total) * 100)) : null,
    summary: remaining > 0 ? `~${formatDuration(remaining)} осталось` : 'завершается…',
    detail: `прошло ${formatDuration(elapsed)} · всего ~${formatDuration(total)}`,
  }
}

function estimateFromProgress(status: ScanStatusResponse, elapsed: number, progress: number): ScanTimeEstimate {
  const total = Math.round((elapsed * 100) / progress)
  const remaining = Math.max(0, total - elapsed)
  return {
    elapsedSeconds: elapsed,
    remainingSeconds: remaining,
    totalSeconds: total,
    progressPercent: progress,
    summary: `~${formatDuration(remaining)} осталось`,
    detail: `прошло ${formatDuration(elapsed)} · всего ~${formatDuration(total)} · ${progress}%`,
  }
}

/** Estimates remaining/total scan time from status polling data. */
export function estimateScanTime(
  statusInfo: ScanStatusResponse | null,
  scanStatus?: string,
): ScanTimeEstimate | null {
  if (!statusInfo) {
    return null
  }

  const elapsed = statusInfo.elapsedSeconds ?? 0
  const progress = statusInfo.progress ?? 0

  if (scanStatus && isTerminalStatus(scanStatus)) {
    if (elapsed <= 0) {
      return null
    }
    return {
      elapsedSeconds: elapsed,
      remainingSeconds: 0,
      totalSeconds: elapsed,
      progressPercent: 100,
      summary: `завершён за ${formatDuration(elapsed)}`,
      detail: null,
    }
  }

  if (progress >= 5 && progress < 100 && elapsed >= 30) {
    return estimateFromProgress(statusInfo, elapsed, progress)
  }

  if ((statusInfo.steps?.length ?? 0) > 0) {
    return estimateFromSteps(statusInfo, elapsed)
  }

  const total = DEFAULT_PLAN_SECONDS
  const remaining = Math.max(0, total - elapsed)
  return {
    elapsedSeconds: elapsed,
    remainingSeconds: remaining,
    totalSeconds: total,
    progressPercent: total > 0 ? Math.min(99, Math.round((elapsed / total) * 100)) : null,
    summary: `~${formatDuration(remaining)} осталось`,
    detail: `прошло ${formatDuration(elapsed)} · план ~${formatDuration(total)}`,
  }
}
