export const TERMINAL_STATUSES = ['SUCCEEDED', 'FAILED', 'CANCELLED', 'CANCELED', 'PARTIAL_SUCCESS']
export const RUNNING_STATUSES = ['QUEUED', 'RUNNING', 'WAITING_FOR_AUTH']

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

// Text-only status labels (icons via ScanStatusBadge + lucide-react).
export const statusLabelsPlain: Record<string, string> = {
  SUCCEEDED: 'Завершён',
  FAILED: 'Ошибка',
  PARTIAL_SUCCESS: 'Частично',
  RUNNING: 'Выполняется',
  QUEUED: 'В очереди',
  WAITING_FOR_AUTH: 'Ожидание авторизации',
  PENDING: 'Приостановлен',
  CANCELLED: 'Отменён',
  CANCELED: 'Отменён',
}

/** @deprecated Use statusLabelsPlain; kept for non-UI text (e.g. job log). */
export const statusLabels: Record<string, string> = statusLabelsPlain

export function getStatusClass(status: string): string {
  return status.toLowerCase().replace('_', '-')
}

export function isTerminalStatus(status?: string): boolean {
  return !!status && TERMINAL_STATUSES.includes(status)
}

export function isRunningStatus(status?: string): boolean {
  return !!status && RUNNING_STATUSES.includes(status)
}

export function isCiScan(scan: { source?: string; ciTokenId?: string }): boolean {
  return scan.source === 'jenkins' || scan.source === 'ci' || !!scan.ciTokenId
}

// stepLabel maps a backend step type to a human-readable name.
export function stepLabel(stepType: string): string {
  switch (stepType) {
    case 'katana':
      return 'Katana'
    case 'httpxProbe':
      return 'httpx'
    case 'zapBaseline':
      return 'ZAP Baseline'
    case 'wapiti':
      return 'Wapiti'
    case 'nucleiTemplates':
    case 'nucleiCLI':
      return 'Nuclei'
    default:
      return stepType
  }
}
