import { api } from '../api/api'

type ReportFormat = 'html' | 'docx' | 'pdf' | 'endpoints' | 'discovered-urls'

export async function downloadReport(jobId: string, format: 'html' | 'docx' | 'pdf' = 'docx'): Promise<void> {
  const { blob, filename, contentType } = await api.getReport(jobId, format)
  const url = URL.createObjectURL(blob)
  try {
    if (format === 'html' && contentType.includes('text/html')) {
      window.open(url, '_blank')
    } else {
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
    }
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}

export async function openReportInNewTab(jobId: string, format: ReportFormat): Promise<void> {
  const { blob } = await api.getReport(jobId, format)
  const url = URL.createObjectURL(blob)
  window.open(url, '_blank')
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export async function downloadScanDump(scanId: string): Promise<void> {
  const { blob, filename } = await api.downloadScanDump(scanId)
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
}
