import { Scan, Finding, ScanConfig, ScanStatusResponse } from '../../entities/Scan/model/types'
import {
  CiTokenCreateResponse,
  CiTokenListItem,
  ScanLogsResponse,
  ScanWithFindingsCount,
  UserRow,
} from '../../entities/CiToken/model/types'
import { getToken, onAuthExpired } from '../auth/token'

const BASE_URL = '/api/v1'

function headers(): HeadersInit {
  const token = getToken()
  const h: HeadersInit = { 'Content-Type': 'application/json' }
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function handleJsonResponse<T>(res: Response): Promise<T> {
  const text = await res.text()
  if (!res.ok) {
    if (res.status === 401) {
      onAuthExpired()
    }
    const trimmed = text.trim()
    let msg = trimmed || res.statusText || 'Request failed'
    if (trimmed) {
      try {
        const j = JSON.parse(trimmed) as { error?: string; message?: string }
        if (typeof j.error === 'string' && j.error) msg = j.error
        else if (typeof j.message === 'string' && j.message) msg = j.message
      } catch {
        /* Go http.Error и др. отдают plain text — показываем как есть */
      }
    }
    throw new Error(msg)
  }
  // Empty/null/unparsable body -> null. Endpoints that can hit this path use a
  // `T | null` generic and coalesce (e.g. getScans, getScanStatus).
  const emptyResult: unknown = null
  if (!text || text === 'null') {
    return emptyResult as T
  }
  try {
    return JSON.parse(text) as T
  } catch {
    return emptyResult as T
  }
}

function parseFilename(contentDisposition: string | null, fallback: string): string {
  if (!contentDisposition) return fallback
  const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i)
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1])
    } catch {
      return utf8Match[1]
    }
  }
  const plainMatch = contentDisposition.match(/filename="?([^";]+)"?/i)
  if (plainMatch?.[1]) return plainMatch[1]
  return fallback
}

export const api = {
  async login(login: string, password: string): Promise<{ token: string }> {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login, password }),
    })
    return handleJsonResponse(res)
  },

  async getMe(): Promise<{ id: string; login: string; role: string }> {
    const res = await fetch(`${BASE_URL}/auth/me`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async getScans(): Promise<Scan[]> {
    const res = await fetch(`${BASE_URL}/scans`, { headers: headers() })
    const data = await handleJsonResponse<Scan[] | null>(res)
    return data || []
  },

  async createScan(config: ScanConfig): Promise<Scan> {
    const res = await fetch(`${BASE_URL}/scans`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(config),
    })
    return handleJsonResponse(res)
  },

  async getScan(id: string): Promise<Scan & { findings: Finding[] }> {
    const res = await fetch(`${BASE_URL}/scans/${id}`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async deleteScan(jobId: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}`, {
      method: 'DELETE',
      headers: headers(),
    })
    if (!res.ok) throw new Error('Delete failed')
  },

  async getScanStatus(id: string): Promise<ScanStatusResponse> {
    const res = await fetch(`${BASE_URL}/scans/${id}/status`, { headers: headers() })
    const data = await handleJsonResponse<ScanStatusResponse | null>(res)
    return data || { status: 'UNKNOWN' }
  },

  async getScanEndpoints(jobId: string): Promise<string[]> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/endpoints`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async getDiscoveredUrls(jobId: string): Promise<string[]> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/discovered-urls`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async getReport(jobId: string, format: 'html' | 'docx' | 'pdf' | 'endpoints' | 'discovered-urls' = 'docx'): Promise<{ blob: Blob; filename: string; contentType: string }> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/reports?format=${format}`, { headers: headers() })
    if (!res.ok) {
      await handleJsonResponse<unknown>(res)
    }
    const blob = await res.blob()
    const filename = parseFilename(res.headers.get('content-disposition'), `report-${jobId.slice(0, 8)}.${format === 'endpoints' ? 'txt' : format}`)
    const contentType = res.headers.get('content-type') || blob.type || 'application/octet-stream'
    return { blob, filename, contentType }
  },

  async cancelScan(jobId: string): Promise<{ status: string }> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/cancel`, {
      method: 'POST',
      headers: headers(),
    })
    return handleJsonResponse(res)
  },

  async restartScan(jobId: string): Promise<Scan> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/restart`, {
      method: 'POST',
      headers: headers(),
    })
    return handleJsonResponse(res)
  },

  async listCiTokens(): Promise<CiTokenListItem[]> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens`, { headers: headers() })
    const data = await handleJsonResponse<CiTokenListItem[] | null>(res)
    return data || []
  },

  async createCiToken(body: { name?: string; ownerUserId: string; expiresAt?: string }): Promise<CiTokenCreateResponse> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
    })
    return handleJsonResponse(res)
  },

  async getCiToken(id: string): Promise<CiTokenListItem> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens/${id}`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async revokeCiToken(id: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens/${id}`, { method: 'DELETE', headers: headers() })
    if (!res.ok) await handleJsonResponse(res)
  },

  async patchCiTokenOwner(id: string, ownerUserId: string): Promise<CiTokenListItem> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens/${id}`, {
      method: 'PATCH',
      headers: headers(),
      body: JSON.stringify({ ownerUserId }),
    })
    return handleJsonResponse(res)
  },

  async listCiTokenScans(tokenId: string, page = 1, limit = 20): Promise<ScanWithFindingsCount[]> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens/${tokenId}/scans?page=${page}&limit=${limit}`, { headers: headers() })
    const data = await handleJsonResponse<ScanWithFindingsCount[] | null>(res)
    return data || []
  },

  async listUsers(): Promise<UserRow[]> {
    const res = await fetch(`${BASE_URL}/admin/users`, { headers: headers() })
    const data = await handleJsonResponse<UserRow[] | null>(res)
    return data || []
  },

  async createUser(body: { login: string; password: string; role: string }): Promise<UserRow> {
    const res = await fetch(`${BASE_URL}/admin/users`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
    })
    return handleJsonResponse(res)
  },

  async getUser(id: string): Promise<{ user: UserRow; ciTokens: CiTokenListItem[] }> {
    const res = await fetch(`${BASE_URL}/admin/users/${id}`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async patchUserRole(id: string, role: string): Promise<UserRow> {
    const res = await fetch(`${BASE_URL}/admin/users/${id}`, {
      method: 'PATCH',
      headers: headers(),
      body: JSON.stringify({ role }),
    })
    return handleJsonResponse(res)
  },

  async deleteUser(id: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/admin/users/${id}`, {
      method: 'DELETE',
      headers: headers(),
    })
    if (!res.ok) await handleJsonResponse(res)
  },

  async verifyCiToken(token: string): Promise<{ valid: boolean; login: string; role: string; name?: string; ownerLogin?: string }> {
    const res = await fetch(`${BASE_URL}/admin/ci-tokens/verify`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ token }),
    })
    return handleJsonResponse(res)
  },

  async listMyCiTokens(): Promise<CiTokenListItem[]> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens`, { headers: headers() })
    const data = await handleJsonResponse<CiTokenListItem[] | null>(res)
    return data || []
  },

  async createMyCiToken(body: { name?: string; expiresAt?: string }): Promise<CiTokenCreateResponse> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
    })
    return handleJsonResponse(res)
  },

  async verifyMyCiToken(token: string): Promise<{ valid: boolean; name?: string; status?: string; jenkinsCredentialId?: string }> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens/verify`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ token }),
    })
    return handleJsonResponse(res)
  },

  async revokeMyCiToken(id: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens/${id}`, { method: 'DELETE', headers: headers() })
    if (!res.ok) await handleJsonResponse(res)
  },

  async getMyCiToken(id: string): Promise<CiTokenListItem> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens/${id}`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async listMyCiTokenScans(tokenId: string, page = 1, limit = 20): Promise<ScanWithFindingsCount[]> {
    const res = await fetch(`${BASE_URL}/me/ci-tokens/${tokenId}/scans?page=${page}&limit=${limit}`, { headers: headers() })
    const data = await handleJsonResponse<ScanWithFindingsCount[] | null>(res)
    return data || []
  },

  async getScanLogs(scanId: string, level?: string): Promise<ScanLogsResponse> {
    const q = level ? `?level=${encodeURIComponent(level)}` : ''
    const res = await fetch(`${BASE_URL}/scans/${scanId}/logs${q}`, { headers: headers() })
    return handleJsonResponse(res)
  },

  async downloadScanDump(scanId: string): Promise<{ blob: Blob; filename: string }> {
    const res = await fetch(`${BASE_URL}/scans/${scanId}/dump`, { headers: headers() })
    if (!res.ok) await handleJsonResponse(res)
    const blob = await res.blob()
    const filename = parseFilename(res.headers.get('content-disposition'), `dast-dump-${scanId.slice(0, 8)}.zip`)
    return { blob, filename }
  },
}