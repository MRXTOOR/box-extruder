import { Scan, Finding, ScanConfig } from '../../entities/Scan/model/types'

const BASE_URL = '/api/v1'

function getToken(): string | null {
  return localStorage.getItem('token')
}

function headers(): HeadersInit {
  const token = getToken()
  const h: HeadersInit = { 'Content-Type': 'application/json' }
  if (token) h['Authorization'] = `Bearer ${token}`
  return h
}

async function handleJsonResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || 'Request failed')
  }
  const text = await res.text()
  if (!text || text === 'null') {
    return null as unknown as T
  }
  try {
    return JSON.parse(text)
  } catch {
    return null as unknown as T
  }
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
    try {
      const res = await fetch(`${BASE_URL}/scans`, { headers: headers() })
      const data = await handleJsonResponse<Scan[] | null>(res)
      return data || []
    } catch {
      return []
    }
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

  async getScanStatus(id: string): Promise<{ status: string } | string> {
    try {
      const res = await fetch(`${BASE_URL}/scans/${id}/status`, { headers: headers() })
      const text = await res.text()
      if (!text || text === 'null') return { status: 'UNKNOWN' }
      try {
        return JSON.parse(text)
      } catch {
        return text
      }
    } catch {
      return { status: 'UNKNOWN' }
    }
  },

  async getScanEndpoints(jobId: string): Promise<{ endpoints: string[] }> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}/endpoints`, { headers: headers() })
    return handleJsonResponse(res)
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
}