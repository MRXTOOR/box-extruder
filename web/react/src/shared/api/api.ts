import { Scan, Finding } from '../../entities/Scan/model/types'

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

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }))
    throw new Error(err.error || 'Request failed')
  }
  return res.json()
}

export const api = {
  async login(login: string, password: string): Promise<{ token: string }> {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ login, password }),
    })
    return handleResponse(res)
  },

  async getMe(): Promise<{ id: string; login: string; role: string }> {
    const res = await fetch(`${BASE_URL}/auth/me`, { headers: headers() })
    return handleResponse(res)
  },

  async getScans(): Promise<Scan[]> {
    const res = await fetch(`${BASE_URL}/scans`, { headers: headers() })
    return handleResponse(res)
  },

  async createScan(data: { targetUrl: string }): Promise<Scan> {
    const res = await fetch(`${BASE_URL}/scans`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(data),
    })
    return handleResponse(res)
  },

  async getScan(id: string): Promise<Scan & { findings: Finding[] }> {
    const res = await fetch(`${BASE_URL}/scans/${id}`, { headers: headers() })
    return handleResponse(res)
  },

  async deleteScan(jobId: string): Promise<void> {
    const res = await fetch(`${BASE_URL}/scans/${jobId}`, {
      method: 'DELETE',
      headers: headers(),
    })
    if (!res.ok) throw new Error('Delete failed')
  },

  async getScanStatus(id: string): Promise<string> {
    const res = await fetch(`${BASE_URL}/scans/${id}/status`, { headers: headers() })
    return handleResponse(res)
  },
}