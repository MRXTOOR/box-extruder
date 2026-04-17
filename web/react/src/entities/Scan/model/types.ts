export interface Scan {
  id: string
  userId: string
  jobId: string
  targetUrl: string
  status: ScanStatus
  configHash?: string
  createdAt: string
  updatedAt: string
  finishedAt?: string
}

export type ScanStatus = 
  | 'QUEUED' 
  | 'RUNNING' 
  | 'SUCCEEDED' 
  | 'FAILED' 
  | 'PARTIAL_SUCCESS'
  | 'WAITING_FOR_AUTH'
  | 'PENDING'
  | 'CANCELLED'

export interface Finding {
  id: string
  scanId: string
  severity: FindingSeverity
  name: string
  description: string
  evidence?: Record<string, unknown>
  createdAt: string
}

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface User {
  id: string
  login: string
  role: UserRole
  createdAt: string
}

export type UserRole = 'admin' | 'specialist'

export interface ScanConfig {
  targetUrl: string
  login?: string
  password?: string
  authUrl?: string
  verifyUrl?: string
  katanaDepth?: number
  katanaMaxUrls?: number
  zapSpiderMinutes?: number
  zapPassiveSecs?: number
  startPoints?: string
  insecureSkipVerify?: boolean
}