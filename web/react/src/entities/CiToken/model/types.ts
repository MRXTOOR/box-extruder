export interface CiTokenListItem {
  id: string
  userId: string
  name: string
  status: string
  serviceUserLogin: string
  ownerUserId?: string
  ownerLogin?: string
  createdByLogin?: string
  scanCount: number
  jenkinsCredentialId: string
  createdAt: string
  lastUsedAt?: string
  revokedAt?: string
  expiresAt?: string
}

export interface CiTokenCreateResponse {
  secret: string
  token: CiTokenListItem
  ownerLogin: string
  serviceUserLogin: string
  jenkinsCredentialId: string
}

export interface ScanWithFindingsCount {
  id: string
  jobId: string
  targetUrl: string
  status: string
  source?: string
  createdAt: string
  finishedAt?: string
  findingsCount: number
}

export interface ScanLogEvent {
  time: string
  level: string
  step?: string
  message: string
}

export interface ScanLogsResponse {
  events: ScanLogEvent[]
  orchestratorTail: string[]
  workerFiles: { name: string; size: number }[]
  summary?: {
    jobId: string
    status: string
    targetUrl: string
    errors: string[]
    findingsCount: number
  }
}

export interface UserRow {
  id: string
  login: string
  role: string
  createdAt: string
  ciTokenCount?: number
}
