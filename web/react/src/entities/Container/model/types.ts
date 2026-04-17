export interface ContainerStatus {
  name: string
  image: string
  status: string
  state: string
  health: 'healthy' | 'unhealthy' | 'starting' | 'stopped' | 'restarting' | 'dead' | 'unknown'
  startedAt: string
  finishedAt?: string
  exitCode: number
  oomKilled: boolean
  restarting: boolean
}