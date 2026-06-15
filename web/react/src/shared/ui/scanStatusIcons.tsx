import type { LucideIcon } from 'lucide-react'
import {
  Ban,
  CheckCircle2,
  Circle,
  CirclePause,
  Clock,
  KeyRound,
  Play,
  TriangleAlert,
  XCircle,
} from "lucide-react";

export const scanStatusIconMap: Record<string, LucideIcon> = {
  SUCCEEDED: CheckCircle2,
  FAILED: XCircle,
  PARTIAL_SUCCESS: TriangleAlert,
  RUNNING: Play,
  QUEUED: Clock,
  WAITING_FOR_AUTH: KeyRound,
  PENDING: CirclePause,
  CANCELLED: Ban,
  CANCELED: Ban,
}

export function scanStatusIcon(status: string): LucideIcon {
  return scanStatusIconMap[status] ?? Circle
}
