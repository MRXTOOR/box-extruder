import { useEffect } from 'react'
import { Check, X } from 'lucide-react'
import styles from './Toast.module.css'

export type ToastVariant = 'success' | 'error'

export interface ToastProps {
  variant: ToastVariant
  message: string
  durationMs?: number
  onClose: () => void
}

export function Toast({ variant, message, durationMs = 10_000, onClose }: ToastProps) {
  useEffect(() => {
    const timer = window.setTimeout(onClose, durationMs)
    return () => window.clearTimeout(timer)
  }, [durationMs, onClose, message, variant])

  return (
    <div
      className={`${styles.toast} ${variant === 'success' ? styles.success : styles.error}`}
      role="status"
      aria-live="polite"
    >
      <span className={styles.icon} aria-hidden>
        {variant === 'success' ? (
          <Check size={18} strokeWidth={2.5} />
        ) : (
          <X size={18} strokeWidth={2.5} />
        )}
      </span>
      <p className={styles.message}>{message}</p>
      <button type="button" className={styles.close} onClick={onClose} aria-label="Закрыть">
        <X size={16} strokeWidth={2} />
      </button>
    </div>
  )
}
