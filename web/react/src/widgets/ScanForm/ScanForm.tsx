import { FC, FormEvent, useState } from 'react'
import styles from './ScanForm.module.css'

export interface ScanFormProps {
  onSubmit: (targetUrl: string) => Promise<void>
}

export const ScanForm: FC<ScanFormProps> = ({ onSubmit }) => {
  const [targetUrl, setTargetUrl] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await onSubmit(targetUrl)
      setTargetUrl('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form className={styles.form} onSubmit={handleSubmit}>
      <input
        type="text"
        className={styles.input}
        placeholder="Target URL (https://example.com)"
        value={targetUrl}
        onChange={(e) => setTargetUrl(e.target.value)}
        required
        disabled={loading}
      />
      <button type="submit" className={styles.button} disabled={loading}>
        {loading ? 'Starting...' : 'Start Scan'}
      </button>
    </form>
  )
}