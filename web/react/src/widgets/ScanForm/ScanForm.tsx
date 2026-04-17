import { FC, FormEvent, useState } from 'react'
import styles from './ScanForm.module.css'

export interface ScanFormProps {
  onSubmit: (targetUrl: string, config?: ScanConfig) => Promise<void>
}

export interface ScanConfig {
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

export const ScanForm: FC<ScanFormProps> = ({ onSubmit }) => {
  const [targetUrl, setTargetUrl] = useState('')
  const [login, setLogin] = useState('')
  const [password, setPassword] = useState('')
  const [authUrl, setAuthUrl] = useState('')
  const [verifyUrl, setVerifyUrl] = useState('')
  const [katanaDepth, setKatanaDepth] = useState('')
  const [katanaMaxUrls, setKatanaMaxUrls] = useState('')
  const [zapSpiderMinutes, setZapSpiderMinutes] = useState('')
  const [zapPassiveSecs, setZapPassiveSecs] = useState('')
  const [startPoints, setStartPoints] = useState('')
  const [insecureSkipVerify, setInsecureSkipVerify] = useState(false)
  const [advOpen, setAdvOpen] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await onSubmit(targetUrl, {
        login: login || undefined,
        password: password || undefined,
        authUrl: authUrl || undefined,
        verifyUrl: verifyUrl || undefined,
        katanaDepth: katanaDepth ? parseInt(katanaDepth) : undefined,
        katanaMaxUrls: katanaMaxUrls ? parseInt(katanaMaxUrls) : undefined,
        zapSpiderMinutes: zapSpiderMinutes ? parseInt(zapSpiderMinutes) : undefined,
        zapPassiveSecs: zapPassiveSecs ? parseInt(zapPassiveSecs) : undefined,
        startPoints: startPoints || undefined,
        insecureSkipVerify,
      })
      setTargetUrl('')
      setLogin('')
      setPassword('')
      setAuthUrl('')
      setVerifyUrl('')
      setKatanaDepth('')
      setKatanaMaxUrls('')
      setZapSpiderMinutes('')
      setZapPassiveSecs('')
      setStartPoints('')
      setInsecureSkipVerify(false)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form className={styles.form} onSubmit={handleSubmit}>
      <div className={styles.field}>
        <label className={styles.label} htmlFor="targetUrl">Target URL</label>
        <input
          id="targetUrl"
          type="url"
          className={styles.input}
          placeholder="https://example.com"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          required
          disabled={loading}
        />
      </div>

      <div className={styles.row2}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="login">Логин / Email</label>
          <input
            id="login"
            type="text"
            className={styles.input}
            value={login}
            onChange={(e) => setLogin(e.target.value)}
            disabled={loading}
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="password">Пароль</label>
          <input
            id="password"
            type="password"
            className={styles.input}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
          />
        </div>
      </div>

      <div className={styles.field}>
        <label className={styles.label} htmlFor="authUrl">
          Auth URL <span className={styles.labelOptional}>— опционально</span>
        </label>
        <input
          id="authUrl"
          type="text"
          className={styles.input}
          placeholder="точный endpoint логина"
          value={authUrl}
          onChange={(e) => setAuthUrl(e.target.value)}
          disabled={loading}
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label} htmlFor="verifyUrl">
          Verify URL <span className={styles.labelOptional}>— опционально</span>
        </label>
        <input
          id="verifyUrl"
          type="text"
          className={styles.input}
          placeholder="/api/me или /profile"
          value={verifyUrl}
          onChange={(e) => setVerifyUrl(e.target.value)}
          disabled={loading}
        />
      </div>

      <details className={styles.advSettings} open={advOpen}>
        <summary onClick={(e) => { e.preventDefault(); setAdvOpen(!advOpen) }}>
          Дополнительные настройки сканирования
        </summary>
        <div className={styles.advSettingsBody}>
          <div className={styles.row2}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="katanaDepth">Глубина обхода (Katana/ZAP)</label>
              <input
                id="katanaDepth"
                type="number"
                className={styles.input}
                min="1"
                max="100"
                placeholder="10"
                value={katanaDepth}
                onChange={(e) => setKatanaDepth(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="katanaMaxUrls">Макс. URL для Katana</label>
              <input
                id="katanaMaxUrls"
                type="number"
                className={styles.input}
                min="1"
                placeholder="5000"
                value={katanaMaxUrls}
                onChange={(e) => setKatanaMaxUrls(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div className={styles.row2}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="zapSpiderMinutes">Время Spider (минуты)</label>
              <input
                id="zapSpiderMinutes"
                type="number"
                className={styles.input}
                min="1"
                placeholder="30"
                value={zapSpiderMinutes}
                onChange={(e) => setZapSpiderMinutes(e.target.value)}
                disabled={loading}
              />
            </div>
            <div className={styles.field}>
              <label className={styles.label} htmlFor="zapPassiveSecs">Passive Wait (секунды)</label>
              <input
                id="zapPassiveSecs"
                type="number"
                className={styles.input}
                min="1"
                placeholder="120"
                value={zapPassiveSecs}
                onChange={(e) => setZapPassiveSecs(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="startPoints">
              Start Points <span className={styles.labelOptional}>— дополнительные URL для обхода (по одному на строку)</span>
            </label>
            <textarea
              id="startPoints"
              className={styles.textarea}
              rows={3}
              placeholder="https://example.com/about&#10;https://example.com/contact"
              value={startPoints}
              onChange={(e) => setStartPoints(e.target.value)}
              disabled={loading}
            />
          </div>

          <label className={styles.checkboxLabel}>
            <input
              type="checkbox"
              checked={insecureSkipVerify}
              onChange={(e) => setInsecureSkipVerify(e.target.checked)}
              disabled={loading}
            />
            <span>Пропускать проверку TLS-сертификатов (для самоподписанных)</span>
          </label>
        </div>
      </details>

      <button type="submit" className={styles.button} disabled={loading}>
        {loading ? 'Запуск...' : 'Автодетект и запуск скана'}
      </button>
    </form>
  )
}