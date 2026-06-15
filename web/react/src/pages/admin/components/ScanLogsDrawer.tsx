import { useEffect, useState } from 'react'
import { api } from '../../../shared/api/api'
import { ScanLogsResponse } from '../../../entities/CiToken/model/types'
import { downloadScanDump } from '../../../shared/lib/download'
import styles from '../Admin.module.css'

interface Props {
  scanId: string
  onClose: () => void
}

export function ScanLogsDrawer({ scanId, onClose }: Props) {
  const [tab, setTab] = useState<'events' | 'orch' | 'workers'>('events')
  const [logs, setLogs] = useState<ScanLogsResponse | null>(null)
  const [errorsOnly, setErrorsOnly] = useState(false)

  useEffect(() => {
    api.getScanLogs(scanId, errorsOnly ? 'error,warn' : undefined).then(setLogs).catch(alert)
  }, [scanId, errorsOnly])

  const events = logs?.events || []

  return (
    <>
      <div className={styles.modalBackdrop} onClick={onClose} />
      <div className={styles.drawer}>
        <div className={styles.drawerHead}>
          <strong>Журнал скана</strong>
          <button type="button" className={styles.btn} onClick={onClose}>Закрыть</button>
        </div>
        <div className={styles.drawerBody}>
          <div className={styles.tabs}>
            <button type="button" className={`${styles.tab} ${tab === 'events' ? styles.tabActive : ''}`} onClick={() => setTab('events')}>События</button>
            <button type="button" className={`${styles.tab} ${tab === 'orch' ? styles.tabActive : ''}`} onClick={() => setTab('orch')}>Оркестратор</button>
            <button type="button" className={`${styles.tab} ${tab === 'workers' ? styles.tabActive : ''}`} onClick={() => setTab('workers')}>Воркеры</button>
          </div>
          <label>
            <input type="checkbox" checked={errorsOnly} onChange={(e) => setErrorsOnly(e.target.checked)} /> Только ошибки и предупреждения
          </label>
          {tab === 'events' && events.map((ev, i) => (
            <div key={i} className={`${styles.logLine} ${ev.level === 'error' ? styles.logError : ev.level === 'warn' ? styles.logWarn : ''}`}>
              [{ev.time}] {ev.step && `${ev.step}: `}{ev.message}
            </div>
          ))}
          {tab === 'orch' && (logs?.orchestratorTail || []).map((line, i) => (
            <div key={i} className={styles.logLine}>{line}</div>
          ))}
          {tab === 'workers' && (logs?.workerFiles || []).map((f) => (
            <div key={f.name} className={styles.logLine}>{f.name} ({f.size} байт)</div>
          ))}
          <div style={{ marginTop: 16 }}>
            <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={() => downloadScanDump(scanId).catch(alert)}>
              Скачать полный архив
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
