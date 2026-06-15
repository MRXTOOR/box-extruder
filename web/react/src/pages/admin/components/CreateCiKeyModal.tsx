import { useEffect, useMemo, useState } from 'react'
import { api } from '../../../shared/api/api'
import { UserRow } from '../../../entities/CiToken/model/types'
import styles from '../Admin.module.css'

interface Props {
  onClose: () => void
  onCreated: () => void
  scope?: 'admin' | 'self'
  defaultOwnerUserId?: string
}

function generateCiKeyName(): string {
  const bytes = new Uint8Array(4)
  crypto.getRandomValues(bytes)
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  return `key-${hex}`
}

function minExpiryDate(): string {
  const d = new Date()
  d.setDate(d.getDate() + 1)
  return d.toISOString().slice(0, 10)
}

export function CreateCiKeyModal({ onClose, onCreated, scope = 'admin', defaultOwnerUserId }: Props) {
  const isSelf = scope === 'self'
  const [name, setName] = useState(generateCiKeyName)
  const [ownerUserId, setOwnerUserId] = useState(defaultOwnerUserId || '')
  const [expiresAt, setExpiresAt] = useState('')
  const [users, setUsers] = useState<UserRow[]>([])
  const [secret, setSecret] = useState<string | null>(null)
  const [jenkinsCredId, setJenkinsCredId] = useState('')
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [saving, setSaving] = useState(false)

  const minDate = useMemo(() => minExpiryDate(), [])

  useEffect(() => {
    if (!isSelf && !defaultOwnerUserId) {
      api.listUsers().then(setUsers).catch(() => {})
    }
  }, [isSelf, defaultOwnerUserId])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try {
      const payload = {
        name,
        expiresAt: expiresAt || undefined,
      }
      const res = isSelf
        ? await api.createMyCiToken(payload)
        : await api.createCiToken({ ...payload, ownerUserId })
      setSecret(res.secret)
      setJenkinsCredId(res.jenkinsCredentialId)
      onCreated()
    } catch (err) {
      alert(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  const verifySecret = async () => {
    if (!secret) return
    setVerifying(true)
    setVerifyMsg(null)
    try {
      if (isSelf) {
        const res = await api.verifyMyCiToken(secret)
        setVerifyMsg(`OK: ключ «${res.name || '—'}», статус ${res.status || '—'}`)
      } else {
        const res = await api.verifyCiToken(secret)
        setVerifyMsg(`OK: сервисная учётка ${res.login}, ключ «${res.name || '—'}», владелец ${res.ownerLogin || '—'}`)
      }
    } catch (err) {
      setVerifyMsg(err instanceof Error ? err.message : String(err))
    } finally {
      setVerifying(false)
    }
  }

  const copySecret = () => {
    if (secret) navigator.clipboard.writeText(secret)
  }

  const title = secret
    ? 'Ключ создан'
    : isSelf
      ? 'Создать CI-ключ для себя'
      : defaultOwnerUserId
        ? 'Сгенерировать CI-ключ для пользователя'
        : 'Сгенерировать CI-ключ'

  return (
    <div className={styles.modalBackdrop} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <h3 className={styles.title}>{title}</h3>
        {secret ? (
          <>
            <p className={styles.warn}>Секрет показывается один раз — сохраните его в Jenkins Secret text.</p>
            <div className={styles.secretBox}>{secret}</div>
            <p className={styles.subtitle}>Метка: <code>{name}</code></p>
            <p className={styles.subtitle}>Credential ID: <code>{jenkinsCredId}</code></p>
            <pre className={styles.secretBox}>{`apiTokenCredentialId: '${jenkinsCredId}'`}</pre>
            {verifyMsg && <p className={styles.subtitle}>{verifyMsg}</p>}
            <div className={styles.actions}>
              <button type="button" className={styles.btn} onClick={copySecret}>Скопировать</button>
              <button type="button" className={styles.btn} disabled={verifying} onClick={verifySecret}>
                {verifying ? 'Проверка…' : 'Проверить ключ'}
              </button>
              <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={onClose}>Готово</button>
            </div>
          </>
        ) : (
          <form onSubmit={submit}>
            {isSelf && (
              <p className={styles.subtitle}>Ключ будет привязан к вашей учётной записи. Jenkins-сканы по нему появятся в этом разделе.</p>
            )}
            <div className={styles.field}>
              <label>Метка ключа (Jenkins credential)</label>
              <div className={styles.headRow}>
                <code className={styles.secretBox} style={{ margin: 0, flex: 1 }}>{name}</code>
                <button type="button" className={styles.btn} onClick={() => setName(generateCiKeyName())}>
                  Другая метка
                </button>
              </div>
              <span className={styles.subtitle}>Генерируется автоматически · credential ID: dast-ci-{name}</span>
            </div>
            {!isSelf && !defaultOwnerUserId && (
              <div className={styles.field}>
                <label htmlFor="ci-owner">Владелец</label>
                <select id="ci-owner" value={ownerUserId} onChange={(e) => setOwnerUserId(e.target.value)} required>
                  <option value="">Выберите пользователя</option>
                  {users.map((u) => (
                    <option key={u.id} value={u.id}>{u.login} ({u.role})</option>
                  ))}
                </select>
              </div>
            )}
            <div className={styles.field}>
              <label htmlFor="ci-exp">Срок действия (необязательно)</label>
              <input
                id="ci-exp"
                type="date"
                value={expiresAt}
                min={minDate}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
              <span className={styles.subtitle}>Оставьте пустым — ключ без срока. Истекает в конце выбранного дня (UTC).</span>
            </div>
            <div className={styles.actions}>
              <button type="button" className={styles.btn} onClick={onClose}>Отмена</button>
              <button type="submit" className={`${styles.btn} ${styles.btnPrimary}`} disabled={saving}>
                {saving ? 'Создание…' : 'Сгенерировать'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
