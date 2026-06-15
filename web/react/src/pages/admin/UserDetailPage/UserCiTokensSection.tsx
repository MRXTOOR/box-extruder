import { Link } from 'react-router-dom'

import type { CiTokenListItem } from '../../../entities/CiToken/model/types'
import styles from '../Admin.module.css'

type Props = {
  tokens: CiTokenListItem[]
  onCreateKey: () => void
}

export function UserCiTokensSection({ tokens, onCreateKey }: Props) {
  return (
    <>
      <div className={styles.headRow}>
        <h3>CI-ключи владельца</h3>
        <button type="button" className={`${styles.btn} ${styles.btnPrimary}`} onClick={onCreateKey}>
          Сгенерировать ключ
        </button>
      </div>
      {tokens.length === 0 ? (
        <p className={styles.empty}>Ключей нет</p>
      ) : (
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Метка</th>
              <th>Статус</th>
              <th>Сканов</th>
              <th>Создал</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td>{t.status}</td>
                <td>{t.scanCount}</td>
                <td>{t.createdByLogin || '—'}</td>
                <td><Link to={`/admin/ci-keys/${t.id}`}>История сканов</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  )
}
