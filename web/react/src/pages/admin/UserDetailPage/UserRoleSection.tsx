import { roleLabel } from '../components/CreateUserModal'
import styles from '../Admin.module.css'
import type { UserRow } from '../../../entities/CiToken/model/types'

type RoleEditorState = {
  role: string
  saving: boolean
  onChange: (role: string) => void
  onSave: () => void
}

type DeleteState = {
  deleting: boolean
  onDelete: () => void
}

type Props = {
  user: UserRow
  roleEditor: RoleEditorState
  deleteAction: DeleteState
}

export function UserRoleSection({ user, roleEditor, deleteAction }: Props) {
  return (
    <>
      <h2 className={styles.title}>{user.login}</h2>
      <div className={styles.field} style={{ maxWidth: 280 }}>
        <label htmlFor="user-role">Роль</label>
        <div className={styles.headRow}>
          <select id="user-role" value={roleEditor.role} onChange={(e) => roleEditor.onChange(e.target.value)}>
            <option value="specialist">{roleLabel('specialist')}</option>
            <option value="admin">{roleLabel('admin')}</option>
          </select>
          <button
            type="button"
            className={`${styles.btn} ${styles.btnPrimary}`}
            disabled={roleEditor.saving || roleEditor.role === user.role}
            onClick={roleEditor.onSave}
          >
            {roleEditor.saving ? 'Сохранение…' : 'Сохранить роль'}
          </button>
        </div>
      </div>
      <div className={styles.actions} style={{ marginTop: '1rem' }}>
        <button type="button" className={styles.btn} disabled={deleteAction.deleting} onClick={deleteAction.onDelete}>
          {deleteAction.deleting ? 'Удаление…' : 'Удалить пользователя'}
        </button>
      </div>
    </>
  )
}
