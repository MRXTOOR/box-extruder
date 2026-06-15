import { useEffect, useId, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, LogOut } from 'lucide-react'
import { clearToken } from '../../../shared/auth/token'
import type { CurrentUser } from '../../../shared/auth/userContext'

function userInitial(login: string): string {
  const ch = login.trim().charAt(0)
  return ch ? ch.toUpperCase() : '?'
}

const ROLE_LABEL: Record<string, string> = {
  admin: 'Администратор',
  specialist: 'Специалист',
}

export function UserMenu({ user }: { user: CurrentUser }) {
  const navigate = useNavigate()
  const menuId = useId()
  const rootRef = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const handleLogout = () => {
    setOpen(false)
    clearToken()
    navigate('/login')
  }

  return (
    <div className="user-menu" ref={rootRef}>
      <button
        type="button"
        className={`user-menu-trigger${open ? ' user-menu-trigger-open' : ''}`}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-controls={menuId}
        title={user.login}
      >
        <span className="user-avatar" aria-hidden="true">
          {userInitial(user.login)}
        </span>
        <ChevronDown className="user-menu-chevron" size={14} strokeWidth={2} aria-hidden />
      </button>
      {open && (
        <div id={menuId} className="user-menu-dropdown" role="menu">
          <div className="user-menu-header">
            <span className="user-menu-avatar-lg" aria-hidden="true">
              {userInitial(user.login)}
            </span>
            <div className="user-menu-meta">
              <span className="user-menu-login">{user.login}</span>
              <span className="user-menu-role">{ROLE_LABEL[user.role] ?? user.role}</span>
            </div>
          </div>
          <button type="button" className="user-menu-item" role="menuitem" onClick={handleLogout}>
            <LogOut size={16} strokeWidth={2} aria-hidden />
            Выйти
          </button>
        </div>
      )}
    </div>
  )
}
