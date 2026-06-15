import { ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { KeyRound, Radar, Shield, Users } from 'lucide-react'
import { useCurrentUser, useIsAdmin } from '../../../shared/auth/userContext'
import { UserMenu } from './UserMenu'
import './Layout.css'

type NavItem = {
  to: string
  label: string
  icon: typeof Radar
  isActive?: (pathname: string) => boolean
}

const NAV_ITEMS: NavItem[] = [
  {
    to: '/',
    label: 'Сканы',
    icon: Radar,
    isActive: (p) => p === '/' || p.startsWith('/scans/'),
  },
  {
    to: '/ci-keys',
    label: 'Мои CI-ключи',
    icon: KeyRound,
    isActive: (p) => p === '/ci-keys' || p.startsWith('/ci-keys/'),
  },
]

const ADMIN_NAV_ITEMS: NavItem[] = [
  {
    to: '/admin/users',
    label: 'Пользователи',
    icon: Users,
    isActive: (p) => p.startsWith('/admin/users'),
  },
  {
    to: '/admin/ci-keys',
    label: 'CI-ключи',
    icon: Shield,
    isActive: (p) => p.startsWith('/admin/ci-keys'),
  },
]

function navTabClass(active: boolean) {
  return `nav-tab${active ? ' nav-tab-active' : ''}`
}

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const user = useCurrentUser()
  const isAdmin = useIsAdmin()

  const renderTab = (item: NavItem) => {
    const Icon = item.icon
    const active = item.isActive
      ? item.isActive(location.pathname)
      : location.pathname === item.to
    return (
      <NavLink
        key={item.to}
        to={item.to}
        className={navTabClass(active)}
        aria-current={active ? 'page' : undefined}
      >
        <Icon className="nav-tab-icon" size={16} strokeWidth={2} aria-hidden />
        <span>{item.label}</span>
      </NavLink>
    )
  }

  return (
    <div className="shell">
      <div className="noise" aria-hidden="true"></div>
      <main className="main-content">
        <header className="top">
          <div className="brand">
            <div className="logo" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" stroke="url(#g)" strokeWidth="1.5" strokeLinejoin="round"/>
                <path d="M12 2v20M3 7l9 5 9-5" stroke="url(#g)" strokeWidth="1.2" strokeLinecap="round"/>
                <defs>
                  <linearGradient id="g" x1="3" y1="2" x2="21" y2="22" gradientUnits="userSpaceOnUse">
                    <stop stopColor="#58a6ff"/>
                    <stop offset="1" stopColor="#a371f7"/>
                  </linearGradient>
                </defs>
              </svg>
            </div>
            <h1>DAST</h1>
          </div>

          <div className="top-actions">
            <nav className="header-nav" aria-label="Основная навигация">
              <div className="nav-tabs">
                {NAV_ITEMS.filter((item) => !(isAdmin && item.to === '/ci-keys')).map(renderTab)}
                {isAdmin && (
                  <>
                    <span className="nav-divider" aria-hidden="true" />
                    <span className="nav-group-label">Админ</span>
                    {ADMIN_NAV_ITEMS.map(renderTab)}
                  </>
                )}
              </div>
            </nav>
            {user && <UserMenu user={user} />}
          </div>
        </header>
        {children}
      </main>
    </div>
  )
}
