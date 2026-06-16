import { ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { KeyRound, Radar, Shield, Users } from 'lucide-react'
import { useCurrentUser, useIsAdmin } from '../../../shared/auth/userContext'
import { BrandLogo } from '../../../shared/ui/BrandLogo'
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
          <NavLink to="/" className="brand" aria-label="DAST — на главную">
            <BrandLogo />
          </NavLink>

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
