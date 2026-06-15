import { Routes, Route, Outlet, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { LoginPage } from '../pages/LoginPage/LoginPage'
import { ScansPage } from '../pages/ScansPage/ScansPage'
import { ScanDetailPage } from '../pages/ScanDetailPage/ScanDetailPage'
import { CiKeysPage } from '../pages/admin/CiKeysPage/CiKeysPage'
import { CiKeyDetailPage } from '../pages/admin/CiKeyDetailPage/CiKeyDetailPage'
import { UsersPage } from '../pages/admin/UsersPage/UsersPage'
import { UserDetailPage } from '../pages/admin/UserDetailPage/UserDetailPage'
import { MyCiKeysPage } from '../pages/CiKeysPage/MyCiKeysPage'
import { MyCiKeyDetailPage } from '../pages/CiKeysPage/MyCiKeyDetailPage'
import { isAuthenticated } from '../shared/auth/token'
import { useCurrentUser } from '../shared/auth/userContext'

function LayoutWrapper() {
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const user = useCurrentUser()
  if (user && user.role !== 'admin') {
    return <Navigate to="/" replace />
  }
  return <>{children}</>
}

function NonAdminRoute({ children }: { children: React.ReactNode }) {
  const user = useCurrentUser()
  if (user?.role === 'admin') {
    return <Navigate to="/" replace />
  }
  return <>{children}</>
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={
        <ProtectedRoute>
          <LayoutWrapper />
        </ProtectedRoute>
      }>
        <Route index element={<ScansPage />} />
        <Route path="scans/:id" element={<ScanDetailPage />} />
        <Route path="ci-keys" element={<NonAdminRoute><MyCiKeysPage /></NonAdminRoute>} />
        <Route path="ci-keys/:id" element={<NonAdminRoute><MyCiKeyDetailPage /></NonAdminRoute>} />
        <Route path="admin/ci-keys" element={<AdminRoute><CiKeysPage /></AdminRoute>} />
        <Route path="admin/ci-keys/:id" element={<AdminRoute><CiKeyDetailPage /></AdminRoute>} />
        <Route path="admin/users" element={<AdminRoute><UsersPage /></AdminRoute>} />
        <Route path="admin/users/:id" element={<AdminRoute><UserDetailPage /></AdminRoute>} />
      </Route>
    </Routes>
  )
}
