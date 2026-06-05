import { Routes, Route, Outlet, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { LoginPage } from '../pages/LoginPage/LoginPage'
import { ScansPage } from '../pages/ScansPage/ScansPage'
import { ScanDetailPage } from '../pages/ScanDetailPage/ScanDetailPage'
import { isAuthenticated } from '../shared/auth/token'

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
      </Route>
    </Routes>
  )
}