import { Routes, Route, Outlet } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { LoginPage } from '../pages/LoginPage/LoginPage'
import { ScansPage } from '../pages/ScansPage/ScansPage'
import { ScanDetailPage } from '../pages/ScanDetailPage/ScanDetailPage'

function LayoutWrapper() {
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<LayoutWrapper />}>
        <Route index element={<ScansPage />} />
        <Route path="scans/:id" element={<ScanDetailPage />} />
      </Route>
    </Routes>
  )
}