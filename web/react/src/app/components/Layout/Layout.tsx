import { ReactNode } from 'react'
import './Layout.css'

export function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="layout">
      <header className="header">
        <h1>DAST Enterprise</h1>
        <nav>
          <a href="/">Scans</a>
          <button onClick={() => {
            localStorage.removeItem('token')
            window.location.href = '/login'
          }}>Logout</button>
        </nav>
      </header>
      <main className="main">{children}</main>
    </div>
  )
}