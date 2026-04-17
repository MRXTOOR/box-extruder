import { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import './Layout.css'

export function Layout({ children }: { children: ReactNode }) {
  const navigate = useNavigate()

  const handleLogout = () => {
    localStorage.removeItem('token')
    navigate('/login')
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
            <div>
              <h1>DAST</h1>
              <p className="tagline">Автодетект логина, Katana → ZAP → Nuclei — один запуск из браузера.</p>
            </div>
          </div>
          <div className="pipeline" title="Цепочка сканирования">
            <span><span className="dot" aria-hidden="true"></span>Katana</span>
            <span className="arrow" aria-hidden="true">→</span>
            <span><span className="dot g" aria-hidden="true"></span>ZAP</span>
            <span className="arrow" aria-hidden="true">→</span>
            <span><span className="dot p" aria-hidden="true"></span>Nuclei</span>
          </div>
          <button className="logout-btn" onClick={handleLogout}>Выйти</button>
        </header>
        {children}
      </main>
      <footer className="foot">Локальный оркестратор · отчёты и события в отдельных вкладках</footer>
    </div>
  )
}