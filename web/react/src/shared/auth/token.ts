// Centralized JWT storage. localStorage is XSS-readable; this is a known
// limitation kept for simplicity. Keep the storage key in one place so the
// whole app stays consistent.
const TOKEN_KEY = 'token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function isAuthenticated(): boolean {
  return !!getToken()
}

// onAuthExpired clears the session and sends the user back to the login page.
// Called when the API rejects a request with 401 (expired/invalid token).
export function onAuthExpired(): void {
  clearToken()
  if (window.location.pathname !== '/login') {
    window.location.assign('/login')
  }
}
