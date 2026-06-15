import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { api } from '../api/api'
import { clearToken, isAuthenticated } from './token'

export interface CurrentUser {
  id: string
  login: string
  role: string
}

type UserContextValue = {
  user: CurrentUser | null
  reload: () => Promise<void>
}

const UserContext = createContext<UserContextValue>({
  user: null,
  reload: async () => {},
})

export function UserProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(null)

  const reload = async () => {
    if (!isAuthenticated()) {
      setUser(null)
      return
    }
    try {
      setUser(await api.getMe())
    } catch {
      clearToken()
      setUser(null)
    }
  }

  useEffect(() => {
    reload()
  }, [])

  return (
    <UserContext.Provider value={{ user, reload }}>
      {children}
    </UserContext.Provider>
  )
}

export function useCurrentUser() {
  return useContext(UserContext).user
}

export function useUserReload() {
  return useContext(UserContext).reload
}

export function useIsAdmin() {
  const user = useCurrentUser()
  return user?.role === 'admin'
}
