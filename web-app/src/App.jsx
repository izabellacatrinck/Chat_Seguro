import React, { useState, useEffect } from 'react'
import Login from './components/Login'
import ChatInterface from './components/ChatInterface'

function App() {
  const [clientId, setClientId] = useState(null)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  useEffect(() => {
    const savedClientId = localStorage.getItem('client_id')
    if (savedClientId) {
      setClientId(savedClientId)
      setIsAuthenticated(true)
    }
  }, [])

  const handleLogin = (id) => {
    setClientId(id)
    setIsAuthenticated(true)
    localStorage.setItem('client_id', id)
  }

  const handleLogout = () => {
    setClientId(null)
    setIsAuthenticated(false)
    localStorage.removeItem('client_id')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950">
      {!isAuthenticated ? (
        <Login onLogin={handleLogin} />
      ) : (
        <ChatInterface clientId={clientId} onLogout={handleLogout} />
      )}
    </div>
  )
}

export default App
