import { useState, useEffect, useRef } from 'react'
import ThreatHuntingPlatform from './ThreatHuntingPlatform'
import './App.css'

function App() {
  const [messages, setMessages] = useState([])
  const [activities, setActivities] = useState([])
  const [searchResults, setSearchResults] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef(null)

  useEffect(() => {
    // Connect to WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.hostname}:8002/ws`
    
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      console.log('WebSocket connected')
      setIsConnected(true)
    }

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      console.log('WebSocket message received:', data)
      
      if (data.type === 'activity') {
        // Activity updates during the search process
        const activity = {
          type: data.status === 'running' ? 'info' : data.status === 'done' ? 'success' : 'error',
          message: data.title,
          details: data.detail,
          timestamp: new Date().toISOString()
        }
        setActivities(prev => [...prev, activity])
      } else if (data.type === 'final') {
        // Final results with SPL, count, results, and summary
        setSearchResults({
          summary: data.summary,
          results: data.results,
          spl: data.spl,
          count: data.count
        })
        // Add assistant message with summary
        setMessages(prev => [...prev, { role: 'assistant', content: data.summary }])
      } else if (data.type === 'error') {
        // Error from backend
        const errorMsg = `${data.title}: ${data.detail}`
        setMessages(prev => [...prev, { role: 'error', content: errorMsg }])
        setActivities(prev => [...prev, {
          type: 'error',
          message: data.title,
          details: data.detail,
          timestamp: new Date().toISOString()
        }])
      }
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      setIsConnected(false)
    }

    ws.onclose = () => {
      console.log('WebSocket disconnected')
      setIsConnected(false)
    }

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close()
      }
    }
  }, [])

  const sendMessage = (message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      // Backend expects plain text, not JSON
      wsRef.current.send(message)
      setMessages(prev => [...prev, { role: 'user', content: message }])
    }
  }

  return (
    <ThreatHuntingPlatform 
      messages={messages}
      activities={activities}
      searchResults={searchResults}
      isConnected={isConnected}
      onSendMessage={sendMessage}
    />
  )
}

export default App
