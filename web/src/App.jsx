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
      
      if (data.type === 'chat_response') {
        setMessages(prev => [...prev, { role: 'assistant', content: data.message }])
      } else if (data.type === 'activity') {
        setActivities(prev => [...prev, data])
      } else if (data.type === 'search_results') {
        setSearchResults(data)
      } else if (data.type === 'error') {
        setMessages(prev => [...prev, { role: 'error', content: data.message }])
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
      wsRef.current.send(JSON.stringify({ message }))
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
