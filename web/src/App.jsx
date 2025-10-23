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
    const wsUrl = `${protocol}//${window.location.hostname}:8005/ws`
    
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
        // Correlate completion events to their corresponding running activity
        // so the spinner changes to a checkmark on the same line.
        const correlates = new Map([
          ['SPL generated', 'Generating SPL query'],
          ['VQL generated', 'Generating VQL query'],
          ['Summary ready', 'Summarizing results'],
        ])

        setActivities(prev => {
          const updated = [...prev]

          const status = data.status
          const title = data.title
          const detail = data.detail

          // Special handling for "Search completed" - match either Splunk or Velociraptor
          if (status === 'done' && title === 'Search completed') {
            // Try to find either executing search activity
            let targetIdx = updated.findIndex(a => a.id === 'Executing Splunk search')
            if (targetIdx < 0) {
              targetIdx = updated.findIndex(a => a.id === 'Executing Velociraptor query')
            }
            if (targetIdx >= 0) {
              updated[targetIdx] = {
                ...updated[targetIdx],
                type: 'success',
                status: 'done',
                details: detail,
                timestamp: new Date().toISOString(),
              }
              // Mark 'Analyzing question' as complete if present
              const analyzingIdx = updated.findIndex(a => a.id === 'Analyzing question')
              if (analyzingIdx >= 0 && updated[analyzingIdx].type === 'info') {
                updated[analyzingIdx] = {
                  ...updated[analyzingIdx],
                  type: 'success',
                  status: 'done',
                  timestamp: new Date().toISOString(),
                }
              }
              return updated
            }
          }

          // If this is a completion that maps to a running step, update the running step only
          if (status === 'done' && correlates.has(title)) {
            const targetId = correlates.get(title)
            const targetIdx = updated.findIndex(a => a.id === targetId)
            if (targetIdx >= 0) {
              updated[targetIdx] = {
                ...updated[targetIdx],
                type: 'success',
                status: 'done',
                // Prefer the newly provided detail (e.g., the generated SPL/VQL string)
                details: (detail && String(detail).length > 0) ? detail : updated[targetIdx].details,
                timestamp: new Date().toISOString(),
              }
            } else {
              // If we didn't track the running step yet, fall back to adding this as its own entry
              updated.push({
                id: title,
                type: 'success',
                message: title,
                details: detail,
                status: 'done',
                timestamp: new Date().toISOString(),
              })
            }
            // Mark 'Analyzing question' as complete if present
            const analyzingIdx = updated.findIndex(a => a.id === 'Analyzing question')
            if (analyzingIdx >= 0 && updated[analyzingIdx].type === 'info') {
              updated[analyzingIdx] = {
                ...updated[analyzingIdx],
                type: 'success',
                status: 'done',
                timestamp: new Date().toISOString(),
              }
            }
            return updated
          }

          // If this is a new activity after 'Analyzing question', mark 'Analyzing question' as complete
          if (title !== 'Analyzing question') {
            const analyzingIdx = updated.findIndex(a => a.id === 'Analyzing question')
            if (analyzingIdx >= 0 && updated[analyzingIdx].type === 'info') {
              updated[analyzingIdx] = {
                ...updated[analyzingIdx],
                type: 'success',
                status: 'done',
                timestamp: new Date().toISOString(),
              }
            }
          }

          // Otherwise, insert/update this activity by its own title
          const id = title
          const existingIndex = updated.findIndex(a => a.id === id)
          const type = status === 'running' ? 'info' : status === 'done' ? 'success' : 'error'
          const entry = { id, type, message: title, details: detail, status, timestamp: new Date().toISOString() }

          if (existingIndex >= 0) {
            updated[existingIndex] = entry
          } else {
            updated.push(entry)
          }

          return updated
        })
      } else if (data.type === 'final') {
        // Final results with SPL/VQL, count, results, summary, and source
        setSearchResults({
          summary: data.summary,
          results: data.results,
          spl: data.spl,
          vql: data.vql,
          count: data.count,
          source: data.source || 'splunk' // default to splunk for backward compatibility
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
      // Clear previous run's activity and summary before sending a new question
      setActivities([])
      setSearchResults(null)
      // Backend expects plain text, not JSON
      wsRef.current.send(message)
      setMessages(prev => [...prev, { role: 'user', content: message }])
    }
  }

  const handleNewHunt = () => {
    // Clear all UI state for a fresh hunt
    setMessages([])
    setActivities([])
    setSearchResults(null)
  }

  return (
    <ThreatHuntingPlatform 
      messages={messages}
      activities={activities}
      searchResults={searchResults}
      isConnected={isConnected}
      onSendMessage={sendMessage}
      onNewHunt={handleNewHunt}
    />
  )
}

export default App
