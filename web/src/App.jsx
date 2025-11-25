import { useState, useEffect, useRef } from 'react'
import ThreatHuntingPlatform from './ThreatHuntingPlatform'
import './App.css'

function App() {
  const [messages, setMessages] = useState([])
  const [activities, setActivities] = useState([])
  const [searchResults, setSearchResults] = useState(null)
  const [isConnected, setIsConnected] = useState(false)
  const [isHunting, setIsHunting] = useState(false)
  const [connectionId, setConnectionId] = useState(0)
  const [settings, setSettings] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('ath_settings') || '{}')
      return {
        defaultIndex: saved.defaultIndex || 'main',
        timePolicyMode: saved.timePolicyMode || 'normalize',
        splModel: saved.splModel || 'splunk_hunter',
        vqlModel: saved.vqlModel || 'velociraptor_hunter',
        summaryModel: saved.summaryModel || 'llama3:8b',
        rawResultLimit: typeof saved.rawResultLimit === 'number' ? saved.rawResultLimit : 50,
      }
    } catch {
      return { defaultIndex: 'main', timePolicyMode: 'normalize', splModel: 'splunk_hunter', vqlModel: 'velociraptor_hunter', summaryModel: 'llama3:8b', rawResultLimit: 50 }
    }
  })
  const wsRef = useRef(null)

  useEffect(() => {
    // Connect to WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.hostname}:8005/ws`

    console.log(`Connecting to WebSocket (ID: ${connectionId})...`)
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      console.log('WebSocket connected')
      setIsConnected(true)
    }

    ws.onmessage = (event) => {
      try {
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
          setIsHunting(false)
          // Final results with SPL/VQL, count, results, summary, and source
          // Ensure summary is a string to prevent React render crashes
          const safeSummary = typeof data.summary === 'string' ? data.summary : JSON.stringify(data.summary || '');

          // Ensure results is always an array
          let safeResults = data.results;
          if (!Array.isArray(safeResults)) {
            // If results is a string or object, wrap it in an array
            safeResults = safeResults ? [safeResults] : [];
          }

          setSearchResults({
            summary: safeSummary,
            results: safeResults,
            spl: data.spl,
            vql: data.vql,
            count: data.count,
            source: data.source || 'splunk', // default to splunk for backward compatibility
            multi_hunt: data.multi_hunt || false,
            result_sections: data.result_sections || null,
            ioc: data.ioc,
            ioc_type: data.ioc_type,
          })
          // Add assistant message with summary
          setMessages(prev => [...prev, { role: 'assistant', content: safeSummary }])
        } else if (data.type === 'approval_required') {
          // HITL Approval Request
          setActivities(prev => [...prev, {
            type: 'approval_required',
            message: data.title,
            details: data.detail,
            thread_id: data.thread_id,
            next_node: data.next_node,
            timestamp: new Date().toISOString()
          }])
          // Also add a system message
          setMessages(prev => [...prev, { role: 'assistant', content: `⚠️ **Approval Required**: ${data.detail}` }])
        } else if (data.type === 'error') {
          setIsHunting(false)
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
      } catch (err) {
        console.error('Error processing WebSocket message:', err)
        setActivities(prev => [...prev, {
          type: 'error',
          message: 'Client Error',
          details: 'Failed to process server response',
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
  }, [connectionId])

  const sendMessage = (message) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      // Clear previous run's activity and summary before sending a new question
      setActivities([])
      setSearchResults(null)
      setIsHunting(true)
      const payload = {
        type: 'ask',
        question: message,
        settings: {
          defaultIndex: settings.defaultIndex,
          timePolicyMode: settings.timePolicyMode,
          splModel: settings.splModel,
          vqlModel: settings.vqlModel,
          summaryModel: settings.summaryModel,
          rawResultLimit: settings.rawResultLimit,
        },
      }
      wsRef.current.send(JSON.stringify(payload))
      setMessages(prev => [...prev, { role: 'user', content: message }])
    }
  }

  const stopHunt = () => {
    if (isHunting) {
      setIsHunting(false)
      setActivities(prev => [...prev, {
        type: 'error',
        message: 'Stopped',
        details: 'Hunt terminated by user',
        status: 'error',
        timestamp: new Date().toISOString()
      }])
      setMessages(prev => [...prev, { role: 'error', content: 'Hunt terminated by user.' }])

      // Force reconnection to kill the server process
      setConnectionId(prev => prev + 1)
    }
  }

  const handleApproval = (approved, thread_id) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      const payload = {
        type: approved ? 'approve' : 'deny',
        thread_id: thread_id
      }
      wsRef.current.send(JSON.stringify(payload))

      // Update the activity to show decision
      setActivities(prev => prev.map(a => {
        if (a.type === 'approval_required') {
          return {
            ...a,
            type: approved ? 'success' : 'error',
            message: approved ? 'Approved' : 'Denied',
            details: approved ? 'Action approved by user' : 'Action denied by user',
            status: 'done'
          }
        }
        return a
      }))
    }
  }

  const handleNewHunt = () => {
    // Clear all UI state for a fresh hunt
    setMessages([])
    setActivities([])
    setSearchResults(null)
    setIsHunting(false)
  }

  const updateSettings = (next) => {
    setSettings(prev => {
      const merged = { ...prev, ...next }
      localStorage.setItem('ath_settings', JSON.stringify(merged))
      return merged
    })
  }

  return (
    <ThreatHuntingPlatform
      messages={messages}
      activities={activities}
      searchResults={searchResults}
      isConnected={isConnected}
      isHunting={isHunting}
      settings={settings}
      onUpdateSettings={updateSettings}
      onSendMessage={sendMessage}
      onStopHunt={stopHunt}
      onApprove={handleApproval}
      onNewHunt={handleNewHunt}
    />
  )
}

export default App
