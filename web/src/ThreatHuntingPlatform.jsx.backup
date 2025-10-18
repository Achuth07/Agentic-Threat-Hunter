import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, LayoutDashboard, Plug, Settings, Menu, Shield, Activity, Search, AlertCircle, CheckCircle2, Clock, X } from 'lucide-react';

export default function ThreatHuntingPlatform({ messages, activities, searchResults, isConnected, onSendMessage }) {
  const [sidebarExpanded, setSidebarExpanded] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState('chat');
  const [inputMessage, setInputMessage] = useState('');
  const messagesEndRef = useRef(null);
  const activitiesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (inputMessage.trim() && onSendMessage) {
      onSendMessage(inputMessage);
      setInputMessage('');
    }
  };

  const menuItems = [
    { id: 'chat', icon: MessageSquare, label: 'AI Chat' },
    { id: 'activity', icon: Activity, label: 'Activity Feed' },
    { id: 'integrations', icon: Plug, label: 'Integrations' },
    { id: 'settings', icon: Settings, label: 'Settings' },
  ];

  // Splunk is the only real integration for now
  const integrations = [
    { name: 'Splunk', type: 'SIEM', status: isConnected ? 'connected' : 'disconnected', description: 'Security Information and Event Management' },
    { name: 'Ollama', type: 'LLM', status: isConnected ? 'connected' : 'disconnected', description: 'Local Language Model for AI Analysis' },
  ];

  return (
    <div className="flex h-screen bg-black text-white overflow-hidden">
      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        ${sidebarExpanded ? 'w-64' : 'w-20'} 
        ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        fixed lg:relative z-50 h-screen
        bg-neutral-950 border-r border-neutral-800 
        transition-all duration-300 flex flex-col
      `}>
        <div className="p-4 lg:p-6 border-b border-neutral-800 flex items-center gap-3">
          <div className="w-8 h-8 bg-white rounded-lg flex items-center justify-center flex-shrink-0">
            <Shield className="w-5 h-5 text-black" />
          </div>
          {sidebarExpanded && <span className="font-semibold text-sm lg:text-base">ThreatGuard AI</span>}
          <button 
            className="ml-auto lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          >
            <Menu className="w-5 h-5" />
          </button>
        </div>

        <div className="px-4 pt-6 pb-2">
          {sidebarExpanded && <div className="text-xs text-neutral-500 font-medium mb-3 px-3">Home</div>}
        </div>

        <nav className="flex-1 px-4">
          {menuItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg mb-1 transition-all ${
                  activeView === item.id 
                    ? 'bg-neutral-900 text-white' 
                    : 'text-neutral-400 hover:bg-neutral-900 hover:text-white'
                }`}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />
                {sidebarExpanded && <span className="text-sm font-medium">{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {sidebarExpanded && (
          <>
            <div className="px-4 pb-2">
              <div className="text-xs text-neutral-500 font-medium mb-3 px-3">Connected Systems</div>
            </div>
            <div className="px-4 pb-6">
              {integrations.map((int) => (
                <div key={int.name} className="flex items-center gap-3 px-3 py-2.5 text-neutral-400 transition-colors">
                  <div className="w-5 h-5 flex items-center justify-center">
                    <div className={`w-2 h-2 rounded-full ${int.status === 'connected' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                  </div>
                  <span className="text-sm font-medium">{int.name}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden w-full">
        {/* Header */}
        <div className="bg-black border-b border-neutral-800 px-4 lg:px-8 py-4 lg:py-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0 flex-1">
            <button 
              className="lg:hidden flex-shrink-0"
              onClick={() => setMobileMenuOpen(true)}
            >
              <Menu className="w-6 h-6" />
            </button>
            <div className="min-w-0">
              <h1 className="text-lg lg:text-2xl font-semibold mb-0.5 lg:mb-1 truncate">
                {activeView === 'chat' && 'AI Threat Hunting'}
                {activeView === 'activity' && 'Activity Feed'}
                {activeView === 'integrations' && 'Integrations'}
                {activeView === 'settings' && 'Settings'}
              </h1>
              <p className="text-xs lg:text-sm text-neutral-400 hidden sm:block truncate">
                {activeView === 'chat' && 'Chat with the AI agent to hunt for threats in Splunk'}
                {activeView === 'activity' && 'Real-time agent operations and workflow'}
                {activeView === 'integrations' && 'Connected security platforms and data sources'}
                {activeView === 'settings' && 'Configure threat hunting preferences'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs ${
              isConnected 
                ? 'border-green-500/20 bg-green-500/10 text-green-500' 
                : 'border-red-500/20 bg-red-500/10 text-red-500'
            }`}>
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></div>
              <span className="hidden sm:inline">{isConnected ? 'Connected' : 'Disconnected'}</span>
            </div>
          </div>
        </div>

        {/* Chat View */}
        {activeView === 'chat' && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Chat Messages Area */}
            <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6 space-y-4 lg:space-y-6">
              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                  <Shield className="w-5 h-5 text-lime-500" />
                </div>
                <div className="flex-1">
                  <div className="bg-neutral-950 rounded-2xl p-5 border border-neutral-800">
                    <p className="text-sm text-neutral-200 leading-relaxed">Hello! I'm your AI threat hunting agent. I'm continuously monitoring your connected platforms: <span className="text-lime-500 font-medium">Splunk, CrowdStrike, Okta, and AWS</span>. Ask me anything about your security posture or let me hunt autonomously.</p>
                  </div>
                </div>
              </div>

              <div className="flex gap-3 lg:gap-4 justify-end">
                <div className="max-w-full lg:max-w-2xl">
                  <div className="bg-neutral-900 rounded-2xl p-4 lg:p-5 border border-neutral-800">
                    <p className="text-xs lg:text-sm text-neutral-200">Investigate any suspicious authentication activities in the last 24 hours</p>
                  </div>
                </div>
              </div>

              <div className="flex gap-4">
                <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                  <Shield className="w-5 h-5 text-lime-500" />
                </div>
                <div className="flex-1">
                  <div className="bg-neutral-950 rounded-2xl p-5 border border-neutral-800">
                    <p className="text-sm text-neutral-200 leading-relaxed mb-4">I've completed a comprehensive threat hunt across all platforms. Here's what I found:</p>
                    <div className="bg-black rounded-xl p-4 border border-neutral-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-green-500" />
                          <span className="text-xs text-neutral-300 font-medium">SIEM Analysis</span>
                        </div>
                        <span className="text-xs text-green-500 font-medium">Complete</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-green-500" />
                          <span className="text-xs text-neutral-300 font-medium">EDR Correlation</span>
                        </div>
                        <span className="text-xs text-green-500 font-medium">Complete</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="w-4 h-4 text-green-500" />
                          <span className="text-xs text-neutral-300 font-medium">IAM Investigation</span>
                        </div>
                        <span className="text-xs text-green-500 font-medium">Complete</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Chat Input */}
            <div className="border-t border-neutral-800 px-4 lg:px-8 py-4 lg:py-6 bg-black">
              <div className="flex gap-2 lg:gap-3">
                <input
                  type="text"
                  placeholder="Ask the AI agent to investigate threats..."
                  className="flex-1 bg-neutral-950 border border-neutral-800 rounded-xl px-4 lg:px-5 py-2.5 lg:py-3 text-xs lg:text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-lime-500 transition-colors"
                />
                <button className="bg-lime-500 hover:bg-lime-400 text-black px-4 lg:px-6 py-2.5 lg:py-3 rounded-xl flex items-center gap-2 font-medium transition-colors flex-shrink-0">
                  <span className="text-xs lg:text-sm">Send</span>
                </button>
              </div>
            </div>

            {/* Search Result Summary */}
            <div className="border-t border-neutral-800 bg-neutral-950 px-4 lg:px-8 py-4 lg:py-6">
              <div className="mb-3 lg:mb-4">
                <h3 className="text-sm lg:text-base font-semibold mb-1">Search Result Summary</h3>
                <p className="text-xs text-neutral-500">Analysis results from {searchSummary.timeRange.toLowerCase()}</p>
              </div>
              
              <div className="bg-black rounded-xl p-5 border border-neutral-800">
                <p className="text-sm text-neutral-300 leading-relaxed mb-4">
                  The AI agent completed a comprehensive threat hunt across <span className="text-lime-500 font-medium">4 integrated platforms</span> (Splunk, CrowdStrike, Okta, and AWS). 
                  The analysis identified <span className="text-red-400 font-medium">3 true positive threats</span> requiring immediate attention, including privilege escalation attempts and suspicious process execution. 
                  Additionally, <span className="text-green-400 font-medium">12 false positives</span> were automatically filtered out, and <span className="text-blue-400 font-medium">5 events remain under investigation</span> pending additional context.
                </p>
                <p className="text-sm text-neutral-300 leading-relaxed">
                  Total of <span className="font-medium text-white">847 security events</span> were analyzed in the last 24 hours. The correlation engine cross-referenced authentication logs, endpoint telemetry, IAM policy changes, and cloud API activity to provide high-fidelity threat detection with minimal analyst intervention.
                </p>
              </div>
            </div>

            {/* Raw Search Results */}
            <div className="border-t border-neutral-800 bg-black px-4 lg:px-8 py-4 lg:py-6 flex-1 overflow-y-auto">
              <div className="mb-4 lg:mb-5">
                <h3 className="text-sm lg:text-base font-semibold mb-1">Raw Search Results</h3>
                <p className="text-xs text-neutral-500">Raw JSON responses from security platforms</p>
              </div>
              
              <div className="space-y-3">
                {rawResults.map((result) => (
                  <div key={result.id} className="bg-neutral-950 rounded-xl border border-neutral-800 overflow-hidden">
                    <div className="bg-neutral-900 px-5 py-3 border-b border-neutral-800 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-semibold text-lime-500 bg-lime-500/10 px-2 py-1 rounded">
                          {result.platform}
                        </span>
                        <span className="text-xs text-neutral-500">Event ID: {result.id}</span>
                      </div>
                      <button className="text-xs text-neutral-400 hover:text-white transition-colors">
                        Copy JSON
                      </button>
                    </div>
                    <div className="p-5">
                      <pre className="text-xs text-neutral-300 overflow-x-auto font-mono">
                        {JSON.stringify(result.raw_json, null, 2)}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Dashboard View */}
        {activeView === 'dashboard' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6 mb-6 lg:mb-8">
              {[
                { label: 'Active Threats', value: '3', trend: '+2', trendUp: false, color: 'text-orange-500', bg: 'bg-orange-500/10' },
                { label: 'Investigated', value: '127', trend: '+12.5%', trendUp: true, color: 'text-blue-500', bg: 'bg-blue-500/10' },
                { label: 'False Positives', value: '94', trend: '+12.5%', trendUp: true, color: 'text-green-500', bg: 'bg-green-500/10' },
                { label: 'Remediated', value: '33', trend: '+4.5%', trendUp: true, color: 'text-lime-500', bg: 'bg-lime-500/10' },
              ].map((stat) => (
                <div key={stat.label} className="bg-neutral-950 rounded-2xl p-4 lg:p-6 border border-neutral-800">
                  <div className="flex items-start justify-between mb-3 lg:mb-4">
                    <div className="text-xs lg:text-sm text-neutral-400 font-medium">{stat.label}</div>
                    <div className={`flex items-center gap-1 text-xs font-semibold ${stat.color} ${stat.bg} px-2 py-1 rounded flex-shrink-0`}>
                      {stat.trendUp ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                      <span className="hidden sm:inline">{stat.trend}</span>
                    </div>
                  </div>
                  <div className="text-2xl lg:text-3xl font-bold">{stat.value}</div>
                  <div className="text-xs text-neutral-500 mt-2 hidden sm:block">
                    {stat.trendUp ? 'Strong performance' : 'Needs attention'}
                  </div>
                  <div className="text-xs text-neutral-600 mt-1 hidden sm:block">
                    {stat.trendUp ? 'Exceeds expectations' : 'Monitor closely'}
                  </div>
                </div>
              ))}
            </div>

            <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6 mb-6 lg:mb-8">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4 lg:mb-6">
                <div>
                  <h3 className="text-sm lg:text-base font-semibold mb-1">Threat Detection Timeline</h3>
                  <p className="text-xs text-neutral-500">Total detections over time</p>
                </div>
                <div className="flex gap-2 overflow-x-auto pb-2 lg:pb-0">
                  {['Last 3 months', 'Last 30 days', 'Last 7 days'].map((range) => (
                    <button
                      key={range}
                      onClick={() => setTimeRange(range)}
                      className={`text-xs px-3 lg:px-4 py-2 rounded-lg font-medium transition-colors whitespace-nowrap ${
                        range === 'Last 7 days'
                          ? 'bg-neutral-900 text-white border border-neutral-700'
                          : 'text-neutral-400 hover:text-white'
                      }`}
                    >
                      {range}
                    </button>
                  ))}
                </div>
              </div>
              
              <div className="h-48 relative">
                <svg className="w-full h-full" viewBox="0 0 800 200" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="threatGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="0%" stopColor="#84cc16" stopOpacity="0.5"/>
                      <stop offset="100%" stopColor="#84cc16" stopOpacity="0.05"/>
                    </linearGradient>
                  </defs>
                  <path
                    d="M 0 120 Q 100 80, 200 100 T 400 90 T 600 110 T 800 70 L 800 200 L 0 200 Z"
                    fill="url(#threatGradient)"
                  />
                  <path
                    d="M 0 120 Q 100 80, 200 100 T 400 90 T 600 110 T 800 70"
                    fill="none"
                    stroke="#84cc16"
                    strokeWidth="2"
                  />
                </svg>
                <div className="absolute bottom-0 left-0 right-0 flex justify-between text-xs text-neutral-600 px-4">
                  {['Jun 23', 'Jun 24', 'Jun 25', 'Jun 26', 'Jun 27', 'Jun 28', 'Jun 29'].map((date) => (
                    <span key={date}>{date}</span>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-neutral-950 rounded-2xl border border-neutral-800 overflow-hidden">
              <div className="p-4 lg:p-6 border-b border-neutral-800">
                <div className="flex items-center gap-2 lg:gap-4 overflow-x-auto pb-2 lg:pb-0">
                  <button className="text-xs lg:text-sm font-medium px-3 lg:px-4 py-2 bg-neutral-900 rounded-lg border-b-2 border-white whitespace-nowrap">
                    Outline
                  </button>
                  <button className="text-xs lg:text-sm font-medium text-neutral-400 hover:text-white px-3 lg:px-4 py-2 flex items-center gap-2 whitespace-nowrap">
                    <span className="hidden sm:inline">Past Performance</span>
                    <span className="sm:hidden">Past</span>
                    <span className="bg-neutral-800 text-neutral-400 text-xs px-2 py-0.5 rounded">3</span>
                  </button>
                  <button className="text-xs lg:text-sm font-medium text-neutral-400 hover:text-white px-3 lg:px-4 py-2 flex items-center gap-2 whitespace-nowrap">
                    <span className="hidden sm:inline">Key Personnel</span>
                    <span className="sm:hidden">Personnel</span>
                    <span className="bg-neutral-800 text-neutral-400 text-xs px-2 py-0.5 rounded">2</span>
                  </button>
                  <button className="text-xs lg:text-sm font-medium text-neutral-400 hover:text-white px-3 lg:px-4 py-2 whitespace-nowrap hidden md:block">
                    Focus Documents
                  </button>
                  <div className="ml-auto flex gap-2">
                    <button className="text-xs lg:text-sm px-3 lg:px-4 py-2 bg-neutral-900 hover:bg-neutral-800 rounded-lg border border-neutral-800 transition-colors items-center gap-2 hidden md:flex">
                      <span>⚙</span>
                      <span className="hidden lg:inline">Customize Columns</span>
                    </button>
                    <button className="text-xs lg:text-sm px-3 lg:px-4 py-2 bg-white hover:bg-neutral-200 text-black rounded-lg font-medium transition-colors flex items-center gap-2 whitespace-nowrap">
                      <Plus className="w-4 h-4" />
                      <span className="hidden sm:inline">Add Section</span>
                      <span className="sm:hidden">Add</span>
                    </button>
                  </div>
                </div>
              </div>
              
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-black border-b border-neutral-800">
                    <tr>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">
                        <input type="checkbox" className="w-4 h-4" />
                      </th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Header</th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Section Type</th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Status</th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Target</th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Limit</th>
                      <th className="text-left text-xs font-medium text-neutral-400 px-6 py-4">Reviewer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { header: 'Privilege Escalation', type: 'True Positive', status: 'Critical', target: 'Okta', limit: 'High' },
                      { header: 'Unusual API Activity', type: 'Under Investigation', status: 'Warning', target: 'AWS', limit: 'Medium' },
                      { header: 'Brute Force Attempt', type: 'False Positive', status: 'Resolved', target: 'SIEM', limit: 'Low' },
                    ].map((row, i) => (
                      <tr key={i} className="border-b border-neutral-800 hover:bg-neutral-900/50 transition-colors">
                        <td className="px-6 py-4">
                          <input type="checkbox" className="w-4 h-4" />
                        </td>
                        <td className="px-6 py-4 text-sm">{row.header}</td>
                        <td className="px-6 py-4 text-sm text-neutral-400">{row.type}</td>
                        <td className="px-6 py-4">
                          <span className={`text-xs px-3 py-1 rounded-full ${
                            row.status === 'Critical' ? 'bg-red-500/10 text-red-500' :
                            row.status === 'Warning' ? 'bg-orange-500/10 text-orange-500' :
                            'bg-green-500/10 text-green-500'
                          }`}>
                            {row.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-neutral-400">{row.target}</td>
                        <td className="px-6 py-4 text-sm text-neutral-400">{row.limit}</td>
                        <td className="px-6 py-4 text-sm text-neutral-400">AI Agent</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Integrations View */}
        {activeView === 'integrations' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6">
              {[
                { name: 'Splunk', type: 'SIEM', status: 'connected', desc: 'Security Information and Event Management' },
                { name: 'CrowdStrike', type: 'EDR', status: 'connected', desc: 'Endpoint Detection and Response' },
                { name: 'Okta', type: 'IAM', status: 'connected', desc: 'Identity and Access Management' },
                { name: 'AWS', type: 'Cloud', status: 'connected', desc: 'Cloud Security Monitoring' },
                { name: 'Microsoft Sentinel', type: 'SIEM', status: 'disconnected', desc: 'Cloud-native SIEM' },
                { name: 'Azure AD', type: 'IAM', status: 'disconnected', desc: 'Cloud Identity Management' },
              ].map((platform) => (
                <div key={platform.name} className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6 hover:border-neutral-700 transition-colors">
                  <div className="flex items-start justify-between mb-3 lg:mb-4 gap-3">
                    <div className="min-w-0 flex-1">
                      <h3 className="font-semibold text-sm lg:text-base mb-1 lg:mb-1.5 truncate">{platform.name}</h3>
                      <p className="text-xs lg:text-sm text-neutral-400 line-clamp-2">{platform.desc}</p>
                    </div>
                    <span className={`text-xs px-2 lg:px-3 py-1 lg:py-1.5 rounded-full font-medium whitespace-nowrap flex-shrink-0 ${
                      platform.status === 'connected' 
                        ? 'bg-green-500/10 text-green-500 border border-green-500/20' 
                        : 'bg-neutral-800 text-neutral-400 border border-neutral-700'
                    }`}>
                      {platform.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 lg:gap-3 pt-3 lg:pt-4 border-t border-neutral-800">
                    <span className="text-xs text-neutral-500 bg-neutral-900 px-2 lg:px-3 py-1 lg:py-1.5 rounded-lg border border-neutral-800">
                      {platform.type}
                    </span>
                    <button className={`ml-auto text-xs lg:text-sm px-3 lg:px-4 py-1.5 lg:py-2 rounded-lg font-medium transition-colors ${
                      platform.status === 'connected' 
                        ? 'bg-neutral-900 hover:bg-neutral-800 text-white border border-neutral-800' 
                        : 'bg-lime-500 hover:bg-lime-400 text-black'
                    }`}>
                      {platform.status === 'connected' ? 'Configure' : 'Connect'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Settings View */}
        {activeView === 'settings' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="max-w-3xl mx-auto">
              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6 mb-4 lg:mb-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">Autonomous Hunting</h3>
                <div className="space-y-3 lg:space-y-4">
                  <label className="flex items-start sm:items-center justify-between p-3 lg:p-4 bg-black rounded-xl border border-neutral-800 hover:border-neutral-700 transition-colors cursor-pointer gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs lg:text-sm font-medium mb-1">Enable continuous threat hunting</div>
                      <div className="text-xs text-neutral-500">AI agent will actively hunt for threats 24/7</div>
                    </div>
                    <input type="checkbox" defaultChecked className="w-5 h-5 flex-shrink-0" />
                  </label>
                  <label className="flex items-start sm:items-center justify-between p-3 lg:p-4 bg-black rounded-xl border border-neutral-800 hover:border-neutral-700 transition-colors cursor-pointer gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs lg:text-sm font-medium mb-1">Auto-remediate false positives</div>
                      <div className="text-xs text-neutral-500">Automatically dismiss confirmed false positives</div>
                    </div>
                    <input type="checkbox" className="w-5 h-5 flex-shrink-0" />
                  </label>
                </div>
              </div>

              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">Alert Preferences</h3>
                <div className="space-y-3 lg:space-y-4">
                  <label className="flex items-start sm:items-center justify-between p-3 lg:p-4 bg-black rounded-xl border border-neutral-800 hover:border-neutral-700 transition-colors cursor-pointer gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs lg:text-sm font-medium mb-1">Email notifications</div>
                      <div className="text-xs text-neutral-500">Receive email alerts for critical threats</div>
                    </div>
                    <input type="checkbox" defaultChecked className="w-5 h-5 flex-shrink-0" />
                  </label>
                  <label className="flex items-start sm:items-center justify-between p-3 lg:p-4 bg-black rounded-xl border border-neutral-800 hover:border-neutral-700 transition-colors cursor-pointer gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs lg:text-sm font-medium mb-1">Slack integration</div>
                      <div className="text-xs text-neutral-500">Send notifications to Slack channels</div>
                    </div>
                    <input type="checkbox" className="w-5 h-5 flex-shrink-0" />
                  </label>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}