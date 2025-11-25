import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Activity, Plug, Settings, Menu, Shield, Search, AlertCircle, CheckCircle2, Clock, Copy, Plus, TrendingUp, ArrowUpRight, ArrowDownRight, Send, Square, Check, X } from 'lucide-react';

export default function ThreatHuntingPlatform({ messages, activities, searchResults, isConnected, isHunting, settings, onUpdateSettings, onSendMessage, onStopHunt, onApprove, onNewHunt }) {
  const [sidebarExpanded, setSidebarExpanded] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState('chat');
  const [dashboardRange, setDashboardRange] = useState('3m'); // 3m | 30d | 7d
  const [inputMessage, setInputMessage] = useState('');
  const [health, setHealth] = useState({
    splunk: { connected: null, message: '' },
    velociraptor: { connected: null, message: '', config: '', config_exists: null },
    virustotal: { connected: null, message: '' },
    atomicredteam: { connected: null, message: '' },
    sigma: { connected: null, message: '', rule_count: 0 },
    checking: false,
  });
  const messagesEndRef = useRef(null);
  const didInitialScrollRef = useRef(false);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    // Avoid scrolling to bottom on initial load; scroll only after first render
    if (!didInitialScrollRef.current) {
      didInitialScrollRef.current = true;
      return;
    }
    scrollToBottom();
  }, [messages, activities, searchResults]);

  const handleSendMessage = (e) => {
    e.preventDefault();
    if (isHunting && onStopHunt) {
      onStopHunt();
      return;
    }
    if (inputMessage.trim() && onSendMessage) {
      onSendMessage(inputMessage);
      setInputMessage('');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const formatRelativeTime = (timestamp) => {
    if (!timestamp) return '';
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffSecs = Math.floor(diffMs / 1000);

    if (diffSecs < 1) return 'just now';
    if (diffSecs < 60) return `${diffSecs}s ago`;
    const diffMins = Math.floor(diffSecs / 60);
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };


  const checkHealth = async (which) => {
    try {
      setHealth((prev) => ({ ...prev, checking: true }));
      const targets = which ? [which] : ['splunk', 'velociraptor', 'virustotal', 'atomicredteam', 'sigma'];
      for (const t of targets) {
        const res = await fetch(`/health/${t}`);
        const json = await res.json();
        setHealth((prev) => ({ ...prev, [t]: json }));
      }
    } catch (e) {
      console.error('Health check failed', e);
    } finally {
      setHealth((prev) => ({ ...prev, checking: false }));
    }
  };

  useEffect(() => {
    // Run initial health checks on mount
    checkHealth();
  }, []);

  const menuItems = [
    { id: 'dashboard', icon: TrendingUp, label: 'Dashboard' },
    { id: 'chat', icon: MessageSquare, label: 'AI Chat' },
    { id: 'activity', icon: Activity, label: 'Activity Feed' },
    { id: 'integrations', icon: Plug, label: 'Integrations' },
    { id: 'settings', icon: Settings, label: 'Settings' },
  ];

  const integrations = [
    {
      name: 'Splunk',
      type: 'SIEM',
      status: health.splunk.connected === null ? 'unknown' : (health.splunk.connected ? 'connected' : 'disconnected'),
      description: health.splunk.message || 'Security Information and Event Management'
    },
    {
      name: 'Velociraptor',
      type: 'EDR/DFIR',
      status: health.velociraptor.connected === null ? 'unknown' : (health.velociraptor.connected ? 'connected' : 'disconnected'),
      description: health.velociraptor.message || 'Endpoint forensics and live response',
      config: health.velociraptor.config,
      configExists: health.velociraptor.config_exists,
    },
    {
      name: 'VirusTotal',
      type: 'Threat Intel',
      status: health.virustotal.connected === null ? 'unknown' : (health.virustotal.connected ? 'connected' : 'disconnected'),
      description: health.virustotal.message || 'IOC reputation and malware analysis',
    },
    {
      name: 'Atomic Red Team',
      type: 'Attack Simulation',
      status: health.atomicredteam.connected === null ? 'unknown' : (health.atomicredteam.connected ? 'connected' : 'disconnected'),
      description: health.atomicredteam.message || 'Adversary emulation and attack simulation',
    },
    {
      name: 'Sigma Rules',
      type: 'Detection Rules',
      status: health.sigma.connected === null ? 'unknown' : (health.sigma.connected ? 'connected' : 'disconnected'),
      description: health.sigma.message || 'Community threat detection rules',
      ruleCount: health.sigma.rule_count,
    }
  ];
  const llmIntegration = { name: 'LLaMA3:8b via Ollama', status: isConnected ? 'connected' : 'disconnected' };

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
          <div className="w-8 h-8 bg-white rounded-lg flex items-center justify-center overflow-hidden flex-shrink-0">
            <img src="/favicons/android-chrome-512x512.png" alt="WhatCyber logo" className="w-8 h-8 object-cover" />
          </div>
          {sidebarExpanded && (
            <div className="flex flex-col leading-tight">
              <span className="font-bold text-sm lg:text-base">WhatCyber</span>
              <span className="text-xs text-neutral-400">Agentic AI</span>
            </div>
          )}
          <button
            className="ml-auto lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          >
            <Menu className="w-5 h-5" />
          </button>
        </div>

        <div className="px-4 pt-6 pb-2">
          {sidebarExpanded && <div className="text-xs text-neutral-500 font-medium mb-3 px-3">Navigation</div>}
        </div>

        <nav className="flex-1 px-4">
          {menuItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveView(item.id);
                  setMobileMenuOpen(false);
                }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg mb-1 transition-all ${activeView === item.id
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
            <div className="px-4 pb-4">
              {integrations.map((int) => (
                <div key={int.name} className="flex items-center justify-between px-3 py-2.5 text-neutral-400 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-5 h-5 flex items-center justify-center">
                      <div className={`w-2 h-2 rounded-full ${int.status === 'connected' ? 'bg-brand' : int.status === 'unknown' ? 'bg-neutral-500' : 'bg-red-500'}`}></div>
                    </div>
                    <span className="text-sm font-medium">{int.name}</span>
                  </div>
                  <button
                    onClick={() => checkHealth(int.name.toLowerCase())}
                    className="text-[10px] px-2 py-1 rounded border border-neutral-800 hover:border-neutral-700 text-neutral-400 hover:text-white"
                  >
                    Check health
                  </button>
                </div>
              ))}
            </div>
            <div className="px-4 pb-2">
              <div className="text-xs text-neutral-500 font-medium mb-3 px-3">Connected LLM</div>
            </div>
            <div className="px-4 pb-6">
              <div className="flex items-center gap-3 px-3 py-2.5 text-neutral-400 transition-colors">
                <div className="w-5 h-5 flex items-center justify-center">
                  <div className={`w-2 h-2 rounded-full ${llmIntegration.status === 'connected' ? 'bg-brand' : 'bg-red-500'}`}></div>
                </div>
                <span className="text-sm font-medium">{llmIntegration.name}</span>
              </div>
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
                {activeView === 'dashboard' && 'Dashboard'}
                {activeView === 'chat' && 'AI Threat Hunting'}
                {activeView === 'activity' && 'Activity Feed'}
                {activeView === 'integrations' && 'Integrations'}
                {activeView === 'settings' && 'Settings'}
              </h1>
              <p className="text-xs lg:text-sm text-neutral-400 hidden sm:block truncate">
                {activeView === 'dashboard' && 'Overview of hunts, alerts, and activity'}
                {activeView === 'chat' && 'Chat with the AI agent to hunt for threats in Splunk'}
                {activeView === 'activity' && 'Real-time agent operations and workflow'}
                {activeView === 'integrations' && 'Connected security platforms and data sources'}
                {activeView === 'settings' && 'Configure threat hunting preferences'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {activeView === 'chat' && (
              <>
                {/* Mobile icon-only */}
                <button
                  onClick={onNewHunt}
                  className="sm:hidden inline-flex items-center justify-center w-9 h-9 rounded-lg bg-brand text-black hover:bg-brand-600 transition-colors"
                  aria-label="Start a new threat hunt"
                  title="Start a new threat hunt"
                >
                  <Plus className="w-5 h-5" />
                </button>
                {/* Desktop labeled */}
                <button
                  onClick={onNewHunt}
                  className="hidden sm:inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-brand text-black font-medium hover:bg-brand-600 transition-colors"
                  title="Start a new threat hunt"
                >
                  <Plus className="w-4 h-4" />
                  <span>New Threat Hunt</span>
                </button>
              </>
            )}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs ${isConnected
              ? 'border-brand/20 bg-brand/10 text-brand'
              : 'border-red-500/20 bg-red-500/10 text-red-500'
              }`}>
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-brand' : 'bg-red-500'}`}></div>
              <span className="hidden sm:inline">{isConnected ? 'Connected' : 'Disconnected'}</span>
            </div>
          </div>
        </div>

        {activeView === 'dashboard' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            {/* Time range + Quick Create */}
            <div className="flex items-center justify-between mb-4 lg:mb-6">
              <div className="flex gap-2 bg-neutral-950 border border-neutral-800 rounded-xl p-1">
                {[
                  { id: '3m', label: 'Last 3 months' },
                  { id: '30d', label: 'Last 30 days' },
                  { id: '7d', label: 'Last 7 days' },
                ].map((r) => (
                  <button
                    key={r.id}
                    onClick={() => setDashboardRange(r.id)}
                    className={`text-xs lg:text-sm px-3 py-1.5 rounded-lg transition-colors ${dashboardRange === r.id ? 'bg-brand text-black' : 'text-neutral-400 hover:text-white'}`}
                  >
                    {r.label}
                  </button>
                ))}
              </div>
              <button className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-brand text-black font-medium hover:bg-brand-600 transition-colors">
                <Plus className="w-4 h-4" />
                <span className="hidden sm:inline">Quick Create</span>
              </button>
            </div>

            {/* Stat cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-5 mb-4 lg:mb-6">
              {[
                { title: 'Detections', value: '1,250', delta: '+12.5%', up: true, sub: 'Trending up this month' },
                { title: 'New Alerts', value: '1,234', delta: '-20%', up: false, sub: 'Down vs previous period' },
                { title: 'Active Incidents', value: '45,678', delta: '+12.5%', up: true, sub: 'Strong user retention' },
                { title: 'MTTR', value: '4.5h', delta: '+4.5%', up: true, sub: 'Steady performance increase' },
              ].map((c, idx) => (
                <div key={idx} className="bg-neutral-950 border border-neutral-800 rounded-2xl p-4 lg:p-5">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="text-xs text-neutral-400 mb-1">{c.title}</p>
                      <div className="flex items-baseline gap-2">
                        <span className="text-xl lg:text-2xl font-semibold text-white">{c.value}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded-full border ${c.up ? 'text-brand border-brand/30 bg-brand/10' : 'text-red-500 border-red-500/30 bg-red-500/10'}`}
                        >
                          <span className="inline-flex items-center gap-1">
                            {c.up ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                            {c.delta}
                          </span>
                        </span>
                      </div>
                    </div>
                  </div>
                  <p className="text-[11px] text-neutral-500">{c.sub}</p>
                </div>
              ))}
            </div>

            {/* Area chart */}
            <div className="bg-neutral-950 border border-neutral-800 rounded-2xl p-4 lg:p-6 mb-6">
              <div className="flex items-center justify-between mb-3 lg:mb-4">
                <div>
                  <h3 className="text-sm lg:text-base font-semibold">Total Alerts</h3>
                  <p className="text-xs text-neutral-500">Total for the selected range</p>
                </div>
              </div>
              <div className="w-full h-72 lg:h-80">
                <svg viewBox="0 0 600 240" className="w-full h-full" style={{ maxWidth: '100%' }}>
                  <defs>
                    <linearGradient id="gradBrand" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="rgba(34,197,94,0.5)" />
                      <stop offset="100%" stopColor="rgba(34,197,94,0.05)" />
                    </linearGradient>
                    <filter id="shadow" x="-10%" y="-10%" width="120%" height="120%">
                      <feDropShadow dx="0" dy="4" stdDeviation="4" floodColor="#22c55e" floodOpacity="0.10" />
                    </filter>
                  </defs>
                  {/* Smooth area under curve */}
                  <path d="M0,200 C60,120 120,80 180,100 C240,140 300,60 360,90 C420,120 480,60 540,110 L600,110 L600,240 L0,240 Z" fill="url(#gradBrand)" filter="url(#shadow)" />
                  {/* Smooth line */}
                  <path d="M0,200 C60,120 120,80 180,100 C240,140 300,60 360,90 C420,120 480,60 540,110 L600,110" stroke="#22c55e" strokeWidth="3" fill="none" filter="url(#shadow)" />
                  {/* Dots on data points */}
                  <circle cx="0" cy="200" r="4" fill="#22c55e" />
                  <circle cx="60" cy="120" r="4" fill="#22c55e" />
                  <circle cx="120" cy="80" r="4" fill="#22c55e" />
                  <circle cx="180" cy="100" r="4" fill="#22c55e" />
                  <circle cx="240" cy="140" r="4" fill="#22c55e" />
                  <circle cx="300" cy="60" r="4" fill="#22c55e" />
                  <circle cx="360" cy="90" r="4" fill="#22c55e" />
                  <circle cx="420" cy="120" r="4" fill="#22c55e" />
                  <circle cx="480" cy="60" r="4" fill="#22c55e" />
                  <circle cx="540" cy="110" r="4" fill="#22c55e" />
                  <circle cx="600" cy="110" r="4" fill="#22c55e" />
                  {/* X axis labels */}
                  <g fill="#555" fontSize="11">
                    <text x="0" y="230">Jun 23</text>
                    <text x="120" y="230">Jun 24</text>
                    <text x="240" y="230">Jun 25</text>
                    <text x="360" y="230">Jun 26</text>
                    <text x="480" y="230">Jun 27</text>
                    <text x="600" y="230">Jun 28</text>
                  </g>
                </svg>
              </div>
            </div>

            {/* Pills row */}
            <div className="flex flex-wrap gap-2 mb-4">
              {['Outline', 'Past Performance', 'Key Personnel', 'Focus Documents'].map((p, i) => (
                <span key={p} className={`text-xs px-2 py-1 rounded-lg border ${i === 0 ? 'bg-neutral-900 text-white' : 'text-neutral-400 hover:text-white'} border-neutral-800`}>{p}</span>
              ))}
            </div>

            {/* Sections */}
            <div className="grid grid-cols-1 gap-3">
              {['Open Incidents', 'Recent Hunts', 'Top Sources'].map((sec) => (
                <div key={sec} className="bg-neutral-950 border border-neutral-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-semibold">{sec}</h4>
                    <button className="text-xs text-neutral-400 hover:text-white">View all</button>
                  </div>
                  <p className="text-xs text-neutral-500 mt-1">Data will appear here as activity occurs.</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Chat View */}
        {activeView === 'chat' && (
          <div className="flex-1 overflow-y-auto">
            {/* Chat Messages Area */}
            <div className="px-4 lg:px-8 py-4 lg:py-6 space-y-4 lg:space-y-6 border-b border-neutral-800 min-h-[35vh] lg:min-h-[40vh]">
              {messages.length === 0 ? (
                <div className="flex gap-4">
                  <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                    <Shield className="w-5 h-5 text-brand" />
                  </div>
                  <div className="flex-1">
                    <div className="bg-neutral-950 rounded-2xl p-5 border border-neutral-800">
                      <p className="text-sm text-neutral-200 leading-relaxed">
                        Hello! I'm your AI threat hunting agent. I can help you search Splunk for security threats.
                        Try asking me something like: <span className="text-brand font-medium">"Find failed authentication attempts in the last 24 hours"</span>
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                messages.map((msg, idx) => (
                  <div key={idx} className={`flex gap-4 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                    {msg.role !== 'user' && (
                      <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                        <Shield className="w-5 h-5 text-brand" />
                      </div>
                    )}
                    <div className={`flex-1 ${msg.role === 'user' ? 'max-w-full lg:max-w-2xl' : ''}`}>
                      <div className={`rounded-2xl p-4 lg:p-5 border ${msg.role === 'user'
                        ? 'bg-neutral-900 border-neutral-800'
                        : msg.role === 'error'
                          ? 'bg-red-500/10 border-red-500/20'
                          : 'bg-neutral-950 border-neutral-800'
                        }`}>
                        <p className={`text-xs lg:text-sm leading-relaxed whitespace-pre-wrap ${msg.role === 'error' ? 'text-red-400' : 'text-neutral-200'
                          }`}>
                          {msg.content}
                        </p>
                      </div>
                    </div>
                  </div>
                ))
              )}

              {/* Live Agent Activity Monitor */}
              {activities.length > 0 && (
                <div className="flex gap-4">
                  <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                    <Shield className="w-5 h-5 text-brand" />
                  </div>
                  <div className="flex-1">
                    <div className="bg-neutral-950 rounded-2xl p-5 border border-neutral-800">
                      <p className="text-sm text-neutral-200 leading-relaxed mb-4">
                        I'm initiating a comprehensive threat hunt across all platforms. Check the agent activity monitor below for real-time progress.
                      </p>
                      <div className="bg-black rounded-xl p-4 border border-neutral-800 space-y-3">
                        {activities.map((activity) => (
                          <div key={activity.id || activity.message} className="space-y-1">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                {activity.type === 'info' ? (
                                  <div className="animate-spin">
                                    <Clock className="w-4 h-4 text-blue-500" />
                                  </div>
                                ) : activity.type === 'success' ? (
                                  <CheckCircle2 className="w-4 h-4 text-brand" />
                                ) : activity.type === 'approval_required' ? (
                                  <AlertCircle className="w-4 h-4 text-yellow-500" />
                                ) : (
                                  <AlertCircle className="w-4 h-4 text-red-500" />
                                )}
                                <span className="text-xs text-neutral-300 font-medium">{activity.message}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                {activity.timestamp && (
                                  <span className="text-[10px] text-neutral-500" title={new Date(activity.timestamp).toLocaleString()}>
                                    {formatRelativeTime(activity.timestamp)}
                                  </span>
                                )}
                                <span className={`text-xs font-medium ${activity.type === 'info' ? 'text-blue-500' :
                                  activity.type === 'success' ? 'text-brand' :
                                    activity.type === 'approval_required' ? 'text-yellow-500' :
                                      'text-red-500'
                                  }`}>
                                  {activity.type === 'info' ? 'In Progress' :
                                    activity.type === 'success' ? 'Complete' :
                                      activity.type === 'approval_required' ? 'Approval Required' :
                                        'Error'}
                                </span>
                              </div>
                            </div>
                            {activity.details && (
                              <div className="ml-7 text-[11px] text-neutral-500 font-mono break-all">
                                {activity.details}
                              </div>
                            )}
                            {activity.type === 'approval_required' && (
                              <div className="ml-7 mt-2 flex gap-2">
                                <button
                                  onClick={() => onApprove(true, activity.thread_id)}
                                  className="flex items-center gap-1.5 px-3 py-1.5 bg-brand text-black text-xs font-semibold rounded-lg hover:bg-brand-600 transition-colors"
                                >
                                  <Check className="w-3 h-3" />
                                  Approve
                                </button>
                                <button
                                  onClick={() => onApprove(false, activity.thread_id)}
                                  className="flex items-center gap-1.5 px-3 py-1.5 bg-neutral-800 text-white text-xs font-semibold rounded-lg hover:bg-neutral-700 transition-colors"
                                >
                                  <X className="w-3 h-3" />
                                  Deny
                                </button>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Agent summary message below activity monitor */}
              {searchResults && searchResults.summary && (
                <div className="flex gap-4 mt-6">
                  <div className="w-10 h-10 rounded-xl bg-neutral-900 flex items-center justify-center flex-shrink-0">
                    <Shield className="w-5 h-5 text-brand" />
                  </div>
                  <div className="flex-1">
                    <div className="bg-neutral-950 rounded-2xl p-5 border border-neutral-800">
                      <p className="text-sm text-neutral-200 leading-relaxed">{searchResults.summary}</p>
                    </div>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Chat Input */}
            <div className="border-b border-neutral-800 px-4 lg:px-8 py-4 lg:py-6 bg-black">
              <form onSubmit={handleSendMessage} className="flex gap-2 lg:gap-3">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  placeholder="Ask the AI agent to investigate threats..."
                  disabled={!isConnected || isHunting}
                  className="flex-1 bg-neutral-950 border border-neutral-800 rounded-xl px-4 lg:px-5 py-2.5 lg:py-3 text-xs lg:text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-brand transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <button
                  type="submit"
                  disabled={!isConnected || (!inputMessage.trim() && !isHunting)}
                  className={`${isHunting ? 'bg-red-500 hover:bg-red-600 shadow-lg shadow-red-500/50' : 'bg-brand hover:bg-brand-600'} text-black px-4 lg:px-6 py-2.5 lg:py-3 rounded-xl flex items-center justify-center gap-2 font-medium transition-all flex-shrink-0 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-brand disabled:shadow-none min-w-[90px] lg:min-w-[110px]`}
                >
                  {isHunting ? (
                    <>
                      <Square className="w-3 h-3 fill-current" />
                      <span className="text-xs lg:text-sm font-semibold">Stop</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-3 h-3" />
                      <span className="text-xs lg:text-sm">Send</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Search Results Summary */}
            <div className="border-b border-neutral-800 bg-neutral-950 px-4 lg:px-8 py-4 lg:py-6">
              <div className="mb-3 lg:mb-4">
                <h3 className="text-sm lg:text-base font-semibold mb-1">Search Result Summary</h3>
                <p className="text-xs text-neutral-500">AI-generated analysis of findings</p>
              </div>

              {searchResults && searchResults.summary ? (
                <div className="bg-black rounded-xl p-4 lg:p-5 border border-neutral-800">
                  <p className="text-xs lg:text-sm text-neutral-300 leading-relaxed whitespace-pre-wrap">
                    {searchResults.summary}
                  </p>
                </div>
              ) : (
                <div className="bg-black rounded-xl p-4 lg:p-5 border border-neutral-800">
                  <p className="text-xs lg:text-sm text-neutral-500 italic">
                    No search results yet. Send a query to see the AI analysis here.
                  </p>
                </div>
              )}
            </div>

            {/* Raw Search Results */}
            <div className="bg-black px-4 lg:px-8 py-4 lg:py-6">
              {searchResults && searchResults.multi_hunt && searchResults.result_sections ? (
                // Multi-hunt: render all three result sections
                <div className="space-y-6">
                  {searchResults.result_sections.map((section, sectionIdx) => (
                    <div key={sectionIdx} className="space-y-4">
                      <div className="mb-4 lg:mb-5">
                        <h3 className="text-sm lg:text-base font-semibold mb-1">{section.title}</h3>
                        <p className="text-xs text-neutral-500">
                          {section.count} {section.source === 'virustotal' ? 'IOC report' :
                            section.source === 'velociraptor' ? 'connection(s)' : 'event(s)'}
                        </p>
                      </div>

                      {section.results && Array.isArray(section.results) && section.results.length > 0 ? (
                        <div className="space-y-3">
                          {section.results.map((result, idx) => (
                            <div key={idx} className="bg-neutral-950 rounded-xl border border-neutral-800 overflow-hidden">
                              <div className="bg-neutral-900 px-4 lg:px-5 py-3 border-b border-neutral-800 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                  <span className="text-xs font-semibold text-brand bg-brand/10 px-2 py-1 rounded">
                                    {section.source === 'velociraptor' ? 'Velociraptor' :
                                      section.source === 'virustotal' ? 'VirusTotal' :
                                        'Splunk'}
                                  </span>
                                  <span className="text-xs text-neutral-500">
                                    {section.source === 'velociraptor' ? `Connection ${idx + 1}` :
                                      section.source === 'virustotal' ? `IOC Report` :
                                        `Event ${idx + 1}`}
                                  </span>
                                </div>
                                <button
                                  onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
                                  className="text-xs text-neutral-400 hover:text-white transition-colors flex items-center gap-1"
                                >
                                  <Copy className="w-3 h-3" />
                                  <span className="hidden sm:inline">Copy JSON</span>
                                </button>
                              </div>
                              <div className="p-4 lg:p-5">
                                <pre className="text-xs text-neutral-300 overflow-x-auto font-mono">
                                  {JSON.stringify(result, null, 2)}
                                </pre>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="bg-neutral-950 rounded-xl border border-neutral-800 p-8 text-center">
                          <Search className="w-12 h-12 text-neutral-600 mx-auto mb-4" />
                          <p className="text-neutral-500 text-sm">No results for {section.title}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                // Single hunt: render single result set
                <>
                  <div className="mb-4 lg:mb-5">
                    <h3 className="text-sm lg:text-base font-semibold mb-1">Raw Search Results</h3>
                    <p className="text-xs text-neutral-500">
                      {searchResults && searchResults.results
                        ? `${searchResults.results.length} ${searchResults.source === 'velociraptor' ? 'rows from Velociraptor' :
                          searchResults.source === 'virustotal' ? 'threat intel results from VirusTotal' :
                            'events from Splunk'
                        }`
                        : 'Waiting for search results'}
                    </p>
                  </div>

                  {searchResults && searchResults.results && Array.isArray(searchResults.results) && searchResults.results.length > 0 ? (
                    <div className="space-y-3 pb-6">
                      {searchResults.results.map((result, idx) => (
                        <div key={idx} className="bg-neutral-950 rounded-xl border border-neutral-800 overflow-hidden">
                          <div className="bg-neutral-900 px-4 lg:px-5 py-3 border-b border-neutral-800 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <span className="text-xs font-semibold text-brand bg-brand/10 px-2 py-1 rounded">
                                {searchResults.source === 'velociraptor' ? 'Velociraptor' :
                                  searchResults.source === 'virustotal' ? 'VirusTotal' :
                                    'Splunk'}
                              </span>
                              <span className="text-xs text-neutral-500">
                                {searchResults.source === 'velociraptor' ? `Row ${idx + 1}` :
                                  searchResults.source === 'virustotal' ? `IOC Report` :
                                    `Event ${idx + 1}`}
                              </span>
                            </div>
                            <button
                              onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
                              className="text-xs text-neutral-400 hover:text-white transition-colors flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" />
                              <span className="hidden sm:inline">Copy JSON</span>
                            </button>
                          </div>
                          <div className="p-4 lg:p-5">
                            <pre className="text-xs text-neutral-300 overflow-x-auto font-mono">
                              {JSON.stringify(result, null, 2)}
                            </pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="bg-neutral-950 rounded-xl border border-neutral-800 p-8 text-center mb-6">
                      <Search className="w-12 h-12 text-neutral-600 mx-auto mb-4" />
                      <p className="text-neutral-500 text-sm">No raw events yet. Results will appear here after a search.</p>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Activity Feed View */}
        {activeView === 'activity' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="max-w-4xl mx-auto space-y-4">
              {activities.length === 0 ? (
                <div className="text-center py-12">
                  <Activity className="w-12 h-12 text-neutral-600 mx-auto mb-4" />
                  <p className="text-neutral-400">No activity yet. Send a message to start hunting!</p>
                </div>
              ) : (
                activities.map((activity, idx) => (
                  <div key={idx} className={`bg-neutral-950 rounded-xl border p-4 lg:p-5 ${activity.type === 'approval_required' ? 'border-yellow-500/50 bg-yellow-500/5' : 'border-neutral-800'
                    }`}>
                    <div className="flex items-start gap-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${activity.type === 'error'
                        ? 'bg-red-500/10 text-red-500'
                        : activity.type === 'success'
                          ? 'bg-brand/10 text-brand'
                          : activity.type === 'approval_required'
                            ? 'bg-yellow-500/10 text-yellow-500'
                            : 'bg-blue-500/10 text-blue-500'
                        }`}>
                        {activity.type === 'error' && <AlertCircle className="w-4 h-4" />}
                        {activity.type === 'success' && <CheckCircle2 className="w-4 h-4" />}
                        {activity.type === 'info' && <Clock className="w-4 h-4" />}
                        {activity.type === 'approval_required' && <AlertCircle className="w-4 h-4" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-neutral-200 mb-1">{activity.message}</p>
                        {activity.details && (
                          <p className="text-xs text-neutral-500">{activity.details}</p>
                        )}

                        {/* Approval Buttons */}
                        {activity.type === 'approval_required' && (
                          <div className="mt-3 flex gap-3">
                            <button
                              onClick={() => onApprove(true, activity.thread_id)}
                              className="flex items-center gap-1.5 px-3 py-1.5 bg-brand text-black text-xs font-semibold rounded-lg hover:bg-brand-600 transition-colors"
                            >
                              <Check className="w-3 h-3" />
                              Approve
                            </button>
                            <button
                              onClick={() => onApprove(false, activity.thread_id)}
                              className="flex items-center gap-1.5 px-3 py-1.5 bg-neutral-800 text-white text-xs font-semibold rounded-lg hover:bg-neutral-700 transition-colors"
                            >
                              <X className="w-3 h-3" />
                              Deny
                            </button>
                          </div>
                        )}

                        {activity.timestamp && (
                          <p className="text-xs text-neutral-600 mt-2">
                            {new Date(activity.timestamp).toLocaleTimeString()}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Integrations View */}
        {activeView === 'integrations' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="max-w-4xl mx-auto flex items-center justify-between mb-4">
              <div className="text-xs text-neutral-500">
                {health.checking ? 'Checking integration health…' : 'View and refresh the status of your integrations.'}
              </div>
              <button
                onClick={() => checkHealth()}
                disabled={health.checking}
                className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${health.checking
                  ? 'border-neutral-800 text-neutral-600 cursor-not-allowed'
                  : 'border-neutral-800 text-neutral-300 hover:text-white hover:border-neutral-700'
                  }`}
              >
                {health.checking ? 'Checking…' : 'Refresh all'}
              </button>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6 max-w-4xl mx-auto">
              {integrations.map((platform) => (
                <div key={platform.name} className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6 hover:border-neutral-700 transition-colors">
                  <div className="flex items-start justify-between mb-3 lg:mb-4 gap-3">
                    <div className="min-w-0 flex-1">
                      <h3 className="font-semibold text-sm lg:text-base mb-1 lg:mb-1.5 truncate">{platform.name}</h3>
                      <p className="text-xs lg:text-sm text-neutral-400 line-clamp-2">{platform.description}</p>
                    </div>
                    <span className={`text-xs px-2 lg:px-3 py-1 lg:py-1.5 rounded-full font-medium whitespace-nowrap flex-shrink-0 ${platform.status === 'connected'
                      ? 'bg-brand/10 text-brand border border-brand/20'
                      : platform.status === 'unknown'
                        ? 'bg-neutral-900 text-neutral-400 border border-neutral-700'
                        : 'bg-red-500/10 text-red-500 border border-red-500/20'
                      }`}>
                      {platform.status}
                    </span>
                  </div>
                  <div className="pt-3 lg:pt-4 border-t border-neutral-800 space-y-3">
                    <div className="flex items-center gap-2 lg:gap-3">
                      <span className="text-xs text-neutral-500 bg-neutral-900 px-2 lg:px-3 py-1 lg:py-1.5 rounded-lg border border-neutral-800">
                        {platform.type}
                      </span>
                      <button
                        onClick={() => checkHealth(platform.name.toLowerCase())}
                        disabled={health.checking}
                        className={`text-xs px-2 lg:px-3 py-1 lg:py-1.5 rounded-lg border transition-colors ${health.checking
                          ? 'border-neutral-800 text-neutral-600 cursor-not-allowed'
                          : 'border-neutral-800 text-neutral-300 hover:text-white hover:border-neutral-700'
                          }`}
                      >
                        {health.checking ? 'Checking…' : 'Check health'}
                      </button>
                    </div>

                    {platform.name === 'Velociraptor' && (
                      <div className="text-xs text-neutral-400 bg-black rounded-xl border border-neutral-800 p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-neutral-500">Config path</span>
                          <span className="text-neutral-300 truncate max-w-[60%]" title={platform.config || 'Not set'}>
                            {platform.config || 'Not set'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between mt-2">
                          <span className="text-neutral-500">Config exists</span>
                          <span className={`${platform.configExists === true
                            ? 'text-brand'
                            : platform.configExists === false
                              ? 'text-red-500'
                              : 'text-neutral-400'
                            }`}>
                            {platform.configExists === true ? 'Yes' : platform.configExists === false ? 'No' : 'Unknown'}
                          </span>
                        </div>
                      </div>
                    )}

                    {platform.name === 'Sigma Rules' && platform.ruleCount > 0 && (
                      <div className="text-xs text-neutral-400 bg-black rounded-xl border border-neutral-800 p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-neutral-500">Available rules</span>
                          <span className="text-brand font-medium">
                            {platform.ruleCount.toLocaleString()}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Settings View */}
        {activeView === 'settings' && (
          <div className="flex-1 overflow-y-auto px-4 lg:px-8 py-4 lg:py-6">
            <div className="max-w-3xl mx-auto space-y-4 lg:space-y-6">
              {/* Connection Status */}
              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">Connection Status</h3>
                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 lg:p-4 bg-black rounded-xl border border-neutral-800">
                    <div>
                      <div className="text-xs lg:text-sm font-medium mb-1">WebSocket</div>
                      <div className="text-xs text-neutral-500">
                        {isConnected ? 'Connected to backend' : 'Disconnected from backend'}
                      </div>
                    </div>
                    <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-brand' : 'bg-red-500'}`}></div>
                  </div>
                </div>
              </div>

              {/* Query Configuration */}
              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">Query Configuration</h3>
                <div className="space-y-4">
                  {/* Default Index */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Default Splunk Index
                    </label>
                    <input
                      type="text"
                      value={settings.defaultIndex}
                      onChange={(e) => onUpdateSettings({ defaultIndex: e.target.value })}
                      placeholder="main"
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-brand transition-colors"
                    />
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Index to use when not explicitly specified in the query
                    </p>
                  </div>

                  {/* Time Policy Mode */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Time Window Policy
                    </label>
                    <select
                      value={settings.timePolicyMode}
                      onChange={(e) => onUpdateSettings({ timePolicyMode: e.target.value })}
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white focus:outline-none focus:border-brand transition-colors"
                    >
                      <option value="off">Off – No automatic time windows</option>
                      <option value="normalize">Normalize – Fix invalid syntax only</option>
                      <option value="infer">Infer – Add time windows from natural language</option>
                    </select>
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Controls how the agent handles time ranges in queries
                    </p>
                  </div>

                  {/* Raw Result Limit */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Raw Result Limit
                    </label>
                    <input
                      type="number"
                      min="10"
                      max="500"
                      value={settings.rawResultLimit}
                      onChange={(e) => onUpdateSettings({ rawResultLimit: parseInt(e.target.value, 10) || 50 })}
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white focus:outline-none focus:border-brand transition-colors"
                    />
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Maximum number of raw events to display (10–500)
                    </p>
                  </div>
                </div>
              </div>

              {/* Model Configuration */}
              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">AI Model Configuration</h3>
                <div className="space-y-4">
                  {/* SPL Model */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Splunk Query Generation Model
                    </label>
                    <select
                      value={settings.splModel}
                      onChange={(e) => onUpdateSettings({ splModel: e.target.value })}
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white focus:outline-none focus:border-brand transition-colors"
                    >
                      <option value="splunk_hunter">splunk_hunter (Default)</option>
                      <option value="velociraptor_hunter">velociraptor_hunter</option>
                      <option value="llama3:8b">llama3:8b</option>
                      <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option>
                    </select>
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Ollama model for generating SPL queries
                    </p>
                  </div>

                  {/* VQL Model */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Velociraptor Query Generation Model
                    </label>
                    <select
                      value={settings.vqlModel}
                      onChange={(e) => onUpdateSettings({ vqlModel: e.target.value })}
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white focus:outline-none focus:border-brand transition-colors"
                    >
                      <option value="velociraptor_hunter">velociraptor_hunter (Default)</option>
                      <option value="splunk_hunter">splunk_hunter</option>
                      <option value="llama3:8b">llama3:8b</option>
                      <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option>
                    </select>
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Ollama model for generating VQL queries
                    </p>
                  </div>

                  {/* Summary Model */}
                  <div>
                    <label className="text-xs lg:text-sm font-medium text-neutral-300 mb-2 block">
                      Summary Generation Model
                    </label>
                    <select
                      value={settings.summaryModel}
                      onChange={(e) => onUpdateSettings({ summaryModel: e.target.value })}
                      className="w-full bg-black border border-neutral-800 rounded-lg px-3 lg:px-4 py-2 lg:py-2.5 text-xs lg:text-sm text-white focus:outline-none focus:border-brand transition-colors"
                    >
                      <option value="llama3:8b">llama3:8b (Default)</option>
                      <option value="splunk_hunter">splunk_hunter</option>
                      <option value="velociraptor_hunter">velociraptor_hunter</option>
                      <option value="qwen2.5-coder:7b">qwen2.5-coder:7b</option>
                    </select>
                    <p className="text-xs text-neutral-500 mt-1.5">
                      Ollama model for summarizing search results
                    </p>
                  </div>
                </div>
              </div>

              {/* About */}
              <div className="bg-neutral-950 rounded-2xl border border-neutral-800 p-4 lg:p-6">
                <h3 className="text-sm lg:text-base font-semibold mb-4 lg:mb-5">About</h3>
                <div className="space-y-2 text-xs lg:text-sm text-neutral-400">
                  <p><span className="text-neutral-300 font-medium">Version:</span> 1.0.0</p>
                  <p><span className="text-neutral-300 font-medium">Backend:</span> FastAPI + WebSocket</p>
                  <p><span className="text-neutral-300 font-medium">LLM:</span> Ollama (Local)</p>
                  <p><span className="text-neutral-300 font-medium">SIEM:</span> Splunk Enterprise</p>
                  <p><span className="text-neutral-300 font-medium">EDR/DFIR:</span> Velociraptor</p>
                  <p><span className="text-neutral-300 font-medium">Threat Intel:</span> VirusTotal</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
