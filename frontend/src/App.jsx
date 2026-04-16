import { useCallback, useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import {
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import './App.css'

const apiRoot = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const api = axios.create({
  baseURL: `${apiRoot}/api`,
})

const ATTACK_TYPES = ['All', 'SQL Injection', 'XSS', 'Command Injection', 'LFI', 'Other']
const ATTACK_COLORS = {
  'SQL Injection': '#f4d34f',
  XSS: '#5ac88d',
  'Command Injection': '#3f8cff',
  LFI: '#6e70e8',
  Other: '#9ca3af',
}

function detectAttackType(reason = '', attackType = '') {
  const source = `${attackType} ${reason}`.toLowerCase()
  if (source.includes('sql')) return 'SQL Injection'
  if (source.includes('xss') || source.includes('script')) return 'XSS'
  if (source.includes('command injection') || source.includes('cmd') || source.includes('shell')) return 'Command Injection'
  if (source.includes('lfi') || source.includes('../') || source.includes('path traversal')) return 'LFI'
  return 'Other'
}

function detectSeverity(type) {
  if (type === 'SQL Injection' || type === 'Command Injection') return 'High'
  if (type === 'LFI' || type === 'XSS') return 'Medium'
  return 'Low'
}

function formatTimestamp(value) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '--'
  return date.toLocaleString()
}

function toPercent(part, total) {
  if (!total) return 0
  return Math.round((part / total) * 100)
}

function getDelta(current, previous) {
  if (previous === 0) {
    if (current === 0) return { text: '0.0%', trend: 'flat' }
    return { text: '+100.0%', trend: 'up' }
  }

  const percent = ((current - previous) / previous) * 100
  const sign = percent > 0 ? '+' : ''
  const trend = percent > 0 ? 'up' : percent < 0 ? 'down' : 'flat'
  return { text: `${sign}${percent.toFixed(1)}%`, trend }
}

function MiniBars({ bars, color }) {
  return (
    <div className="mini-bars" aria-hidden="true">
      {bars.map((bar, idx) => (
        <span key={`${color}-${idx}`} style={{ height: `${bar}%`, background: color }} />
      ))}
    </div>
  )
}

function StatCard({ icon, title, value, subtitle, delta, trend, details, color, active, onClick }) {
  const trendGlyph = trend === 'up' ? '^' : trend === 'down' ? 'v' : '-'

  return (
    <button type="button" className={`panel-card stat-card clickable ${active ? 'active' : ''}`} onClick={onClick}>
      <div className="stat-top">
        <span className="stat-icon" style={{ background: `${color}25`, color }}>{icon}</span>
        <span className={`stat-delta ${trend}`}>{trendGlyph} {delta}</span>
      </div>
      <p className="stat-title">{title}</p>
      <h3>{value}</h3>
      <div className="stat-bottom">
        <span>{subtitle}</span>
        <MiniBars bars={[38, 41, 44, 39, 50, 47]} color={color} />
      </div>
      {details && <p className="stat-extra">{details}</p>}
    </button>
  )
}

function DashboardPage() {
  const [theme, setTheme] = useState(localStorage.getItem('cafw_theme') || 'dark')
  const [logPage, setLogPage] = useState(1)
  const [range, setRange] = useState('7d')
  const [attackFilter, setAttackFilter] = useState('All')
  const [severityFilter, setSeverityFilter] = useState('All')
  const [query, setQuery] = useState('')
  const [sortConfig, setSortConfig] = useState({ key: 'created_at', dir: 'desc' })
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [selectedLog, setSelectedLog] = useState(null)
  const [copiedField, setCopiedField] = useState('')
  const [backendUp, setBackendUp] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState('')
  const [statsData, setStatsData] = useState({
    total_attacks_blocked: 0,
    total_users: 0,
    verified_users: 0,
    latest_attacks: [],
  })
  const [windowAnchor, setWindowAnchor] = useState(Date.now())
  const LOGS_PAGE_SIZE = 10

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('cafw_theme', theme)
  }, [theme])

  const mappedRangeDays = range === '24h' ? 1 : range === '30d' ? 30 : 7

  const fetchDashboard = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const [statsResponse, healthResponse] = await Promise.all([
        api.get('/dashboard/stats', {
          params: {
            range_days: Math.min(mappedRangeDays * 2, 90),
            attack_type: 'all',
            limit: 200,
          },
        }),
        axios.get(`${apiRoot}/health`),
      ])

      setStatsData(statsResponse.data)
      setWindowAnchor(Date.now())
      setBackendUp(healthResponse.data?.status === 'ok')
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load dashboard data')
      setBackendUp(false)
    } finally {
      setLoading(false)
    }
  }, [mappedRangeDays])

  useEffect(() => {
    fetchDashboard()
  }, [fetchDashboard])

  useEffect(() => {
    if (!autoRefresh) return () => {}
    const intervalId = window.setInterval(fetchDashboard, 15000)
    return () => window.clearInterval(intervalId)
  }, [autoRefresh, fetchDashboard])

  const logs = useMemo(
    () => statsData.latest_attacks.map((item) => {
      const attackType = detectAttackType(item.reason, item.attack_type)
      return {
        ...item,
        attackType,
        severity: detectSeverity(attackType),
      }
    }),
    [statsData],
  )

  const { currentWindowLogs, previousWindowLogs } = useMemo(() => {
    const now = new Date(windowAnchor)
    const currentStart = new Date(now)
    currentStart.setDate(now.getDate() - mappedRangeDays)

    const previousStart = new Date(now)
    previousStart.setDate(now.getDate() - (mappedRangeDays * 2))

    const current = []
    const previous = []

    logs.forEach((entry) => {
      const entryTime = new Date(entry.created_at)
      if (entryTime >= currentStart && entryTime <= now) {
        current.push(entry)
      } else if (entryTime >= previousStart && entryTime < currentStart) {
        previous.push(entry)
      }
    })

    return { currentWindowLogs: current, previousWindowLogs: previous }
  }, [logs, mappedRangeDays, windowAnchor])

  const applyAttackAndSearch = useCallback((entries) => {
    const normalizedQuery = query.trim().toLowerCase()

    return entries
      .filter((entry) => (attackFilter === 'All' ? true : entry.attackType === attackFilter))
      .filter((entry) => {
        if (!normalizedQuery) return true
        return [entry.ip_address, entry.method, entry.path, entry.attackType, entry.reason, entry.payload_excerpt]
          .join(' ')
          .toLowerCase()
          .includes(normalizedQuery)
      })
  }, [attackFilter, query])

  const baseCurrentLogs = useMemo(() => applyAttackAndSearch(currentWindowLogs), [applyAttackAndSearch, currentWindowLogs])
  const basePreviousLogs = useMemo(() => applyAttackAndSearch(previousWindowLogs), [applyAttackAndSearch, previousWindowLogs])

  const filteredLogs = useMemo(
    () => baseCurrentLogs.filter((entry) => (severityFilter === 'All' ? true : entry.severity === severityFilter)),
    [baseCurrentLogs, severityFilter],
  )

  const sortedLogs = useMemo(() => {
    const next = [...filteredLogs]
    const { key, dir } = sortConfig

    next.sort((a, b) => {
      let left = a[key]
      let right = b[key]

      if (key === 'created_at') {
        left = new Date(left).getTime()
        right = new Date(right).getTime()
      }

      if (typeof left === 'string') {
        left = left.toLowerCase()
        right = right.toLowerCase()
      }

      if (left < right) return dir === 'asc' ? -1 : 1
      if (left > right) return dir === 'asc' ? 1 : -1
      return 0
    })

    return next
  }, [filteredLogs, sortConfig])

  const totalLogPages = Math.max(1, Math.ceil(sortedLogs.length / LOGS_PAGE_SIZE))
  const visibleLogs = useMemo(() => {
    const start = (logPage - 1) * LOGS_PAGE_SIZE
    return sortedLogs.slice(start, start + LOGS_PAGE_SIZE)
  }, [sortedLogs, logPage])

  useEffect(() => {
    setLogPage((current) => Math.min(Math.max(1, current), totalLogPages))
  }, [totalLogPages])

  const donutData = useMemo(() => {
    const total = filteredLogs.length
    return ATTACK_TYPES.slice(1).map((type) => {
      const count = filteredLogs.filter((item) => item.attackType === type).length
      return { type, value: count, percent: toPercent(count, total) }
    })
  }, [filteredLogs])

  const activityData = useMemo(() => {
    const days = mappedRangeDays
    const now = new Date()
    const slots = []

    for (let i = days - 1; i >= 0; i -= 1) {
      const day = new Date(now)
      day.setDate(now.getDate() - i)
      slots.push({
        key: day.toISOString().slice(0, 10),
        label: day.toLocaleDateString(undefined, { weekday: 'short' }),
        logs: 0,
      })
    }

    const map = new Map(slots.map((slot) => [slot.key, slot]))
    filteredLogs.forEach((entry) => {
      const key = new Date(entry.created_at).toISOString().slice(0, 10)
      const found = map.get(key)
      if (found) found.logs += 1
    })

    return [...map.values()]
  }, [filteredLogs, mappedRangeDays])

  const stats = useMemo(() => {
    const criticalAlerts = baseCurrentLogs.filter((entry) => entry.severity === 'High').length
    const uniqueIps = new Set(baseCurrentLogs.map((entry) => entry.ip_address)).size

    const previousCriticalAlerts = basePreviousLogs.filter((entry) => entry.severity === 'High').length
    const previousUniqueIps = new Set(basePreviousLogs.map((entry) => entry.ip_address)).size

    const typeCounts = ATTACK_TYPES.slice(1).reduce((acc, type) => {
      acc[type] = baseCurrentLogs.filter((entry) => entry.attackType === type).length
      return acc
    }, {})

    return {
      totalLogs: currentWindowLogs.length,
      detectedAttacks: baseCurrentLogs.length,
      criticalAlerts,
      uniqueIps,
      totalUsers: statsData.total_users,
      verifiedUsers: statsData.verified_users,
      previousTotalLogs: previousWindowLogs.length,
      previousDetectedAttacks: basePreviousLogs.length,
      previousCriticalAlerts,
      previousUniqueIps,
      typeCounts,
    }
  }, [baseCurrentLogs, basePreviousLogs, currentWindowLogs.length, previousWindowLogs.length, statsData])

  const detectedDetails = `XSS=${stats.typeCounts.XSS || 0} | SQL=${stats.typeCounts['SQL Injection'] || 0} | Command=${stats.typeCounts['Command Injection'] || 0} | LFI=${stats.typeCounts.LFI || 0} | Other=${stats.typeCounts.Other || 0}`

  const totalDelta = getDelta(stats.totalLogs, stats.previousTotalLogs)
  const detectedDelta = getDelta(stats.detectedAttacks, stats.previousDetectedAttacks)
  const criticalDelta = getDelta(stats.criticalAlerts, stats.previousCriticalAlerts)
  const uniqueIpDelta = getDelta(stats.uniqueIps, stats.previousUniqueIps)

  const cards = [
    {
      icon: 'O',
      title: 'Total Logs',
      value: stats.totalLogs.toLocaleString(),
      subtitle: 'Across selected backend range',
      delta: totalDelta.text,
      trend: totalDelta.trend,
      color: '#4aa8ff',
      onClick: () => {
        setSeverityFilter('All')
        setQuery('')
        setAttackFilter('All')
      },
      active: severityFilter === 'All' && query === '' && attackFilter === 'All',
    },
    {
      icon: 'A',
      title: 'Detected Attacks',
      value: stats.detectedAttacks,
      subtitle: 'After current filters',
      delta: detectedDelta.text,
      trend: detectedDelta.trend,
      details: detectedDetails,
      color: '#e77272',
      onClick: () => setSeverityFilter('Medium'),
      active: severityFilter === 'Medium',
    },
    {
      icon: '!',
      title: 'Critical Alerts',
      value: stats.criticalAlerts,
      subtitle: 'High severity events',
      delta: criticalDelta.text,
      trend: criticalDelta.trend,
      color: '#ff6f6f',
      onClick: () => setSeverityFilter('High'),
      active: severityFilter === 'High',
    },
    {
      icon: 'G',
      title: 'Unique IPs',
      value: stats.uniqueIps,
      subtitle: `${stats.verifiedUsers}/${stats.totalUsers} verified users`,
      delta: uniqueIpDelta.text,
      trend: uniqueIpDelta.trend,
      color: '#62d69e',
      onClick: () => setSeverityFilter('Low'),
      active: severityFilter === 'Low',
    },
  ]

  const criticalLogCount = baseCurrentLogs.filter((entry) => entry.severity === 'High').length

  const toggleSort = (key) => {
    setSortConfig((current) => {
      if (current.key === key) {
        return { key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
      }
      return { key, dir: 'asc' }
    })
  }

  const handleCopy = useCallback((label, value) => {
    if (!value) return
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(String(value)).catch(() => {})
    }
    setCopiedField(label)
    window.setTimeout(() => setCopiedField(''), 1200)
  }, [])

  return (
    <main className="dashboard-shell">
      <div className="glow glow-one" />
      <div className="glow glow-two" />

      <header className="topbar panel-card">
        <div className="brand">
          <span className="avatar">A</span>
          <h1>Admin Dashboard</h1>
          <span className={`status-dot ${backendUp ? 'ok' : 'down'}`}>{backendUp ? 'Backend Online' : 'Backend Offline'}</span>
        </div>

        <div className="topbar-actions">
          <label className="theme-toggle" aria-label="Toggle dark or light theme">
            <input
              type="checkbox"
              checked={theme === 'dark'}
              onChange={() => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))}
            />
            <span className="toggle-track">
              <span className="toggle-thumb" />
            </span>
            <span className="toggle-label">{theme === 'dark' ? 'Dark' : 'Light'}</span>
          </label>

          <button className="admin-chip" type="button" onClick={() => setQuery('admin')}>
            <span className="avatar small">A</span>
            Admin
          </button>
        </div>
      </header>

      <section className="welcome-area">
        <h2>Welcome Admin</h2>
        <p>Fully interactive security dashboard with backend-driven filtering.</p>
      </section>

      {error && <p className="error-banner">{error}</p>}

      <section className="toolbar panel-card">
        <div className="toolbar-left">
          <label>
            Range
            <select value={range} onChange={(e) => setRange(e.target.value)}>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </label>

          <label>
            Attack Type
            <select value={attackFilter} onChange={(e) => setAttackFilter(e.target.value)}>
              {ATTACK_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
          </label>

          <label>
            Severity
            <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="All">All</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </label>
        </div>

        <div className="toolbar-right">
          <input
            className="search-input"
            type="search"
            placeholder="Search logs, IP, payload"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button type="button" className="ghost" onClick={fetchDashboard} disabled={loading}>
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button type="button" className={`ghost ${autoRefresh ? 'active' : ''}`} onClick={() => setAutoRefresh((prev) => !prev)}>
            Auto Refresh {autoRefresh ? 'On' : 'Off'}
          </button>
        </div>
      </section>

      <p className="meta-line">Last updated: {lastUpdated || '--'} | Source: live backend</p>

      <section className="stats-grid">
        {cards.map((card) => (
          <StatCard key={card.title} {...card} />
        ))}
      </section>

      <section className="main-grid">
        <article className="panel-card attack-panel">
          <div className="panel-header">
            <h3>Attack Types</h3>
          </div>

          <div className="attack-content">
            <div className="donut-wrap">
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie
                    data={donutData.filter((entry) => entry.value > 0)}
                    dataKey="value"
                    nameKey="type"
                    innerRadius={58}
                    outerRadius={95}
                    paddingAngle={2}
                  >
                    {donutData.filter((entry) => entry.value > 0).map((entry) => (
                      <Cell key={entry.type} fill={ATTACK_COLORS[entry.type]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <ul className="legend-list">
              {donutData.map((entry) => (
                <li key={entry.type}>
                  <button type="button" className="legend-btn" onClick={() => setAttackFilter(entry.type)}>
                    <span className="dot" style={{ background: ATTACK_COLORS[entry.type] }} />
                    <span>{entry.type}</span>
                    <strong>{entry.percent}%</strong>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </article>

        <article className="panel-card activity-panel">
          <div className="panel-header">
            <h3>Logs Activity</h3>
          </div>

          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={activityData}>
              <XAxis dataKey="label" axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} axisLine={false} tickLine={false} />
              <Tooltip cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Line
                type="natural"
                dataKey="logs"
                stroke="#64d69f"
                strokeWidth={3}
                strokeLinecap="round"
                strokeLinejoin="round"
                dot={{ r: 4, fill: '#64d69f', stroke: '#64d69f' }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </article>
      </section>

      <section className="panel-card logs-panel">
        <div className="panel-header">
          <h3>Recent Logs</h3>
          <span>{sortedLogs.length} entries</span>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th><button type="button" onClick={() => toggleSort('ip_address')}>IP Address</button></th>
                <th><button type="button" onClick={() => toggleSort('method')}>Method</button></th>
                <th><button type="button" onClick={() => toggleSort('path')}>Path</button></th>
                <th><button type="button" onClick={() => toggleSort('attackType')}>Attack Type</button></th>
                <th>Payload</th>
                <th><button type="button" onClick={() => toggleSort('severity')}>Severity</button></th>
                <th><button type="button" onClick={() => toggleSort('created_at')}>Timestamp</button></th>
              </tr>
            </thead>
            <tbody>
              {visibleLogs.map((row) => (
                <tr key={row.id} className="clickable-row" onClick={() => setSelectedLog(row)}>
                  <td>{row.ip_address}</td>
                  <td>{row.method}</td>
                  <td>{row.path}</td>
                  <td>{row.attackType}</td>
                  <td>{row.payload_excerpt || '-'}</td>
                  <td>
                    <span className={`sev-tag ${row.severity.toLowerCase()}`}>{row.severity}</span>
                  </td>
                  <td>{formatTimestamp(row.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="logs-actions">
          <span className="page-meta">Page {logPage} of {totalLogPages}</span>
          <button
            type="button"
            className="ghost"
            onClick={() => setLogPage((current) => Math.max(1, current - 1))}
            disabled={logPage <= 1}
          >
            Prev
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => setLogPage((current) => Math.min(totalLogPages, current + 1))}
            disabled={logPage >= totalLogPages}
          >
            Next
          </button>
        </div>
      </section>

      {selectedLog && (
        <section className="log-modal-backdrop" onClick={() => setSelectedLog(null)}>
          <article className="panel-card log-modal" onClick={(event) => event.stopPropagation()}>
            <header className="log-modal-head">
              <div>
                <p className="log-kicker">Log Details</p>
                <h4>{selectedLog.path}</h4>
                <p className="log-sub">{selectedLog.ip_address} • {formatTimestamp(selectedLog.created_at)}</p>
              </div>
              <button type="button" className="ghost log-close" onClick={() => setSelectedLog(null)} aria-label="Close log details">Close</button>
            </header>

            <div className="log-pills">
              <span className={`pill ${selectedLog.severity.toLowerCase()}`}>{selectedLog.severity}</span>
              <span className="pill">{selectedLog.method}</span>
              <span className="pill">{selectedLog.attackType}</span>
            </div>

            <div className="log-grid">
              <div className="log-card">
                <h5>Origin</h5>
                <div className="kv-row">
                  <span>IP</span>
                  <strong>{selectedLog.ip_address}</strong>
                  <button type="button" className="copy-btn" onClick={() => handleCopy('ip', selectedLog.ip_address)}>
                    {copiedField === 'ip' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="kv-row">
                  <span>Path</span>
                  <strong>{selectedLog.path}</strong>
                  <button type="button" className="copy-btn" onClick={() => handleCopy('path', selectedLog.path)}>
                    {copiedField === 'path' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>

              <div className="log-card">
                <h5>Reason</h5>
                <p className="log-reason">{selectedLog.reason || '-'}</p>
              </div>

              <div className="log-card log-span">
                <h5>Payload</h5>
                <div className="payload-row">
                  <code>{selectedLog.payload_excerpt || '-'}</code>
                  <button
                    type="button"
                    className="copy-btn"
                    onClick={() => handleCopy('payload', selectedLog.payload_excerpt)}
                    disabled={!selectedLog.payload_excerpt}
                  >
                    {copiedField === 'payload' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          </article>
        </section>
      )}
    </main>
  )
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  )
}
