import { useEffect, useMemo, useState } from 'react'

const apiBase = ''

function getToken() {
  return localStorage.getItem('token')
}

async function api(path, { method = 'GET', body } = {}) {
  const token = getToken()
  const res = await fetch(apiBase + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  })

  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(data?.error || 'Request failed')
  }
  return data
}

export default function App() {
  const [mode, setMode] = useState('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const [handle, setHandle] = useState('')
  const [appPassword, setAppPassword] = useState('')

  const [text, setText] = useState('')
  const [scheduledAt, setScheduledAt] = useState('')

  const [posts, setPosts] = useState([])
  const [feed, setFeed] = useState([])
  const [isConnecting, setIsConnecting] = useState(false)

  const [status, setStatus] = useState('')
  const authed = useMemo(() => Boolean(getToken()), [])

  async function onRegister(e) {
    e.preventDefault()
    setStatus('')
    try {
      await api('/api/auth/register', { method: 'POST', body: { email, password } })
      setStatus('Registered. Now login.')
      setMode('login')
    } catch (err) {
      setStatus(err.message)
    }
  }

  async function onLogin(e) {
    e.preventDefault()
    setStatus('')
    try {
      const data = await api('/api/auth/login', { method: 'POST', body: { email, password } })
      localStorage.setItem('token', data.token)
      window.location.reload()
    } catch (err) {
      setStatus(err.message)
    }
  }

  async function onConnect(e) {
    e.preventDefault()
    setStatus('')
    try {
      await api('/api/bluesky/connect', { method: 'POST', body: { handle, appPassword } })
      setStatus('Bluesky connected')
    } catch (err) {
      setStatus(err.message)
    }
  }

  async function onOAuthConnect() {
    setStatus('')
    setIsConnecting(true)
    try {
      const { sessionId, authUrl } = await api('/api/bluesky/auth/start', {
        method: 'POST',
        body: { serverUrl: 'https://bsky.social' } // Provide server URL for demo
      })
      // Store sessionId in sessionStorage for callback handling
      sessionStorage.setItem('oauthSessionId', sessionId)
      window.location.href = authUrl
    } catch (err) {
      setStatus(err.message)
      setIsConnecting(false)
    }
  }

  // Handle OAuth callback
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const code = urlParams.get('code')
    const state = urlParams.get('state')
    const error = urlParams.get('error')
    
    if (error) {
      setStatus(`OAuth error: ${error}`)
      window.history.replaceState({}, document.title, window.location.pathname)
      return
    }
    
    if (code && state) {
      handleOAuthCallback(code, state)
    }
  }, [])

  async function handleOAuthCallback(code, state) {
    try {
      const result = await api(`/api/bluesky/callback?code=${code}&state=${state}`)
      setStatus(`Connected as ${result.handle} (${result.did})`)
      window.history.replaceState({}, document.title, window.location.pathname)
      sessionStorage.removeItem('oauthSessionId')
      await refresh()
    } catch (err) {
      setStatus(err.message)
    } finally {
      setIsConnecting(false)
    }
  }

  async function onInstantPost(e) {
    e.preventDefault()
    setStatus('')
    try {
      await api('/api/posts/instant', { method: 'POST', body: { text } })
      setText('')
      setStatus('Posted')
      await refresh()
    } catch (err) {
      setStatus(err.message)
    }
  }

  async function onSchedulePost(e) {
    e.preventDefault()
    setStatus('')
    try {
      await api('/api/posts/schedule', { method: 'POST', body: { text, scheduledAt } })
      setText('')
      setScheduledAt('')
      setStatus('Scheduled')
      await refresh()
    } catch (err) {
      setStatus(err.message)
    }
  }

  async function refresh() {
    const [p, f] = await Promise.all([
      api('/api/posts'),
      api('/api/bluesky/feed').catch(() => ({ feed: [] }))
    ])
    setPosts(p.posts || [])
    setFeed(f.feed || [])
  }

  async function logout() {
    localStorage.removeItem('token')
    window.location.reload()
  }

  useEffect(() => {
    if (getToken()) {
      refresh().catch(() => {})
    }
  }, [])

  if (!getToken()) {
    return (
      <div style={{ maxWidth: 520, margin: '40px auto', fontFamily: 'system-ui' }}>
        <h2>Bluesky Demo</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button onClick={() => setMode('login')} disabled={mode === 'login'}>
            Login
          </button>
          <button onClick={() => setMode('register')} disabled={mode === 'register'}>
            Register
          </button>
        </div>

        {mode === 'register' ? (
          <form onSubmit={onRegister}>
            <input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
            <button type="submit">Create account</button>
          </form>
        ) : (
          <form onSubmit={onLogin}>
            <input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
            <button type="submit">Login</button>
          </form>
        )}

        {status ? <p style={{ marginTop: 12 }}>{status}</p> : null}
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 900, margin: '30px auto', fontFamily: 'system-ui' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2>Bluesky Demo</h2>
        <button onClick={logout}>Logout</button>
      </div>

      <section style={{ border: '1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h3>1) Connect Bluesky</h3>
        <div style={{ marginBottom: 16 }}>
          <button 
            onClick={onOAuthConnect} 
            disabled={isConnecting}
            style={{ 
              backgroundColor: '#0085ff', 
              color: 'white', 
              border: 'none', 
              padding: '12px 24px', 
              borderRadius: 8, 
              cursor: isConnecting ? 'not-allowed' : 'pointer',
              fontSize: 16,
              fontWeight: 'bold'
            }}
          >
            {isConnecting ? 'Connecting...' : 'Connect with Bluesky'}
          </button>
        </div>
        
        <div style={{ margin: '16px 0', textAlign: 'center', color: '#666' }}>
          — or —
        </div>
        
        <form onSubmit={onConnect}>
          <input 
            placeholder="handle (e.g. you.bsky.social)" 
            value={handle} 
            onChange={(e) => setHandle(e.target.value)} 
            style={{ width: '100%', padding: 8, marginBottom: 8 }} 
          />
          <input 
            type="password" 
            placeholder="App Password" 
            value={appPassword} 
            onChange={(e) => setAppPassword(e.target.value)} 
            style={{ width: '100%', padding: 8, marginBottom: 8 }} 
          />
          <button type="submit">Connect with App Password</button>
        </form>
      </section>

      <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <div style={{ border: '1px solid #ddd', padding: 16, borderRadius: 8 }}>
          <h3>2) Instant Post</h3>
          <form onSubmit={onInstantPost}>
            <textarea placeholder="What's happening?" value={text} onChange={(e) => setText(e.target.value)} style={{ width: '100%', padding: 8, minHeight: 90, marginBottom: 8 }} />
            <button type="submit">Post now</button>
          </form>
        </div>

        <div style={{ border: '1px solid #ddd', padding: 16, borderRadius: 8 }}>
          <h3>3) Schedule Post</h3>
          <form onSubmit={onSchedulePost}>
            <textarea placeholder="Text" value={text} onChange={(e) => setText(e.target.value)} style={{ width: '100%', padding: 8, minHeight: 90, marginBottom: 8 }} />
            <input type="datetime-local" value={scheduledAt} onChange={(e) => setScheduledAt(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
            <button type="submit">Schedule</button>
          </form>
        </div>
      </section>

      {status ? <p>{status}</p> : null}

      <section style={{ border: '1px solid #ddd', padding: 16, borderRadius: 8, marginBottom: 16 }}>
        <h3>4) Your Posts (saved in DB)</h3>
        <button onClick={() => refresh().catch(() => {})} style={{ marginBottom: 8 }}>
          Refresh
        </button>
        <div style={{ display: 'grid', gap: 8 }}>
          {posts.map((p) => (
            <div key={p._id} style={{ padding: 12, border: '1px solid #eee', borderRadius: 8 }}>
              <div style={{ fontSize: 12, opacity: 0.7 }}>
                {p.status} {p.scheduledAt ? `| scheduled: ${new Date(p.scheduledAt).toLocaleString()}` : ''}
              </div>
              <div>{p.text}</div>
              {p.error ? <div style={{ color: 'crimson' }}>{p.error}</div> : null}
            </div>
          ))}
        </div>
      </section>

      <section style={{ border: '1px solid #ddd', padding: 16, borderRadius: 8 }}>
        <h3>5) Bluesky Feed (author feed)</h3>
        <div style={{ display: 'grid', gap: 8 }}>
          {feed.map((item) => (
            <div key={item.uri} style={{ padding: 12, border: '1px solid #eee', borderRadius: 8 }}>
              <div style={{ fontSize: 12, opacity: 0.7 }}>{new Date(item.indexedAt).toLocaleString()}</div>
              <div>{item.text}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
