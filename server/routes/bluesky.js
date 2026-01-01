const express = require('express')
const { BskyAgent } = require('@atproto/api')
const crypto = require('crypto')

const { requireAuth } = require('../middleware/auth')
const User = require('../models/User')
const { encryptText, decryptText } = require('../lib/crypto')
const { OAuthHelper } = require('../lib/oauth')

const router = express.Router()

// Store OAuth sessions temporarily (in production, use Redis or database)
const oauthSessions = new Map()

async function makeAgentForUser(user) {
  if (!user?.bskyHandle || !user?.bskyAppPasswordEnc) {
    const err = new Error('Bluesky not connected')
    err.status = 400
    throw err
  }

  const agent = new BskyAgent({ service: 'https://bsky.social' })
  const appPassword = decryptText(user.bskyAppPasswordEnc)
  await agent.login({ identifier: user.bskyHandle, password: appPassword })
  return agent
}

// OAuth endpoints
router.post('/auth/start', requireAuth, async (req, res) => {
  try {
    const { identifier, serverUrl } = req.body || {}
    
    if (!identifier && !serverUrl) {
      return res.status(400).json({ error: 'identifier or serverUrl required' })
    }

    // Resolve server and get metadata
    let authServer
    if (serverUrl) {
      const metadata = await OAuthHelper.fetchServerMetadata(serverUrl)
      authServer = metadata.issuer
    } else {
      // For demo purposes, default to bsky.social
      authServer = 'https://bsky.social'
    }

    // Generate OAuth session data
    const sessionId = crypto.randomBytes(16).toString('hex')
    const codeVerifier = OAuthHelper.generateCodeVerifier()
    const codeChallenge = OAuthHelper.generateCodeChallenge(codeVerifier)
    const state = OAuthHelper.generateState()
    const dpopKeyPair = await OAuthHelper.generateDPoPKeyPair()
    
    const clientId = process.env.BSKY_OAUTH_CLIENT_ID || `${req.protocol}://${req.get('host')}/oauth/client-metadata.json`
    const redirectUri = process.env.BSKY_OAUTH_REDIRECT_URI || `${req.protocol}://${req.get('host').replace(':5000', ':5173')}/auth/callback`
    
    // Store session data
    oauthSessions.set(sessionId, {
      codeVerifier,
      state,
      dpopKeyPair,
      authServer,
      clientId,
      redirectUri,
      identifier,
      userId: req.userId,
      nonce: null
    })
    
    // Clean up old sessions (older than 10 minutes)
    setTimeout(() => oauthSessions.delete(sessionId), 600000)
    
    // Make PAR request
    const parResult = await OAuthHelper.makePARRequest(
      authServer,
      clientId,
      redirectUri,
      codeChallenge,
      state,
      identifier,
      dpopKeyPair
    )
    
    // Update session with nonce
    const session = oauthSessions.get(sessionId)
    session.nonce = parResult.nonce
    
    let authUrl
    if (parResult.useDirectAuth) {
      // Use direct authorization URL
      authUrl = parResult.authUrl
    } else {
      // Use PAR request URI
      authUrl = `${authServer}/oauth/authorize?` +
        `request_uri=${encodeURIComponent(parResult.requestUri)}&` +
        `client_id=${encodeURIComponent(clientId)}`
    }
    
    return res.json({ sessionId, authUrl })
  } catch (err) {
    console.error('OAuth auth start failed:', err)
    return res.status(500).json({ error: err.message || 'Failed to start OAuth flow' })
  }
})

router.get('/callback', async (req, res) => {
  try {
    const { code, state, error, iss } = req.query
    
    if (error) {
      return res.status(400).json({ error: `OAuth error: ${error}` })
    }
    
    if (!code || !state) {
      return res.status(400).json({ error: 'Missing code or state' })
    }
    
    // Find session by state
    let sessionId = null
    let sessionData = null
    
    for (const [sid, session] of oauthSessions.entries()) {
      if (session.state === state) {
        sessionId = sid
        sessionData = session
        break
      }
    }
    
    if (!sessionData) {
      return res.status(400).json({ error: 'Invalid or expired state' })
    }
    
    const { codeVerifier, dpopKeyPair, authServer, clientId, redirectUri, userId, nonce } = sessionData
    
    // Exchange code for tokens
    const { tokens, nonce: newNonce } = await OAuthHelper.exchangeCodeForTokens(
      authServer,
      code,
      redirectUri,
      codeVerifier,
      clientId,
      dpopKeyPair,
      nonce
    )
    
    // Store tokens securely
    await User.findByIdAndUpdate(userId, {
      bskyHandle: null, // Will be set after getting user info
      bskyAccessTokenEnc: encryptText(tokens.access_token),
      bskyRefreshTokenEnc: encryptText(tokens.refresh_token || ''),
      bskyTokenType: tokens.token_type || 'DPoP',
      bskyExpiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
      bskyDid: tokens.sub, // DID from the token response
      bskyAuthServer: authServer,
      bskyDpopKeyEnc: encryptText(JSON.stringify(dpopKeyPair)),
      bskyNonceEnc: encryptText(newNonce || nonce || '')
    })
    
    // Get user info using the access token
    const agent = new BskyAgent({ service: authServer })
    await agent.resumeSession(tokens.access_token)
    
    const handle = agent.session?.handle
    if (handle) {
      await User.findByIdAndUpdate(userId, { bskyHandle: handle })
    }
    
    // Clean up session
    oauthSessions.delete(sessionId)
    
    return res.json({ ok: true, handle, did: tokens.sub })
  } catch (err) {
    console.error('OAuth callback failed:', err)
    return res.status(500).json({ error: err.message || 'OAuth callback failed' })
  }
})

// Updated makeAgentForUser to use OAuth tokens
async function makeAgentForUser(user) {
  if (!user?.bskyHandle && !user?.bskyDid) {
    const err = new Error('Bluesky not connected')
    err.status = 400
    throw err
  }

  const service = user.bskyAuthServer || 'https://bsky.social'
  const agent = new BskyAgent({ service })
  
  // Try OAuth token first
  if (user.bskyAccessTokenEnc) {
    try {
      const accessToken = decryptText(user.bskyAccessTokenEnc)
      await agent.resumeSession(accessToken)
      
      // Check if token needs refresh
      if (user.bskyRefreshTokenEnc && user.bskyExpiresAt && new Date() >= user.bskyExpiresAt) {
        const refreshToken = decryptText(user.bskyRefreshTokenEnc)
        const dpopKeyPair = JSON.parse(decryptText(user.bskyDpopKeyEnc || '{}'))
        const nonce = decryptText(user.bskyNonceEnc || '')
        const clientId = process.env.BSKY_OAUTH_CLIENT_ID || `${process.env.PROTOCOL || 'http'}://${process.env.HOST || 'localhost'}:${process.env.PORT || 5000}/oauth/client-metadata.json`
        
        try {
          const { tokens } = await OAuthHelper.refreshAccessToken(
            service,
            refreshToken,
            clientId,
            dpopKeyPair,
            nonce
          )
          
          await agent.resumeSession(tokens.access_token)
          
          // Update stored tokens
          await User.findByIdAndUpdate(user._id, {
            bskyAccessTokenEnc: encryptText(tokens.access_token),
            bskyRefreshTokenEnc: encryptText(tokens.refresh_token || refreshToken),
            bskyExpiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
          })
        } catch (refreshErr) {
          console.warn('Token refresh failed:', refreshErr.message)
          // Continue with existing token if refresh fails
        }
      }
      
      return agent
    } catch (oauthErr) {
      console.warn('OAuth token failed, falling back to app password:', oauthErr.message)
    }
  }
  
  // Fallback to app password
  if (!user?.bskyAppPasswordEnc) {
    const err = new Error('Bluesky not connected')
    err.status = 400
    throw err
  }

  const appPassword = decryptText(user.bskyAppPasswordEnc)
  await agent.login({ identifier: user.bskyHandle, password: appPassword })
  return agent
}

router.post('/connect', requireAuth, async (req, res) => {
  try {
    const { handle, appPassword } = req.body || {}
    if (!handle || !appPassword) {
      return res.status(400).json({ error: 'handle and appPassword required' })
    }

    const agent = new BskyAgent({ service: 'https://bsky.social' })
    await agent.login({ identifier: handle, password: appPassword })

    const enc = encryptText(appPassword)
    await User.findByIdAndUpdate(req.userId, { bskyHandle: handle, bskyAppPasswordEnc: enc })

    return res.json({ ok: true })
  } catch (err) {
    console.error('Bluesky connect failed:', err)
    const status = err?.status || err?.response?.status || 400
    const msg =
      err?.message ||
      err?.response?.data?.message ||
      err?.response?.data?.error ||
      'Bluesky connect failed'
    return res.status(status).json({ error: msg })
  }
})

router.get('/feed', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
    const agent = await makeAgentForUser(user)

    const out = await agent.getAuthorFeed({ actor: user.bskyHandle, limit: 20 })
    const feed = (out.data.feed || []).map((it) => ({
      uri: it.post?.uri,
      cid: it.post?.cid,
      text: it.post?.record?.text,
      indexedAt: it.post?.indexedAt
    }))

    return res.json({ feed })
  } catch (err) {
    const status = err.status || 400
    return res.status(status).json({ error: err.message || 'Failed to fetch feed' })
  }
})

module.exports = { router, makeAgentForUser }
