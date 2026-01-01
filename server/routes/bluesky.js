const express = require('express')
const { BskyAgent } = require('@atproto/api')
const crypto = require('crypto')
const { requireAuth } = require('../middleware/auth')
const User = require('../models/User')
const { encryptText, decryptText } = require('../lib/crypto')
const { OAuthHelper } = require('../lib/oauth')

const router = express.Router()

// OAuth endpoints
router.post('/auth/start', requireAuth, async (req, res) => {
  try {
    const { identifier, serverUrl } = req.body || {}
    if (!identifier && !serverUrl) {
      return res.status(400).json({ error: 'identifier or serverUrl required' })
    }

    let authServer = serverUrl || 'https://bsky.social'
    if (serverUrl) {
      const metadata = await OAuthHelper.fetchServerMetadata(serverUrl)
      authServer = metadata.issuer
    }

    const codeVerifier = OAuthHelper.generateCodeVerifier()
    const codeChallenge = OAuthHelper.generateCodeChallenge(codeVerifier)
    const state = OAuthHelper.generateState()
    const dpopKeyPair = await OAuthHelper.generateDPoPKeyPair()
    
    // Vercel friendly URL logic
    const host = process.env.HOST || req.get('host')
    const protocol = process.env.PROTOCOL || 'https'
    const clientId = process.env.BSKY_OAUTH_CLIENT_ID || `${protocol}://${host}/oauth/client-metadata.json`
    const redirectUri = process.env.BSKY_OAUTH_REDIRECT_URI || `${protocol}://${host}/auth/callback`
    
    // Store session in MongoDB instead of a Map for Vercel persistence
    await User.findByIdAndUpdate(req.userId, {
      oauthTempState: {
        codeVerifier,
        state,
        dpopKeyPair: JSON.stringify(dpopKeyPair),
        authServer,
        clientId,
        redirectUri
      }
    })
    
    const parResult = await OAuthHelper.makePARRequest(
      authServer, clientId, redirectUri, codeChallenge, state, identifier, dpopKeyPair
    )
    
    let authUrl = parResult.useDirectAuth 
      ? parResult.authUrl 
      : `${authServer}/oauth/authorize?request_uri=${encodeURIComponent(parResult.requestUri)}&client_id=${encodeURIComponent(clientId)}`
    
    return res.json({ authUrl })
  } catch (err) {
    console.error('OAuth auth start failed:', err)
    return res.status(500).json({ error: err.message || 'Failed to start OAuth flow' })
  }
})

router.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query
    if (!code || !state) return res.status(400).json({ error: 'Missing code or state' })
    
    // Retrieve session from DB by state
    const user = await User.findOne({ 'oauthTempState.state': state })
    if (!user || !user.oauthTempState) return res.status(400).json({ error: 'Invalid or expired state' })
    
    const { codeVerifier, dpopKeyPair, authServer, clientId, redirectUri } = user.oauthTempState
    const parsedKeyPair = JSON.parse(dpopKeyPair)
    
    const { tokens, nonce } = await OAuthHelper.exchangeCodeForTokens(
      authServer, code, redirectUri, codeVerifier, clientId, parsedKeyPair, null
    )
    
    await User.findByIdAndUpdate(user._id, {
      bskyAccessTokenEnc: encryptText(tokens.access_token),
      bskyRefreshTokenEnc: encryptText(tokens.refresh_token || ''),
      bskyExpiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
      bskyDid: tokens.sub,
      bskyAuthServer: authServer,
      bskyDpopKeyEnc: encryptText(dpopKeyPair),
      bskyNonceEnc: encryptText(nonce || ''),
      $unset: { oauthTempState: 1 } // Clean up temp state
    })
    
    const agent = new BskyAgent({ service: authServer })
    await agent.resumeSession(tokens.access_token)
    if (agent.session?.handle) {
      await User.findByIdAndUpdate(user._id, { bskyHandle: agent.session.handle })
    }
    
    return res.json({ ok: true, handle: agent.session?.handle })
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Callback failed' })
  }
})

async function makeAgentForUser(user) {
  if (!user?.bskyHandle && !user?.bskyDid) throw new Error('Bluesky not connected')

  const service = user.bskyAuthServer || 'https://bsky.social'
  const agent = new BskyAgent({ service })
  
  if (user.bskyAccessTokenEnc) {
    try {
      let accessToken = decryptText(user.bskyAccessTokenEnc)
      
      // Token Refresh Logic
      if (user.bskyRefreshTokenEnc && user.bskyExpiresAt && new Date() >= user.bskyExpiresAt) {
        const refreshToken = decryptText(user.bskyRefreshTokenEnc)
        const dpopKeyPair = JSON.parse(decryptText(user.bskyDpopKeyEnc))
        const nonce = decryptText(user.bskyNonceEnc || '')
        const host = process.env.HOST || 'localhost:5000'
        const clientId = process.env.BSKY_OAUTH_CLIENT_ID || `https://${host}/oauth/client-metadata.json`
        
        const { tokens } = await OAuthHelper.refreshAccessToken(service, refreshToken, clientId, dpopKeyPair, nonce)
        accessToken = tokens.access_token
        
        await User.findByIdAndUpdate(user._id, {
          bskyAccessTokenEnc: encryptText(tokens.access_token),
          bskyRefreshTokenEnc: encryptText(tokens.refresh_token || refreshToken),
          bskyExpiresAt: tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000) : null,
        })
      }
      
      await agent.resumeSession(accessToken)
      return agent
    } catch (err) {
      console.warn('OAuth failed, trying app password')
    }
  }
  
  if (user.bskyAppPasswordEnc) {
    const appPassword = decryptText(user.bskyAppPasswordEnc)
    await agent.login({ identifier: user.bskyHandle, password: appPassword })
    return agent
  }
  
  throw new Error('No valid authentication found')
}

// ... existing /connect and /feed routes ...
router.post('/connect', requireAuth, async (req, res) => {
  try {
    const { handle, appPassword } = req.body || {}
    const agent = new BskyAgent({ service: 'https://bsky.social' })
    await agent.login({ identifier: handle, password: appPassword })
    await User.findByIdAndUpdate(req.userId, { bskyHandle: handle, bskyAppPasswordEnc: encryptText(appPassword) })
    return res.json({ ok: true })
  } catch (err) {
    return res.status(400).json({ error: err.message })
  }
})

router.get('/feed', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
    const agent = await makeAgentForUser(user)
    const out = await agent.getAuthorFeed({ actor: user.bskyHandle, limit: 20 })
    const feed = (out.data.feed || []).map(it => ({
      uri: it.post?.uri,
      text: it.post?.record?.text,
      indexedAt: it.post?.indexedAt
    }))
    return res.json({ feed })
  } catch (err) {
    return res.status(400).json({ error: err.message })
  }
})

module.exports = { router, makeAgentForUser }