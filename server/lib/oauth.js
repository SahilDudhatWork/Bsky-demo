const crypto = require('crypto')
const { encryptText, decryptText } = require('./crypto')

class OAuthHelper {
  static generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url')
  }

  static generateCodeChallenge(codeVerifier) {
    return crypto.createHash('sha256').update(codeVerifier).digest('base64url')
  }

  static generateState() {
    return crypto.randomBytes(16).toString('hex')
  }

  static async generateDPoPKeyPair() {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'jwk' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })
  }

  static createDPoPProof(keyPair, method, url, nonce = null, accessToken = null) {
    const header = {
      typ: 'dpop+jwt',
      alg: 'ES256',
      jwk: keyPair.publicKey
    }

    const payload = {
      jti: crypto.randomBytes(16).toString('hex'),
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000)
    }

    if (nonce) {
      payload.nonce = nonce
    }

    if (accessToken) {
      const hash = crypto.createHash('sha256').update(accessToken).digest()
      payload.ath = hash.toString('base64url')
    }

    const privateKey = crypto.createPrivateKey(keyPair.privateKey)
    return crypto.sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString('base64url')
  }

  static async makeDPoPRequest(url, options = {}, dpopKeyPair, nonce = null, accessToken = null) {
    const method = options.method || 'GET'
    const dpopProof = this.createDPoPProof(dpopKeyPair, method, url, nonce, accessToken)
    
    const headers = {
      ...options.headers,
      'DPoP': dpopProof
    }

    if (accessToken) {
      headers['Authorization'] = `DPoP ${accessToken}`
    }

    const response = await fetch(url, {
      ...options,
      headers
    })

    // Update nonce if provided in response
    const newNonce = response.headers.get('DPoP-Nonce')
    if (newNonce) {
      return { response, nonce: newNonce }
    }

    return { response }
  }

  static async makePARRequest(authServer, clientId, redirectUri, codeChallenge, state, loginHint = null, dpopKeyPair) {
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'atproto transition:generic',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state: state
    })

    if (loginHint) {
      params.append('login_hint', loginHint)
    }

    let nonce = null
    let maxRetries = 2
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const { response, nonce: newNonce } = await this.makeDPoPRequest(
          `${authServer}/oauth/par`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept': 'application/json'
            },
            body: params.toString()
          },
          dpopKeyPair,
          nonce
        )

        if (response.ok) {
          const data = await response.json()
          return { requestUri: data.request_uri, nonce: newNonce || nonce }
        }

        // If we get a 404, let's try the traditional OAuth flow without PAR
        if (response.status === 404 && attempt === 0) {
          console.warn('PAR endpoint not found, falling back to direct authorization')
          // For direct auth, use a simple client ID, not the metadata URL
          const simpleClientId = 'bluesky-demo-app'
          
          // Generate a direct authorization URL instead
          const authUrl = `${authServer}/oauth/authorize?` +
            `client_id=${encodeURIComponent(simpleClientId)}&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            `response_type=code&` +
            `scope=${encodeURIComponent('atproto transition:generic')}&` +
            `code_challenge=${encodeURIComponent(codeChallenge)}&` +
            `code_challenge_method=S256&` +
            `state=${state}` +
            (loginHint ? `&login_hint=${encodeURIComponent(loginHint)}` : '')
          
          return { authUrl, nonce: newNonce || nonce, useDirectAuth: true }
        }

        // If we get 400, it might be a request format issue, try direct auth
        if (response.status === 400 && attempt === 0) {
          const errorData = await response.json().catch(() => ({}))
          console.warn('PAR request invalid, falling back to direct authorization:', errorData)
          
          // For direct auth, use a simple client ID, not the metadata URL
          const simpleClientId = 'bluesky-demo-app'
          
          // Generate a direct authorization URL instead
          const authUrl = `${authServer}/oauth/authorize?` +
            `client_id=${encodeURIComponent(simpleClientId)}&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            `response_type=code&` +
            `scope=${encodeURIComponent('atproto transition:generic')}&` +
            `code_challenge=${encodeURIComponent(codeChallenge)}&` +
            `code_challenge_method=S256&` +
            `state=${state}` +
            (loginHint ? `&login_hint=${encodeURIComponent(loginHint)}` : '')
          
          return { authUrl, nonce: newNonce || nonce, useDirectAuth: true }
        }

        if (response.status === 401) {
          const errorData = await response.json().catch(() => ({}))
          if (errorData.error === 'use_dpop_nonce' && newNonce) {
            nonce = newNonce
            continue
          }
        }

        const errorData = await response.json().catch(() => ({}))
        throw new Error(`PAR request failed: ${response.status} - ${errorData.error || errorData.error_description || 'Unknown error'}`)
      } catch (err) {
        if (attempt === maxRetries - 1) {
          throw err
        }
        // Retry on network errors
        await new Promise(resolve => setTimeout(resolve, 1000))
      }
    }

    throw new Error('PAR request failed after retries')
  }

  static async exchangeCodeForTokens(authServer, code, redirectUri, codeVerifier, clientId, dpopKeyPair, nonce) {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      client_id: clientId
    })

    let currentNonce = nonce
    let maxRetries = 2

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const { response, nonce: newNonce } = await this.makeDPoPRequest(
        `${authServer}/oauth/token`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: params.toString()
        },
        dpopKeyPair,
        currentNonce
      )

      if (response.ok) {
        const data = await response.json()
        return { 
          tokens: data, 
          nonce: newNonce || currentNonce 
        }
      }

      if (response.status === 401) {
        const errorData = await response.json().catch(() => ({}))
        if (errorData.error === 'use_dpop_nonce' && newNonce) {
          currentNonce = newNonce
          continue
        }
      }

      const errorData = await response.json().catch(() => ({}))
      throw new Error(`Token exchange failed: ${errorData.error_description || errorData.error || response.status}`)
    }

    throw new Error('Token exchange failed after retries')
  }

  static async refreshAccessToken(authServer, refreshToken, clientId, dpopKeyPair, nonce) {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId
    })

    let currentNonce = nonce
    let maxRetries = 2

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const { response, nonce: newNonce } = await this.makeDPoPRequest(
        `${authServer}/oauth/token`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: params.toString()
        },
        dpopKeyPair,
        currentNonce
      )

      if (response.ok) {
        const data = await response.json()
        return { 
          tokens: data, 
          nonce: newNonce || currentNonce 
        }
      }

      if (response.status === 401) {
        const errorData = await response.json().catch(() => ({}))
        if (errorData.error === 'use_dpop_nonce' && newNonce) {
          currentNonce = newNonce
          continue
        }
      }

      const errorData = await response.json().catch(() => ({}))
      throw new Error(`Token refresh failed: ${errorData.error_description || errorData.error || response.status}`)
    }

    throw new Error('Token refresh failed after retries')
  }

  static async fetchServerMetadata(serverUrl) {
    // Try protected resource metadata first
    try {
      const resourceResponse = await fetch(`${serverUrl}/.well-known/oauth-protected-resource`)
      if (resourceResponse.ok) {
        const resourceData = await resourceResponse.json()
        if (resourceData.authorization_servers && resourceData.authorization_servers.length > 0) {
          const authServer = resourceData.authorization_servers[0]
          const authResponse = await fetch(`${authServer}/.well-known/oauth-authorization-server`)
          if (authResponse.ok) {
            return await authResponse.json()
          }
        }
      }
    } catch (err) {
      console.warn('Failed to fetch protected resource metadata:', err.message)
    }

    // Fallback to direct auth server metadata
    try {
      const authResponse = await fetch(`${serverUrl}/.well-known/oauth-authorization-server`)
      if (authResponse.ok) {
        return await authResponse.json()
      }
    } catch (err) {
      console.warn('Failed to fetch auth server metadata:', err.message)
    }

    // Final fallback - assume standard Bluesky endpoints
    console.warn('Could not fetch OAuth metadata, using Bluesky defaults')
    return {
      issuer: serverUrl,
      authorization_endpoint: `${serverUrl}/oauth/authorize`,
      token_endpoint: `${serverUrl}/oauth/token`,
      pushed_authorization_request_endpoint: `${serverUrl}/oauth/par`,
      scopes_supported: ['atproto', 'transition:generic']
    }
  }
}

module.exports = { OAuthHelper }
