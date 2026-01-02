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

    // Create proper JWT with header and payload
    const jwtHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
    const jwtPayload = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const jwtData = `${jwtHeader}.${jwtPayload}`
    
    const privateKey = crypto.createPrivateKey(keyPair.privateKey)
    const signature = crypto.sign(null, Buffer.from(jwtData), privateKey).toString('base64url')
    
    return `${jwtData}.${signature}`
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
    console.log('Starting PAR request:', {
      authServer,
      clientId,
      redirectUri,
      codeChallenge: codeChallenge.substring(0, 20) + '...',
      state,
      loginHint
    })

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

    // Try direct authorization first (simpler and more reliable)
    try {
      console.log('Trying direct authorization (simpler approach)')
      const authUrl = `${authServer}/oauth/authorize?` +
        `client_id=${encodeURIComponent(clientId)}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `response_type=code&` +
        `scope=${encodeURIComponent('atproto transition:generic')}&` +
        `code_challenge=${encodeURIComponent(codeChallenge)}&` +
        `code_challenge_method=S256&` +
        `state=${state}` +
        (loginHint ? `&login_hint=${encodeURIComponent(loginHint)}` : '')
      
      console.log('Direct auth URL generated successfully')
      return { authUrl, useDirectAuth: true }
    } catch (err) {
      console.error('Direct auth failed:', err.message)
    }

    // Fallback to PAR with DPoP if direct fails
    let nonce = null
    let maxRetries = 3
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const parUrl = `${authServer}/oauth/par`
        console.log(`PAR attempt ${attempt + 1}/${maxRetries} to ${parUrl}`)
        
        const { response, nonce: newNonce } = await this.makeDPoPRequest(
          parUrl,
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

        console.log(`PAR response status: ${response.status}`)
        
        if (response.ok) {
          const data = await response.json()
          console.log('PAR success:', data)
          return { requestUri: data.request_uri, nonce: newNonce || nonce }
        }

        // Handle DPoP nonce error
        if (response.status === 401) {
          const errorData = await response.json().catch(() => ({}))
          console.log('PAR 401 error:', errorData)
          if (errorData.error === 'use_dpop_nonce' && newNonce) {
            nonce = newNonce
            continue // Retry with new nonce
          }
        }

        // If we get a 404 or 400, fall back to direct authorization
        if ((response.status === 404 || response.status === 400) && attempt === 0) {
          console.warn(`PAR endpoint returned ${response.status}, falling back to direct authorization`)
          
          const authUrl = `${authServer}/oauth/authorize?` +
            `client_id=${encodeURIComponent(clientId)}&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            `response_type=code&` +
            `scope=${encodeURIComponent('atproto transition:generic')}&` +
            `code_challenge=${encodeURIComponent(codeChallenge)}&` +
            `code_challenge_method=S256&` +
            `state=${state}` +
            (loginHint ? `&login_hint=${encodeURIComponent(loginHint)}` : '')
          
          return { authUrl, nonce: newNonce || nonce, useDirectAuth: true }
        }

        // For other errors, try to get error details
        const errorData = await response.json().catch(() => ({}))
        console.error('PAR error details:', errorData)
        throw new Error(`PAR request failed: ${response.status} - ${errorData.error || errorData.error_description || 'Unknown error'}`)
      } catch (err) {
        console.error(`PAR attempt ${attempt + 1} failed:`, err.message)
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

    console.log('Starting token exchange (simplified approach)')

    // Try simple POST request first (without DPoP)
    try {
      const tokenUrl = `${authServer}/oauth/token`
      console.log('Trying simple token exchange without DPoP')
      
      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json'
        },
        body: params.toString()
      })

      console.log(`Token exchange response status: ${response.status}`)

      if (response.ok) {
        const data = await response.json()
        console.log('Token exchange success (simple)')
        return { tokens: data, nonce: nonce }
      }

      // If simple request fails, try with DPoP
      console.log('Simple token exchange failed, trying with DPoP')
    } catch (err) {
      console.log('Simple token exchange error, trying DPoP:', err.message)
    }

    // Fallback to DPoP approach
    let currentNonce = nonce
    let maxRetries = 3

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const tokenUrl = `${authServer}/oauth/token`
      const { response, nonce: newNonce } = await this.makeDPoPRequest(
        tokenUrl,
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
        console.log('Token exchange success (DPoP)')
        return { 
          tokens: data, 
          nonce: newNonce || currentNonce 
        }
      }

      // Handle DPoP nonce error
      if (response.status === 401) {
        const errorData = await response.json().catch(() => ({}))
        console.log('Token exchange 401 error:', errorData)
        if (errorData.error === 'use_dpop_nonce' && newNonce) {
          currentNonce = newNonce
          continue // Retry with new nonce
        }
      }

      const errorData = await response.json().catch(() => ({}))
      console.error('Token exchange error details:', errorData)
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
    let maxRetries = 3

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const tokenUrl = `${authServer}/oauth/token`
      const { response, nonce: newNonce } = await this.makeDPoPRequest(
        tokenUrl,
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

      // Handle DPoP nonce error
      if (response.status === 401) {
        const errorData = await response.json().catch(() => ({}))
        if (errorData.error === 'use_dpop_nonce' && newNonce) {
          currentNonce = newNonce
          continue // Retry with new nonce
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
