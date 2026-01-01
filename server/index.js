const path = require('path')

require('dotenv').config({ path: path.join(__dirname, '.env') })

const express = require('express')
const cors = require('cors')

const { connectDb } = require('./lib/db')
const authRoutes = require('./routes/auth')
const { router: blueskyRoutes } = require('./routes/bluesky')
const postRoutes = require('./routes/posts')
const { startScheduler } = require('./scheduler')

const app = express()

app.use(cors())
app.use(express.json({ limit: '1mb' }))

app.get('/api/health', (req, res) => {
  res.json({ ok: true })
})

app.use('/api/auth', authRoutes)
app.use('/api/bluesky', blueskyRoutes)
app.use('/api/posts', postRoutes)

// Serve client metadata for atproto OAuth
app.get('/oauth/client-metadata.json', (req, res) => {
  const clientId = `${req.protocol}://${req.get('host')}/oauth/client-metadata.json`
  const redirectUri = `${req.protocol}://${req.get('host').replace(':5000', ':5173')}/auth/callback`
  
  res.json({
    client_id: clientId,
    application_type: 'web',
    client_name: 'Bluesky Demo App',
    client_uri: `${req.protocol}://${req.get('host')}`,
    dpop_bound_access_tokens: true,
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: [redirectUri],
    response_types: ['code'],
    scope: 'atproto transition:generic',
    token_endpoint_auth_method: 'none'
  })
})

const port = process.env.PORT || 5000

async function main() {
  await connectDb()
  startScheduler()

  app.listen(port, () => {
    console.log(`API listening on http://localhost:${port}`)
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
