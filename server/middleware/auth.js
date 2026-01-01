const jwt = require('jsonwebtoken')

function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) {
    return res.status(401).json({ error: 'Missing token' })
  }

  try {
    const secret = process.env.JWT_SECRET
    if (!secret) {
      return res.status(500).json({ error: 'Missing JWT_SECRET' })
    }

    const payload = jwt.verify(token, secret)
    req.userId = payload.sub
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

module.exports = { requireAuth }
