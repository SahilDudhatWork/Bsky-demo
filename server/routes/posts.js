const express = require('express')

const { requireAuth } = require('../middleware/auth')
const Post = require('../models/Post')
const User = require('../models/User')
const { makeAgentForUser } = require('./bluesky')

const router = express.Router()

router.get('/', requireAuth, async (req, res) => {
  const posts = await Post.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(50)
  return res.json({ posts })
})

router.post('/instant', requireAuth, async (req, res) => {
  try {
    const { text } = req.body || {}
    if (!text) {
      return res.status(400).json({ error: 'text required' })
    }

    const user = await User.findById(req.userId)
    
    // Check if Bluesky is connected
    if (!user?.bskyHandle && !user?.bskyDid) {
      return res.status(400).json({ error: 'Please connect your Bluesky account first' })
    }

    // Post directly to Bluesky without saving to database
    const agent = await makeAgentForUser(user)
    const out = await agent.post({ text })

    return res.json({ 
      ok: true, 
      bskyUri: out.uri,
      bskyCid: out.cid,
      message: 'Posted successfully to Bluesky'
    })
  } catch (err) {
    console.error('Post creation error:', err)
    return res.status(400).json({ error: err.message || 'Post failed' })
  }
})

router.post('/schedule', requireAuth, async (req, res) => {
  const { text, scheduledAt } = req.body || {}
  if (!text || !scheduledAt) {
    return res.status(400).json({ error: 'text and scheduledAt required' })
  }

  const date = new Date(scheduledAt)
  if (Number.isNaN(date.getTime())) {
    return res.status(400).json({ error: 'scheduledAt invalid' })
  }

  const postDoc = await Post.create({ userId: req.userId, text, scheduledAt: date, status: 'scheduled' })
  return res.json({ ok: true, post: postDoc })
})

module.exports = router
