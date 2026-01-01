const cron = require('node-cron')

const Post = require('./models/Post')
const User = require('./models/User')
const { makeAgentForUser } = require('./routes/bluesky')

let started = false

function startScheduler() {
  if (started) return
  started = true

  cron.schedule('* * * * *', async () => {
    const now = new Date()

    const due = await Post.find({
      status: 'scheduled',
      scheduledAt: { $lte: now }
    })
      .sort({ scheduledAt: 1 })
      .limit(25)

    for (const post of due) {
      try {
        post.status = 'posting'
        post.error = undefined
        await post.save()

        const user = await User.findById(post.userId)
        const agent = await makeAgentForUser(user)
        const out = await agent.post({ text: post.text })

        post.status = 'posted'
        post.bskyUri = out.uri
        post.bskyCid = out.cid
        await post.save()
      } catch (err) {
        post.status = 'failed'
        post.error = err?.message || 'Failed'
        await post.save()
      }
    }
  })

  console.log('Scheduler started')
}

module.exports = { startScheduler }
