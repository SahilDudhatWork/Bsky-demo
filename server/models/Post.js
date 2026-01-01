const mongoose = require('mongoose')

const PostSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    text: { type: String, required: true },
    scheduledAt: { type: Date },
    status: { type: String, enum: ['draft', 'scheduled', 'posting', 'posted', 'failed'], default: 'draft', index: true },
    bskyUri: { type: String },
    bskyCid: { type: String },
    error: { type: String }
  },
  { timestamps: true }
)

module.exports = mongoose.model('Post', PostSchema)
