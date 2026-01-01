const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    bskyHandle: { type: String },
    bskyAppPasswordEnc: { type: String },
    // OAuth fields
    bskyAccessTokenEnc: { type: String },
    bskyRefreshTokenEnc: { type: String },
    bskyTokenType: { type: String },
    bskyExpiresAt: { type: Date },
    bskyDid: { type: String },
    bskyAuthServer: { type: String },
    bskyDpopKeyEnc: { type: String },
    bskyNonceEnc: { type: String },
    oauthTempState: { type: Object }
  },
  { timestamps: true }
)

module.exports = mongoose.model('User', UserSchema)
