const crypto = require('crypto')

function getKey() {
  const secret = process.env.CRYPTO_SECRET
  if (!secret) {
    throw new Error('Missing CRYPTO_SECRET')
  }
  return crypto.scryptSync(secret, 'bsky_salt', 32)
}

function encryptText(plain) {
  const key = getKey()
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, enc]).toString('base64')
}

function decryptText(payload) {
  const key = getKey()
  const buf = Buffer.from(String(payload), 'base64')
  const iv = buf.subarray(0, 12)
  const tag = buf.subarray(12, 28)
  const enc = buf.subarray(28)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  const plain = Buffer.concat([decipher.update(enc), decipher.final()])
  return plain.toString('utf8')
}

module.exports = { encryptText, decryptText }
