const path = require('path')

require('dotenv').config({ path: path.join(__dirname, '.env') })

const { env } = process

module.exports = {
  app: {
    host: env.HOST || undefined, // Make sure it's undefined if not truey - heroku only wants to bind port
    port: env.PORT || 9200,
    domain: env.DOMAIN || `http://${env.HOST}:${env.PORT}`
  },

  identity: {
    tenantName: env.IDENTITY_TENANTNAME,
    tenantId: env.IDENTITY_TENANTID,
    cookiePassword: env.IDENTITY_COOKIEPASSWORD,
    clientId: env.IDENTITY_CLIENTID,
    clientSecret: env.IDENTITY_CLIENTSECRET,
    defaultPolicy: env.IDENTITY_DEFAULT_POLICY,
    resetPasswordPolicy: env.IDENTITY_RESET_PASSWORD_POLICY,
    disallowedRedirectPath: '/error'
  },

  mongoCache: {
    enabled: false,
    host: '127.0.0.1'
  }
}
