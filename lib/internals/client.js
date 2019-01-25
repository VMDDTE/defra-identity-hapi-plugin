const debug = require('debug')('defra.identity:internals:client')
const Issuer = require('openid-client').Issuer

Issuer.defaultHttpOptions = {
  timeout: 5000,
  retries: 2
}

module.exports = ({
  server,
  cache,
  config
}) => {
  const e = {}
  const clients = {}

  e.getClient = async ({ policyName }) => {
    const {
      clientId,
      clientSecret,
      tenantName,
      tenantId,
      defaultPolicy
    } = config

    debug(`${policyName} policy requested`)

    if (!policyName && defaultPolicy) { policyName = defaultPolicy }

    if (!clients[policyName]) {
      debug(`${policyName} not found. Instantiating...`)

      debug('Instantiating issuer...')

      const endpointAppend = policyName ? `?p=${policyName}` : ''

      // Initialise b2c
      // https://login.microsoftonline.com/dcidmdev.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=b2c_1_b2c-webapp-signup-signin
      /*
      const issuer = new Issuer({
        issuer: `https://login.microsoftonline.com/${tenantId}/v2.0/`,
        authorization_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize${endpointAppend}`,
        token_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token${endpointAppend}`,
        end_session_endpoint: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/logout${endpointAppend}`,
        jwks_uri: `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys${endpointAppend}`

        // userinfo_endpoint: undefined, // Microsoft does not provide this - need to use graph api instead afaik
      })
      */

      const issuer = new Issuer({
        issuer: `https://${tenantName}.b2clogin.com/${tenantId}/v2.0/`,
        authorization_endpoint: `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/oauth2/v2.0/authorize${endpointAppend}`,
        token_endpoint: `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/oauth2/v2.0/token${endpointAppend}`,
        end_session_endpoint: `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/oauth2/v2.0/logout${endpointAppend}`,
        jwks_uri: `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/discovery/v2.0/keys${endpointAppend}`

        // userinfo_endpoint: undefined, // Microsoft does not provide this - need to use graph api instead afaik
      })

      debug('Issuer instantiated')
      debug('Instantiating client...')

      const client = new issuer.Client({
        client_id: clientId,
        client_secret: clientSecret,
        token_endpoint_auth_method: 'client_secret_post',
        token_endpoint_auth_signing_alg: 'RS256'
      })

      client.CLOCK_TOLERANCE = 300

      debug('Client instantiated')

      clients[policyName] = client

      debug(`${policyName} client registered. There are a currently a total of %d clients registered`, Object.keys(clients).length)
    }

    return clients[policyName]
  }

  return e
}
