const Hoek = require('hoek')
const url = require('url')
const qs = require('querystring')
const debug = require('debug')('defra.identity:methods')
const uuidv4 = require('uuid/v4')
const _ = require('lodash')

module.exports = (
  {
    server,
    cache,
    config,
    internals
  }) => {
  debug('Registering server methods...')

  /**
   * Gets the user's session credentials - i.e. refresh token, expiry times of credentials
   *
   * @param {object} request - hapi request object
   * @returns {object|Boolean}
   */
  const getCredentials = async (request) => {
    Hoek.assert(typeof request === 'object', 'request object must be passed to idm.getCredentials')

    let cacheKey

    try {
      cacheKey = request.state[config.cookieName].sub
    } catch (e) {
      return false
    }

    if (!cacheKey) { return false }

    const cacheData = await cache.get(cacheKey)

    if (cacheData && typeof cacheData === 'object') {
      cacheData.isExpired = function () {
        const nowTimestamp = ((new Date()).getTime()) / 1000

        return !this.claims || (this.claims.exp < nowTimestamp)
      }
    }

    return cacheData
  }

  /**
   * Gets the user's claims
   *
   * @param {object} request - hapi request object
   * @returns {object|null}
   */
  const getClaims = async (request) => {
    Hoek.assert(typeof request === 'object', 'request object must be passed to idm.getClaims')

    const credentials = await server.methods.idm.getCredentials(request)

    if (credentials) { return credentials.claims }

    return null
  }

  /**
   * Gets a url to the plugin's outboundPath
   *
   * @param {string} backToPath - Where to send the user after they have logged in
   * @param {object} obj
   * @param {string} obj.policyName - The name of the policy the user should be sent to
   * @param {Boolean} obj.forceLogin - Whether the user should be forced to log in or not - ignores whether they are already logged in at the IdP
   * @param {Boolean} obj.returnUrlObject - Whether to return a url object. By default returns the url as a string
   */
  const generateAuthenticationUrl = (backToPath, { policyName, forceLogin = false, returnUrlObject = false } = {}) => {
    backToPath = backToPath || config.defaultBackToPath

    const outboundUrl = url.parse(config.appDomain)

    outboundUrl.pathname = config.outboundPath

    outboundUrl.query = {
      backToPath,
      policyName,
      forceLogin: forceLogin ? 'yes' : undefined
    }

    if (returnUrlObject) { return outboundUrl }

    return outboundUrl.format()
  }

  /**
   * Logs the user out
   *
   * @param {object} request - hapi request object
   */
  const logout = async (request) => {
    Hoek.assert(typeof request === 'object', 'request object must be passed to idm.logout')
    const [cacheKey] = _.at(request, `state.${config.cookieName}.sub`)

    if (cacheKey) {
      const { claims: { acr } } = await cache.get(cacheKey)
      const client = await internals.client.getClient({ policyName: acr })

      const regex = /\w+:\/\//gi;
      let sanitised=request.query.backToPath.replace(regex, '');
      if(sanitised.indexOf('/') > 0) {
        sanitised = sanitised.substring(sanitised.indexOf('/'), sanitised.length);
      } else {
        sanitised = '/business';
      }

      await cache.drop(cacheKey)
      request.query.backToPath = `${client.endSessionUrl()}&post_logout_redirect_uri=${config.appDomain}${sanitised}`
    }

    request.cookieAuth.clear()
  }

  /**
   * Refreshes the user's JWT
   *
   * @param {object} request - hapi request object
   * @param {string} refreshToken - The current JWT's refresh token - Can be retrieved from `server.methods.idm.getCredentials()`
   * @param {string} policyName - The policy the user was authenticated via when the JWT was issued
   */
  const refreshToken = async (request, refreshToken, policyName) => {
    const client = await internals.client.getClient({ policyName })

    const tokenSet = await client.refresh(refreshToken)

    internals.routes.storeTokenSetResponse(request, tokenSet)

    debug('refreshed and validated tokens %j', tokenSet)
    debug('refreshed id_token claims %j', tokenSet.claims)
  }

  /**
   * Saves the user guid state in cache and generates an IdP url to send the user to. This is the function used by the outbound path route handler
   *
   * @param {object} obj
   * @param {string} obj.backToPath - Where to send the user after they have logged in
   * @param {string} obj.policyName - The name of the policy the user should be sent to
   * @param {Boolean} obj.forceLogin - Whether the user should be forced to log in or not - ignores whether they are already logged in at the IdP
   * @param {object} obj2
   * @param {string} obj2.stateUid - Manually specify the state uid to be assigned to the user's cache entry
   * @param {object} obj2.stateCacheData - Any extra data to be stored in the user's cache entry - used when the user is sent on a reset password journey
   *
   * @returns {string} IdP authentication url
   */
  const generateFinalOutboundRedirectUrl = async ({ backToPath, policyName, forceLogin }, { stateUid = null, stateCacheData = {} } = {}) => {
    policyName = policyName || config.defaultPolicy
    stateUid = stateUid || uuidv4()

    if (forceLogin === 'yes') { forceLogin = true }

    stateCacheData = Hoek.applyToDefaults({
      policyName,
      forceLogin,
      backToPath
    }, stateCacheData)

    await cache.set(stateUid, stateCacheData)

    const client = await internals.client.getClient({ policyName })

    let authorizationUrl = client.authorizationUrl({
      redirect_uri: config.returnUriFqdn,
      scope: 'openid offline_access',
      response_mode: 'form_post',
      state: stateUid
    })

    if (forceLogin) {
      const parsedAuthorizationUrl = url.parse(authorizationUrl)

      if (typeof parsedAuthorizationUrl.query === 'string') { parsedAuthorizationUrl.query = qs.parse(parsedAuthorizationUrl.query) }

      parsedAuthorizationUrl.query.prompt = 'login'

      delete parsedAuthorizationUrl.search

      authorizationUrl = parsedAuthorizationUrl.format()
    }

    return authorizationUrl
  }

  server.method('idm.getCredentials', getCredentials)
  server.method('idm.getClaims', getClaims)
  server.method('idm.generateAuthenticationUrl', generateAuthenticationUrl)
  server.method('idm.logout', logout)
  server.method('idm.refreshToken', refreshToken)
  server.method('idm.generateFinalOutboundRedirectUrl', generateFinalOutboundRedirectUrl)

  server.method('idm.getConfig', () => config)
  server.method('idm.getInternals', () => internals)
  server.method('idm.getCache', () => cache)

  debug('Done registering server methods')
}
