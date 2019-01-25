const { URL } = require('url')
const authCookie = require('hapi-auth-cookie')
const Hoek = require('hoek')
const debug = require('debug')('defra.identity:index')
const qs = require('querystring')

const routes = require('./routes')
const methods = require('./methods')
const Internals = require('./internals')
const configDefaults = require('./configDefaults')

const setConfig = options => {
  debug('Setting config')

  for (const option in options) {
    Hoek.assert(configDefaults[option] !== undefined, `${option} option not recognised`)
  }

  const {
    tenantName,
    tenantId,
    cookiePassword,
    clientId,
    clientSecret,
    appDomain,
    disallowedRedirectPath,
    loginOnDisallow,
    defaultPolicy,
    resetPasswordPolicy,
    callbacks,
    cache
  } = options

  Hoek.assert(!!cookiePassword && cookiePassword.length === 32, 'cookiePassword must be supplied as a 32 character string')
  Hoek.assert(!!tenantName, 'tenantName must be supplied')
  Hoek.assert(!!tenantId, 'tenantId must be supplied')
  Hoek.assert(!!clientId, 'clientId must be supplied')
  Hoek.assert(!!clientSecret, 'clientSecret must be supplied')
  Hoek.assert(!!appDomain, 'appDomain must be supplied')
  Hoek.assert(!!resetPasswordPolicy, 'resetPasswordPolicy must be supplied')
  Hoek.assert(!!disallowedRedirectPath, 'disallowedRedirectPath must be supplied')
  Hoek.assert(!loginOnDisallow || (loginOnDisallow && defaultPolicy), 'defaultPolicy must be specified when passing true for loginOnDisallow')

  if (cache) {
    const cacheRequiredMethods = ['get', 'set', 'drop']

    cacheRequiredMethods.forEach(methodName => {
      Hoek.assert(typeof cache[methodName] === 'function', `If cache is passed, it must contain the methods ${cacheRequiredMethods}. Missing ${methodName}`)
    })
  }

  if (callbacks) {
    for (const callbackName in callbacks) {
      Hoek.assert(typeof callbacks[callbackName] === 'function', `callbacks.${callbackName} must be falsey or an async function`)
    }
  }

  const config = Hoek.applyToDefaults(configDefaults, options)

  const redirectUri = new URL(appDomain)

  redirectUri.pathname = config.returnUri

  config.returnUriFqdn = redirectUri.toString()

  config.resetPasswordPolicy = resetPasswordPolicy.toLowerCase()

  debug('Config set')

  return config
}

module.exports = {
  name: 'idm',
  version: '0.0.1',
  register: async function (server, options) {
    debug('Auth plugin register called')

    const config = setConfig(options)

    const {
      cacheSegment,
      cacheCookieTtlMs,
      cookiePassword,
      cookieName,
      disallowedRedirectPath,
      loginOnDisallow,
      isSecure,
      onByDefault,
      defaultPolicy
    } = config

    // Initialise cache
    let cache

    if (options.cache) {
      debug('Cache object passed in, using that for our cache')

      cache = options.cache
    } else {
      debug('No cache object specified, using in memory cache with segment %s', cacheSegment)

      cache = server.cache(
        {
          segment: cacheSegment,
          expiresIn: cacheCookieTtlMs
        }
      )
    }

    // Register internal methods
    const internals = Internals({
      server,
      cache,
      config
    })

    if (defaultPolicy) { await internals.client.getClient({ policyName: defaultPolicy }) }

    // Register server methods
    methods({
      server,
      cache,
      config,
      internals
    })

    debug('Registering hapi-auth-cookie...')

    // Register cookie plugin
    await server.register(authCookie)

    server.auth.strategy('idm', 'cookie', {
      password: cookiePassword,
      cookie: cookieName,
      redirectOnTry: false,
      appendNext: true,
      ttl: cacheCookieTtlMs,
      isSecure,
      redirectTo: (request) => {
        const { path } = request

        let redirectTo

        if (loginOnDisallow) {
          redirectTo = server.methods.idm.generateAuthenticationUrl(path)
        } else {
          redirectTo = disallowedRedirectPath

          redirectTo += '?' + qs.stringify({
            notLoggedInErr: 'yes'
          })
        }

        return redirectTo
      },
      validateFunc: async (request, session) => {
        // Retrieve from session store
        const credentials = await server.methods.idm.getCredentials(request)

        return {
          valid: !!credentials,
          credentials
        }
      }
    })

    debug('Done registering hapi-auth-cookie')

    if (onByDefault) {
      debug('onByDefault is true - setting default auth method')

      server.auth.default('idm')
    } else {
      debug('onByDefault is false - not setting default auth method')
    }

    // Register routes
    routes({
      server,
      cache,
      config,
      internals
    })

    debug('Auth plugin successfully registered')
  }
}
