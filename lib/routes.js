const to = require('await-to-js').default
const debug = require('debug')('defra.identity:routes')

module.exports = ({
  server,
  cache,
  config,
  internals
}) => {
  debug('Registering routes...')

  server.route({
    method: 'GET',
    path: config.outboundPath,
    config: {
      auth: false
    },
    handler: async (request, h) => {
      try {
        const outboundUrl = await server.methods.idm.generateFinalOutboundRedirectUrl(request.query)

        return h.redirect(outboundUrl)
      } catch (e) {
        debug(e)

        return config.callbacks.onError(e, request, h)
      }
    }
  })

  server.route({
    method: 'POST',
    path: config.returnUri,
    config: {
      auth: false
    },
    handler: async (request, h) => {
      try {
        const { payload } = request

        /** Get our saved state **/
        const { state: stateUid } = payload

        const [savedStateErr, savedState] = await to(cache.get(stateUid))

        if (!savedState || savedStateErr) {
          debug(savedStateErr)

          return h.redirect(config.disallowedRedirectPath) // @todo attach error message to this
        }

        const { policyName } = savedState

        /** Exchange code for token and validate token **/
        const client = await internals.client.getClient({ policyName })

        const [authorizationErr, tokenSet] = await to(client.authorizationCallback(config.returnUriFqdn, request.payload, { state: stateUid }))

        /** Handle authorisation error **/
        if (authorizationErr) {
          return internals.routes.handleAuthorisationError(request, h, stateUid, savedState, authorizationErr)
        }

        return internals.routes.handleValidatedToken(request, h, stateUid, savedState, tokenSet)
      } catch (e) {
        debug(e)

        return config.callbacks.onError(e, request, h)
      }
    }
  })

  server.route({
    method: 'GET',
    path: config.logoutPath,
    config: {
      auth: false
    },
    handler: async (request, h) => {
      try {
        await server.methods.idm.logout(request)

        const { query } = request
        const redirPath = query.backToPath || '/'
        let url = new URL(redirPath);

        const sanitised = redirPath.replace(url.protocol + '//', '').replace(url.host, '');

        return h.redirect(sanitised || '/')
      } catch (e) {
        debug(e)

        return config.callbacks.onError(e, request, h)
      }
    }
  })

  debug('Done registering routes')
}
