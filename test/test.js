const { expect } = require('code')
const Lab = require('lab')
const lab = exports.lab = Lab.script()

const to = require('await-to-js').default
const uuidv4 = require('uuid/v4')
const url = require('url')
const qs = require('querystring')

// const jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.eyJleHAiOjE1MjE3MzQ5NTMsIm5iZiI6MTUyMTczMTM1MywidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL2NiMDk2NzVhLWFmMjEtNGRkZS05Y2Y4LWY2MzIzNWEyMTlhMC92Mi4wLyIsInN1YiI6IjZlODdjNmU1LTljMDktNDdlMC1hMWNmLTkyYTYxZDI2MTI1ZiIsImF1ZCI6IjY1MmY0NmQwLTI2NzAtNGEzNC05ZmJjLTAxY2Q1ZmFjZmEzNCIsIm5vbmNlIjoiZGVmYXVsdE5vbmNlIiwiaWF0IjoxNTIxNzMxMzUzLCJhdXRoX3RpbWUiOjE1MjE3MzEzNTMsIm9pZCI6IjZlODdjNmU1LTljMDktNDdlMC1hMWNmLTkyYTYxZDI2MTI1ZiIsImdpdmVuX25hbWUiOiJDaGVzaGlyZSIsImZhbWlseV9uYW1lIjoiQ2hlc2hpcmUiLCJlbWFpbHMiOlsiZGVmcmFAaWFtY2hyaXNjaGVzaGlyZS5jby51ayJdLCJ0ZnAiOiJCMkNfMV9iMmMtd2ViYXBwLXNpZ251cC1zaWduaW4ifQ.kFNwgCFuYmR0T1Y0fkggMd2OjrNOaDFRJe1wfX3qAtEl49OP3lfAhLQIyAdlpT3Yotp4oanhUoDMlgMXsP1z1JhRUT_Bsb892tF8-ZRxOHggO3Jciy1RmTnEFJDJH_FMLvExBgliuo8qhYu0g_gqUZVC1f5FogpMtzAe63d2HXVheicw3OsrBHBBaHMLRYnCH0PvoA-UqU0-DAHkgxcg7ldAqxvVCULT9GxQc6_FpZWP9O6lx0ECCRoAir5Lnr7nRGD5gkFhJlAa3szJQmC7ETh8eIJbeTHwxWpNeun-YxDkiqMrbgo9khqRGiViA0lnIzqq899LBhdtRUoY7gu0gw'

const server = require('../demo')

const validatePolicyRedirectUrl = (redirectUrl, idmConfig, policyName) => {
  // Make sure we've been redirected to the appropriate identity provider
  const parsedHeaderLocation = url.parse(redirectUrl)

  expect(parsedHeaderLocation.protocol).to.equal('https:')
  expect(parsedHeaderLocation.host).to.equal('login.microsoftonline.com')
  expect(parsedHeaderLocation.pathname).to.equal(`/${idmConfig.tenantId}/oauth2/v2.0/authorize`)

  // Make sure we've been redirect with the appropriate parameters
  const parsedQuerystring = qs.parse(parsedHeaderLocation.query)

  expect(parsedQuerystring.p).to.equal(policyName)
  expect(parsedQuerystring.redirect_uri).to.equal(idmConfig.appDomain + idmConfig.returnUri)
  expect(parsedQuerystring.scope).to.equal('openid offline_access')
  expect(parsedQuerystring.response_mode).to.equal('form_post')
  expect(parsedQuerystring.client_id).to.equal(idmConfig.clientId)
  expect(parsedQuerystring.response_type).to.equal('code')
}

lab.experiment('Defra.Identity HAPI plugin functionality', () => {
  lab.test('Should return an outbound redirect url', async () => {
    const idmConfig = server.methods.idm.getConfig()

    const {
      defaultPolicy,
      outboundPath
    } = idmConfig

    const url = server.methods.idm.generateAuthenticationUrl('/', {
      returnUrlObject: true,
      policyName: defaultPolicy,
      forceLogin: false
    })

    const {
      query,
      pathname
    } = url

    expect(query).to.equal({
      backToPath: '/',
      policyName: defaultPolicy,
      forceLogin: undefined
    })

    expect(pathname).to.equal(outboundPath)
  })

  lab.test('The plugin should redirect the request to the identity provider with the appropriate parameters', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const injectionUrl = server.methods.idm.generateAuthenticationUrl('/')

    const res = await server.inject({
      method: 'GET',
      url: injectionUrl
    })

    // Make sure we've been redirected
    expect(res.statusCode).to.equal(302)

    validatePolicyRedirectUrl(res.headers.location, idmConfig, idmConfig.defaultPolicy)
  })

  lab.test('The plugin should save state on outbound url and reject valid but expired jwt', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const returnUri = idmConfig.returnUri

    const stateUid = uuidv4()

    // https://login.microsoftonline.com/cb09675a-af21-4dde-9cf8-f63235a219a0/oauth2/v2.0/authorize?p=b2c_1_b2c-webapp-signup-signin&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Flogin%2Freturn&scope=openid%20offline_access&response_mode=form_post&state=1234&client_id=4948935b-6137-4ee8-86a3-2d0a2e31442b&response_type=code&prompt=login
    // Generate final outbound url - we don't need to follow it, we just need it to cache our state - will generate url above
    await server.methods.idm.generateFinalOutboundRedirectUrl({
      backToPath: '/',
      forceLogin: true
    }, {
      stateUid
    })

    const res = await server.inject({
      method: 'POST',
      url: returnUri,
      payload: {
        'state': stateUid,
        'code': 'eyJraWQiOiJjcGltY29yZV8wOTI1MjAxNSIsInZlciI6IjEuMCIsInppcCI6IkRlZmxhdGUiLCJzZXIiOiIxLjAifQ..OGGZBoSqVKtszxvD.9wZLifx4zEVQXF5fUpBgJEe1bAyk0dSvbqgvfWwtZIb_4mQ4fTJoWswfBSV5wBA5OvGnXmB4LJQ3nau2ZgjvNf9CQXw2rkew9xjVIbae6zQ3JocEfX6hFqwOEtS4Lgyw_LtWdXqUp74UCcpOzoZiqtLWctyR3xheJl28h0b7BH5NZ8U7Okm4-T-Il-RIcfS3ts5Mfs8EktFjBW3JMprYuttRQ-0qWSGbdmEtMnlu-ByPmvqk0Ss6GNDnHQFicwIbTjEgWt6254iJtBsMbnDmt9r-o6KB1-ZHoQo6mHmGsmuZp7In_WvFUCWRbRt7cHQdyPdWz9kaWfx8vuVmC-8r0RvdTOhQo1P3LgNAyYcBGTnLT1W6mHl7JhffjKfyEtwQNVwclHBK1cTbqK0E4ENrPSd7jkrI7KBV08qQG0s_8p2z0U24nCgHiSJel-yPVF_4Wi3usopcKH2HFOvUHDLDcbYcBWIcEEykDdxpfeWCbW8iObui514E1unjz9qtaIOsLRdxtIXLL8GLhe5kd4nCJMIPRazhQ9OZXVXUDCZQiPC2gUG0cOpzhByY5S-X3ruQPXVePPQETGNwrNasU05Wm6JL5cXJQvBVax_5NdobEEos-m9UKoc7PQ.EQxigB0PwkD8dKoDrfgRHQ'
      }
    })

    expect(res.statusCode).to.equal(302)

    const parsedHeaderLocation = url.parse(res.headers.location)

    expect(parsedHeaderLocation.pathname).to.equal(idmConfig.disallowedRedirectPath)
  })

  lab.test('The plugin should execute our final redirect function', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const idmInternals = server.methods.idm.getInternals()
    const idmCache = server.methods.idm.getCache()

    const tokenSet = {
      'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.eyJleHAiOjE1MjE4MjQ5NjUsIm5iZiI6MTUyMTgyMTM2NSwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL2NiMDk2NzVhLWFmMjEtNGRkZS05Y2Y4LWY2MzIzNWEyMTlhMC92Mi4wLyIsInN1YiI6IjZlODdjNmU1LTljMDktNDdlMC1hMWNmLTkyYTYxZDI2MTI1ZiIsImF1ZCI6IjQ5NDg5MzViLTYxMzctNGVlOC04NmEzLTJkMGEyZTMxNDQyYiIsImlhdCI6MTUyMTgyMTM2NSwiYXV0aF90aW1lIjoxNTIxODIxMzY1LCJvaWQiOiI2ZTg3YzZlNS05YzA5LTQ3ZTAtYTFjZi05MmE2MWQyNjEyNWYiLCJnaXZlbl9uYW1lIjoiQ2hlc2hpcmUiLCJmYW1pbHlfbmFtZSI6IkNoZXNoaXJlIiwiZW1haWxzIjpbImRlZnJhQGlhbWNocmlzY2hlc2hpcmUuY28udWsiXSwidGZwIjoiQjJDXzFfYjJjLXdlYmFwcC1zaWdudXAtc2lnbmluIn0.plRV2ZoPcnXR7rj4zSexyksfoQE9AKBUaTKZTpfTcYmBmqnD159MH6sOoczWNp1mnI6ilwGj5c6Sdd0qlwaGmFOvylgebuDec2mvIbjxZ8kXSwl_GkgTE20sQVstsxhC66CU83fn7siRVLLhOWUmKD73KOFA5tb4lCYndXfbie4o0KFofWDrV-uzRJbr7BXXAyITdUCEs3gw29WTM0neKOUZJnnc930LjqAIbQmr4lvTrtq5qwj9OwE5G_vq0RVblWUuE4iQPobOMyJlUL74l74Nr1XarCqpP3RYerYRXNsRcJhasbQfknfoMrX2rnzj_h5xbSQO9cauAsphmXapfw',
      'token_type': 'Bearer',
      'not_before': 1521821365,
      'id_token_expires_in': 3600,
      'profile_info': 'eyJ2ZXIiOiIxLjAiLCJ0aWQiOiJjYjA5Njc1YS1hZjIxLTRkZGUtOWNmOC1mNjMyMzVhMjE5YTAiLCJzdWIiOm51bGwsIm5hbWUiOm51bGwsInByZWZlcnJlZF91c2VybmFtZSI6bnVsbCwiaWRwIjpudWxsfQ',
      'refresh_token': 'eyJraWQiOiJjcGltY29yZV8wOTI1MjAxNSIsInZlciI6IjEuMCIsInppcCI6IkRlZmxhdGUiLCJzZXIiOiIxLjAifQ..og5tc9dcMCi1x9Sz.T5seCETmDU0m548QJ2rLYW8wEarhlCIL8MkJMVpzUpkDVJ-2FxHcFQghqNMxSi4PwogUqST4jDkeGdiazZw0Y66epXzwhvdmcHafXwUsFWV9tCTUPfsCfLHBWOYpdsOyFIFndMO5IOwodWYQc6W5lcdUsKlI-GDJvXnNUgKUdqKuXWBQsX9kaDCOFS8ze9MRrBgYmTleBsiXLdfOkVlBz5Gi5Mob69oiXjqyAjXY-h9OJDT9yFYbQcGuOBoOQqY5vomjCVLcX6cWy4t_IMlkGbs8GMCG0-yrgvDdIqILZqpa4bIkNiGiDeHasCCDTs1TLJYBbhc7rBa6A3wLdyRrrrDlntKA0g2A0jVCzWcyPvCcen9R0hcGBchCyfUR0yCEu9oHXFSN8v1UW_7mfumX_b8rrQ853nVKyjNlf5SI3UwYApnsE5I7EKFc_yHkM6uHVEfrWBQQX4NLbm3854QPp3gRFzaqr6WYnQWRy5vqHFqCt0k7zh3qCq0gubZw3K7rVZK-VON8Kpd2KLBP1MszaXLNzAdVcNQUVni-FYbxiYrVDvzI9LgFRtRJMtHjQC_6Ln8bY2RHm98FEiy53FQ6yT25OMuTmq3t9YKedpf1hvyRe9NwkrVuRhMK0uI.4D663219YNoPSmqnLBK7Hw',
      'refresh_token_expires_in': 1209600,
      'claims': {
        'exp': 1521824965,
        'nbf': 1521821365,
        'ver': '1.0',
        'iss': 'https://login.microsoftonline.com/cb09675a-af21-4dde-9cf8-f63235a219a0/v2.0/',
        'sub': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'aud': '4948935b-6137-4ee8-86a3-2d0a2e31442b',
        'iat': 1521821365,
        'auth_time': 1521821365,
        'oid': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'given_name': 'Chris',
        'family_name': 'Cheshire',
        'emails': [
          'cheese@biscuits.com'
        ],
        'tfp': 'B2C_1_b2c-webapp-signup-signin'
      }
    }

    const dummyRequest = {
      cookieAuth: {
        set: () => {}
      }
    }

    const stateUid = uuidv4()

    const responseIdentifier = uuidv4()

    // Set a custom preReturnUriRedirectOutcome so we know handleValidatedToken has run in its entirety
    idmConfig.callbacks.preReturnUriRedirect = (request, h, tokenSet, backToPath) => responseIdentifier

    await idmInternals.routes.handleValidatedToken(dummyRequest, null, stateUid, {}, tokenSet)

    const [cachedDataErr, cachedData] = await to(idmCache.get(tokenSet.claims.oid))

    if (cachedDataErr) {
      console.error(cachedDataErr)
    }

    expect(cachedData.claims.sub).to.equal(tokenSet.claims.sub)
  })

  lab.test('The plugin should redirect the request to reset the password to the reset password policy', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const idmInternals = server.methods.idm.getInternals()
    const idmCache = server.methods.idm.getCache()

    const stateUid = uuidv4()

    const savedState = {
      policyName: 'testPolicyName'
    }

    const authorisationErr = {
      error_description: 'AADB2C90118: The user has forgotten their password.\n' +
      'Correlation ID: b894fb27-5da9-4906-973d-0ebd8e4237c6\n' +
      'Timestamp: 2018-03-23 17:25:05Z\n' +
      'login_hint: cheese@biscuits.com\n'
    }

    const dummyH = {
      redirect: resetPasswordOutboundUrl => resetPasswordOutboundUrl
    }

    const resetPasswordOutboundUrl = await idmInternals.routes.handleAuthorisationError(null, dummyH, stateUid, savedState, authorisationErr)

    validatePolicyRedirectUrl(resetPasswordOutboundUrl, idmConfig, idmConfig.resetPasswordPolicy)

    const [cachedStateErr, cachedState] = await to(idmCache.get(stateUid))

    if (cachedStateErr) {
      console.error(cachedStateErr)
    }

    expect(cachedState.policyName).to.equal(idmConfig.resetPasswordPolicy)
    expect(cachedState.policyPrePasswordReset).to.equal(savedState.policyName)
  })

  lab.test('The plugin should redirect to the original policy after a password reset has been completed', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const idmInternals = server.methods.idm.getInternals()
    const idmCache = server.methods.idm.getCache()

    /** Generate our password reset policy cache entries and url **/
    const stateUid = uuidv4()

    const authorisationErr = {
      error_description: 'AADB2C90118: The user has forgotten their password.\n' +
      'Correlation ID: b894fb27-5da9-4906-973d-0ebd8e4237c6\n' +
      'Timestamp: 2018-03-23 17:25:05Z\n' +
      'login_hint: cheese@biscuits.com\n'
    }

    const dummyH = {
      redirect: resetPasswordOutboundUrl => resetPasswordOutboundUrl
    }

    await idmInternals.routes.handleAuthorisationError(null, dummyH, stateUid, {
      policyName: 'testPolicyName'
    }, authorisationErr)

    const [savedStateErr, savedState] = await to(idmCache.get(stateUid))

    if (savedStateErr) {
      console.error(savedStateErr)
    }

    const tokenSet = {
      'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.eyJleHAiOjE1MjE4MjQ5NjUsIm5iZiI6MTUyMTgyMTM2NSwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL2NiMDk2NzVhLWFmMjEtNGRkZS05Y2Y4LWY2MzIzNWEyMTlhMC92Mi4wLyIsInN1YiI6IjZlODdjNmU1LTljMDktNDdlMC1hMWNmLTkyYTYxZDI2MTI1ZiIsImF1ZCI6IjQ5NDg5MzViLTYxMzctNGVlOC04NmEzLTJkMGEyZTMxNDQyYiIsImlhdCI6MTUyMTgyMTM2NSwiYXV0aF90aW1lIjoxNTIxODIxMzY1LCJvaWQiOiI2ZTg3YzZlNS05YzA5LTQ3ZTAtYTFjZi05MmE2MWQyNjEyNWYiLCJnaXZlbl9uYW1lIjoiQ2hlc2hpcmUiLCJmYW1pbHlfbmFtZSI6IkNoZXNoaXJlIiwiZW1haWxzIjpbImRlZnJhQGlhbWNocmlzY2hlc2hpcmUuY28udWsiXSwidGZwIjoiQjJDXzFfYjJjLXdlYmFwcC1zaWdudXAtc2lnbmluIn0.plRV2ZoPcnXR7rj4zSexyksfoQE9AKBUaTKZTpfTcYmBmqnD159MH6sOoczWNp1mnI6ilwGj5c6Sdd0qlwaGmFOvylgebuDec2mvIbjxZ8kXSwl_GkgTE20sQVstsxhC66CU83fn7siRVLLhOWUmKD73KOFA5tb4lCYndXfbie4o0KFofWDrV-uzRJbr7BXXAyITdUCEs3gw29WTM0neKOUZJnnc930LjqAIbQmr4lvTrtq5qwj9OwE5G_vq0RVblWUuE4iQPobOMyJlUL74l74Nr1XarCqpP3RYerYRXNsRcJhasbQfknfoMrX2rnzj_h5xbSQO9cauAsphmXapfw',
      'token_type': 'Bearer',
      'not_before': 1521821365,
      'id_token_expires_in': 3600,
      'profile_info': 'eyJ2ZXIiOiIxLjAiLCJ0aWQiOiJjYjA5Njc1YS1hZjIxLTRkZGUtOWNmOC1mNjMyMzVhMjE5YTAiLCJzdWIiOm51bGwsIm5hbWUiOm51bGwsInByZWZlcnJlZF91c2VybmFtZSI6bnVsbCwiaWRwIjpudWxsfQ',
      'refresh_token': 'eyJraWQiOiJjcGltY29yZV8wOTI1MjAxNSIsInZlciI6IjEuMCIsInppcCI6IkRlZmxhdGUiLCJzZXIiOiIxLjAifQ..og5tc9dcMCi1x9Sz.T5seCETmDU0m548QJ2rLYW8wEarhlCIL8MkJMVpzUpkDVJ-2FxHcFQghqNMxSi4PwogUqST4jDkeGdiazZw0Y66epXzwhvdmcHafXwUsFWV9tCTUPfsCfLHBWOYpdsOyFIFndMO5IOwodWYQc6W5lcdUsKlI-GDJvXnNUgKUdqKuXWBQsX9kaDCOFS8ze9MRrBgYmTleBsiXLdfOkVlBz5Gi5Mob69oiXjqyAjXY-h9OJDT9yFYbQcGuOBoOQqY5vomjCVLcX6cWy4t_IMlkGbs8GMCG0-yrgvDdIqILZqpa4bIkNiGiDeHasCCDTs1TLJYBbhc7rBa6A3wLdyRrrrDlntKA0g2A0jVCzWcyPvCcen9R0hcGBchCyfUR0yCEu9oHXFSN8v1UW_7mfumX_b8rrQ853nVKyjNlf5SI3UwYApnsE5I7EKFc_yHkM6uHVEfrWBQQX4NLbm3854QPp3gRFzaqr6WYnQWRy5vqHFqCt0k7zh3qCq0gubZw3K7rVZK-VON8Kpd2KLBP1MszaXLNzAdVcNQUVni-FYbxiYrVDvzI9LgFRtRJMtHjQC_6Ln8bY2RHm98FEiy53FQ6yT25OMuTmq3t9YKedpf1hvyRe9NwkrVuRhMK0uI.4D663219YNoPSmqnLBK7Hw',
      'refresh_token_expires_in': 1209600,
      'claims': {
        'exp': 1521824965,
        'nbf': 1521821365,
        'ver': '1.0',
        'iss': 'https://login.microsoftonline.com/cb09675a-af21-4dde-9cf8-f63235a219a0/v2.0/',
        'sub': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'aud': '4948935b-6137-4ee8-86a3-2d0a2e31442b',
        'iat': 1521821365,
        'auth_time': 1521821365,
        'oid': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'given_name': 'Chris',
        'family_name': 'Cheshire',
        'emails': [
          'cheese@biscuits.com'
        ],
        'tfp': idmConfig.resetPasswordPolicy
      }
    }

    const dummyRequest = {
      cookieAuth: {
        set: () => {}
      }
    }

    idmConfig.callbacks.resetPasswordConfirmation = (request, h, originalPolicyOutboundUrl) => originalPolicyOutboundUrl

    const handlerResponse = await idmInternals.routes.handleValidatedToken(dummyRequest, null, stateUid, savedState, tokenSet)

    validatePolicyRedirectUrl(handlerResponse, idmConfig, savedState.policyPrePasswordReset)

    const [cachedStateErr, cachedState] = await to(idmCache.get(stateUid))

    if (cachedStateErr) {
      console.error(cachedStateErr)
    }

    expect(cachedState.policyName).to.equal(savedState.policyPrePasswordReset)
    expect(cachedState.policyPrePasswordReset).to.be.undefined()
  })

  lab.test('Log out', async () => {
    const idmConfig = server.methods.idm.getConfig()
    const idmInternals = server.methods.idm.getInternals()
    const idmCache = server.methods.idm.getCache()

    const tokenSet = {
      'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ilg1ZVhrNHh5b2pORnVtMWtsMll0djhkbE5QNC1jNTdkTzZRR1RWQndhTmsifQ.eyJleHAiOjE1MjE4MjQ5NjUsIm5iZiI6MTUyMTgyMTM2NSwidmVyIjoiMS4wIiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL2NiMDk2NzVhLWFmMjEtNGRkZS05Y2Y4LWY2MzIzNWEyMTlhMC92Mi4wLyIsInN1YiI6IjZlODdjNmU1LTljMDktNDdlMC1hMWNmLTkyYTYxZDI2MTI1ZiIsImF1ZCI6IjQ5NDg5MzViLTYxMzctNGVlOC04NmEzLTJkMGEyZTMxNDQyYiIsImlhdCI6MTUyMTgyMTM2NSwiYXV0aF90aW1lIjoxNTIxODIxMzY1LCJvaWQiOiI2ZTg3YzZlNS05YzA5LTQ3ZTAtYTFjZi05MmE2MWQyNjEyNWYiLCJnaXZlbl9uYW1lIjoiQ2hlc2hpcmUiLCJmYW1pbHlfbmFtZSI6IkNoZXNoaXJlIiwiZW1haWxzIjpbImRlZnJhQGlhbWNocmlzY2hlc2hpcmUuY28udWsiXSwidGZwIjoiQjJDXzFfYjJjLXdlYmFwcC1zaWdudXAtc2lnbmluIn0.plRV2ZoPcnXR7rj4zSexyksfoQE9AKBUaTKZTpfTcYmBmqnD159MH6sOoczWNp1mnI6ilwGj5c6Sdd0qlwaGmFOvylgebuDec2mvIbjxZ8kXSwl_GkgTE20sQVstsxhC66CU83fn7siRVLLhOWUmKD73KOFA5tb4lCYndXfbie4o0KFofWDrV-uzRJbr7BXXAyITdUCEs3gw29WTM0neKOUZJnnc930LjqAIbQmr4lvTrtq5qwj9OwE5G_vq0RVblWUuE4iQPobOMyJlUL74l74Nr1XarCqpP3RYerYRXNsRcJhasbQfknfoMrX2rnzj_h5xbSQO9cauAsphmXapfw',
      'token_type': 'Bearer',
      'not_before': 1521821365,
      'id_token_expires_in': 3600,
      'profile_info': 'eyJ2ZXIiOiIxLjAiLCJ0aWQiOiJjYjA5Njc1YS1hZjIxLTRkZGUtOWNmOC1mNjMyMzVhMjE5YTAiLCJzdWIiOm51bGwsIm5hbWUiOm51bGwsInByZWZlcnJlZF91c2VybmFtZSI6bnVsbCwiaWRwIjpudWxsfQ',
      'refresh_token': 'eyJraWQiOiJjcGltY29yZV8wOTI1MjAxNSIsInZlciI6IjEuMCIsInppcCI6IkRlZmxhdGUiLCJzZXIiOiIxLjAifQ..og5tc9dcMCi1x9Sz.T5seCETmDU0m548QJ2rLYW8wEarhlCIL8MkJMVpzUpkDVJ-2FxHcFQghqNMxSi4PwogUqST4jDkeGdiazZw0Y66epXzwhvdmcHafXwUsFWV9tCTUPfsCfLHBWOYpdsOyFIFndMO5IOwodWYQc6W5lcdUsKlI-GDJvXnNUgKUdqKuXWBQsX9kaDCOFS8ze9MRrBgYmTleBsiXLdfOkVlBz5Gi5Mob69oiXjqyAjXY-h9OJDT9yFYbQcGuOBoOQqY5vomjCVLcX6cWy4t_IMlkGbs8GMCG0-yrgvDdIqILZqpa4bIkNiGiDeHasCCDTs1TLJYBbhc7rBa6A3wLdyRrrrDlntKA0g2A0jVCzWcyPvCcen9R0hcGBchCyfUR0yCEu9oHXFSN8v1UW_7mfumX_b8rrQ853nVKyjNlf5SI3UwYApnsE5I7EKFc_yHkM6uHVEfrWBQQX4NLbm3854QPp3gRFzaqr6WYnQWRy5vqHFqCt0k7zh3qCq0gubZw3K7rVZK-VON8Kpd2KLBP1MszaXLNzAdVcNQUVni-FYbxiYrVDvzI9LgFRtRJMtHjQC_6Ln8bY2RHm98FEiy53FQ6yT25OMuTmq3t9YKedpf1hvyRe9NwkrVuRhMK0uI.4D663219YNoPSmqnLBK7Hw',
      'refresh_token_expires_in': 1209600,
      'claims': {
        'exp': 1521824965,
        'nbf': 1521821365,
        'ver': '1.0',
        'iss': 'https://login.microsoftonline.com/cb09675a-af21-4dde-9cf8-f63235a219a0/v2.0/',
        'sub': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'aud': '4948935b-6137-4ee8-86a3-2d0a2e31442b',
        'iat': 1521821365,
        'auth_time': 1521821365,
        'oid': '6e87c6e5-9c09-47e0-a1cf-92a61d26125f',
        'given_name': 'Chris',
        'family_name': 'Cheshire',
        'emails': [
          'cheese@biscuits.com'
        ],
        'tfp': 'B2C_1_b2c-webapp-signup-signin'
      }
    }

    const dummyRequest = {
      cookieAuth: {
        set: () => {}
      }
    }

    const stateUid = uuidv4()

    idmConfig.callbacks.preReturnUriRedirect = (request, h, tokenSet, backToPath) => true

    await idmInternals.routes.handleValidatedToken(dummyRequest, null, stateUid, {}, tokenSet)

    /** Now that we should be logged in, check for presence of cache entry before and after we log out **/
    const [preLogoutCachedDataErr, preLogoutCachedData] = await to(idmCache.get(tokenSet.claims.sub))

    if (preLogoutCachedDataErr) {
      console.error(preLogoutCachedDataErr)
    }

    expect(preLogoutCachedData.claims.sub).to.equal(tokenSet.claims.sub)

    try {
      await server.methods.idm.logout({
        state: {
          [idmConfig.cookieName]: {
            sub: preLogoutCachedData.claims.sub
          }
        }
      })
    } catch (e) {
      // Error will be thrown, because the removal of the cookie will fail
      // console.error(e)
    }

    const [postLogoutCachedDataErr, postLogoutCachedData] = await to(idmCache.get(tokenSet.claims.sub))

    if (postLogoutCachedDataErr) {
      console.error(postLogoutCachedDataErr)
    }

    expect(postLogoutCachedData).to.be.null()
  })
})
