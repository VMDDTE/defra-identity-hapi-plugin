module.exports = {
  tenantName: null,
  // B2C tenant guid - must be guid (not tenant domain) in order to match with oidc token issuer
  tenantId: null,
  // Password to encode cookie - should be 32 characters
  cookiePassword: null,
  // Might need to segment cookieName and cacheSegment by app name
  // Name of cookie containing cache record identifier
  cookieName: 'idm',
  cacheSegment: 'idm',
  // Specify caching mechanism
  // Must follow api detailed below
  cache: null,
  // cache: {
  //   get: async (key) => {},
  //   set: async (key, value, ttl) => {}
  //   drop: async (key) => {}
  // }
  // Cache ttl in ms - irrelevant if custom cache is specified above
  cacheCookieTtlMs: 24 * 60 * 60 * 1000,
  // Where to send users who are disallowed
  disallowedRedirectPath: null,
  // Automatically redirect to B2C when disallowed
  loginOnDisallow: false,
  // Is app being served securely - if true, only secure cookies will be set
  isSecure: true,
  // Path of outbound redirect page
  outboundPath: '/login/out',
  // Path of return redirect page
  returnUri: '/login/return',
  // Path of logout page - false if no log out page required
  logoutPath: '/logout',
  // Root domain the service can be found at - used for oidc return uri
  appDomain: null,
  // B2C application id
  clientId: null,
  // B2C application secret
  clientSecret: null,
  // Default B2C policy
  defaultPolicy: null,
  // B2C password policy
  resetPasswordPolicy: null,
  // Turn on authentication requirement for all pages by default
  onByDefault: false,
  // Default path to send users to when they are disallowed
  defaultBackToPath: '/',
  callbacks: {
    /**
     * Function called when user is returned back from IdP - before user is redirected - if a truey value is returned, that will be returned to the client instead of the standard JS redirect
     */
    // preReturnUriRedirect: async (request, h, tokenSet, backToPath) => {},
    /**
     * Function called when reset password is complete - should return view confirming password reset and link to continue - if falsey value is returned then the standard, unstyled page will be returned to the user
     */
    // resetPasswordConfirmation: async (request, h, originalPolicyOutboundUrl) => {}
    /**
     * Function called on uncaught error in routes exposed by plugin - if request & h are passed, the response of this function will be returned to the client
     */
    // onError: async (err, request, h) => {},
  }
}
