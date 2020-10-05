# Defra.Identity hapi plugin

**Note:** This plugin is designed for use with Hapi v17

The Defra.Identity hapi plugin (DIHP) is designed to streamline and standardise the way Defra services interact with an OpenID Connect (OIDC) Identity Provider (IdP).

You can read more about OpenID Connect [here](https://connect2id.com/learn/openid-connect).

At present, the role of IdP is fulfilled by [Microsoft B2C](https://azure.microsoft.com/en-gb/services/active-directory-b2c/).  

# Before you start

Before you use DIHP, there are a few things you will need. If you do not have the following items, please contact X to begin the onboarding process.

- B2C Tenant ID
- Client ID
- Client Secret
- The names of your policies
    - You will need, as a minimum:
        - A signup/signin policy
        - A password reset policy

# Quick start
Generic docs about how to implement hapi auth plugins can be found [here](https://hapijs.com/tutorials/auth).

The full set of configuration options, along with their defaults, can be found in [lib/configDefaults.js](blob/lib/configDefaults.js)

Example implementation with required config values:

```
const {
      IDENTITY_TENANTNAME,
      IDENTITY_TENANTID,
      IDENTITY_COOKIEPASSWORD,
      IDENTITY_CLIENTID,
      IDENTITY_CLIENTSECRET,
      HOST,
      PORT
  } = process.env

await server.register({
    plugin: require('defra-identity-hapi-plugin'),
    options: {
      tenantName: IDENTITY_TENANTNAME,
      tenantId: IDENTITY_TENANTID,
      cookiePassword: IDENTITY_COOKIEPASSWORD,
      appDomain: `http://${HOST}:${PORT}`,
      clientId: IDENTITY_CLIENTID,
      clientSecret: IDENTITY_CLIENTSECRET,
      resetPasswordPolicy: 'b2c_1_resetpassword,
      disallowedRedirectPath: '/error,
      isSecure: false, // Set this if without https - i.e. localhost
    }
  })
```

## Auth by default
By default, the `onByDefault` option is false. So in the example above, to secure a route with DIHP, you will need to enable auth for that specific route.

For example: 

```
server.route({
    method: 'GET',
    path: '/',
    options: {
      auth: 'idm'
    },
    handler: async function (request, h) {
      return 'Hello world'
    }
})
```

You can enable auth for every route by passing `onByDefault` as true. If you do this, you will need to specify which routes you **don't** want auth enabled on.

For example:

```
server.route({
    method: 'GET',
    path: '/',
    options: {
      auth: false
    },
    handler: async function (request, h) {
      return 'Hello world'
    }
})
```

## Cache
By default, DIHP uses an in memory cache. This is useful for getting an implementation up and running quickly in development. In production you can pass a `cache` object to the config. This can be any type of cache implementation, as long as the object you pass in adheres to the following api:
```
{
 get: async (key) => {},
 set: async (key, value, ttl) => {}
 drop: async (key) => {}
}
```

This is the same interface as the built in hapi cache. An example implementation can be found in [`demo/server.js`](blob/demo/server.js).

## Cookie
DIHP uses [hapi-auth-cookie](https://github.com/hapijs/hapi-auth-cookie) to manage its cookies. DIHP will use this to store an encrypted reference to the users claims, stored in the plugin's cache.

This reference does not include any user information, at no point does the plugin expose any user information to the client's browser.

You can specify the name of the cookie set on the user's browser by passing in `cookieName`. 

You must also pass in `cookiePassword`. It is a required field, that must be 32 characters long. This password is used to encrypt the data in the cookie.  

## Routes

The following routes are exposed by the plugin. All route paths are customisable when instantiating the plugin

1. Outbound path - default: /login/out
    - Calls `server.methods.idm.generateFinalOutboundRedirectUrl` with parameters contained within the url and and redirects the user to the url returned
2. Return uri - default: /login/return
    - Handles the user upon return from an authentication request
3. Log out - default: /logout
    - Logs the user out and redirects them to a specified path 

## Refreshing token
At present, the plugin exposes functionality to refresh the user's token, but it does not do it automatically. It is up to the service to decide when to check the validity of the claims and execute the refresh function

For example:

```
server.route({
    method: 'GET',
    path: '/',
    handler: async function (request, h) {
      const creds = await server.methods.idm.getCredentials(request)
    
      if (creds && creds.isExpired()) {
        await server.methods.idm.refreshToken(request, creds.tokenSet.refresh_token)
      }
    
      return 'Hello world'
    }
})
```

## Generating urls
DIHP uses OIDC's 'state' capability to be able to match up users it has sent to the IdP. This means that just before the user is sent to the IdP, a guid is generated, which is sent to the IdP, and stored locally in the cache. When the user returns from the IdP, the state is returned with them. The state returned is matched with the entry in the cache to retrieve some persisted journey data.

This persisted journey data includes:
- The policy the user was sent to
- Whether they have been through a reset password journey
- Where they should be sent to after authentication

It is important to send the user to B2C via the Outbound path exposed by DIHP. It is here the cache is populated with the above information.
You can generate an outbound url by executing the `idm.generateAuthenticationUrl` server method detailed in [server methods](#server-methods).

For example:

```
<a href="<%= idm.generateAuthenticationUrl('/account', {forceLogin: false}) %>">Click here to log in</a>
```

## Server methods

The following server methods will be created by the plugin, for consumption inside or outside of the plugin:

1. idm.getCredentials
    - Returns the user's session credentials - i.e. refresh token, expiry times of credentials
2. idm.getClaims
    - Returns the user's claims
    - Return object includes function attached to check whether the claims have expired. See [refresh token](#refresh-token)
3. idm.generateAuthenticationUrl
    - Returns a url to the plugin's outboundPath
    - Accepts parameters to specify
        - Whether the user should be forced to log in (As opposed to B2C checking to see if they are already logged in and sending them straight through the process)
        - The url path that the user should be redirected to after authentication
        - The policy name (Defaults to the default policy passed into the plugin on instantiation)
4. idm.logout
    - Logs the user out
    - Clears their cookie and cache record
5. idm.refreshToken
    - Refreshes the JWT
6. idm.generateFinalOutboundRedirectUrl
    - Saves the user guid state in cache
    - Returns the url to send a user straight to B2C (this is the function used by the outbound path route handler)
    
The server method source, with jsdocs can be found in [lib/methods.js](blob/lib/methods.js)

## Contributing to this project
If you have an idea you'd like to contribute please log an issue.

All contributions should be submitted via a pull request.

Please note that the codebase conforms to the [Jaavascript Standard Style](https://standardjs.com/).

Please make sure to run `npm run test` before opening any pull requests.

## License

THIS INFORMATION IS LICENSED UNDER THE CONDITIONS OF THE OPEN GOVERNMENT LICENCE found at:

<http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3>

The following attribution statement MUST be cited in your products and applications when using this information.

>Contains public sector information licensed under the Open Government license v3

### About the license

The Open Government Licence (OGL) was developed by the Controller of Her Majesty's Stationery Office (HMSO) to enable information providers in the public sector to license the use and re-use of their information under a common open licence.

It is designed to encourage use and re-use of information freely and flexibly, with only a few conditions.
