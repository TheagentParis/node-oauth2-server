
# oauth2-server

[![npm Version][npm-image]][npm-url]
[![npm Downloads][downloads-image]][downloads-url]
[![Test Status][travis-image]][travis-url]
[![MIT Licensed][license-image]][license-url]
[![oauthjs Slack][slack-image]][slack-url]

Complete, compliant and well tested module for implementing an OAuth2 server in [Node.js](https://nodejs.org).

Note: After a period of hiatus, this project is now back under active maintenance. Dependencies have been updated and bug fixes will land in v3 (current master). v4 will be _mostly backwards compatible_ with no code changes required for users using a supported node release. More details in [#621](https://github.com/oauthjs/node-oauth2-server/issues/621).

## Installation

```bash
npm install oauth2-server
```

The *oauth2-server* module is framework-agnostic but there are several officially supported wrappers available for popular HTTP server frameworks such as [Express](https://npmjs.org/package/express-oauth-server) and [Koa](https://npmjs.org/package/koa-oauth-server). If you're using one of those frameworks it is strongly recommended to use the respective wrapper module instead of rolling your own.


## Features

- Supports `authorization_code`, `client_credentials`, `refresh_token` and `password` grant, as well as *extension grants*, with scopes.
- Can be used with *promises*, *Node-style callbacks*, *ES6 generators* and *async*/*await* (using [Babel](https://babeljs.io)).
- Fully [RFC 6749](https://tools.ietf.org/html/rfc6749.html) and [RFC 6750](https://tools.ietf.org/html/rfc6750.html) compliant.
- Implicitly supports any form of storage, e.g. *PostgreSQL*, *MySQL*, *MongoDB*, *Redis*, etc.
- Complete [test suite](https://github.com/oauthjs/node-oauth2-server/tree/master/test).
- **API Key and Basic Authentication** support for direct authentication without Bearer tokens.


## API Key & Basic Authentication

In addition to standard OAuth2 Bearer token authentication, this module supports **API Key** and **Basic Authentication** for direct resource access without requiring a token exchange flow.

### API Key Authentication

Authenticate requests using an API key sent via header, query parameter, or cookie.

**Configuration:**

```javascript
var OAuth2Server = require('oauth2-server');

var oauth = new OAuth2Server({
  model: model,
  // Enable API Key in header (recommended)
  allowApiKeyInHeader: 'X-API-Key',
  // Or in query string (less secure - logged in URLs)
  allowApiKeyInQuery: 'api_key',
  // Or in cookie
  allowApiKeyInCookie: 'api_key'
});
```

**Required Model Method:**

```javascript
model.getAccessTokenFromApiKey = async function(apiKey) {
  const record = await db.apiKeys.findOne({ key: apiKey, active: true });
  if (!record) return null;

  return {
    accessToken: apiKey,
    accessTokenExpiresAt: record.expiresAt || new Date('2099-12-31'),
    scope: record.scope,
    client: record.client,
    user: record.user  // REQUIRED
  };
};
```

**Usage:**

```bash
# Header (recommended)
curl -X GET http://localhost/api/resource \
  -H "X-API-Key: ak_live_abc123"

# Query string
curl -X GET "http://localhost/api/resource?api_key=ak_live_abc123"
```

### Basic Authentication

Authenticate requests using HTTP Basic Authentication (username:password).

**Configuration:**

```javascript
var oauth = new OAuth2Server({
  model: model,
  allowBasicAuthentication: true
});
```

**Required Model Method:**

```javascript
model.getAccessTokenFromBasicAuth = async function(username, password) {
  const user = await db.users.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return null;
  }

  return {
    accessToken: `basic-session-${user.id}`,
    accessTokenExpiresAt: new Date(Date.now() + 3600000), // 1 hour
    scope: user.defaultScope,
    client: { id: 'basic-auth-client' },
    user: user  // REQUIRED
  };
};
```

**Usage:**

```bash
# Base64 encode credentials: echo -n "username:password" | base64
curl -X GET http://localhost/api/resource \
  -H "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
```

### Combined Authentication

You can enable multiple authentication methods simultaneously. Bearer tokens always work alongside these methods.

```javascript
var oauth = new OAuth2Server({
  model: model,
  allowApiKeyInHeader: 'X-API-Key',
  allowBasicAuthentication: true
});

// Authenticate endpoint - accepts Bearer, API Key, or Basic
app.use('/api', function(req, res, next) {
  oauth.authenticate(new Request(req), new Response(res))
    .then(function(token) {
      req.user = token.user;
      next();
    })
    .catch(function(err) {
      res.status(err.code || 500).json({ error: err.message });
    });
});
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowApiKeyInHeader` | `string\|false` | `false` | Header name for API key (e.g., `'X-API-Key'`) |
| `allowApiKeyInQuery` | `string\|false` | `false` | Query parameter name for API key |
| `allowApiKeyInCookie` | `string\|false` | `false` | Cookie name for API key |
| `allowBasicAuthentication` | `boolean` | `false` | Enable HTTP Basic Authentication |

### Security Considerations

1. **API Keys should be treated like passwords** - store hashed when possible
2. **Basic Auth credentials are only base64 encoded, not encrypted** - always use HTTPS
3. **API Keys in query strings are logged by web servers** - prefer headers
4. **Implement rate limiting** at the application level
5. **Scope verification** works the same for all authentication methods


## Documentation

[Documentation](https://oauth2-server.readthedocs.io) is hosted on Read the Docs.


## Examples

Most users should refer to our [Express](https://github.com/oauthjs/express-oauth-server/tree/master/examples) or [Koa](https://github.com/oauthjs/koa-oauth-server/tree/master/examples) examples.

More examples can be found here: https://github.com/14gasher/oauth-example

## Upgrading from 2.x

This module has been rewritten using a promise-based approach, introducing changes to the API and model specification. v2.x is no longer supported.

Please refer to our [3.0 migration guide](https://oauth2-server.readthedocs.io/en/latest/misc/migrating-v2-to-v3.html) for more information.


## Tests

To run the test suite, install dependencies, then run `npm test`:

```bash
npm install
npm test
```


[npm-image]: https://img.shields.io/npm/v/oauth2-server.svg
[npm-url]: https://npmjs.org/package/oauth2-server
[downloads-image]: https://img.shields.io/npm/dm/oauth2-server.svg
[downloads-url]: https://npmjs.org/package/oauth2-server
[travis-image]: https://img.shields.io/travis/oauthjs/node-oauth2-server/master.svg
[travis-url]: https://travis-ci.org/oauthjs/node-oauth2-server
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[license-url]: https://raw.githubusercontent.com/oauthjs/node-oauth2-server/master/LICENSE
[slack-image]: https://slack.oauthjs.org/badge.svg
[slack-url]: https://slack.oauthjs.org

