'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var InsufficientScopeError = require('../errors/insufficient-scope-error');
var InvalidTokenError = require('../errors/invalid-token-error');
var ExpiredTokenError = require('../errors/expired-token-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var Request = require('../request');
var Response = require('../response');
var ServerError = require('../errors/server-error');
var UnauthorizedRequestError = require('../errors/unauthorized-request-error');

/**
 * Constructor.
 */

function AuthenticateHandler(options) {
  options = options || {};

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getAccessToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAccessToken()`');
  }

  if (options.scope && undefined === options.addAcceptedScopesHeader) {
    throw new InvalidArgumentError('Missing parameter: `addAcceptedScopesHeader`');
  }

  if (options.scope && undefined === options.addAuthorizedScopesHeader) {
    throw new InvalidArgumentError('Missing parameter: `addAuthorizedScopesHeader`');
  }

  if (options.scope && !options.model.verifyScope) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `verifyScope()`');
  }

  // API Key options
  this.allowApiKeyInHeader = options.allowApiKeyInHeader || false;
  this.allowApiKeyInQuery = options.allowApiKeyInQuery || false;
  this.allowApiKeyInCookie = options.allowApiKeyInCookie || false;

  // Validate API Key model method
  var apiKeyEnabled = this.allowApiKeyInHeader || this.allowApiKeyInQuery || this.allowApiKeyInCookie;
  if (apiKeyEnabled && !options.model.getAccessTokenFromApiKey) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAccessTokenFromApiKey()`');
  }

  // Basic Auth option
  this.allowBasicAuthentication = options.allowBasicAuthentication || false;

  // Validate Basic Auth model method
  if (this.allowBasicAuthentication && !options.model.getAccessTokenFromBasicAuth) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAccessTokenFromBasicAuth()`');
  }

  this.addAcceptedScopesHeader = options.addAcceptedScopesHeader;
  this.addAuthorizedScopesHeader = options.addAuthorizedScopesHeader;
  this.allowBearerTokensInQueryString = options.allowBearerTokensInQueryString;
  this.model = options.model;
  this.scope = options.scope;
}

/**
 * Authenticate Handler.
 */

AuthenticateHandler.prototype.handle = function(request, response) {
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  var self = this;

  return Promise.bind(this)
    .then(function() {
      return this.getTokenFromRequest(request);
    })
    .then(function(tokenInfo) {
      // Route to appropriate handler based on type
      switch (tokenInfo.type) {
        case 'apiKey':
          return this.getAccessTokenFromApiKey(tokenInfo.value);
        case 'basic':
          return this.getAccessTokenFromBasicAuth(tokenInfo.username, tokenInfo.password);
        case 'bearer':
        default:
          return this.getAccessToken(tokenInfo.value);
      }
    })
    .tap(function(token) {
      return this.validateAccessToken(token);
    })
    .tap(function(token) {
      if (!this.scope) {
        return;
      }

      return this.verifyScope(token);
    })
    .tap(function(token) {
      return this.updateResponse(response, token);
    })
    .catch(function(e) {
      // Include the "WWW-Authenticate" response header field if the client
      // lacks any authentication information.
      //
      // @see https://tools.ietf.org/html/rfc6750#section-3.1
      if (e instanceof UnauthorizedRequestError) {
        var challenges = ['Bearer realm="Service"'];
        if (self.allowBasicAuthentication) {
          challenges.push('Basic realm="Service"');
        }
        response.set('WWW-Authenticate', challenges.join(', '));
      }

      if (!(e instanceof OAuthError)) {
        throw new ServerError(e);
      }

      throw e;
    });
};

/**
 * Get the token from the header or body, depending on the request.
 *
 * "Clients MUST NOT use more than one method to transmit the token in each request."
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2
 */

AuthenticateHandler.prototype.getTokenFromRequest = function(request) {
  var headerToken = request.get('Authorization');
  var queryToken = request.query.access_token;
  var bodyToken = request.body.access_token;

  // API Key detection
  var apiKeyHeader = this.allowApiKeyInHeader && request.get(this.allowApiKeyInHeader);
  var apiKeyQuery = this.allowApiKeyInQuery && request.query[this.allowApiKeyInQuery];
  var apiKeyCookie = this.allowApiKeyInCookie && this.getCookie(request, this.allowApiKeyInCookie);

  // Count authentication methods used
  var methods = [
    headerToken,
    queryToken,
    bodyToken,
    apiKeyHeader,
    apiKeyQuery,
    apiKeyCookie
  ].filter(Boolean).length;

  if (methods > 1) {
    throw new InvalidRequestError('Invalid request: only one authentication method is allowed');
  }

  // API Key (header)
  if (apiKeyHeader) {
    return { type: 'apiKey', value: apiKeyHeader };
  }

  // API Key (query)
  if (apiKeyQuery) {
    return { type: 'apiKey', value: apiKeyQuery };
  }

  // API Key (cookie)
  if (apiKeyCookie) {
    return { type: 'apiKey', value: apiKeyCookie };
  }

  // Authorization header (Bearer or Basic)
  if (headerToken) {
    return this.getTokenFromRequestHeader(request);
  }

  // Query string (access_token)
  if (queryToken) {
    return this.getTokenFromRequestQuery(request);
  }

  // Body (access_token)
  if (bodyToken) {
    return this.getTokenFromRequestBody(request);
  }

  throw new UnauthorizedRequestError('Unauthorized request: no authentication given');
};

/**
 * Get the token from the request header.
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.1
 */

AuthenticateHandler.prototype.getTokenFromRequestHeader = function(request) {
  var token = request.get('Authorization');

  // Check for Basic authentication
  if (this.allowBasicAuthentication) {
    var basicMatches = token.match(/^Basic\s+(\S+)$/i);
    if (basicMatches) {
      return this.parseBasicAuth(basicMatches[1]);
    }
  }

  // Check for Bearer token
  var bearerMatches = token.match(/^Bearer\s+(\S+)$/i);
  if (bearerMatches) {
    return { type: 'bearer', value: bearerMatches[1] };
  }

  throw new InvalidRequestError('Invalid request: malformed authorization header');
};

/**
 * Get the token from the request query.
 *
 * "Don't pass bearer tokens in page URLs:  Bearer tokens SHOULD NOT be passed in page
 * URLs (for example, as query string parameters). Instead, bearer tokens SHOULD be
 * passed in HTTP message headers or message bodies for which confidentiality measures
 * are taken. Browsers, web servers, and other software may not adequately secure URLs
 * in the browser history, web server logs, and other data structures. If bearer tokens
 * are passed in page URLs, attackers might be able to steal them from the history data,
 * logs, or other unsecured locations."
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.3
 */

AuthenticateHandler.prototype.getTokenFromRequestQuery = function(request) {
  if (!this.allowBearerTokensInQueryString) {
    throw new InvalidRequestError('Invalid request: do not send bearer tokens in query URLs');
  }

  return { type: 'bearer', value: request.query.access_token };
};

/**
 * Get the token from the request body.
 *
 * "The HTTP request method is one for which the request-body has defined semantics.
 * In particular, this means that the "GET" method MUST NOT be used."
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.2
 */

AuthenticateHandler.prototype.getTokenFromRequestBody = function(request) {
  if (request.method === 'GET') {
    throw new InvalidRequestError('Invalid request: token may not be passed in the body when using the GET verb');
  }

  if (!request.is('application/x-www-form-urlencoded')) {
    throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
  }

  return { type: 'bearer', value: request.body.access_token };
};

/**
 * Parse Basic authentication credentials.
 */

AuthenticateHandler.prototype.parseBasicAuth = function(encoded) {
  var decoded;
  try {
    decoded = Buffer.from(encoded, 'base64').toString('utf8');
  } catch (e) {
    throw new InvalidRequestError('Invalid request: malformed basic authentication');
  }

  var colonIndex = decoded.indexOf(':');
  if (colonIndex === -1) {
    throw new InvalidRequestError('Invalid request: malformed basic authentication');
  }

  return {
    type: 'basic',
    username: decoded.substring(0, colonIndex),
    password: decoded.substring(colonIndex + 1)
  };
};

/**
 * Get cookie value from request.
 */

AuthenticateHandler.prototype.getCookie = function(request, name) {
  var cookies = request.get('cookie');
  if (!cookies) {
    return null;
  }

  var match = cookies.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? match[1] : null;
};

/**
 * Get the access token from the model.
 */

AuthenticateHandler.prototype.getAccessToken = function(token) {
  return promisify(this.model.getAccessToken, 1).call(this.model, token)
    .then(function(accessToken) {
      if (!accessToken) {
        throw new InvalidTokenError('Invalid token: access token is invalid');
      }

      if (!accessToken.user) {
        throw new ServerError('Server error: `getAccessToken()` did not return a `user` object');
      }

      return accessToken;
    });
};

/**
 * Get access token from API key.
 */

AuthenticateHandler.prototype.getAccessTokenFromApiKey = function(apiKey) {
  return promisify(this.model.getAccessTokenFromApiKey, 1).call(this.model, apiKey)
    .then(function(accessToken) {
      if (!accessToken) {
        throw new InvalidTokenError('Invalid token: API key is invalid');
      }

      if (!accessToken.user) {
        throw new ServerError('Server error: `getAccessTokenFromApiKey()` did not return a `user` object');
      }

      return accessToken;
    });
};

/**
 * Get access token from Basic authentication credentials.
 */

AuthenticateHandler.prototype.getAccessTokenFromBasicAuth = function(username, password) {
  return promisify(this.model.getAccessTokenFromBasicAuth, 2).call(this.model, username, password)
    .then(function(accessToken) {
      if (!accessToken) {
        throw new InvalidTokenError('Invalid token: invalid credentials');
      }

      if (!accessToken.user) {
        throw new ServerError('Server error: `getAccessTokenFromBasicAuth()` did not return a `user` object');
      }

      return accessToken;
    });
};

/**
 * Validate access token.
 */

AuthenticateHandler.prototype.validateAccessToken = function(accessToken) {
  if (!(accessToken.accessTokenExpiresAt instanceof Date)) {
    throw new ServerError('Server error: `accessTokenExpiresAt` must be a Date instance');
  }

  if (accessToken.accessTokenExpiresAt < new Date()) {
    throw new ExpiredTokenError('Invalid token: access token has expired');
  }

  return accessToken;
};

/**
 * Verify scope.
 */

AuthenticateHandler.prototype.verifyScope = function(accessToken) {
  return promisify(this.model.verifyScope, 2).call(this.model, accessToken, this.scope)
    .then(function(scope) {
      if (!scope) {
        throw new InsufficientScopeError('Insufficient scope: authorized scope is insufficient');
      }

      return scope;
    });
};

/**
 * Update response.
 */

AuthenticateHandler.prototype.updateResponse = function(response, accessToken) {
  if (this.scope && this.addAcceptedScopesHeader) {
    response.set('X-Accepted-OAuth-Scopes', this.scope);
  }

  if (this.scope && this.addAuthorizedScopesHeader) {
    response.set('X-OAuth-Scopes', accessToken.scope);
  }
};

/**
 * Export constructor.
 */

module.exports = AuthenticateHandler;
