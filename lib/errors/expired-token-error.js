'use strict';

/**
 * Module dependencies.
 */

var _ = require('lodash');
var OAuthError = require('./oauth-error');
var util = require('util');

/**
 * Constructor.
 *
 * "The access token provided is expired, revoked, malformed, or invalid for other reasons."
 *
 * @see https://tools.ietf.org/html/rfc6750#section-3.1
 */

function ExpiredTokenError(message, properties) {
  properties = _.assign({
    code: 401,
    name: 'expired_token'
  }, properties);

  OAuthError.call(this, message, properties);
}

/**
 * Inherit prototype.
 */

util.inherits(ExpiredTokenError, OAuthError);

/**
 * Export constructor.
 */

module.exports = ExpiredTokenError;
