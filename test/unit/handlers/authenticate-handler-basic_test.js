'use strict';

/**
 * Module dependencies.
 */

var AuthenticateHandler = require('../../../lib/handlers/authenticate-handler');
var InvalidArgumentError = require('../../../lib/errors/invalid-argument-error');
var InvalidTokenError = require('../../../lib/errors/invalid-token-error');
var InvalidRequestError = require('../../../lib/errors/invalid-request-error');
var Request = require('../../../lib/request');
var ServerError = require('../../../lib/errors/server-error');
var sinon = require('sinon');
var should = require('should');

/**
 * Test `AuthenticateHandler` Basic authentication.
 */

describe('AuthenticateHandler - Basic Auth', function() {
  describe('constructor()', function() {
    it('should throw when Basic Auth enabled without `getAccessTokenFromBasicAuth` model method', function() {
      try {
        new AuthenticateHandler({
          model: { getAccessToken: function() {} },
          allowBasicAuthentication: true
        });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getAccessTokenFromBasicAuth()`');
      }
    });

    it('should not throw when Basic Auth enabled with `getAccessTokenFromBasicAuth` model method', function() {
      var handler = new AuthenticateHandler({
        model: {
          getAccessToken: function() {},
          getAccessTokenFromBasicAuth: function() {}
        },
        allowBasicAuthentication: true
      });

      handler.allowBasicAuthentication.should.equal(true);
    });
  });

  describe('parseBasicAuth()', function() {
    it('should decode valid base64 credentials', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });

      // 'demo:secret' -> base64 = 'ZGVtbzpzZWNyZXQ='
      var result = handler.parseBasicAuth('ZGVtbzpzZWNyZXQ=');

      result.should.eql({
        type: 'basic',
        username: 'demo',
        password: 'secret'
      });
    });

    it('should handle password with colon', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });

      // 'user:pass:word' -> base64 = 'dXNlcjpwYXNzOndvcmQ='
      var result = handler.parseBasicAuth('dXNlcjpwYXNzOndvcmQ=');

      result.should.eql({
        type: 'basic',
        username: 'user',
        password: 'pass:word'
      });
    });

    it('should handle empty password', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });

      // 'user:' -> base64 = 'dXNlcjo='
      var result = handler.parseBasicAuth('dXNlcjo=');

      result.should.eql({
        type: 'basic',
        username: 'user',
        password: ''
      });
    });

    it('should throw on missing colon separator', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });

      try {
        // 'invalidcreds' -> base64 = 'aW52YWxpZGNyZWRz'
        handler.parseBasicAuth('aW52YWxpZGNyZWRz');
        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid request: malformed basic authentication');
      }
    });
  });

  describe('getTokenFromRequestHeader()', function() {
    it('should detect Basic auth when enabled', function() {
      var handler = new AuthenticateHandler({
        model: {
          getAccessToken: function() {},
          getAccessTokenFromBasicAuth: function() {}
        },
        allowBasicAuthentication: true
      });
      var request = new Request({
        body: {},
        headers: { 'Authorization': 'Basic ZGVtbzpzZWNyZXQ=' },
        method: 'GET',
        query: {}
      });

      var result = handler.getTokenFromRequestHeader(request);

      result.should.eql({
        type: 'basic',
        username: 'demo',
        password: 'secret'
      });
    });

    it('should still detect Bearer token when Basic auth is enabled', function() {
      var handler = new AuthenticateHandler({
        model: {
          getAccessToken: function() {},
          getAccessTokenFromBasicAuth: function() {}
        },
        allowBasicAuthentication: true
      });
      var request = new Request({
        body: {},
        headers: { 'Authorization': 'Bearer token123' },
        method: 'GET',
        query: {}
      });

      var result = handler.getTokenFromRequestHeader(request);

      result.should.eql({ type: 'bearer', value: 'token123' });
    });

    it('should throw when Basic auth header provided but Basic auth not enabled', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} },
        allowBasicAuthentication: false
      });
      var request = new Request({
        body: {},
        headers: { 'Authorization': 'Basic ZGVtbzpzZWNyZXQ=' },
        method: 'GET',
        query: {}
      });

      try {
        handler.getTokenFromRequestHeader(request);
        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidRequestError);
        e.message.should.equal('Invalid request: malformed authorization header');
      }
    });

    it('should be case-insensitive for Basic keyword', function() {
      var handler = new AuthenticateHandler({
        model: {
          getAccessToken: function() {},
          getAccessTokenFromBasicAuth: function() {}
        },
        allowBasicAuthentication: true
      });
      var request = new Request({
        body: {},
        headers: { 'Authorization': 'basic ZGVtbzpzZWNyZXQ=' },
        method: 'GET',
        query: {}
      });

      var result = handler.getTokenFromRequestHeader(request);

      result.should.eql({
        type: 'basic',
        username: 'demo',
        password: 'secret'
      });
    });

    it('should be case-insensitive for Bearer keyword', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });
      var request = new Request({
        body: {},
        headers: { 'Authorization': 'bearer token123' },
        method: 'GET',
        query: {}
      });

      var result = handler.getTokenFromRequestHeader(request);

      result.should.eql({ type: 'bearer', value: 'token123' });
    });
  });

  describe('getAccessTokenFromBasicAuth()', function() {
    it('should call `model.getAccessTokenFromBasicAuth()`', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromBasicAuth: sinon.stub().returns({ user: {} })
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowBasicAuthentication: true
      });

      return handler.getAccessTokenFromBasicAuth('demo', 'secret')
        .then(function() {
          model.getAccessTokenFromBasicAuth.callCount.should.equal(1);
          model.getAccessTokenFromBasicAuth.firstCall.args.should.have.length(2);
          model.getAccessTokenFromBasicAuth.firstCall.args[0].should.equal('demo');
          model.getAccessTokenFromBasicAuth.firstCall.args[1].should.equal('secret');
          model.getAccessTokenFromBasicAuth.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });

    it('should throw `InvalidTokenError` when model returns null', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromBasicAuth: sinon.stub().returns(null)
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowBasicAuthentication: true
      });

      return handler.getAccessTokenFromBasicAuth('demo', 'wrongpassword')
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidTokenError);
          e.message.should.equal('Invalid token: invalid credentials');
        });
    });

    it('should throw `ServerError` when model returns no user', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromBasicAuth: sinon.stub().returns({ accessToken: 'token' })
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowBasicAuthentication: true
      });

      return handler.getAccessTokenFromBasicAuth('demo', 'secret')
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal('Server error: `getAccessTokenFromBasicAuth()` did not return a `user` object');
        });
    });
  });
});
