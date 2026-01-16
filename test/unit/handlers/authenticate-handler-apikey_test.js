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
 * Test `AuthenticateHandler` API Key authentication.
 */

describe('AuthenticateHandler - API Key', function() {
  describe('constructor()', function() {
    it('should throw when API Key enabled without `getAccessTokenFromApiKey` model method', function() {
      try {
        new AuthenticateHandler({
          model: { getAccessToken: function() {} },
          allowApiKeyInHeader: 'X-API-Key'
        });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getAccessTokenFromApiKey()`');
      }
    });

    it('should not throw when API Key enabled with `getAccessTokenFromApiKey` model method', function() {
      var handler = new AuthenticateHandler({
        model: {
          getAccessToken: function() {},
          getAccessTokenFromApiKey: function() {}
        },
        allowApiKeyInHeader: 'X-API-Key'
      });

      handler.allowApiKeyInHeader.should.equal('X-API-Key');
    });

    it('should throw when API Key query enabled without `getAccessTokenFromApiKey` model method', function() {
      try {
        new AuthenticateHandler({
          model: { getAccessToken: function() {} },
          allowApiKeyInQuery: 'api_key'
        });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getAccessTokenFromApiKey()`');
      }
    });

    it('should throw when API Key cookie enabled without `getAccessTokenFromApiKey` model method', function() {
      try {
        new AuthenticateHandler({
          model: { getAccessToken: function() {} },
          allowApiKeyInCookie: 'api_key'
        });

        should.fail();
      } catch (e) {
        e.should.be.an.instanceOf(InvalidArgumentError);
        e.message.should.equal('Invalid argument: model does not implement `getAccessTokenFromApiKey()`');
      }
    });
  });

  describe('getTokenFromRequest()', function() {
    describe('with API key in header', function() {
      it('should return API key token info', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInHeader: 'X-API-Key'
        });
        var request = new Request({
          body: {},
          headers: { 'X-API-Key': 'ak_live_abc123' },
          method: 'GET',
          query: {}
        });

        var result = handler.getTokenFromRequest(request);

        result.should.eql({ type: 'apiKey', value: 'ak_live_abc123' });
      });

      it('should work with custom header name', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInHeader: 'Api-Key'
        });
        var request = new Request({
          body: {},
          headers: { 'Api-Key': 'ak_test_xyz' },
          method: 'GET',
          query: {}
        });

        var result = handler.getTokenFromRequest(request);

        result.should.eql({ type: 'apiKey', value: 'ak_test_xyz' });
      });
    });

    describe('with API key in query', function() {
      it('should return API key token info', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInQuery: 'api_key'
        });
        var request = new Request({
          body: {},
          headers: {},
          method: 'GET',
          query: { api_key: 'ak_live_query123' }
        });

        var result = handler.getTokenFromRequest(request);

        result.should.eql({ type: 'apiKey', value: 'ak_live_query123' });
      });
    });

    describe('with API key in cookie', function() {
      it('should return API key token info', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInCookie: 'api_key'
        });
        var request = new Request({
          body: {},
          headers: { 'cookie': 'api_key=ak_live_cookie123' },
          method: 'GET',
          query: {}
        });

        var result = handler.getTokenFromRequest(request);

        result.should.eql({ type: 'apiKey', value: 'ak_live_cookie123' });
      });

      it('should extract cookie from multiple cookies', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInCookie: 'api_key'
        });
        var request = new Request({
          body: {},
          headers: { 'cookie': 'session=abc; api_key=ak_live_cookie456; other=xyz' },
          method: 'GET',
          query: {}
        });

        var result = handler.getTokenFromRequest(request);

        result.should.eql({ type: 'apiKey', value: 'ak_live_cookie456' });
      });
    });

    describe('with multiple authentication methods', function() {
      it('should throw when API key and Bearer token both present', function() {
        var handler = new AuthenticateHandler({
          model: {
            getAccessToken: function() {},
            getAccessTokenFromApiKey: function() {}
          },
          allowApiKeyInHeader: 'X-API-Key'
        });
        var request = new Request({
          body: {},
          headers: {
            'X-API-Key': 'ak_live_abc123',
            'Authorization': 'Bearer token123'
          },
          method: 'GET',
          query: {}
        });

        try {
          handler.getTokenFromRequest(request);
          should.fail();
        } catch (e) {
          e.should.be.an.instanceOf(InvalidRequestError);
          e.message.should.equal('Invalid request: only one authentication method is allowed');
        }
      });
    });
  });

  describe('getCookie()', function() {
    it('should return null when no cookies present', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });
      var request = new Request({
        body: {},
        headers: {},
        method: 'GET',
        query: {}
      });

      var result = handler.getCookie(request, 'api_key');

      should.equal(result, null);
    });

    it('should return null when cookie not found', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });
      var request = new Request({
        body: {},
        headers: { 'cookie': 'other=value' },
        method: 'GET',
        query: {}
      });

      var result = handler.getCookie(request, 'api_key');

      should.equal(result, null);
    });

    it('should return cookie value when found', function() {
      var handler = new AuthenticateHandler({
        model: { getAccessToken: function() {} }
      });
      var request = new Request({
        body: {},
        headers: { 'cookie': 'api_key=test123' },
        method: 'GET',
        query: {}
      });

      var result = handler.getCookie(request, 'api_key');

      result.should.equal('test123');
    });
  });

  describe('getAccessTokenFromApiKey()', function() {
    it('should call `model.getAccessTokenFromApiKey()`', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromApiKey: sinon.stub().returns({ user: {} })
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowApiKeyInHeader: 'X-API-Key'
      });

      return handler.getAccessTokenFromApiKey('ak_live_abc123')
        .then(function() {
          model.getAccessTokenFromApiKey.callCount.should.equal(1);
          model.getAccessTokenFromApiKey.firstCall.args.should.have.length(1);
          model.getAccessTokenFromApiKey.firstCall.args[0].should.equal('ak_live_abc123');
          model.getAccessTokenFromApiKey.firstCall.thisValue.should.equal(model);
        })
        .catch(should.fail);
    });

    it('should throw `InvalidTokenError` when model returns null', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromApiKey: sinon.stub().returns(null)
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowApiKeyInHeader: 'X-API-Key'
      });

      return handler.getAccessTokenFromApiKey('invalid_key')
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(InvalidTokenError);
          e.message.should.equal('Invalid token: API key is invalid');
        });
    });

    it('should throw `ServerError` when model returns no user', function() {
      var model = {
        getAccessToken: function() {},
        getAccessTokenFromApiKey: sinon.stub().returns({ accessToken: 'token' })
      };
      var handler = new AuthenticateHandler({
        model: model,
        allowApiKeyInHeader: 'X-API-Key'
      });

      return handler.getAccessTokenFromApiKey('ak_live_abc123')
        .then(should.fail)
        .catch(function(e) {
          e.should.be.an.instanceOf(ServerError);
          e.message.should.equal('Server error: `getAccessTokenFromApiKey()` did not return a `user` object');
        });
    });
  });
});
