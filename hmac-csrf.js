
var uuid = require('uuid');
var crypto = require('crypto');
var URL = require('url');

module.exports = function(options) {
  options = options || {};
  options.keys = options.keys || {}

  var sessionCookie = options.sessionCookie || 'connect.sid'
  var secret = options.secret || uuid.v4();
  var validityDelay = options.validityDelay || 86400*1000/*24h*/;
  var algorithm = options.algorithm || 'sha256';
  var templateResponseAttr = options.templateAttr || 'locals';

  var keys = {
    query : options.keys.query  || '_csrf',
    body  : options.keys.body   || '_csrf',
    header: options.keys.header || 'x-csrf-token'
  };

  return function(req, res, next) {

    if ('HEAD' == req.method || 'OPTIONS' == req.method) {
      return next();
    }

    var sessionId = extractSessionId(sessionCookie, req, res);

    if('GET' == req.method) {
      if(res[templateResponseAttr]) {
        res[templateResponseAttr]._csrf = generateCSRF(secret, algorithm, validityDelay, sessionId);
      }
      return next();
    }

    if(options.origin && req.headers.origin) {
      if(options.origin !== req.headers.origin) {
        res.writeHead(403);
        res.end('CSRF attempt. Origin header mismatch.');
        return;
      }
    }

    if(options.ignore && options.ignore.length > 0) {
      for(var i = 0 ; i < options.ignore.length ; i++) {
        var path = options.ignore[i];
        if((path instanceof RegExp && path.test(req.url)) || req.url === path) {
          return next()
        }
      }
    }

    if(csrfTokenValid(secret, algorithm, validityDelay, sessionId, keys, req)) {
      next();
    } else {
      res.writeHead(403);
      res.end('CSRF attempt. Token.');
    }
  }
}

function csrfTokenValid(secret, algorithm, validityDelay, sessionId, keys, req) {
  var token = extractCSRFToken(keys, req);

  if(!token) {
    console.log('CSRF attempt. Token missing.');
    return false;
  }

  if(!sessionId) {
    console.log('CSRF attempt. Could not resume session.');
    return false;
  }

  var data = /^{(\d+)}(.*)$/.exec(token);
  if(data && data.length === 3) {
    var now = Date.now()
    var expirationTimestamp = Number(data[1])
    if(expirationTimestamp > now) {
      var actualHash = data[2];
      var expectedHash = generateHash(secret, algorithm, expirationTimestamp, sessionId);
      if(actualHash === expectedHash) {
        return true;
      } else {
        console.log('CSRF attempt. Invalid token.');
      }
    } else {
      console.log('CSRF attempt. Expired token.', new Date(expirationTimestamp));
    }
  }

  return false;

}

function extractCSRFToken(keys, req) {
  if(req.headers && req.headers[keys.header]) {
    return req.headers[keys.header];
  }
  if(req.body && req.body[keys.body]) {
    return req.body[keys.body];
  }
  var url = URL.parse(req.url, true, false)
  if(url.query && url.query[keys.query]) {
    return url.query[keys.query];
  }
}

function extractSessionId(sessionCookie, req, res) {
  if(req.cookies && req.cookies[sessionCookie]) {
    return req.cookies[sessionCookie];
  }
}

function generateHash(secret, algorithm, expirationTimestamp, sessionId) {
  var hmac = crypto.createHmac(algorithm, secret);
  hmac.setEncoding('hex');
  hmac.write(sessionId);
  hmac.write('' + expirationTimestamp);
  hmac.end();
  return hmac.read();
}

function generateCSRF(secret, algorithm, validityDelay, sessionId) {
  if(sessionId) {
    var expirationTimestamp = Date.now() + validityDelay;
    var hash = generateHash(secret, algorithm, expirationTimestamp, sessionId)
    hash = '{' + expirationTimestamp + '}' + hash;

    return hash
  }
}
