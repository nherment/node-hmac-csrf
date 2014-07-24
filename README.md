
hmac-csrf
=========

Express middleware

sessionless csrf with
- HTTP Origin check for modern browsers.
- Fall back to hmac token
- Token generated based on the session cookie. Works with hmac signed
cookies with a stateless server.
- ability to exclude routes from the CSRF path.
- Compatible with templates



  var HmacCsrf = require('hmac-csrf')

  var options = {
    'secret': '123456',
    'validityDelay': 86400,         // the delay after which a CSRF token expires
    'sessionCookie': 'connect.sid'  // the cookie used in the HMAC generation
    'algorithm': 'sha256',          // the HMAC algorithm
    'origin': null,                 // If the HTTP origin header should be used for CSRF protection, put it here
    'templateAttr': 'locals',       // the '_csrf' token will be set on res[templateAttr]
    'ignore': [                     // do not run CSRF validation for these paths
      '/foo/bar'
    ],
    'keys': {
      'query': '_csrf',
      'body': '_csrf',
      'header': 'x-csrf-token'
    }
  }

  app.use(HmacCsrf(options))
