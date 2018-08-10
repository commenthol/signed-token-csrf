# signed-token-csrf

> CSRF connect middlewares using signed tokens

[![NPM version](https://badge.fury.io/js/signed-token-csrf.svg)](https://www.npmjs.com/package/signed-token-csrf/)
[![Build Status](https://secure.travis-ci.org/commenthol/signed-token-csrf.svg?branch=master)](https://travis-ci.org/commenthol/signed-token-csrf)

<!-- !toc (minlevel=2) -->

* [API](#api)
  * [new Csrf(secret, [opts])](#new-csrfsecret-opts)
  * [create](#create)
  * [verify](#verify)
  * [verifyXhr](#verifyxhr)
  * [csrf](#csrf)
* [Example](#example)
  * [Forms](#forms)
  * [XHR](#xhr)
* [Installation](#installation)
* [Tests](#tests)
* [License](#license)
* [References](#references)

<!-- toc! -->

## API

### new Csrf(secret, [opts])

**Parameters**

| parameter              | type   | description |
| ---------------------- | ------ | ----------- |
| `secret`               | String | a server side secret |
| `[opts]`               | Object | _optional:_ options |
| `[opts.name=csrf]`     | String | _optional:_ header &amp; cookie name of token |
| `[opts.cookie]`        | Object | _optional:_ cookie options - defaults to  `{path: '/', httpOnly: true, secure: true, sameSite: true}` |
| `[opts.token]`         | Object | _optional:_ signedToken options - defaults to `{digest: 'sha256', commonlen: 24, tokenlen: 48}` |
| `[opts.ignoreMethods]` | Array&lt;String&gt; | _optional:_ ignore methods `['HEAD', 'OPTIONS']` |
| `[opts.host]`          | String | _optional:_ hostname of service to check against |

### create

Connect middleware `(req, res, next) => {}`

Creates method `req.csrfToken()` to get CSRF token as well as the secret for
signing in `req.session.csrf` if available or sets a csrf cookie.
Name of session key and cookie name can be changed via opts.name.
Default name is `csrf`.

**NOTE:** If used together with `verifyXhr()` only set CSRF Cookie on successful login!

### verify

Connect middleware `(req, res, next) => {}`

Obtains a token from a request using either `req.body.csrf`, `req.query.csrf` or `req.headers['x-csrf-token']` and verifies it with the secret from `req.session.csrf` if available or from the `csrf` cookie.
`body-parser` is required to obtain the token from the request body.
Name of session key and cookie name can be changed via `opts.name`

### verifyXhr

Connect middleware `(req, res, next) => {}`

Verifies the cookie only; For token based xhr requests.
See [Your API-Centric Web App Is Probably Not Safe Against XSS and CSRF][].

**NOTE:** Only set CSRF Cookie with `create()` on successful login!

### csrf

Connect middleware `(req, res, next) => {}` which chains `create` and `verify`.


## Example

### Forms

See `./example/app.js`. Run with `node exampe/app.js` and open http://localhost:3000 in browser.

```js
const Csrf = require('signed-token-csrf')
const bodyParser = require('body-parser')
const session = require('express-session')
const app = require('express')()
const csrf = new Csrf('csrfSecret', {cookie: {secure: false}})

// works with or without a session
app.use(session({secret: 'sessionSecret', resave: false, saveUninitialized: true}))

app.use(csrf.checkOrigin)

app.get('/form',
  csrf.create, // adds CSRF protection
  (req, res) => { // render a form
    res.end(`
      <form action="/form" method="POST">
        <input type="hidden" name="csrf" value="${req.csrfToken()}" >
        <input type="text" name="text" value="some text"><br>
        <button>Submit</button>
      </form>
    `)
  }
)
app.post('/form', // render the submitted values or throw
  bodyParser.urlencoded({extended: false}),
  csrf.verify,
  (req, res) => {
    res.end(`
<h2>Parameters</h2>
<pre>
text: ${req.body.text}
csrf: ${req.body.csrf}
</pre>
    `)
  }
)

app.use('/', (req, res) => {
  res.redirect('/form')
})

app.listen(3000)
```

### XHR

Run example and browse to http://localhost:3000/xhr

```js
app.use(csrf.checkOrigin)

app.get('/api/login',
  (req, res, next) => {
    // prevent creating a new csrf cookie if authenticated
    const err = req.headers.authorization && httpError(403, 'already authenticated')
    next(err)
  },
  csrf.create,
  (req, res) => res.json({token: 'your-auth-token'})
)

app.use('/api',
  csrf.verifyXhr,
  (req, res) => res.json({})
)
```

## Installation

Requires [nodejs](http://nodejs.org/).

```sh
$ npm install signed-token-csrf
```


## Tests

```sh
$ npm test
```


## License

Unlicense <https://unlicense.org>


## References

<!-- !ref -->

* [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet - OWASP][Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet - OWASP]
* [Your API-Centric Web App Is Probably Not Safe Against XSS and CSRF][Your API-Centric Web App Is Probably Not Safe Against XSS and CSRF]

<!-- ref! -->

[Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet - OWASP]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
[Your API-Centric Web App Is Probably Not Safe Against XSS and CSRF]: http://www.redotheweb.com/2015/11/09/api-security.html
