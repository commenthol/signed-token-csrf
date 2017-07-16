const Cookie = require('cookie')
const signedToken = require('signed-token')
const timingSafeEqual = require('compare-timing-safe')
const chain = require('connect-chain-if')
const _set = require('lodash.set')
const _get = require('lodash.get')

/**
* A CSRF connect middleware which creates and verifies csrf tokens
*
* @example
* const Csrf = require('signed-token-csrf')
* const csrf = new Csrf('mycsrfsecret', {cookie: {secure: false}}).csrf
* const app = require('express')()
* app.use('/',
*   bodyParser.urlencoded({extended: false}),
*   csrf // adds CSRF middleware
* )
*/
class Csrf {
  /**
  * @param {String} secret - a server side secret
  * @param {Object} [opts] - options
  * @param {String} [opts.name=csrf] - header & cookie name of token
  * @param {Object} [opts.cookie] - cookie options - defaults to `{path: '/', httpOnly: true, secure: true, sameSite: true}`
  * @param {Object} [opts.token] - signedToken options - defaults to `{digest: 'sha256', commonlen: 24, tokenlen: 48}`
  * @param {Object} [opts.ignoreMethods] - ignore methods `['HEAD', 'OPTIONS']`
  */
  constructor (secret, opts = {}) {
    if (!secret) throw new TypeError('need a secret')

    this.opts = Object.assign({name: 'csrf'}, opts)
    this.opts.cookie = Object.assign({path: '/', httpOnly: true, secure: true, sameSite: true}, opts.cookie)
    this.opts.token = Object.assign({digest: 'sha256', commonlen: 24, tokenlen: 48}, opts.token)
    this.opts.ignoreMethods = ['HEAD', 'OPTIONS'].concat(opts.ignoreMethods)

    this._signSecret = signedToken(secret, this.opts.token)
    this.csrf = this.csrf.bind(this)
    this.create = this.create.bind(this)
    this.verify = this.verify.bind(this)
  }

  /**
  * creates a CSRF token and sets `res.locals.csrf` as well as the secret for
  * signing in `req.session.csrf` if available or sets a `csrf` cookie.
  * Name of session key and cookie name can be changed via `opts.name`
  */
  create (req, res, next) {
    const {opts} = this || {}

    if (this.opts.ignoreMethods.indexOf(req.method) !== -1) {
      next()
      return
    }

    let {secret, cookie} = getSecret(req, opts)
    if (secret) {
      const vSecret = this._signSecret.verifySync(secret)
      if (!vSecret) {
        secret = null
        cookie = null
      }
    }
    if (!secret) {
      secret = this._signSecret.createSync()
    }

    const token = signedToken(secret, opts.token).createSync()
    // use res.locals.csrf to set hidden input in form
    _set(res, ['locals', opts.name], token)

    // store secret either in session or cookie
    if (req.session) {
      req.session[opts.name] = secret
    } else if (!cookie) {
      setCookie(res, opts.name, secret, opts.cookie)
    }
    next()
  }

  /**
  * verifies a CSRF from `req.body.csrf` and verifies with the secret from
  * `req.session.csrf` if available or from `csrf` cookie
  * body-parser is required to obtain the token from the request body
  * Name of session key and cookie name can be changed via `opts.name`
  */
  verify (req, res, next) {
    const {opts} = this || {}

    if (opts.ignoreMethods.indexOf(req.method) !== -1) {
      next()
      return
    }

    const token =
      _get(req, ['body', opts.name]) || // needs bodyParser
      _get(req, ['query', opts.name]) ||
      _get(req, ['headers', `x-${opts.name}-token`])

    const {secret} = getSecret(req, opts)

    if (!token || !secret) {
      next(httpError(403, 'misconfigured csrf', 'ECSRFMISCONFIG'))
      return
    }

    const vSecret = this._signSecret.verifySync(secret)
    const vToken = signedToken(secret, opts.token).verifySync(token) ||
      Math.random().toString()

    if (!vSecret || !timingSafeEqual(token, vToken)) {
      next(httpError(403, 'bad csrf token', 'ECSRFBADTOKEN'))
      return
    }
    next()
  }

  /**
  * express middleware which chains `create` and `verify`
  */
  csrf (req, res, next) {
    chain.if(
      req.method === 'GET',
      this.create,
      [this.create, this.verify]
    )(req, res, next)
  }
}

module.exports = Csrf

/**
* @private
*/
function getSecret (req, opts) {
  const cookies = req.cookies || Cookie.parse(_get(req, 'headers.cookie', '')) || {}
  const cookie = cookies[opts.name]
  const secret = _get(req, ['session', opts.name], cookie)
  return {secret, cookie}
}

/*
* @private
*/
function setCookie (res, name, value, options) {
  const data = Cookie.serialize(name, value, options)
  const curr = res.getHeader('set-cookie') || []
  const header = Array.isArray(curr)
    ? curr.concat(data)
    : [curr, data]
  res.setHeader('set-cookie', header)
}

/*
* @private
*/
function httpError (statusCode, message, code) {
  const err = new Error(message)
  err.statusCode = statusCode || 500
  err.code = code
  return err
}
