const Cookie = require('cookie')
const signedToken = require('signed-token')
const timingSafeEqual = require('compare-timing-safe')
const chain = require('connect-chain-if')

/** @typedef {import('./types').RequestCsrf} Request */
/** @typedef {import('./types').ResponseCsrf} Response */
/** @typedef {import('./types').HttpError} HttpError */

/**
 * A CSRF connect middleware which creates and verifies csrf tokens
 *
 * @example
 * const Csrf = require('signed-token-csrf')
 * const csrf = new Csrf('csrfSecret', {cookie: {secure: false}}).csrf
 * const app = require('express')()
 * app.use('/',
 *   bodyParser.urlencoded({extended: false}),
 *   csrf, // adds CSRF middleware
 *   (req, res) => res.json({ csrf: req.csrfToken() })
 * )
 */
class Csrf {
  /**
   * @param {string} secret - a server side secret
   * @param {object} [opts] - options
   * @param {string} [opts.name=csrf] - header & cookie name of token
   * @param {object} [opts.cookie] - cookie options - defaults to `{path: '/', httpOnly: true, secure: true, sameSite: true}`
   * @param {object} [opts.token] - signedToken options - defaults to `{digest: 'sha256', commonlen: 24, tokenlen: 48}`
   * @param {string[]} [opts.ignoreMethods] - ignore methods `['HEAD', 'OPTIONS']`
   * @param {string} [opts.host] - hostname of service to check against
   */
  constructor (secret, opts = {}) {
    if (!secret) throw new TypeError('need a secret')

    this.opts = {
      name: 'csrf',
      ...opts,
      cookie: { path: '/', httpOnly: true, secure: true, sameSite: true, ...opts.cookie },
      token: { digest: 'sha256', commonlen: 24, tokenlen: 48, ...opts.token },
      ignoreMethods: ['HEAD', 'OPTIONS'].concat(opts.ignoreMethods || [])
    }

    this._signSecret = signedToken(secret, this.opts.token)

    ;['checkOrigin', 'create', 'verify', 'verifyXhr', 'csrf'].forEach(prop => {
      this[prop] = this[prop].bind(this)
    })
  }

  /**
   * Checks origin/ referer of request against `opts.hostname`, `X-Forwarded-Host` or `Host` header.
   * For XHR Requests `X-Requested-With: XMLHttpRequest` is checked only
   * @param {Request} req
   * @param {Response} res
   * @param {Function} next
   */
  checkOrigin (req, res, next) {
    const { opts } = this || {}
    if (this._ignoreMethods(req, next)) return

    const { headers } = req || {}
    const origin = headers.origin || headers.referer || headers.referrer || ''
    const host = String(opts.host || headers['x-forwarded-host'] || headers.host || 'host')
    const isFromOrigin = (origin.indexOf(host) > 6)
    const isXMLHttpRequest = (headers['x-requested-with'] === 'XMLHttpRequest')

    if (isXMLHttpRequest || isFromOrigin || !origin) {
      next()
    } else {
      next(httpError(403, 'bad origin', 'ECSRFBADORIGIN'))
    }
  }

  /**
   * Creates method `req.csrfToken()` to get CSRF token as well as the secret for
   * signing in `req.session.csrf` if available or sets a `csrf` cookie.
   * Name of session key and cookie name can be changed via `opts.name`.
   * Default name is `csrf`.
   * @param {Request} req
   * @param {Response} res
   * @param {Function} next
   */
  create (req, res, next) {
    const { opts } = this || {}
    if (this._ignoreMethods(req, next)) return

    let { secret, cookie } = getSecret(req, opts)
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

    req.csrfToken = () => signedToken(secret, opts.token).createSync()

    // store secret either in session or cookie
    if (req.session) {
      req.session[opts.name] = secret
    } else if (!cookie) {
      setCookie(res, opts.name, secret, opts.cookie)
    }
    next()
  }

  /**
   * Obtains a token from a request using either `req.body.csrf`, `req.query.csrf`
   * or `req.headers['x-csrf-token']` and verifies it with the secret from
   * `req.session.csrf` if available or from the `csrf` cookie.
   * `body-parser` is required to obtain the token from the request body.
   * Name of session key and cookie name can be changed via `opts.name`
   */
  verify (req, res, next) {
    const { opts } = this || {}
    if (this._ignoreMethods(req, next)) return

    const token =
      req.csrf || // in case you like to use a custom middleware upfront
      req.body?.[opts.name] || // needs bodyParser
      req.query?.[opts.name] ||
      req.headers?.[`x-${opts.name}-token`]

    const { secret } = getSecret(req, opts)

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
   * Verifies the cookie only; For token based xhr requests
   * Requires `XMLHttpRequest.withCredentials = true`
   * @see http://www.redotheweb.com/2015/11/09/api-security.html
   * @param {Request} req
   * @param {Response} res
   * @param {Function} next
   */
  verifyXhr (req, res, next) {
    const { opts } = this || {}
    if (this._ignoreMethods(req, next)) return

    const { secret } = getSecret(req, opts)
    if (!secret) {
      next(httpError(403, 'misconfigured csrf', 'ECSRFMISCONFIG'))
      return
    }

    const vSecret = this._signSecret.verifySync(secret)
    if (!vSecret) {
      next(httpError(403, 'bad csrf token', 'ECSRFBADTOKEN'))
      return
    }
    next()
  }

  /**
   * Express middleware which chains `create` and `verify`
   * @param {Request} req
   * @param {Response} res
   * @param {Function} next
   */
  csrf (req, res, next) {
    if (this._ignoreMethods(req, next)) return

    chain.if(
      req.method === 'GET',
      this.create,
      [this.create, this.verify]
    )(req, res, next)
  }

  /**
   * @private
   * @param {Request} req
   * @param {Function} next
   */
  _ignoreMethods (req, next) {
    if (this.opts.ignoreMethods.indexOf(req.method) !== -1) {
      next()
      return true
    }
  }
}

module.exports = Csrf

/**
 * get secret from session or cookie
 * @private
 * @param {Request} req
 * @param {object} opts
 * @param {object} opts.name
 */
function getSecret (req, opts) {
  const cookies = req.cookies || Cookie.parse(req.headers?.cookie || '') || {}
  const cookie = cookies[opts.name]
  const secret = req.session?.[opts.name] || cookie
  return { secret, cookie }
}

/**
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

/**
 * @private
 * @param {number} statusCode
 * @param {string} message
 * @param {string} [code]
 * @return {HttpError}
 */
function httpError (statusCode, message, code) {
  /** @type {HttpError} */
  const err = new Error(message)
  err.status = err.statusCode = statusCode || 500
  err.code = code
  return err
}
