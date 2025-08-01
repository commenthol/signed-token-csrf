const http = require('http')
const bodyParser = require('body-parser')
const express = require('express')
const session = require('express-session')
const cors = require('cors')

const final = (name) => (req, res) => {
  res.body = Object.assign({ session: req.session }, res.body)
  res.body[name] = req.csrfToken && req.csrfToken()
  res.json(res.body)
}

const finalError = (name) => (err, req, res, _next) => {
  // console.log(err.stack)
  res.statusCode = err.statusCode || 500
  res.body = {
    error: err.message || http.STATUS_CODES[err.statusCode],
    code: err.code
  }
  final(name)(req, res)
}

/* eslint-disable */
const logger = (req, res, next) => {
  console.log(req.method, req.url, req.headers, req.body, req.session)
  res.on('finish', () => console.log(res.statusCode, res._headers))
  next()
}
/* eslint-enable */

const appCookie = (csrf, name = 'csrf') => {
  const app = express()
  app.use(bodyParser.json(), bodyParser.urlencoded({ extended: false }))
  app.use('/', csrf.csrf)
  app.use(final(name), finalError(name))

  return app
}

const appSession = (csrf, name = 'csrf') => {
  const app = express()
  app.use(bodyParser.json(), bodyParser.urlencoded({ extended: false }))
  app.use(
    '/',
    session({
      secret: 'secret',
      resave: false,
      saveUninitialized: true,
      cookie: {}
    }),
    csrf.csrf
  )
  app.use(final(name), finalError(name))

  return app
}

const appCookieXhr = (csrf, name = 'csrf') => {
  const app = express()
  app.use(cors())

  app.use(bodyParser.json(), bodyParser.urlencoded({ extended: false }))
  app.use(
    '/',
    // logger,
    (req, res, next) => {
      req.method === 'GET'
        ? csrf.create(req, res, next) // NOTE: Only set CRSF Token on login!
        : csrf.verifyXhr(req, res, next)
    }
  )
  app.use(final(name), finalError(name))

  return app
}

module.exports = {
  appCookie,
  appSession,
  appCookieXhr
}
