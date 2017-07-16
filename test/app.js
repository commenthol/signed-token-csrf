const http = require('http')
const bodyParser = require('body-parser')
const express = require('express')
const session = require('express-session')

const final = (req, res) => {
  res.body = Object.assign({session: req.session}, res.body, res.locals)
  res.json(res.body)
}

const finalError = (err, req, res, next) => {
  // console.log(err.stack)
  res.statusCode = err.statusCode || 500
  res.body = {
    error: err.message || http.STATUS_CODES[err.statusCode],
    code: err.code
  }
  final(req, res)
}

/* eslint-disable */
const logger = (req, res, next) => {
  console.log(req.method, req.url, req.headers, req.body, req.session)
  next()
}
/* eslint-enable */

const appCookie = (csrf) => {
  const app = express()
  app.use(
    bodyParser.json(),
    bodyParser.urlencoded({extended: false})
  )
  app.use('/',
    csrf.csrf
  )
  app.use(final, finalError)

  return app
}

const appSession = (csrf) => {
  const app = express()
  app.use(
    bodyParser.json(),
    bodyParser.urlencoded({extended: false})
  )
  app.use('/',
    session({
      secret: 'secret',
      resave: false,
      saveUninitialized: true,
      cookie: {}
    }),
    csrf.csrf
  )
  app.use(final, finalError)

  return app
}

module.exports = {
  appCookie,
  appSession
}
