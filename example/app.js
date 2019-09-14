// const Csrf = require('signed-token-csrf')
const Csrf = require('..')
const express = require('express')
const bodyParser = require('body-parser')
const session = require('express-session')
const app = express()
const csrf = new Csrf('csrfSecret', { cookie: { secure: false } })

const httpError = (status, message) => {
  const err = new Error(message)
  err.status = status
  return err
}

const html = (body) => `<!doctype html>
<html><head><meta charset="utf-8"></head><body>
<p>
  <a href="/form">form</a>
  <a href="/xhr">xhr</a>
  <a href="/destroy">destroy cookies</a>
</p>
${body}
</body></html>`

const htmlFormGet = (req) => html(`
<form action="/form" method="POST">
  csrf <input type="hidden_" name="csrf" value="${req.csrfToken()}" > use type="hidden"<br>
  text <input type="text" name="text" value="some text"><br>
  <button>Submit</button>
</form>`)

const htmlFormPost = (req) => html(`
<h2>Parameters</h2>
<pre>
text: ${req.body.text}
csrf: ${req.body.csrf}
</pre>`)

const htmlXhr = () => html(`
<p>
  <a href="javascript:test('GET', '/api')">get</a>
  <a href="javascript:test('GET', '/api/login')">get token</a>
  <a href="javascript:test('POST', '/api')">post</a>
</p>
<pre id="out"></pre>
<script src='xhr.js'></script>`)

// works with or without a session - comment line
app.use(session({ secret: 'sessionSecret', resave: false, saveUninitialized: true }))

app.use(csrf.checkOrigin)

app.get('/form',
  csrf.create, // adds CSRF middleware
  (req, res) => res.end(htmlFormGet(req))
)
app.post('/form',
  bodyParser.urlencoded({ extended: false }),
  csrf.verify,
  (req, res) => res.end(htmlFormPost(req))
)

app.get('/xhr', (req, res) => res.end(htmlXhr()))
app.get('/api/login',
  (req, res, next) => {
    // prevent creating a new csrf cookie if authenticated
    const err = req.headers.authorization && httpError(403, 'already authenticated')
    next(err)
  },
  csrf.create,
  (req, res) => res.json({ token: 'your-auth-token' })
)
app.use('/api',
  csrf.verifyXhr,
  (req, res) => res.json({})
)

app.use('/destroy', (req, res) => {
  res.clearCookie('csrf')
  res.clearCookie('connect.sid')
  res.end(html(''))
})
app.use('/$', (req, res) => {
  res.end(html(''))
})

app.use(express.static(__dirname))

app.use((err, req, res, next) => {
  res.statusCode = err.status || 500
  if (/json/i.test(req.headers.accept)) {
    res.json({ error: err.message })
  } else {
    res.end(html(`<pre>${err.stack}</pre>`))
  }
})

app.listen(3000)
