// const Csrf = require('signed-token-csrf')
const Csrf = require('..')
const bodyParser = require('body-parser')
const session = require('express-session')
const app = require('express')()
const csrf = new Csrf('csrfSecret', {cookie: {secure: false}})

// works with or without a session
app.use(session({secret: 'sessionSecret', resave: false, saveUninitialized: true}))

app.get('/form',
  csrf.create, // adds CSRF middleware
  (req, res) => {
    res.end(`
      <form action="/form" method="POST">
        <input type="hidden" name="csrf" value="${req.csrfToken()}" >
        <input type="text" name="text" value="some text"><br>
        <button>Submit</button>
      </form>
    `)
  }
)
app.post('/form',
  bodyParser.urlencoded({extended: false}),
  csrf.verify,
  (req, res) => {
    res.end(`
<h2>Parameters</h2>
<pre>
text: ${req.body.text}
csrf: ${req.body.csrf}
</pre>
<a href="/form">back</a>
    `)
  }
)

app.use('/', (req, res) => {
  res.redirect('/form')
})

app.listen(3000)
