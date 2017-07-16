# signed-token-csrf

> CSRF connect middleware using signed tokens

## Example

See `./example/app.js`

```js
const Csrf = require('signed-token-csrf')
const bodyParser = require('body-parser')
const session = require('express-session')
const app = require('express')()
const csrf = new Csrf('csrfSecret', {cookie: {secure: false}})

// works with or without a session
app.use(session({secret: 'sessionSecret', resave: false, saveUninitialized: true}))

app.get('/form',
  csrf.create, // adds CSRF protection
  (req, res) => { // render a form
    res.end(`
      <form action="/form" method="POST">
        <input type="hidden" name="csrf" value="${res.locals.csrf}" >
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

## API

### `new Csrf(secret, [opts])`

**Parameters**

| parameter              | type   | description                                                                                          |
| ---------------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| `secret`               | String | a server side secret                                                                                 |
| `[opts]`               | Object | _optional:_ options                                                                                  |
| `[opts.name=csrf]`     | String | _optional:_ header &amp; cookie name of token                                                        |
| `[opts.cookie]`        | Object | _optional:_ cookie options - defaults to  `{path: '/', httpOnly: true, secure: true, sameSite: true}`|
| `[opts.token]`         | Object | _optional:_ signedToken options - defaults to `{digest: 'sha256', commonlen: 24, tokenlen: 48}`      |
| `[opts.ignoreMethods]` | Array&lt;String&gt; | _optional:_ ignore methods `['HEAD', 'OPTIONS']`                                        |

### `create`

Creates method `req.csrfToken()` to get CSRF token as well as the secret for 
signing in `req.session.csrf` if available or sets a csrf cookie.
Name of session key and cookie name can be changed via opts.name.
Default name is `csrf`.


### `verify`

Obtains a token from a request using either `req.body.csrf`, `req.query.csrf` or `req.headers['x-csrf-token']` and verifies it with the secret from `req.session.csrf` if available or from the `csrf` cookie.
`body-parser` is required to obtain the token from the request body.
Name of session key and cookie name can be changed via `opts.name`


### `csrf`

connect middleware which chains `create` and `verify`.


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
