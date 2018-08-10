/* global describe, it */

const assert = require('assert')
const setCookieParser = require('set-cookie-parser')
const request = require('supertest')
const {appCookie, appSession, appCookieXhr} = require('./app')
const Csrf = require('..')

const cookieOpts = {cookie: {secure: false}}

describe('#signed-token-csrf', function () {
  describe('general', function () {
    it('should throw on missing secret', function () {
      assert.throws(() => {
        new Csrf() // eslint-disable-line no-new
      }, /need a secret/)
    })
  })

  describe('cookie', function () {
    const csrf = new Csrf('ssshhh', cookieOpts)
    const app = appCookie(csrf)

    it('should return csrf token', function () {
      return request(app)
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
    })

    it('should work in req.body', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('form')
            .send({csrf: res.body.csrf})
            .expect(200)
        })
    })

    it('should work in req.query', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/?csrf=' + res.body.csrf)
            .type('form')
            .expect(200)
        })
    })

    it('should work in x-csrf-token header', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('form')
            .set('x-csrf-token', res.body.csrf)
            .expect(200)
        })
    })

    it('should work with different name', function () {
      const name = 'state'
      const csrf = new Csrf('ssshhh', Object.assign({name}, cookieOpts))
      const app = appCookie(csrf, name)
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf(name))
        .expect(assertCsrfCookie(name))
        .expect(200)
        .then((res) => {
          // console.log(res.headers, res.body)
          return agent
            .post('/')
            .type('form')
            .send({state: res.body.state})
            .expect(200)
        })
    })

    it('should fail with an invalid token', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('json')
            .send({csrf: 'oopsy'})
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(403)
        })
    })

    it('should fail with no token', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(403)
        })
    })

    it('should create a new cookie if invalid on GET', function () {
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .get('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrf())
            .expect(assertCsrfCookie())
            .expect(200)
        })
    })

    it('should create a new cookie if invalid on POST', function () {
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrf())
            .expect(assertCsrfCookie())
            .expect(403)
        })
    })

    it('should ignoreMethods DELETE', function () {
      const csrf = new Csrf('ssshhh', Object.assign({ignoreMethods: ['DELETE']}, cookieOpts))
      const app = appCookie(csrf)
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .delete('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrfNoCookie())
            .expect(200)
        })
    })
  })

  describe('session', function () {
    const csrf = new Csrf('ssshhh')
    const app = appSession(csrf)

    it('should return csrf token', function () {
      return request(app)
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
    })

    it('should work in req.body', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('form')
            .send({csrf: res.body.csrf})
            .expect(200)
        })
    })

    it('should work in req.query', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/?csrf=' + res.body.csrf)
            .type('form')
            .expect(200)
        })
    })

    it('should work in x-csrf-token header', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('form')
            .set('x-csrf-token', res.body.csrf)
            .expect(200)
        })
    })

    it('should work with different name', function () {
      const name = 'state'
      const csrf = new Csrf('ssshhh', {name})
      const app = appSession(csrf, name)
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf(name))
        .expect(assertCsrfNoCookie(name))
        .expect(200)
        .then((res) => {
          // console.log(res.headers, res.body)
          return agent
            .post('/')
            .type('form')
            .send({state: res.body.state})
            .expect(200)
        })
    })

    it('should fail with an invalid token', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('json')
            .send({csrf: 'oopsy'})
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(403)
        })
    })

    it('should fail with no token', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(403)
        })
    })

    it('should create a new cookie if invalid on GET', function () {
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .get('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(200)
        })
    })

    it('should create a new cookie if invalid on POST', function () {
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrf())
            .expect(assertCsrfNoCookie())
            .expect(403)
        })
    })

    it('should ignoreMethods DELETE', function () {
      const csrf = new Csrf('ssshhh', Object.assign({ignoreMethods: ['DELETE']}, cookieOpts))
      const app = appSession(csrf)
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfNoCookie())
        .expect(200)
        .then((res) => {
          // console.log(res.statusCode, res.headers, res.body)
          return agent
            .delete('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrfNoCookie())
            .expect(200)
        })
    })
  })

  describe('cookieXhr', function () {
    const csrf = new Csrf('ssshhh', cookieOpts)
    const app = appCookieXhr(csrf)

    it('should return csrf token', function () {
      return request(app)
        .get('/')
        // .then(res => console.log(res.headers))
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
    })

    it('should verify xhr request', function () {
      const agent = request.agent(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .post('/')
            .type('json')
            .send({})
            .expect(200)
        })
    })

    it('should fail with an invalid token', function () {
      return request.agent(app)
        .post('/')
        .set('Cookie', `csrf=BvuSyrOlD1k1zoCVU5ZnIrSlephg8w-ep0Bu3jnFmkVjYNzX`)
        .type('json')
        .send()
        .expect(403)
    })

    it('should fail with no token', function () {
      return request.agent(app)
        .post('/')
        .expect(assertCsrfNoCookie())
        .expect(403)
    })

    it('should ignoreMethods DELETE', function () {
      const csrf = new Csrf('ssshhh', Object.assign({ignoreMethods: ['DELETE']}, cookieOpts))
      const app = appCookieXhr(csrf)
      const agent = request(app)
      return agent
        .get('/')
        .expect(assertCsrf())
        .expect(assertCsrfCookie())
        .expect(200)
        .then((res) => {
          return agent
            .delete('/')
            .set('Cookie', 'csrf=bad')
            .expect(assertCsrfNoCookie())
            .expect(200)
        })
    })
  })
})

function setCookieParse (res) {
  let cookies = {}
  setCookieParser.parse(res).forEach(p => (cookies[p.name] = p))
  return cookies
}

function assertCsrf (name = 'csrf') {
  return (res) => {
    assert.strictEqual(typeof res.body[name], 'string')
    assert.strictEqual(res.body[name].length, 48)
  }
}

function assertCsrfCookie (name = 'csrf') {
  return (res) => {
    const cookies = setCookieParse(res)
    assert.strictEqual(cookies[name].value.length, 48)
    assert.ok(res.body[name] !== cookies[name].value)
    cookies[name].value = 'test'
    assert.deepStrictEqual(cookies[name], {
      name,
      value: 'test',
      path: '/',
      httpOnly: true,
      // secure: true,
      sameSite: 'Strict'
    })
  }
}

function assertCsrfNoCookie (name = 'csrf') {
  return (res) => {
    const cookies = setCookieParse(res)
    assert.ok(!cookies[name])
  }
}
