/* global describe, it */

const assert = require('assert')
const Csrf = require('..')

const cookieOpts = { cookie: { secure: false } }

describe('#signed-token-csrf', function () {
  describe('checkOrigin', function () {
    const csrf = new Csrf('ssshhh', cookieOpts)

    it('shall pass on XMLHttpRequest', function (done) {
      const req = {
        method: 'GET',
        headers: {
          'x-requested-with': 'XMLHttpRequest'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall pass on matching referer and host', function (done) {
      const req = {
        method: 'GET',
        headers: {
          host: 'aa.aa:8443',
          referer: 'https://aa.aa:8443'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall pass on matching origin and host', function (done) {
      const req = {
        method: 'GET',
        headers: {
          host: 'aa.aa:8443',
          origin: 'https://aa.aa:8443'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall pass on matching origin and x-forwarded-host', function (done) {
      const req = {
        method: 'GET',
        headers: {
          'x-forwarded-host': 'aa.aa',
          origin: 'https://aa.aa:8443'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall pass on matching origin and options.host', function (done) {
      const csrf = new Csrf('ssshhh', Object.assign({ host: 'aa.aa' }, cookieOpts))
      const req = {
        method: 'GET',
        headers: {
          host: 'bb.bb',
          origin: 'https://aa.aa:8443'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })

    it('shall bypass HEAD request', function (done) {
      const req = {
        method: 'HEAD',
        headers: {}
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall pass on missing origin/ referer header', function (done) {
      const req = {
        method: 'GET',
        headers: {}
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(!err)
        done()
      })
    })
    it('shall fail on different origin and host', function (done) {
      const req = {
        method: 'GET',
        headers: {
          host: 'bb.bb',
          origin: 'https://aa.aa/path?query'
        }
      }
      const res = {}
      csrf.checkOrigin(req, res, (err) => {
        assert.ok(err)
        assert.strictEqual(err.status, 403)
        done()
      })
    })
  })
})
