/* eslint no-undef:0 no-unused-vars:0 */

var token

function xhr (url, opts, cb) {
  opts = opts || {method: 'GET'}
  opts.headers = opts.headers || {}
  opts.headers.Accept = 'application/json'
  opts.headers['X-Requested-With'] = 'XMLHttpRequest'
  if (token) opts.headers.Authorization = 'Token ' + token
  var req = new XMLHttpRequest()
  req.open(opts.method, url, true)
  req.withCredentials = true
  for (var key in opts.headers) req.setRequestHeader(key, opts.headers[key])
  req.onreadystatechange = function () {
    if (req.readyState === 4) {
      try {
        req.body = JSON.parse(req.response || req.responseText)
        if (req.body && req.body.token) token = req.body.token
      } catch (e) {}
      cb(null, req)
    }
  }
  req.send(opts.body)
}

function test (method, url) {
  const pre = document.getElementById('out')
  xhr(url, {method: method}, function (_err, res) {
    pre.innerText += [method, url, res.status, JSON.stringify(res.body), '\n'].join(' ')
  })
}
