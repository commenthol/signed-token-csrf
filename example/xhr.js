/* eslint no-undef:0 no-unused-vars:0 */

let token

function xhr (url, opts, cb) {
  opts = opts || { method: 'GET' }
  opts.headers = opts.headers || {}
  opts.headers.Accept = 'application/json'
  opts.headers['X-Requested-With'] = 'XMLHttpRequest'
  if (token) opts.headers.Authorization = 'Token ' + token
  const req = new XMLHttpRequest()
  req.open(opts.method, url, true)
  req.withCredentials = true
  for (const key in opts.headers) req.setRequestHeader(key, opts.headers[key])
  req.onreadystatechange = function () {
    if (req.readyState === 4) {
      try {
        // @ts-expect-error
        req.body = JSON.parse(req.response || req.responseText)
        // @ts-expect-error
        if (req.body && req.body.token) token = req.body.token
      } catch (e) {}
      cb(null, req)
    }
  }
  req.send(opts.body)
}

function test (method, url) {
  const pre = document.getElementById('out')
  xhr(url, { method }, function (_err, res) {
    if (!pre) return
    pre.innerText += [method, url, res.status, JSON.stringify(res.body), '\n'].join(' ')
  })
}
