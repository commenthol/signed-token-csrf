export = Csrf;
/** @typedef {import('./types.js').RequestCsrf} Request */
/** @typedef {import('./types.js').ResponseCsrf} Response */
/** @typedef {import('./types.js').HttpError} HttpError */
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
declare class Csrf {
    /**
     * @param {string} secret - a server side secret
     * @param {object} [opts] - options
     * @param {string} [opts.name=csrf] - header & cookie name of token
     * @param {object} [opts.cookie] - cookie options - defaults to `{path: '/', httpOnly: true, secure: true, sameSite: true}`
     * @param {object} [opts.token] - signedToken options - defaults to `{digest: 'sha256', commonlen: 24, tokenlen: 48}`
     * @param {string[]} [opts.ignoreMethods] - ignore methods `['HEAD', 'OPTIONS']`
     * @param {string} [opts.host] - hostname of service to check against
     */
    constructor(secret: string, opts?: {
        name?: string | undefined;
        cookie?: object;
        token?: object;
        ignoreMethods?: string[] | undefined;
        host?: string | undefined;
    });
    opts: {
        cookie: any;
        token: any;
        ignoreMethods: string[];
        name: string;
        host?: string | undefined;
    };
    _signSecret: any;
    /**
     * Checks origin/ referer of request against `opts.hostname`, `X-Forwarded-Host` or `Host` header.
     * For XHR Requests `X-Requested-With: XMLHttpRequest` is checked only
     * @param {Request} req
     * @param {Response} res
     * @param {Function} next
     */
    checkOrigin(req: Request, res: Response, next: Function): void;
    /**
     * Creates method `req.csrfToken()` to get CSRF token as well as the secret for
     * signing in `req.session.csrf` if available or sets a `csrf` cookie.
     * Name of session key and cookie name can be changed via `opts.name`.
     * Default name is `csrf`.
     * @param {Request} req
     * @param {Response} res
     * @param {Function} next
     */
    create(req: Request, res: Response, next: Function): void;
    /**
     * Obtains a token from a request using either `req.body.csrf`, `req.query.csrf`
     * or `req.headers['x-csrf-token']` and verifies it with the secret from
     * `req.session.csrf` if available or from the `csrf` cookie.
     * `body-parser` is required to obtain the token from the request body.
     * Name of session key and cookie name can be changed via `opts.name`
     */
    verify(req: any, res: any, next: any): void;
    /**
     * Verifies the cookie only; For token based xhr requests
     * Requires `XMLHttpRequest.withCredentials = true`
     * @see http://www.redotheweb.com/2015/11/09/api-security.html
     * @param {Request} req
     * @param {Response} res
     * @param {Function} next
     */
    verifyXhr(req: Request, res: Response, next: Function): void;
    /**
     * Express middleware which chains `create` and `verify`
     * @param {Request} req
     * @param {Response} res
     * @param {Function} next
     */
    csrf(req: Request, res: Response, next: Function): void;
    /**
     * @private
     * @param {Request} req
     * @param {Function} next
     */
    private _ignoreMethods;
}
declare namespace Csrf {
    export { Request, Response, HttpError };
}
type Request = import("./types.js").RequestCsrf;
type Response = import("./types.js").ResponseCsrf;
type HttpError = import("./types.js").HttpError;
