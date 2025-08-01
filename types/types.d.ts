import { Request, Response } from 'express-serve-static-core';
export interface RequestCsrf extends Request {
    session?: object;
    csrfToken: () => string;
}
export interface ResponseCsrf extends Response {
}
export interface HttpError extends Error {
    statusCode?: number;
    status?: number;
    code?: string;
}
