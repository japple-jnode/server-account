/*
@jnode/server-account/handlers.js

Official account system for JNS.

by JustApple
*/

// dependcies
const { util, routerConstructors: r, handlerConstructors: h } = require('@jnode/server');

// register handler
class RegisterHandler {
    constructor(manager, options = {}) {
        this.manager = manager;
        this.cookieOptions = options.cookieOptions;
        this.cookieDuration = options.cookieDuration || 604800; // seconds
    }

    async handle(ctx, env) {
        let body = (await ctx.receiveBody(1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            throw _Error('Body is not vaild JSON.', 'BODY_NOT_JSON', 400);
        }

        try {
            const account = await this.manager.register(body?.account, body?.email, body?.password, body?.displayName);
            const data = await account.data();
            const date = Date.now();
            const token = await account.manager.signToken({ typ: 'jnsat' }, {
                typ: 'login', id: data.id,
                cre: date, exp: date + this.cookieDuration * 1000
            });
            ctx.setCookie('jnsat', token, {
                'HttpOnly': true,
                ...this.cookieOptions,
                'Max-Age': this.cookieDuration
            });
            return h.JSON({ status: 200, id: data.id, account: data.account, displayName: data.displayName, createdAt: data.createdAt.toISOString() }).handle(ctx, env);
        } catch (e) {
            throw e;
        }
    }
}

// login handler
class LoginHandler {
    constructor(manager, options = {}) {
        this.manager = manager;
        this.cookieOptions = options.cookieOptions;
        this.cookieDuration = options.cookieDuration || 604800; // seconds
    }

    async handle(ctx, env) {
        let body = (await ctx.receiveBody(1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            throw _Error('Body is not vaild JSON.', 'BODY_NOT_JSON', 400);
        }

        try {
            const account = await this.manager.login(body?.account, body?.password);
            const data = await account.data();
            const date = Date.now();
            const token = await account.manager.signToken({ typ: 'jnsat' }, {
                typ: 'login', id: data.id,
                cre: date, exp: date + this.cookieDuration * 1000
            });
            ctx.setCookie('jnsat', token, {
                'HttpOnly': true,
                ...this.cookieOptions,
                'Max-Age': this.cookieDuration
            });
            return h.JSON({ status: 200, id: data.id, account: data.account, displayName: data.displayName, createdAt: data.createdAt.toISOString() }).handle(ctx, env);
        } catch (e) {
            throw e;
        }
    }
}

// reset password handler
class ResetPasswordHandler {
    constructor(manager, options = {}) {
        this.manager = manager;
        this.cookieOptions = options.cookieOptions;
        this.cookieDuration = options.cookieDuration || 604800; // seconds
    }

    async handle(ctx, env) {
        let body = (await ctx.receiveBody(1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            throw _Error('Body is not vaild JSON.', 'BODY_NOT_JSON', 400);
        }

        try {
            if (body?.id !== ctx.identity.account?.id) throw _Error('Account id is incorrect.', 'ID_INCORRECT', 401);

            const account = await this.manager.verifyAccountPassword(body?.id, body?.oldPassword);
            await this.manager.resetAccountPassword(body?.id, body?.newPassword);

            const data = await account.data();
            const date = Date.now() + 100; // prevent token expires right away
            const token = await account.manager.signToken({ typ: 'jnsat' }, {
                typ: 'login', id: data.id,
                cre: date, exp: date + this.cookieDuration * 1000
            });
            ctx.setCookie('jnsat', token, {
                'HttpOnly': true,
                ...this.cookieOptions,
                'Max-Age': this.cookieDuration
            });
            return h.JSON({ status: 200 }).handle(ctx, env);
        } catch (e) {
            throw e;
        }
    }
}

// delete account handler
class DeleteAccountHandler {
    constructor(manager, options = {}) {
        this.manager = manager;
    }

    async handle(ctx, env) {
        let body = (await ctx.receiveBody(1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            throw _Error('Body is not vaild JSON.', 'BODY_NOT_JSON', 400);
        }

        try {
            if (body?.id !== ctx.identity.account?.id) throw _Error('Account id is incorrect.', 'ID_INCORRECT', 401);
            const account = await this.manager.verifyAccountPassword(body?.id, body?.password);
            await this.manager.deleteAccount(body?.id);
            return h.JSON({ status: 200 }).handle(ctx, env);
        } catch (e) {
            throw e;
        }
    }
}

// error
function _Error(message, code, status = 500) {
    const err = new Error(message);
    err.code = code;
    err.statusCode = status;
    return err;
}

// export
module.exports = {
    RegisterHandler, LoginHandler, ResetPasswordHandler, DeleteAccountHandler,
    handlerConstructors: {
        Register: (manager, options) => new RegisterHandler(manager, options),
        Login: (manager, options) => new LoginHandler(manager, options),
        ResetPassword: (manager, options) => new ResetPasswordHandler(manager, options),
        DeleteAccount: (manager, options) => new DeleteAccountHandler(manager, options)
    }
};