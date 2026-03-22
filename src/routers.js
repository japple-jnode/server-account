/*
@jnode/server-account/routers.js

Official account system for JNS.

by JustApple
*/

// dependencies
const { routerConstructors: r, handlerConstructors: h } = require('@jnode/server');
const Account = require('./account.js');

// token verify router
class TokenVerifyRouter {
    constructor(service, pass, fail, by = 'authorization') {
        this.service = service;
        this.pass = pass;
        this.fail = (fail === null) ? pass : fail;
        this.by = (typeof by === 'function') ? by : (env, ctx) => {
            const header = ctx.headers['authorization'] ?? '';
            if (header.startsWith('Bearer ')) return header.slice(7);
            else return header;
        };
    }

    route(env, ctx) {
        const token = this.by(env, ctx);
        if (!token) return this.fail;

        try {
            const result = this.service.verifyToken(token);
            ctx.identity.token = result;
            return this.pass;
        } catch {
            return this.fail;
        }
    }
}

// json error message router
class JSONErrorMessageRouter {
    constructor(next) {
        this.next = next;
    }

    route(env, ctx) {
        env.codeHandlers['000'] = function (ctx, env, code) {
            return h.JSON({ status: code, code: env.error?.code ?? 'UNKNOWN', message: (typeof env.error === 'string') ? env.error : env.error?.message ?? 'Unknown error.' }, { statusCode: code }).handle(ctx, env);
        };
        return this.next;
    }
}

// account token verify router
class AccountTokenVerifyRouter extends TokenVerifyRouter {
    constructor(manager, pass, fail) {
        super(manager.authService, pass, fail, (env, ctx) => {
            return ctx.cookie['jnsat'];
        });
        this.manager = manager;
    }

    async route(env, ctx) {
        const token = this.by(env, ctx);
        if (!token) return this.fail;

        try {
            const result = this.service.verifyToken(token);
            const account = new Account(this.manager, result.payload.id);

            const now = Date.now();
            if (now > result.payload.exp) throw _Error('Token expires.', 'TOK_EXP', 401);

            const data = await account.data();
            if (data.securityReset.getTime() > result.payload.cre) throw _Error('Token expires due to reset.', 'TOK_EXP_RESET', 401);

            ctx.identity.token = result;
            ctx.identity.account = account;
            return this.pass;
        } catch (e) {
            env.error = e;
            return this.fail;
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
    TokenVerifyRouter, JSONErrorMessageRouter, AccountTokenVerifyRouter,
    routerConstructors: {
        TokenVerify: (service, pass, fail, by) => new TokenVerifyRouter(service, pass, fail, by),
        JSONErrorMessage: (next) => new JSONErrorMessageRouter(next),
        AccountTokenVerify: (service, pass, fail) => new AccountTokenVerifyRouter(service, pass, fail),
    }
};