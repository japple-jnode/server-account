/*
@jnode/server-account

Official account system for JNS.

by JustApple
*/

// dependencies
const fs = require('fs/promises');
const crypto = require('crypto');
const { util, routerConstructors: r, handlerConstructors: h } = require('@jnode/server');
const dble = require('@jnode/db/dble');
const { receiveBody, setCookie } = util;

// account manager
class AccountManager {
    constructor(db, options = {}) {
        this.db = db;
        this.privateKey = options.privateKey;
        this.publicKey = options.publicKey;
        this.tokenTime = options.tokenTime || 604800000; // 7 days
    }

    static async setup(dbFile = './accounts.jdb', options = {}) {
        let db;

        if (dbFile instanceof dble.DBLEFile) {
            db = dbFile;
        } else {
            // check file exists
            let fileExists = true;
            try {
                const stats = await fs.stat(dbFile);
                if (!stats.isFile()) throw new Error('JNS Account: Could not setup database on a folder.')
            } catch (err) {
                if (err.code === 'ENOENT') fileExists = false;
                else throw err;
            }

            if (fileExists) {
                db = await dble.DBLEFile.load(dbFile);
            } else { // create database
                db = await dble.DBLEFile.create(dbFile, {
                    fields: options.fields ?? [
                        new dble.DBLEUInt32Field('xid', true, true),
                        new dble.DBLEStringField(32, 'id', true),
                        new dble.DBLEStringField(32, 'name'),
                        new dble.DBLEStringField(96, 'email', true),
                        new dble.DBLEAnyField(32, 'pw'),
                        new dble.DBLEBigUInt64Field('created'),
                        new dble.DBLEBigUInt64Field('token_reset'),
                        new dble.DBLEBigUInt64Field('banned_until'),
                        new dble.DBLEBigUInt64Field('last_login'),
                        new dble.DBLEAnyField(10, 'flags')
                    ]
                });
            }

            // check fields exists
            const requiredFields = ['xid', 'id', 'name', 'email', 'pw', 'created', 'token_reset', 'banned_until', 'last_login', 'flags'];
            for (let i of requiredFields) {
                if (!db.fieldsMap[i]) throw new Error(`JNS Account: Database missing field '${i}'.`);
            }

            // load key
            try {
                options.privateKey = await fs.readFile(options.privateKeyFile ?? './token-private.pem', 'utf8');
                options.publicKey = await fs.readFile(options.privateKeyFile ?? './token-public.pem', 'utf8');
            } catch {
                await new Promise((resolve, reject) => {
                    crypto.generateKeyPair('rsa', {
                        modulusLength: 2048,
                        publicKeyEncoding: {
                            type: 'spki',
                            format: 'pem'
                        },
                        privateKeyEncoding: {
                            type: 'pkcs8',
                            format: 'pem'
                        }
                    }, (err, publicKey, privateKey) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        options.privateKey = privateKey;
                        options.publicKey = publicKey;

                        resolve();
                    });
                });

                await fs.writeFile(options.privateKeyFile ?? './token-private.pem', this.privateKey, 'utf8');
                await fs.writeFile(options.publicKeyFile ?? './token-public.pem', this.publicKey, 'utf8');
            }

            return new AccountManager(db, options);
        }
    }

    async getAccountByXid(xid, skipQueue) {
        const line = await this.db.getLineByField('xid', xid, skipQueue);
        if (typeof line === 'number') return new Account(this, line);
        else return null;
    }

    async getAccountById(id, skipQueue) {
        const line = await this.db.getLineByField('id', id.toLowerCase(), skipQueue);
        if (typeof line === 'number') return new Account(this, line);
        else return null;
    }

    async getAccountByEmail(email, skipQueue) {
        const line = await this.db.getLineByField('email', email.toLowerCase(), skipQueue);
        if (typeof line === 'number') return new Account(this, line);
        else return null;
    }

    signToken(payload = {}, options) {
        const now = Date.now();
        payload.cre = now;
        payload.exp = now + (options.time ?? this.tokenTime);
        const encodedPayload = base64URLEncode(JSON.stringify(payload));
        const signer = crypto.createSign('RSA-SHA256');
        signer.update(encodedPayload);
        return `${encodedPayload}.${signer.sign(this.privateKey, 'base64url')}`;
    }
}

// account
class Account {
    constructor(manager, line) {
        this.manager = manager;
        this.line = line;
    }

    async getData(skipQueue) {
        return (await this.manager.db.readLine(this.line, skipQueue))?.fields;
    }

    checkPassword(password, skipQueue) {
        return this.manager.db._doTask(async () => {
            const data = await this.getData(true);
            return await verifyPassword(password, data.pw);
        }, skipQueue);
    }

    generateAccessToken(options, skipQueue) {
        return this.manager.db._doTask(async () => {
            const data = await this.getData(true);
            const now = Date.now();
            return this.manager.signToken({
                x: data.xid.toString(),
                v: 1,
                ...options.data
            }, options);
        }, skipQueue);
    }
}

// base64url encode
function base64URLEncode(str) {
    return Buffer.from(str, 'utf8').toString('base64url');
}

// hash password
function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16);
        crypto.scrypt(password, salt, 16, { cost: 16384 }, (err, hash) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(Buffer.concat([salt, hash]));
        });
    });
}

// verify password
function verifyPassword(password, storedBuffer) {
    return new Promise((resolve, reject) => {
        const salt = storedBuffer.subarray(0, 16);
        const originalHash = storedBuffer.subarray(16);
        crypto.scrypt(password, salt, 16, { cost: 16384 }, (err, newHash) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(crypto.timingSafeEqual(originalHash, newHash));
        });
    });
}

// routers


// handlers

// register api
class RegisterHandler {
    constructor(manager) {
        this.manager = manager;
    }

    async handle(ctx, env) {
        let body = (await receiveBody(ctx.req, 1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            return h.JSON({ status: 400, message: 'Body is not vaild JSON.' }, { statusCode: 400 }).handle(ctx, env);
        }

        // check fields
        if ( // id
            typeof body?.id !== 'string' ||
            !/^\w{4,32}$/.test(body.id)
        ) return h.JSON({ status: 400, message: '\'id\' should be a string in /^\w{4,32}$/.' }, { statusCode: 400 }).handle(ctx, env);

        if ( // display name
            typeof body?.name !== 'string' ||
            !(body.name = body.name.trim().replace(/\s+/g, ' ').replace(/[\x00-\x1F\x7F\u202E\u202D\u202B\u202A\u200B-\u200D]/g, '')) ||
            Buffer.byteLength(body.name) > 32 ||
            body.name.length < 1
        ) return h.JSON({ status: 400, message: '\'name\' should be a string between 1 to 32 bytes of UTF-8.' }, { statusCode: 400 }).handle(ctx, env);

        if ( // email
            typeof body?.email !== 'string' ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(body.email = body.email.trim().toLowerCase()) ||
            body.email.length > 96
        ) return h.JSON({ status: 400, message: '\'email\' should be a string in /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/ and <= 96 chars.' }, { statusCode: 400 }).handle(ctx, env);

        if ( // password
            typeof body?.pw !== 'string' ||
            !/^[\x20-\x7E]+$/.test(body.pw) ||
            body.pw.trim().length === 0
        ) return h.JSON({ status: 400, message: '\'pw\' should be a string in /^[\x20-\x7E]+$/.' }, { statusCode: 400 }).handle(ctx, env);

        if ( // password safety
            typeof this.manager.passwordChecker === 'function' ?
                !this.manager.passwordChecker(body.pw) : !(
                    /[A-Z]/.test(body.pw) &&
                    /[a-z]/.test(body.pw) &&
                    /[0-9]/.test(body.pw) &&
                    /[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]/.test(body.pw) &&
                    body.pw.length >= 8 &&
                    body.pw.length <= 64
                )
        ) return h.JSON({ status: 400, message: this.manager.passwordMessage ?? 'Password isn\'t strong enough, must have a-z, A-Z, 0-9, and symbol. And between 8 to 64 chars.' }, { statusCode: 400 }).handle(ctx, env);

        // start a task for safe database handling
        await this.manager.db._doTask(async () => {
            // check if id and email address exists
            if (await this.manager.getAccountById(body.id, true)) return h.JSON({ status: 409, message: 'This ID is already in use.' }, { statusCode: 409 }).handle(ctx, env);
            if (await this.manager.getAccountByEmail(body.email, true)) return h.JSON({ status: 409, message: 'This email has already registed.' }, { statusCode: 409 }).handle(ctx, env);

            // regist account
            const line = await this.manager.db.appendLine({
                id: body.id,
                name: body.name,
                email: body.email,
                pw: await hashPassword(body.pw),
                created: Date.now(),
                token_reset: 0,
                banned_until: 0,
                last_login: 0,
                flags: Buffer.alloc(10)
            }, true);


            const account = new Account(this.manager, line);
            const accd = await account.getData(true);
            setCookie(ctx.res, 'acc_token', await account.generateAccessToken({ typ: 'account' }, true), {
                'SameSite': 'Lax',
                'Max-Age': Math.ceil(this.manager.tokenTime / 1000)
            });

            return h.JSON({
                status: 200,
                account: {
                    xid: accd.xid.toString(),
                    id: accd.id,
                    name: accd.name,
                    email: accd.email,
                    created: (new Date(Number(accd.created))).toISOString()
                }
            }).handle(ctx, env);
        });
    }
}

// login handler
class LoginHandler {
    constructor(manager) {
        this.manager = manager;
    }

    async handle(ctx, env) {
        let body = (await receiveBody(ctx.req, 1024)).toString('utf8');

        try {
            body = JSON.parse(body);
        } catch { // not JSON, bad request
            return h.JSON({ status: 400, message: 'Body is not vaild JSON.' }, { statusCode: 400 }).handle(ctx, env);
        }

        // check fields
        if ( // id or email
            (
                typeof body?.account !== 'string' ||
                !/^\w{4,32}$/.test(body.account)
            ) && (
                typeof body?.account !== 'string' ||
                !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(body.account = body.account.trim().toLowerCase()) ||
                body.account.length > 96
            )
        ) return h.JSON({ status: 400, message: '\'account\' should be vaild ID or email.' }, { statusCode: 400 }).handle(ctx, env);

        if ( // password
            typeof body?.pw !== 'string' ||
            !/^[\x20-\x7E]+$/.test(body.pw) ||
            body.pw.trim().length === 0
        ) return h.JSON({ status: 400, message: '\'pw\' should be a string in /^[\x20-\x7E]+$/.' }, { statusCode: 400 }).handle(ctx, env);

        // start a task for safe database handling
        await this.manager.db._doTask(async () => {
            // get account
            let account;
            if (body.account.includes('@')) { // email
                account = await this.manager.getAccountByEmail(body.account, true);
            } else { // id
                account = await this.manager.getAccountById(body.account, true);
            }

            if (!account) return h.JSON({ status: 401, message: 'Account not found.' }, { statusCode: 401 }).handle(ctx, env);

            // check password
            if (await account.checkPassword(body.pw, true)) {
                const accd = await account.getData(true);
                setCookie(ctx.res, 'acc_token', await account.generateAccessToken({ typ: 'account' }, true), {
                    'SameSite': 'Lax',
                    'Max-Age': Math.ceil(this.manager.tokenTime / 1000)
                });

                return h.JSON({
                    status: 200,
                    account: {
                        xid: accd.xid.toString(),
                        id: accd.id,
                        name: accd.name,
                        email: accd.email,
                        created: (new Date(Number(accd.created))).toISOString()
                    }
                }).handle(ctx, env);
            } else return h.JSON({ status: 401, message: 'Account or password is incorrect.' }, { statusCode: 401 }).handle(ctx, env);
        });
    }
}

// export
module.exports = {
    AccountManager,
    RegisterHandler, LoginHandler,
    routerConstructors: {

    },
    handlerConstructors: {
        Register: (manager) => new RegisterHandler(manager),
        Login: (manager) => new LoginHandler(manager)
    }
};