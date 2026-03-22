/*
@jnode/server-account/manager.js

Official account system for JNS.

by JustApple
*/

// dependcies
const crypto = require('crypto');
const { AuthService } = require('@jnode/auth');
const Account = require('./account.js');

// account manager
//   anyone could build an account manager in the protocol
//   here is an example in-memory account manager
class AccountManager {
    constructor(data = new Map(), options = {}) { // constructor depends on different managers
        this.data = data;

        // index
        this.accountIndex = new Map();
        this.emailIndex = new Map();
        for (const [i, d] of this.data) {
            this.accountIndex.set(String(d.account).toLowerCase(), i);
            this.emailIndex.set(String(d.email).toLowerCase(), i);
        }

        if (options.authService) {
            this.authService = options.authService;
        } else {
            if (!options.privateKey || !options.publicKey) {
                const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                    modulusLength: 2048,
                    publicKeyEncoding: {
                        type: 'spki',
                        format: 'pem'
                    },
                    privateKeyEncoding: {
                        type: 'pkcs8',
                        format: 'pem'
                    }
                });
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            } else {
                this.publicKey = options.publicKey;
                this.privateKey = options.privateKey;
            }
            this.authService = new AuthService(this.publicKey, this.privateKey);
        }
    }

    // regist an account, parameter must be followed, could be an async function
    // returns an Account
    register(account, email, password, displayName) {
        // check account format
        if (
            typeof account !== 'string' ||
            !/^\w{4,32}$/.test(account)
        ) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);
        account = account.toLowerCase();

        // check email format
        if (typeof email !== 'string') throw _Error('Bad email format.', 'EMAIL_BAD_FORMAT', 400);
        email = email.trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw _Error('Bad email format.', 'EMAIL_BAD_FORMAT', 400);

        // check password format
        if (
            typeof password !== 'string' ||
            !/^[\x20-\x7E]+$/.test(password) ||
            password.trim().length === 0
        ) throw _Error('Bad password format.', 'PW_BAD_FORMAT', 400);

        // check display name format
        if (typeof displayName !== 'string') throw _Error('Bad display name format.', 'DNAME_BAD_FORMAT', 400);
        displayName = displayName.trim().replace(/\s+/g, ' ').replace(/[\x00-\x1F\x7F\u202E\u202D\u202B\u202A\u200B-\u200D]/g, '');
        if (
            displayName.length > 32 ||
            displayName.length < 2
        ) throw _Error('Bad display name format.', 'DNAME_BAD_FORMAT', 400);

        // check password safety
        if (!(
            /[A-Z]/.test(password) &&
            /[a-z]/.test(password) &&
            /[0-9]/.test(password) &&
            /[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]/.test(password) &&
            password.length >= 8 &&
            password.length <= 64
        )) throw _Error('Password too weak.', 'PW_TOO_WEAK', 400);

        // check account
        if (this.accountIndex.has(account)) throw _Error('Account already exists.', 'ACC_CONFLICT', 409);

        // check email
        if (this.emailIndex.has(email)) throw _Error('Email already in use.', 'EMAIL_CONFLICT', 409);

        // hash password
        const pwSalt = crypto.randomBytes(16);
        const pwHash = crypto.scryptSync(password, pwSalt, 16);

        // regist
        const id = account;
        this.data.set(id, { id, account, email, displayName, pwSalt, pwHash, createdAt: new Date(), permissions: new Set(), securityReset: new Date(0) });
        this.accountIndex.set(account, id);
        this.emailIndex.set(email, id);

        return new Account(this, id);
    }

    // login to an account, parameter must be followed, could be an async function
    // returns an Account
    login(account, password) {
        // check basic account format
        if (typeof account !== 'string') throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);

        let id;

        // check account or email format and get account
        if (account.includes('@')) { // email as account
            account = account.trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(account)) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);
            id = this.emailIndex.get(account);
        } else { // account as account
            if (!/^\w{4,32}$/.test(account)) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);
            account = account.toLowerCase();
            id = this.accountIndex.get(account);
        }

        // check password format
        if (
            typeof password !== 'string' ||
            !/^[\x20-\x7E]+$/.test(password) ||
            password.trim().length === 0
        ) throw _Error('Bad password format.', 'PW_BAD_FORMAT', 400);

        // check if account exists
        if (!id) throw _Error('Account not found.', 'ACC_NOT_FOUND', 401);

        // verify password
        const { pwSalt, pwHash } = this.data.get(id);
        if (!crypto.timingSafeEqual(crypto.scryptSync(password, pwSalt, 16), pwHash)) throw _Error('Password incorrect.', 'PW_INCORRECT', 401);

        return new Account(this, id);
    }

    // delete an account, parameter must be followed, could be an async function
    // returns undefined
    deleteAccount(id) {
        // check if account exists
        const d = this.data.get(id);
        if (!d) throw _Error('Could not found account with provided ID.', 'ACC_NOT_FOUND', 401);

        this.accountIndex.delete(d.account);
        this.emailIndex.delete(d.email);
        this.data.delete(id);
    }

    // reset account password, parameter must be followed, could be an async function
    resetAccountPassword(id, password) {
        // check new password format
        if (
            typeof password !== 'string' ||
            !/^[\x20-\x7E]+$/.test(password) ||
            password.trim().length === 0
        ) throw _Error('Bad new password format.', 'PW_BAD_FORMAT', 400);

        // check password safety
        if (!(
            /[A-Z]/.test(password) &&
            /[a-z]/.test(password) &&
            /[0-9]/.test(password) &&
            /[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]/.test(password) &&
            password.length >= 8 &&
            password.length <= 64
        )) throw _Error('New password too weak.', 'PW_TOO_WEAK', 400);

        // check if account exists
        const d = this.data.get(id);
        if (!d) throw _Error('Could not found account with provided ID.', 'ACC_NOT_FOUND', 401);

        // hash password
        const newPwSalt = crypto.randomBytes(16);
        const newPwHash = crypto.scryptSync(password, newPwSalt, 16);

        // update
        d.pwSalt = newPwSalt;
        d.pwHash = newPwHash;
        d.securityReset = new Date();

        return new Account(this, id);
    }

    // verify account password, parameter must be followed, could be an async function
    verifyAccountPassword(id, password) {
        // check if account exists
        const d = this.data.get(id);
        if (!d) throw _Error('Could not found account with provided ID.', 'ACC_NOT_FOUND', 401);

        // verify password
        const { pwSalt, pwHash } = d;
        if (!crypto.timingSafeEqual(crypto.scryptSync(password, pwSalt, 16), pwHash)) throw _Error('Password incorrect.', 'PW_INCORRECT', 401);

        return new Account(this, id);
    }

    // get data of an account, parameter must be followed, could be an async function
    // returns object of:
    //   required properties: id (unique internal id string), account (unique string), email (string), createdAt (Date), permissions (Set)
    //   recommend properties: displayName (string)
    getAccountData(id) {
        return this.data.get(id);
    }

    // sign a token, parameter must be followed, could be an async function
    signToken(header, payload) {
        return this.authService.signToken(header, payload);
    }

    // verify a token, parameter must be followed, could be an async function
    verifyToken(token) {
        return this.authService.verifyToken(token);
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
module.exports = AccountManager;
