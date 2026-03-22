/*
@jnode/server-account/manager-dble.js

Official account system for JNS.

by JustApple
*/

// dependcies
const crypto = require('crypto');
const fs = require('fs/promises');
const { AuthService } = require('@jnode/auth');
const Account = require('./account.js');
const dble = require('@jnode/db/dble');

// id
class DBLEIdField extends dble.DBLEField {
    constructor(name, isKey = true, isRelative = true) {
        super(4, 'ID', name, isKey, isRelative);
    }

    parse(buf, offset) {
        return String(buf.readUInt32LE(offset));
    }

    write(data, buf = Buffer.alloc(this.length), offset = 0) {
        buf.writeUInt32LE(Number(data), offset);
        return buf;
    }

    default(relative = '-1') {
        return String(Number(relative) + 1);
    }
}

// permission manager
class PermissionManager {
    // binding: { PERMISSION: offset }
    constructor(bindings = {}, length = 8) {
        this.bindings = bindings;
        this.length = length;
    }

    // check if a buffer permission if it has permission 
    has(buf = Buffer.alloc(this.length), permission = '', offset = 0) {
        let index;
        if (typeof permission === 'number') index = permission;
        else index = this.bindings[permission];

        if (typeof index !== 'number') return false;

        const atByte = offset + Math.floor(index / 8);
        const atBit = index % 8;

        if (atByte >= buf.length) return false;

        return (buf[atByte] & (1 << atBit)) !== 0;
    }

    set(buf = Buffer.alloc(this.length), permission = '', offset = 0) {
        let index;
        if (typeof permission === 'number') index = permission;
        else index = this.bindings[permission];

        if (typeof index !== 'number') return buf;

        const atByte = offset + Math.floor(index / 8);
        const atBit = index % 8;

        if (atByte >= buf.length) return buf;

        buf[atByte] |= (1 << atBit);
        return buf;
    }

    remove(buf = Buffer.alloc(this.length), permission = '', offset = 0) {
        let index;
        if (typeof permission === 'number') index = permission;
        else index = this.bindings[permission];

        if (typeof index !== 'number') return buf;

        const atByte = offset + Math.floor(index / 8);
        const atBit = index % 8;

        if (atByte >= buf.length) return buf;

        buf[atByte] &= ~(1 << atBit);

        return buf;
    }

    toSet(buf = Buffer.alloc(this.length), offset = 0) {
        const set = new Set();
        for (let i in this.bindings) {
            if (this.has(buf, i, offset)) set.add(i);
        }
        return set;
    }

    fromSet(set = new Set(), buf = Buffer.alloc(this.length), offset = 0) {
        for (let i of set) {
            if (typeof this.bindings[i] === 'number') this.set(buf, i, offset);
        }
        return buf;
    }
}

// account manager dble
//   dble supported account manager
class AccountManagerDBLE {
    constructor(db, options = {}) {
        this.db = db;
        this.authService = options.authService;
        this.permissionManager = options.permissionManager ?? new PermissionManager({ VERIFIED: 0 }, 16);
    }

    static PermissionManager = PermissionManager;

    static async setup(dbFile, options = {}) {
        let authService;
        let pubKey;
        let priKey;
        let db;

        // setup auth service
        if (options.authService) {
            authService = options.authService;
        } else {
            if (options.privateKey && options.publicKey) {
                pubKey = options.publicKey;
                priKey = options.privateKey;
            } else {
                try {
                    pubKey = await fs.readFile(options.publicKeyFile || './token-public.pem', 'utf8');
                    priKey = await fs.readFile(options.privateKeyFile || './token-private.pem', 'utf8');
                } catch { }
            }

            if (!pubKey || !priKey) {
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
                await fs.writeFile(options.publicKeyFile || './token-public.pem', publicKey);
                await fs.writeFile(options.privateKeyFile || './token-private.pem', privateKey);
                pubKey = publicKey;
                priKey = privateKey;
            }

            authService = new AuthService(pubKey, priKey);
        }

        // setup db
        if (!(dbFile instanceof dble.DBLEFile)) {
            dbFile = dbFile ?? './accounts.jdb';
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
                db = await dble.DBLEFile.load(dbFile, { ...options, types: { 'ID': DBLEIdField, ...options.types } });
            } else { // create database
                db = await dble.DBLEFile.create(dbFile, {
                    fields: options.fields ?? [
                        new DBLEIdField('id', true, true),
                        new dble.DBLEStringField(32, 'account', true),
                        new dble.DBLEStringField(32, 'displayName'),
                        new dble.DBLEStringField(96, 'email', true),
                        new dble.DBLEAnyField(16, 'pwSalt'),
                        new dble.DBLEAnyField(16, 'pwHash'),
                        new dble.DBLEDateField('createdAt'),
                        new dble.DBLEDateField('securityReset'),
                        new dble.DBLEAnyField(16, 'permissions')
                    ],
                    types: { 'ID': DBLEIdField }
                });
            }

            // check fields exists
            const requiredFields = ['id', 'account', 'displayName', 'email', 'pwSalt', 'pwHash', 'createdAt', 'securityReset', 'permissions'];
            for (let i of requiredFields) {
                if (!db.fieldsMap[i]) throw new Error(`JNS Account: Database missing field '${i}'.`);
            }
        }

        return new AccountManagerDBLE(db, { ...options, authService });
    }

    // register an account
    async register(account, email, password, displayName) {
        // check account format
        if (
            typeof account !== 'string' ||
            !/^\w{4,32}$/.test(account)
        ) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);

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
        if (this.db.indices.account.has(account.toLowerCase())) throw _Error('Account already exists.', 'ACC_CONFLICT', 409);

        // check email
        if (this.db.indices.email.has(email)) throw _Error('Email already in use.', 'EMAIL_CONFLICT', 409);

        // hash password
        const pwSalt = crypto.randomBytes(16);
        const pwHash = crypto.scryptSync(password, pwSalt, 16);

        // register
        const line = await this.db.appendLine({
            account: account.toLowerCase(), email, pwSalt, pwHash,
            displayName,
            createdAt: new Date(),
            securityReset: new Date(0),
            permissions: Buffer.alloc(16)
        });

        const id = await this.db.getField(line, 'id');

        return new Account(this, id);
    }

    // login to an account
    async login(account, password) {
        if (typeof account !== 'string') throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);

        let line;
        if (account.includes('@')) { // email
            account = account.trim().toLowerCase();
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(account)) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);
            line = await this.db.getLineByField('email', account);
        } else { // account
            if (!/^\w{4,32}$/.test(account)) throw _Error('Bad account format.', 'ACC_BAD_FORMAT', 400);
            line = await this.db.getLineByField('account', account.toLowerCase());
        }

        if (line === undefined) throw _Error('Account not found.', 'ACC_NOT_FOUND', 401);

        const data = (await this.db.readLine(line)).fields;

        // check password format
        if (
            typeof password !== 'string' ||
            !/^[\x20-\x7E]+$/.test(password) ||
            password.trim().length === 0
        ) throw _Error('Bad password format.', 'PW_BAD_FORMAT', 400);

        // verify password
        const { pwSalt, pwHash, id } = data;
        if (!crypto.timingSafeEqual(crypto.scryptSync(password, pwSalt, 16), pwHash)) throw _Error('Password incorrect.', 'PW_INCORRECT', 401);

        return new Account(this, id);
    }

    // delete an account
    async deleteAccount(id) {
        const line = await this.db.getLineByField('id', id);
        if (line === undefined) throw _Error('Could not find account with provided ID.', 'ACC_NOT_FOUND', 401);
        await this.db.deleteLine(line, true);
    }

    // reset account password
    async resetAccountPassword(id, password) {
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

        const line = await this.db.getLineByField('id', id);
        if (line === undefined) throw _Error('Could not find account with provided ID.', 'ACC_NOT_FOUND', 401);

        const newPwSalt = crypto.randomBytes(16);
        const newPwHash = crypto.scryptSync(password, newPwSalt, 16);

        await this.db.setLine(line, {
            pwSalt: newPwSalt,
            pwHash: newPwHash,
            securityReset: new Date()
        });

        return new Account(this, id);
    }

    // verify account password
    async verifyAccountPassword(id, password) {
        const line = await this.db.getLineByField('id', id);
        if (line === undefined) throw _Error('Could not find account with provided ID.', 'ACC_NOT_FOUND', 401);

        const data = (await this.db.readLine(line)).fields;

        // verify password
        const { pwSalt, pwHash } = data;
        if (!crypto.timingSafeEqual(crypto.scryptSync(password, pwSalt, 16), pwHash)) throw _Error('Password incorrect.', 'PW_INCORRECT', 401);

        return new Account(this, id);
    }

    // get data of an account
    async getAccountData(id) {
        const line = await this.db.getLineByField('id', id);
        if (line === undefined) return null;
        const data = (await this.db.readLine(line)).fields;

        // convert permissions buffer to Set
        data.permissions = this.permissionManager.toSet(data.permissions);
        data.id = String(data.id);

        return data;
    }

    // sign a token
    signToken(header, payload) {
        return this.authService.signToken(header, payload);
    }

    // verify a token
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
module.exports = AccountManagerDBLE;