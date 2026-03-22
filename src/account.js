/*
@jnode/server-account/account.js

Official account system for JNS.

by JustApple
*/

// account
class Account {
    constructor(manager, id) {
        this.manager = manager;
        this.id = id;
    }

    // may return Promise
    // required properties: id (unique internal id string), account (unique string), email (string), createdAt (Date), permissions (Set), securityReset (Date)
    // recommend properties: displayName (string)
    data() {
        return this.manager.getAccountData(this.id);
    }
}

// export
module.exports = Account;