# `@jnode/server-account`

Official account system for JNS.

## Installation

```
npm i @jnode/server-account
```

## Quick start

### Import

```js
const { AccountManager, routerConstructors: ar, handlerConstructors: ah } = require('@jnode/server-account');
const { createServer, routerConstructors: r } = require('@jnode/server');
```

### Start an account server

```js
const manager = new AccountManager();

const server = createServer(
  // setup JSON error messages for account operations
  ar.JSONErrorMessage(
    r.Path(
      // fallback for authenticated users
      ah.Login(manager), // Default at root if needed, or:
      {
        '/register': ah.Register(manager),
        '/login': ah.Login(manager),
        // protect sensitive routes
        '/api': ar.AccountTokenVerify(
          manager,
          r.Path(null, {
            '@GET /profile': (ctx) => ctx.identity.account.data(),
            '@POST /reset-password': ah.ResetPassword(manager)
          }),
          401 // fail if not logged in
        )
      }
    )
  )
);

server.listen(8080);
```

## How it works?

`@jnode/server-account` provides a complete workflow for managing user accounts, authentication tokens, and protected routing in JNS.

1. **AccountManager**: Handles the core logic like registration, password hashing (using `scrypt`), and token signing (using `@jnode/auth`).
2. **Account Routers**: Specifically designed to verify tokens and inject the `Account` instance into `ctx.identity.account`.
3. **Account Handlers**: Standardized handlers for common tasks like `Login` or `Register` that automatically handle body parsing and cookie setting.

The system is designed to be extensible; while a default in-memory manager is provided, you can use `AccountManagerDBLE` for persistent storage using `@jnode/db`.

------

# Reference

## Class: `account.AccountManager`

The core manager for handling account lifecycle and authentication.

### `new account.AccountManager([data, options])`

- `data` [\<Map\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map) Initial account data. **Default:** `new Map()`.
- `options` [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)
  - `authService` [\<AuthService\>](https://github.com/japple-jnode/auth#class-authauthservice) A custom auth service.
  - `publicKey` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) RSA public key for tokens.
  - `privateKey` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) RSA private key for tokens.

If keys are not provided and no `authService` is passed, a new 2048-bit RSA key pair will be generated automatically.

### `manager.register(account, email, password, displayName)`

- Returns: [\<account.Account\>](#class-accountaccount)

Registers a new user. Performs validation on formats and password strength. Throws errors with codes like `ACC_CONFLICT` or `PW_TOO_WEAK`.

### `manager.login(account, password)`

- `account` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) Account name or email.
- Returns: [\<account.Account\>](#class-accountaccount)

Verifies credentials. Throws `ACC_NOT_FOUND` or `PW_INCORRECT` on failure.

### `manager.resetAccountPassword(id, password)`

- `id` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) Internal account ID.
- `password` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) New password.

Updates the password and sets `securityReset` to the current time, which invalidates old tokens.

### `manager.signToken(header, payload)`

Signs a token using the internal `AuthService`.

## Class: `account.Account`

Represents a specific account instance.

### `account.data()`

- Returns: [\<Promise\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) | [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)

Returns the raw data of the account, including `id`, `account`, `email`, `displayName`, `createdAt`, and `permissions`.

## Built-in routers

### Router: `TokenVerify(service, pass, fail[, by])`

- `service` [\<AuthService\>](https://github.com/japple-jnode/auth#class-authauthservice) The auth service to use.
- `pass` [router-extended] Target if token is valid.
- `fail` [router-extended] Target if token is invalid or missing.
- `by` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) | [\<Function\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function) How to extract the token. **Default:** extracts from `Authorization` header.

### Router: `JSONErrorMessage(next)`

Wraps the routing process to provide standardized JSON error responses for status codes. When a numeric error is thrown (e.g., `400`), it returns:
`{ "status": 400, "code": "ERR_CODE", "message": "..." }`.

### Router: `AccountTokenVerify(manager, pass, fail)`

Specific version of `TokenVerify` that:

1. Looks for the `jnsat` cookie.
2. Injects an `Account` instance into `ctx.identity.account`.
3. Validates if the token was created before a password reset.

## Built-in handlers

### Handler: `Register(manager[, options])`

Handles `POST` requests containing JSON: `{ "account", "email", "password", "displayName" }`. On success, sets the `jnsat` cookie.

### Handler: `Login(manager[, options])`

Handles `POST` requests containing JSON: `{ "account", "password" }`. On success, sets the `jnsat` cookie.

- `options` [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)
  - `cookieDuration` [\<number\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#number_type) Token lifetime in seconds. **Default:** `604800` (7 days).
  - `cookieOptions` [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object) Additional cookie attributes (e.g., `Secure`, `Domain`).

### Handler: `ResetPassword(manager[, options])`

Handles password changes. Requires `ctx.identity.account` to be set (typically by using `AccountTokenVerify` before this handler). Expects JSON: `{ "id", "oldPassword", "newPassword" }`.

### Handler: `DeleteAccount(manager[, options])`

Deletes the account. Expects JSON: `{ "id", "password" }`. Requires authentication.
