# `@jnode/server-account`

Official account system for JNS (Node.js). It provides a full-stack solution for user registration, authentication via signed tokens, and account management.

## Installation

```
npm i @jnode/server-account
```

## Quick start

### Import

```js
const { AccountManager, routerConstructors: acr, handlerConstructors: ach } = require('@jnode/server-account');
const { createServer, routerConstructors: r, handlerConstructors: h } = require('@jnode/server');
```

### Start a basic account server

```js
const manager = new AccountManager();

const server = createServer(
  // Use JSONErrorMessage to catch errors and return structured JSON
  acr.JSONErrorMessage(
    r.Path(404, {
      '/api/register': ach.Register(manager),
      '/api/login': ach.Login(manager),
      // Protect sensitive routes using AccountTokenVerify
      '/api/user': acr.AccountTokenVerify(
        manager,
        r.Path(null, {
          '@GET /profile': async (ctx, env) => {
            const data = await ctx.identity.account.data();
            return h.JSON({ 
              status: 200, 
              account: data.account, 
              displayName: data.displayName 
            }).handle(ctx, env);
          },
          '@POST /reset-password': ach.ResetPassword(manager),
          '@POST /delete': ach.DeleteAccount(manager)
        }),
        401 // Fail handler if not logged in
      )
    })
  )
);

server.listen(8080);
```

## How it works?

`@jnode/server-account` defines a standardized account protocol:

1. **Manager**: Logic core. Handles password hashing (using `scrypt`) and data persistence.
2. **Account**: A wrapper class for specific user data access.
3. **Router**: Middlewares to verify identity. `AccountTokenVerify` injects the `Account` instance into `ctx.identity.account`.
4. **Handler**: Web controllers that consume JSON requests and interact with the `Manager`.

---

# Reference

## Class: `account.AccountManager`

The core manager for handling account lifecycle.

### `new account.AccountManager([data, options])`

- `data` [\<Map\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map) Account storage. **Default:** `new Map()`.
- `options` [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)
  - `authService` [\<AuthService\>](https://github.com/japple-jnode/auth) Custom auth service.
  - `publicKey` / `privateKey` [\<string\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type) RSA keys for tokens.

### `manager.register(account, email, password, displayName)`

Registers a user. Performs strict format validation (see [Validation Rules](#validation-rules)).

### `manager.login(account, password)`

Verifies credentials. `account` can be the username or email.

### `manager.resetAccountPassword(id, password)`

Updates password and sets `securityReset` to now, invalidating all old tokens.

## Class: `account.Account`

### `account.data()`

- Returns: [\<Promise\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) | [\<Object\>](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)
  - `id`, `account`, `email`, `displayName`, `createdAt`, `permissions`, `securityReset`.

---

## Web API Format (Built-in Handlers)

The following handlers expect **JSON** input and return **JSON** output.

### Validation Rules

For `Register` and `ResetPassword` handlers:

- **account**: 4-32 characters, alphanumeric (`\w`).
- **email**: Standard email regex.
- **password**: 8-64 characters, must include:
  - Uppercase & Lowercase letters.
  - Numbers.
  - Symbols (`!@#$%^&*` etc.).
- **displayName**: 2-32 characters, sanitized (no control codes).

### Handler: `Register(manager[, options])`

- **Request Method**: `POST` (usually)
- **Request Body**:

  ```json
  {
    "account": "username",
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "displayName": "My Name"
  }
  ```

- **Success Response**: `200 OK`

  ```json
  {
    "status": 200,
    "id": "username",
    "account": "username",
    "displayName": "My Name",
    "createdAt": "2023-10-27T..."
  }
  ```

- **Cookie**: Sets `jnsat` (HttpOnly).

### Handler: `Login(manager[, options])`

- **Request Body**:

  ```json
  {
    "account": "username_or_email",
    "password": "SecurePassword123!"
  }
  ```

- **Success Response**: Same as `Register`.
- **Cookie**: Sets `jnsat` (HttpOnly).

### Handler: `ResetPassword(manager[, options])`

*Requires authentication via `AccountTokenVerify`.*

- **Request Body**:

  ```json
  {
    "id": "current_user_id",
    "oldPassword": "CurrentPassword123!",
    "newPassword": "NewSecurePassword456!"
  }
  ```

- **Success Response**: `{"status": 200}`.
- **Cookie**: Refreshes `jnsat` with a new `cre` (creation) timestamp.

### Handler: `DeleteAccount(manager)`

*Requires authentication via `AccountTokenVerify`.*

- **Request Body**:

  ```json
  {
    "id": "current_user_id",
    "password": "CurrentPassword123!"
  }
  ```

- **Success Response**: `{"status": 200}`.

---

## Built-in routers

### Router: `AccountTokenVerify(manager, pass, fail)`

Verifies the `jnsat` cookie.

- If **Pass**: Sets `ctx.identity.account` and `ctx.identity.token`.
- If **Fail**: Calls `fail` handler (e.g., `401`).
- **Security**: Automatically rejects tokens issued before the account's last `securityReset`.

### Router: `JSONErrorMessage(next)`

Catches errors thrown during routing/handling.

- **Format**:

  ```json
  {
    "status": 401,
    "code": "ACC_NOT_FOUND",
    "message": "Account not found."
  }
  ```

### Router: `TokenVerify(service, pass, fail[, by])`

Generic token verifier. `by` can be a function to extract tokens from headers or other sources.
