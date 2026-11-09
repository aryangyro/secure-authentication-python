# Secure Authentication in Python

A small, complete login system in one Python file. It shows how real
authentication works in layers: a password, then a one-time code, then a
token — instead of trusting a password on its own.

If you are new to this, start at the top and read down. Every idea is
explained in plain English before the code that uses it.

## What authentication is

Authentication is how a system answers one question: **are you really
who you say you are?**

Most systems answer it in steps, because any single step can fail:

1. **Something you know** — a password.
2. **Something you have** — a one-time code sent to a second device or
   channel. This project stores it in a file, `otp_store.txt`, so you can
   see exactly how it works.
3. **Something the system gives you after you pass** — a token, which
   proves you already logged in, so you do not have to type your password
   on every page.

This project does all three, in that order: password → one-time code
(OTP) → token → protected resource.

## What this project does

- Registers users and stores their passwords safely (hashed, never
  plain text).
- Checks a password at login, tracks failed attempts, and locks an
  account after 5 wrong tries.
- Logs every login attempt to `auth.log`.
- Generates a 6-digit one-time code (OTP) after a correct password,
  stores it in `otp_store.txt`, and checks it with strict rules.
- Issues a JWT token after the OTP passes, stores it in `tokens.txt`,
  and uses it to guard a protected resource.
- Lets a token expire, and lets you revoke it — after that, it stops
  working, even if someone copied it.

## The files

| File | What it is |
| --- | --- |
| `auth_app.py` | The whole project, 290 lines. Registration, login, OTP, tokens, demo and interactive mode. |
| `test_auth.py` | 29 automated tests for the project. Run it with `python3 test_auth.py`. |
| `README.md` | This file. |
| `WORKLOG.md` | What was built on Nov 8, 2026, test results, and challenges. |
| `users.json` | Created when you run the program. Usernames, password hashes, failed-attempt counts, locked flags. Never put real passwords in here. |
| `auth.log` | Created when you run the program. One line per login attempt. |
| `otp_store.txt` | Created when you run the program. One line: username, OTP value, expiry time, tries used. |
| `tokens.txt` | Created when you run the program. One line per token: username, token, `active` or `revoked`. |

Files like `users.json`, `auth.log`, `otp_store.txt` and `tokens.txt`
are generated when you run the program, and are ignored by git — they
are not part of the project itself.

## Quick start

You need Python 3. Install the two optional libraries first:

```bash
pip install bcrypt pyjwt
```

Both are optional. If they are not installed, the program falls back
to code from Python's standard library (PBKDF2 for passwords, a simple
signed token for JWT). The behaviour is the same either way.

Run the demo — it walks through the whole flow by itself:

```bash
python3 auth_app.py
```

Or run it interactively, typing your own username, password and OTP:

```bash
python3 auth_app.py --interactive
```

Run the tests:

```bash
python3 test_auth.py
```

## How to run the demo, step by step

The demo (`python3 auth_app.py`) does this, in order:

1. **Registers a user, `alice`.**
   Her password is stored as a hash. The program prints the fields
   that are stored — `username`, `password_hash`, `failed`, `locked` —
   and confirms no plain-text password is stored.

2. **Tries 5 wrong passwords for alice.**
   Each one fails, and the failed count goes up: 1/5, 2/5, … 5/5.
   After the fifth, alice's account is locked.

3. **Tries the correct password while alice is locked.**
   It is refused. Locking works even for the right password — that is
   the point. An attacker cannot keep guessing forever, and a locked
   account stays locked until it is unlocked.

4. **Registers a fresh user, `bob`, and logs him in properly.**
   Correct password → the program generates an OTP for bob.

5. **Enters a wrong OTP, then the right one.**
   The wrong one fails (1/3). The right one passes, and the OTP is
   removed straight away — it can never be used again.

6. **Creates a token for bob and opens the protected resource.**
   With a valid token, access is granted and the demo "secret data"
   is shown.

7. **Tries the same OTP again.**
   There is no OTP left for bob, so it fails. Reuse is impossible.

8. **Revokes the token, then tries the protected resource again.**
   Access is denied. Then it tries with no token at all — also denied.

The demo ends by listing the files it created: `users.json`,
`auth.log`, `otp_store.txt`, `tokens.txt`. Open them and look at
what is inside — that is the best way to understand the project.

## Part 1: passwords and hashing

### Why you never store a plain-text password

If passwords are stored as plain text, anyone who reads the user
database — a stolen backup, a leaked file, an insider — has
every password. People reuse passwords across sites, so one leak can
compromise many accounts.

The fix is to store a **hash** of the password instead. A hash is a
one-way fingerprint: you can check whether a password matches a hash,
but you cannot turn a hash back into the password.

### Hashing vs encryption

These are often confused, and the difference matters:

- **Encryption is reversible.** You encrypt with a key, and anyone
  with the key can decrypt. That is right for data you need to read
  back, like a message — and wrong for passwords, because anyone who
  steals the key gets every password.
- **Hashing is one-way.** There is no key and no "un-hash". To check
  a login, the program hashes the password the user just typed and
  compares it with the stored hash. If they match, the password was
  right. The program never needs to know the password itself.

### Salt, bcrypt and PBKDF2

Two extra ideas make hashing strong in practice:

- **A salt** is a random value mixed into the hash. Every user gets
  a different salt, so the same password produces a different hash
  for different users. Without a salt, an attacker can pre-compute
  hashes for common passwords once and compare them against every
  account at once.
- **A slow hash** makes guessing expensive. `bcrypt` and PBKDF2
  repeat the hashing many times on purpose. A normal hash takes a
  fraction of a millisecond; a password hash is designed to take
  noticeably longer. That hardly matters to one real user logging in,
  but it makes trying millions of passwords very slow for an attacker.

This project uses `bcrypt` when it is installed. If it is not, it
falls back to PBKDF2-HMAC-SHA256 with a 16-byte random salt and
200,000 iterations, using only Python's standard library.

### Password rules

Registration rejects weak passwords. A password must be at least
8 characters long and contain an uppercase letter, a lowercase
letter, a digit and a symbol. That is enforced in `strong()` in
`auth_app.py`. It is a simple rule, not a perfect one — a long
passphrase can be stronger than a short complicated password — but
it stops the weakest choices, like `password` or `12345678`.

### Brute-force protection

A **brute-force attack** is just guessing passwords over and over.
Two things slow it down here:

- **Failed-attempt tracking.** Every wrong password for a user adds
  1 to that user's `failed` count in `users.json`.
- **Lockout.** After 5 failed attempts, the account is locked
  (`locked: true`). While locked, even the correct password is
  refused. The demo shows this with alice.

Lockout has a trade-off worth knowing: an attacker who knows a
username can lock that person out on purpose. Real systems handle
that with unlock steps (email reset, waiting time, admin unlock).
This project keeps the simple version — lock after 5 — so the idea
is easy to see.

### Logging

Every login attempt is written to `auth.log`, one line per attempt,
with a timestamp, the username, what happened (`login`,
`login-locked`, `otp`, `otp-expired`, `otp-max-attempts`) and
`SUCCESS` or `FAIL`. Logging matters for two reasons: you can spot
an attack in progress (many failures for one user), and after an
incident you can reconstruct what happened. The log never records
passwords or OTP values.

## Part 2: OTP — a second factor

A password alone is one factor. **Multi-factor authentication**
adds a second, different kind of check. Here the second factor is a
**one-time password (OTP)**: a short code that works once and then
dies.

### How the OTP works here

1. After the password is accepted, `generate_otp()` makes a 6-digit
   code using Python's `secrets` module. `secrets` is designed for
   security — unlike the normal `random` module, its output is not
   predictable.
2. The OTP is written to `otp_store.txt` as one line:

   ```
   bob,482913,1794186497,0
   ```

   That is: username, OTP value, expiry time (a Unix timestamp),
   and tries used so far (0).
3. The user types the code back in. `verify_otp()` checks it.

### The OTP rules, and why each one exists

- **6 digits.** Short enough to type, long enough that guessing it
  (1 in a million) is impractical within the other limits.
- **Expires in 60 seconds.** If someone intercepts an OTP, they
  have a minute at most. An expired OTP is deleted from
  `otp_store.txt` when it is checked, and the attempt is logged as
  `otp-expired`.
- **Maximum 3 wrong attempts.** After the third wrong guess the OTP
  is deleted. An attacker cannot sit there guessing all million
  combinations.
- **Single use.** A correct OTP is deleted immediately after it
  passes. Trying the same code again finds no OTP at all — the demo
  shows this. Reusing a stolen code is impossible.
- **Removed after use or expiry.** There is no leftover code lying
  around in the file to be found later.

In a real system the OTP would be sent to the user's phone or email,
not shown on screen. This project stores it in a file so you can
watch the whole mechanism work. The interactive mode prints the OTP
as a demo convenience — in production you would never do that.

## Part 3: JWT tokens

Once the password and the OTP have both passed, the user has proved
who they are. Typing a password on every page would be annoying and
risky, so the system hands them a **token** instead: proof that
they already logged in.

### What a token is

This project uses a **JWT (JSON Web Token)**. A JWT has three
parts — a header, a payload, and a signature — joined by dots.
The payload here is small:

```json
{"user": "bob", "exp": 1794186497}
```

`exp` is the expiry time. The signature is made with a secret key
(`SECRET` in `auth_app.py`) using HMAC-SHA256. Anyone can read the
payload, but nobody can change it — changing `user` to `alice`, for
example — without the secret, because the signature would no longer
match.

If `pyjwt` is not installed, the program uses a simple signed-token
fallback: the payload is base64-encoded and signed the same way
with HMAC-SHA256. The idea is identical; only the format differs.

> **Important:** the secret key in this project is a demo value
> written in the code. In a real system it must be a long random
> secret kept outside the code (an environment variable or a secret
> manager). Anyone who knows the secret can forge tokens for any user.

### How tokens are stored and checked

- `create_token()` makes a token valid for 15 minutes and appends a
  line to `tokens.txt`: username, token, `active`.
- `validate_token()` checks, in order: is the token in `tokens.txt`
  at all? Is its status `active`? Is the signature valid? Has it
  expired? Only if all four pass does it return the username.
- `protected_resource()` calls `validate_token()` first. With no
  token, a revoked token, a forged token or an expired token, it
  prints `ACCESS DENIED` and shows nothing.

### Expiry and revocation

- **Expiry** is automatic: after 15 minutes the token's `exp`
  time has passed and it is rejected. Short-lived tokens limit the
  damage if one is stolen.
- **Revocation** is manual: `revoke_token()` changes the token's
  status in `tokens.txt` from `active` to `revoked`. A revoked token
  is rejected even before its 15 minutes are up. That is how you
  log someone out, or kill a token you suspect is stolen.

A token is not a password — it is a short-lived pass that proves a
login already happened, and it can be taken away.

## Expected output

Running `python3 auth_app.py` prints something like this (OTP values
and times will differ on your run):

```
============================================================
Demo: password -> OTP -> token -> resource
============================================================
Register: alice created.
Stored fields: username, password_hash, failed, locked
Plain-text password stored: False

-- wrong passwords, then lockout --
Login: wrong password (1/5).
Login: wrong password (2/5).
Login: wrong password (3/5).
Login: wrong password (4/5).
Login: wrong password (5/5).
Login: alice is now LOCKED.

-- correct password while locked --
Login: alice is LOCKED after 5 failed attempts.

-- full login with a fresh user: password, OTP, token --
Register: bob created.
Login: bob password OK.
OTP: generated for bob, valid 60s, expires 20:10:28.
otp_store.txt holds username, OTP value, expiry, tries.
OTP: wrong try, then correct OTP
OTP: wrong (1/3). Try again.
OTP: correct. OTP removed (single use).
Token: created for bob, valid 15 min.
Token stored in tokens.txt (status: active).

-- protected resource --
Token: valid for bob.
Protected resource: welcome bob, access granted.
Secret data: account balance $1,250.00 (demo only).

-- reuse the same OTP --
OTP: no OTP found for this user.

-- revoke token, try again --
Token: revoked.
Token: status is revoked. REJECTED.
Protected resource: ACCESS DENIED (no valid token).

-- no token at all --
Token: not found in tokens.txt. REJECTED.
Protected resource: ACCESS DENIED (no valid token).

Demo done. Files: users.json, auth.log, otp_store.txt, tokens.txt
```

Interactive mode is a conversation instead: it asks for a username
(and a password if the user is new), then a password, then the OTP,
then shows the protected resource and asks if you want to revoke
the token.

## Tests

`test_auth.py` runs 29 checks and prints `PASS` or `FAIL` for each,
then a total. It covers:

- Weak and duplicate registration rejected; no plain-text password
  stored; correct login passes, wrong login fails.
- Failed count tracked; locked after 5 failures; locked user cannot
  log in; `auth.log` has the attempts.
- OTP stored with username, 6-digit code and ~60s expiry; wrong OTP
  fails, correct OTP passes, OTP removed after use, OTP not reusable,
  OTP removed after 3 wrong tries, expired OTP rejected.
- Token stored in `tokens.txt`; valid token accepted; protected
  resource works with a token and fails without one; forged token
  rejected; expired token rejected; revoke works; revoked token
  rejected.

Result on Nov 8, 2026: **29 passed, 0 failed.**

```bash
python3 test_auth.py
```

## Threats this project is designed against

A short version of the analysis that goes with this code:

| Threat | What happens | Mitigation in this project |
| --- | --- | --- |
| Plain-text password leak | A stolen user file gives away every password. | Passwords are stored only as salted hashes. |
| Brute force | An attacker guesses passwords repeatedly. | 5 failed attempts lock the account; every attempt is logged. |
| OTP interception | An attacker reads a code in transit. | 60-second expiry, 3-attempt limit, single use. |
| OTP reuse | A stolen code is used again later. | The code is deleted the moment it is used. |
| Token forgery | An attacker edits a token to become someone else. | HMAC signature — any change breaks the signature. |
| Token replay | A stolen token is reused. | 15-minute expiry and revocation in `tokens.txt`. |
| Weak passwords | Easy passwords are guessed first. | Registration enforces length and character rules. |

Things this project does **not** do: it does not send OTPs over a
real channel, it does not unlock a locked account by itself, it does
not rate-limit by IP address, and `users.json` is a plain file, not a
database. Those are deliberate simplifications for a learning project.

## Glossary

| Term | Meaning |
| --- | --- |
| Authentication | Proving you are who you say you are. |
| Password hash | A one-way fingerprint of a password. You can check a password against it, but you cannot reverse it. |
| Salt | Random data mixed into a hash so the same password gives a different hash for each user. |
| bcrypt | A password-hashing algorithm designed to be slow on purpose. |
| PBKDF2 | Password-Based Key Derivation Function 2 — repeats hashing many times to slow down guessing. |
| Brute force | Guessing passwords over and over until one works. |
| Lockout | Blocking an account after too many failed attempts. |
| OTP | One-time password — a short code that works once, then dies. |
| Second factor / MFA | A second, different kind of check after the password (multi-factor authentication). |
| `secrets` | Python's module for generating numbers and tokens that must not be predictable. |
| JWT | JSON Web Token — a signed, self-contained token proving a login happened. |
| Token expiry (`exp`) | The time after which a token is no longer valid. |
| Revocation | Deliberately cancelling a token before it expires. |
| Protected resource | A page or piece of data that only logged-in users may see. |
| HMAC | A way of signing data with a secret key so tampering can be detected. |
| SQL injection / XSS | Attack techniques where malicious input is treated as code. This project uses parameterised queries and escaping where relevant, and input validation throughout. |

## Limitations

- The demo secret key is written in the code — fine for learning,
  unsafe for production. Use a long random secret stored outside
  the code.
- The OTP is stored in a plain file and shown in interactive mode
  for demonstration. A real system sends it over a separate channel
  and never displays it.
- `users.json` is a file, not a database. It works for a small
  project; it does not handle many users at once or concurrent writes.
- A locked account has no unlock flow here — you would add a reset
  or a waiting period in a real system.
- The token fallback (when `pyjwt` is missing) is a simple signed
  token, not a standards-compliant JWT. Use `pyjwt` for anything real.
