# Common Mistakes in Authentication

These are mistakes that show up again and again in login systems, including
in code written by people who know better. Each one looks harmless until it
is not. The examples use the code in this project (`auth_app.py`) where
possible, so you can see the right version next to the wrong one.

## 1. Generating OTPs or tokens with `random`

Python's `random` module is fine for games and shuffling a playlist. It is
not fine for security, because its output can be predicted if someone sees
enough of it. An OTP made with `random.randint(100000, 999999)` is guessable
in a way an OTP made with `secrets` is not.

**Wrong:**

```python
import random
otp = random.randint(100000, 999999)  # predictable
```

**Right:**

```python
import secrets
otp = secrets.randbelow(900000) + 100000  # unpredictable
```

This project uses `secrets` for OTPs. Anywhere a value must not be guessed —
OTPs, tokens, password-reset links, salts — use `secrets`, never `random`.

## 2. Comparing secrets with `==`

Comparing two strings with `==` stops at the first character that differs.
That sounds harmless, but it leaks timing information: a guess that matches
the first three characters takes slightly longer to reject than a guess that
matches none. An attacker who measures response times carefully can work out
a token or hash one character at a time.

**Wrong:**

```python
if user_token == stored_token:
    grant_access()
```

**Right:**

```python
import hmac
if hmac.compare_digest(user_token, stored_token):
    grant_access()
```

`hmac.compare_digest` always takes the same amount of time, whatever the
input. Use it for tokens, hashes, OTPs — anything secret that gets compared.

## 3. Logging passwords, OTPs or tokens

Logs are supposed to help you find out what went wrong. They become the
problem when they record the very secrets they are meant to protect. A log
line like `Login failed for bob, password hunter2, OTP 482913` hands an
attacker everything they need, and logs get copied, backed up and shared
far more freely than password files do.

This project logs the username, the event and SUCCESS or FAIL — never the
password or the OTP value. Check your own logging the same way: if a line
would help an attacker log in, it should not be in the log.

## 4. Checking a token's expiry before its signature

A JWT carries its own expiry time in the payload, and it is tempting to
check that first: if it is expired, reject it and move on. The problem is
that the payload is not trustworthy until the signature has been verified.
Anyone can write a token that says `exp` is next year. Expiry only means
something after you know the token was really issued by your system.

Always verify in this order: signature first, then expiry, then anything
else. In this project `validate_token()` checks the signature before it
trusts the `exp` value.

## 5. Keeping the signing secret in the code

The demo in this project has a secret key written in `auth_app.py`, and the
README says plainly that this is a demo shortcut. In a real system it is a
serious mistake: anyone who can read the code — a leaked repo, a stolen
laptop, a contractor who kept a copy — can forge a token for any user.

Keep secrets out of the code. Load them from an environment variable or a
secret manager, and make the program refuse to start if the secret is
missing rather than falling back to a default one.

```python
import os
SECRET = os.environ["AUTH_SECRET"]  # fails loudly if not set
```

## 6. Letting old tokens live on after a password change

When a user changes their password — usually because they think it was
stolen — they expect the attacker to be locked out. But if their old JWT
is still valid for its remaining 15 minutes, or longer in a system with
long-lived tokens, the attacker keeps access anyway. Changing the password
without invalidating existing sessions only locks the front door while
the back door stays open.

Fix it by revoking all of a user's tokens when their password changes, or
by storing a token version per user and bumping it on password change so
older tokens stop validating. This project keeps tokens in `tokens.txt`
with an `active` or `revoked` status — the same mechanism works for this.

## 7. Rate-limiting the password but not the OTP

Lockout after 5 wrong passwords is good, and this project does it. But
many systems forget the second door: the OTP step. If an attacker can try
OTP codes without limit, a 6-digit code is only a million guesses away,
and a million guesses is fast for a script.

Rate-limit every guessable step, not just the first one. This project
limits OTP attempts to 3 and deletes the code after that. The same idea
applies to password-reset codes and any other short code a user types in.

## How to spot these in your own code

- Search for `random.` in any file that handles logins, tokens or codes.
  Every hit is worth a second look.
- Search for `==` used to compare a token, hash or code. Replace it with
  `hmac.compare_digest`.
- Read one page of your own logs. If you can see a password, an OTP or a
  token in there, fix the logging.
- Change your password in your own system, then try the old token. If it
  still works, your password change is only half a fix.
