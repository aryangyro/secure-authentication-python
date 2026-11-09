# Work log — Nov 8, 2026

## What I did today
- Built a secure authentication system in one Python file, `auth_app.py`
  (290 lines): password registration and login with salted hashing,
  brute-force lockout after 5 failed attempts, login logging, a
  file-based one-time password (OTP) as a second factor, and JWT tokens
  with expiry and revocation guarding a protected resource.
- The OTP uses `secrets` for a 6-digit code, stored in `otp_store.txt`
  with username, OTP value and expiry, valid for 60 seconds, max 3 wrong
  attempts, single-use and removed after use or expiry.
- Tokens are stored in `tokens.txt` with an active/revoked status, valid
  for 15 minutes, and are required to access the protected resource.
- Wrote `test_auth.py` with 29 automated tests, and a beginner-friendly
  README explaining authentication, hashing, OTP and tokens in plain
  English, with a glossary and a threats table.

## Test results
- `pip install bcrypt pyjwt` worked (bcrypt 5.0.0, pyjwt 2.15.1).
- Demo: exit 0. Wrong passwords 1–5 lock the account; the correct
  password is refused while locked; the full flow (password → OTP →
  token → protected resource) works; OTP reuse fails; a revoked token
  is refused; no token is refused.
- `test_auth.py`: **29 passed, 0 failed** — weak/duplicate registration,
  no plain-text password stored, lockout after 5, auth.log entries, OTP
  format/expiry/3-attempt limit/reuse/expiry, token storage/validation/
  forgery/expiry/revocation, protected resource with and without a token.
- Interactive mode tested with a scripted session (new user, full login
  succeeded, exit 0).

## Challenges
- The script first came out at 323 lines, over the concise target, so it
  was trimmed to 290 lines without cutting features.
- A demo bug: the token was created for the wrong user after the lockout
  test switched to a fresh user — caught by reading the demo output
  ("welcome alice" instead of "welcome bob") and fixed.
- Keeping the code short while covering three layers (password, OTP,
  token) in one file, without it turning into an over-engineered
  framework.
