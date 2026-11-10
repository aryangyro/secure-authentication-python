# Exercises: try the login system yourself

These use the demo in `auth_app.py`. Run `python3 auth_app.py` first
to see the full flow, then try each one on your own.

## 1. Look at a real password hash

Register a user with the password `hello123`, then open `users.json`
and find the entry. You will see a long string of random-looking
characters instead of `hello123`.

Now register a second user with the *same* password `hello123` and
compare the two hashes. They are different. That is the salt doing
its job — the same password never produces the same stored value
twice, so a stolen database cannot be cracked by looking up one hash.

## 2. Lock an account, then unlock it

Log in as `alice` with the wrong password five times in a row. On the
fifth failure the account locks. Try the correct password now — it
still fails, because a locked account stays locked.

Check `auth.log` afterwards. Every failed attempt is there with a
time, which is exactly the record you would want if someone was
guessing passwords against a real account.

## 3. Break the OTP rules (and watch them hold)

After a correct password, an OTP is written to `otp_store.txt`.
Try these, one at a time:

- Enter the wrong code three times. After the third try it stops
  working, even if you then type the right one.
- Wait more than a minute and enter the right code. It should be
  expired by then.
- Enter the right code twice. The second time it fails, because a
  used code is deleted.

Each rule exists because a code that can be guessed, reused, or kept
forever is not a second factor at all.

## 4. Revoke a token and prove it is dead

Log in fully, get a token, and use it to open the protected resource
— it works. Now revoke the token and try again with the same token.
It fails, even though the token itself has not changed. That is the
whole point of revocation: the token is just a string, and the system
decides whether it still counts.

## 5. One thing to change

The demo stores OTPs in a plain text file so you can see how they
work. In a real system, where would you send the code instead, and
what would break if that channel was not secure? Write your answer
in a sentence or two before reading on.

> One honest answer: send it by SMS or an authenticator app, and if
> that channel is not secure, an attacker who can read it can log in
> as you — the second factor is only as strong as the way it is
> delivered.
