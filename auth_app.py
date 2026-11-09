#!/usr/bin/env python3
"""Secure authentication: salted passwords, file OTP, JWT tokens.
Demo: python3 auth_app.py | Interactive: --interactive"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

BASE = Path(__file__).parent
USERS = BASE / "users.json"
LOG = BASE / "auth.log"
OTP_FILE = BASE / "otp_store.txt"
TOKENS = BASE / "tokens.txt"
MAX_FAILS = 5          # lock account after 5 bad logins
OTP_EXPIRY = 60        # OTP valid for 60 seconds
OTP_ATTEMPTS = 3       # max 3 wrong OTP tries
TOKEN_EXPIRY = 15 * 60  # token valid for 15 minutes
SECRET = "demo-secret-key-change-in-production"

def load_users():
    return json.loads(USERS.read_text()) if USERS.exists() else {}

def save_users(users):
    USERS.write_text(json.dumps(users, indent=2))

def log_attempt(username, action, ok):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG, "a") as f:
        f.write(f"{stamp} | {username} | {action} | {'SUCCESS' if ok else 'FAIL'}\n")

def hash_password(password):
    """Salted hash. bcrypt if installed, else PBKDF2 fallback."""
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return f"pbkdf2$200000${salt.hex()}${dk.hex()}"

def check_password(password, stored):
    if stored.startswith(("$2b$", "$2a$")):
        import bcrypt
        return bcrypt.checkpw(password.encode(), stored.encode())
    try:
        _, iters, salt, want = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk, bytes.fromhex(want))
    except Exception:
        return False

def strong(pw):
    """8+ chars, upper, lower, digit, symbol."""
    return (len(pw) >= 8 and any(c.isupper() for c in pw)
            and any(c.islower() for c in pw) and any(c.isdigit() for c in pw)
            and any(not c.isalnum() for c in pw))

def register(username, password):
    users = load_users()
    if username in users:
        print(f"Register: {username} already exists.")
        return False
    if not strong(password):
        print("Register: weak password. Need 8+ chars, upper, lower, digit, symbol.")
        return False
    users[username] = {"password_hash": hash_password(password),
                       "failed": 0, "locked": False}
    save_users(users)
    print(f"Register: {username} created.")
    print("Stored fields: username, password_hash, failed, locked")
    print("Plain-text password stored: False")
    return True

def login(username, password):
    """Check a password. Locks the account after 5 failures."""
    users = load_users()
    user = users.get(username)
    if not user:
        log_attempt(username, "login", False)
        print(f"Login: {username} not found.")
        return False
    if user["locked"]:
        log_attempt(username, "login-locked", False)
        print(f"Login: {username} is LOCKED after {MAX_FAILS} failed attempts.")
        return False
    if check_password(password, user["password_hash"]):
        user["failed"] = 0
        save_users(users)
        log_attempt(username, "login", True)
        print(f"Login: {username} password OK.")
        return True
    user["failed"] += 1
    if user["failed"] >= MAX_FAILS:
        user["locked"] = True
        print(f"Login: wrong password ({user['failed']}/{MAX_FAILS}).")
        print(f"Login: {username} is now LOCKED.")
    else:
        print(f"Login: wrong password ({user['failed']}/{MAX_FAILS}).")
    save_users(users)
    log_attempt(username, "login", False)
    return False

def generate_otp(username):
    """6-digit OTP from secrets, saved to otp_store.txt."""
    otp = f"{secrets.randbelow(900000) + 100000}"
    expiry = int(time.time()) + OTP_EXPIRY
    OTP_FILE.write_text(f"{username},{otp},{expiry},0\n")
    print(f"OTP: generated for {username}, valid {OTP_EXPIRY}s, expires "
          f"{time.strftime('%H:%M:%S', time.localtime(expiry))}.")
    print("otp_store.txt holds username, OTP value, expiry, tries.")
    return otp

def _read_otp():
    if not OTP_FILE.exists():
        return None
    u, o, e, tr = OTP_FILE.read_text().strip().split(",")
    return {"username": u, "otp": o, "expiry": int(e), "tries": int(tr)}

def _remove_otp():
    OTP_FILE.unlink(missing_ok=True)

def verify_otp(username, entered):
    """Check OTP: correct, not expired, max 3 tries, single use."""
    rec = _read_otp()
    if not rec or rec["username"] != username:
        print("OTP: no OTP found for this user.")
        return False
    if time.time() > rec["expiry"]:
        _remove_otp()
        log_attempt(username, "otp-expired", False)
        print("OTP: EXPIRED. Removed from otp_store.txt.")
        return False
    if entered == rec["otp"]:
        _remove_otp()
        log_attempt(username, "otp", True)
        print("OTP: correct. OTP removed (single use).")
        return True
    rec["tries"] += 1
    if rec["tries"] >= OTP_ATTEMPTS:
        _remove_otp()
        log_attempt(username, "otp-max-attempts", False)
        print(f"OTP: wrong ({rec['tries']}/{OTP_ATTEMPTS}). "
              "Max attempts reached, OTP removed.")
    else:
        OTP_FILE.write_text(f"{username},{rec['otp']},{rec['expiry']},{rec['tries']}\n")
        print(f"OTP: wrong ({rec['tries']}/{OTP_ATTEMPTS}). Try again.")
    log_attempt(username, "otp", False)
    return False

def _encode(payload):
    try:
        import jwt
        return jwt.encode(payload, SECRET, algorithm="HS256")
    except ImportError:  # simple signed token fallback
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        return f"{body}.{sig}"

def _decode(token):
    try:
        import jwt
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except ImportError:
        body, sig = token.rsplit(".", 1)
        want = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, want):
            raise ValueError("bad signature")
        return json.loads(base64.urlsafe_b64decode(body))

def create_token(username):
    token = _encode({"user": username,
                     "exp": int(time.time()) + TOKEN_EXPIRY})
    with open(TOKENS, "a") as f:
        f.write(f"{username},{token},active\n")
    print(f"Token: created for {username}, valid 15 min.")
    print("Token stored in tokens.txt (status: active).")
    return token

def validate_token(token):
    found = None
    if TOKENS.exists():
        for line in TOKENS.read_text().splitlines():
            user, saved, status = line.split(",", 2)
            if saved == token:
                found = (user, status)
    if not found:
        print("Token: not found in tokens.txt. REJECTED.")
        return None
    user, status = found
    if status != "active":
        print(f"Token: status is {status}. REJECTED.")
        return None
    try:
        data = _decode(token)
    except Exception as e:
        print(f"Token: invalid ({e}). REJECTED.")
        return None
    if data.get("exp", 0) < time.time():
        print("Token: EXPIRED. REJECTED.")
        return None
    print(f"Token: valid for {data['user']}.")
    return data["user"]

def revoke_token(token):
    if not TOKENS.exists():
        return False
    lines, done = [], False
    for line in TOKENS.read_text().splitlines():
        user, saved, status = line.split(",", 2)
        if saved == token:
            lines.append(f"{user},{saved},revoked")
            done = True
        else:
            lines.append(line)
    TOKENS.write_text("\n".join(lines) + "\n")
    print("Token: revoked." if done else "Token: not found.")
    return done

def protected_resource(token):
    """Demo protected page: needs a valid token."""
    user = validate_token(token)
    if not user:
        print("Protected resource: ACCESS DENIED (no valid token).")
        return False
    print(f"Protected resource: welcome {user}, access granted.")
    print("Secret data: account balance $1,250.00 (demo only).")
    return True

def demo():
    print("=" * 60)
    print("Demo: password -> OTP -> token -> resource")
    print("=" * 60)
    for f in (USERS, LOG, OTP_FILE, TOKENS):
        if f.exists():
            f.unlink()
    register("alice", "Str0ng!Pass")
    print("\n-- wrong passwords, then lockout --")
    for _ in range(5):
        login("alice", "Wrong!Pass1")
    print("\n-- correct password while locked --")
    login("alice", "Str0ng!Pass")
    print("\n-- full login with a fresh user: password, OTP, token --")
    register("bob", "Str0ng!Pass")
    if login("bob", "Str0ng!Pass"):
        otp = generate_otp("bob")
        print("OTP: wrong try, then correct OTP")
        verify_otp("bob", "000000")
        if verify_otp("bob", otp):
            token = create_token("bob")
            print("\n-- protected resource --")
            protected_resource(token)
            print("\n-- reuse the same OTP --")
            verify_otp("bob", otp)
            print("\n-- revoke token, try again --")
            revoke_token(token)
            protected_resource(token)
    print("\n-- no token at all --")
    protected_resource("no-such-token")
    print("\nDemo done. Files: users.json, auth.log, otp_store.txt, tokens.txt")

def interactive():
    print("Interactive login. Type 'quit' to stop.")
    user = input("Username: ").strip()
    if user == "quit":
        return
    if user not in load_users():
        pw = input("New user - choose a password: ")
        if not register(user, pw):
            return
    pw = input("Password: ")
    if not login(user, pw):
        return
    otp = generate_otp(user)
    print(f"(Demo: your OTP is {otp})")
    if verify_otp(user, input("Enter OTP: ").strip()):
        token = create_token(user)
        protected_resource(token)
        if input("Revoke token now? (y/n): ").strip() == "y":
            revoke_token(token)

if __name__ == "__main__":
    import sys
    if "--interactive" in sys.argv:
        interactive()
    else:
        demo()
