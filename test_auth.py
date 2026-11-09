"""Tests for auth_app.py. Run: python3 test_auth.py"""
import json, time, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import auth_app as a

passed = failed = 0
def check(name, cond):
    global passed, failed
    print(("PASS" if cond else "FAIL"), "-", name)
    if cond: passed += 1
    else: failed += 1

# fresh state
for f in (a.USERS, a.LOG, a.OTP_FILE, a.TOKENS):
    if f.exists(): f.unlink()

# Task 1
check("weak password rejected", a.register("u1", "weak") is False)
check("strong password registered", a.register("alice", "Str0ng!Pass") is True)
check("duplicate register rejected", a.register("alice", "Str0ng!Pass") is False)
users = a.load_users()
check("no plaintext password stored",
      "password" not in users["alice"] and users["alice"]["password_hash"] != "Str0ng!Pass")
check("correct login passes", a.login("alice", "Str0ng!Pass") is True)
check("wrong password fails", a.login("alice", "Wrong!Pass1") is False)
check("failed count tracked", a.load_users()["alice"]["failed"] == 1)
for _ in range(4):
    a.login("alice", "Wrong!Pass1")
check("locked after 5 fails", a.load_users()["alice"]["locked"] is True)
check("locked user cannot log in", a.login("alice", "Str0ng!Pass") is False)
log = a.LOG.read_text()
check("auth.log has 7 login attempts", log.count("login") >= 7)
# unlock for the rest of the tests
users = a.load_users(); users["alice"]["failed"] = 0; users["alice"]["locked"] = False
a.save_users(users)

# Task 2
check("login ok after unlock", a.login("alice", "Str0ng!Pass") is True)
otp = a.generate_otp("alice")
parts = a.OTP_FILE.read_text().strip().split(",")
check("otp_store.txt has username, otp, expiry", len(parts) == 4 and parts[0] == "alice" and len(parts[1]) == 6)
check("otp expiry is ~60s away", 30 < int(parts[2]) - int(time.time()) <= 60)
check("wrong OTP fails", a.verify_otp("alice", "000000") is False)
check("correct OTP passes", a.verify_otp("alice", otp) is True)
check("OTP removed after use", not a.OTP_FILE.exists())
check("OTP not reusable", a.verify_otp("alice", otp) is False)
# max 3 attempts
otp2 = a.generate_otp("alice")
a.verify_otp("alice", "111111"); a.verify_otp("alice", "222222")
check("OTP removed after 3 wrong tries", a.verify_otp("alice", "333333") is False and not a.OTP_FILE.exists())
# expired OTP
otp3 = a.generate_otp("alice")
u, o, e, tr = a.OTP_FILE.read_text().strip().split(",")
a.OTP_FILE.write_text(f"{u},{o},{int(time.time()) - 5},{tr}\n")
check("expired OTP rejected", a.verify_otp("alice", otp3) is False and not a.OTP_FILE.exists())

# Task 3
otp4 = a.generate_otp("alice")
check("OTP ok before token", a.verify_otp("alice", otp4) is True)
token = a.create_token("alice")
check("token stored in tokens.txt", token in a.TOKENS.read_text())
check("valid token accepted", a.validate_token(token) == "alice")
check("protected resource with token", a.protected_resource(token) is True)
check("protected resource without token", a.protected_resource("bad-token") is False)
check("forged token rejected", a.validate_token(token[:-4] + "xxxx") is None)
# expired token
old = a._encode({"user": "alice", "exp": int(time.time()) - 10})
with open(a.TOKENS, "a") as f: f.write(f"alice,{old},active\n")
check("expired token rejected", a.validate_token(old) is None)
check("revoke works", a.revoke_token(token) is True)
check("revoked token rejected", a.validate_token(token) is None)
check("protected resource after revoke", a.protected_resource(token) is False)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
