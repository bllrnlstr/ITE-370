import os
import re
import json
import time
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv


load_dotenv)
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key-change-me")
DB_NAME    = os.getenv("DB_NAME", "users.json")


logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def log(msg, level="info"):
    print(f"[LOG] {msg}")
    getattr(logging, level)(msg)


def load_db():
    if os.path.exists(DB_NAME):
        with open(DB_NAME, "r") as f:
            return json.load(f)
    return {"users": {}, "sessions": {}, "login_attempts": {}}

def save_db(db):
    with open(DB_NAME, "w") as f:
        json.dump(db, f, indent=2)

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except Exception:
        return False


# INPUT VALIDATION & SANITIZATIONl

def validate_username(username: str) -> bool:
    """Allow only alphanumeric usernames, 3-20 characters."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_password(password: str) -> bool:
    """Require min 8 chars, 1 uppercase, 1 digit."""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True

def sanitize_input(text: str) -> str:
    """Remove potentially dangerous characters."""
    return re.sub(r'[<>\'\";\\/]', '', text).strip()


def safe_error(msg: str) -> str:
    """Return a generic error message to the user (never expose internals)."""
    log(f"Error occurred: {msg}", level="error")
    return "An error occurred. Please try again."


# SESSION 

SESSION_TIMEOUT_MINUTES = 30

def create_session(username: str, db: dict) -> str:
    """Generate a secure session token."""
    token = secrets.token_hex(32)
    expiry = (datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)).isoformat()
    db["sessions"][token] = {"username": username, "expiry": expiry}
    save_db(db)
    log(f"Session created for user: {username}")
    return token

def validate_session(token: str, db: dict) -> str | None:
    """Validate session token; return username or None if expired/invalid."""
    session = db["sessions"].get(token)
    if not session:
        return None
    if datetime.now() > datetime.fromisoformat(session["expiry"]):
        del db["sessions"][token]
        save_db(db)
        log(f"Session expired for token: {token[:8]}...")
        return None
    return session["username"]

def delete_session(token: str, db: dict):
    """Delete session on logout."""
    if token in db["sessions"]:
        user = db["sessions"][token].get("username")
        del db["sessions"][token]
        save_db(db)
        log(f"Session deleted for user: {user}")


#  Login Attempt Limiting

MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def check_lockout(username: str, db: dict) -> bool:
    """Return True if account is locked out."""
    attempts = db["login_attempts"].get(username, {})
    count = attempts.get("count", 0)
    locked_until = attempts.get("locked_until")

    if locked_until:
        if datetime.now() < datetime.fromisoformat(locked_until):
            remaining = (datetime.fromisoformat(locked_until) - datetime.now()).seconds // 60
            print(f"  Account locked. Try again in {remaining} minute(s).")
            return True
        else:
            db["login_attempts"][username] = {"count": 0}
            save_db(db)

    return False

def record_failed_attempt(username: str, db: dict):
    """Record a failed login attempt; lock account if limit exceeded."""
    attempts = db["login_attempts"].get(username, {"count": 0})
    attempts["count"] = attempts.get("count", 0) + 1

    if attempts["count"] >= MAX_ATTEMPTS:
        attempts["locked_until"] = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        print(f"  Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.")
        log(f"Account locked: {username}", level="warning")

    db["login_attempts"][username] = attempts
    save_db(db)

def clear_attempts(username: str, db: dict):
    """Clear failed attempts on successful login."""
    db["login_attempts"].pop(username, None)
    save_db(db)
    
def register(db: dict):
    print("\n--- REGISTER ---")
    username = sanitize_input(input("  Username: "))
    password = input("  Password: ")

    if not validate_username(username):
        print("  Invalid username. Use 3-20 alphanumeric characters only.")
        return
    if not validate_password(password):
        print("  Weak password. Must be 8+ chars, include uppercase and a number.")
        return
    if username in db["users"]:
        print("  Username already exists.")
        return

    db["users"][username] = {"password": hash_password(password)}
    save_db(db)
    log(f"New user registered: {username}")
    print(f"  User '{username}' registered successfully!")

def login(db: dict) -> str | None:
    print("\n--- LOGIN ---")
    username = sanitize_input(input("  Username: "))
    password = input("  Password: ")

    if check_lockout(username, db):
        return None

    user = db["users"].get(username)
    if not user or not verify_password(password, user["password"]):
        record_failed_attempt(username, db)
        print("  Invalid username or password.")
        log(f"Failed login attempt for: {username}", level="warning")
        return None

    clear_attempts(username, db)
    token = create_session(username, db)
    print(f"  Login successful! Welcome, {username}.")
    print(f"  Session token: {token[:16]}... (session expires in {SESSION_TIMEOUT_MINUTES} mins)")
    return token

def logout(token: str, db: dict):
    delete_session(token, db)
    print("  Logged out successfully.")

def dashboard(token: str, db: dict):
    username = validate_session(token, db)
    if not username:
        print("  Session expired. Please log in again.")
        return
    print(f"\n  Welcome to your dashboard, {username}!")
    print(f"  Your data is protected with hashed passwords and session tokens.")

def secure_delete(filepath: str, passes: int = 3):
    """Overwrite file with random bytes before deleting."""
    if not os.path.exists(filepath):
        print(f"  File not found: {filepath}")
        return
    size = os.path.getsize(filepath)
    with open(filepath, "ba+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
    os.remove(filepath)
    log(f"Secure delete performed on: {filepath}")
    print(f"  '{filepath}' securely deleted ({passes} overwrite passes).")


def main():
    print("=" * 45)
    print("   ITE 370 - Secure Python Application")
    print("=" * 45)

    db = load_db()
    session_token = None

    while True:
        print("\n[MENU]")
        print("  1. Register")
        print("  2. Login")
        print("  3. Dashboard (requires login)")
        print("  4. Logout")
        print("  5. Secure Delete a file")
        print("  6. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            register(db)
        elif choice == "2":
            session_token = login(db)
        elif choice == "3":
            if session_token:
                dashboard(session_token, db)
            else:
                print("  Please log in first.")
        elif choice == "4":
            if session_token:
                logout(session_token, db)
                session_token = None
            else:
                print("  Not logged in.")
        elif choice == "5":
            fname = input("  Enter filename to securely delete: ").strip()
            secure_delete(fname)
        elif choice == "6":
            print("  Goodbye!")
            break
        else:
            print("  Invalid choice.")

if __name__ == "__main__":
    main()
