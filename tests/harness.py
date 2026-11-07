"""Shared setup: a throwaway copy of the local database, a super admin and a
school admin with known passwords, and Flask test clients."""
import os, shutil, sys, tempfile, re
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="btsp-test-")
shutil.copy(os.path.join(ROOT, "database.db"), os.path.join(TMP, "database.db"))
os.makedirs(os.path.join(TMP, "uploads"))
os.environ.update(BTSP_DB_PATH=os.path.join(TMP, "database.db"),
                  BTSP_UPLOAD_DIR=os.path.join(TMP, "uploads"),
                  SECRET_KEY="test-secret")
sys.path.insert(0, ROOT)
import app as appmod  # noqa: E402
generate_password_hash = appmod.generate_password_hash
app = appmod.app
app.config["TESTING"] = True

with app.app_context():
    db = appmod.get_db()
    for name, role in (("t_super", "super"), ("t_school", "school")):
        db.execute("DELETE FROM admin_user WHERE username = ?", (name,))
        db.execute("INSERT INTO admin_user (username, password_hash, role, full_name) VALUES (?,?,?,?)",
                   (name, generate_password_hash("Test-pass-123"), role, name))
    db.execute("DELETE FROM auth_attempts")
    db.commit()

FAILS = []
def check(label, cond, detail=""):
    print(("  ok    " if cond else "  FAIL  ") + label + ("" if cond else "  -> " + str(detail)[:300]))
    if not cond:
        FAILS.append(label)

def client_as(username=None):
    c = app.test_client()
    if username:
        r = c.post("/admin/login", data={"username": username, "password": "Test-pass-123"})
        assert r.status_code in (302, 303), ("login failed", r.status_code, r.data[:300])
    return c

def q(sql, args=()):
    with app.app_context():
        return appmod.get_db().execute(sql, args).fetchall()

def done():
    print()
    print("FAILED: %d" % len(FAILS) if FAILS else "ALL PASSED")
    for f in FAILS: print("   -", f)
    shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(1 if FAILS else 0)
