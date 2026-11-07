"""Every route in the app, every role: nothing may answer 500."""
import re
from harness import *

# a real id for each kind of object, so detail/edit pages are exercised
def first(sql):
    r = q(sql); return r[0][0] if r else 1
IDS = {
    "formation": first("SELECT id FROM formations LIMIT 1"),
    "certificate": first("SELECT id FROM certificates LIMIT 1"),
    "testimonial": first("SELECT id FROM testimonials LIMIT 1"),
    "gallery": first("SELECT id FROM gallery LIMIT 1"),
    "section": first("SELECT id FROM custom_sections LIMIT 1"),
    "faq": first("SELECT id FROM faqs LIMIT 1"),
    "session": first("SELECT id FROM training_sessions LIMIT 1"),
    "partner": first("SELECT id FROM partners LIMIT 1"),
    "course": first("SELECT id FROM courses LIMIT 1"),
    "module": first("SELECT id FROM course_modules LIMIT 1"),
    "student": first("SELECT id FROM students LIMIT 1"),
    "user": first("SELECT id FROM admin_user WHERE username='t_school'"),
    "teacher": first("SELECT id FROM teachers LIMIT 1"),
    "class": first("SELECT id FROM school_classes WHERE kind='annual' LIMIT 1"),
    "short": first("SELECT id FROM school_classes WHERE kind='short' LIMIT 1"),
    "pupil": first("SELECT id FROM class_students LIMIT 1"),
}
def guess(endpoint):
    for key, kw in (("short", "short"), ("module", "module"), ("quiz", "module"), ("course", "course"),
                    ("certificate", "certificate"), ("testimonial", "testimonial"), ("gallery", "gallery"),
                    ("section", "section"), ("faq", "faq"), ("session", "session"), ("partner", "partner"),
                    ("student", "student"), ("user", "user"), ("teacher", "teacher"), ("class", "class"),
                    ("pupil", "pupil"), ("formation", "formation")):
        if key in endpoint:
            return IDS[kw]
    return 1

def build(rule, endpoint, real=True):
    url = rule.rule
    for arg in rule.arguments:
        if arg == "lang": val = "en"
        elif arg == "slug": val = "services"
        elif arg in ("filename",): val = "hero-btsp.jpg"
        elif arg == "year": val = "2026"
        elif arg == "month": val = "11"
        elif arg in ("student_id",) and "paiements" in url: val = str(IDS["pupil"])
        else: val = str(guess(endpoint) if real else 999999)
        url = re.sub(r"<(?:[^:<>]+:)?%s>" % arg, val, url)
    return url

admin, school, anon = client_as("t_super"), client_as("t_school"), app.test_client()
stu = app.test_client()
stu.post("/student/signup", data={"email": "sweep@example.com", "password": "Sweep-pass-123", "first_name": "S", "last_name": "W"})

skip_get = {"admin_logout", "student_logout", "static"}
gets, posts = [], []
for rule in app.url_map.iter_rules():
    if rule.endpoint in skip_get or "logout" in rule.rule: continue
    (gets if "GET" in rule.methods else posts).append(rule)
print("GET routes: %d, POST-only routes: %d" % (len(gets), len(posts)))

print("\nGET every page as super admin, school admin, student and anonymous")
for rule in sorted(gets, key=lambda r: r.rule):
    url = build(rule, rule.endpoint)
    for who, c in (("super", admin), ("school", school), ("student", stu), ("anon", anon)):
        r = c.get(url)
        check("%-7s GET %-55s %d" % (who, url, r.status_code), r.status_code < 500, r.data[:400])
    # super admin must actually reach admin pages (not be bounced)
    if url.startswith("/admin") and rule.endpoint not in ("admin_login",):
        r = admin.get(url)
        check("super reaches %s" % url, r.status_code in (200, 302, 404) and "/admin/login" not in (r.headers.get("Location") or ""), (r.status_code, r.headers.get("Location")))

print("\nPOST every write route with empty and bogus data (ids that do not exist)")
for rule in sorted(posts + [r for r in gets if "POST" in r.methods], key=lambda r: r.rule):
    if rule.endpoint in ("admin_login", "student_login", "student_signup", "submit_inscription", "submit_proposal"):
        continue
    url = build(rule, rule.endpoint, real=False)
    for who, c in (("super", admin), ("school", school), ("anon", anon)):
        r = c.post(url, data={})
        check("%-6s POST %-55s %d" % (who, url, r.status_code), r.status_code < 500, r.data[:400])
        r = c.post(url, data={"amount": "1e999", "price": "abc", "sort_order": "x", "id": "-1",
                             "class_id": "abc", "student_id": "0", "kind": "pack", "item": "x"})
        check("%-6s POST junk %-50s %d" % (who, url, r.status_code), r.status_code < 500, r.data[:400])
done()
