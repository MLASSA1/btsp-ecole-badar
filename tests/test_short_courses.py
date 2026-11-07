import re
from harness import *

def stat_values(html):
    return re.findall(r'class="stat-value">([^<]*)<', html)

with app.app_context():
    db = appmod.get_db()
    db.execute("INSERT INTO teachers (first_name, last_name) VALUES ('Prof', 'TestCourte')")
    db.commit()
tid = q("SELECT id FROM teachers WHERE last_name='TestCourte'")[0]["id"]
fid = q("SELECT id FROM formations WHERE active=1 LIMIT 1")[0]["id"]

print("Short courses (formations courtes) — run as the school-role admin")
sch = client_as("t_school")
check("list page loads for school staff", sch.get("/admin/courtes").status_code == 200)
check("add form loads", sch.get("/admin/courtes/add").status_code == 200)
mk = lambda name, dur, price: sch.post("/admin/courtes/add", data={
    "name": name, "formation_id": fid, "teacher_id": tid, "duration_label": dur, "price": price,
    "room": "Salle 1", "schedule": "9h-17h", "start_date": "2026-11-20", "end_date": "2026-11-20", "active": "1"})
check("create 1-day course", mk("TEST Courte A", "1 jour", "800").status_code == 302)
check("create 3-day course", mk("TEST Courte B", "3 jours", "2000").status_code == 302)
check("junk price saved as 0, no crash", mk("TEST Courte Junk", "1 mois", "abc").status_code == 302
      and q("SELECT price FROM school_classes WHERE name='TEST Courte Junk'")[0]["price"] == 0)
A = q("SELECT id FROM school_classes WHERE name='TEST Courte A' AND kind='short'")[0]["id"]
B = q("SELECT id FROM school_classes WHERE name='TEST Courte B' AND kind='short'")[0]["id"]
J = q("SELECT id FROM school_classes WHERE name='TEST Courte Junk'")[0]["id"]
check("detail page loads", sch.get("/admin/courtes/%d" % A).status_code == 200)
check("participant form loads", sch.get("/admin/courtes/%d/participants/add" % A).status_code == 200)
sch.post("/admin/courtes/%d/participants/add" % A, data={"first_name": "Ali", "last_name": "Un", "phone": "06", "fee": ""})
sch.post("/admin/courtes/%d/participants/add" % A, data={"first_name": "Sara", "last_name": "Deux", "phone": "06", "fee": "600"})
sch.post("/admin/courtes/%d/participants/add" % B, data={"first_name": "Omar", "last_name": "TroisZz", "phone": "06", "fee": ""})
p = {r["first_name"]: r["id"] for r in q("SELECT id, first_name FROM class_students WHERE class_id IN (?,?)", (A, B))}
check("3 participants added", len(p) == 3, p)
pay = lambda cls, sid, amt: sch.post("/admin/courtes/paiement", data={"class_id": cls, "student_id": sid, "amount": amt, "method": "Espèces", "paid_on": "2026-11-20"})
pay(A, p["Ali"], "800"); pay(A, p["Sara"], "300"); pay(B, p["Omar"], "1000")
check("3 payments recorded", len(q("SELECT 1 FROM session_payments WHERE class_id IN (?,?)", (A, B))) == 3)
pay(A, p["Ali"], "0"); pay(A, p["Ali"], "-50"); pay(A, p["Ali"], "1e999")
check("zero / negative / junk amounts refused", len(q("SELECT 1 FROM session_payments WHERE class_id IN (?,?)", (A, B))) == 3)
check("payment for a participant of another course refused", pay(A, p["Omar"], "100").status_code == 404)
check("payment with missing ids refused", sch.post("/admin/courtes/paiement", data={"amount": "5"}).status_code == 400)
det = sch.get("/admin/courtes/%d" % A).data.decode()
check("detail lists both participants", "Ali" in det and "Sara" in det)

base = "/admin/courtes?teacher_id=%d" % tid
v = stat_values(sch.get(base).data.decode())
# A: expected 800 (course price) + 600 (own fee) = 1400, collected 1100; B: expected 2000, collected 1000; Junk: 0
# stats: courses, participants, collected, outstanding
check("totals over my courses: 3 courses, 3 participants, 2100 collected, 1300 outstanding",
      v[:4] == ["3", "3", "2100", "1300"], v)
v = stat_values(sch.get(base + "&duration=1+jour").data.decode())
check("filter by duration (1 jour) -> course A only", v[:4] == ["1", "2", "1100", "300"], v)
lst = sch.get(base + "&price_min=1000").data.decode()
check("filter price_min=1000 -> B only", "TEST Courte B" in lst and "TEST Courte A" not in lst)
lst = sch.get(base + "&price_min=500&price_max=900").data.decode()
check("price range 500-900 -> A only", "TEST Courte A" in lst and "TEST Courte B" not in lst)
lst = sch.get(base + "&formation_id=%d" % fid).data.decode()
check("filter by formation keeps both", "TEST Courte A" in lst and "TEST Courte B" in lst)
check("filters with junk values do not crash", sch.get("/admin/courtes?price_min=abc&teacher_id=x&status=zzz").status_code == 200)

check("short-course participants stay out of the year pupils list", "TroisZz" not in sch.get("/admin/eleves").data.decode().split("<tbody")[-1])
check("and out of the monthly payments board", "TroisZz" not in sch.get("/admin/paiements").data.decode())

sch.post("/admin/courtes/%d/edit" % B, data={"name": "TEST Courte B", "formation_id": fid, "teacher_id": tid,
         "duration_label": "3 jours", "price": "2500", "room": "", "schedule": "", "start_date": "", "end_date": "", "active": "1"})
check("edit price", q("SELECT price FROM school_classes WHERE id=?", (B,))[0]["price"] == 2500)
pid = q("SELECT id FROM session_payments WHERE class_id=? ", (B,))[0]["id"]
sch.post("/admin/courtes/paiement/%d/delete" % pid)
check("delete a payment", not q("SELECT 1 FROM session_payments WHERE id=?", (pid,)))
check("unknown course -> 404", sch.get("/admin/courtes/999999").status_code == 404)
for c in (A, B, J):
    sch.post("/admin/courtes/%d/delete" % c)
check("delete courses removes participants and payments",
      not q("SELECT 1 FROM school_classes WHERE id IN (?,?,?)", (A, B, J))
      and not q("SELECT 1 FROM class_students WHERE class_id IN (?,?)", (A, B))
      and not q("SELECT 1 FROM session_payments WHERE class_id IN (?,?)", (A, B)))
check("anonymous visitor is sent to login", app.test_client().get("/admin/courtes").status_code == 302)
done()
