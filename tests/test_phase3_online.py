import re
from harness import *

MEET = "https://meet.google.com/tst-priv-ate"
admin = client_as("t_super")
print("Online courses — private and paid")
r = admin.post("/admin/courses/add", data={"title": "TEST Cours HACCP", "description": "desc", "category": "culinary",
                                           "duration": "4 semaines", "meet_link": MEET, "instructor": "Chef", "lang": "fr",
                                           "price": "1500"})
check("admin creates course with price", r.status_code == 302)
cid = q("SELECT id, price FROM courses WHERE title='TEST Cours HACCP'")[0]
check("price stored", cid["price"] == 1500, cid["price"]); cid = cid["id"]
admin.post("/admin/courses/%d/modules/add" % cid, data={"title": "Module 1", "video_url": "https://youtu.be/x", "duration_minutes": "10", "sort_order": "1"})
mid = q("SELECT id FROM course_modules WHERE course_id=?", (cid,))[0]["id"]

pub = app.test_client()
check("public En ligne shows price", "1500 DH" in pub.get("/en-ligne").data.decode())
check("public page never shows the meet link", MEET not in pub.get("/en-ligne").data.decode())

stu = app.test_client()
r = stu.post("/student/signup", data={"email": "eleve.test@example.com", "password": "Eleve-pass-123",
                                      "first_name": "Eleve", "last_name": "Test", "phone": "0600000000"})
check("student signs up", r.status_code in (302, 303), r.status_code)
check("catalogue shows price on the button", "1500 DH" in stu.get("/student/courses").data.decode())
check("course page before enrolling redirects", stu.get("/student/course/%d" % cid).status_code == 302)
stu.post("/student/enroll/%d" % cid)
e = q("SELECT * FROM student_enrollments WHERE course_id=?", (cid,))
check("enrolment created as pending", len(e) == 1 and e[0]["status"] == "pending", [dict(x) for x in e])
page = stu.get("/student/course/%d" % cid).data.decode()
check("pending: no meet link on course page", MEET not in page)
check("pending: payment instructions shown", "en attente de paiement" in page.lower())
check("pending: modules not clickable", "/student/module/%d" % mid not in page)
check("pending: dashboard has no meet link", MEET not in stu.get("/student/dashboard").data.decode())
r = stu.get("/student/module/%d" % mid)
check("pending: module page blocked", r.status_code == 302 and "/student/course/" in r.headers["Location"])
stu.post("/student/module/%d/complete" % mid)
check("pending: cannot mark module complete", not q("SELECT 1 FROM student_progress sp JOIN students s ON s.id=sp.student_id WHERE s.email='eleve.test@example.com' AND sp.completed=1"))
check("pending: quiz post blocked", stu.post("/student/quiz/%d" % mid).status_code == 302)

lst = admin.get("/admin/courses").data.decode()
check("admin list shows 1 pending", "1 en attente" in lst)
check("admin registrations page loads", admin.get("/admin/courses/%d/inscriptions" % cid).status_code == 200)
eid = e[0]["id"]
admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "confirm", "enrollment_id": eid, "amount": "1500", "method": "Virement", "note": "reçu 42"})
e = q("SELECT * FROM student_enrollments WHERE id=?", (eid,))[0]
check("payment confirmed", e["status"] == "paid" and e["paid_amount"] == 1500 and e["paid_method"] == "Virement", dict(e))
page = stu.get("/student/course/%d" % cid).data.decode()
check("paid: meet link visible", MEET in page)
check("paid: dashboard shows live link", MEET in stu.get("/student/dashboard").data.decode())
check("paid: module opens", stu.get("/student/module/%d" % mid).status_code == 200)
stu.post("/student/module/%d/complete" % mid)
check("paid: module completes -> course completed",
      q("SELECT completed FROM student_enrollments WHERE id=?", (eid,))[0]["completed"] == 1)
check("paid: certificate page loads", stu.get("/student/certificates").status_code == 200)

admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "revoke", "enrollment_id": eid})
check("revoke: back to pending, link hidden",
      q("SELECT status FROM student_enrollments WHERE id=?", (eid,))[0]["status"] == "pending"
      and MEET not in stu.get("/student/course/%d" % cid).data.decode())

app.test_client().post("/student/signup", data={"email": "paye.ecole@example.com", "password": "Eleve-pass-123",
                                              "first_name": "Paye", "last_name": "Ecole", "phone": "0611111111"})
other = q("SELECT id FROM students WHERE email = 'paye.ecole@example.com'")
if other:
    admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "add", "student_id": other[0]["id"], "amount": "1200", "method": "Espèces"})
    check("admin adds a student who paid at school -> paid",
          q("SELECT status FROM student_enrollments WHERE course_id=? AND student_id=?", (cid, other[0]["id"]))[0]["status"] == "paid")
    r = admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "add", "student_id": other[0]["id"]})
    check("adding the same student twice is refused, no duplicate",
          len(q("SELECT 1 FROM student_enrollments WHERE course_id=? AND student_id=?", (cid, other[0]["id"]))) == 1)
check("junk enrollment id handled", admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "confirm", "enrollment_id": "abc"}).status_code == 302)
check("junk amount handled", admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "confirm", "enrollment_id": eid, "amount": "1e999"}).status_code == 302
      and q("SELECT paid_amount FROM student_enrollments WHERE id=?", (eid,))[0]["paid_amount"] == 1500)
check("other student cannot read registrations page", app.test_client().get("/admin/courses/%d/inscriptions" % cid).status_code == 302)
school = client_as("t_school")
check("school-role admin cannot open registrations", school.get("/admin/courses/%d/inscriptions" % cid).status_code in (302, 403))
check("settings page has payment instructions field", "online_payment_info" in admin.get("/admin/settings").data.decode())
# module delete with progress (used to crash)
r = admin.post("/admin/modules/%d/delete" % mid)
check("deleting a module students have completed works", r.status_code == 302 and not q("SELECT 1 FROM course_modules WHERE id=?", (mid,)))
admin.post("/admin/courses/%d/modules/add" % cid, data={"title": "Module 2", "sort_order": "2"})
mid2 = q("SELECT id FROM course_modules WHERE course_id=?", (cid,))[0]["id"]
admin.post("/admin/courses/%d/inscriptions" % cid, data={"action": "confirm", "enrollment_id": eid, "amount": "1500", "method": "Carte"})
stu.post("/student/module/%d/complete" % mid2)
r = admin.post("/admin/courses/%d/delete" % cid)
check("deleting a course with progress works (used to be a 500)", r.status_code == 302, r.status_code)
check("deleting the course removes its registrations", not q("SELECT 1 FROM student_enrollments WHERE course_id=?", (cid,)))
done()
