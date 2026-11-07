import re
from harness import *
pub, admin = app.test_client(), client_as("t_super")
H = {"Origin": "http://localhost"}
print("Public funnels -> admin")
t = appmod.TRANSLATIONS["fr"]

# 1. individual registration from the Contact page
contact = pub.get("/contact").data.decode()
check("contact page has the registration form", 'id="contactForm"' in contact)
opt = re.search(r'<select id="formation" name="formation"[^>]*>.*?<option value="([^"]+)">', contact, re.S).group(1)
r = pub.post("/api/inscription", data={"inscription_type": "individual", "prenom": "Funnel", "nom": "Individu",
             "email": "funnel.ind@example.com", "telephone": "0612345678", "formation": opt, "message": "test"}, headers=H)
check("individual registration accepted", r.status_code == 200 and r.json.get("success"), r.data[:200])
check("it lands in admin Inscriptions", "funnel.ind@example.com" in admin.get("/admin/inscriptions").data.decode())

# 2. registration from a programme page (state diploma)
sid = [r["id"] for r in q("SELECT id, diploma_type FROM formations WHERE active=1") if appmod.is_state_diploma(r["diploma_type"])][0]
fp = pub.get("/formation/%d" % sid).data.decode()
check("programme page has its own registration form", 'id="inscription"' in fp)
r = pub.post("/api/inscription", data={"inscription_type": "individual", "prenom": "Etat", "nom": "Diplome",
             "email": "funnel.etat@example.com", "telephone": "0612345678",
             "formation": q("SELECT title FROM formations WHERE id=?", (sid,))[0]["title"]}, headers=H)
check("state-diploma registration accepted", r.status_code == 200 and r.json.get("success"), r.data[:200])

# 3. company training request from the Devis page, choosing a pack
devis = pub.get("/devis").data.decode()
check("devis page offers packs and services in the dropdown", t["pack_1_title"] in devis and t["pro_1_title"] in devis)
r = pub.post("/api/inscription", data={"inscription_type": "corporate", "company_name": "Hôtel Test", "prenom": "Directeur",
             "email": "funnel.corp@example.com", "telephone": "0522000000",
             "formation": "Pack — " + t["pack_1_title"], "num_participants": "12", "budget": "10k_30k"}, headers=H)
check("company request accepted", r.status_code == 200 and r.json.get("success"), r.data[:200])
check("company request in admin", "Hôtel Test" in admin.get("/admin/inscriptions").data.decode())

# 4. detailed proposal
r = pub.post("/api/proposal", data={"company_name": "Riad Test", "contact_name": "Gérant", "email": "funnel.prop@example.com",
             "phone": "0522111111", "training_type": t["pack_2_title"], "num_participants": "8",
             "objectives": "HACCP", "budget": "under_10k", "timeline": "Décembre"}, headers=H)
check("proposal accepted", r.status_code == 200 and (r.json or {}).get("success"), r.data[:200])
check("proposal in admin Propositions", "Riad Test" in admin.get("/admin/proposals").data.decode())

# validation and abuse
r = pub.post("/api/inscription", data={"prenom": "x"}, headers=H)
check("missing fields -> 400 with a message", r.status_code == 400 and r.json.get("error"))
r = pub.post("/api/inscription", data={"prenom": "a", "nom": "b", "email": "not-an-email", "telephone": "1", "formation": "x"}, headers=H)
check("bad email -> 400", r.status_code == 400)
n_before = len(q("SELECT 1 FROM inscriptions"))
r = pub.post("/api/inscription", data={"prenom": "bot", "nom": "bot", "email": "bot@example.com", "telephone": "1", "formation": "x", "website": "spam"}, headers=H)
check("honeypot: bot told OK but nothing stored", r.status_code == 200 and len(q("SELECT 1 FROM inscriptions")) == n_before)
r = pub.post("/api/inscription", data={"prenom": "a"}, headers={"Origin": "https://evil.example"})
check("cross-site post refused", r.status_code == 403)

# admin processes the leads
iid = q("SELECT id FROM inscriptions WHERE email='funnel.ind@example.com'")[0]["id"]
admin.post("/admin/inscriptions/%d/status" % iid, data={"status": "contacted"})
check("admin changes inscription status", q("SELECT status FROM inscriptions WHERE id=?", (iid,))[0]["status"] == "contacted")
pid = q("SELECT id FROM proposals WHERE email='funnel.prop@example.com'")[0]["id"]
admin.post("/admin/proposals/%d/status" % pid, data={"status": "sent"})
check("admin changes proposal status", q("SELECT status FROM proposals WHERE id=?", (pid,))[0]["status"] in ("sent", "pending", "new", "contacted"))
admin.post("/admin/inscriptions/%d/delete" % iid)
check("admin deletes an inscription", not q("SELECT 1 FROM inscriptions WHERE id=?", (iid,)))

# student funnel entry points from the public site
check("En ligne page links to student signup", '/student/signup' in pub.get("/en-ligne").data.decode())
check("student signup page loads", pub.get("/student/signup").status_code == 200)
done()
