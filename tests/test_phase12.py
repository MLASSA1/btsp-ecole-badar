import re
from harness import *

pub = app.test_client()
print("Phase 1 — pages")
pages = ["/", "/services", "/catalogue", "/references", "/formations", "/en-ligne",
         "/certificats", "/a-propos", "/contact", "/devis"]
for lp in ("", "/en", "/ar"):
    for p in pages:
        url = (lp + p) if p != "/" else (lp + "/")
        r = pub.get(url)
        check("GET %s -> 200" % url, r.status_code == 200, r.status_code)
        body = r.data.decode()
        check("  %s has no leftover '#pro-contact'/'#catalogue' anchors" % url,
              'href="#pro-contact"' not in body and 'href="#catalogue"' not in body)
home = pub.get("/").data.decode()
i_hero = home.find('class="hero"'); i_state = home.find('id="diplomes-etat"'); i_pro = home.find('id="services"')
check("home: state diplomas sit right after the hero", 0 < i_hero < i_state < i_pro, (i_hero, i_state, i_pro))
state_titles = re.findall(r'<h3><a href="/formation/\d+">([^<]+)</a></h3>', home)
check("home: shows the two state diplomas", len(state_titles) == 2, state_titles)
check("home: packs teaser shows 3 + 'see all'", home.count('class="corp-card pack-card"') == 3 and '/catalogue" class="btn btn-primary' in home)
check("catalogue page shows all 9 packs", pub.get("/catalogue").data.decode().count('class="corp-card pack-card"') == 9)
check("/en redirects to /en/", pub.get("/en").status_code == 301)
check("/fr/services redirects to /services", pub.get("/fr/services").headers.get("Location", "").endswith("/services"))
check("unknown page 404", pub.get("/nope").status_code == 404 and pub.get("/en/nope").status_code == 404)
sm = pub.get("/sitemap.xml").data.decode()
check("sitemap lists the new pages", "/services</loc>" in sm and "/en/devis</loc>" in sm, sm[:200])

print("\nPhase 2 — offer visibility")
admin = client_as("t_super")
check("admin offer page loads", admin.get("/admin/offre").status_code == 200)
school = client_as("t_school")
check("school-role admin cannot open it", school.get("/admin/offre").status_code in (302, 403))

admin.post("/admin/offre", data={"kind": "pro", "item": "2"})
svc = pub.get("/services").data.decode()
check("hidden service 2 gone from /services", svc.count('class="pro-card"') == 3, svc.count('class="pro-card"'))
check("grid re-flows to 3 columns", '--cols: 3' in svc)
t = appmod.TRANSLATIONS["fr"]
check("hidden service gone from footer and quote form",
      t["pro_2_title"] not in pub.get("/devis").data.decode().split('<footer')[0].split('id="corporateForm"')[1]
      and t["pro_2_title"] not in pub.get("/").data.decode().split('<footer')[1])
admin.post("/admin/offre", data={"kind": "pack", "item": "1"})
admin.post("/admin/offre", data={"kind": "pack", "item": "3"})
cat = pub.get("/catalogue").data.decode()
nums = re.findall(r'class="corp-num">[^<]*?(\d+)</span>', cat)
check("two packs hidden -> 7 shown, renumbered 1..7", nums == [str(i) for i in range(1, 8)], nums)
check("heading says 7", re.search(r"<h2>7 ", cat) is not None)
check("hidden pack title absent", t["pack_1_title"] not in cat and t["pack_3_title"] not in cat)
check("home teaser still 3 packs", pub.get("/").data.decode().count('class="corp-card pack-card"') == 3)
# hide all services -> section disappears entirely
for i in (1, 3, 4):
    admin.post("/admin/offre", data={"kind": "pro", "item": str(i)})
check("all services hidden -> no services section", 'id="services"' not in pub.get("/services").data.decode())
# state diploma toggle
ids = [r["id"] for r in q("SELECT id, diploma_type FROM formations WHERE active=1") if appmod.is_state_diploma(r["diploma_type"])]
admin.post("/admin/offre", data={"kind": "formation", "item": str(ids[0])})
h = pub.get("/").data.decode()
check("one state diploma hidden -> single full-width card", 'data-count="1"' in h.split('id="diplomes-etat"')[1][:2000])
check("its page now 404s", pub.get("/formation/%d" % ids[0]).status_code == 404)
admin.post("/admin/offre", data={"kind": "formation", "item": str(ids[1])})
check("both hidden -> no state section, no state tab",
      'id="diplomes-etat"' not in pub.get("/").data.decode() and 'data-cat="state"' not in pub.get("/formations").data.decode())
# restore everything
for k, i in (("pro", 1), ("pro", 2), ("pro", 3), ("pro", 4), ("pack", 1), ("pack", 3), ("formation", ids[0]), ("formation", ids[1])):
    admin.post("/admin/offre", data={"kind": k, "item": str(i)})
check("restored: 4 services, 9 packs, 2 diplomas",
      pub.get("/services").data.decode().count('class="pro-card"') == 4
      and pub.get("/catalogue").data.decode().count('class="corp-card pack-card"') == 9
      and pub.get("/").data.decode().split('id="diplomes-etat"')[1][:600].count('data-count="2"') == 1)
check("bad action rejected politely", admin.post("/admin/offre", data={"kind": "x", "item": "1"}).status_code == 302)
done()
