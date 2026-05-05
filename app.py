import os
import secrets
import uuid
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_from_directory, g, abort, session as flask_session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from translations import TRANSLATIONS, SUPPORTED_LANGS, DEFAULT_LANG

DATABASE_URL = os.environ.get("DATABASE_URL")
USE_PG = bool(DATABASE_URL)

if USE_PG:
    import psycopg2
    import psycopg2.extras
else:
    import sqlite3


class PgRow(dict):
    """Dict subclass that supports integer index access like sqlite3.Row."""

    def __init__(self, data):
        super().__init__(data)
        self._values = list(data.values())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def _wrap_row(row):
    if row is None:
        return None
    return PgRow(row)


def _wrap_rows(rows):
    return [PgRow(r) for r in rows]


class PgCursorWrapper:
    """Wraps a psycopg2 cursor so existing code using ? placeholders works."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=None):
        sql = sql.replace("?", "%s")
        self._cursor.execute(sql, params)
        return self

    def fetchone(self):
        return _wrap_row(self._cursor.fetchone())

    def fetchall(self):
        return _wrap_rows(self._cursor.fetchall())

    def __iter__(self):
        return (_wrap_row(r) for r in self._cursor)


class PgConnectionWrapper:
    """Wraps a psycopg2 connection to behave like sqlite3 with dict rows."""

    def __init__(self, dsn):
        self._conn = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.RealDictCursor)
        self._conn.autocommit = False

    def execute(self, sql, params=None):
        cur = PgCursorWrapper(self._conn.cursor())
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def cursor(self):
        return PgCursorWrapper(self._conn.cursor())

# --------------- Config ---------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "admin", "templates"),
    static_folder=os.path.join(BASE_DIR, "admin", "static"),
    static_url_path="/admin/static",
)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Veuillez vous connecter."

# --------------- Database helpers ---------------

def get_db():
    if "db" not in g:
        if USE_PG:
            g.db = PgConnectionWrapper(DATABASE_URL)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _get_init_connection():
    if USE_PG:
        return PgConnectionWrapper(DATABASE_URL)
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    return db


def _run_ddl(db, statements):
    if USE_PG:
        for stmt in statements:
            db.execute(stmt)
        db.commit()
    else:
        db.executescript("\n".join(s + ";" for s in statements))


def init_db():
    db = _get_init_connection()

    if USE_PG:
        auto_id = "SERIAL PRIMARY KEY"
    else:
        auto_id = "INTEGER PRIMARY KEY AUTOINCREMENT"

    tables = [
        f"""CREATE TABLE IF NOT EXISTS admin_user (
            id {auto_id if USE_PG else 'INTEGER PRIMARY KEY'},
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS formations (
            id {auto_id},
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            duration TEXT NOT NULL,
            diploma_type TEXT NOT NULL DEFAULT 'Certificat',
            features TEXT NOT NULL DEFAULT '',
            image TEXT DEFAULT '',
            badge TEXT DEFAULT '',
            featured INTEGER DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            category TEXT NOT NULL DEFAULT 'culinary',
            lang TEXT NOT NULL DEFAULT 'fr',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS certificates (
            id {auto_id},
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            formation_id INTEGER,
            active INTEGER DEFAULT 1,
            sort_order INTEGER DEFAULT 0,
            lang TEXT NOT NULL DEFAULT 'fr',
            FOREIGN KEY (formation_id) REFERENCES formations(id) ON DELETE SET NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS testimonials (
            id {auto_id},
            name TEXT NOT NULL,
            promotion TEXT NOT NULL,
            content TEXT NOT NULL,
            rating INTEGER DEFAULT 5,
            avatar_letter TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS gallery (
            id {auto_id},
            title TEXT NOT NULL,
            image TEXT NOT NULL,
            large INTEGER DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS custom_sections (
            id {auto_id},
            section_key TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            subtitle TEXT DEFAULT '',
            content TEXT DEFAULT '',
            image TEXT DEFAULT '',
            icon TEXT DEFAULT '',
            button_text TEXT DEFAULT '',
            button_link TEXT DEFAULT '',
            animation TEXT DEFAULT 'fade-up',
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS students (
            id {auto_id},
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            phone TEXT DEFAULT '',
            avatar_letter TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS courses (
            id {auto_id},
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT DEFAULT 'culinary',
            image TEXT DEFAULT '',
            duration TEXT DEFAULT '',
            meet_link TEXT DEFAULT '',
            instructor TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS course_modules (
            id {auto_id},
            course_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            video_url TEXT DEFAULT '',
            materials_url TEXT DEFAULT '',
            duration_minutes INTEGER DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
        )""",
        f"""CREATE TABLE IF NOT EXISTS student_enrollments (
            id {auto_id},
            student_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            certificate_issued INTEGER DEFAULT 0,
            FOREIGN KEY (student_id) REFERENCES students(id),
            FOREIGN KEY (course_id) REFERENCES courses(id),
            UNIQUE(student_id, course_id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS student_progress (
            id {auto_id},
            student_id INTEGER NOT NULL,
            module_id INTEGER NOT NULL,
            watched INTEGER DEFAULT 0,
            watch_time_seconds INTEGER DEFAULT 0,
            completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id),
            FOREIGN KEY (module_id) REFERENCES course_modules(id),
            UNIQUE(student_id, module_id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS quizzes (
            id {auto_id},
            module_id INTEGER NOT NULL,
            question TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT DEFAULT '',
            option_d TEXT DEFAULT '',
            correct_answer TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (module_id) REFERENCES course_modules(id) ON DELETE CASCADE
        )""",
        f"""CREATE TABLE IF NOT EXISTS quiz_attempts (
            id {auto_id},
            student_id INTEGER NOT NULL,
            module_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            passed INTEGER DEFAULT 0,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id),
            FOREIGN KEY (module_id) REFERENCES course_modules(id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS rewards (
            id {auto_id},
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            icon TEXT DEFAULT '',
            criteria TEXT NOT NULL,
            active INTEGER DEFAULT 1
        )""",
        f"""CREATE TABLE IF NOT EXISTS student_rewards (
            id {auto_id},
            student_id INTEGER NOT NULL,
            reward_id INTEGER NOT NULL,
            earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id),
            FOREIGN KEY (reward_id) REFERENCES rewards(id),
            UNIQUE(student_id, reward_id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS proposals (
            id {auto_id},
            company_name TEXT NOT NULL,
            contact_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            training_type TEXT NOT NULL,
            num_participants INTEGER DEFAULT 1,
            objectives TEXT DEFAULT '',
            budget TEXT DEFAULT '',
            timeline TEXT DEFAULT '',
            status TEXT DEFAULT 'nouveau',
            admin_notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS faqs (
            id {auto_id},
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr'
        )""",
        f"""CREATE TABLE IF NOT EXISTS training_sessions (
            id {auto_id},
            title TEXT NOT NULL,
            formation_id INTEGER,
            start_date TEXT NOT NULL,
            end_date TEXT DEFAULT '',
            spots_total INTEGER DEFAULT 20,
            spots_taken INTEGER DEFAULT 0,
            location TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            lang TEXT NOT NULL DEFAULT 'fr',
            FOREIGN KEY (formation_id) REFERENCES formations(id) ON DELETE SET NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS partners (
            id {auto_id},
            name TEXT NOT NULL,
            logo TEXT NOT NULL,
            website_url TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1
        )""",
        f"""CREATE TABLE IF NOT EXISTS inscriptions (
            id {auto_id},
            prenom TEXT NOT NULL,
            nom TEXT NOT NULL,
            email TEXT NOT NULL,
            telephone TEXT NOT NULL,
            formation TEXT NOT NULL,
            message TEXT DEFAULT '',
            status TEXT DEFAULT 'nouveau',
            inscription_type TEXT DEFAULT 'individual',
            company_name TEXT DEFAULT '',
            num_participants INTEGER DEFAULT 1,
            desired_dates TEXT DEFAULT '',
            budget TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
    ]

    _run_ddl(db, tables)

    # Create default admin
    existing = db.execute("SELECT id FROM admin_user LIMIT 1").fetchone()
    if not existing:
        db.execute(
            "INSERT INTO admin_user (username, password_hash) VALUES (?, ?)",
            ("admin", generate_password_hash("admin123")),
        )
        print(">>> Default admin created: admin / admin123")
        print(">>> CHANGE THIS PASSWORD IMMEDIATELY after first login!")

    # Seed site settings
    defaults = {
        "site_name": "BTSP",
        "site_name_full": "École BADAR Training and Service",
        "site_tagline": "Établissement Privé de Formation Professionnelle",
        "about_title": "Un Centre d'Excellence au Service de Votre Avenir",
        "about_text": "BTSP est un établissement privé de formation professionnelle à Guelmim, spécialisé dans les arts culinaires, l'hôtellerie et les technologies de l'information. Notre pédagogie allie pratique intensive et expertise professionnelle.",
        "about_text_2": "Notre centre offre un cadre moderne et professionnel, équipé des dernières technologies pour vous préparer aux exigences du marché national et international.",
        "address": "شارع المقاومة بقرب من صيدلية المقاومة زنقة 07 طابق الثاني، كلميم",
        "phone": "06.37.48.62.76",
        "phone_2": "06.50.51.58.44",
        "email": "contact@btsp.ma",
        "hours": "Lun - Sam : 08h00 - 18h00",
        "facebook_url": "#",
        "instagram_url": "#",
        "whatsapp_url": "https://wa.me/212637486276",
        "stat_diplomes": "500+",
        "stat_formations": "15+",
        "stat_reussite": "98%",
        "years_experience": "12",
        "services_title": "Formation Sur Mesure pour Entreprises & Hôtels",
        "services_text": "Nous proposons des programmes de formation personnalisés pour les entreprises, hôtels et groupes professionnels.",
        "logo_url": "/uploads/logo.jpeg",
        "hero_title_fr": "Votre Avenir",
        "hero_subtitle_fr": "Commence Ici",
        "hero_title_en": "Your Future",
        "hero_subtitle_en": "Starts Here",
        "hero_title_ar": "مستقبلك",
        "hero_subtitle_ar": "يبدأ هنا",
        "hero_bg_image": "",
        "show_hero": "1",
        "show_about": "1",
        "show_services": "1",
        "show_formations": "1",
        "show_certificates": "1",
        "show_gallery": "1",
        "show_testimonials": "1",
        "show_contact": "1",
    }
    for key, value in defaults.items():
        db.execute(
            "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
            (key, value),
        )

    # Seed formations — Culinary (FR)
    count = db.execute("SELECT COUNT(*) FROM formations").fetchone()[0]
    if count == 0:
        seed_formations = [
            # Culinary formations (FR)
            ("Cake Design & Décoration", "Maîtrisez l'art du cake design : pâte à sucre, modelage, wedding cakes, gâteaux 3D et techniques de décoration avancées.", "6 Mois", "Certificat", "Pâte à sucre & fondant|Wedding cakes & pièces montées|Modelage & sculpture|Aérographe & techniques modernes", "", "Populaire", 0, 1, "culinary", "fr"),
            ("Pâtisserie Professionnelle", "Formation complète en pâtisserie française et marocaine : viennoiseries, entremets, chocolaterie, confiserie et pâtisserie moderne.", "12 Mois", "Diplôme", "Pâtisserie française & marocaine|Chocolaterie & confiserie|Entremets & desserts à l'assiette|Gestion de laboratoire", "", "Excellence", 1, 2, "culinary", "fr"),
            ("Arts Culinaires & Cuisine", "Développez vos compétences en cuisine internationale et marocaine : techniques de cuisson, dressage, hygiène alimentaire et gestion de cuisine.", "9 Mois", "Diplôme", "Cuisine marocaine & internationale|Techniques de cuisson avancées|Hygiène & sécurité alimentaire|Dressage & présentation", "", "", 0, 3, "culinary", "fr"),
            ("Boulangerie & Viennoiserie", "Apprenez les secrets du pain artisanal et des viennoiseries : pétrissage, fermentation, façonnage et cuisson parfaite.", "3 Mois", "Certificat", "Pains traditionnels & spéciaux|Viennoiseries classiques|Fermentation & levains|Techniques artisanales", "", "", 0, 5, "culinary", "fr"),
            ("Chocolaterie & Confiserie", "Explorez l'univers du chocolat : tempérage, moulage, ganaches, bonbons et créations artistiques en chocolat.", "4 Mois", "Certificat", "Tempérage & techniques|Bonbons & pralinés|Pièces artistiques|Confiserie traditionnelle", "", "", 0, 6, "culinary", "fr"),
            # Hospitality (FR)
            ("Hôtellerie & Restauration", "Préparez-vous aux métiers de l'hôtellerie : accueil, service en salle, gestion hôtelière, organisation d'événements et management.", "12 Mois", "Diplôme", "Accueil & réception|Service en salle & bar|Gestion hôtelière|Organisation d'événements", "", "", 0, 4, "hospitality", "fr"),
            # IT formations (FR)
            ("Intelligence Artificielle & Machine Learning", "Maîtrisez les fondamentaux de l'IA : Python, deep learning, NLP, vision par ordinateur et déploiement de modèles ML en production.", "6 Mois", "Certificat", "Python pour l'IA|Deep Learning & réseaux de neurones|NLP & vision par ordinateur|Déploiement de modèles ML", "", "Nouveau", 0, 7, "it", "fr"),
            ("Cloud Computing & DevOps", "Formation complète en cloud computing : AWS, Azure, GCP, conteneurisation Docker/Kubernetes, CI/CD et infrastructure as code.", "9 Mois", "Diplôme", "AWS, Azure & GCP|Docker & Kubernetes|CI/CD & automatisation|Terraform & Infrastructure as Code", "", "Demandé", 1, 8, "it", "fr"),
            ("Cybersécurité", "Protégez les systèmes et réseaux : tests de pénétration, sécurité réseau, cryptographie, réponse aux incidents et conformité.", "6 Mois", "Certificat", "Tests de pénétration & ethical hacking|Sécurité réseau & pare-feu|Cryptographie & PKI|Réponse aux incidents & SIEM", "", "", 0, 9, "it", "fr"),
            ("DevOps & CI/CD", "Automatisez le cycle de développement : Git, Jenkins, GitHub Actions, monitoring, observabilité et pratiques SRE.", "4 Mois", "Certificat", "Git & gestion de versions|Jenkins & GitHub Actions|Monitoring & observabilité|Pratiques SRE & fiabilité", "", "", 0, 10, "it", "fr"),
        ]
        for f in seed_formations:
            db.execute(
                "INSERT INTO formations (title, description, duration, diploma_type, features, image, badge, featured, sort_order, category, lang) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                f,
            )

    # Seed certificates
    count = db.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    if count == 0:
        seed_certs = [
            ("Certificat en Cake Design", "Attestation de maîtrise des techniques de décoration de gâteaux et cake design professionnel.", 1, "fr"),
            ("Diplôme en Pâtisserie", "Diplôme professionnel en pâtisserie française et marocaine, reconnu par les établissements du secteur.", 2, "fr"),
            ("Diplôme en Hôtellerie", "Formation certifiante en gestion hôtelière, accueil et service de restauration.", 3, "fr"),
            ("Certificat en Arts Culinaires", "Attestation de compétences en cuisine professionnelle, techniques avancées et hygiène alimentaire.", 4, "fr"),
            ("Certificat en Cloud & DevOps", "Attestation de compétences en cloud computing, conteneurisation et automatisation CI/CD.", 5, "fr"),
            ("Certificat en Cybersécurité", "Attestation de compétences en sécurité informatique, tests de pénétration et réponse aux incidents.", 6, "fr"),
            ("Certificat en Intelligence Artificielle", "Attestation de compétences en IA, machine learning et déploiement de modèles.", 7, "fr"),
        ]
        for c in seed_certs:
            db.execute("INSERT INTO certificates (title, description, sort_order, lang) VALUES (?,?,?,?)", c)

    # Seed testimonials
    count = db.execute("SELECT COUNT(*) FROM testimonials").fetchone()[0]
    if count == 0:
        seed_test = [
            ("Fatima Z.", "Diplômée en Cake Design - Promotion 2024", "Grâce à BTSP, j'ai pu ouvrir ma propre pâtisserie. La formation en cake design m'a donné toutes les compétences nécessaires.", 5, "F", "fr"),
            ("Youssef B.", "Diplômé en Hôtellerie - Promotion 2023", "Une expérience incroyable ! Les formateurs sont passionnés et les ateliers sont très bien équipés. Je travaille maintenant dans un hôtel 5 étoiles à Marrakech.", 5, "Y", "fr"),
            ("Sara M.", "Diplômée en Pâtisserie - Promotion 2024", "La formation en pâtisserie professionnelle est complète et très pratique. Les stages m'ont permis de me préparer au monde professionnel avec confiance.", 5, "S", "fr"),
            ("Ahmed K.", "Diplômé Cloud & DevOps - Promotion 2025", "La formation DevOps m'a permis de décrocher un poste d'ingénieur cloud. Les certifications BTSP sont très valorisées sur le marché.", 5, "A", "fr"),
        ]
        for t in seed_test:
            db.execute("INSERT INTO testimonials (name, promotion, content, rating, avatar_letter, lang) VALUES (?,?,?,?,?,?)", t)

    # Seed FAQs
    count = db.execute("SELECT COUNT(*) FROM faqs").fetchone()[0]
    if count == 0:
        seed_faqs = [
            ("Quels sont les prérequis pour s'inscrire ?", "Aucun prérequis n'est nécessaire pour la plupart de nos formations. Un entretien de motivation est organisé pour évaluer votre projet professionnel.", 1, "fr"),
            ("Quelle est la durée des formations ?", "Nos formations varient de 3 à 12 mois selon le programme choisi. Les formations en cake design et chocolaterie durent 3-6 mois, tandis que les diplômes en pâtisserie et hôtellerie durent 9-12 mois.", 2, "fr"),
            ("Les certificats sont-ils reconnus ?", "Oui, nos certificats et diplômes sont reconnus au niveau national. Ils sont délivrés par BTSP, établissement privé accrédité de formation professionnelle.", 3, "fr"),
            ("Proposez-vous des stages en entreprise ?", "Oui, toutes nos formations incluent un stage pratique en entreprise. Nous avons des partenariats avec des hôtels, restaurants et entreprises IT au Maroc et à l'international.", 4, "fr"),
            ("Comment se déroule le paiement ?", "Le paiement peut se faire en une ou plusieurs fois. Nous proposons des facilités de paiement adaptées à votre situation. Contactez-nous pour plus de détails.", 5, "fr"),
            ("Proposez-vous des formations à distance ?", "Certaines de nos formations IT (Cloud, DevOps, Cybersécurité) sont disponibles en format hybride. Les formations culinaires sont exclusivement en présentiel.", 6, "fr"),
        ]
        for f in seed_faqs:
            db.execute("INSERT INTO faqs (question, answer, sort_order, lang) VALUES (?,?,?,?)", f)

    # Seed training sessions
    count = db.execute("SELECT COUNT(*) FROM training_sessions").fetchone()[0]
    if count == 0:
        seed_sessions = [
            ("Cake Design - Session Été", 1, "2026-06-15", "2026-12-15", 20, 12, "Guelmim", 1, "fr"),
            ("Cloud & DevOps - Session Automne", 8, "2026-09-01", "2027-05-30", 15, 5, "Guelmim", 1, "fr"),
            ("Pâtisserie Pro - Session Septembre", 2, "2026-09-15", "2027-09-15", 18, 8, "Guelmim", 1, "fr"),
            ("Cybersécurité - Intensif", 9, "2026-07-01", "2026-12-30", 12, 3, "Guelmim / En ligne", 1, "fr"),
        ]
        for s in seed_sessions:
            db.execute("INSERT INTO training_sessions (title, formation_id, start_date, end_date, spots_total, spots_taken, location, active, lang) VALUES (?,?,?,?,?,?,?,?,?)", s)

    # Seed rewards
    count = db.execute("SELECT COUNT(*) FROM rewards").fetchone()[0]
    if count == 0:
        seed_rewards = [
            ("Premier Pas", "Connexion pour la première fois", "star", "first_login"),
            ("Studieux", "Regarder 10 vidéos de formation", "video", "watch_10_videos"),
            ("Perfectionniste", "Obtenir 100% à un quiz", "trophy", "perfect_quiz"),
            ("Diplômé", "Terminer un cours complet", "graduation", "complete_course"),
            ("Assidu", "Regarder toutes les vidéos d'un cours", "flame", "all_videos_course"),
        ]
        for r in seed_rewards:
            db.execute("INSERT INTO rewards (title, description, icon, criteria) VALUES (?,?,?,?)", r)

    db.commit()
    db.close()


def migrate_db():
    """Add new columns to existing databases (idempotent)."""
    if USE_PG:
        return
    db = sqlite3.connect(DB_PATH)
    migrations = [
        "ALTER TABLE formations ADD COLUMN category TEXT NOT NULL DEFAULT 'culinary'",
        "ALTER TABLE formations ADD COLUMN lang TEXT NOT NULL DEFAULT 'fr'",
        "ALTER TABLE certificates ADD COLUMN lang TEXT NOT NULL DEFAULT 'fr'",
        "ALTER TABLE testimonials ADD COLUMN lang TEXT NOT NULL DEFAULT 'fr'",
        "ALTER TABLE gallery ADD COLUMN lang TEXT NOT NULL DEFAULT 'fr'",
        "ALTER TABLE inscriptions ADD COLUMN inscription_type TEXT DEFAULT 'individual'",
        "ALTER TABLE inscriptions ADD COLUMN company_name TEXT DEFAULT ''",
        "ALTER TABLE inscriptions ADD COLUMN num_participants INTEGER DEFAULT 1",
        "ALTER TABLE inscriptions ADD COLUMN desired_dates TEXT DEFAULT ''",
        "ALTER TABLE inscriptions ADD COLUMN budget TEXT DEFAULT ''",
    ]
    for sql in migrations:
        try:
            db.execute(sql)
        except sqlite3.OperationalError:
            pass
    db.commit()
    db.close()


# --------------- Auth ---------------

class AdminUser(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT id, username FROM admin_user WHERE id = ?", (user_id,)).fetchone()
    if row:
        return AdminUser(row["id"], row["username"])
    return None


# --------------- File upload helpers ---------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_upload(file, subfolder):
    if file and file.filename and allowed_file(file.filename):
        ext = file.filename.rsplit(".", 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        folder = os.path.join(UPLOAD_DIR, subfolder)
        os.makedirs(folder, exist_ok=True)
        filepath = os.path.join(folder, filename)
        file.save(filepath)
        return f"/uploads/{subfolder}/{filename}"
    return None


def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM site_settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


# --------------- Public routes ---------------

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/static-site/<path:filename>")
def static_site(filename):
    return send_from_directory(BASE_DIR, filename)


@app.route("/")
def index_default():
    return render_public("fr")


@app.route("/<lang>/")
def index_lang(lang):
    if lang not in SUPPORTED_LANGS:
        abort(404)
    return render_public(lang)


def render_public(lang):
    db = get_db()
    settings = get_settings()
    t = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])
    formations = db.execute(
        "SELECT * FROM formations WHERE active = 1 AND lang = ? ORDER BY sort_order",
        (lang,),
    ).fetchall()
    # Fallback to FR if no formations in requested language
    if not formations and lang != "fr":
        formations = db.execute(
            "SELECT * FROM formations WHERE active = 1 AND lang = 'fr' ORDER BY sort_order"
        ).fetchall()
    certificates = db.execute(
        "SELECT * FROM certificates WHERE active = 1 AND lang = ? ORDER BY sort_order",
        (lang,),
    ).fetchall()
    if not certificates and lang != "fr":
        certificates = db.execute(
            "SELECT * FROM certificates WHERE active = 1 AND lang = 'fr' ORDER BY sort_order"
        ).fetchall()
    testimonials = db.execute(
        "SELECT * FROM testimonials WHERE active = 1 AND lang = ? ORDER BY created_at DESC",
        (lang,),
    ).fetchall()
    if not testimonials and lang != "fr":
        testimonials = db.execute(
            "SELECT * FROM testimonials WHERE active = 1 AND lang = 'fr' ORDER BY created_at DESC"
        ).fetchall()
    gallery = db.execute(
        "SELECT * FROM gallery WHERE active = 1 ORDER BY sort_order"
    ).fetchall()
    custom_sections = db.execute(
        "SELECT * FROM custom_sections WHERE active = 1 AND lang = ? ORDER BY sort_order",
        (lang,),
    ).fetchall()
    if not custom_sections and lang != "fr":
        custom_sections = db.execute(
            "SELECT * FROM custom_sections WHERE active = 1 AND lang = 'fr' ORDER BY sort_order"
        ).fetchall()
    faqs = db.execute(
        "SELECT * FROM faqs WHERE active = 1 AND lang = ? ORDER BY sort_order",
        (lang,),
    ).fetchall()
    if not faqs and lang != "fr":
        faqs = db.execute(
            "SELECT * FROM faqs WHERE active = 1 AND lang = 'fr' ORDER BY sort_order"
        ).fetchall()
    sessions = db.execute(
        "SELECT * FROM training_sessions WHERE active = 1 AND lang = ? ORDER BY start_date",
        (lang,),
    ).fetchall()
    if not sessions and lang != "fr":
        sessions = db.execute(
            "SELECT * FROM training_sessions WHERE active = 1 AND lang = 'fr' ORDER BY start_date"
        ).fetchall()
    partners = db.execute(
        "SELECT * FROM partners WHERE active = 1 ORDER BY sort_order"
    ).fetchall()
    hero_title = settings.get(f"hero_title_{lang}", t.get("hero_title", ""))
    hero_subtitle = settings.get(f"hero_subtitle_{lang}", t.get("hero_subtitle", ""))
    return render_template(
        "public/index.html",
        settings=settings,
        formations=formations,
        certificates=certificates,
        testimonials=testimonials,
        gallery=gallery,
        custom_sections=custom_sections,
        faqs=faqs,
        sessions=sessions,
        partners=partners,
        hero_title=hero_title,
        hero_subtitle=hero_subtitle,
        t=t,
        lang=lang,
        supported_langs=SUPPORTED_LANGS,
    )


@app.route("/api/inscription", methods=["POST"])
def submit_inscription():
    data = request.form
    inscription_type = data.get("inscription_type", "individual")

    if inscription_type == "corporate":
        required = ["company_name", "prenom", "email", "telephone", "formation"]
    else:
        required = ["prenom", "nom", "email", "telephone", "formation"]

    for field in required:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Le champ {field} est requis."}), 400

    db = get_db()
    db.execute(
        """INSERT INTO inscriptions
        (prenom, nom, email, telephone, formation, message, inscription_type, company_name, num_participants, desired_dates, budget)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            data.get("prenom", "").strip(),
            data.get("nom", "").strip(),
            data["email"].strip(),
            data["telephone"].strip(),
            data["formation"].strip(),
            data.get("message", "").strip(),
            inscription_type,
            data.get("company_name", "").strip(),
            int(data.get("num_participants", 1) or 1),
            data.get("desired_dates", "").strip(),
            data.get("budget", "").strip(),
        ),
    )
    db.commit()
    return jsonify({"success": True, "message": "Votre demande a été envoyée avec succès !"})


@app.route("/api/proposal", methods=["POST"])
def submit_proposal():
    data = request.form
    required = ["company_name", "contact_name", "email", "phone", "training_type"]
    for field in required:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Le champ {field} est requis."}), 400
    db = get_db()
    db.execute(
        """INSERT INTO proposals
        (company_name, contact_name, email, phone, training_type, num_participants, objectives, budget, timeline)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            data["company_name"].strip(),
            data["contact_name"].strip(),
            data["email"].strip(),
            data["phone"].strip(),
            data["training_type"].strip(),
            int(data.get("num_participants", 1) or 1),
            data.get("objectives", "").strip(),
            data.get("budget", "").strip(),
            data.get("timeline", "").strip(),
        ),
    )
    db.commit()
    return jsonify({"success": True, "message": "Votre demande de proposition a été envoyée !"})


# --------------- Admin Auth ---------------

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id, username, password_hash FROM admin_user WHERE username = ?",
            (username,),
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            login_user(AdminUser(row["id"], row["username"]))
            return redirect(url_for("admin_dashboard"))
        flash("Identifiants incorrects.", "error")
    return render_template("admin/login.html")


@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# --------------- Admin Dashboard ---------------

@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    stats = {
        "formations": db.execute("SELECT COUNT(*) FROM formations WHERE active=1").fetchone()[0],
        "certificates": db.execute("SELECT COUNT(*) FROM certificates WHERE active=1").fetchone()[0],
        "testimonials": db.execute("SELECT COUNT(*) FROM testimonials WHERE active=1").fetchone()[0],
        "inscriptions_new": db.execute("SELECT COUNT(*) FROM inscriptions WHERE status='nouveau'").fetchone()[0],
        "inscriptions_total": db.execute("SELECT COUNT(*) FROM inscriptions").fetchone()[0],
        "gallery": db.execute("SELECT COUNT(*) FROM gallery WHERE active=1").fetchone()[0],
    }
    recent_inscriptions = db.execute(
        "SELECT * FROM inscriptions ORDER BY created_at DESC LIMIT 5"
    ).fetchall()
    return render_template("admin/dashboard.html", stats=stats, recent=recent_inscriptions)


# --------------- Admin: Formations CRUD ---------------

@app.route("/admin/formations")
@login_required
def admin_formations():
    db = get_db()
    formations = db.execute("SELECT * FROM formations ORDER BY sort_order").fetchall()
    return render_template("admin/formations.html", formations=formations)


@app.route("/admin/formations/add", methods=["GET", "POST"])
@login_required
def admin_formation_add():
    if request.method == "POST":
        image_url = ""
        if "image" in request.files:
            image_url = save_upload(request.files["image"], "formations") or ""
        db = get_db()
        db.execute(
            "INSERT INTO formations (title, description, duration, diploma_type, features, image, badge, featured, sort_order, category, lang) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                request.form["duration"].strip(),
                request.form["diploma_type"],
                request.form.get("features", "").strip(),
                image_url,
                request.form.get("badge", "").strip(),
                1 if request.form.get("featured") else 0,
                int(request.form.get("sort_order", 0)),
                request.form.get("category", "culinary"),
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Formation ajoutée avec succès.", "success")
        return redirect(url_for("admin_formations"))
    return render_template("admin/formation_form.html", formation=None)


@app.route("/admin/formations/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_formation_edit(id):
    db = get_db()
    formation = db.execute("SELECT * FROM formations WHERE id = ?", (id,)).fetchone()
    if not formation:
        flash("Formation introuvable.", "error")
        return redirect(url_for("admin_formations"))
    if request.method == "POST":
        image_url = formation["image"]
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "formations") or image_url
        db.execute(
            "UPDATE formations SET title=?, description=?, duration=?, diploma_type=?, features=?, image=?, badge=?, featured=?, sort_order=?, category=?, lang=? WHERE id=?",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                request.form["duration"].strip(),
                request.form["diploma_type"],
                request.form.get("features", "").strip(),
                image_url,
                request.form.get("badge", "").strip(),
                1 if request.form.get("featured") else 0,
                int(request.form.get("sort_order", 0)),
                request.form.get("category", "culinary"),
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Formation mise à jour.", "success")
        return redirect(url_for("admin_formations"))
    return render_template("admin/formation_form.html", formation=formation)


@app.route("/admin/formations/<int:id>/delete", methods=["POST"])
@login_required
def admin_formation_delete(id):
    db = get_db()
    db.execute("DELETE FROM formations WHERE id = ?", (id,))
    db.commit()
    flash("Formation supprimée.", "success")
    return redirect(url_for("admin_formations"))


@app.route("/admin/formations/<int:id>/toggle", methods=["POST"])
@login_required
def admin_formation_toggle(id):
    db = get_db()
    db.execute("UPDATE formations SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (id,))
    db.commit()
    return redirect(url_for("admin_formations"))


# --------------- Admin: Certificates CRUD ---------------

@app.route("/admin/certificates")
@login_required
def admin_certificates():
    db = get_db()
    certificates = db.execute("SELECT * FROM certificates ORDER BY sort_order").fetchall()
    return render_template("admin/certificates.html", certificates=certificates)


@app.route("/admin/certificates/add", methods=["GET", "POST"])
@login_required
def admin_certificate_add():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO certificates (title, description, sort_order, lang) VALUES (?,?,?,?)",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                int(request.form.get("sort_order", 0)),
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Certificat ajouté avec succès.", "success")
        return redirect(url_for("admin_certificates"))
    formations = db.execute("SELECT id, title FROM formations ORDER BY title").fetchall()
    return render_template("admin/certificate_form.html", certificate=None, formations=formations)


@app.route("/admin/certificates/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_certificate_edit(id):
    db = get_db()
    certificate = db.execute("SELECT * FROM certificates WHERE id = ?", (id,)).fetchone()
    if not certificate:
        flash("Certificat introuvable.", "error")
        return redirect(url_for("admin_certificates"))
    if request.method == "POST":
        db.execute(
            "UPDATE certificates SET title=?, description=?, sort_order=?, lang=? WHERE id=?",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                int(request.form.get("sort_order", 0)),
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Certificat mis à jour.", "success")
        return redirect(url_for("admin_certificates"))
    formations = db.execute("SELECT id, title FROM formations ORDER BY title").fetchall()
    return render_template("admin/certificate_form.html", certificate=certificate, formations=formations)


@app.route("/admin/certificates/<int:id>/delete", methods=["POST"])
@login_required
def admin_certificate_delete(id):
    db = get_db()
    db.execute("DELETE FROM certificates WHERE id = ?", (id,))
    db.commit()
    flash("Certificat supprimé.", "success")
    return redirect(url_for("admin_certificates"))


# --------------- Admin: Testimonials CRUD ---------------

@app.route("/admin/testimonials")
@login_required
def admin_testimonials():
    db = get_db()
    testimonials = db.execute("SELECT * FROM testimonials ORDER BY created_at DESC").fetchall()
    return render_template("admin/testimonials.html", testimonials=testimonials)


@app.route("/admin/testimonials/add", methods=["GET", "POST"])
@login_required
def admin_testimonial_add():
    if request.method == "POST":
        name = request.form["name"].strip()
        db = get_db()
        db.execute(
            "INSERT INTO testimonials (name, promotion, content, rating, avatar_letter, lang) VALUES (?,?,?,?,?,?)",
            (
                name,
                request.form["promotion"].strip(),
                request.form["content"].strip(),
                int(request.form.get("rating", 5)),
                name[0].upper() if name else "?",
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Témoignage ajouté.", "success")
        return redirect(url_for("admin_testimonials"))
    return render_template("admin/testimonial_form.html", testimonial=None)


@app.route("/admin/testimonials/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_testimonial_edit(id):
    db = get_db()
    testimonial = db.execute("SELECT * FROM testimonials WHERE id = ?", (id,)).fetchone()
    if not testimonial:
        flash("Témoignage introuvable.", "error")
        return redirect(url_for("admin_testimonials"))
    if request.method == "POST":
        name = request.form["name"].strip()
        db.execute(
            "UPDATE testimonials SET name=?, promotion=?, content=?, rating=?, avatar_letter=?, lang=? WHERE id=?",
            (
                name,
                request.form["promotion"].strip(),
                request.form["content"].strip(),
                int(request.form.get("rating", 5)),
                name[0].upper() if name else "?",
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Témoignage mis à jour.", "success")
        return redirect(url_for("admin_testimonials"))
    return render_template("admin/testimonial_form.html", testimonial=testimonial)


@app.route("/admin/testimonials/<int:id>/delete", methods=["POST"])
@login_required
def admin_testimonial_delete(id):
    db = get_db()
    db.execute("DELETE FROM testimonials WHERE id = ?", (id,))
    db.commit()
    flash("Témoignage supprimé.", "success")
    return redirect(url_for("admin_testimonials"))


# --------------- Admin: Gallery CRUD ---------------

@app.route("/admin/gallery")
@login_required
def admin_gallery():
    db = get_db()
    images = db.execute("SELECT * FROM gallery ORDER BY sort_order").fetchall()
    return render_template("admin/gallery.html", images=images)


@app.route("/admin/gallery/add", methods=["GET", "POST"])
@login_required
def admin_gallery_add():
    if request.method == "POST":
        image_url = save_upload(request.files.get("image"), "gallery")
        if not image_url:
            flash("Veuillez sélectionner une image valide.", "error")
            return render_template("admin/gallery_form.html", image=None)
        db = get_db()
        db.execute(
            "INSERT INTO gallery (title, image, large, sort_order, lang) VALUES (?,?,?,?,?)",
            (
                request.form["title"].strip(),
                image_url,
                1 if request.form.get("large") else 0,
                int(request.form.get("sort_order", 0)),
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Image ajoutée à la galerie.", "success")
        return redirect(url_for("admin_gallery"))
    return render_template("admin/gallery_form.html", image=None)


@app.route("/admin/gallery/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_gallery_edit(id):
    db = get_db()
    image = db.execute("SELECT * FROM gallery WHERE id = ?", (id,)).fetchone()
    if not image:
        flash("Image introuvable.", "error")
        return redirect(url_for("admin_gallery"))
    if request.method == "POST":
        image_url = image["image"]
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "gallery") or image_url
        db.execute(
            "UPDATE gallery SET title=?, image=?, large=?, sort_order=?, lang=? WHERE id=?",
            (
                request.form["title"].strip(),
                image_url,
                1 if request.form.get("large") else 0,
                int(request.form.get("sort_order", 0)),
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Image mise à jour.", "success")
        return redirect(url_for("admin_gallery"))
    return render_template("admin/gallery_form.html", image=image)


@app.route("/admin/gallery/<int:id>/delete", methods=["POST"])
@login_required
def admin_gallery_delete(id):
    db = get_db()
    db.execute("DELETE FROM gallery WHERE id = ?", (id,))
    db.commit()
    flash("Image supprimée.", "success")
    return redirect(url_for("admin_gallery"))


# --------------- Admin: Inscriptions ---------------

@app.route("/admin/inscriptions")
@login_required
def admin_inscriptions():
    db = get_db()
    inscriptions = db.execute("SELECT * FROM inscriptions ORDER BY created_at DESC").fetchall()
    return render_template("admin/inscriptions.html", inscriptions=inscriptions)


@app.route("/admin/inscriptions/<int:id>/status", methods=["POST"])
@login_required
def admin_inscription_status(id):
    status = request.form.get("status", "nouveau")
    db = get_db()
    db.execute("UPDATE inscriptions SET status = ? WHERE id = ?", (status, id))
    db.commit()
    return redirect(url_for("admin_inscriptions"))


@app.route("/admin/inscriptions/<int:id>/delete", methods=["POST"])
@login_required
def admin_inscription_delete(id):
    db = get_db()
    db.execute("DELETE FROM inscriptions WHERE id = ?", (id,))
    db.commit()
    flash("Inscription supprimée.", "success")
    return redirect(url_for("admin_inscriptions"))


# --------------- Admin: Custom Sections CRUD ---------------

@app.route("/admin/sections")
@login_required
def admin_sections():
    db = get_db()
    sections = db.execute("SELECT * FROM custom_sections ORDER BY sort_order").fetchall()
    return render_template("admin/sections.html", sections=sections)


@app.route("/admin/sections/add", methods=["GET", "POST"])
@login_required
def admin_section_add():
    if request.method == "POST":
        image_url = ""
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "sections") or ""
        db = get_db()
        db.execute(
            """INSERT INTO custom_sections
            (section_key, title, subtitle, content, image, icon, button_text, button_link, animation, sort_order, active, lang)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                request.form.get("section_key", "").strip() or f"section_{uuid.uuid4().hex[:6]}",
                request.form["title"].strip(),
                request.form.get("subtitle", "").strip(),
                request.form.get("content", "").strip(),
                image_url,
                request.form.get("icon", "").strip(),
                request.form.get("button_text", "").strip(),
                request.form.get("button_link", "").strip(),
                request.form.get("animation", "fade-up"),
                int(request.form.get("sort_order", 0)),
                1 if request.form.get("active") is None or request.form.get("active") else 1,
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Section ajoutée avec succès.", "success")
        return redirect(url_for("admin_sections"))
    return render_template("admin/section_form.html", section=None)


@app.route("/admin/sections/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_section_edit(id):
    db = get_db()
    section = db.execute("SELECT * FROM custom_sections WHERE id = ?", (id,)).fetchone()
    if not section:
        flash("Section introuvable.", "error")
        return redirect(url_for("admin_sections"))
    if request.method == "POST":
        image_url = section["image"]
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "sections") or image_url
        db.execute(
            """UPDATE custom_sections SET
            section_key=?, title=?, subtitle=?, content=?, image=?, icon=?, button_text=?, button_link=?,
            animation=?, sort_order=?, active=?, lang=? WHERE id=?""",
            (
                request.form.get("section_key", "").strip(),
                request.form["title"].strip(),
                request.form.get("subtitle", "").strip(),
                request.form.get("content", "").strip(),
                image_url,
                request.form.get("icon", "").strip(),
                request.form.get("button_text", "").strip(),
                request.form.get("button_link", "").strip(),
                request.form.get("animation", "fade-up"),
                int(request.form.get("sort_order", 0)),
                1 if request.form.get("active") else 0,
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Section mise à jour.", "success")
        return redirect(url_for("admin_sections"))
    return render_template("admin/section_form.html", section=section)


@app.route("/admin/sections/<int:id>/delete", methods=["POST"])
@login_required
def admin_section_delete(id):
    db = get_db()
    db.execute("DELETE FROM custom_sections WHERE id = ?", (id,))
    db.commit()
    flash("Section supprimée.", "success")
    return redirect(url_for("admin_sections"))


@app.route("/admin/sections/<int:id>/toggle", methods=["POST"])
@login_required
def admin_section_toggle(id):
    db = get_db()
    db.execute("UPDATE custom_sections SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (id,))
    db.commit()
    return redirect(url_for("admin_sections"))


# --------------- Admin: Settings ---------------

@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    db = get_db()
    if request.method == "POST":
        # Handle logo upload
        if "logo_file" in request.files and request.files["logo_file"].filename:
            logo_url = save_upload(request.files["logo_file"], "branding")
            if logo_url:
                db.execute(
                    "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    ("logo_url", logo_url),
                )
        # Handle hero background image
        if "hero_bg_file" in request.files and request.files["hero_bg_file"].filename:
            hero_bg = save_upload(request.files["hero_bg_file"], "branding")
            if hero_bg:
                db.execute(
                    "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    ("hero_bg_image", hero_bg),
                )
        # Handle section visibility toggles (checkboxes send no value when unchecked)
        visibility_keys = ["show_hero", "show_about", "show_services", "show_formations",
                          "show_certificates", "show_gallery", "show_testimonials", "show_contact"]
        for vk in visibility_keys:
            value = "1" if request.form.get(f"setting_{vk}") else "0"
            db.execute(
                "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                (vk, value),
            )
        # Handle all other text settings
        for key in request.form:
            if key.startswith("setting_") and key[8:] not in visibility_keys:
                setting_key = key[8:]
                db.execute(
                    "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (setting_key, request.form[key].strip()),
                )
        db.commit()
        flash("Paramètres sauvegardés.", "success")
        return redirect(url_for("admin_settings"))
    settings = get_settings()
    return render_template("admin/settings.html", settings=settings)


# --------------- Admin: Change Password ---------------

@app.route("/admin/password", methods=["GET", "POST"])
@login_required
def admin_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pass = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        db = get_db()
        row = db.execute(
            "SELECT password_hash FROM admin_user WHERE id = ?", (current_user.id,)
        ).fetchone()
        if not check_password_hash(row["password_hash"], current):
            flash("Mot de passe actuel incorrect.", "error")
        elif len(new_pass) < 6:
            flash("Le nouveau mot de passe doit contenir au moins 6 caractères.", "error")
        elif new_pass != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
        else:
            db.execute(
                "UPDATE admin_user SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_pass), current_user.id),
            )
            db.commit()
            flash("Mot de passe modifié avec succès.", "success")
    return render_template("admin/password.html")


# --------------- Admin: Proposals ---------------

@app.route("/admin/proposals")
@login_required
def admin_proposals():
    db = get_db()
    proposals = db.execute("SELECT * FROM proposals ORDER BY created_at DESC").fetchall()
    return render_template("admin/proposals.html", proposals=proposals)


@app.route("/admin/proposals/<int:id>/status", methods=["POST"])
@login_required
def admin_proposal_status(id):
    db = get_db()
    db.execute("UPDATE proposals SET status=?, admin_notes=? WHERE id=?",
               (request.form.get("status", "nouveau"), request.form.get("admin_notes", ""), id))
    db.commit()
    flash("Proposition mise à jour.", "success")
    return redirect(url_for("admin_proposals"))


@app.route("/admin/proposals/<int:id>/delete", methods=["POST"])
@login_required
def admin_proposal_delete(id):
    db = get_db()
    db.execute("DELETE FROM proposals WHERE id = ?", (id,))
    db.commit()
    flash("Proposition supprimée.", "success")
    return redirect(url_for("admin_proposals"))


# --------------- Admin: FAQs CRUD ---------------

@app.route("/admin/faqs")
@login_required
def admin_faqs():
    db = get_db()
    faqs = db.execute("SELECT * FROM faqs ORDER BY sort_order").fetchall()
    return render_template("admin/faqs.html", faqs=faqs)


@app.route("/admin/faqs/add", methods=["GET", "POST"])
@login_required
def admin_faq_add():
    if request.method == "POST":
        db = get_db()
        db.execute("INSERT INTO faqs (question, answer, sort_order, lang) VALUES (?,?,?,?)",
                   (request.form["question"].strip(), request.form["answer"].strip(),
                    int(request.form.get("sort_order", 0)), request.form.get("lang", "fr")))
        db.commit()
        flash("FAQ ajoutée.", "success")
        return redirect(url_for("admin_faqs"))
    return render_template("admin/faq_form.html", faq=None)


@app.route("/admin/faqs/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_faq_edit(id):
    db = get_db()
    faq = db.execute("SELECT * FROM faqs WHERE id = ?", (id,)).fetchone()
    if not faq:
        flash("FAQ introuvable.", "error")
        return redirect(url_for("admin_faqs"))
    if request.method == "POST":
        db.execute("UPDATE faqs SET question=?, answer=?, sort_order=?, lang=? WHERE id=?",
                   (request.form["question"].strip(), request.form["answer"].strip(),
                    int(request.form.get("sort_order", 0)), request.form.get("lang", "fr"), id))
        db.commit()
        flash("FAQ mise à jour.", "success")
        return redirect(url_for("admin_faqs"))
    return render_template("admin/faq_form.html", faq=faq)


@app.route("/admin/faqs/<int:id>/delete", methods=["POST"])
@login_required
def admin_faq_delete(id):
    db = get_db()
    db.execute("DELETE FROM faqs WHERE id = ?", (id,))
    db.commit()
    flash("FAQ supprimée.", "success")
    return redirect(url_for("admin_faqs"))


# --------------- Admin: Training Sessions CRUD ---------------

@app.route("/admin/sessions")
@login_required
def admin_sessions():
    db = get_db()
    sessions = db.execute("SELECT * FROM training_sessions ORDER BY start_date").fetchall()
    return render_template("admin/sessions.html", sessions=sessions)


@app.route("/admin/sessions/add", methods=["GET", "POST"])
@login_required
def admin_session_add():
    if request.method == "POST":
        db = get_db()
        db.execute(
            "INSERT INTO training_sessions (title, start_date, end_date, spots_total, spots_taken, location, active, lang) VALUES (?,?,?,?,?,?,?,?)",
            (request.form["title"].strip(), request.form["start_date"], request.form.get("end_date", ""),
             int(request.form.get("spots_total", 20)), int(request.form.get("spots_taken", 0)),
             request.form.get("location", "").strip(), 1, request.form.get("lang", "fr")))
        db.commit()
        flash("Session ajoutée.", "success")
        return redirect(url_for("admin_sessions"))
    return render_template("admin/session_form.html", session=None)


@app.route("/admin/sessions/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_session_edit(id):
    db = get_db()
    sess = db.execute("SELECT * FROM training_sessions WHERE id = ?", (id,)).fetchone()
    if not sess:
        flash("Session introuvable.", "error")
        return redirect(url_for("admin_sessions"))
    if request.method == "POST":
        db.execute(
            "UPDATE training_sessions SET title=?, start_date=?, end_date=?, spots_total=?, spots_taken=?, location=?, active=?, lang=? WHERE id=?",
            (request.form["title"].strip(), request.form["start_date"], request.form.get("end_date", ""),
             int(request.form.get("spots_total", 20)), int(request.form.get("spots_taken", 0)),
             request.form.get("location", "").strip(), 1 if request.form.get("active") else 0,
             request.form.get("lang", "fr"), id))
        db.commit()
        flash("Session mise à jour.", "success")
        return redirect(url_for("admin_sessions"))
    return render_template("admin/session_form.html", session=sess)


@app.route("/admin/sessions/<int:id>/delete", methods=["POST"])
@login_required
def admin_session_delete(id):
    db = get_db()
    db.execute("DELETE FROM training_sessions WHERE id = ?", (id,))
    db.commit()
    flash("Session supprimée.", "success")
    return redirect(url_for("admin_sessions"))


# --------------- Admin: Partners CRUD ---------------

@app.route("/admin/partners")
@login_required
def admin_partners():
    db = get_db()
    partners = db.execute("SELECT * FROM partners ORDER BY sort_order").fetchall()
    return render_template("admin/partners.html", partners=partners)


@app.route("/admin/partners/add", methods=["GET", "POST"])
@login_required
def admin_partner_add():
    if request.method == "POST":
        logo_url = save_upload(request.files.get("logo"), "partners")
        if not logo_url:
            flash("Veuillez sélectionner un logo.", "error")
            return render_template("admin/partner_form.html", partner=None)
        db = get_db()
        db.execute("INSERT INTO partners (name, logo, website_url, sort_order) VALUES (?,?,?,?)",
                   (request.form["name"].strip(), logo_url,
                    request.form.get("website_url", "").strip(), int(request.form.get("sort_order", 0))))
        db.commit()
        flash("Partenaire ajouté.", "success")
        return redirect(url_for("admin_partners"))
    return render_template("admin/partner_form.html", partner=None)


@app.route("/admin/partners/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_partner_edit(id):
    db = get_db()
    partner = db.execute("SELECT * FROM partners WHERE id = ?", (id,)).fetchone()
    if not partner:
        flash("Partenaire introuvable.", "error")
        return redirect(url_for("admin_partners"))
    if request.method == "POST":
        logo_url = partner["logo"]
        if "logo" in request.files and request.files["logo"].filename:
            logo_url = save_upload(request.files["logo"], "partners") or logo_url
        db.execute("UPDATE partners SET name=?, logo=?, website_url=?, sort_order=? WHERE id=?",
                   (request.form["name"].strip(), logo_url,
                    request.form.get("website_url", "").strip(), int(request.form.get("sort_order", 0)), id))
        db.commit()
        flash("Partenaire mis à jour.", "success")
        return redirect(url_for("admin_partners"))
    return render_template("admin/partner_form.html", partner=partner)


@app.route("/admin/partners/<int:id>/delete", methods=["POST"])
@login_required
def admin_partner_delete(id):
    db = get_db()
    db.execute("DELETE FROM partners WHERE id = ?", (id,))
    db.commit()
    flash("Partenaire supprimé.", "success")
    return redirect(url_for("admin_partners"))


# --------------- Student Auth Helpers ---------------

def get_current_student():
    sid = flask_session.get("student_id")
    if sid:
        db = get_db()
        return db.execute("SELECT * FROM students WHERE id = ? AND active = 1", (sid,)).fetchone()
    return None


def student_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        student = get_current_student()
        if not student:
            return redirect(url_for("student_login"))
        g.student = student
        return f(*args, **kwargs)
    return decorated


def check_and_award_rewards(student_id):
    """Check and award any earned rewards."""
    db = get_db()
    rewards = db.execute("SELECT * FROM rewards WHERE active = 1").fetchall()
    for r in rewards:
        already = db.execute("SELECT id FROM student_rewards WHERE student_id=? AND reward_id=?", (student_id, r["id"])).fetchone()
        if already:
            continue
        earned = False
        if r["criteria"] == "first_login":
            earned = True
        elif r["criteria"] == "watch_10_videos":
            count = db.execute("SELECT COUNT(*) FROM student_progress WHERE student_id=? AND completed=1", (student_id,)).fetchone()[0]
            earned = count >= 10
        elif r["criteria"] == "perfect_quiz":
            perfect = db.execute("SELECT id FROM quiz_attempts WHERE student_id=? AND score=total AND total>0", (student_id,)).fetchone()
            earned = perfect is not None
        elif r["criteria"] == "complete_course":
            completed = db.execute("SELECT id FROM student_enrollments WHERE student_id=? AND completed=1", (student_id,)).fetchone()
            earned = completed is not None
        elif r["criteria"] == "all_videos_course":
            enrollments = db.execute("SELECT course_id FROM student_enrollments WHERE student_id=?", (student_id,)).fetchall()
            for e in enrollments:
                total = db.execute("SELECT COUNT(*) FROM course_modules WHERE course_id=?", (e["course_id"],)).fetchone()[0]
                done = db.execute("""SELECT COUNT(*) FROM student_progress sp
                    JOIN course_modules cm ON sp.module_id=cm.id
                    WHERE sp.student_id=? AND cm.course_id=? AND sp.completed=1""",
                    (student_id, e["course_id"])).fetchone()[0]
                if total > 0 and done >= total:
                    earned = True
                    break
        if earned:
            db.execute("INSERT INTO student_rewards (student_id, reward_id) VALUES (?,?) ON CONFLICT (student_id, reward_id) DO NOTHING", (student_id, r["id"]))
    db.commit()


# --------------- Student Routes ---------------

@app.route("/student/signup", methods=["GET", "POST"])
def student_signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        phone = request.form.get("phone", "").strip()
        if not all([email, password, first_name, last_name]):
            flash("Tous les champs sont requis.", "error")
            return render_template("student/signup.html")
        if len(password) < 6:
            flash("Le mot de passe doit contenir au moins 6 caractères.", "error")
            return render_template("student/signup.html")
        db = get_db()
        existing = db.execute("SELECT id FROM students WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("Cet email est déjà utilisé.", "error")
            return render_template("student/signup.html")
        db.execute(
            "INSERT INTO students (first_name, last_name, email, password_hash, phone, avatar_letter) VALUES (?,?,?,?,?,?)",
            (first_name, last_name, email, generate_password_hash(password), phone, first_name[0].upper()))
        db.commit()
        student = db.execute("SELECT id FROM students WHERE email = ?", (email,)).fetchone()
        flask_session["student_id"] = student["id"]
        check_and_award_rewards(student["id"])
        flash("Bienvenue ! Votre compte a été créé.", "success")
        return redirect(url_for("student_dashboard"))
    return render_template("student/signup.html")


@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if get_current_student():
        return redirect(url_for("student_dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        student = db.execute("SELECT * FROM students WHERE email = ? AND active = 1", (email,)).fetchone()
        if student and check_password_hash(student["password_hash"], password):
            flask_session["student_id"] = student["id"]
            check_and_award_rewards(student["id"])
            return redirect(url_for("student_dashboard"))
        flash("Email ou mot de passe incorrect.", "error")
    return render_template("student/login.html")


@app.route("/student/logout")
def student_logout():
    flask_session.pop("student_id", None)
    return redirect(url_for("student_login"))


@app.route("/student/dashboard")
@student_required
def student_dashboard():
    db = get_db()
    student = g.student
    enrollments = db.execute("""
        SELECT se.*, c.title, c.image, c.category, c.meet_link,
            (SELECT COUNT(*) FROM course_modules WHERE course_id=c.id) as total_modules,
            (SELECT COUNT(*) FROM student_progress sp JOIN course_modules cm ON sp.module_id=cm.id
             WHERE sp.student_id=? AND cm.course_id=c.id AND sp.completed=1) as completed_modules
        FROM student_enrollments se
        JOIN courses c ON se.course_id = c.id
        WHERE se.student_id = ? ORDER BY se.enrolled_at DESC
    """, (student["id"], student["id"])).fetchall()
    rewards = db.execute("""
        SELECT r.*, sr.earned_at FROM student_rewards sr
        JOIN rewards r ON sr.reward_id = r.id
        WHERE sr.student_id = ? ORDER BY sr.earned_at DESC
    """, (student["id"],)).fetchall()
    total_watched = db.execute("SELECT COUNT(*) FROM student_progress WHERE student_id=? AND completed=1", (student["id"],)).fetchone()[0]
    return render_template("student/dashboard.html", student=student, enrollments=enrollments, rewards=rewards, total_watched=total_watched)


@app.route("/student/courses")
@student_required
def student_courses():
    db = get_db()
    courses = db.execute("SELECT * FROM courses WHERE active = 1 ORDER BY created_at DESC").fetchall()
    enrolled_ids = [r["course_id"] for r in db.execute("SELECT course_id FROM student_enrollments WHERE student_id=?", (g.student["id"],)).fetchall()]
    return render_template("student/courses.html", courses=courses, enrolled_ids=enrolled_ids)


@app.route("/student/enroll/<int:course_id>", methods=["POST"])
@student_required
def student_enroll(course_id):
    db = get_db()
    existing = db.execute("SELECT id FROM student_enrollments WHERE student_id=? AND course_id=?", (g.student["id"], course_id)).fetchone()
    if not existing:
        db.execute("INSERT INTO student_enrollments (student_id, course_id) VALUES (?,?)", (g.student["id"], course_id))
        db.commit()
        flash("Vous êtes inscrit au cours !", "success")
    return redirect(url_for("student_course", course_id=course_id))


@app.route("/student/course/<int:course_id>")
@student_required
def student_course(course_id):
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if not course:
        return redirect(url_for("student_courses"))
    enrollment = db.execute("SELECT * FROM student_enrollments WHERE student_id=? AND course_id=?", (g.student["id"], course_id)).fetchone()
    modules = db.execute("SELECT * FROM course_modules WHERE course_id = ? ORDER BY sort_order", (course_id,)).fetchall()
    progress = {}
    for m in modules:
        p = db.execute("SELECT * FROM student_progress WHERE student_id=? AND module_id=?", (g.student["id"], m["id"])).fetchone()
        progress[m["id"]] = p
    return render_template("student/course.html", course=course, modules=modules, progress=progress, enrollment=enrollment)


@app.route("/student/module/<int:module_id>")
@student_required
def student_module(module_id):
    db = get_db()
    module = db.execute("SELECT * FROM course_modules WHERE id = ?", (module_id,)).fetchone()
    if not module:
        return redirect(url_for("student_courses"))
    course = db.execute("SELECT * FROM courses WHERE id = ?", (module["course_id"],)).fetchone()
    # Mark as watched
    existing = db.execute("SELECT * FROM student_progress WHERE student_id=? AND module_id=?", (g.student["id"], module_id)).fetchone()
    if not existing:
        db.execute("INSERT INTO student_progress (student_id, module_id, watched, completed) VALUES (?,?,1,0)", (g.student["id"], module_id))
        db.commit()
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id = ? ORDER BY sort_order", (module_id,)).fetchall()
    return render_template("student/module.html", module=module, course=course, quizzes=quizzes)


@app.route("/student/module/<int:module_id>/complete", methods=["POST"])
@student_required
def student_complete_module(module_id):
    db = get_db()
    db.execute("""INSERT INTO student_progress (student_id, module_id, watched, completed, completed_at)
        VALUES (?,?,1,1,CURRENT_TIMESTAMP)
        ON CONFLICT(student_id, module_id) DO UPDATE SET completed=1, watched=1, completed_at=CURRENT_TIMESTAMP""",
        (g.student["id"], module_id))
    db.commit()
    # Check if course is complete
    module = db.execute("SELECT course_id FROM course_modules WHERE id=?", (module_id,)).fetchone()
    if module:
        total = db.execute("SELECT COUNT(*) FROM course_modules WHERE course_id=?", (module["course_id"],)).fetchone()[0]
        done = db.execute("""SELECT COUNT(*) FROM student_progress sp JOIN course_modules cm ON sp.module_id=cm.id
            WHERE sp.student_id=? AND cm.course_id=? AND sp.completed=1""",
            (g.student["id"], module["course_id"])).fetchone()[0]
        if done >= total and total > 0:
            db.execute("UPDATE student_enrollments SET completed=1, completed_at=CURRENT_TIMESTAMP WHERE student_id=? AND course_id=?",
                       (g.student["id"], module["course_id"]))
            db.commit()
    check_and_award_rewards(g.student["id"])
    flash("Module terminé !", "success")
    return redirect(url_for("student_module", module_id=module_id))


@app.route("/student/quiz/<int:module_id>", methods=["POST"])
@student_required
def student_submit_quiz(module_id):
    db = get_db()
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id=? ORDER BY sort_order", (module_id,)).fetchall()
    score = 0
    for q in quizzes:
        answer = request.form.get(f"q_{q['id']}", "")
        if answer == q["correct_answer"]:
            score += 1
    total = len(quizzes)
    passed = 1 if total > 0 and (score / total) >= 0.7 else 0
    db.execute("INSERT INTO quiz_attempts (student_id, module_id, score, total, passed) VALUES (?,?,?,?,?)",
               (g.student["id"], module_id, score, total, passed))
    db.commit()
    if passed:
        # Auto-complete module on quiz pass
        db.execute("""INSERT INTO student_progress (student_id, module_id, watched, completed, completed_at)
            VALUES (?,?,1,1,CURRENT_TIMESTAMP)
            ON CONFLICT(student_id, module_id) DO UPDATE SET completed=1, watched=1, completed_at=CURRENT_TIMESTAMP""",
            (g.student["id"], module_id))
        db.commit()
    check_and_award_rewards(g.student["id"])
    flash(f"Quiz terminé : {score}/{total} {'- Réussi !' if passed else '- Essayez encore.'}", "success" if passed else "error")
    return redirect(url_for("student_module", module_id=module_id))


@app.route("/student/certificates")
@student_required
def student_certificates():
    db = get_db()
    completed = db.execute("""
        SELECT se.*, c.title, c.image, c.instructor, se.completed_at
        FROM student_enrollments se JOIN courses c ON se.course_id = c.id
        WHERE se.student_id = ? AND se.completed = 1
    """, (g.student["id"],)).fetchall()
    return render_template("student/certificates.html", completed=completed, student=g.student)


# --------------- Admin: LMS Management ---------------

@app.route("/admin/courses")
@login_required
def admin_courses():
    db = get_db()
    courses = db.execute("SELECT * FROM courses ORDER BY created_at DESC").fetchall()
    return render_template("admin/courses.html", courses=courses)


@app.route("/admin/courses/add", methods=["GET", "POST"])
@login_required
def admin_course_add():
    if request.method == "POST":
        image_url = ""
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "courses") or ""
        db = get_db()
        db.execute(
            "INSERT INTO courses (title, description, category, image, duration, meet_link, instructor, lang) VALUES (?,?,?,?,?,?,?,?)",
            (request.form["title"].strip(), request.form["description"].strip(), request.form.get("category", "culinary"),
             image_url, request.form.get("duration", "").strip(), request.form.get("meet_link", "").strip(),
             request.form.get("instructor", "").strip(), request.form.get("lang", "fr")))
        db.commit()
        flash("Cours ajouté.", "success")
        return redirect(url_for("admin_courses"))
    return render_template("admin/course_form.html", course=None)


@app.route("/admin/courses/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_course_edit(id):
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (id,)).fetchone()
    if not course:
        flash("Cours introuvable.", "error")
        return redirect(url_for("admin_courses"))
    if request.method == "POST":
        image_url = course["image"]
        if "image" in request.files and request.files["image"].filename:
            image_url = save_upload(request.files["image"], "courses") or image_url
        db.execute(
            "UPDATE courses SET title=?, description=?, category=?, image=?, duration=?, meet_link=?, instructor=?, lang=? WHERE id=?",
            (request.form["title"].strip(), request.form["description"].strip(), request.form.get("category", "culinary"),
             image_url, request.form.get("duration", "").strip(), request.form.get("meet_link", "").strip(),
             request.form.get("instructor", "").strip(), request.form.get("lang", "fr"), id))
        db.commit()
        flash("Cours mis à jour.", "success")
        return redirect(url_for("admin_courses"))
    return render_template("admin/course_form.html", course=course)


@app.route("/admin/courses/<int:id>/delete", methods=["POST"])
@login_required
def admin_course_delete(id):
    db = get_db()
    db.execute("DELETE FROM courses WHERE id=?", (id,))
    db.commit()
    flash("Cours supprimé.", "success")
    return redirect(url_for("admin_courses"))


@app.route("/admin/courses/<int:course_id>/modules")
@login_required
def admin_modules(course_id):
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    modules = db.execute("SELECT * FROM course_modules WHERE course_id=? ORDER BY sort_order", (course_id,)).fetchall()
    return render_template("admin/modules.html", course=course, modules=modules)


@app.route("/admin/courses/<int:course_id>/modules/add", methods=["GET", "POST"])
@login_required
def admin_module_add(course_id):
    if request.method == "POST":
        db = get_db()
        db.execute(
            "INSERT INTO course_modules (course_id, title, description, video_url, materials_url, duration_minutes, sort_order) VALUES (?,?,?,?,?,?,?)",
            (course_id, request.form["title"].strip(), request.form.get("description", "").strip(),
             request.form.get("video_url", "").strip(), request.form.get("materials_url", "").strip(),
             int(request.form.get("duration_minutes", 0)), int(request.form.get("sort_order", 0))))
        db.commit()
        flash("Module ajouté.", "success")
        return redirect(url_for("admin_modules", course_id=course_id))
    return render_template("admin/module_form.html", module=None, course_id=course_id)


@app.route("/admin/modules/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_module_edit(id):
    db = get_db()
    module = db.execute("SELECT * FROM course_modules WHERE id=?", (id,)).fetchone()
    if not module:
        flash("Module introuvable.", "error")
        return redirect(url_for("admin_courses"))
    if request.method == "POST":
        db.execute(
            "UPDATE course_modules SET title=?, description=?, video_url=?, materials_url=?, duration_minutes=?, sort_order=? WHERE id=?",
            (request.form["title"].strip(), request.form.get("description", "").strip(),
             request.form.get("video_url", "").strip(), request.form.get("materials_url", "").strip(),
             int(request.form.get("duration_minutes", 0)), int(request.form.get("sort_order", 0)), id))
        db.commit()
        flash("Module mis à jour.", "success")
        return redirect(url_for("admin_modules", course_id=module["course_id"]))
    return render_template("admin/module_form.html", module=module, course_id=module["course_id"])


@app.route("/admin/modules/<int:id>/delete", methods=["POST"])
@login_required
def admin_module_delete(id):
    db = get_db()
    module = db.execute("SELECT course_id FROM course_modules WHERE id=?", (id,)).fetchone()
    course_id = module["course_id"] if module else 0
    db.execute("DELETE FROM course_modules WHERE id=?", (id,))
    db.commit()
    flash("Module supprimé.", "success")
    return redirect(url_for("admin_modules", course_id=course_id))


@app.route("/admin/modules/<int:module_id>/quizzes", methods=["GET", "POST"])
@login_required
def admin_quizzes(module_id):
    db = get_db()
    module = db.execute("SELECT * FROM course_modules WHERE id=?", (module_id,)).fetchone()
    if request.method == "POST":
        db.execute(
            "INSERT INTO quizzes (module_id, question, option_a, option_b, option_c, option_d, correct_answer, sort_order) VALUES (?,?,?,?,?,?,?,?)",
            (module_id, request.form["question"].strip(), request.form["option_a"].strip(),
             request.form["option_b"].strip(), request.form.get("option_c", "").strip(),
             request.form.get("option_d", "").strip(), request.form["correct_answer"],
             int(request.form.get("sort_order", 0))))
        db.commit()
        flash("Question ajoutée.", "success")
        return redirect(url_for("admin_quizzes", module_id=module_id))
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id=? ORDER BY sort_order", (module_id,)).fetchall()
    return render_template("admin/quizzes.html", module=module, quizzes=quizzes)


@app.route("/admin/quizzes/<int:id>/delete", methods=["POST"])
@login_required
def admin_quiz_delete(id):
    db = get_db()
    quiz = db.execute("SELECT module_id FROM quizzes WHERE id=?", (id,)).fetchone()
    module_id = quiz["module_id"] if quiz else 0
    db.execute("DELETE FROM quizzes WHERE id=?", (id,))
    db.commit()
    flash("Question supprimée.", "success")
    return redirect(url_for("admin_quizzes", module_id=module_id))


@app.route("/admin/students")
@login_required
def admin_students():
    db = get_db()
    students = db.execute("SELECT * FROM students ORDER BY created_at DESC").fetchall()
    return render_template("admin/students.html", students=students)


@app.route("/admin/students/<int:id>/progress")
@login_required
def admin_student_progress(id):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id=?", (id,)).fetchone()
    enrollments = db.execute("""
        SELECT se.*, c.title as course_title,
            (SELECT COUNT(*) FROM course_modules WHERE course_id=c.id) as total_modules,
            (SELECT COUNT(*) FROM student_progress sp JOIN course_modules cm ON sp.module_id=cm.id
             WHERE sp.student_id=? AND cm.course_id=c.id AND sp.completed=1) as completed_modules
        FROM student_enrollments se JOIN courses c ON se.course_id=c.id
        WHERE se.student_id=?
    """, (id, id)).fetchall()
    quiz_results = db.execute("""
        SELECT qa.*, cm.title as module_title FROM quiz_attempts qa
        JOIN course_modules cm ON qa.module_id=cm.id
        WHERE qa.student_id=? ORDER BY qa.attempted_at DESC
    """, (id,)).fetchall()
    rewards = db.execute("""
        SELECT r.*, sr.earned_at FROM student_rewards sr
        JOIN rewards r ON sr.reward_id=r.id WHERE sr.student_id=?
    """, (id,)).fetchall()
    return render_template("admin/student_progress.html", student=student, enrollments=enrollments, quiz_results=quiz_results, rewards=rewards)


@app.route("/admin/rewards")
@login_required
def admin_rewards():
    db = get_db()
    rewards = db.execute("SELECT * FROM rewards ORDER BY id").fetchall()
    return render_template("admin/rewards.html", rewards=rewards)


# --------------- Run ---------------

if __name__ == "__main__":
    init_db()
    migrate_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
