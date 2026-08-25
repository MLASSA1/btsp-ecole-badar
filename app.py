import hashlib
import os
import re
import secrets
import shutil
import uuid
from datetime import date
from functools import wraps
from werkzeug.security import generate_password_hash as _generate_password_hash
from werkzeug.security import check_password_hash

# Werkzeug defaults to scrypt, which needs a Python built against a recent
# OpenSSL. Fall back to pbkdf2 where scrypt is unavailable (e.g. the stock
# macOS Python 3.9). check_password_hash reads the method from the stored
# hash, so both kinds of hashes keep working side by side.
PASSWORD_HASH_METHOD = "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256"


def generate_password_hash(password):
    return _generate_password_hash(password, method=PASSWORD_HASH_METHOD)
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
# In production the app runs from a container image that is replaced on every
# release, so the database and the uploaded media have to live on a mounted
# volume instead of next to the code — otherwise a deploy silently discards
# every pupil, class and payment record.
DB_PATH = os.environ.get("BTSP_DB_PATH") or os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.environ.get("BTSP_UPLOAD_DIR") or os.path.join(BASE_DIR, "uploads")
BUNDLED_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "admin", "templates"),
    static_folder=os.path.join(BASE_DIR, "admin", "static"),
    static_url_path="/admin/static",
)
def _load_secret_key():
    """A stable key across workers and restarts.

    A per-process random key means each gunicorn worker signs sessions with a
    different secret, so users get logged out at random. Prefer the env var;
    otherwise persist one next to the database.
    """
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    keyfile = os.path.join(BASE_DIR, ".secret_key")
    try:
        with open(keyfile) as fh:
            saved = fh.read().strip()
        if saved:
            return saved
    except OSError:
        pass
    generated = secrets.token_hex(32)
    try:
        with open(keyfile, "w") as fh:
            fh.write(generated)
        os.chmod(keyfile, 0o600)
    except OSError:
        print(">>> WARNING: could not persist SECRET_KEY; set the SECRET_KEY env var.")
    return generated


app.config["SECRET_KEY"] = _load_secret_key()
# SameSite=Lax stops the browser sending session cookies on cross-site POSTs,
# which is what a CSRF attack needs.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS", "").lower() in ("1", "true", "yes")
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
            g.db = sqlite3.connect(DB_PATH, timeout=15)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA foreign_keys=ON")
            # Wait for a concurrent writer instead of failing instantly. With
            # several gunicorn workers on one SQLite file, the default (0 ms)
            # turns a momentary overlap into a 500.
            g.db.execute("PRAGMA busy_timeout=15000")
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
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'super',
            full_name TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            long_description TEXT DEFAULT '',
            program_content TEXT DEFAULT '',
            prerequisites TEXT DEFAULT '',
            career_outcomes TEXT DEFAULT '',
            schedule TEXT DEFAULT '',
            price TEXT DEFAULT '',
            next_start TEXT DEFAULT '',
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
        # --------- School administration: teachers, classes, pupils, fees ---------
        f"""CREATE TABLE IF NOT EXISTS teachers (
            id {auto_id},
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            specialty TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            photo TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS school_classes (
            id {auto_id},
            name TEXT NOT NULL,
            formation_id INTEGER,
            teacher_id INTEGER,
            academic_year TEXT DEFAULT '',
            monthly_fee REAL DEFAULT 0,
            room TEXT DEFAULT '',
            schedule TEXT DEFAULT '',
            start_date TEXT DEFAULT '',
            end_date TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        f"""CREATE TABLE IF NOT EXISTS class_students (
            id {auto_id},
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            guardian_phone TEXT DEFAULT '',
            class_id INTEGER,
            monthly_fee REAL DEFAULT 0,
            enrolled_on TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        # One row per pupil per month. No row at all means "not paid yet", so a
        # fresh month needs no seeding.
        f"""CREATE TABLE IF NOT EXISTS payments (
            id {auto_id},
            student_id INTEGER NOT NULL,
            class_id INTEGER,
            year INTEGER NOT NULL,
            month INTEGER NOT NULL,
            amount REAL DEFAULT 0,
            status TEXT DEFAULT 'paid',
            method TEXT DEFAULT '',
            paid_on TEXT DEFAULT '',
            note TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (student_id, year, month)
        )""",
    ]

    _run_ddl(db, tables)

    # Create the first admin account.
    #
    # A hard-coded default password is fine on a laptop and fatal on a public
    # host: this repository is public, so anyone could read it and sign in to
    # the live school back-office. Take the credentials from the environment,
    # and when none are set invent a random password and print it once rather
    # than falling back to something guessable.
    existing = db.execute("SELECT id FROM admin_user LIMIT 1").fetchone()
    if not existing:
        admin_name = os.environ.get("BTSP_ADMIN_USER", "admin").strip() or "admin"
        admin_pass = os.environ.get("BTSP_ADMIN_PASSWORD", "").strip()
        generated = not admin_pass
        if generated:
            admin_pass = secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO admin_user (username, password_hash) VALUES (?, ?)",
            (admin_name, generate_password_hash(admin_pass)),
        )
        if generated:
            print(f">>> First admin created: {admin_name} / {admin_pass}")
            print(">>> This password is shown once. Save it, then change it after login.")
        else:
            print(f">>> First admin created: {admin_name} (password taken from BTSP_ADMIN_PASSWORD)")

    # Seed site settings
    defaults = {
        "site_name": "BTSP",
        "site_name_full": "École BADAR Training and Service",
        "site_tagline": "Établissement Privé de Formation Professionnelle",
        "about_title": "Un Centre d'Excellence au Service de Votre Avenir",
        "about_text": "BTSP est un établissement privé de formation professionnelle au Maroc, spécialisé dans les arts culinaires, l'hôtellerie et les technologies de l'information. Notre pédagogie allie pratique intensive, expertise professionnelle et cours en ligne.",
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
        "show_pillars": "1",
        "show_services": "1",
        "show_formations": "1",
        "show_online": "1",
        "show_process": "1",
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
            # Catalogue réel BTSP. Les durées non communiquées par l'école sont
            # renseignées « Nous consulter » plutôt qu'inventées.
            ("Réceptionniste d'Hôtel", 'Accueil et enregistrement des clients, gestion des réservations, facturation et relation client en établissement hôtelier.', 'Nous consulter', 'Certificat', 'Accueil & check-in / check-out|Gestion des réservations|Facturation et encaissement|Logiciels de réception', '', '', 0, 1, 'hospitality', "fr"),
            ('Femme de Chambre / Valet de Chambre', "Entretien et remise en état des chambres, gestion du linge, produits et protocoles d'hygiène en hôtellerie.", 'Nous consulter', 'Certificat', "Remise en état des chambres|Gestion du linge et des stocks d'étage|Produits et protocoles d'hygiène|Organisation et rapidité d'exécution", '', '', 0, 2, 'hospitality', "fr"),
            ('Barman – Barista', 'Préparation des boissons chaudes et froides, techniques de bar, cocktails, extraction du café et service au comptoir.', 'Nous consulter', 'Certificat', 'Techniques de bar et cocktails|Extraction et latte art|Carte des boissons|Service au comptoir', '', '', 0, 3, 'hospitality', "fr"),
            ('Service en Restauration Gastronomique', 'Service en salle haut de gamme : mise en place, techniques de service, accord mets et boissons, relation avec la clientèle.', 'Nous consulter', 'Certificat', "Mise en place et dressage|Techniques de service à l'assiette|Accord mets et boissons|Prise de commande et conseil", '', '', 0, 4, 'hospitality', "fr"),
            ('Relation Client et Accueil', "Techniques d'accueil, gestion des réclamations et qualité de service dans les métiers en contact avec la clientèle.", 'Nous consulter', 'Attestation', "Techniques d'accueil|Gestion des réclamations|Qualité de service|Fidélisation de la clientèle", '', '', 0, 5, 'hospitality', "fr"),
            ('Cuisine Marocaine et Internationale', 'Techniques de cuisson, préparations de base, cuisine marocaine traditionnelle et grands classiques de la cuisine internationale.', 'Nous consulter', 'Certificat', 'Techniques de cuisson et découpe|Cuisine marocaine traditionnelle|Cuisine internationale|Hygiène et organisation du poste', '', 'Populaire', 1, 10, 'culinary', "fr"),
            ('Boulangerie', 'Pétrissage, fermentation, façonnage et cuisson : pains traditionnels, pains spéciaux et viennoiseries.', 'Nous consulter', 'Certificat', 'Pétrissage et fermentation|Pains traditionnels et spéciaux|Viennoiseries|Cuisson et finition', '', '', 0, 11, 'culinary', "fr"),
            ('Boucherie et Charcuterie', "Découpe et désossage, préparation des viandes, charcuterie, conservation et présentation à l'étal.", 'Nous consulter', 'Certificat', 'Découpe et désossage|Préparations bouchères|Charcuterie et salaisons|Conservation et traçabilité', '', '', 0, 12, 'culinary', "fr"),
            ('Traiteur et Organisation des Événements', 'Conception de buffets, production en volume, logistique et coordination des prestations traiteur et événementielles.', 'Nous consulter', 'Certificat', 'Conception de buffets et menus|Production en volume|Logistique et matériel|Coordination du jour J', '', '', 0, 13, 'culinary', "fr"),
            ('Décoration et Présentation des Plats', "Dressage à l'assiette, harmonie des couleurs, techniques de décoration et mise en valeur des préparations.", 'Nous consulter', 'Certificat', "Dressage à l'assiette|Harmonie des couleurs et volumes|Techniques de décor|Photographie culinaire", '', '', 0, 14, 'culinary', "fr"),
            ('Sécurité Alimentaire (Food Safety)', "Règles d'hygiène en cuisine professionnelle, chaîne du froid, traçabilité et principes HACCP.", 'Nous consulter', 'Attestation', 'Hygiène du personnel et des locaux|Chaîne du froid et stockage|Traçabilité|Principes HACCP', '', '', 0, 15, 'culinary', "fr"),
            ('Gestion des Stocks et Approvisionnement', 'Réception et contrôle des marchandises, rotation des stocks, inventaires et relation avec les fournisseurs.', 'Nous consulter', 'Certificat', 'Réception et contrôle|Rotation et rangement des stocks|Inventaires|Commandes et fournisseurs', '', '', 0, 20, 'business', "fr"),
            ('Commerce et Vente', 'Techniques de vente, argumentaire commercial, négociation et suivi de la clientèle.', 'Nous consulter', 'Certificat', 'Techniques de vente|Argumentaire et négociation|Suivi client|Objectifs et reporting', '', '', 0, 21, 'business', "fr"),
            ("Entrepreneuriat et Création d'Entreprise", "De l'idée au projet : étude de marché, business plan, démarches de création et gestion des premiers mois d'activité.", 'Nous consulter', 'Certificat', 'Étude de marché|Business plan|Démarches de création|Gestion et financement', '', '', 0, 22, 'business', "fr"),
            ('Informatique Bureautique (Word, Excel, PowerPoint)', 'Maîtrise des outils bureautiques du quotidien : traitement de texte, tableurs et présentations professionnelles.', 'Nous consulter', 'Certificat', 'Word — documents professionnels|Excel — tableaux et formules|PowerPoint — présentations|Organisation des fichiers et impression', '', '', 0, 30, 'business', "fr"),
            ('Marketing Digital', 'Présence en ligne, réseaux sociaux, création de contenu et campagnes publicitaires pour développer une activité.', 'Nous consulter', 'Certificat', 'Réseaux sociaux et communauté|Création de contenu|Publicité en ligne|Analyse des résultats', '', 'Demandé', 0, 31, 'business', "fr"),
            ('Langue Française Professionnelle', 'Français appliqué au monde du travail : expression orale et écrite, vocabulaire métier et correspondance professionnelle.', 'Nous consulter', 'Attestation', 'Expression orale|Expression écrite|Vocabulaire métier|Correspondance professionnelle', '', '', 0, 40, 'languages', "fr"),
            ("Anglais Professionnel pour l'Hôtellerie et le Tourisme", "Anglais opérationnel pour l'accueil, la réception, le service et la relation avec une clientèle internationale.", 'Nous consulter', 'Attestation', "Accueil et réception en anglais|Vocabulaire de l'hôtellerie|Service et restauration|Situations client courantes", '', '', 0, 41, 'languages', "fr"),
            ('Techniques de Communication Professionnelle', 'Communiquer efficacement en milieu professionnel : écoute, expression, travail en équipe et gestion des situations difficiles.', 'Nous consulter', 'Attestation', 'Écoute et reformulation|Expression en public|Travail en équipe|Gestion des situations difficiles', '', '', 0, 42, 'languages', "fr"),
            ("Technicien en Laboratoire d'Analyses Médicales", "Diplôme reconnu par l'État — تقني في مختبر التحاليل الطبية. Prélèvements, techniques d'analyse, hygiène et sécurité au laboratoire.", '1 An', "Diplôme d'État", "Prélèvements et manipulation|Techniques d'analyse|Hygiène et sécurité au laboratoire|Gestion des résultats", '', "Diplôme d'État", 1, 50, 'health', "fr"),
            ('Aide aux Personnes Âgées', "Diplôme reconnu par l'État — رعاية المسنين. Accompagnement quotidien, soins de confort et relation d'aide auprès des personnes âgées.", '1 An', "Diplôme d'État", "Accompagnement au quotidien|Soins de confort et d'hygiène|Relation d'aide et écoute|Prévention et sécurité", '', "Diplôme d'État", 0, 51, 'health', "fr"),
            ('Aide-Soignant / Assistant Thérapeute', "Diplôme reconnu par l'État — مساعد معالج. Assistance aux soins, hygiène, confort du patient et travail en équipe soignante.", '1 An', "Diplôme d'État", 'Assistance aux soins|Hygiène et confort du patient|Surveillance et transmission|Travail en équipe soignante', '', "Diplôme d'État", 0, 52, 'health', "fr"),
            ("Technicien en Animation de Crèche et Jardin d'Enfants", "Diplôme reconnu par l'État — تقني في تنشيط الحضانة ورياض الأطفال. Encadrement, éveil et sécurité des jeunes enfants.", '2 Ans', "Diplôme d'État", "Développement de l'enfant|Activités d'éveil et animation|Hygiène et sécurité|Relation avec les familles", '', "Diplôme d'État", 1, 53, 'health', "fr"),
            ('Premiers Secours (Secourisme)', 'Gestes qui sauvent, conduite à tenir face à un accident et alerte des secours en milieu professionnel.', 'Nous consulter', 'Attestation', "Protection et alerte|Gestes qui sauvent|Situations d'urgence courantes|Trousse de secours", '', '', 0, 54, 'health', "fr"),
            ("Cuisine — Diplôme d'État", "Diplôme reconnu par l'État — طبخ. Parcours complet d'une année : techniques culinaires, production et organisation en cuisine professionnelle.", '1 An', "Diplôme d'État", 'Techniques culinaires fondamentales|Production et service|Hygiène et sécurité alimentaire|Organisation de la cuisine', '', "Diplôme d'État", 1, 16, 'culinary', "fr"),
            ("Pâtisserie — Diplôme d'État", "Diplôme reconnu par l'État — الحلويات. Parcours complet d'une année : pâtes, crèmes, entremets et pâtisserie marocaine et internationale.", '1 An', "Diplôme d'État", 'Pâtes, crèmes et cuissons|Entremets et desserts|Pâtisserie marocaine|Organisation du laboratoire', '', "Diplôme d'État", 1, 17, 'culinary', "fr"),
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
        # Detail-page fields. All optional — the page falls back to the summary
        # fields when a formation has not been filled in yet.
        "ALTER TABLE formations ADD COLUMN long_description TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN program_content TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN prerequisites TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN career_outcomes TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN schedule TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN price TEXT DEFAULT ''",
        "ALTER TABLE formations ADD COLUMN next_start TEXT DEFAULT ''",
        # Existing admins keep full access; new school staff are created as 'school'.
        "ALTER TABLE admin_user ADD COLUMN role TEXT NOT NULL DEFAULT 'super'",
        "ALTER TABLE admin_user ADD COLUMN full_name TEXT DEFAULT ''",
    ]
    if USE_PG:
        # Postgres aborts the whole transaction on a failed statement, so each
        # ALTER needs its own connection-level commit and IF NOT EXISTS.
        conn = PgConnectionWrapper(DATABASE_URL)
        for sql in migrations:
            try:
                conn.execute(sql.replace("ADD COLUMN", "ADD COLUMN IF NOT EXISTS", 1))
                conn.commit()
            except Exception:
                conn.rollback()
        conn.close()
        return

    db = sqlite3.connect(DB_PATH)
    for sql in migrations:
        try:
            db.execute(sql)
        except sqlite3.OperationalError:
            pass
    db.commit()
    db.close()


# --------------- Auth ---------------

class AdminUser(UserMixin):
    """role is 'super' (everything) or 'school' (École section only)."""

    def __init__(self, id, username, role="super", full_name=""):
        self.id = id
        self.username = username
        self.role = role or "super"
        self.full_name = full_name or ""

    @property
    def is_super(self):
        return self.role == "super"


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, full_name FROM admin_user WHERE id = ?", (user_id,)
    ).fetchone()
    if row:
        return AdminUser(row["id"], row["username"], row["role"], row["full_name"])
    return None


def super_required(view):
    """Guards everything outside the École section from school staff."""

    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_super:
            flash("Cette section est réservée au directeur.", "error")
            return redirect(url_for("admin_dashboard"))
        return view(*args, **kwargs)

    return wrapped


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


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")


def valid_email(value):
    """Loose sanity check. A lead the school cannot reply to is worse than none."""
    return bool(EMAIL_RE.match((value or "").strip()))


def form_int(name, default=0, minimum=None, maximum=None):
    """Read an integer from the form without crashing on junk.

    `int(request.form.get("x", 0))` only falls back when the key is absent — a
    cleared number input posts "x=" and raised ValueError, returning a bare 500
    and losing everything the user had typed.
    """
    raw = (request.form.get(name) or "").strip()
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        return default
    # "1e999" parses to inf, and int(inf) raises OverflowError.
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return default
    value = int(parsed)
    if minimum is not None:
        value = max(value, minimum)
    if maximum is not None:
        value = min(value, maximum)
    return value


def get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM site_settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


# --------------- Public routes ---------------

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    response = send_from_directory(UPLOAD_DIR, filename)
    # Uploads are user-supplied. An SVG can carry <script>, so serve them under
    # a CSP that forbids scripting and stop the browser sniffing content types.
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# BASE_DIR is the project root — it holds app.py and database.db. Only the two
# public stylesheets may be served from it, never the whole directory.
PUBLIC_ASSETS = {"style.css", "app.css"}


@app.route("/static-site/<path:filename>")
def static_site(filename):
    if filename not in PUBLIC_ASSETS:
        abort(404)
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
    # Online catalogue from the e-learning module, shown on the landing page.
    online_courses = db.execute(
        "SELECT * FROM courses WHERE active = 1 AND lang = ? ORDER BY created_at DESC LIMIT 6",
        (lang,),
    ).fetchall()
    if not online_courses and lang != "fr":
        online_courses = db.execute(
            "SELECT * FROM courses WHERE active = 1 AND lang = 'fr' ORDER BY created_at DESC LIMIT 6"
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
        online_courses=online_courses,
        hero_title=hero_title,
        hero_subtitle=hero_subtitle,
        t=t,
        lang=lang,
        supported_langs=SUPPORTED_LANGS,
    )


@app.route("/formation/<int:formation_id>")
def formation_detail_default(formation_id):
    return render_formation(formation_id, "fr")


@app.route("/<lang>/formation/<int:formation_id>")
def formation_detail_lang(lang, formation_id):
    if lang not in SUPPORTED_LANGS:
        abort(404)
    return render_formation(formation_id, lang)


def render_formation(formation_id, lang):
    db = get_db()
    formation = db.execute(
        "SELECT * FROM formations WHERE id = ? AND active = 1", (formation_id,)
    ).fetchone()
    if not formation:
        abort(404)

    settings = get_settings()
    t = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANG])

    # Other programmes from the same pôle, to keep browsing going.
    related = db.execute(
        "SELECT * FROM formations WHERE active = 1 AND category = ? AND id != ? AND lang = ?"
        " ORDER BY sort_order LIMIT 3",
        (formation["category"], formation_id, formation["lang"]),
    ).fetchall()

    sessions = db.execute(
        "SELECT * FROM training_sessions WHERE active = 1 AND lang = ? ORDER BY start_date LIMIT 3",
        (lang,),
    ).fetchall()

    faqs = db.execute(
        "SELECT * FROM faqs WHERE active = 1 AND lang = ? ORDER BY sort_order LIMIT 5",
        (lang,),
    ).fetchall()

    all_formations = db.execute(
        "SELECT id, title FROM formations WHERE active = 1 AND lang = ? ORDER BY sort_order",
        (formation["lang"],),
    ).fetchall()

    return render_template(
        "public/formation.html",
        settings=settings,
        formation=formation,
        related=related,
        sessions=sessions,
        faqs=faqs,
        formations=all_formations,
        t=t,
        lang=lang,
        supported_langs=SUPPORTED_LANGS,
    )


@app.route("/api/inscription", methods=["POST"])
def submit_inscription():
    data = request.form
    if data.get("website", "").strip():
        # Honeypot field, invisible to humans. Answer 200 so the bot believes
        # it succeeded and does not retry, but store nothing.
        return jsonify({"success": True, "message": "OK"})
    inscription_type = data.get("inscription_type", "individual")

    if inscription_type == "corporate":
        required = ["company_name", "prenom", "email", "telephone", "formation"]
    else:
        required = ["prenom", "nom", "email", "telephone", "formation"]

    for field in required:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Le champ {field} est requis."}), 400
    if not valid_email(data.get("email", "")):
        return jsonify({"error": "Veuillez saisir une adresse email valide."}), 400

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
            form_int("num_participants", 1, minimum=1, maximum=100000),
            data.get("desired_dates", "").strip(),
            data.get("budget", "").strip(),
        ),
    )
    db.commit()
    return jsonify({"success": True, "message": "Votre demande a été envoyée avec succès !"})


@app.route("/api/proposal", methods=["POST"])
def submit_proposal():
    data = request.form
    if data.get("website", "").strip():
        return jsonify({"success": True, "message": "OK"})
    required = ["company_name", "contact_name", "email", "phone", "training_type"]
    for field in required:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Le champ {field} est requis."}), 400
    if not valid_email(data.get("email", "")):
        return jsonify({"error": "Veuillez saisir une adresse email valide."}), 400
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
            form_int("num_participants", 1, minimum=1, maximum=100000),
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
            "SELECT id, username, password_hash, role, full_name FROM admin_user WHERE username = ?",
            (username,),
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            login_user(AdminUser(row["id"], row["username"], row["role"], row["full_name"]))
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

    # School staff get a school dashboard; they never see site-content counters.
    if not current_user.is_super:
        today = date.today()
        pupils = db.execute("SELECT COUNT(*) FROM class_students WHERE active=1").fetchone()[0]
        paid = db.execute(
            "SELECT COUNT(*) FROM payments WHERE year=? AND month=? AND status='paid'",
            (today.year, today.month),
        ).fetchone()[0]
        collected = db.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE year=? AND month=? AND status='paid'",
            (today.year, today.month),
        ).fetchone()[0]
        school_stats = {
            "teachers": db.execute("SELECT COUNT(*) FROM teachers WHERE active=1").fetchone()[0],
            "classes": db.execute("SELECT COUNT(*) FROM school_classes WHERE active=1").fetchone()[0],
            "pupils": pupils,
            "paid": paid,
            "unpaid": max(pupils - paid, 0),
            "collected": collected or 0,
            "inscriptions_new": db.execute(
                "SELECT COUNT(*) FROM inscriptions WHERE status='nouveau'"
            ).fetchone()[0],
        }
        classes = db.execute(
            """SELECT c.*, t.first_name AS teacher_first, t.last_name AS teacher_last,
                      (SELECT COUNT(*) FROM class_students s WHERE s.class_id = c.id AND s.active = 1) AS student_count
                 FROM school_classes c
                 LEFT JOIN teachers t ON c.teacher_id = t.id
                WHERE c.active = 1
                ORDER BY c.name"""
        ).fetchall()
        return render_template(
            "admin/school_dashboard.html",
            stats=school_stats,
            classes=classes,
            month_label=MONTHS_FR[today.month - 1],
            year=today.year,
            month=today.month,
        )

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
@super_required
def admin_formations():
    db = get_db()
    formations = db.execute("SELECT * FROM formations ORDER BY sort_order").fetchall()
    return render_template("admin/formations.html", formations=formations)


@app.route("/admin/formations/add", methods=["GET", "POST"])
@super_required
def admin_formation_add():
    if request.method == "POST":
        image_url = ""
        if "image" in request.files:
            image_url = save_upload(request.files["image"], "formations") or ""
        db = get_db()
        db.execute(
            "INSERT INTO formations (title, description, duration, diploma_type, features, image, badge, featured, sort_order, category, lang, long_description, program_content, prerequisites, career_outcomes, schedule, price, next_start) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                request.form["duration"].strip(),
                request.form["diploma_type"],
                request.form.get("features", "").strip(),
                image_url,
                request.form.get("badge", "").strip(),
                1 if request.form.get("featured") else 0,
                form_int("sort_order", 0),
                request.form.get("category", "culinary"),
                request.form.get("lang", "fr"),
                request.form.get("long_description", "").strip(),
                request.form.get("program_content", "").strip(),
                request.form.get("prerequisites", "").strip(),
                request.form.get("career_outcomes", "").strip(),
                request.form.get("schedule", "").strip(),
                request.form.get("price", "").strip(),
                request.form.get("next_start", "").strip(),
            ),
        )
        db.commit()
        flash("Formation ajoutée avec succès.", "success")
        return redirect(url_for("admin_formations"))
    return render_template("admin/formation_form.html", formation=None)


@app.route("/admin/formations/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
            "UPDATE formations SET title=?, description=?, duration=?, diploma_type=?, features=?, image=?, badge=?, featured=?, sort_order=?, category=?, lang=?, long_description=?, program_content=?, prerequisites=?, career_outcomes=?, schedule=?, price=?, next_start=? WHERE id=?",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                request.form["duration"].strip(),
                request.form["diploma_type"],
                request.form.get("features", "").strip(),
                image_url,
                request.form.get("badge", "").strip(),
                1 if request.form.get("featured") else 0,
                form_int("sort_order", 0),
                request.form.get("category", "culinary"),
                request.form.get("lang", "fr"),
                request.form.get("long_description", "").strip(),
                request.form.get("program_content", "").strip(),
                request.form.get("prerequisites", "").strip(),
                request.form.get("career_outcomes", "").strip(),
                request.form.get("schedule", "").strip(),
                request.form.get("price", "").strip(),
                request.form.get("next_start", "").strip(),
                id,
            ),
        )
        db.commit()
        flash("Formation mise à jour.", "success")
        return redirect(url_for("admin_formations"))
    return render_template("admin/formation_form.html", formation=formation)


@app.route("/admin/formations/<int:id>/delete", methods=["POST"])
@super_required
def admin_formation_delete(id):
    db = get_db()
    db.execute("DELETE FROM formations WHERE id = ?", (id,))
    db.commit()
    flash("Formation supprimée.", "success")
    return redirect(url_for("admin_formations"))


@app.route("/admin/formations/<int:id>/toggle", methods=["POST"])
@super_required
def admin_formation_toggle(id):
    db = get_db()
    db.execute("UPDATE formations SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (id,))
    db.commit()
    return redirect(url_for("admin_formations"))


# --------------- Admin: Certificates CRUD ---------------

@app.route("/admin/certificates")
@super_required
def admin_certificates():
    db = get_db()
    certificates = db.execute("SELECT * FROM certificates ORDER BY sort_order").fetchall()
    return render_template("admin/certificates.html", certificates=certificates)


@app.route("/admin/certificates/add", methods=["GET", "POST"])
@super_required
def admin_certificate_add():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO certificates (title, description, sort_order, lang) VALUES (?,?,?,?)",
            (
                request.form["title"].strip(),
                request.form["description"].strip(),
                form_int("sort_order", 0),
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Certificat ajouté avec succès.", "success")
        return redirect(url_for("admin_certificates"))
    formations = db.execute("SELECT id, title FROM formations ORDER BY title").fetchall()
    return render_template("admin/certificate_form.html", certificate=None, formations=formations)


@app.route("/admin/certificates/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
                form_int("sort_order", 0),
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
@super_required
def admin_certificate_delete(id):
    db = get_db()
    db.execute("DELETE FROM certificates WHERE id = ?", (id,))
    db.commit()
    flash("Certificat supprimé.", "success")
    return redirect(url_for("admin_certificates"))


# --------------- Admin: Testimonials CRUD ---------------

@app.route("/admin/testimonials")
@super_required
def admin_testimonials():
    db = get_db()
    testimonials = db.execute("SELECT * FROM testimonials ORDER BY created_at DESC").fetchall()
    return render_template("admin/testimonials.html", testimonials=testimonials)


@app.route("/admin/testimonials/add", methods=["GET", "POST"])
@super_required
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
                form_int("rating", 5, minimum=1, maximum=5),
                name[0].upper() if name else "?",
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Témoignage ajouté.", "success")
        return redirect(url_for("admin_testimonials"))
    return render_template("admin/testimonial_form.html", testimonial=None)


@app.route("/admin/testimonials/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
                form_int("rating", 5, minimum=1, maximum=5),
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
@super_required
def admin_testimonial_delete(id):
    db = get_db()
    db.execute("DELETE FROM testimonials WHERE id = ?", (id,))
    db.commit()
    flash("Témoignage supprimé.", "success")
    return redirect(url_for("admin_testimonials"))


# --------------- Admin: Gallery CRUD ---------------

@app.route("/admin/gallery")
@super_required
def admin_gallery():
    db = get_db()
    images = db.execute("SELECT * FROM gallery ORDER BY sort_order").fetchall()
    return render_template("admin/gallery.html", images=images)


@app.route("/admin/gallery/add", methods=["GET", "POST"])
@super_required
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
                form_int("sort_order", 0),
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Image ajoutée à la galerie.", "success")
        return redirect(url_for("admin_gallery"))
    return render_template("admin/gallery_form.html", image=None)


@app.route("/admin/gallery/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
                form_int("sort_order", 0),
                request.form.get("lang", "fr"),
                id,
            ),
        )
        db.commit()
        flash("Image mise à jour.", "success")
        return redirect(url_for("admin_gallery"))
    return render_template("admin/gallery_form.html", image=image)


@app.route("/admin/gallery/<int:id>/delete", methods=["POST"])
@super_required
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
@super_required
def admin_sections():
    db = get_db()
    sections = db.execute("SELECT * FROM custom_sections ORDER BY sort_order").fetchall()
    return render_template("admin/sections.html", sections=sections)


@app.route("/admin/sections/add", methods=["GET", "POST"])
@super_required
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
                form_int("sort_order", 0),
                1 if request.form.get("active") is None or request.form.get("active") else 1,
                request.form.get("lang", "fr"),
            ),
        )
        db.commit()
        flash("Section ajoutée avec succès.", "success")
        return redirect(url_for("admin_sections"))
    return render_template("admin/section_form.html", section=None)


@app.route("/admin/sections/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
                form_int("sort_order", 0),
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
@super_required
def admin_section_delete(id):
    db = get_db()
    db.execute("DELETE FROM custom_sections WHERE id = ?", (id,))
    db.commit()
    flash("Section supprimée.", "success")
    return redirect(url_for("admin_sections"))


@app.route("/admin/sections/<int:id>/toggle", methods=["POST"])
@super_required
def admin_section_toggle(id):
    db = get_db()
    db.execute("UPDATE custom_sections SET active = CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=?", (id,))
    db.commit()
    return redirect(url_for("admin_sections"))


# --------------- Admin: Settings ---------------

@app.route("/admin/settings", methods=["GET", "POST"])
@super_required
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
        visibility_keys = ["show_hero", "show_about", "show_pillars", "show_services",
                          "show_formations", "show_online", "show_process", "show_certificates",
                          "show_gallery", "show_testimonials", "show_contact"]
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
@super_required
def admin_proposals():
    db = get_db()
    proposals = db.execute("SELECT * FROM proposals ORDER BY created_at DESC").fetchall()
    return render_template("admin/proposals.html", proposals=proposals)


@app.route("/admin/proposals/<int:id>/status", methods=["POST"])
@super_required
def admin_proposal_status(id):
    db = get_db()
    db.execute("UPDATE proposals SET status=?, admin_notes=? WHERE id=?",
               (request.form.get("status", "nouveau"), request.form.get("admin_notes", ""), id))
    db.commit()
    flash("Proposition mise à jour.", "success")
    return redirect(url_for("admin_proposals"))


@app.route("/admin/proposals/<int:id>/delete", methods=["POST"])
@super_required
def admin_proposal_delete(id):
    db = get_db()
    db.execute("DELETE FROM proposals WHERE id = ?", (id,))
    db.commit()
    flash("Proposition supprimée.", "success")
    return redirect(url_for("admin_proposals"))


# --------------- Admin: FAQs CRUD ---------------

@app.route("/admin/faqs")
@super_required
def admin_faqs():
    db = get_db()
    faqs = db.execute("SELECT * FROM faqs ORDER BY sort_order").fetchall()
    return render_template("admin/faqs.html", faqs=faqs)


@app.route("/admin/faqs/add", methods=["GET", "POST"])
@super_required
def admin_faq_add():
    if request.method == "POST":
        db = get_db()
        db.execute("INSERT INTO faqs (question, answer, sort_order, lang) VALUES (?,?,?,?)",
                   (request.form["question"].strip(), request.form["answer"].strip(),
                    form_int("sort_order", 0), request.form.get("lang", "fr")))
        db.commit()
        flash("FAQ ajoutée.", "success")
        return redirect(url_for("admin_faqs"))
    return render_template("admin/faq_form.html", faq=None)


@app.route("/admin/faqs/<int:id>/edit", methods=["GET", "POST"])
@super_required
def admin_faq_edit(id):
    db = get_db()
    faq = db.execute("SELECT * FROM faqs WHERE id = ?", (id,)).fetchone()
    if not faq:
        flash("FAQ introuvable.", "error")
        return redirect(url_for("admin_faqs"))
    if request.method == "POST":
        db.execute("UPDATE faqs SET question=?, answer=?, sort_order=?, lang=? WHERE id=?",
                   (request.form["question"].strip(), request.form["answer"].strip(),
                    form_int("sort_order", 0), request.form.get("lang", "fr"), id))
        db.commit()
        flash("FAQ mise à jour.", "success")
        return redirect(url_for("admin_faqs"))
    return render_template("admin/faq_form.html", faq=faq)


@app.route("/admin/faqs/<int:id>/delete", methods=["POST"])
@super_required
def admin_faq_delete(id):
    db = get_db()
    db.execute("DELETE FROM faqs WHERE id = ?", (id,))
    db.commit()
    flash("FAQ supprimée.", "success")
    return redirect(url_for("admin_faqs"))


# --------------- Admin: Training Sessions CRUD ---------------

@app.route("/admin/sessions")
@super_required
def admin_sessions():
    db = get_db()
    sessions = db.execute("SELECT * FROM training_sessions ORDER BY start_date").fetchall()
    return render_template("admin/sessions.html", sessions=sessions)


@app.route("/admin/sessions/add", methods=["GET", "POST"])
@super_required
def admin_session_add():
    if request.method == "POST":
        db = get_db()
        db.execute(
            "INSERT INTO training_sessions (title, start_date, end_date, spots_total, spots_taken, location, active, lang) VALUES (?,?,?,?,?,?,?,?)",
            (request.form["title"].strip(), request.form["start_date"], request.form.get("end_date", ""),
             form_int("spots_total", 20, minimum=0), form_int("spots_taken", 0, minimum=0),
             request.form.get("location", "").strip(), 1, request.form.get("lang", "fr")))
        db.commit()
        flash("Session ajoutée.", "success")
        return redirect(url_for("admin_sessions"))
    return render_template("admin/session_form.html", session=None)


@app.route("/admin/sessions/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
             form_int("spots_total", 20, minimum=0), form_int("spots_taken", 0, minimum=0),
             request.form.get("location", "").strip(), 1 if request.form.get("active") else 0,
             request.form.get("lang", "fr"), id))
        db.commit()
        flash("Session mise à jour.", "success")
        return redirect(url_for("admin_sessions"))
    return render_template("admin/session_form.html", session=sess)


@app.route("/admin/sessions/<int:id>/delete", methods=["POST"])
@super_required
def admin_session_delete(id):
    db = get_db()
    db.execute("DELETE FROM training_sessions WHERE id = ?", (id,))
    db.commit()
    flash("Session supprimée.", "success")
    return redirect(url_for("admin_sessions"))


# --------------- Admin: Partners CRUD ---------------

@app.route("/admin/partners")
@super_required
def admin_partners():
    db = get_db()
    partners = db.execute("SELECT * FROM partners ORDER BY sort_order").fetchall()
    return render_template("admin/partners.html", partners=partners)


@app.route("/admin/partners/add", methods=["GET", "POST"])
@super_required
def admin_partner_add():
    if request.method == "POST":
        logo_url = save_upload(request.files.get("logo"), "partners")
        if not logo_url:
            flash("Veuillez sélectionner un logo.", "error")
            return render_template("admin/partner_form.html", partner=None)
        db = get_db()
        db.execute("INSERT INTO partners (name, logo, website_url, sort_order) VALUES (?,?,?,?)",
                   (request.form["name"].strip(), logo_url,
                    request.form.get("website_url", "").strip(), form_int("sort_order", 0)))
        db.commit()
        flash("Partenaire ajouté.", "success")
        return redirect(url_for("admin_partners"))
    return render_template("admin/partner_form.html", partner=None)


@app.route("/admin/partners/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
                    request.form.get("website_url", "").strip(), form_int("sort_order", 0), id))
        db.commit()
        flash("Partenaire mis à jour.", "success")
        return redirect(url_for("admin_partners"))
    return render_template("admin/partner_form.html", partner=partner)


@app.route("/admin/partners/<int:id>/delete", methods=["POST"])
@super_required
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


def module_access(module_id):
    """Return (module, error_redirect) for a module the student may open.

    Both write endpoints below reached the database with a raw URL id, so a
    bogus id was a 500 and a module from a course the student never enrolled in
    was writable. One helper keeps all three routes consistent.
    """
    db = get_db()
    module = db.execute("SELECT * FROM course_modules WHERE id = ?", (module_id,)).fetchone()
    if not module:
        flash("Ce module n'existe pas.", "error")
        return None, redirect(url_for("student_courses"))
    enrolled = db.execute(
        "SELECT 1 FROM student_enrollments WHERE student_id=? AND course_id=?",
        (g.student["id"], module["course_id"]),
    ).fetchone()
    if not enrolled:
        flash("Inscrivez-vous à ce cours pour accéder à son contenu.", "warning")
        return None, redirect(url_for("student_course", course_id=module["course_id"]))
    return module, None


def sync_course_completion(student_id, course_id):
    """Mark the enrolment complete once every module is done.

    Called from both completion paths. Previously only the "mark complete"
    button ran this, so a student who finished their last module by passing its
    quiz never had the course closed out and never received a certificate.
    Returns True when this call is what completed the course.
    """
    db = get_db()
    total = db.execute(
        "SELECT COUNT(*) FROM course_modules WHERE course_id=?", (course_id,)
    ).fetchone()[0]
    if not total:
        return False
    done = db.execute(
        """SELECT COUNT(*) FROM student_progress sp
             JOIN course_modules cm ON sp.module_id = cm.id
            WHERE sp.student_id=? AND cm.course_id=? AND sp.completed=1""",
        (student_id, course_id),
    ).fetchone()[0]
    if done < total:
        return False
    already = db.execute(
        "SELECT completed FROM student_enrollments WHERE student_id=? AND course_id=?",
        (student_id, course_id),
    ).fetchone()
    if already and already["completed"]:
        return False
    db.execute(
        "UPDATE student_enrollments SET completed=1, completed_at=CURRENT_TIMESTAMP"
        " WHERE student_id=? AND course_id=?",
        (student_id, course_id),
    )
    db.commit()
    return True


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
        if not valid_email(email):
            flash("Veuillez saisir une adresse email valide.", "error")
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
    return render_template("student/courses.html", courses=courses, enrolled_ids=enrolled_ids, student=g.student)


@app.route("/student/enroll/<int:course_id>", methods=["POST"])
@student_required
def student_enroll(course_id):
    db = get_db()
    course = db.execute("SELECT id FROM courses WHERE id=? AND active=1", (course_id,)).fetchone()
    if not course:
        flash("Ce cours n'est pas disponible.", "error")
        return redirect(url_for("student_courses"))
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
    return render_template("student/course.html", course=course, modules=modules, progress=progress, enrollment=enrollment, student=g.student)


@app.route("/student/module/<int:module_id>")
@student_required
def student_module(module_id):
    db = get_db()
    module, denied = module_access(module_id)
    if denied:
        return denied
    course = db.execute("SELECT * FROM courses WHERE id = ?", (module["course_id"],)).fetchone()
    # Mark as watched
    existing = db.execute("SELECT * FROM student_progress WHERE student_id=? AND module_id=?", (g.student["id"], module_id)).fetchone()
    if not existing:
        db.execute("INSERT INTO student_progress (student_id, module_id, watched, completed) VALUES (?,?,1,0)", (g.student["id"], module_id))
        db.commit()
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id = ? ORDER BY sort_order", (module_id,)).fetchall()
    return render_template("student/module.html", module=module, course=course, quizzes=quizzes, student=g.student)


@app.route("/student/module/<int:module_id>/complete", methods=["POST"])
@student_required
def student_complete_module(module_id):
    module, denied = module_access(module_id)
    if denied:
        return denied
    db = get_db()
    db.execute("""INSERT INTO student_progress (student_id, module_id, watched, completed, completed_at)
        VALUES (?,?,1,1,CURRENT_TIMESTAMP)
        ON CONFLICT(student_id, module_id) DO UPDATE SET completed=1, watched=1, completed_at=CURRENT_TIMESTAMP""",
        (g.student["id"], module_id))
    db.commit()
    finished = sync_course_completion(g.student["id"], module["course_id"])
    check_and_award_rewards(g.student["id"])
    if finished:
        flash("Cours terminé ! Votre certificat est disponible.", "success")
        return redirect(url_for("student_certificates"))
    flash("Module terminé !", "success")
    return redirect(url_for("student_module", module_id=module_id))


@app.route("/student/quiz/<int:module_id>", methods=["POST"])
@student_required
def student_submit_quiz(module_id):
    module, denied = module_access(module_id)
    if denied:
        return denied
    db = get_db()
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id=? ORDER BY sort_order", (module_id,)).fetchall()
    if not quizzes:
        # Without this, submitting a module that has no questions recorded a
        # bogus 0/0 failed attempt against the student.
        flash("Ce module ne comporte pas de quiz.", "error")
        return redirect(url_for("student_module", module_id=module_id))
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
    finished = sync_course_completion(g.student["id"], module["course_id"]) if passed else False
    check_and_award_rewards(g.student["id"])
    flash(f"Quiz terminé : {score}/{total} {'- Réussi !' if passed else '- Essayez encore.'}", "success" if passed else "error")
    if finished:
        flash("Cours terminé ! Votre certificat est disponible.", "success")
        return redirect(url_for("student_certificates"))
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
@super_required
def admin_courses():
    db = get_db()
    courses = db.execute("SELECT * FROM courses ORDER BY created_at DESC").fetchall()
    return render_template("admin/courses.html", courses=courses)


@app.route("/admin/courses/add", methods=["GET", "POST"])
@super_required
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
@super_required
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
@super_required
def admin_course_delete(id):
    db = get_db()
    db.execute("DELETE FROM courses WHERE id=?", (id,))
    db.commit()
    flash("Cours supprimé.", "success")
    return redirect(url_for("admin_courses"))


@app.route("/admin/courses/<int:course_id>/modules")
@super_required
def admin_modules(course_id):
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    modules = db.execute("SELECT * FROM course_modules WHERE course_id=? ORDER BY sort_order", (course_id,)).fetchall()
    return render_template("admin/modules.html", course=course, modules=modules)


@app.route("/admin/courses/<int:course_id>/modules/add", methods=["GET", "POST"])
@super_required
def admin_module_add(course_id):
    if request.method == "POST":
        db = get_db()
        db.execute(
            "INSERT INTO course_modules (course_id, title, description, video_url, materials_url, duration_minutes, sort_order) VALUES (?,?,?,?,?,?,?)",
            (course_id, request.form["title"].strip(), request.form.get("description", "").strip(),
             request.form.get("video_url", "").strip(), request.form.get("materials_url", "").strip(),
             form_int("duration_minutes", 0, minimum=0), form_int("sort_order", 0)))
        db.commit()
        flash("Module ajouté.", "success")
        return redirect(url_for("admin_modules", course_id=course_id))
    return render_template("admin/module_form.html", module=None, course_id=course_id)


@app.route("/admin/modules/<int:id>/edit", methods=["GET", "POST"])
@super_required
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
             form_int("duration_minutes", 0, minimum=0), form_int("sort_order", 0), id))
        db.commit()
        flash("Module mis à jour.", "success")
        return redirect(url_for("admin_modules", course_id=module["course_id"]))
    return render_template("admin/module_form.html", module=module, course_id=module["course_id"])


@app.route("/admin/modules/<int:id>/delete", methods=["POST"])
@super_required
def admin_module_delete(id):
    db = get_db()
    module = db.execute("SELECT course_id FROM course_modules WHERE id=?", (id,)).fetchone()
    course_id = module["course_id"] if module else 0
    db.execute("DELETE FROM course_modules WHERE id=?", (id,))
    db.commit()
    flash("Module supprimé.", "success")
    return redirect(url_for("admin_modules", course_id=course_id))


@app.route("/admin/modules/<int:module_id>/quizzes", methods=["GET", "POST"])
@super_required
def admin_quizzes(module_id):
    db = get_db()
    module = db.execute("SELECT * FROM course_modules WHERE id=?", (module_id,)).fetchone()
    if request.method == "POST":
        db.execute(
            "INSERT INTO quizzes (module_id, question, option_a, option_b, option_c, option_d, correct_answer, sort_order) VALUES (?,?,?,?,?,?,?,?)",
            (module_id, request.form["question"].strip(), request.form["option_a"].strip(),
             request.form["option_b"].strip(), request.form.get("option_c", "").strip(),
             request.form.get("option_d", "").strip(), request.form["correct_answer"],
             form_int("sort_order", 0)))
        db.commit()
        flash("Question ajoutée.", "success")
        return redirect(url_for("admin_quizzes", module_id=module_id))
    quizzes = db.execute("SELECT * FROM quizzes WHERE module_id=? ORDER BY sort_order", (module_id,)).fetchall()
    return render_template("admin/quizzes.html", module=module, quizzes=quizzes)


@app.route("/admin/quizzes/<int:id>/delete", methods=["POST"])
@super_required
def admin_quiz_delete(id):
    db = get_db()
    quiz = db.execute("SELECT module_id FROM quizzes WHERE id=?", (id,)).fetchone()
    module_id = quiz["module_id"] if quiz else 0
    db.execute("DELETE FROM quizzes WHERE id=?", (id,))
    db.commit()
    flash("Question supprimée.", "success")
    return redirect(url_for("admin_quizzes", module_id=module_id))


@app.route("/admin/students")
@super_required
def admin_students():
    db = get_db()
    students = db.execute("SELECT * FROM students ORDER BY created_at DESC").fetchall()
    return render_template("admin/students.html", students=students)


@app.route("/admin/students/<int:id>/progress")
@super_required
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
@super_required
def admin_rewards():
    db = get_db()
    rewards = db.execute("SELECT * FROM rewards ORDER BY id").fetchall()
    return render_template("admin/rewards.html", rewards=rewards)


# --------------- Admin: Users & roles (super only) ---------------

@app.route("/admin/users")
@super_required
def admin_users():
    db = get_db()
    # No created_at here: databases created before this column existed cannot get
    # it via ALTER (SQLite rejects a CURRENT_TIMESTAMP default on ADD COLUMN).
    users = db.execute(
        "SELECT id, username, role, full_name FROM admin_user ORDER BY role, username"
    ).fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/add", methods=["GET", "POST"])
@super_required
def admin_user_add():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "school")
        if not username or not password:
            flash("Nom d'utilisateur et mot de passe sont requis.", "error")
            return render_template("admin/user_form.html", user=None)
        if db.execute("SELECT id FROM admin_user WHERE username=?", (username,)).fetchone():
            flash("Ce nom d'utilisateur existe déjà.", "error")
            return render_template("admin/user_form.html", user=None)
        db.execute(
            "INSERT INTO admin_user (username, password_hash, role, full_name) VALUES (?,?,?,?)",
            (
                username,
                generate_password_hash(password),
                "super" if role == "super" else "school",
                request.form.get("full_name", "").strip(),
            ),
        )
        db.commit()
        flash("Compte créé.", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", user=None)


@app.route("/admin/users/<int:id>/edit", methods=["GET", "POST"])
@super_required
def admin_user_edit(id):
    db = get_db()
    user = db.execute(
        "SELECT id, username, role, full_name FROM admin_user WHERE id=?", (id,)
    ).fetchone()
    if not user:
        abort(404)
    if request.method == "POST":
        role = request.form.get("role", "school")
        role = "super" if role == "super" else "school"
        # Never let the last super account demote itself out of existence.
        if user["role"] == "super" and role != "super":
            supers = db.execute("SELECT COUNT(*) FROM admin_user WHERE role='super'").fetchone()[0]
            if supers <= 1:
                flash("Impossible : il doit rester au moins un administrateur du site.", "error")
                return redirect(url_for("admin_users"))
        db.execute(
            "UPDATE admin_user SET full_name=?, role=? WHERE id=?",
            (request.form.get("full_name", "").strip(), role, id),
        )
        new_password = request.form.get("password", "")
        if new_password:
            db.execute(
                "UPDATE admin_user SET password_hash=? WHERE id=?",
                (generate_password_hash(new_password), id),
            )
        db.commit()
        flash("Compte mis à jour.", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", user=user)


@app.route("/admin/users/<int:id>/delete", methods=["POST"])
@super_required
def admin_user_delete(id):
    db = get_db()
    if int(current_user.id) == id:
        flash("Vous ne pouvez pas supprimer votre propre compte.", "error")
        return redirect(url_for("admin_users"))
    user = db.execute("SELECT role FROM admin_user WHERE id=?", (id,)).fetchone()
    if user and user["role"] == "super":
        supers = db.execute("SELECT COUNT(*) FROM admin_user WHERE role='super'").fetchone()[0]
        if supers <= 1:
            flash("Impossible : il doit rester au moins un administrateur du site.", "error")
            return redirect(url_for("admin_users"))
    db.execute("DELETE FROM admin_user WHERE id=?", (id,))
    db.commit()
    flash("Compte supprimé.", "success")
    return redirect(url_for("admin_users"))


# --------------- Admin: School (teachers, classes, pupils, fees) ---------------

MONTHS_FR = [
    "Janvier", "Février", "Mars", "Avril", "Mai", "Juin",
    "Juillet", "Août", "Septembre", "Octobre", "Novembre", "Décembre",
]


def _teacher_form():
    return (
        request.form["first_name"].strip(),
        request.form["last_name"].strip(),
        request.form.get("email", "").strip(),
        request.form.get("phone", "").strip(),
        request.form.get("specialty", "").strip(),
        request.form.get("bio", "").strip(),
    )


@app.route("/admin/teachers")
@login_required
def admin_teachers():
    db = get_db()
    teachers = db.execute(
        """SELECT t.*,
                  (SELECT COUNT(*) FROM school_classes c WHERE c.teacher_id = t.id AND c.active = 1) AS class_count,
                  (SELECT COUNT(*) FROM class_students s
                     JOIN school_classes c ON s.class_id = c.id
                    WHERE c.teacher_id = t.id AND s.active = 1) AS student_count
             FROM teachers t
            ORDER BY t.last_name, t.first_name"""
    ).fetchall()
    return render_template("admin/teachers.html", teachers=teachers)


@app.route("/admin/teachers/add", methods=["GET", "POST"])
@login_required
def admin_teacher_add():
    db = get_db()
    if request.method == "POST":
        photo = save_upload(request.files.get("photo"), "teachers") or ""
        db.execute(
            "INSERT INTO teachers (first_name, last_name, email, phone, specialty, bio, photo)"
            " VALUES (?,?,?,?,?,?,?)",
            _teacher_form() + (photo,),
        )
        db.commit()
        flash("Enseignant ajouté.", "success")
        return redirect(url_for("admin_teachers"))
    classes = db.execute("SELECT * FROM school_classes ORDER BY name").fetchall()
    return render_template("admin/teacher_form.html", teacher=None, classes=classes)


@app.route("/admin/teachers/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_teacher_edit(id):
    db = get_db()
    teacher = db.execute("SELECT * FROM teachers WHERE id=?", (id,)).fetchone()
    if not teacher:
        abort(404)
    if request.method == "POST":
        photo = save_upload(request.files.get("photo"), "teachers") or teacher["photo"]
        db.execute(
            "UPDATE teachers SET first_name=?, last_name=?, email=?, phone=?, specialty=?, bio=?,"
            " photo=?, active=? WHERE id=?",
            _teacher_form() + (photo, 1 if request.form.get("active") else 0, id),
        )
        db.commit()
        flash("Enseignant mis à jour.", "success")
        return redirect(url_for("admin_teachers"))
    classes = db.execute(
        "SELECT * FROM school_classes WHERE teacher_id=? ORDER BY name", (id,)
    ).fetchall()
    return render_template("admin/teacher_form.html", teacher=teacher, classes=classes)


@app.route("/admin/teachers/<int:id>/delete", methods=["POST"])
@login_required
def admin_teacher_delete(id):
    db = get_db()
    # Keep the classes, just unassign them.
    db.execute("UPDATE school_classes SET teacher_id = NULL WHERE teacher_id=?", (id,))
    db.execute("DELETE FROM teachers WHERE id=?", (id,))
    db.commit()
    flash("Enseignant supprimé. Ses classes sont désormais sans responsable.", "success")
    return redirect(url_for("admin_teachers"))


@app.route("/admin/classes")
@login_required
def admin_classes():
    db = get_db()
    classes = db.execute(
        """SELECT c.*, t.first_name AS teacher_first, t.last_name AS teacher_last,
                  f.title AS formation_title,
                  (SELECT COUNT(*) FROM class_students s WHERE s.class_id = c.id AND s.active = 1) AS student_count
             FROM school_classes c
             LEFT JOIN teachers t ON c.teacher_id = t.id
             LEFT JOIN formations f ON c.formation_id = f.id
            ORDER BY c.active DESC, c.name"""
    ).fetchall()
    return render_template("admin/classes.html", classes=classes)


def _class_form():
    def _num(name):
        raw = request.form.get(name, "").strip()
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return 0.0
        # Reject inf/NaN and negatives: one bad fee poisoned the month totals.
        if value != value or value in (float("inf"), float("-inf")) or value < 0:
            return 0.0
        return round(value, 2)

    def _fk(name):
        raw = request.form.get(name, "").strip()
        return int(raw) if raw.isdigit() else None

    return (
        request.form["name"].strip(),
        _fk("formation_id"),
        _fk("teacher_id"),
        request.form.get("academic_year", "").strip(),
        _num("monthly_fee"),
        request.form.get("room", "").strip(),
        request.form.get("schedule", "").strip(),
        request.form.get("start_date", "").strip(),
        request.form.get("end_date", "").strip(),
    )


@app.route("/admin/classes/add", methods=["GET", "POST"])
@login_required
def admin_class_add():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO school_classes (name, formation_id, teacher_id, academic_year, monthly_fee,"
            " room, schedule, start_date, end_date) VALUES (?,?,?,?,?,?,?,?,?)",
            _class_form(),
        )
        db.commit()
        flash("Classe créée.", "success")
        return redirect(url_for("admin_classes"))
    return render_template(
        "admin/class_form.html",
        klass=None,
        teachers=db.execute("SELECT * FROM teachers WHERE active=1 ORDER BY last_name").fetchall(),
        formations=db.execute("SELECT id, title FROM formations ORDER BY sort_order").fetchall(),
    )


@app.route("/admin/classes/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_class_edit(id):
    db = get_db()
    klass = db.execute("SELECT * FROM school_classes WHERE id=?", (id,)).fetchone()
    if not klass:
        abort(404)
    if request.method == "POST":
        db.execute(
            "UPDATE school_classes SET name=?, formation_id=?, teacher_id=?, academic_year=?,"
            " monthly_fee=?, room=?, schedule=?, start_date=?, end_date=?, active=? WHERE id=?",
            _class_form() + (1 if request.form.get("active") else 0, id),
        )
        db.commit()
        flash("Classe mise à jour.", "success")
        return redirect(url_for("admin_class_detail", id=id))
    return render_template(
        "admin/class_form.html",
        klass=klass,
        teachers=db.execute("SELECT * FROM teachers WHERE active=1 ORDER BY last_name").fetchall(),
        formations=db.execute("SELECT id, title FROM formations ORDER BY sort_order").fetchall(),
    )


@app.route("/admin/classes/<int:id>")
@login_required
def admin_class_detail(id):
    db = get_db()
    klass = db.execute(
        """SELECT c.*, t.first_name AS teacher_first, t.last_name AS teacher_last,
                  t.email AS teacher_email, t.phone AS teacher_phone, t.specialty AS teacher_specialty,
                  f.title AS formation_title
             FROM school_classes c
             LEFT JOIN teachers t ON c.teacher_id = t.id
             LEFT JOIN formations f ON c.formation_id = f.id
            WHERE c.id = ?""",
        (id,),
    ).fetchone()
    if not klass:
        abort(404)

    today = date.today()
    year = request.args.get("year", type=int) or today.year
    month = request.args.get("month", type=int) or today.month

    students = db.execute(
        """SELECT s.*, p.status, p.amount AS paid_amount, p.paid_on, p.method
             FROM class_students s
             LEFT JOIN payments p
               ON p.student_id = s.id AND p.year = ? AND p.month = ?
            WHERE s.class_id = ? AND s.active = 1
            ORDER BY s.last_name, s.first_name""",
        (year, month, id),
    ).fetchall()

    paid = sum(1 for s in students if s["status"] == "paid")
    collected = sum((s["paid_amount"] or 0) for s in students if s["status"] == "paid")

    return render_template(
        "admin/class_detail.html",
        klass=klass,
        students=students,
        year=year,
        month=month,
        months=MONTHS_FR,
        paid_count=paid,
        unpaid_count=len(students) - paid,
        collected=collected,
    )


@app.route("/admin/classes/<int:id>/delete", methods=["POST"])
@login_required
def admin_class_delete(id):
    db = get_db()
    # Detach the pupils rather than deleting people along with the class.
    db.execute("UPDATE class_students SET class_id = NULL WHERE class_id=?", (id,))
    db.execute("DELETE FROM school_classes WHERE id=?", (id,))
    db.commit()
    flash("Classe supprimée. Les élèves ont été détachés.", "success")
    return redirect(url_for("admin_classes"))


def _pupil_form():
    def _fk(name):
        raw = request.form.get(name, "").strip()
        return int(raw) if raw.isdigit() else None

    def _num(name):
        raw = request.form.get(name, "").strip()
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return 0.0
        # Reject inf/NaN and negatives: one bad fee poisoned the month totals.
        if value != value or value in (float("inf"), float("-inf")) or value < 0:
            return 0.0
        return round(value, 2)

    return (
        request.form["first_name"].strip(),
        request.form["last_name"].strip(),
        request.form.get("email", "").strip(),
        request.form.get("phone", "").strip(),
        request.form.get("guardian_phone", "").strip(),
        _fk("class_id"),
        _num("monthly_fee"),
        request.form.get("enrolled_on", "").strip(),
        request.form.get("notes", "").strip(),
    )


@app.route("/admin/eleves")
@login_required
def admin_pupils():
    db = get_db()
    class_filter = request.args.get("class_id", type=int)
    sql = """SELECT s.*, c.name AS class_name
               FROM class_students s
               LEFT JOIN school_classes c ON s.class_id = c.id"""
    params = ()
    if class_filter:
        sql += " WHERE s.class_id = ?"
        params = (class_filter,)
    sql += " ORDER BY s.active DESC, s.last_name, s.first_name"
    return render_template(
        "admin/pupils.html",
        pupils=db.execute(sql, params).fetchall(),
        classes=db.execute("SELECT * FROM school_classes ORDER BY name").fetchall(),
        class_filter=class_filter,
    )


@app.route("/admin/eleves/add", methods=["GET", "POST"])
@login_required
def admin_pupil_add():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO class_students (first_name, last_name, email, phone, guardian_phone,"
            " class_id, monthly_fee, enrolled_on, notes) VALUES (?,?,?,?,?,?,?,?,?)",
            _pupil_form(),
        )
        db.commit()
        flash("Élève ajouté.", "success")
        return redirect(url_for("admin_pupils"))
    return render_template(
        "admin/pupil_form.html",
        pupil=None,
        classes=db.execute("SELECT * FROM school_classes WHERE active=1 ORDER BY name").fetchall(),
        preselect=request.args.get("class_id", type=int),
    )


@app.route("/admin/eleves/<int:id>/edit", methods=["GET", "POST"])
@login_required
def admin_pupil_edit(id):
    db = get_db()
    pupil = db.execute("SELECT * FROM class_students WHERE id=?", (id,)).fetchone()
    if not pupil:
        abort(404)
    if request.method == "POST":
        db.execute(
            "UPDATE class_students SET first_name=?, last_name=?, email=?, phone=?, guardian_phone=?,"
            " class_id=?, monthly_fee=?, enrolled_on=?, notes=?, active=? WHERE id=?",
            _pupil_form() + (1 if request.form.get("active") else 0, id),
        )
        db.commit()
        flash("Élève mis à jour.", "success")
        return redirect(url_for("admin_pupils"))
    payments = db.execute(
        "SELECT * FROM payments WHERE student_id=? ORDER BY year DESC, month DESC", (id,)
    ).fetchall()
    return render_template(
        "admin/pupil_form.html",
        pupil=pupil,
        classes=db.execute("SELECT * FROM school_classes ORDER BY name").fetchall(),
        payments=payments,
        months=MONTHS_FR,
        preselect=None,
    )


@app.route("/admin/eleves/<int:id>/delete", methods=["POST"])
@login_required
def admin_pupil_delete(id):
    db = get_db()
    db.execute("DELETE FROM payments WHERE student_id=?", (id,))
    db.execute("DELETE FROM class_students WHERE id=?", (id,))
    db.commit()
    flash("Élève supprimé.", "success")
    return redirect(url_for("admin_pupils"))


@app.route("/admin/paiements")
@login_required
def admin_payments():
    db = get_db()
    today = date.today()
    year = request.args.get("year", type=int) or today.year
    month = request.args.get("month", type=int) or today.month
    class_filter = request.args.get("class_id", type=int)
    status_filter = request.args.get("status", "")

    sql = """SELECT s.id, s.first_name, s.last_name, s.phone, s.monthly_fee AS student_fee,
                    c.id AS class_id, c.name AS class_name, c.monthly_fee AS class_fee,
                    t.first_name AS teacher_first, t.last_name AS teacher_last,
                    p.status, p.amount AS paid_amount, p.paid_on, p.method
               FROM class_students s
               LEFT JOIN school_classes c ON s.class_id = c.id
               LEFT JOIN teachers t ON c.teacher_id = t.id
               LEFT JOIN payments p
                 ON p.student_id = s.id AND p.year = ? AND p.month = ?
              WHERE s.active = 1"""
    params = [year, month]
    if class_filter:
        sql += " AND s.class_id = ?"
        params.append(class_filter)
    sql += " ORDER BY c.name, s.last_name, s.first_name"

    rows = db.execute(sql, tuple(params)).fetchall()

    # A pupil's own fee overrides the class fee when it is set.
    pupils = []
    for r in rows:
        due = r["student_fee"] or r["class_fee"] or 0
        paid = r["status"] == "paid"
        if status_filter == "paid" and not paid:
            continue
        if status_filter == "unpaid" and paid:
            continue
        pupils.append({"row": r, "due": due, "paid": paid})

    total_due = sum(p["due"] for p in pupils)
    total_collected = sum((p["row"]["paid_amount"] or 0) for p in pupils if p["paid"])
    paid_count = sum(1 for p in pupils if p["paid"])

    return render_template(
        "admin/payments.html",
        pupils=pupils,
        year=year,
        month=month,
        months=MONTHS_FR,
        years=list(range(today.year - 3, today.year + 2)),
        classes=db.execute("SELECT * FROM school_classes ORDER BY name").fetchall(),
        class_filter=class_filter,
        status_filter=status_filter,
        total_due=total_due,
        total_collected=total_collected,
        paid_count=paid_count,
        unpaid_count=len(pupils) - paid_count,
    )


@app.route("/admin/paiements/<int:student_id>/<int:year>/<int:month>/recu")
@login_required
def admin_payment_receipt(student_id, year, month):
    """Printable receipt for one paid month.

    School staff need something to hand the family; the payments board only
    recorded that money arrived.
    """
    if month < 1 or month > 12:
        abort(404)
    db = get_db()
    row = db.execute(
        """SELECT p.*, s.first_name, s.last_name, s.phone, s.guardian_phone,
                  c.name AS class_name, c.monthly_fee AS class_fee,
                  t.first_name AS teacher_first, t.last_name AS teacher_last
             FROM payments p
             JOIN class_students s ON p.student_id = s.id
             LEFT JOIN school_classes c ON s.class_id = c.id
             LEFT JOIN teachers t ON c.teacher_id = t.id
            WHERE p.student_id = ? AND p.year = ? AND p.month = ?""",
        (student_id, year, month),
    ).fetchone()
    if not row:
        flash("Aucun paiement enregistré pour ce mois — le reçu n'existe pas.", "error")
        return redirect(url_for("admin_payments", year=year, month=month))

    # Stable, human-readable number: BTSP-YYYY-MM-000ID
    number = f"BTSP-{year}-{month:02d}-{row['id']:04d}"
    return render_template(
        "admin/payment_receipt.html",
        p=row,
        number=number,
        month_label=MONTHS_FR[month - 1],
        year=year,
        month=month,
        settings=get_settings(),
        issued_on=date.today().isoformat(),
    )


@app.route("/admin/paiements/mark", methods=["POST"])
@login_required
def admin_payment_mark():
    db = get_db()
    student_id = request.form.get("student_id", type=int)
    year = request.form.get("year", type=int)
    month = request.form.get("month", type=int)
    action = request.form.get("action", "paid")

    if not (student_id and year and month):
        abort(400)
    # Without this the board happily stores month=99 or year=99999 rows that no
    # screen can ever show again, and they still count toward the revenue totals.
    if not (1 <= month <= 12) or not (2000 <= year <= 2100):
        abort(400)

    if action == "unpaid":
        # No row means unpaid, so clearing the row is the whole operation.
        db.execute(
            "DELETE FROM payments WHERE student_id=? AND year=? AND month=?",
            (student_id, year, month),
        )
    else:
        pupil = db.execute(
            """SELECT s.monthly_fee AS student_fee, s.class_id, c.monthly_fee AS class_fee
                 FROM class_students s
                 LEFT JOIN school_classes c ON s.class_id = c.id
                WHERE s.id = ?""",
            (student_id,),
        ).fetchone()
        if not pupil:
            abort(404)
        amount = request.form.get("amount", type=float)
        if amount is None:
            amount = pupil["student_fee"] or pupil["class_fee"] or 0
        # A typo in the amount box must not turn into negative or nonsense revenue.
        if amount != amount or amount in (float("inf"), float("-inf")):
            amount = 0.0
        amount = min(max(float(amount), 0.0), 1_000_000.0)
        db.execute(
            """INSERT INTO payments (student_id, class_id, year, month, amount, status, method, paid_on)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT (student_id, year, month) DO UPDATE SET
                 class_id = EXCLUDED.class_id, amount = EXCLUDED.amount,
                 status = EXCLUDED.status, method = EXCLUDED.method, paid_on = EXCLUDED.paid_on""",
            (
                student_id,
                pupil["class_id"],
                year,
                month,
                amount,
                "paid",
                request.form.get("method", "").strip(),
                request.form.get("paid_on", "").strip() or date.today().isoformat(),
            ),
        )
    db.commit()

    if request.form.get("redirect_to") == "class":
        return redirect(
            url_for("admin_class_detail", id=request.form.get("class_id", type=int),
                    year=year, month=month)
        )
    return redirect(
        url_for("admin_payments", year=year, month=month,
                class_id=request.form.get("class_id_filter") or None,
                status=request.form.get("status_filter") or None)
    )


# --------------- Run ---------------

# Run at import so gunicorn (`app:app`) gets the schema too — previously these
# only ran under `python app.py`, so new tables never reached production. Both
# are idempotent.
# Each programme gets a photograph of its own trade. Keyed by title rather
# than id because a fresh install numbers the catalogue differently, and only
# applied to rows with no image, so anything an admin uploads later stands.
FORMATION_IMAGES = {
    "Réceptionniste d'Hôtel":
        "https://images.unsplash.com/photo-1590381105924-c72589b9ef3f?w=900&h=600&fit=crop&q=75",
    "Femme de Chambre / Valet de Chambre":
        "https://images.unsplash.com/photo-1590490360182-c33d57733427?w=900&h=600&fit=crop&q=75",
    "Barman – Barista":
        "https://images.unsplash.com/photo-1514933651103-005eec06c04b?w=900&h=600&fit=crop&q=75",
    "Service en Restauration Gastronomique":
        "https://images.unsplash.com/photo-1552566626-52f8b828add9?w=900&h=600&fit=crop&q=75",
    "Relation Client et Accueil":
        "https://images.unsplash.com/photo-1573497019940-1c28c88b4f3e?w=900&h=600&fit=crop&q=75",
    "Cuisine Marocaine et Internationale":
        "https://images.unsplash.com/photo-1596797038530-2c107229654b?w=900&h=600&fit=crop&q=75",
    "Boulangerie":
        "https://images.unsplash.com/photo-1509440159596-0249088772ff?w=900&h=600&fit=crop&q=75",
    "Boucherie et Charcuterie":
        "https://images.unsplash.com/photo-1607623814075-e51df1bdc82f?w=900&h=600&fit=crop&q=75",
    "Traiteur et Organisation des Événements":
        "https://images.unsplash.com/photo-1555244162-803834f70033?w=900&h=600&fit=crop&q=75",
    "Décoration et Présentation des Plats":
        "https://images.unsplash.com/photo-1476224203421-9ac39bcb3327?w=900&h=600&fit=crop&q=75",
    "Sécurité Alimentaire (Food Safety)":
        "https://images.unsplash.com/photo-1563453392212-326f5e854473?w=900&h=600&fit=crop&q=75",
    "Gestion des Stocks et Approvisionnement":
        "https://images.unsplash.com/photo-1553413077-190dd305871c?w=900&h=600&fit=crop&q=75",
    "Commerce et Vente":
        "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=900&h=600&fit=crop&q=75",
    "Entrepreneuriat et Création d'Entreprise":
        "https://images.unsplash.com/photo-1519389950473-47ba0277781c?w=900&h=600&fit=crop&q=75",
    "Informatique Bureautique (Word, Excel, PowerPoint)":
        "https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=900&h=600&fit=crop&q=75",
    "Marketing Digital":
        "https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=900&h=600&fit=crop&q=75",
    "Langue Française Professionnelle":
        "https://images.unsplash.com/photo-1524995997946-a1c2e315a42f?w=900&h=600&fit=crop&q=75",
    "Anglais Professionnel pour l'Hôtellerie et le Tourisme":
        "https://images.unsplash.com/photo-1523240795612-9a054b0db644?w=900&h=600&fit=crop&q=75",
    "Techniques de Communication Professionnelle":
        "https://images.unsplash.com/photo-1475721027785-f74eccf877e2?w=900&h=600&fit=crop&q=75",
    "Technicien en Laboratoire d'Analyses Médicales":
        "https://images.unsplash.com/photo-1582719471384-894fbb16e074?w=900&h=600&fit=crop&q=75",
    "Aide aux Personnes Âgées":
        "https://images.unsplash.com/photo-1581579438747-1dc8d17bbce4?w=900&h=600&fit=crop&q=75",
    "Aide-Soignant / Assistant Thérapeute":
        "https://images.unsplash.com/photo-1631217868264-e5b90bb7e133?w=900&h=600&fit=crop&q=75",
    "Technicien en Animation de Crèche et Jardin d'Enfants":
        "https://images.unsplash.com/photo-1503676260728-1c00da094a0b?w=900&h=600&fit=crop&q=75",
    "Premiers Secours (Secourisme)":
        "https://images.unsplash.com/photo-1584515933487-779824d29309?w=900&h=600&fit=crop&q=75",
    "Cuisine — Diplôme d'État":
        "https://images.unsplash.com/photo-1577219491135-ce391730fb2c?w=900&h=600&fit=crop&q=75",
    "Pâtisserie — Diplôme d'État":
        "https://images.unsplash.com/photo-1486427944299-d1955d23e34d?w=900&h=600&fit=crop&q=75",
}


def seed_formation_images():
    """Fill in the stock photo for programmes that have none."""
    db = get_db()
    filled = 0
    for title, url in FORMATION_IMAGES.items():
        cur = db.execute(
            "UPDATE formations SET image = ? WHERE title = ? AND (image IS NULL OR image = '')",
            (url, title),
        )
        filled += cur.rowcount or 0
    # The diploma specimen ships with the code, so point at it once.
    row = db.execute(
        "SELECT value FROM site_settings WHERE key = 'cert_specimen_image'"
    ).fetchone()
    if not row or not row["value"]:
        db.execute(
            "INSERT INTO site_settings (key, value) VALUES (?, ?) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            ("cert_specimen_image", "/uploads/diplome-specimen-btsp.jpg"),
        )
    db.commit()
    if filled:
        print(f">>> Seeded images for {filled} formation(s)")


def seed_bundled_uploads():
    """Copy media shipped with the code onto the upload volume.

    Files committed to uploads/ (the diploma specimen) live inside the image,
    while /uploads/<name> is served from the mounted volume. Without this the
    site would ask for a file the volume has never seen. Existing files are
    left alone so an admin's replacement is never overwritten by a deploy.
    """
    if os.path.abspath(UPLOAD_DIR) == os.path.abspath(BUNDLED_UPLOAD_DIR):
        return
    if not os.path.isdir(BUNDLED_UPLOAD_DIR):
        return
    for name in os.listdir(BUNDLED_UPLOAD_DIR):
        source = os.path.join(BUNDLED_UPLOAD_DIR, name)
        target = os.path.join(UPLOAD_DIR, name)
        if os.path.isfile(source) and not os.path.exists(target):
            try:
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                shutil.copy2(source, target)
                print(f">>> Seeded upload: {name}")
            except OSError as exc:
                print(f">>> Could not seed upload {name}: {exc}")


with app.app_context():
    init_db()
    migrate_db()
    seed_bundled_uploads()
    seed_formation_images()


if __name__ == "__main__":
    # Never default the interactive debugger on — it is remote code execution
    # for anyone who can reach a traceback.
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
