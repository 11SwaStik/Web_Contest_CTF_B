"""SQLite data layer: schema, seed data, and query helpers.

The database is a single file, seeded idempotently on startup. On ephemeral
hosting the file is recreated every deploy/restart, giving each run a clean,
identical, known-good state — ideal for a fair contest.

Design note: every helper here that takes user input uses **parameterized**
queries and is safe. The single intentional SQL-injection vulnerability lives
in the store search (see `app/challenges/sqli.py`), where the query is built by
string concatenation on purpose — including the `hidden = 0` listing filter it
shares with every other product query, which is what a comment-bypass defeats.
"""
import os
import random
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

from .config import Config

DB_PATH = Config.DB_PATH


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS categories (
    id    INTEGER PRIMARY KEY,
    name  TEXT NOT NULL,
    slug  TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    price       REAL NOT NULL,
    category    TEXT NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0,
    rating      REAL NOT NULL DEFAULT 0,
    emoji       TEXT NOT NULL DEFAULT '📦',
    -- Q1 flag (Set B): one unlisted row with hidden=1. Every normal listing
    -- query filters it out; the vulnerable search does too, but a comment
    -- (`-- `) truncates the query and drops that filter. No UNION needed.
    hidden      INTEGER NOT NULL DEFAULT 0
);

-- Q2 (Fieldnote) accounts. Passwords are stored hashed.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'member',
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    company       TEXT NOT NULL DEFAULT '',
    plan          TEXT NOT NULL DEFAULT 'Starter'
);

CREATE TABLE IF NOT EXISTS invoices (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    number   TEXT NOT NULL,
    date     TEXT NOT NULL,
    amount   REAL NOT NULL,
    status   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    when_at  TEXT NOT NULL,
    text     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS team_members (
    id      INTEGER PRIMARY KEY,
    company TEXT NOT NULL,
    name    TEXT NOT NULL,
    email   TEXT NOT NULL,
    role    TEXT NOT NULL
);

-- Q3 (Tidepool API) accounts. `api_token` authenticates the owner.
CREATE TABLE IF NOT EXISTS api_accounts (
    id           INTEGER PRIMARY KEY,
    owner_name   TEXT NOT NULL,
    email        TEXT NOT NULL,
    plan         TEXT NOT NULL,
    api_token    TEXT NOT NULL UNIQUE,
    private_note TEXT NOT NULL
);

-- Birchwood commerce: product reviews (P1), orders, and decoy form captures.
CREATE TABLE IF NOT EXISTS reviews (
    id         INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL,
    author     TEXT NOT NULL,
    rating     INTEGER NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id           INTEGER PRIMARY KEY,
    order_number TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL,
    full_name    TEXT NOT NULL,
    address      TEXT NOT NULL,
    city         TEXT NOT NULL,
    postcode     TEXT NOT NULL,
    subtotal     REAL NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
    id           INTEGER PRIMARY KEY,
    order_number TEXT NOT NULL,
    product_id   INTEGER NOT NULL,
    name         TEXT NOT NULL,
    price        REAL NOT NULL,
    qty          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id         INTEGER PRIMARY KEY,
    email      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contact_messages (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    message    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

CATEGORIES = [
    ("Plants", "plants"),
    ("Kitchen", "kitchen"),
    ("Lighting", "lighting"),
    ("Textiles", "textiles"),
    ("Decor", "decor"),
]

# (name, description, price, category, stock, rating, emoji)
PRODUCTS = [
    ("Fiddle Leaf Fig", "Statement floor plant with broad, glossy leaves. Bright indirect light.", 54.99, "Plants", 23, 4.5, "🌿"),
    ("Monstera Deliciosa", "Iconic split-leaf philodendron, shipped in a 6in nursery pot.", 39.00, "Plants", 61, 4.8, "🪴"),
    ("Trailing Pothos", "Low-maintenance trailing vine, thrives almost anywhere.", 18.50, "Plants", 87, 4.2, "🌱"),
    ("Hand-thrown Ceramic Bowl", "Stoneware serving bowl, reactive glaze, dishwasher safe.", 48.00, "Kitchen", 38, 4.7, "🍲"),
    ("Walnut Serving Board", "Live-edge walnut board, food-safe oil finish.", 64.00, "Kitchen", 52, 4.1, "🪵"),
    ("Linen Napkin Set", "Set of four stonewashed linen napkins.", 32.00, "Kitchen", 44, 4.4, "🧺"),
    ("Rattan Pendant Lamp", "Handwoven rattan shade, warm ambient glow.", 129.00, "Lighting", 19, 4.6, "💡"),
    ("Ceramic Table Lamp", "Matte-glaze base with a linen drum shade.", 89.00, "Lighting", 23, 4.3, "🏮"),
    ("Brass Wall Sconce", "Articulated brass arm, soft dimmable light.", 75.00, "Lighting", 31, 4.5, "🕯️"),
    ("Wool Throw Blanket", "Chunky-knit merino wool throw, 50x60in.", 79.99, "Textiles", 48, 4.9, "🧶"),
    ("Linen Duvet Cover", "Stonewashed European flax linen, queen size.", 149.00, "Textiles", 34, 4.7, "🛏️"),
    ("Woven Floor Rug", "Hand-loomed jute and wool blend, 5x7ft.", 142.00, "Textiles", 20, 4.4, "🧵"),
    ("Hand-blown Glass Vase", "Organic-shaped vase, each piece one of a kind.", 39.50, "Decor", 56, 4.2, "🏺"),
    ("Carved Wood Candle Holder", "Solid ash wood, holds three taper candles.", 34.00, "Decor", 63, 4.5, "🕯️"),
    ("Woven Wall Hanging", "Macrame wall hanging, cotton cord, natural dye.", 58.00, "Decor", 40, 4.0, "🧶"),
    ("Ceramic Planter Set", "Set of three nesting planters with drainage.", 45.99, "Decor", 57, 4.1, "🪴"),
]

# Q1 flag (Set B). Stored as an ordinary, unlisted product row (hidden=1) —
# the search comment-bypass reveals it directly as a "product" card. No
# second table, no UNION.
SQLI_FLAG_B = "FLAG{scaler_cmnt_byp4ss_hidd3n_b1}"

# Q2 (Fieldnote) accounts. The member credential is handed to students in the
# challenge prompt; the admin password is strong and unknown (the intended path
# is a JWT forgery, not cracking the admin login).
USERS = [
    # (username, password, role, full_name, email, company, plan)
    ("jordan", "fieldnote2026", "member", "Jordan Mehta",
     "jordan@brightline.example", "Brightline Logistics", "Pro"),
    ("sara", "hunter2meh", "member", "Sara Lindqvist",
     "sara@brightline.example", "Brightline Logistics", "Pro"),
    ("admin", "C0balt-Adm1n-Pw-551207-keep-secret", "admin",
     "Site Administrator", "admin@fieldnote.example", "Fieldnote", "Enterprise"),
]

FIELDNOTE_INVOICES = [
    # (username, number, date, amount, status)
    ("jordan", "INV-2026-0412", "2026-09-01", 149.00, "Paid"),
    ("jordan", "INV-2026-0388", "2026-08-01", 149.00, "Paid"),
    ("jordan", "INV-2026-0355", "2026-07-01", 149.00, "Paid"),
    ("jordan", "INV-2026-0431", "2026-10-01", 149.00, "Due"),
    ("sara", "INV-2026-0410", "2026-09-01", 149.00, "Paid"),
]

FIELDNOTE_ACTIVITY = [
    # (username, when_at, text)
    ("jordan", "2026-09-24 14:32", "Signed in from Chrome on macOS"),
    ("jordan", "2026-09-22 09:11", "Exported the September usage report"),
    ("jordan", "2026-09-20 16:45", "Invited a new team member"),
    ("jordan", "2026-09-18 11:02", "Updated billing details"),
    ("sara", "2026-09-23 10:05", "Signed in from Firefox on Windows"),
]

FIELDNOTE_TEAM = [
    # (company, name, email, role)
    ("Brightline Logistics", "Jordan Mehta", "jordan@brightline.example", "Owner"),
    ("Brightline Logistics", "Sara Lindqvist", "sara@brightline.example", "Member"),
    ("Brightline Logistics", "Priya Anand", "priya@brightline.example", "Member"),
    ("Brightline Logistics", "Lena Fischer", "lena@brightline.example", "Billing"),
]

# Q3 (Tidepool API) accounts. The student is given the token for account 104
# ("starter" plan). The flag unlocks on that *same* account once its own
# `plan` is mass-assigned to "internal" via PATCH /v1/accounts/me — these
# other accounts are realism/decoys only, not part of the solution path.
API_ACCOUNTS = [
    # (id, owner_name, email, plan, api_token, private_note)
    (100, "Tidepool System", "system@tidepool.example", "enterprise",
     "tp_live_sk_SYSTEM_0e91c4", "Reserved for internal tooling."),
    (101, "Nina Patel", "nina@vaultworks.example", "pro",
     "tp_live_sk_nina_2a71b9", "Renewal due in March."),
    (104, "You (Demo User)", "demo@tidepool.example", "starter",
     "tp_live_sk_demo_7c3f9a2b1e", "Welcome to Tidepool!"),
    (102, "Marco Reyes", "marco@brightline.example", "pro",
     "tp_live_sk_marco_5f0c8d", "Migrating from legacy CRM."),
    (103, "Aiko Tanaka", "aiko@lumen.example", "enterprise",
     "tp_live_sk_aiko_9b347e", "Quarterly export automated."),
]


# A few reviews so product pages feel real (P1 content, safe data).
REVIEWS = [
    (2, "Devon R.", 5, "Arrived in perfect shape, gorgeous fenestrated leaves already."),
    (2, "Priya S.", 4, "Great size for the price, packaging kept it totally safe."),
    (1, "Chen L.", 5, "Statement plant that transformed our living room corner."),
    (4, "Marcus T.", 5, "The glaze is even more beautiful in person."),
    (7, "Ana V.", 4, "Lovely warm light; the rattan weave is beautifully made."),
    (10, "Sam K.", 5, "So soft and chunky, looks great draped on the sofa."),
]


def seed(conn):
    cur = conn.cursor()

    if cur.execute("SELECT COUNT(*) c FROM categories").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO categories (name, slug) VALUES (?, ?)", CATEGORIES
        )

    if cur.execute("SELECT COUNT(*) c FROM products").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO products (name, description, price, category, stock, rating, emoji) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            PRODUCTS,
        )
        # The flag, seeded as a normal-looking but unlisted (hidden=1) row.
        cur.execute(
            "INSERT INTO products (name, description, price, category, stock, rating, emoji, hidden) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (SQLI_FLAG_B, "Internal — not for sale.", 0, "Internal", 0, 0, "🔒"),
        )

    if cur.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO users (username, password_hash, role, full_name, email, company, plan) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(u, generate_password_hash(p), r, n, e, co, pl)
             for (u, p, r, n, e, co, pl) in USERS],
        )

    if cur.execute("SELECT COUNT(*) c FROM invoices").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO invoices (username, number, date, amount, status) VALUES (?, ?, ?, ?, ?)",
            FIELDNOTE_INVOICES,
        )

    if cur.execute("SELECT COUNT(*) c FROM activity_log").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO activity_log (username, when_at, text) VALUES (?, ?, ?)",
            FIELDNOTE_ACTIVITY,
        )

    if cur.execute("SELECT COUNT(*) c FROM team_members").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO team_members (company, name, email, role) VALUES (?, ?, ?, ?)",
            FIELDNOTE_TEAM,
        )

    if cur.execute("SELECT COUNT(*) c FROM api_accounts").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO api_accounts (id, owner_name, email, plan, api_token, private_note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            API_ACCOUNTS,
        )

    if cur.execute("SELECT COUNT(*) c FROM reviews").fetchone()["c"] == 0:
        cur.executemany(
            "INSERT INTO reviews (product_id, author, rating, body) VALUES (?, ?, ?, ?)",
            REVIEWS,
        )

    conn.commit()


# If an existing DB predates the current schema (e.g. a stale contest.db), it is
# rebuilt from scratch. The data here is disposable seed data, so this is safe
# and prevents "no such column" 500s after a schema change.
_EXPECTED_COLUMNS = {
    "users": {"email", "company", "plan"},
    "api_accounts": {"private_note"},
    "products": {"hidden"},
}


def _schema_is_current(conn):
    for table, needed in _EXPECTED_COLUMNS.items():
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        if rows and not needed.issubset({r[1] for r in rows}):
            return False
    return True


def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    if not _schema_is_current(conn):
        conn.close()
        if DB_PATH != ":memory:" and os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        conn = get_db()
        conn.executescript(SCHEMA)
    seed(conn)
    conn.close()


# --- Safe query helpers (parameterized) -----------------------------------

def list_categories():
    conn = get_db()
    rows = conn.execute("SELECT name, slug FROM categories ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def featured_products(limit=8):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM products WHERE hidden = 0 ORDER BY rating DESC, id ASC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def products_in_category(slug, limit=50):
    conn = get_db()
    row = conn.execute("SELECT name FROM categories WHERE slug = ?", (slug,)).fetchone()
    if row is None:
        conn.close()
        return None, []
    name = row["name"]
    rows = conn.execute(
        "SELECT * FROM products WHERE category = ? AND hidden = 0 ORDER BY id LIMIT ?",
        (name, limit),
    ).fetchall()
    conn.close()
    return name, [dict(r) for r in rows]


def get_product(pid):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM products WHERE id = ? AND hidden = 0", (pid,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def related_products(category, exclude_id, limit=4):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM products WHERE category = ? AND id != ? AND hidden = 0 "
        "ORDER BY rating DESC LIMIT ?",
        (category, exclude_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Columns the vulnerable search selects, rendered as product cards.
SEARCH_COLUMNS = "id, name, price, category, emoji, rating"


def search_products(q):
    """INTENTIONALLY VULNERABLE product search (string-concatenated SQL).

    No ORDER BY / LIMIT in the SQL — sorting and pagination happen in Python.
    The query also filters out unlisted (`hidden`) rows, same as every other
    listing — but because `q` is concatenated directly, a `-- ` comment in a
    payload truncates the query and drops that trailing filter entirely:

        xyz' OR 1=1--

    turns `... LIKE '%xyz' OR 1=1-- %' AND hidden = 0` into
    `... LIKE '%xyz' OR 1=1` (the rest is commented out) — every row,
    including the hidden flag product, is returned. No UNION, no second
    table, no column-matching. Returns (rows, error).
    """
    query = (
        f"SELECT {SEARCH_COLUMNS} FROM products "
        f"WHERE name LIKE '%{q}%' AND hidden = 0"
    )
    conn = get_db()
    try:
        rows = [dict(r) for r in conn.execute(query).fetchall()]
        return rows, None
    except Exception as e:
        return None, f"{e}\n\n[debug] query: {query}"
    finally:
        conn.close()


def category_products(slug):
    """SAFE (parameterized) — all products in a category, unsorted."""
    conn = get_db()
    cat = conn.execute("SELECT name FROM categories WHERE slug = ?", (slug,)).fetchone()
    if cat is None:
        conn.close()
        return None, []
    rows = conn.execute(
        "SELECT * FROM products WHERE category = ? AND hidden = 0", (cat["name"],)
    ).fetchall()
    conn.close()
    return cat["name"], [dict(r) for r in rows]


def products_by_ids(ids):
    """SAFE — fetch products for a set of ids (for the cart)."""
    if not ids:
        return []
    conn = get_db()
    marks = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT * FROM products WHERE id IN ({marks}) AND hidden = 0", tuple(ids)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def reviews_for(product_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT author, rating, body FROM reviews WHERE product_id = ? ORDER BY id DESC",
        (product_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_order(email, full_name, address, city, postcode, items, subtotal):
    """Create an order + its line items. `items` = list of dicts with
    id/name/price/qty. Returns the generated order number."""
    number = "BWD-" + "".join(str(random.randint(0, 9)) for _ in range(8))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = get_db()
    conn.execute(
        "INSERT INTO orders (order_number, email, full_name, address, city, postcode, subtotal, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (number, email, full_name, address, city, postcode, subtotal, now),
    )
    conn.executemany(
        "INSERT INTO order_items (order_number, product_id, name, price, qty) VALUES (?, ?, ?, ?, ?)",
        [(number, it["id"], it["name"], it["price"], it["qty"]) for it in items],
    )
    conn.commit()
    conn.close()
    return number


def get_order(number):
    conn = get_db()
    order = conn.execute(
        "SELECT * FROM orders WHERE order_number = ?", (number,)
    ).fetchone()
    if order is None:
        conn.close()
        return None, []
    items = conn.execute(
        "SELECT * FROM order_items WHERE order_number = ?", (number,)
    ).fetchall()
    conn.close()
    return dict(order), [dict(i) for i in items]


def add_newsletter(email):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = get_db()
    conn.execute("INSERT INTO newsletter_subscribers (email, created_at) VALUES (?, ?)",
                 (email, now))
    conn.commit()
    conn.close()


def add_contact_message(name, email, message):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = get_db()
    conn.execute("INSERT INTO contact_messages (name, email, message, created_at) VALUES (?, ?, ?, ?)",
                 (name, email, message, now))
    conn.commit()
    conn.close()


# --- Q2 auth helpers (parameterized; password check is constant-time) ------

def authenticate(username, password):
    """Return the user dict if credentials are valid, else None."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and check_password_hash(row["password_hash"], password):
        return dict(row)
    return None


def get_user(username):
    conn = get_db()
    row = conn.execute(
        "SELECT id, username, role, full_name, email, company, plan "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def invoices_for(username):
    conn = get_db()
    rows = conn.execute(
        "SELECT number, date, amount, status FROM invoices WHERE username = ? "
        "ORDER BY date DESC",
        (username,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_invoice(username, number):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM invoices WHERE username = ? AND number = ?",
        (username, number),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def activity_for(username, limit=6):
    conn = get_db()
    rows = conn.execute(
        "SELECT when_at, text FROM activity_log WHERE username = ? "
        "ORDER BY when_at DESC LIMIT ?",
        (username, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def team_for(company):
    conn = get_db()
    rows = conn.execute(
        "SELECT name, email, role FROM team_members WHERE company = ? ORDER BY id",
        (company,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_profile(username, full_name, email):
    conn = get_db()
    conn.execute(
        "UPDATE users SET full_name = ?, email = ? WHERE username = ?",
        (full_name, email, username),
    )
    conn.commit()
    conn.close()


def update_password(username, new_password):
    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (generate_password_hash(new_password), username),
    )
    conn.commit()
    conn.close()


def update_plan(username, plan):
    conn = get_db()
    conn.execute("UPDATE users SET plan = ? WHERE username = ?", (plan, username))
    conn.commit()
    conn.close()


def add_team_member(company, name, email, role="Member"):
    conn = get_db()
    conn.execute(
        "INSERT INTO team_members (company, name, email, role) VALUES (?, ?, ?, ?)",
        (company, name, email, role),
    )
    conn.commit()
    conn.close()


# --- Q3 API helpers (parameterized) ---------------------------------------

def api_account_by_token(token):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_accounts WHERE api_token = ?", (token,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def api_account_by_id(account_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_accounts WHERE id = ?", (account_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# INTENTIONAL VULNERABILITY (Q3, Set B): `plan` is in the assignable set, so
# a client can PATCH their own tier — mass assignment. SQL itself stays
# parameterized/safe throughout; the flaw is purely which fields are allowed,
# not how the query is built.
_API_ACCOUNT_ASSIGNABLE_FIELDS = {"owner_name", "email", "plan"}


def update_api_account_fields(account_id, data):
    """Merge client-provided fields into an API account. See the
    intentional-vulnerability note above `_API_ACCOUNT_ASSIGNABLE_FIELDS`."""
    fields = {
        k: v for k, v in (data or {}).items()
        if k in _API_ACCOUNT_ASSIGNABLE_FIELDS and isinstance(v, str) and v
    }
    if not fields:
        return
    conn = get_db()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(
        f"UPDATE api_accounts SET {set_clause} WHERE id = ?",
        (*fields.values(), account_id),
    )
    conn.commit()
    conn.close()
