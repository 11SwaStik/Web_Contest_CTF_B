"""Q3 — API Attacks (Set B, easier): the Tidepool developer platform.

A small but real-feeling API product: a marketing landing page, a developer
reference, and a JSON API secured with bearer tokens. Authentication works
correctly everywhere. The flaw is **Mass Assignment** (OWASP API6): the
"update my profile" endpoint, `PATCH /v1/accounts/me`, blindly merges
whatever JSON fields the client sends into the account record — including
`plan`, a field the UI and docs never expose as editable. A student who
notices this can simply add `"plan": "internal"` to the request body they're
already sending and flip their own account's tier. Once `plan == "internal"`,
the API reveals the flag on that same account.

No BOLA, no cross-account access, no id-guessing — just a legitimate "edit
your profile" request with one extra field. Tool-agnostic: works identically
in Postman, Burp Suite's Repeater, curl, or a browser DevTools fetch() call.

Intended path:
  1. Land on /api, explore to the reference and the sandbox key.
  2. Call GET /api/v1/accounts/me — see your own account (id 104, plan "starter").
  3. Find the PATCH /v1/accounts/me endpoint in the docs (used for updating
     your name/email) and send a normal-looking update.
  4. Add an extra field the docs never mention: "plan": "internal".
  5. The response reflects the change — and once your plan is "internal",
     the flag appears in `private_note`.

Intentionally vulnerable code for an authorised training contest — do not add
a field whitelist that excludes `plan`.
"""
from flask import Blueprint, request, jsonify, render_template

from .. import db

bp = Blueprint("api", __name__, url_prefix="/api")

# The sandbox key is shown to developers in the reference (like a real test key).
DEMO_TOKEN = "tp_live_sk_demo_7c3f9a2b1e"
DEMO_ACCOUNT_ID = 104

MASS_ASSIGN_FLAG_B = "FLAG{scaler_m4ss_4ss1gn_pl4n_b3}"


def _bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    return None


def _authenticate():
    """Return the calling account for a valid token, else None."""
    token = _bearer_token()
    if not token:
        return None
    return db.api_account_by_token(token)


def _unauthorized():
    return jsonify(
        error="unauthorized",
        message="Provide a valid 'Authorization: Bearer <token>' header.",
    ), 401


def _public_view(account):
    note = account["private_note"]
    if account["plan"] == "internal":
        # VULN surface: plan is reachable via mass assignment (see PATCH
        # /v1/accounts/me below), and flipping it unlocks this field.
        note = MASS_ASSIGN_FLAG_B
    return {
        "id": account["id"],
        "owner_name": account["owner_name"],
        "email": account["email"],
        "plan": account["plan"],
        "private_note": note,
    }


# --- Pages ---------------------------------------------------------------

@bp.route("/", strict_slashes=False)
def landing():
    return render_template("api/landing.html")


@bp.route("/docs")
def docs():
    return render_template("api/docs.html", token=DEMO_TOKEN,
                           account_id=DEMO_ACCOUNT_ID)


def _events_for(account):
    """Synthetic, caller-scoped event feed (benign decoy)."""
    seed = [
        ("account.updated", "Profile fields synced (owner_name, email, plan)"),
        ("invoice.paid", "Invoice INV-2026-0412 marked paid"),
        ("key.used", "API key used from 10.14.22.6"),
        ("usage.threshold", "Reached 68% of monthly request quota"),
        ("member.invited", "Team member invited"),
    ]
    out = []
    for i, (etype, msg) in enumerate(seed):
        out.append({
            "id": f"evt_{account['id']}{1000 + i}",
            "type": etype,
            "message": msg,
            "created": f"2026-09-{24 - i:02d}T10:0{i}:00Z",
        })
    return out


@bp.route("/dashboard")
def dashboard():
    # Sandbox dashboard: shows the demo account, its key, usage and events.
    account = db.api_account_by_id(DEMO_ACCOUNT_ID)
    used, limit = 68420, 100000
    return render_template("api/dashboard.html", account=account,
                           token=DEMO_TOKEN, used=used, limit=limit,
                           pct=round(used * 100 / limit),
                           events=_events_for(account))


# --- JSON API ------------------------------------------------------------

@bp.route("/v1/accounts/me", methods=["GET", "PATCH"])
def me():
    caller = _authenticate()
    if not caller:
        return _unauthorized()

    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        # --- Mass assignment: every field the client sends is applied, with
        # no whitelist excluding `plan`. ---
        db.update_api_account_fields(caller["id"], data)
        caller = db.api_account_by_id(caller["id"])

    return jsonify(_public_view(caller))


@bp.route("/v1/accounts/<int:account_id>")
def get_account(account_id):
    # SAFE — scoped to the caller's own account only (not the vulnerable
    # surface; see PATCH /v1/accounts/me above).
    caller = _authenticate()
    if not caller:
        return _unauthorized()
    if account_id != caller["id"]:
        return jsonify(error="not_found",
                       message=f"No account with id {account_id}."), 404
    return jsonify(_public_view(caller))


@bp.route("/v1/usage")
def usage():
    # Decoy: benign, correctly scoped to the caller. No flag here.
    caller = _authenticate()
    if not caller:
        return _unauthorized()
    limits = {"starter": 10000, "pro": 100000,
              "enterprise": 1000000, "internal": 0}
    return jsonify(
        account_id=caller["id"],
        plan=caller["plan"],
        requests_this_month=4213 if caller["id"] == DEMO_ACCOUNT_ID else 0,
        monthly_limit=limits.get(caller["plan"], 10000),
    )


@bp.route("/v1/events")
def events():
    # Decoy: benign, correctly scoped to the caller (list envelope). No flag.
    caller = _authenticate()
    if not caller:
        return _unauthorized()
    return jsonify(object="list", data=_events_for(caller), has_more=False)


@bp.route("/v1/health")
def health():
    # Public status endpoint.
    return jsonify(status="operational", version="v1")
