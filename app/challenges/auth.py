"""Q2 — Auth & Session Attacks (Set B, easier): the Fieldnote customer portal.

Fieldnote is a business SaaS portal: marketing site, sign-in, a dashboard, and
real billing / team / settings areas. **Login sessions themselves are safe** —
they use Flask's built-in signed session cookie (tamper-evident, HMAC'd with
the app's secret key), so there is nothing to forge or edit there.

The one intentional flaw is in the **"forgot password" flow**
(`/portal/forgot` → `/portal/reset`): the reset token is **an unsalted MD5
hash of the username** — `md5(username)` — with no secret, no per-request
randomness, and no expiry. It isn't random, but it also isn't handed to you
verbatim: a student has to notice the token *looks like* a hash (32 hex
characters), recognise/guess it's MD5 of something public, and verify that
guess — then reproduce it for a different username with any MD5 tool.

IMPORTANT (closes a trivial bypass): the demo "here's the link we would have
emailed you" display on `/portal/forgot` only ever shows a link for the
account you are **currently signed into** — never for an arbitrary username
you type. This matters: without that restriction, a student could simply type
`admin` into the forgot-password form and the app would hand them the fully
valid, already-computed link, no MD5 required at all. Requiring an existing
session that matches the requested username forces the student to actually
derive the admin token themselves — they can only ever *see* their own token
on-screen (by being logged in as themselves first), never anyone else's.

This is a weak/predictable password-reset token (a real, well-known class of
bug — deriving a "secret" from a public value with no actual secret involved),
exploited entirely through URLs and a form — no cookies, no headers, no
DevTools required.

Intended path:
  1. Sign in with the member account from the prompt (`jordan`).
  2. While signed in, request a password reset for your OWN username. The
     demo page shows the reset link it "emailed" you (only works because
     you're signed in as jordan) — note the token is a 32-char hex string.
  3. Recognise the shape as MD5 and confirm: md5("jordan") matches it exactly.
  4. Compute md5("admin") with any tool (CyberChef, `md5sum`, Python,
     an online calculator) and construct:
     /portal/reset?username=admin&token=<md5("admin")>
  5. Set a new password for the admin account on that page.
  6. Log in as `admin` with the new password → /portal/admin → the flag.

Intentionally vulnerable code for an authorised training contest — do not add
a secret/salt or randomness to the reset token, and do not remove the
same-account restriction on the demo link display (the token derivation
itself should remain the only way to produce a working link for a different
account).
"""
import hashlib

from flask import (Blueprint, request, render_template, redirect, url_for,
                   flash, abort, Response, session)

from .. import db

bp = Blueprint("auth", __name__, url_prefix="/portal")

AUTH_FLAG_A = "FLAG{scaler_unslt3d_md5_r3s3t_b2}"


# --- Session: Flask's built-in signed cookie (safe, not the vulnerable part) -

def _session_ctx():
    """Template-facing session dict, built from Flask's secure session.
    Returns None if not logged in."""
    username = session.get("username")
    if not username:
        return None
    user = db.get_user(username)
    return {"sub": username, "role": user["role"] if user else None}


def _current_user(sess):
    """Full DB user for the session subject (may be None)."""
    return db.get_user(sess.get("sub")) if sess else None


# --- Public marketing -----------------------------------------------------

@bp.route("/", strict_slashes=False)
def index():
    return render_template("portal/landing.html", session=_session_ctx())


# --- Auth -------------------------------------------------------------------

@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = db.authenticate(request.form.get("username", ""),
                               request.form.get("password", ""))  # safe check
        if user:
            session.clear()
            session["username"] = user["username"]
            return redirect(url_for("auth.dashboard"))
        error = "Invalid username or password."
    return render_template("portal/login.html", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


# --- Forgot / reset password (the vulnerable flow) --------------------------

def _reset_token_for(username: str) -> str:
    """INTENTIONAL VULNERABILITY: the reset token is an unsalted MD5 hash of
    the username — a deterministic function of a public value, no secret, no
    randomness, no expiry. Anyone can compute it for any username with any
    MD5 tool and construct `?username=X&token=md5(X)` to reset X's password."""
    return hashlib.md5(username.encode()).hexdigest()


@bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    reset_link = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = db.get_user(username)
        if user:
            token = _reset_token_for(username)
            # Demo environment: there's no real email backend, so instead of
            # actually emailing the link, we show it on-screen — but ONLY for
            # the account you're already signed into (same as "you have
            # access to your own inbox" in a real flow). Requesting a reset
            # for an account that isn't yours never reveals its link or
            # token here; the student has to derive that token themselves.
            if session.get("username") == username:
                reset_link = url_for("auth.reset", username=username, token=token)
        flash("If that account exists, we've sent a reset link to the email on file.", "success")
    return render_template("portal/forgot.html", reset_link=reset_link)


@bp.route("/reset", methods=["GET", "POST"])
def reset():
    username = request.values.get("username", "")
    token = request.values.get("token", "")
    user = db.get_user(username)
    valid = bool(user) and bool(token) and token == _reset_token_for(username)  # <-- VULN

    if not valid:
        flash("This reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot"))

    if request.method == "POST":
        new = request.form.get("new_password", "")
        if len(new) < 6:
            flash("New password must be at least 6 characters.", "error")
        else:
            db.update_password(username, new)
            flash("Password reset. You can now sign in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("portal/reset.html", username=username, token=token)


# --- Authenticated app ----------------------------------------------------

@bp.route("/dashboard")
def dashboard():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess) or {"full_name": sess.get("sub"),
                                   "username": sess.get("sub"),
                                   "company": "—", "plan": "—"}
    return render_template("portal/dashboard.html", session=sess, user=user,
                           active="dashboard",
                           activity=db.activity_for(sess.get("sub")),
                           invoices=db.invoices_for(sess.get("sub")))


@bp.route("/billing")
def billing():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess) or {"plan": "—"}
    return render_template("portal/billing.html", session=sess, user=user,
                           active="billing",
                           invoices=db.invoices_for(sess.get("sub")))


@bp.route("/billing/invoice/<number>")
def invoice(number):
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    # Scoped to the signed-in user (safe — not the vulnerable surface).
    inv = db.get_invoice(sess.get("sub"), number)
    if inv is None:
        abort(404)
    user = _current_user(sess) or {}
    return render_template("portal/invoice.html", session=sess, user=user,
                           active="billing", invoice=inv)


PLANS = ["Starter", "Pro", "Enterprise"]


@bp.route("/billing/plan", methods=["POST"])
def change_plan():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    plan = request.form.get("plan", "")
    if plan in PLANS:
        db.update_plan(sess.get("sub"), plan)
        flash(f"Your plan was changed to {plan}.", "success")
    else:
        flash("Please choose a valid plan.", "error")
    return redirect(url_for("auth.billing"))


@bp.route("/billing/card", methods=["POST"])
def update_card():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    number = request.form.get("number", "").replace(" ", "")
    if number.isdigit() and len(number) >= 12:
        flash(f"Card ending •••• {number[-4:]} saved. (Demo — no charge.)", "success")
    else:
        flash("Please enter a valid card number.", "error")
    return redirect(url_for("auth.billing"))


@bp.route("/billing/invoice/<number>/download")
def invoice_download(number):
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    inv = db.get_invoice(sess.get("sub"), number)
    if inv is None:
        abort(404)
    user = _current_user(sess) or {}
    body = (
        "FIELDNOTE, INC.\nbilling@fieldnote.example\n\n"
        f"Invoice:  {inv['number']}\n"
        f"Date:     {inv['date']}\n"
        f"Status:   {inv['status']}\n"
        f"Bill to:  {user.get('full_name','')} <{user.get('email','')}>\n\n"
        f"{user.get('plan','Subscription')} plan — monthly   ${inv['amount']:.2f}\n"
        "----------------------------------------\n"
        f"TOTAL                               ${inv['amount']:.2f}\n\n"
        "Demo environment — no real charge.\n"
    )
    return Response(
        body, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={inv['number']}.txt"},
    )


@bp.route("/team")
def team():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess) or {"company": ""}
    return render_template("portal/team.html", session=sess, user=user,
                           active="team", members=db.team_for(user.get("company", "")))


@bp.route("/team/invite", methods=["POST"])
def team_invite():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess) or {"company": ""}
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    if name and "@" in email:
        db.add_team_member(user.get("company", ""), name, email, "Member")
        flash(f"Invitation sent to {email}.", "success")
    else:
        flash("Please provide a name and valid email.", "error")
    return redirect(url_for("auth.team"))


@bp.route("/settings")
def settings():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess) or {}
    return render_template("portal/settings.html", session=sess, user=user,
                           active="settings")


@bp.route("/settings/profile", methods=["POST"])
def settings_profile():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    if full_name and "@" in email:
        db.update_profile(sess.get("sub"), full_name, email)
        flash("Profile updated.", "success")
    else:
        flash("Please provide a name and valid email.", "error")
    return redirect(url_for("auth.settings"))


@bp.route("/settings/password", methods=["POST"])
def settings_password():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    current = request.form.get("current", "")
    new = request.form.get("new", "")
    if not db.authenticate(sess.get("sub"), current):
        flash("Current password is incorrect.", "error")
    elif len(new) < 6:
        flash("New password must be at least 6 characters.", "error")
    else:
        db.update_password(sess.get("sub"), new)
        flash("Password changed.", "success")
    return redirect(url_for("auth.settings"))


@bp.route("/settings/notifications", methods=["POST"])
def settings_notifications():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    flash("Notification preferences saved.", "success")
    return redirect(url_for("auth.settings"))


@bp.route("/support")
def support():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    return render_template("portal/support.html", session=sess,
                           user=_current_user(sess) or {}, active="support")


@bp.route("/admin")
def admin():
    sess = _session_ctx()
    if not sess:
        return redirect(url_for("auth.login"))
    user = _current_user(sess)
    role = user["role"] if user else None
    if role != "admin":
        return render_template("portal/forbidden.html", session=sess,
                               user=user or {}, active="admin", role=role), 403
    return render_template("portal/admin.html", session=sess,
                           user=user, active="admin", flag=AUTH_FLAG_A)
