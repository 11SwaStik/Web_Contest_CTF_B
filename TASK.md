# TASK.md — status & to-dos

_Last updated: 2026-10-05_

## Done ✅

- [x] **Full visual + product rebrand (this folder only — Set B)**: each of the
      three apps reimagined as a genuinely different product (new layout
      structure, component shapes, typography, palette — not a recolor):
      - Nexora (electronics store) → **Birchwood** — artisanal home & plant
        goods marketplace. Editorial/boutique layout: warm cream + terracotta,
        serif display type, borderless image-led product cards, two-tier header.
        Catalog, reviews and specs content rewritten to match (5 categories,
        16 products).
      - Cobalt (SaaS portal) → **Fieldnote** — freelance studio client/project
        portal. Replaced the vertical sidebar with a horizontal top-tab layout;
        warm paper + coral palette; bento-style dashboard stats.
      - Fluxwire (developer API) → **Tidepool** — weather/ocean data API.
        Replaced the dark Linear-style console with a light "sky & water"
        theme; docs restructured from left-sidebar nav to main content + a
        right-side "on this page" TOC.
      - All routes, vulnerability mechanics, flags, credentials, and the BOLA/
        JWT/SQLi exploit paths are byte-for-byte unchanged — verified via a
        full exploit smoke test post-redesign. 44/44 tests passing (updated
        where they referenced old product/catalog names). Caught and fixed
        two pre-existing stale-content bugs while in there (a leftover
        `voltix.example` email, and team-member emails that didn't match
        their renamed owners).
      - Scaler briefing page target cards updated to the new names/icons/descriptions.

- [x] **Further difficulty reduction — Q1 and Q2 mechanics replaced (Set B only)**:
      instructor feedback was that even the eased Set B Q1/Q2 were still too hard.
      - **Q1 (Birchwood SQLi)**: dropped UNION entirely. The flag is now an
        ordinary unlisted product row (`hidden=1`) filtered out by every listing
        query, including the vulnerable search — so the whole exploit is a
        classic comment-bypass (`' OR 1=1-- `) that drops the trailing
        `AND hidden = 0` filter. No second table, no column-matching, no recon.
      - **Q2 (Fieldnote)**: dropped JWT entirely. The session is now a plain,
        unsigned base64 JSON cookie (`{"sub":...,"role":...}`) — decode, edit
        `role`, re-encode, replace the cookie. No header/payload/signature
        structure, no `alg` concept.
      - New flags: `FLAG{scaler_cmnt_byp4ss_hidd3n_b1}` (Q1),
        `FLAG{scaler_unsgnd_c00kie_tmpr_b2}` (Q2). Q3 (Tidepool BOLA) untouched.
      - `instructor/answer-keys.md` fully rewritten for both, with verified
        payloads (including a DevTools-console one-liner for Q2). 46/46 tests
        passing; full exploit chain re-verified end-to-end; screenshot-reviewed.

- [x] **Q2 replaced again (Set B only): unsigned-cookie-role-tampering →
      predictable session identifier**. The cookie-tampering version reportedly
      had bugs when tested manually, and a simpler mechanic was requested.
      - `session_token` is now **just `base64(username)`** — no role, no JSON
        structure, no signature. `verify_token` only extracts the username;
        role is always looked up fresh from the DB in the `/admin` route
        (`_current_user(session)["role"]`), never trusted from the cookie.
      - Exploit: log in as `jordan`, decode the cookie → see it's literally
        `jordan`. Guess the obvious admin username, encode `base64("admin")`,
        replace the cookie → now a real, valid session for the `admin`
        account itself (not just a forged role).
      - New flag: `FLAG{scaler_pr3d1ct4bl3_s3ss10n_b2}`.
      - Re-verified end-to-end against a **live running server** (not just the
        test client) end to end: login → cookie literally decodes to
        `jordan` → member blocked (403) → forged `admin` cookie → flag.
        `instructor/answer-keys.md` and `instructor/manual-qa-walkthrough.md`
        Q2 sections fully rewritten and every claim re-verified live. 50/50
        tests passing.

- [x] **Q2 replaced a third time (Set B only): predictable session identifier
      → weak/predictable password-reset token.** Root cause of the prior
      version's real bug: the login cookie was set `httponly=True`, which
      silently blocks `document.cookie` read/write in a real browser — pytest
      and curl never caught it because neither enforces that browser
      behavior. Rather than patch around it again, the whole interaction
      style was dropped: **no exploit in this app now touches cookies.**
      - Login sessions are now Flask's own built-in signed, `HttpOnly` cookie
        — safe, tamper-evident, not part of the puzzle at all.
      - New vuln lives entirely in a new **"forgot password"** flow
        (`/portal/forgot`, `/portal/reset`): the reset token is just the
        username itself, with no randomness, no expiry, no server-side
        binding to an issued request. `/portal/reset?username=X&token=X` is
        accepted for any real username `X`.
      - Exploit: request a reset for your own account, see the demo page show
        the link it "would have emailed," notice token == username, repeat
        the pattern for `admin`, set a new admin password, log in, visit
        `/portal/admin`.
      - Pure URL + form-body exploit, verified working in Postman, curl,
        PowerShell — no browser DevTools, no cookie editing, nothing
        browser-enforced to trip over.
      - New flag: `FLAG{scaler_w3ak_r3s3t_tok3n_b2}`. Also fixed a real
        found-along-the-way bug: `login.html` never rendered flashed
        messages at all, so the post-reset confirmation was silently
        dropped — fixed.
      - Every exploit step was re-verified against a **live running server**
        end-to-end (not just pytest) before being written into either
        instructor doc. 50/50 tests passing. `instructor/answer-keys.md` and
        `instructor/manual-qa-walkthrough.md` Q2 sections fully rewritten.

- [x] **Q2 difficulty restored (Set B only): token=username → token=md5(username).**
      Feedback: the reset token being the literal, unmodified username made
      the exploit pure copy-paste with no actual technical step — "the level
      significantly dropped." Fix: the reset token is now an **unsalted MD5
      hash** of the username, same vulnerability class (predictable,
      unsalted, no server-side state) but now requires the student to
      recognise the 32-hex-char shape, confirm it against their own account,
      and independently compute it for a guessed username — a real, small,
      beginner-accessible technical step (any MD5 tool), not a freebie.
      Still 100% URL/form-based, zero cookies.
      - New flag: `FLAG{scaler_unslt3d_md5_r3s3t_b2}`.
      - Verified live against an actual running server using a completely
        independent, standalone `md5`/`md5sum` command-line tool (not the
        app's own code) to confirm the token really is vanilla, unsalted
        MD5 — not a custom variant.
      - `instructor/answer-keys.md` and `instructor/manual-qa-walkthrough.md`
        Q2 sections updated with the MD5 mechanic, pre-verified hash values
        for `jordan`/`admin`, and PowerShell's native MD5 computation (no
        external tool needed on Windows). 50/50 tests passing.

- [x] **Q2 real bypass found and fixed (Set B only): the forgot-password demo
      was leaking any requested account's token, not just your own.** The
      `/portal/forgot` page showed the computed reset link for *whatever*
      username was typed in, including `admin` — so the MD5-derivation step
      was entirely optional; a student could just type `admin` into the form
      and get handed the working link directly, no hashing needed. Fixed by
      only ever showing the demo link when the requester is already signed
      in **as the exact account requested** — you can only ever see your own
      token this way, never another account's. Admin's token must now be
      genuinely computed.
      - Verified live, reproducing the exact reported bypass: logged in as
        `jordan`, POSTed `username=admin` to `/portal/forgot` → response no
        longer contains admin's link or token. Confirmed the legitimate path
        (login → see own token → derive admin's independently → reset →
        login → flag) still works end-to-end.
      - 51/51 tests passing (2 new tests covering the fix + the original
        bypass scenario explicitly). `instructor/manual-qa-walkthrough.md`
        updated: login is now a prerequisite step, and two new negative
        checks added (requesting another account's reset while logged in;
        requesting any reset while logged out) so this class of regression
        gets caught during QA next time, not after handoff.

- [x] **Q3 topic replaced entirely (Set B only): BOLA → Mass Assignment**:
      instructor felt BOLA (change an id in a URL) was too thin a lesson and
      wanted something naturally suited to Postman/Burp Repeater workflows.
      - `GET /api/v1/accounts/{id}` is now correctly scoped (only the caller's
        own id works; any other id 404s) — the old BOLA path is fully closed.
      - New vuln: `PATCH /api/v1/accounts/me` is a legitimate "update your
        profile" endpoint (docs only mention `owner_name`/`email`) that
        blindly merges **every** field sent, including `plan` — a field the
        docs never expose as editable. Sending `{"plan": "internal"}`
        alongside a normal update flips the caller's own account and unlocks
        the flag in `private_note` on that same account (reflected
        immediately in the PATCH response, and on a follow-up GET).
      - Tool-agnostic by design — equally natural in Postman, Burp Repeater,
        curl, PowerShell, or a DevTools `fetch()` call; no tool is required.
      - New flag: `FLAG{scaler_m4ss_4ss1gn_pl4n_b3}`. `app/db.py` gained
        `update_api_account_fields()` (parameterized; the vuln is purely which
        *fields* are whitelisted, not how the SQL is built — no accidental
        second SQLi introduced). Docs page gained a documented PATCH section
        with a new `.method.patch` badge style.
      - `instructor/answer-keys.md` Q3 fully rewritten with Postman step-by-step,
        Burp Repeater instructions, curl/PowerShell/DevTools equivalents.
        49/49 tests passing; full exploit chain re-verified end-to-end
        (including confirming the old BOLA path now correctly 404s);
        screenshot-reviewed.

- [x] Project scaffold: Flask app, Dockerfile, docker-compose, requirements, .gitignore
- [x] SQLite seed layer (`app/db.py`), idempotent, clean reset on startup
- [x] Config module, logging, 404/500 error pages, `/healthz`
- [x] **Q1 — ShopSmart (SQL Injection), Set A** — built as a full storefront:
      home/hero, featured, category browse, product detail pages, about page;
      rich seed catalogue (16 products, categories, price/stock/rating).
      Only the search is vulnerable (7-column UNION read); everything else is
      parameterized. Verified end-to-end.
- [x] Instructor answer key for Q1 (updated to 7-column payloads)
- [x] Test suite (`tests/`, pytest) — 11 tests passing
- [x] Project docs: README, CLAUDE.md, PLANNING.md, TASK.md

## Realism direction (decided)

- Scaler = wrapper only. Targets are fictional brands: **Birchwood** (store),
  **Fieldnote** (portal), **Tidepool** (API). Scaler appears on the `/`
  engagement briefing.
- No contest hub / no vulnerability-type labels. `/` is a Scaler "Rules of
  Engagement" briefing listing targets by brand only. Standalone sites.
- Minimal hints: subtle vulns, decoys (e.g. Tidepool `/v1/usage`), realistic
  content. Discovery-first.
- Design language modelled on real best-in-class sites (Stripe-style API docs,
  modern storefront, SaaS portal) with our own brands/assets — no cloned logos.

## Realism status per challenge

- [x] `/` Scaler engagement briefing (wrapper) — done.
- [x] **Q3 Tidepool** — elevated: marketing landing + API reference +
      decoy `/v1/usage`. Done to the "real site" bar.
- [x] **Q1 Birchwood (M4, P0)** — full store: home + promo + newsletter, browse
      with sort + in-stock filter + pagination, product pages with specs &
      reviews & add-to-cart, working cart → checkout → order confirmation,
      contact page, shipping/returns pages. Decoys (newsletter/contact) work and
      are non-injectable; search is the only injection point (visible errors, as
      decided). 7 new tests; 29 total passing.
- [ ] **Q1 Birchwood (P1)** — optional: customer review submission form.
- [x] **Q2 Fieldnote (M5, P0)** — full SaaS portal: public marketing landing
      (hero + features + pricing), sign-in, app shell (sidebar + topbar),
      dashboard (stats + usage meter + activity), billing + invoices + invoice
      detail (scoped, safe), team list, settings (profile update + password
      change, both persist), support/FAQ, gated admin. JWT `alg:none` flaw intact
      → admin flag. 6 new tests; 35 total passing. No 500s in edge QA.
- [x] **Q2 Fieldnote — Slack re-skin** — aubergine workspace sidebar, Slack-green
      buttons, blue active nav, workspace header; existing features/flow unchanged;
      vuln unchanged. 35 tests still pass.
- [x] **Q3 Tidepool (M6)** — finished to §7.3: expanded API reference
      (quickstart, auth, errors, full endpoint list), a **developer dashboard**
      (`/api/dashboard`: account, API key, usage meter, recent events), extra
      endpoints (`/v1/events` decoy, `/v1/health` public), consistent JSON error
      envelope. BOLA flaw + flag unchanged. Self-reviewed via screenshots.
      3 new tests; **44 total passing.**

## Set A — status: COMPLETE (P0 across all three, to the "real app" bar)
- Birchwood (store) · Fieldnote (Slack-style SaaS portal) · Tidepool (API platform)
- Scaler engagement briefing wrapper · no dead controls · self-reviewed visually.
- Next: M7 — deploy to Render for instructor difficulty sign-off.

- [x] **Dead-control sweep (all apps)** — every clickable control now acts:
      Fieldnote Change plan (persists), Update card (mock+flash), Download receipt
      (real file download), Invite member (adds member), Save notifications, and
      landing pricing "Choose plan" CTAs. Birchwood & Tidepool already clean.
      6 new tests; 41 total. Also: stale-DB self-heal + `.dockerignore` fix.

Note: mobile responsiveness dropped (desktop lab env only).

## In progress 🚧

- [ ] Instructor to run Q1 locally / on Render and sign off on difficulty
      (early read: slightly hard for absolute beginners — calibrate later via
      the levers below)

## Done ✅ (continued)

- [x] **Q2 — MemberPortal (Auth & Session), Set A** — full login portal with its
      own identity; JWT session token; verifier insecurely accepts `alg:none`
      → privilege escalation to admin panel where the flag lives. HS256 path is
      safe (strong secret). Answer key + 6 tests added. Verified end-to-end.

- [x] **Q3 — Tidepool API (API Attacks), Set A** — real REST API with dev docs,
      bearer-token auth; `GET /v1/accounts/{id}` has BOLA/IDOR (no ownership
      check) → read the system account (1000) for the flag. Answer key + 5 tests.
      Verified end-to-end.
- [x] **Set A complete** — all 3 challenges built, 21 tests passing.
- [x] Landing page links all three challenges.

## To do — Set B (reattempt, equivalent difficulty)

- [ ] Q1 variant (b1) — different injectable field + new flag
- [ ] Q2 variant (b2)
- [ ] Q3 variant (b3)
- [ ] Decide how Set A vs Set B are served (separate routes? env flag? separate deploy?)

## To do — deploy & handoff

- [ ] Push to GitHub
- [ ] Create Render web service (Docker), get public URL
- [ ] Exclude `instructor/` from student-facing build
- [ ] Warm-up / cold-start note for contest day
- [ ] Final smoke test of every flag path on the live URL

## Q1 difficulty levers (for calibration after instructor feedback)

- Show vs hide DB errors (hidden = blind injection = harder).
- Number of columns in the search query (fewer = easier).
- Keep vs remove the recon step (naming the hidden table for them = easier).
- Hint text on the search page for beginners.

## Decisions to confirm

- [ ] Q1: keep DB errors visible, or go blind (harder)?
- [ ] Set A vs Set B delivery mechanism
