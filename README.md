# Web Application Contest

Deliberately vulnerable web app for an **authorised course contest**. Students
solve three independent challenges and submit a `FLAG{...}` for each.

| # | Challenge | Topic | Route | Status |
|---|-----------|-------|-------|--------|
| Q1 | Birchwood | SQL Injection | `/shop` | ✅ built (Set B) |
| Q2 | Fieldnote | Auth & Session | `/portal` | ✅ built (Set B) |
| Q3 | Tidepool | API Attacks | `/api` | ✅ built (Set B) |

Challenges are independent — failing one does not block the others.

## Run it locally

**Option A — Docker (recommended, matches production):**

```bash
docker compose up --build
# open http://localhost:8000
```

**Option B — plain Python (no Docker):**

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py
# open http://localhost:8000
```

The SQLite database is seeded automatically on startup. Restarting the app
resets it to a clean, identical state.

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Covers the store's normal behaviour and the Q1 challenge (search is injectable;
the flag never leaks during ordinary use; a comment-bypass payload surfaces the
hidden flag product), plus the Q2 (reset-token) and Q3 (mass-assignment)
challenges.

## Moving to another machine

The whole folder is self-contained and uses only relative paths. Copy it as-is,
then run either option above. No machine-specific configuration.

## Deploying to Render (free tier)

Deploy notes will be added once Set A is reviewed. In short: push this folder to
a GitHub repo, create a Render **Web Service** from it (Docker environment), and
Render builds the `Dockerfile` and gives you a public HTTPS URL.

## Instructor materials

`instructor/answer-keys.md` contains the intended solution and the flag for each
challenge. **Do not deploy the `instructor/` folder to the student-facing host.**
