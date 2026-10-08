"""Local entrypoint.

Run locally with either:
    python run.py                 # plain Python (uses Flask's dev server)
    docker compose up             # containerised

In production (Render) the app is served by gunicorn via the Dockerfile.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    import os

    port = int(os.environ.get("PORT", 8000))
    # host 0.0.0.0 so it is reachable from outside the container
    app.run(host="0.0.0.0", port=port, debug=True)
