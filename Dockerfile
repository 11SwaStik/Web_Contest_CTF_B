FROM python:3.12-slim

# Keep Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render (and most hosts) inject the port to listen on via $PORT.
ENV PORT=8000
EXPOSE 8000

# Single worker: the SQLite DB is seeded in-process on startup and we want
# one consistent, clean state. Threads handle concurrent students fine.
CMD gunicorn --workers 1 --threads 8 --bind 0.0.0.0:${PORT} "app:create_app()"
