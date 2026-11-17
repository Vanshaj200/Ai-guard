#!/bin/sh
# Railway entrypoint: keep the SQLite DB on the persistent volume.
set -e

DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "$DATA_DIR"

# First boot on a fresh volume: seed it with the database shipped in the repo
if [ ! -f "$DATA_DIR/dev.db" ]; then
  echo "Seeding $DATA_DIR/dev.db from bundled prisma/dev.db"
  cp prisma/dev.db "$DATA_DIR/dev.db"
fi

export DATABASE_URL="${DATABASE_URL:-file:$DATA_DIR/dev.db}"

exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-8000}"
