"""
Builds the database from scratch.

It deletes the existing database file, then runs every SQL script in the
database/ folder in name order (01_..., 02_..., 03_...). Each script creates
its tables and inserts sample data. Run this before testing with Postman so
everyone starts from the same data.

Usage:
    python init_db.py

Author: Mohammad Kourani
"""
import glob
import os
import sqlite3

from dotenv import load_dotenv

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

db_path = os.path.join(PROJECT_DIR, os.getenv("DATABASE_PATH", "instance/security.db"))
sql_folder = os.path.join(PROJECT_DIR, "database")


def main():
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed old database: {db_path}")

    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA foreign_keys = ON")

    sql_files = sorted(glob.glob(os.path.join(sql_folder, "*.sql")))
    if not sql_files:
        print("No SQL files found in database/. Nothing to do.")
        return

    for sql_file in sql_files:
        with open(sql_file, encoding="utf-8") as handle:
            connection.executescript(handle.read())
        print(f"Ran {os.path.basename(sql_file)}")

    connection.commit()

    # Print a short summary so you can see what was created.
    print("\nTables and row counts:")
    table_names = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    for (table_name,) in table_names:
        row_count = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
        print(f"  {table_name}: {row_count} rows")

    connection.close()
    print(f"\nDatabase ready at {db_path}")


if __name__ == "__main__":
    main()
