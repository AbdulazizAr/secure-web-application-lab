# Secure Web Application Lab

A compact Python application built to demonstrate practical web security controls. Users can create an account, sign in, and manage their own security findings without being able to read or delete another user's records.

## Security controls

- Password hashing with Python's `scrypt` implementation
- Parameterized SQLite queries
- CSRF protection on every form
- Ownership checks for each finding
- Login rate limiting
- Secure cookie settings and browser security headers
- Automatic HTML escaping for user content

The tests include common attack-style inputs to confirm that SQL injection, stored cross-site scripting, missing CSRF tokens, and unauthorized record deletion are handled safely.

## Run locally

```bash
python -m app init-db
python -m app serve
```

Open `http://127.0.0.1:5000`, register two local accounts, and create a few findings.

## Test it

```bash
python -m unittest discover -s tests -v
```

## Docker

```bash
docker build -t secure-web-lab .
docker run --rm -p 8000:8000 -e SECRET_KEY="change-this-to-a-long-random-value" secure-web-lab
```

## Project structure

- `app/` contains the application, database code, and templates.
- `tests/` verifies the security controls.
- `docs/security-notes.md` explains the main design choices and limitations.

## Limitations

This is a local portfolio lab. Sessions and rate limits are held in memory, and SQLite is used for simplicity. A production deployment would use a mature web framework, shared session storage, stronger monitoring, managed secrets, and a production database.
