from __future__ import annotations

import argparse
import os
from pathlib import Path
from wsgiref.simple_server import make_server

from .db import init_db
from .web import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Secure Web Application Lab.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db")
    serve = subparsers.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    database = os.environ.get("DATABASE", str(Path("instance") / "secure_web_lab.sqlite3"))
    if args.command == "init-db":
        init_db(database)
        print(f"Initialized {database}")
        return 0
    application = create_app(database=database)
    print(f"Serving on http://{args.host}:{args.port}")
    with make_server(args.host, args.port, application) as server:
        server.serve_forever()
    return 0


raise SystemExit(main())
