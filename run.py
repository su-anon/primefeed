"""Development launcher for the PrimeFeed backend.

Usage:
    python run.py            # start on 127.0.0.1:8000
    python run.py --port 9000
"""

import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="PrimeFeed CTI Ledger backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="enable auto-reload")
    args = parser.parse_args()

    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()