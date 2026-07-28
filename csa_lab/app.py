"""CSA Lab packaged application entry point."""

from __future__ import annotations

import argparse
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from csa_lab.service import LabApplicationService, default_data_root
from csa_lab.web import LabAdminServer


def main(argv: list[str] | None = None) -> None:
    """Start the localhost administration UI and managed collection runtime."""

    parser = argparse.ArgumentParser(description="CSA Lab")
    parser.add_argument("--data-root")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--admin-port", type=int, default=0)
    args = parser.parse_args(argv)
    data_root = (
        Path(args.data_root)
        if args.data_root
        else default_data_root() / "assessments"
    )
    _configure_logging(data_root.parent / "logs")
    service = LabApplicationService(data_root)
    server = LabAdminServer(service, port=args.admin_port)
    logging.getLogger(__name__).info(
        "CSA Lab local administration UI started"
    )
    server.run(open_browser=not args.no_browser)


def _configure_logging(log_root: Path) -> None:
    """Configure sanitized rotating application logs."""

    log_root.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_root / "csa-lab.log",
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        )
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)


if __name__ == "__main__":
    main()
