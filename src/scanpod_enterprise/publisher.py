"""Continuously retries pending transactional-outbox events."""
import time

from .db import SessionLocal
from .services import publish_pending_outbox


def main() -> None:
    while True:
        with SessionLocal() as session:
            publish_pending_outbox(session)
        time.sleep(5)


if __name__ == "__main__":
    main()
