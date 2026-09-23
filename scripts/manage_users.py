"""CLI to add/remove/list the limited set of people allowed to use this tool.

Usage:
  python -m scripts.manage_users add <username> <password>
  python -m scripts.manage_users remove <username>
  python -m scripts.manage_users list
"""
from __future__ import annotations

import sys

from app import auth


def main(argv: list[str]) -> int:
    if len(argv) < 1:
        print(__doc__)
        return 1

    cmd = argv[0]
    if cmd == "add" and len(argv) == 3:
        auth.add_user(argv[1], argv[2])
        print(f"added user '{argv[1]}'")
    elif cmd == "remove" and len(argv) == 2:
        removed = auth.remove_user(argv[1])
        print(f"removed '{argv[1]}'" if removed else f"no such user '{argv[1]}'")
    elif cmd == "list":
        users = auth.list_users()
        print("\n".join(users) if users else "(no users)")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
