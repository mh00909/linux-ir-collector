from __future__ import annotations

import os
from pathlib import Path


def chown_tree_to_sudo_user(path: Path) -> bool:
    """
    If program was executed via sudo, change ownership of the output directory
    to the original user, so it can be deleted without sudo.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")

    if not sudo_uid or not sudo_gid:
        return False  # not running via sudo

    uid = int(sudo_uid)
    gid = int(sudo_gid)

    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for d in dirs:
            os.chown(os.path.join(root, d), uid, gid)
        for f in files:
            os.chown(os.path.join(root, f), uid, gid)

    return True
