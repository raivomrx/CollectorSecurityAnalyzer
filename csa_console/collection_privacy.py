"""Assessment-scoped pseudonym keys for the shared Collector privacy stage."""
import base64
from pathlib import Path
import secrets
from csa_console.canonical import path_lock
from csa_console.file_security import restrict_directory


def assessment_privacy_context(session):
    directory = Path(session.offline_public_key_path).parent
    restrict_directory(directory)
    path = directory / "assessment-privacy.key"
    with path_lock(path):
        try:
            with path.open("xb") as stream:
                stream.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Assessment privacy context is invalid")
    return {"assessmentId": session.assessment_id, "key": base64.b64encode(key).decode("ascii")}
