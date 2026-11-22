"""Platform-independent path policy for BAS sensor evidence and cleanup."""

from pathlib import PurePosixPath

SENSOR_TRACE_PATH = "/tmp/hecate-exec.trace"


def permitted_tmp_path(value: str) -> bool:
    """Accept canonical descendants only; Linux normalizes double-root aliases."""
    if not isinstance(value, str) or not value.startswith("/tmp/") or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        len(path.parts) > 2
        and ".." not in path.parts
        and value == str(path)
        and value != SENSOR_TRACE_PATH
    )
