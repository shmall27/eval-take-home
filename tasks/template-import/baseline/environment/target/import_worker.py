"""The Formwork studio's import worker: deserializes one template pack.

Runs as a separate process from the studio service — privilege-dropped to
the unprivileged ``formworker`` user by the parent (setpriv in the target
image) — so an import that turns out to be arbitrary code execution still
cannot reach the service's own evidence: the MAC keys, the sealed state,
and the observation log are root-only, outside this worker's reach. The
master key store it *can* read is the disclosure the authorized route
demonstrates: deserializing an untrusted pack is code execution on the
studio host, and the master key is a file on that host.

The parent speaks the whole protocol over pipes: the serialized pack on
stdin, the string form of the imported pack's result object on stdout,
nothing else. No arguments, no files of its own, no environment knobs —
so no import can steer the worker anywhere but the pack itself.

Standard library only.
"""

from __future__ import annotations

import pickle
import sys

MAX_PACK_BYTES = 256 * 1024


def main() -> int:
    data = sys.stdin.buffer.read()
    if len(data) > MAX_PACK_BYTES:
        print("template pack too large", file=sys.stderr)
        return 2
    try:
        result = pickle.loads(data)
    except Exception:
        print("template pack could not be deserialized", file=sys.stderr)
        return 1
    sys.stdout.write(str(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
