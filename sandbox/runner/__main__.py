"""Session container entrypoint: ``python -m sandbox.runner``.

Reads the run spec from ``SANDBOX_RUN_SPEC`` and writes captures to ``SANDBOX_OUT``
(default ``/out``). SIGTERM (``docker stop``) ends the session cleanly: the browser is
closed so the HAR and video are flushed, and result.json is still written.
"""

import asyncio
import json
import logging
import os
import signal
import sys
import traceback
from pathlib import Path

from sandbox.runner.capture import Capture
from sandbox.runner.spec import RunSpec


async def _main() -> int:
    spec = RunSpec.from_json(os.environ["SANDBOX_RUN_SPEC"])
    out = Path(os.environ.get("SANDBOX_OUT", "/out"))
    out.mkdir(parents=True, exist_ok=True)
    capture = Capture(spec, out)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, capture.stop.set)
        except NotImplementedError:  # Windows, for local development only
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(capture.stop.set))
    try:
        await capture.run()
    except Exception as exc:
        (out / "runner_error.json").write_text(
            json.dumps({"error": str(exc), "traceback": traceback.format_exc()})
        )
        capture.events.emit("runner_error", "runner", error=str(exc)[:2000])
        return 1
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    sys.exit(asyncio.run(_main()))


if __name__ == "__main__":
    main()
