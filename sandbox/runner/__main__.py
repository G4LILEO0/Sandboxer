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
    run = asyncio.ensure_future(capture.run())
    watchdog = asyncio.ensure_future(_finalise_watchdog(capture, run))
    try:
        await run
    except Exception as exc:
        (out / "runner_error.json").write_text(
            json.dumps({"error": str(exc), "traceback": traceback.format_exc()})
        )
        capture.events.emit("runner_error", "runner", error=str(exc)[:2000])
        return 1
    finally:
        watchdog.cancel()
    return 0


# Seconds the runner may spend ending the session after it is told to stop before it
# writes what it has. The orchestrator kills the container _STOP_TIMEOUT_S (45 s) after
# asking it to stop; closing the browser (video and HAR flush) needs the rest.
FINALISE_BUDGET_S = 20.0


async def _finalise_watchdog(capture: Capture, run: "asyncio.Future[object]") -> None:
    await capture.stop.wait()
    try:
        await asyncio.wait_for(asyncio.shield(run), timeout=FINALISE_BUDGET_S)
    except TimeoutError:
        capture.write_partial_result(
            f"the session did not finish ending within {FINALISE_BUDGET_S:.0f} s; "
            "result written from what was captured until then"
        )
    except Exception:  # noqa: BLE001, S110 - run() reports its own errors
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    sys.exit(asyncio.run(_main()))


if __name__ == "__main__":
    main()
