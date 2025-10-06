import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Basic asyncio support without relying on external plugins."""

    if asyncio.iscoroutinefunction(pyfuncitem.obj):
        import inspect

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            signature = inspect.signature(pyfuncitem.obj)
            kwargs = {name: pyfuncitem.funcargs[name] for name in signature.parameters}
            loop.run_until_complete(pyfuncitem.obj(**kwargs))
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            asyncio.set_event_loop(None)
            loop.close()
        return True
    return None
