"""Standard pytest configuration."""
from typing import List, Generator, Any, Type, Dict, cast

import pytest  # type: ignore
import dictdiffer  # type: ignore
import logging
import os
import pprint
import structlog

pp = pprint.PrettyPrinter(indent=2)


def pytest_assertrepr_compare(op: str, left: Any, right: Any) -> List[str]:  # noqa: U100
    """Pytest comparison function to show dict diffs."""
    output = ["Compare Result:"]

    for line in list(dictdiffer.diff(left, right)):
        output.extend(pp.pformat(line).split("\n"))

    return output


@pytest.fixture()
def repo_root() -> str:
    """Return the real path to the root of the git repo."""
    path = os.path.realpath(os.curdir)

    while True:
        if os.path.isdir(os.path.join(path, ".git")):
            return path
        path = os.path.realpath(os.path.join(path, ".."))


@pytest.fixture()
def log() -> Generator[structlog.BoundLoggerBase, None, None]:
    """Yield a structlog without initializing one through standard means."""
    logging.basicConfig(level=logging.DEBUG)
    log = structlog.get_logger()

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.KeyValueRenderer(),
        ],
        context_class=cast(Type[Dict[str, Any]], dict),
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    yield log
