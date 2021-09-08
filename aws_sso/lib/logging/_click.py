"""Common Click command line integrations for logging."""
from typing import Callable, Optional, Any, Union

import logging
import click

from ..constants import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FORMAT, DEFAULT_LOG_DEST

from ._logging import _LOG_TARGETS, _LOG_FORMATS, configure_logging

_LOGGING_OPTIONS = [name.lower() for name in logging._nameToLevel.keys()]
_LOGGING_TARGETS = [name.lower() for name in _LOG_TARGETS.keys()]
_LOGGING_FORMATS = [name.lower() for name in _LOG_FORMATS.keys()]

_log_level: Optional[str] = None
_log_target: Optional[str] = None
_log_format: Optional[str] = None


def _early_logging(  # noqa: U100
    ctx: click.Context, param: Union[click.Option, click.Parameter], value: Any
) -> Any:
    """Callback which setups up logging as soon as all the logging options have been parsed."""
    global _log_level
    global _log_target
    global _log_format

    if not isinstance(value, (str,)):
        raise click.ClickException("option must be string")

    if param.name == "log_level":
        _log_level = value

    if param.name == "log_target":
        _log_target = value

    if param.name == "log_format":
        _log_format = value

    if _log_level is not None and _log_format is not None and _log_target is not None:
        # When all parameters have parsed, setup logging.
        configure_logging(_log_level, _log_format, _log_target)


def logging_options(clickFn: Callable[..., None]) -> Callable[..., None]:
    """Attach a set of common logging configuration options to a command with click."""
    clickFn = click.option(
        "--log-level",
        type=click.Choice(_LOGGING_OPTIONS, case_sensitive=False),
        default=DEFAULT_LOG_LEVEL,
        show_default=True,
        is_eager=True,
        expose_value=False,
        callback=_early_logging,
    )(clickFn)

    clickFn = click.option(
        "--log-format",
        type=click.Choice(_LOGGING_FORMATS, case_sensitive=False),
        default=DEFAULT_LOG_FORMAT,
        show_default=True,
        is_eager=True,
        expose_value=False,
        callback=_early_logging,
    )(clickFn)

    clickFn = click.option(
        "--log-target",
        type=click.Choice(_LOGGING_TARGETS, case_sensitive=False),
        default=DEFAULT_LOG_DEST,
        show_default=True,
        is_eager=True,
        expose_value=False,
        callback=_early_logging,
    )(clickFn)

    return clickFn
