"""Utility methods to be used in place of some Click operations"""
import functools
from typing import Any, Optional, Callable, Union, Type, NewType, TypeVar, cast

import click

_allow_prompts = False
def set_allow_prompts(value: bool):
    """Helper function to return whether prompting is allowed from the click context"""
    _allow_prompts = value


def prompt(
    text: str,
    default: Optional[Any] = None,
    hide_input: bool = False,
    confirmation_prompt: Union[bool, str] = False,
    type: Optional[click.ParamType] = None,
    value_proc: Optional[Callable[[str], Any]] = None,
    prompt_suffix: str = ": ",
    show_default: bool = True,
    err: bool = False,
    show_choices: bool = True,
) -> Any:
    if not _allow_prompts:
        raise click.ClickException(f"--no-prompts set but prompt requested: {text}")

    return click.prompt(
        text = text,
        default = default,
        hide_input = hide_input,
        confirmation_prompt = confirmation_prompt,
        type = type,
        value_proc = value_proc,
        prompt_suffix = prompt_suffix,
        show_default = show_default,
        err = err,
        show_choices = show_choices,
    )

F = TypeVar("F", bound=Callable[..., Any])
V = TypeVar("V")
def make_pass_decorator_with_constructor(object_type: Type[V], constructor: Callable[[],V]):
    """A modified make_pass_decorator which will return the object via a constructor function if not found"""
    def decorator(f: F) -> F:
        def new_func(*args, **kwargs):  # type: ignore
            ctx = click.get_current_context()

            obj = ctx.find_object(object_type)
            # Not found, then build
            if obj is None:
                obj = constructor()
            return ctx.invoke(f, obj, *args, **kwargs)

        return functools.update_wrapper(cast(F, new_func), f)

    return decorator
