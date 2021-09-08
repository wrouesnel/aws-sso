"""AWS-SSO"""
from typing import List, Optional

import sys

from . import entrypoint

def main(argv: Optional[List[str]] = None) -> None:
    """Entrypoint for the command script."""
    # Allow overriding command line params for debugging.
    if argv is not None:
        sys.argv = argv

    entrypoint(auto_envvar_prefix="AWS_SSO")

if __name__ == "__main__":
    main()
