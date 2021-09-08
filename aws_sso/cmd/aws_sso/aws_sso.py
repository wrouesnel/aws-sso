#!/usr/bin/env python3
# Wrapper script which automates interacting with AWS SSO credentials using the system
# keyring.

import click

import aws_sso.lib.logging as logging

@click.group(context_settings={"auto_envvar_prefix": "AWS_SSO"})
@click.option("--username", default=None, help="Logical username to use credentials from.")
@click.option("--role", default=None, help="AWS role to acquire by default")
@click.pass_context
def cli(ctx, debug, username, role):
    logger = logging.get_logger()
    logger.info("Logging initialized.")