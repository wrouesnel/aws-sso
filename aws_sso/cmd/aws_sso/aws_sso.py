#!/usr/bin/env python3
# Wrapper script which automates interacting with AWS SSO credentials using the system
# keyring.
import dataclasses
import json
import os
import subprocess
import sys
from typing import Optional, Any

import click
import keyring
import tabulate
from structlog.threadlocal import tmp_bind

from ...lib import logging, credentials, json_util, tabulate_utils, keyring_utils
from ...lib import click_utils
from ...lib.credentials import UserPortalCredentials, get_portal
from ...lib.keyring_utils import get_or_prompt
from ...lib.portal import SSOPortal, Profile

logger = logging.get_logger()

pass_usercreds = click.make_pass_decorator(UserPortalCredentials)

def _make_sso_portal() -> SSOPortal:
    portal_creds = click.get_current_context().find_object(UserPortalCredentials)
    return get_portal(portal_creds)

"""pass_portal late-instantiates an SSO portal for subcommands from user credentials on the stack"""
pass_portal = click_utils.make_pass_decorator_with_constructor(SSOPortal, _make_sso_portal)

"""pass_profile retrieves a profile object form the stack"""
pass_profile = click.make_pass_decorator(Profile)

def _allow_prompts_callback(ctx, param, value):
    click_utils.set_allow_prompts(value)

def _debug_browser_callback(ctx, param, value):
    credentials.set_show_browser(value)

@click.group("sso")
# Default options
@click.option("--portal", "-h", show_default=True,
              default=keyring.get_password("aws_sso:portal", "__default"),
              help="SSO portal to authenticate with")
@click.option("--username", "-u", show_default=True,
              default=keyring.get_password("aws_sso:portal", keyring.get_password("aws_sso:portal", "__default")),
              help="Username to authenticate to the portal")
@click.option("--password", "-p", show_default=False, default=None, help="Password to authenticate to the portal")
@click.option("--otp", show_default=False, default=None, help="OTP token (if needed) to authenticate to the portal")
@click.option("--otp-secret", show_default=False, default=None, help="OTP secret to autogenerate a token for auth")
@click.option("--cached-token/--no-cached-token", show_default=True, default=True, help="Should the web token be force refreshed?")
# Output options
@click.option("--output-format", "-O", default=tabulate_utils.OutputFmt.Table.value, is_eager=True, expose_value=False,
              show_default=True,
              type=click_utils.EnumType(tabulate_utils.OutputFmt),
              callback=lambda ctx,param,value: tabulate_utils.set_output_format(value),
              help="Output Format")
@click.option("--table-format", "-T", default="simple", is_eager=True, expose_value=False,
              type=click.Choice(choices=tabulate.tabulate_formats, case_sensitive=False),
              callback=lambda ctx,param,value: tabulate_utils.set_table_format(value),
              help="Table format")
@click.option("--table-headers/--no-table-headers", " /-N", is_eager=True, expose_value=False,
              default=True, show_default=True,
              callback=lambda ctx,param,value: tabulate_utils.set_headers(value),
              help="Include headers in table outputs")
# Debug options
@click.option("--allow-prompts/--no-prompts", show_default=True, default=True, is_eager=True,
              callback=_allow_prompts_callback, expose_value=False,
              help="Disallow prompting for input - fail instead")
@click.option("--show-browser/--no-show-browser", show_default=True, default=False,
              callback=_debug_browser_callback, expose_value=False, is_eager=True,
              help="Unhide the selenium web browser automation window")
@click.pass_context
@logging.logging_options
def entrypoint(ctx,
               portal: Optional[str],
               username: Optional[str],
               password: Optional[str],
               otp: Optional[str],
               otp_secret: Optional[str],
               cached_token: bool,
               ):
    log = logging.get_logger()

    portal_creds = UserPortalCredentials()

    portal_creds.portal = get_or_prompt(portal, "aws_sso:portal", "__default")
    portal_creds.user = get_or_prompt(username, "aws_sso:portal", portal_creds.portal)
    portal_creds.password = get_or_prompt(password, f"aws_sso:portal:password:{portal_creds.portal}",
                                          portal_creds.user)

    if otp is not None:
        portal_creds.otp = otp
    elif otp_secret is not None:
        portal_creds.otp_secret = otp_secret
    else:
        stored_otpsecret = keyring.get_password(f"aws_sso:portal:otpsecret:{portal_creds.portal}", portal_creds.user)
        if stored_otpsecret is not None:
            portal_creds.otp_secret = stored_otpsecret

    portal_creds.force = cached_token

    ctx.obj = portal_creds

@entrypoint.group("list")
def list():
    """List objects"""
    pass

@list.command("consoles")
@pass_portal
def list_consoles(portal: SSOPortal):
    """List profile management URL links"""
    headers = ["Name", "Role", "Console Link"]
    data = []
    for appname, app in sorted(portal.appinstances.items()):
        for profile_name, profile in sorted(app.profiles.items()):
            data.append((
                app.account_name,
                profile_name,
                profile.management_console_url
            ))

    click.echo(tabulate_utils.tabulate(data, headers))

@list.command("profiles")
@pass_portal
def list_envs(portal: SSOPortal):
    """List the available environments and roles"""
    headers = ["Name", "Role", "Account Email", "Account ID"]
    data = []
    for appname, app in sorted(portal.appinstances.items()):
        for profile_name in sorted(app.profiles.keys()):
            data.append((
                app.account_name,
                profile_name,
                app.account_email,
                app.account_id,
            ))

    click.echo(tabulate_utils.tabulate(data, headers))

@entrypoint.group("auth")
@click.argument("account_name", nargs=1, type=click.STRING)
@click.argument("profile", nargs=1, type=click.STRING)
@pass_portal
@click.pass_context
def cli_credentials(ctx, portal: SSOPortal, account_name:str, profile:str):
    """Invoke AWS operations within an account as a role"""
    o = portal.appinstances[account_name].profiles[profile]
    ctx.obj = o

@cli_credentials.command("env")
@pass_profile
def credentials_env(profile: Profile):
    """Emit access credentials on stdout as shell sourceable"""
    creds = profile.env_format_credentials()
    for key, value in sorted(creds.items()):
        click.echo(f"export {key}=\"{value}\"")

@cli_credentials.command("exec")
@click.argument("cmd", nargs=-1, type=click.UNPROCESSED)
@pass_profile
def context_call(profile: Profile, cmd):
    """invoke a command with the requested AWS context"""
    env = os.environ.copy()
    env.update(profile.env_format_credentials())
    p = subprocess.Popen(cmd, env=env)
    p.wait()
    sys.exit(p.returncode)

@entrypoint.group("debug")
def debug():
    """Debugging and development commands"""

@debug.group("dump")
def debug_dump():
    """Dump the full credentials object"""

# @debug_dump.command("yaml")
# @pass_portal
# def dump_yaml(portal: SSOPortal):
#     yaml = ruamel.yaml.YAML(typ="safe")
#     yaml.default_flow_style = False
#     yaml.Representer = SafeDataclassRepresenter
#
#     click.echo(yaml.dump(portal, click.get_text_stream("stdout")))
#
# @debug_dump.command("portal-creds")
# @pass_portal
# def dump_portal_creds(portal: SSOPortal):
#     click.echo(json.dumps(portal, cls=json_util.EnhancedJSONEncoder, indent=True))
