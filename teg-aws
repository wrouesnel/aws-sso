#!/usr/bin/env python3
# Script to get TEG AWS parameters from a YAML file.
import datetime
import subprocess
import getpass
import time

import keyring
import os
import sys

import pytz
import ruamel.yaml as yaml
import click
import json
import uuid
import pprint
import shlex
import pyotp
import pyrfc3339
from collections import OrderedDict

CONFIG_FILE = ".teg-aws.yml"

TIME_ZERO = pyrfc3339.generate(datetime.datetime.fromtimestamp(0), accept_naive=True)
KEYRING_SERVICE = "teg:aws:access:{location}"
CACHED_SERVICE = "teg:aws:cache"


@click.group(context_settings={"auto_envvar_prefix": "TEG_AWS"})
@click.option("--debug/--no-debug", default=False, help="Print debugging information to stderr")
@click.option("--username", default=None, help="Logical username to use credentials from.")
@click.option("--role", default=None, help="AWS role to acquire by default")
@click.pass_context
def cli(ctx, debug, username, role):
    # Find the config file
    aws_config = None
    for p in (
        os.curdir,
        os.environ["HOME"],
        os.path.dirname(__file__),
        os.path.dirname(os.path.realpath(__file__)),
    ):
        config_path = os.path.join(p, CONFIG_FILE)
        if debug:
            sys.stderr.write("Trying to load config file from: {}\n".format(config_path))
        try:
            with open(config_path, "rt", encoding="utf8") as f:
                aws_config = yaml.safe_load(f)
        except Exception as e:
            continue

    if aws_config is None:
        raise Exception("Could not load any TEG AWS configuration map.")

    if username is None or username == "":
        raise Exception("No AWS username found in environment or given as an option.")

    if role not in set(aws_config["roles"]):
        raise Exception("AWS role not found in known roles from config file.")

    ctx.obj = {}
    ctx.obj["debug"] = debug
    ctx.obj["aws_config"] = aws_config
    ctx.obj["aws_username"] = username
    ctx.obj["role"] = role


def list_envs(ctx, param, value):
    """list the avaliable environments"""
    if not value or ctx.resilient_parsing:
        return

    for envname in ctx.obj["aws_config"]["environments"].keys():
        sys.stdout.write(
            "{} {}\n".format(envname, ctx.obj["aws_config"]["environments"][envname]["access"])
        )

    ctx.exit()


@cli.group("env")
@click.option(
    "--list",
    is_flag=True,
    callback=list_envs,
    expose_value=False,
    is_eager=True,
    help="List available environments",
)
@click.argument("environment")
@click.pass_context
def env(ctx, environment=None):
    """invoke operations within a specific AWS environment"""
    ctx.obj["environment"] = environment
    ctx.obj["keyring_service"] = KEYRING_SERVICE.format(location=environment)
    ctx.obj["env_config"] = ctx.obj["aws_config"]["environments"][environment]


@env.group("access-credentials")
@click.pass_obj
def access_credentials(obj):
    """Manipulate AWS access keys"""
    pass


@access_credentials.command("set")
@click.pass_obj
def set_access_credentials(obj):
    """set access credentials for a location"""
    envname = obj["environment"]
    sys.stdout.write("Environment: {}\n".format(envname))
    sys.stdout.write(
        "AWS Access Account: {}\n".format(obj["aws_config"]["environments"][envname]["access"])
    )
    sys.stdout.write("Setting credentials (username {})\n\n".format(obj["aws_username"]))
    aws_access_token = input("AWS Access Key ID: ").strip()
    aws_secret_key = getpass.getpass("AWS Secret Key: ").strip()
    aws_mfa_serial_number = input("AWS MFA Serial Number (leave blank if not setup): ").strip()
    aws_mfa_secret = ""
    if aws_mfa_serial_number != "":
        aws_mfa_secret = getpass.getpass("AWS MFA Secret Key for {} (leave blank if not setup): ".format(aws_mfa_serial_number)).strip()
        if aws_mfa_secret.startswith("key="):
            # Remove the key= prefix from a Keepass like secret
            aws_mfa_secret = aws_mfa_secret.split("key=")[1]
        if aws_mfa_secret == "":
            sys.stderr.write("Blank MFA secret received!\n")

    keyring.set_password(
        obj["keyring_service"],
        obj["aws_username"],
        "{}|{}|{}|{}".format(
            aws_access_token, aws_secret_key, aws_mfa_secret, aws_mfa_serial_number
        ),
    )
    sys.stdout.write(
        "SET: {} {} {}\n".format(
            obj["keyring_service"],
            obj["aws_username"],
            "(with MFA)" if aws_mfa_secret is not None else "",
        )
    )


@access_credentials.command("get")
@click.pass_obj
def get_access_credentials(obj):
    """get access credentials for a given environment"""
    stored_value = keyring.get_password(obj["keyring_service"], obj["aws_username"])

    if stored_value is None:
        raise Exception("No stored credentials for username.")

    aws_access_token, aws_secret_key, _, _ = stored_value.split("|")
    # Write the credentials in env format
    sys.stdout.write("export AWS_ACCESS_KEY_ID={}\n".format(aws_access_token))
    sys.stdout.write("export AWS_SECRET_ACCESS_KEY={}\n".format(aws_secret_key))


@access_credentials.command("mfa")
@click.pass_obj
def get_access_credentials(obj):
    """generate an MFA code"""
    stored_value = keyring.get_password(obj["keyring_service"], obj["aws_username"])

    if stored_value is None:
        raise Exception("No stored credentials for username.")

    _, _, aws_mfa_secret, aws_mfa_serial_number = stored_value.split("|")
    sys.stdout.write("{}\n".format(pyotp.TOTP(aws_mfa_secret).now()))


@env.command("list-contexts")
@click.pass_obj
def list_contexts(obj):
    """list available contexts"""
    env_config = obj["env_config"]

    for context, account in env_config["contexts"].items():
        sys.stdout.write(
            "{} {} {}\n".format(context, account, env_config["accounts"][account]["region"])
        )


@env.group("context")
@click.option("--no-roles/--roles", default=False, help="Disable roles for just this run. Useful when using Ansible.")
@click.argument("context")
@click.pass_obj
def context_details(obj, no_roles, context):
    """lookup context details"""
    env_config = obj["env_config"]

    access_account = env_config["access"]
    context_account = env_config["contexts"][context]

    access_region = env_config["accounts"][access_account]["region"]

    context_region = env_config["accounts"][context_account]["region"]
    context_account_id = env_config["accounts"][context_account]["aws_account_id"]

    role_arn = "arn:aws:iam::{}:role/{}".format(context_account_id, obj["role"])
    role_session_name = "{}-{}".format(obj["aws_username"], uuid.uuid4())

    aws_access_token, aws_secret_key, aws_mfa_secret, aws_mfa_serial_number = keyring.get_password(
        obj["keyring_service"], obj["aws_username"]
    ).split("|")

    # Add the access credentials
    override_env = {}
    override_env["AWS_ACCESS_KEY_ID"] = aws_access_token
    override_env["AWS_SECRET_ACCESS_KEY"] = aws_secret_key
    override_env["AWS_REGION"] = access_region
    override_env["AWS_DEFAULT_REGION"] = access_region

    # Try and load cached credentials
    context_credentials = None
    cached_credentials = None
    cached_str = keyring.get_password(CACHED_SERVICE, "{}|{}|{}".format(aws_access_token,context_account_id,role_arn))
    if cached_str is not None:
        cached_credentials = json.loads(cached_str)
    if cached_credentials is not None and cached_credentials != "":
        # Got cached credentials. See if they're more then 2 minutes old.
        request_time = pyrfc3339.parse(cached_credentials.get("requested_time", TIME_ZERO))
        request_delta = datetime.datetime.now(pytz.UTC) - request_time
        if request_delta.total_seconds() < 120:
            context_credentials = cached_credentials

    if context_credentials is None:
        call_env = os.environ.copy()
        call_env.pop("AWS_SESSION_TOKEN", None)
        call_env.update(override_env)

        if obj["debug"]:
            pprint.pprint(call_env, sys.stderr)

        mfa_code = pyotp.TOTP(aws_mfa_secret).now()

        if env_config.get("disable_roles",False) or no_roles:
            # Roles in this environment so get a session token
            call_args = [
                "aws",
                "--output",
                "json",
                "sts",
                "get-session-token",
                "--serial-number",
                aws_mfa_serial_number,
                "--token-code",
                mfa_code,
            ]
        else:
            call_args = [
                "aws",
                "--output",
                "json",
                "sts",
                "assume-role",
                "--role-arn",
                role_arn,
                "--role-session-name",
                role_session_name,
            ]

        output = subprocess.check_output(call_args, env=call_env)

        call_resp = json.loads(output)

        if obj["debug"]:
            pprint.pprint(call_resp, sys.stderr)

        context_credentials = {
            "account_id": "{}".format(context_account_id),
            "region": context_region,
            "aws_access_token": call_resp["Credentials"]["AccessKeyId"],
            "aws_secret_key": call_resp["Credentials"]["SecretAccessKey"],
            "aws_session_token": call_resp["Credentials"]["SessionToken"],
            "requested_time": pyrfc3339.generate(datetime.datetime.now(pytz.UTC)),
        }
        keyring.set_password(CACHED_SERVICE, aws_access_token, json.dumps(context_credentials))

    obj["context-credentials"] = context_credentials


def context_creds_to_environ(contextcreds):
    """convert context credentials to environ"""
    env = {
        "AWS_ACCOUNT_ID": contextcreds["account_id"],
        "AWS_ACCESS_KEY_ID": contextcreds["aws_access_token"],
        "AWS_SECRET_ACCESS_KEY": contextcreds["aws_secret_key"],
        "AWS_SESSION_TOKEN": contextcreds["aws_session_token"],
        "AWS_REGION": contextcreds["region"],
        "AWS_DEFAULT_REGION": contextcreds["region"],
    }
    return env


@context_details.command("account-id")
@click.pass_obj
def context_as_bash(obj):
    """print the accountid of the specified context to stdout"""
    sys.stdout.write("{}\n".format(obj["context-credentials"]["account_id"]))


@context_details.command("env")
@click.pass_obj
def context_as_bash(obj):
    """output an assumed context role as boto environment variables"""
    for key, value in context_creds_to_environ(obj["context-credentials"]).items():
        sys.stdout.write("export {}={}\n".format(key, shlex.quote(value)))


@context_details.command("call")
@click.argument("cmd", nargs=-1, type=click.UNPROCESSED)
@click.pass_obj
def context_call(obj, cmd):
    """invoke a command with the requested AWS context"""
    env = os.environ.copy()
    env.update(context_creds_to_environ(obj["context-credentials"]))
    p = subprocess.Popen(cmd, env=env)
    p.wait()
    sys.exit(p.returncode)


def main():
    cli()


if __name__ == "__main__":
    main()
