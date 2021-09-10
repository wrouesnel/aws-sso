# AWS Single Sign On Helper

This utility (`aws-sso`) makes it easy to login and switch roles amongst AWS SSO portals.

To get started ensure you have a supported Python `keyring` backend working (i.e. SecretService on
Ubuntu), Firefox and the Selenium webdriver executable installed in your path (geckodriver - download
for your platform from here https://github.com/mozilla/geckodriver/releases)

## Basic Usage

To perform initial setup, run a command like `aws-sso list profiles`. This command will prompt
you for basic configuration information. You will need to have the portal login page URL at hand.

For most usage you will never need anything more then the default.

### Using in the shell

To use the tool in your shell, or with scripts, the necessary AWS configuration can be sourced
using the `env` mode:

```bash
source <(aws-sso auth ${account_name} ${account_profile} env)
```

Note that for most AWS commands you will also need to set `AWS_REGION` and `AWS_DEFAULT_REGION`.
Be aware that the session credentials here have expiries associated.

### Usage with commands

The most common way to use the tool when working across accounts is to use the exec functionality.
This mode automatically injects the shell environment to the command and executes it. It is most
useful with the `aws` command line tool, but will work with anything else too.

```bash
aws-sso auth ${account_name} ${account_profile} exec -- aws codecommit list-repositories
```

You will still need to configure region parameters.

# Known Issues

The DBus keyring integration is not the most reliable thing. Attempting to use this system
with lots of subcommands is likely to lead to keyring access failurs which will lead to
command failures. Effort has been made to mitigate this, but it's an issue with the underlying
subsystems - try and use parallel scripts which only sequentially request credentials.
