
import datetime
import pyrfc3339

CONFIG_FILE = ".aws-sso.yml"

TIME_ZERO = pyrfc3339.generate(datetime.datetime.fromtimestamp(0), accept_naive=True)

KEYRING_DEFAULT_USER = "__default"
KEYRING_AWS_PORTAL_DEFAULT = "aws_sso:aws_sso:portal"

KEYRING_SERVICE = "aws_sso:aws:access:{location}"
CACHED_SERVICE = "aws_sso:aws:cache"

DEFAULT_LOG_LEVEL = "warning"
DEFAULT_LOG_FORMAT = "console"
DEFAULT_LOG_DEST = "stderr"

AWS_PORTAL_BASEURL = "https://portal.sso.us-east-1.amazonaws.com"

KEYRING_LOCK_NAME = "aws-sso-keyring-access"

# This environment variable is used as the PATH to restore instead of whatever aws-sso was launched
# with. This is mostly useful when using wrapper scripts to launch aws-sso from virtualenv.
ENV_AWS_SSO_EXEC_PATH = "AWS_SSO_EXEC_PATH"
