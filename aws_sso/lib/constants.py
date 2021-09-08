
import datetime
import pyrfc3339

CONFIG_FILE = ".aws-sso.yml"

TIME_ZERO = pyrfc3339.generate(datetime.datetime.fromtimestamp(0), accept_naive=True)

KEYRING_DEFAULT_USER = "__default"
KEYRING_AWS_PORTAL_DEFAULT = "aws_sso:aws_sso:portal"

KEYRING_SERVICE = "aws_sso:aws:access:{location}"
CACHED_SERVICE = "aws_sso:aws:cache"



# UUIDs for identitying the request within the app and within the service
REQUEST_ID = "request_id"
LOCAL_ID = "local_id"

# Boolean value which is set to true if an incoming request appears to come from
# another service.
INTERNAL_REQUEST = "internal_request"