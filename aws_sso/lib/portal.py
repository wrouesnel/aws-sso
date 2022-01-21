import base64
import collections
import json
import time
from typing import Dict, Mapping, Optional, Any

import keyring
import requests

from . import logging, keyring_utils
from furl import furl
from .constants import AWS_PORTAL_BASEURL
from .requests_utils import BaseUrlSession

logger = logging.getLogger()

class Profile():
    def __init__(self, portal: "SSOPortal", appinstance: "AppInstance", profile):
        self._portal = portal
        self._appinstance = appinstance
        self._profile = profile

    @property
    def description(self):
        return self._profile["description"]

    @property
    def id(self):
        return self._profile["id"]

    @property
    def name(self):
        return self._profile["name"]

    @property
    def protocol(self):
        return self._profile["protocol"]

    @property
    def relayState(self):
        return self._profile["relayState"]

    @property
    def url(self):
        """Not sure what this is used for yet"""
        return self._profile["url"]

    @property
    def management_console_url(self) -> str:
        console_url = furl(self._portal.portal)
        console_url.path = None
        console_url.fragment = None
        console_url /= "/start/"
        console_url.fragment.path = "/saml/custom"
        console_url.fragment.path /= self._appinstance.fullname
        console_url.fragment.path /= base64.b64encode(f"{self._portal.user_accountid}_{self._appinstance.id}_{self.id}".encode()).decode()

        management_url = str(console_url).replace("(", "%28").replace(")", "%29").replace("=", "%3D")

        return management_url

    def credentials(self) -> Dict[str,str]:
        # Check if credentials are already cached in the keyring
        cache_key = f"aws_sso:portal:credentials:{self._portal.portal}:{self._portal.username}:{self._appinstance.account_name}"
        creds = keyring_utils.get_json_or_none(cache_key, self.name)
        if creds is not None:
            if time.time() < (creds.get("expiration") / 1000):
                logger.debug("Credentials are valid - returned cached credentials")
                return creds
            else:
                logger.debug("Credentials are expired - refreshing")
        else:
            logger.debug("Credentials not cached - refreshing")

        # Creds not present or not valid
        creds = self._portal.session().get("/federation/credentials/", params={
            "account_id": self._appinstance.account_id,
            "role_name": self.name,
            "debug": "true"
        }).json()["roleCredentials"]

        # Append more useful data to the credentials object
        creds["accountId"] = self._appinstance.account_id

        keyring.set_password(cache_key, self.name, json.dumps(creds))

        return creds

    def env_format_credentials(self) -> Dict[str,str]:
        creds = self.credentials()

        accountId = creds["accountId"]
        accessKeyId = creds["accessKeyId"]
        secretAccessKey = creds["secretAccessKey"]
        sessionToken = creds["sessionToken"]

        result_creds = {}

        aws_creds = {
            "AWS_ACCOUNT_EMAIL": self._appinstance.account_email,
            "AWS_ACCOUNT_NAME": self._appinstance.account_name,
            "AWS_ACCOUNT_ID": accountId,
            "AWS_ACCESS_KEY_ID": accessKeyId,
            "AWS_SECRET_ACCESS_KEY": secretAccessKey,
            "AWS_SESSION_TOKEN": sessionToken,
        }

        result_creds.update(aws_creds)

        mc_creds = {
            # Add mc tool credentials
            f"MC_HOST_{self._appinstance.account_name}": f"https://{accessKeyId}:{secretAccessKey}:{sessionToken}@s3.amazonaws.com",
            # Add a generic credential. This one will get overwritten by nested invocations.
            f"MC_HOST_s3": f"https://{accessKeyId}:{secretAccessKey}:{sessionToken}@s3.amazonaws.com",
        }

        result_creds.update(mc_creds)

        rclone_acctname = self._appinstance.account_name.upper().replace("-","")

        rclone_creds = {
            # Add rclone credentials
            f"RCLONE_CONFIG_{rclone_acctname}_TYPE": "s3",
            f"RCLONE_CONFIG_{rclone_acctname}_PROVIDER": "AWS",
            f"RCLONE_CONFIG_{rclone_acctname}_ACCESS_KEY_ID": accessKeyId,
            f"RCLONE_CONFIG_{rclone_acctname}_SECRET_ACCESS_KEY": secretAccessKey,
            f"RCLONE_CONFIG_{rclone_acctname}_SESSION_TOKEN": sessionToken,
        }

        result_creds.update(rclone_creds)

        rclone_general_creds = {
            "RCLONE_CONFIG_S3_TYPE": rclone_creds[f"RCLONE_CONFIG_{rclone_acctname}_TYPE"],
            "RCLONE_CONFIG_S3_PROVIDER": rclone_creds[f"RCLONE_CONFIG_{rclone_acctname}_PROVIDER"],
            "RCLONE_CONFIG_S3_ACCESS_KEY_ID": rclone_creds[f"RCLONE_CONFIG_{rclone_acctname}_ACCESS_KEY_ID"],
            "RCLONE_CONFIG_S3_SECRET_ACCESS_KEY": rclone_creds[f"RCLONE_CONFIG_{rclone_acctname}_SECRET_ACCESS_KEY"],
            "RCLONE_CONFIG_S3_SESSION_TOKEN": rclone_creds[f"RCLONE_CONFIG_{rclone_acctname}_SESSION_TOKEN"],
        }

        result_creds.update(rclone_general_creds)

        return result_creds

class Profiles(collections.Mapping):
    def __init__(self, portal: "SSOPortal", appinstance: "AppInstance"):
        self._portal = portal
        self._appinstance = appinstance
        self._profiles: Dict[str,Profile] = {}

        self._updated_time = 0
        self._cache_key = f"aws_sso:portal:appinstance:profile:{self._portal.portal}:{self._portal.username}:{self._appinstance.account_name}"

    def _get_profiles(self):
        if self._updated_time == 0:
            profiles = self._portal.session().get(f"/instance/appinstance/{self._appinstance.id}/profiles").json()["result"]
            self._updated_time = time.time()
            self._profiles = {p["name"]: Profile(self._portal, self._appinstance, p) for p in profiles}

            # Ensure cache is updated
            for profile in profiles:
                profile["_updated_time"] = self._updated_time
                keyring.set_password(self._cache_key, profile["name"], json.dumps(profile))

    def __getitem__(self, key):
        profile = keyring_utils.get_json_or_none(self._cache_key, key)
        if profile is not None:
            return Profile(self._portal, self._appinstance, profile)
        self._get_profiles()
        return self._profiles[key]

    def __len__(self):
        self._get_profiles()
        return len(self._profiles)

    def __iter__(self):
        self._get_profiles()
        return iter(self._profiles)

class AppInstance():
    def __init__(self, portal: "SSOPortal", appinstance: "AppInstance"):
        self._portal = portal
        self._appinstance = appinstance

    @property
    def applicationId(self) -> str:
        return self._appinstance["applicationId"]

    @property
    def applicationName(self) -> str:
        return self._appinstance["applicationName"]

    @property
    def description(self) -> str:
        return self._appinstance["description"]

    @property
    def icon(self) -> str:
        return self._appinstance["icon"]

    @property
    def id(self) -> str:
        return self._appinstance["id"]

    @property
    def fullname(self) -> str:
        return self._appinstance["name"]

    @property
    def account_name(self) -> str:
        return self._appinstance["searchMetadata"]["AccountName"]

    @property
    def account_id(self) -> str:
        return self._appinstance["searchMetadata"]["AccountId"]

    @property
    def account_email(self) -> str:
        return self._appinstance["searchMetadata"]["AccountEmail"]

    @property
    def profiles(self) -> Mapping[str,Profile]:
        return Profiles(self._portal, self)

class AppInstances(collections.Mapping):
    """Dictionary-like container which provides access to the app instances"""
    def __init__(self, portal):
        self._portal = portal
        self._apps_by_name: Dict[str,AppInstance] = {}
        self._updated_time = 0
        self._cache_key = f"aws_sso:portal:appinstance:{self._portal.portal}"

    def _get_appinstances(self):
        if self._updated_time == 0:
            appinstances = self._portal.session().get("/instance/appinstances").json()["result"]
            self._updated_time = time.time()
            for app in appinstances:
                returned_name = app["searchMetadata"]["AccountName"]
                stored_name = returned_name
                if stored_name in self._apps_by_name:
                    stored_name = f"{stored_name}_{app['id']}"
                    logger.warning(
                        "Name collision in account names: renamed this account",
                        returned_name=returned_name,
                        stored_name=stored_name,
                    )
                # Update keyring cache
                app["_updated_time"] = self._updated_time
                keyring.set_password(self._cache_key, stored_name, json.dumps(app))
                # Update the active dictionary
                self._apps_by_name[stored_name] = AppInstance(self._portal, app)

    def __getitem__(self, key):
        """AppInstances will opportunistically returned the cached name if it exists"""
        app = keyring_utils.get_json_or_none(self._cache_key, key)
        if app is not None:
            return AppInstance(self._portal, app)
        self._get_appinstances()
        return self._apps_by_name[key]

    def __len__(self):
        self._get_appinstances()
        return len(self._apps_by_name)

    def __iter__(self):
        # Ensure the iterator is refreshed
        self._get_appinstances()
        return iter(self._apps_by_name)

class SSOPortal():
    """Manages communicating with the SSO portal (or the keyring cache of its data)"""
    def __init__(self, portal_url, username, bearer_token, user_agent):
        self._portal_url = portal_url
        self._username = username
        self._bearer_token = bearer_token
        self._user_agent = user_agent

        # Try and decache the whoAmI data before requesting
        whoami : Optional[Dict[str,Any]] = None
        cache_data_raw = keyring.get_password(f"aws_sso:portal:authtoken:{self._portal_url}", self._username)
        cache_data = None
        if cache_data_raw is not None:
            cache_data = json.loads(cache_data_raw)
            whoami = cache_data.get("whoami")
            if whoami is not None:
                now = time.time()
                expiry = whoami.get("expireDate", 0) / 1000
                if expiry <= time.time():
                    logger.debug("Cache expired - reacquiring whoami data", now=now, expiry=expiry)
                    whoami = None
                else:
                    logger.debug("Using cached whoami data")
        else:
            logger.debug("No cached whoami data for this portal and user")

        if whoami is None:
            # Retrieve whoAmI and get the updated userIdentifier
            whoami = self.session().get("/token/whoAmI").json()
            if cache_data is not None:
                cache_data["whoami"] = whoami
                keyring.set_password(f"aws_sso:portal:authtoken:{self._portal_url}", self._username, json.dumps(cache_data))
                logger.debug("Updated whoami data in auth cache")

        self._userIdentifier = whoami["userIdentifier"]
        self._userAccountId = whoami["accountId"]

    def session(self) -> BaseUrlSession:
        """Return an authenticated session object on the portal"""
        session = BaseUrlSession(AWS_PORTAL_BASEURL)
        session.headers["x-amz-sso_bearer_token"] = self._bearer_token
        session.headers["x-amz-sso-bearer-token"] = self._bearer_token
        session.headers["User-Agent"] = self._user_agent
        return session

    @property
    def portal(self) -> str:
        return self._portal_url

    @property
    def username(self):
        return self._username

    @property
    def user_accountid(self):
        return self._userAccountId

    @property
    def useridentifier(self) -> str:
        return self._userIdentifier

    @property
    def appinstances(self) -> Mapping[str,AppInstance]:
        return AppInstances(self)
