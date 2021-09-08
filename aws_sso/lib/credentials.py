"""
Handles the grunt-work of getting the complete suite of credentials off of an AWS portal page
"""
import json
import operator
import time
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, Tuple

import click
import keyring
import requests
import retrying
import selenium.webdriver
import structlog
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys

import pyotp
from selenium.webdriver.remote.webelement import WebElement

from aws_sso.lib.constants import AWS_PORTAL_BASEURL
from aws_sso.lib.requests_utils import BaseUrlSession

from furl import furl

from collections import defaultdict

from . import logging
from .portal import SSOPortal

logger = logging.get_logger()

_show_browser = False
def set_show_browser(value: bool):
    _show_browser = value

@dataclass
class UserPortalCredentials:
    portal: str = field(default="")
    user: str = field(default="")
    password: str = field(default="")
    otp_secret: Optional[str] = field(default=None)
    otp: Optional[str] = field(default=None)
    force: bool = field(default=False)

def get_portal(creds: UserPortalCredentials, force:bool=False) -> SSOPortal:
    """
    Retrieve a dictionary of AWS accounts, credentials and roles for the given portal and user
    login
    :param portal: Base URL to the porta login page
    :param user: username to login with
    :param password: login password
    :param otpsecret: OTP secret for the user is needed
    :return:
    """
    bearer_token, user_agent = _get_sso_credentials(creds, force=force)

    return SSOPortal(creds.portal, creds.user, bearer_token, user_agent)

def _get_sso_credentials(creds: UserPortalCredentials, force:bool=False) -> Tuple[str,str]:
    if not force:
        # Try and decode from keyring.
        cache_data_raw = keyring.get_password(f"aws_sso:portal:authtoken:{creds.portal}", creds.user)
        if cache_data_raw is not None:
            cache_data = json.loads(cache_data_raw)
            now = time.time()
            expiry = cache_data.get("expireEpoch", 0)
            if time.time() < expiry:
                logger.debug("Cache is valid - returning cached authentication tokens")
                return cache_data["bearer_token"], cache_data["user_agent"]
            logger.debug("Cache expired - executing reauth", now=now, expiry=expiry)
        else:
            logger.debug("Cache not valid - executing portal reauth")
    else:
        logger.debug("Portal is being forced to reauth")

    opts = Options()
    opts.headless = False if _show_browser else True
    logger.debug("Starting Selenium session", headless=opts.headless)
    should_force = True if force else creds.force
    with Firefox(options=opts) as driver:
        cache_data = _get_aws_sso_credentials_from_portal(driver, creds, force)

    logger.debug("Caching credentials to system keyring")
    keyring.set_password(f"aws_sso:portal:authtoken:{creds.portal}", creds.user, json.dumps(cache_data))

    return cache_data["bearer_token"], cache_data["user_agent"]

def _get_aws_sso_credentials_from_portal(driver:WebDriver,
                                         creds: UserPortalCredentials, force:bool=False) -> Dict[str,Any]:
    """
    Function which authenticates to the SSO service and retrieves data.
    The mechanism is to use selenium to do the initial authentication, and then hand off
    the credentials to requests to fast path it.

    This function makes heavy use of sequenced callbacks to handle retries, since this is
    essentially synchronous code.

    :param browser: Selenium web-driver
    :param creds: User credentials for SSO login
    :return: AWS SSO credentials object
    """
    logger.debug("Fetching portal page")
    driver.get(creds.portal)

    @retrying.retry(wait_fixed=1000, stop_max_delay=15000,
                    retry_on_exception=lambda e: isinstance(e, NoSuchElementException))
    def get_user_input_element():
        e = driver.find_element_by_id("awsui-input-0")
        if e.is_displayed():
            return e
        raise NoSuchElementException("element present but not visible")

    logger.debug("Waiting for user input to appear")
    user_input = get_user_input_element()
    user_input.click()
    user_input.send_keys(creds.user)
    user_input.send_keys(Keys.ENTER)

    @retrying.retry(wait_fixed=1000, stop_max_delay=15000,
                    retry_on_exception=lambda e: isinstance(e, NoSuchElementException))
    def get_user_input_element():
        e = driver.find_element_by_id("awsui-input-1")
        if e.is_displayed():
            return e
        raise NoSuchElementException("element present but not visible")

    logger.debug("Waiting for password input to appear")
    password_input = get_user_input_element()
    password_input.click()
    password_input.send_keys(creds.password)
    password_input.send_keys(Keys.ENTER)

    # Should handle NO OTP case sometime, but not important now.
    @retrying.retry(wait_fixed=1000, stop_max_delay=30000,
                    retry_on_exception=lambda e: isinstance(e, NoSuchElementException))
    def get_otp_input_element():
        e = driver.find_element_by_id("awsui-input-0")
        if e.is_displayed():
            return e
        raise NoSuchElementException("element present but not visible")

    logger.debug("Waiting for OTP input to appear")
    otp_input = get_otp_input_element()
    otp_input.click()

    if creds.otp is not None:
        otp_input.send_keys(creds.otp)
    elif creds.otp_secret is not None:
        otp_input.send_keys(pyotp.TOTP(creds.otp_secret).now())

    otp_input.send_keys(Keys.ENTER)

    # Wait for the page to load so we can extract cookies and switch to requests
    @retrying.retry(wait_fixed=1000, stop_max_delay=30000,
                    retry_on_exception=lambda e: isinstance(e, NoSuchElementException))
    def is_myapps_page_loaded():
        return driver.find_element_by_tag_name("portal-application")

    logger.debug("Waiting for portal page to load")
    is_myapps_page_loaded()

    logger.debug("Getting cookies from portal page")
    cookie_str = driver.execute_script("return document.cookie")
    cookies = {}
    for kv in cookie_str.split("; "):
        name, value = kv.split("=", 1)
        cookies[name] = value
    logger.debug("Getting user agent from browser")

    user_agent = driver.execute_script("return navigator.userAgent;")
    bearer_token = cookies["x-amz-sso_authn"]

    # Recover the expected token life time from the whoami endpoint
    s = BaseUrlSession(AWS_PORTAL_BASEURL)
    s.headers["x-amz-sso_bearer_token"] = bearer_token
    s.headers["x-amz-sso-bearer-token"] = bearer_token
    s.headers["User-Agent"] = user_agent

    # AFAIK the "whoami" gives us our token lifetime. So let's commit that
    logger.debug("Requesting whoAmI")
    whoami = s.get("/token/whoAmI").json()

    # Save the lifetimes into the keyring
    cache_data = {
        "expireEpoch" : whoami["expireDate"] / 1000,
        "bearer_token":  bearer_token,
        "user_agent": user_agent,
        "whoami": whoami,
    }

    return cache_data
