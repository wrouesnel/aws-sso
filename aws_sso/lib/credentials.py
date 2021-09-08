"""
Handles the grunt-work of getting the complete suite of credentials off of an AWS portal page
"""
from dataclasses import dataclass
from typing import Optional

import retrying
import selenium.webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys

import pyotp

@dataclass
class _UserPortalCredentials:
    portal: str
    user: str
    password: str
    otpsecret: Optional[str]

def get_aws_sso_credentials_from_portal(portal, user, password, otpsecret=None):
    """
    Retrieve a dictionary of AWS accounts, credentials and roles for the given portal and user
    login
    :param portal: Base URL to the porta login page
    :param user: username to login with
    :param password: login password
    :param otpsecret: OTP secret for the user is needed
    :return:
    """
    opts = Options()
    opts.headless = True
    assert opts.headless  # Operating in headless mode

    with Firefox(options=opts) as browser:
        _get_aws_sso_credentials_from_portal(browser)

def _get_aws_sso_credentials_from_portal(browser: selenium.webdriver.WebDriver, usercreds: _UserPortalCredentials):
