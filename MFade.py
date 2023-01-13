import argparse
import sys
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import time
import re
import json
from exchangelib import Account, Credentials
import base64
import random


"""
Author: kreep
Twitter: @kreepsec
License: MIT
"""

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
    epilog = "This program is made for use in authorised environments. Please do not use it for evil."
    )
parser.add_argument('--username', '-u', help='target email address (e.g e.alderson@evilcorp.com)')
parser.add_argument('--password', '-p', help='target\'s password')
parser.add_argument('--recon', '-r', action="store_true", help='script will attempt to locate ADFS configurations')
parser.add_argument('--adfs', action="store_true", help='script will attempt to login to ADFS in addition to the other Microsoft protocols')
parser.add_argument('--sleep', '-s', type=int, help='OPSEC: how long to sleep between authentication attempts (in seconds)')
parser.add_argument('--jitter', '-j', type=int, help='OPSEC: percentage change added to sleep value for further sleep randomisation (0-100)')
parser.add_argument('--ioc', action="store_true", help='OPSEC: Print a report with the generated HTTP request times and their corresponding target URLs')
parser.add_argument('--exclude','-e', help="OPSEC: Exclude given checks. Provide the checks to exclude as a comma-separated list. Possible values are: gapi,asm,ews,as,mwp-W,mwp-L,mwp-M,mwp-A,mwp-I,mwp-wp. Check the source code for mappings")

args = parser.parse_args()
if len(sys.argv) < 2:
    parser.print_usage()
    sys.exit(1)

# helper class for colour printing
class pp:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def warning(words):
        print('\033[93m' + '[+] ' + '\033[0m' + words)
    def success(words):
        print('\033[92m' + '[*] ' + '\033[0m' + words)
    def error(words):
        print('\033[91m' + '[-] ' + '\033[0m' + words)
    def info(words):
        print('\033[96m' + '[i] ' + '\033[0m' + words)
    def green(words):
        return '\033[92m' + words + '\033[0m'

# Class to hold IOCs - just http authentication requests for now.
class Iocs:
    def __init__(self):
        self.auth_requests = []

    def add_to_list(self, item):
        self.auth_requests.append(item)

iocs_instance = Iocs()

#  ======  Functionality starts here ======
# Print the list of checks that will be done
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

# Find ADFS configuration
def reconADFS(username):
    adfs_check = requests.get("https://login.microsoftonline.com/getuserrealm.srf", params={"login": username, "xml": "1"})
    if args.ioc:
        req = (adfs_check.url,adfs_check.headers.get('date'))
        iocs_instance.add_to_list(req)
    adfsxml = ET.fromstring(adfs_check.content)
    try:
        root_adfs_url = urlparse(adfsxml.find('AuthURL').text)
        adfs_domain = root_adfs_url.netloc
        if adfsxml.find('NameSpaceType').text == "Federated":
            return root_adfs_url,adfs_domain
        elif adfsxml.find('NameSpaceType').text == "Managed":
            pp.warning("ADFS does not appear to be in use. Authentication appears to be managed by Microsoft.")
            return root_adfs_url,adfs_domain
        elif adfsxml.find('NameSpaceType').text == "Unknown":
            pp.warning("The target email is not linked to Microsoft Online or O365. Authentication will most likely fail.")
            return root_adfs_url,adfs_domain
        return False,False
    except:
        return False, False

#TODO: requires testing - do not have access to a ADFS account right now.
# Authenticate via ADFS
def authADFS(username, password):
    pp.info("Logging into ADFS")
    root_adfs_url,adfs_domain = reconADFS(username)
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
        full_adfs_url = "https://" + adfs_domain + adfsauthpath
        adfs_auth_attempt = adfs_session.post(full_adfs_url, data=userform.fields)

        if "MSISAUTH" in [cookie.name for cookie in adfs_session.cookies]:
            pp.success("Success! We can authenticate to ADFS.")
            pp.warning("NOTE: This part may open a browser. If closed immediately it may prevent an SMS/call to the user.")
            for i in range(5, 0, -1):
                pp.warning("Sending Auth Request in {}...\r".format(i), end="")
                time.sleep(1)

            adfs_srf_auth = adfs_session.post("https://login.microsoftonline.com/login.srf", data=adfs_auth_attempt.forms[0].fields, allow_redirects=False)
            if "Stay signed in" in adfs_srf_auth.text:
                pp.success("There is no MFA for this account.")
                pp.success(f"Login with a web browser to {full_adfs_url}")
                for cookie in adfs_session.cookies:
                    print("{} = {}".format(cookie.name, cookie.value))
            elif adfs_srf_auth.status_code == 302:
                if "device.login.microsoftonline.com" in adfs_srf_auth.headers["Location"]:
                    pp.warning("Redirected after login. MFA is in place to SMS or Call the user.")
                elif "Verify your identity" in adfs_srf_auth.text:
                    pp.warning("MFA is configured.")
            if args.ioc:
                for h in adfs_session:
                    print(h.url)
                    print(h.headers.get('date'))
                    req = (h.url,h.headers.get('date'))
                    iocs_instance.add_to_list(req)
            return True
        else:
            pp.error("Login failed.")
            return False

    except Exception as e:
        pp.error("ADFS authentication failed in an unexpected way. Aborting ADFS check.")
        # print(e)
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

    final_url = url + "/common/oauth2/token" 
    response = requests.post(final_url, data=body_params, headers=headers)
    if args.ioc:
        req = (response.url,response.headers.get('date'))
        iocs_instance.add_to_list(req)
    
    if response.status_code == 200:
        pp.success(f"Success! {username} is able to authenticate to the Microsoft Graph API")
        pp.success("The MSOnline PowerShell module can be used to leverage this.")
        return True

    else:
        # Standard invalid password
        if "AADSTS50126" in response.text:
            pp.error(" Login appears to have failed.")
        # Invalid Tenant Response
        elif "AADSTS50128" in response.text or "AADSTS50059" in response.text:
            pp.error("  Tenant for account {} doesn't exist. Check the domain to make sure they are using Azure/O365 services.".format(username))
        # Invalid Username
        elif "AADSTS50034" in response.text:
            pp.error("  The user {} doesn't exist.".format(username))
        # Microsoft MFA response
        elif "AADSTS50079" in response.text or "AADSTS50076" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates MFA (Microsoft) is in use.".format(username))
        # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
        elif "AADSTS50158" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.".format(username))
        # Locked out account or Smart Lockout in place
        elif "AADSTS50053" in response.text:
            pp.error("  The account {} appears to be locked.".format(username))
        # Disabled account
        elif "AADSTS50057" in response.text:
            pp.error("  The account {} appears to be disabled.".format(username))
        # User password is expired
        elif "AADSTS50055" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The user's password is expired.".format(username))
        # Unknown errors
        else:
            pp.error(" We received an unknown error for the user: {}".format(username))
            # print(response.text)
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

    final_url = url + "/Common/oauth2/token" 
    response = requests.post(final_url, data=body_params, headers=headers)
    if args.ioc:
        req = (response.url,response.headers.get('date'))
        iocs_instance.add_to_list(req)

    if response.status_code == 200:
        pp.success(f"Success! {username} is able to authenticate to the Microsoft Service Management API")
        pp.success("The Az PowerShell module can be used to leverage this.")
        return True

    else:
        # Standard invalid password
        if "AADSTS50126" in response.text:
            pp.error(" Login appears to have failed.")
        # Invalid Tenant Response
        elif "AADSTS50128" in response.text or "AADSTS50059" in response.text:
            pp.error("  Tenant for account {} doesn't exist. Check the domain to make sure they are using Azure/O365 services.".format(username))
        # Invalid Username
        elif "AADSTS50034" in response.text:
            pp.error("  The user {} doesn't exist.".format(username))
        # Microsoft MFA response
        elif "AADSTS50079" in response.text or "AADSTS50076" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates MFA (Microsoft) is in use.".format(username))
        # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
        elif "AADSTS50158" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.".format(username))
        # Locked out account or Smart Lockout in place
        elif "AADSTS50053" in response.text:
            pp.error("  The account {} appears to be locked.".format(username))
        # Disabled account
        elif "AADSTS50057" in response.text:
            pp.error("  The account {} appears to be disabled.".format(username))
        # User password is expired
        elif "AADSTS50055" in response.text:
            pp.error(" SUCCESS! {} was able to authenticate to the Microsoft Graph API - NOTE: The user's password is expired.".format(username))
        # Unknown errors
        else:
            pp.error(" We received an unknown error for the user: {}".format(username))
            # print(response.text)
        return False

def authWP(device, username, password, user_agent):
    pp.info(f"=== Logging into Microsoft Web Portal with {device} User Agent ===")
    o365 = requests.Session()
    headers = {"User-Agent": user_agent}
    response = o365.get('https://outlook.office365.com', headers=headers)
    if args.ioc:
        req = (response.url,response.headers.get('date'))
        iocs_instance.add_to_list(req)
    partialctx_pattern = re.compile(r'urlLogin":".*?"')
    partialctx = partialctx_pattern.findall(response.text)

    ctx_pattern = re.compile(r'ctx=.*?"')
    ctx = ctx_pattern.findall(partialctx[0])[0].replace('ctx=', '').replace('"', '')

    sft_pattern = re.compile(r'sFT":".*?"')
    sft = sft_pattern.findall(response.text)[0].replace('sFT":"', '').replace('"', '')

    userform = {
    "username": username,
    "isOtherIdpSupported": "false",
    "checkPhones": "false",
    "isRemoteNGCSupported": "true",
    "isCookieBannerShown": "false",
    "isFidoSupported": "true",
    "originalRequest": ctx,
    "country": "US", 
    "forceotclogin": "false",
    "isExternalFederationDisallowed": "false",
    "isRemoteConnectSupported": "false",
    "federationFlags": "0",
    "isSignup": "false",
    "flowToken": sft,
    "isAccessPassSupported": "true"
    }

    json_form = json.dumps(userform)
    url = "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
    response = o365.post(url, headers=headers, json=json_form)
    if args.ioc:
        req = (response.url,response.headers.get('date'))
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
    "ctx": ctx,
    "hpgrequestid": "",
    "flowToken": sft,
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

    if args.ioc:
        req = (response.url,response.headers.get('date'))
        iocs_instance.add_to_list(req)

    if "ESTSAUTH" in [cookie.name for cookie in o365.cookies]:
        pp.success(f"SUCCESS! {username} was able to authenticate to the Microsoft 365 Web Portal. Checking MFA now...")
        if "Stay signed in" in response.text:
            pp.success("It appears there is no MFA for this account.")
            pp.success(f"Login with a {device}-based web browser to https://outlook.office365.com. Ex: {user_agent}")
            return True
        elif "Verify your identity" in response.text:
            pp.error("MFA for Microsoft 365 via the web portal is enabled.")
            return False

    pp.error("Login failed.")
    return False

def authEWS(username, password):
    print("=== Logging into Exchange Web Services ===")
    credentials = Credentials(username=username, password=password)
    try:
        account = Account(primary_smtp_address=username, credentials=credentials,autodiscover=True)
        # Retrieve subject line of latest email to verify. Will have to find a better way in the future but this works for now.
        # This will throw an exception if the credentials are invalid.
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
            req = (easlogin.url,easlogin.headers.get('date'))
            iocs_instance.add_to_list(req)
        if easlogin.status_code == 505:
            pp.success(f"SUCCESS! {username} successfully authenticated to O365 ActiveSync.")
            pp.success(f"The Windows 10 Mail app can connect to ActiveSync. See https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/")
            return True
    except Exception as e:
        # print(e)
        pass
    pp.error("Login failed to Microsoft Active Sync")
    return False

def jittered_sleep(stime,jitter=1):
    if args.sleep or args.jitter:
        jitter_range = stime * jitter / 100
        stime += random.uniform(-jitter_range, jitter_range)
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
    
    # pp.success("Starting MFA black magic...")
    ascii_art = """
___  _________        _      
|  \/  ||  ___|      | |     
| .  . || |_ __ _  __| | ___ 
| |\/| ||  _/ _` |/ _` |/ _ \\
| |  | || || (_| | (_| |  __/
\_|  |_/\_| \__,_|\__,_|\___|
                             
    """
    print(ascii_art)
    print("\n")
    if args.exclude:
        showChecks(args.exclude)
    if args.recon:
        print("\n")
        pp.info(" === Locating ADFS configuration ===")
        root_adfs_url,adfs_domain = reconADFS(args.username)
        if adfs_domain:
            pp.success(f"ADFS is present in the target domain. The authentication url is:\n {root_adfs_url.geturl()}")
            print("\n")
        else:
            pp.error("ADFS is not present in the target domain.")
            print("\n")
    if args.adfs:
        adfs_login_success = authADFS(args.username, args.password)
        jittered_sleep(args.sleep,args.jitter)
    print("########## MICROSOFT API CHECKS ##########")
    if not args.exclude or 'gapi' not in args.exclude.split(','):
        gapi_success = authGAPI(args.username, args.password)
        jittered_sleep(args.sleep,args.jitter)
    if not args.exclude or 'asm' not in args.exclude.split(','):
        asm_success = authASM(args.username, args.password)
        jittered_sleep(args.sleep,args.jitter)
    print("\n")
    print("########## MICROSOFT WEB PORTAL CHECKS ##########")
    if not args.exclude or 'mwp-W' not in args.exclude.split(','):
        mwpw_success = authWP('Windows', args.username, args.password, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56')
        jittered_sleep(args.sleep,args.jitter)
    if not args.exclude or 'mwp-L' not in args.exclude.split(','):
        mwpl_success = authWP('Linux', args.username, args.password, 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0')
        jittered_sleep(args.sleep,args.jitter)    
    if not args.exclude or 'mwp-M' not in args.exclude.split(','):
        mwpm_success = authWP('Mac OS', args.username, args.password, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15')
        jittered_sleep(args.sleep,args.jitter)
    if not args.exclude or 'mwp-A' not in args.exclude.split(','):
        mwpa_success = authWP('Android', args.username, args.password, 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Mobile Safari/537.36')
        jittered_sleep(args.sleep,args.jitter)    
    if not args.exclude or 'mwp-I' not in args.exclude.split(','):
        mwpi_success = authWP('iPhone', args.username, args.password, '"Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1')
        jittered_sleep(args.sleep,args.jitter)
    if not args.exclude or 'mwp-wp' not in args.exclude.split(','):
        mwpwp_success = authWP('Windows Phone', args.username, args.password, 'Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 635) like iPhone OS 7_0_3 Mac OS X AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537')
        jittered_sleep(args.sleep,args.jitter)
    print("\n")
    print("########## LEGACY AUTH CHECKS ##########")
    if not args.exclude or 'ews' not in args.exclude.split(','):
        ews_success = authEWS(args.username,args.password)
        jittered_sleep(args.sleep,args.jitter)
    if not args.exclude or 'as' not in args.exclude.split(','):
        as_success = authAS(args.username, args.password)

    # Printing results
    print("\n")
    pp.info("=== SINGLE FACTOR ACCESS RESULTS: ===")
    gapi_result = pp.green("YES") if gapi_success else "NO"
    asm_result = pp.green("YES") if asm_success else "NO"
    mwpw_result = pp.green("YES") if mwpw_success else "NO"
    mwpl_result = pp.green("YES") if mwpl_success else "NO"
    mwpm_result = pp.green("YES") if mwpm_success else "NO"
    mwpa_result = pp.green("YES") if mwpa_success else "NO"
    mwpi_result = pp.green("YES") if mwpi_success else "NO"
    mwpwp_result = pp.green("YES") if mwpwp_success else "NO"
    ews_result = pp.green("YES") if ews_success else "NO"
    adfs_result = pp.green("YES") if adfs_domain else "NO"
    adfs_login_result = pp.green("YES") if adfs_login_success else "NO"
    as_result = pp.green("YES") if as_success else "NO"
    
    results = f"""
    Microsoft Graph API\t\t\t\t\t{gapi_result}
    Microsoft Service Management API\t\t\t{asm_result}
    Microsoft 365 Web Portal w/ Windows User Agent\t{mwpw_result}
    Microsoft 365 Web Portal w/ Linux User Agent\t{mwpl_result}
    Microsoft 365 Web Portal w/ Mac OS User Agent\t{mwpm_result}
    Microsoft 365 Web Portal w/ Android User Agent\t{mwpa_result}
    Microsoft 365 Web Portal w/ iPhone User Agent\t{mwpi_result}
    Microsoft 365 Web Portal w/ Win Phone User Agent\t{mwpwp_result}
    Exchange Web Services\t\t\t\t{ews_result}
    Active Sync\t\t\t\t\t\t{as_result}
    ADFS found\t\t\t\t\t\t{adfs_result}
    ADFS Auth\t\t\t\t\t\t{adfs_login_result}
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


