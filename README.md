# MFade
A python port of [@dafthack](https://github.com/dafthack)'s MFAsweep with some added OPSEC functionality. MFAde can be used to find single-factor authentication failure points in Mircrosoft Services. This port is also cross platform due to the Python codebase and the removal of the modified and encoded EWS DLL that is included in the original MFASweep Powershell script.

The tool will attempt to log in to several Microsoft service endpoints with the given credentials and will return a table showing which endpoints are misconfigured to allow single-factor authentication. 

![example_results](https://user-images.githubusercontent.com/28678856/210753256-923c6f33-570f-41e1-92a1-3470e9286056.png)

Just like MFASweep, this port can currently authenticate to:

- Microsoft Graph API
- Azure Service Management API
- Microsoft 365 Exchange Web Services
- Microsoft 365 Web Portal w/ 6 device types (Windows, Linux, MacOS, Android Phone, iPhone, Windows Phone)
- Microsoft 365 Active Sync
- ADFS

## Usage

```
$ python3 MFade.py -h
usage: MFade.py [-h] [--username USERNAME] [--password PASSWORD] [--recon] [--adfs] [--sleep SLEEP] [--jitter JITTER] [--ioc] [--exclude EXCLUDE]

A tool to find failure points in Microsoft Multi Factor Authentication configurations from an attacker's perspective but with some extra OPSEC
features.

options:
  -h, --help            show this help message and exit
  --username USERNAME, -u USERNAME
                        target email address (e.g e.alderson@evilcorp.com)
  --password PASSWORD, -p PASSWORD
                        target's password
  --recon, -r           script will attempt to locate ADFS configurations
  --adfs                script will attempt to login to ADFS in addition to the other Microsoft protocols
  --sleep SLEEP, -s SLEEP
                        OPSEC: how long to sleep between authentication attempts (in seconds)
  --jitter JITTER, -j JITTER
                        OPSEC: percentage change added to sleep value for further sleep randomisation (0-100)
  --ioc                 OPSEC: Print a report with the generated HTTP request times and their corresponding target URLs
  --exclude EXCLUDE, -e EXCLUDE
                        OPSEC: Exclude given checks. Provide the checks to exclude as a comma-separated list. Possible values are:
                        gapi,asm,ews,as,mwp-W,mwp-L,mwp-M,mwp-A,mwp-I,mwp-wp. Check the source code for mappings

This program is made for use in authorised environments. Please do not use it for evil.
```

### Examples:

Example: Checking for ADFS

`python3 MFade.py -u <email> -p <password> --adfs --recon`

Example: Using sleeps and jitter to throttle the authentication attempts

`python3 MFade.py -u <email> -p <password> --sleep 40 --jitter 10`

Example: Retrieve a mapping of URLs requested and the time and dates of their corresponding HTTP requests for reporting purposes.

`python3 MFade.py -u <email> -p <password> --ioc`

Example: Exclude some checks such as Graph API and EWS.

`python3 MFade.py -u <email> -p <password> --exclude gapi,ews`

## References:
- [Original PSH MFASweep - @dafthack's github](https://github.com/dafthack/MFASweep)
- [Exploiting MFA Inconsistencies on Microsoft Services - Blachills Infosec Blog](https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/)
