# IOTHomeSecurity
Home Security System for IOT Sec on RPI 4!

# Installing Nessus
- Navigate to this link to download Nessus for your RPI (Select Linux - Ubuntu - aarch64):
``` bash
https://www.tenable.com/downloads/nessus?loginAttempted=true
```
- Due to issues with x64 support on Nessus for RPI follow this guide:
``` bash
  https://medium.com/@hunter_7574/nessus-agent-error-fix-jemalloc-unsupported-system-page-size-on-ubuntu-arm64-systems-6ae040f8eefd
```
- At the end when the guide tells you to activate the service, use this command instead:
``` bash
sudo systemctl start nessusd.service
```
- Navigate to your nessus page in the form of this ip:
``` bash
https://{YOUR RPI IP}:8834/
```
follow the prompts to create your account, feel free to set up your scans however you like at this point.
- Then navigate to your account settings in the top right corner under "my account"
- Click on API keys and Generate
- Save these for later
  
# Setting up Gmail SMTP Server
- Create a free gmail account and activate MFA
- Once done, navigate to
``` bash
https://myaccount.google.com/apppasswords
```
- Create a new app and save the code google generates for you, you will need it later.

# Setting up the Repo
- Clone the Repo
```bash
git clone https://github.com/wintah7115/IOTHomeSecurity
cd IOTHomeSecurity
```
- Enter the python virtual enviroment
``` bash
source tmp/.venv/bin/activate
```
- download pipenv using
```bash
sudo apt-get install pipenv
```

- modify .env file in Scripts folder with the following format:
```bash
NESSUS_URL = https:// **URL TO YOUR NESSUS SERVER** :8834/

ACCESS_KEY = access_key

SECRET_KEY = secret_key

NESSUS_USERNAME = Nessus_user

NESSUS_PASSWORD = Pass

SCAN_NAME = "test"

USER = IOTPI

EMAIL_ADDRESS = 'iot.homenetwork.notifications@gmail.com'

EMAIL_PASS = 'jacl pxpa konp isah'

REPORT_NAME = 'test_report.html'
```
- then run
```bash
pipenv install
```
- then run 
```bash
pipenv run python exportscanreport.py
```
