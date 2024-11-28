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
- download python & pipenv using
```bash
sudo apt-get install -y pipenv python3 pip python-is-python3 python3.11-venv
```
- Make a Virtual Enviroment
``` bashe
python -m venv ./tmp/.venv/
```
- Enter the python virtual enviroment
``` bash
source tmp/.venv/bin/activate
```
- then run
```bash
pipenv install
pip install requests
```

- modify .env file in Scripts folder with the following format:
```bash
#Nessus Access Codes
NESSUS_URL = https://{YOUR IP}:8834/
ACCESS_KEY = '{YOUR ACCESS KEY}'
SECRET_KEY = '{YOUR SECRET KEY}'
NESSUS_USERNAME = "{YOUR NESSUS USER}"
NESSUS_PASSWORD = "{YOUR NESSUS PASSWORD}"

#Scan Access
SCAN_NAME = "{NAME OF YOUR NMAP SCAN}"
USER = '{YOUR PI USERNAME}'
REPORT_NAME = '{SCAN NAME}_report.html'
NET_SCAN_NAME = "Network Scan"
NET_REPORT_NAME = 'nmap_report.html'

#Email Acces
EMAIL_ADDRESS = '{YOUR EMAIL ADDRESS}'
EMAIL_PASS = '{YOUR EMAIL API KEY}'
NMAP_TARGET = ""  # Your network range
NMAP_PORTS = '1-65535' #Ports
NMAP_ARGS = "--privileged -sS -sV -A -T4"           # Scan arguments
NMAP_REPORT = "nmap_report.html" # Report filename
```

- then run 
```bash
pipenv run python exportscanreport.py
```
