# IOTHomeSecurity
Home Security System for IOT Sec
- Clone the Repo
```bash
git clone https://github.com/wintah7115/IOTHomeSecurity
cd IOTHomeSecurity
```
- download pipenv using
```bash
sudo apt-get install pipenv
```
- then run
```bash
pipenv install
```
- then run 
```bash
pipenv run python export-scan-report.py
```

- create .env file in Scripts folder with the following format:
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
