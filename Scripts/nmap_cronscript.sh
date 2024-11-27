#!/bin/bash
source /home/IOTPI/Desktop/IOTHomeSecurity/tmp/.venv/bin/activate
cd /home/IOTPI/Desktop/IOTHomeSecurity/Scripts
pipenv run python nmap_mail_send.py aidenjblanchard@protonmail.com
