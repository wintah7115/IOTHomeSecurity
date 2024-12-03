#!/bin/bash
source /home/IOTPI/Desktop/IOTHomeSecurity/tmp/.venv/bin/activate #activates python environment
cd /home/IOTPI/Desktop/IOTHomeSecurity/Scripts
pipenv run python nmap_mail_send.py aidenjblanchard@protonmail.com #runs script
