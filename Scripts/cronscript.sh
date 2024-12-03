#!/bin/bash 
source /home/IOTPI/Desktop/IOTHomeSecurity/tmp/.venv/bin/activate #activates python environment
cd /home/IOTPI/Desktop/IOTHomeSecurity/Scripts 
pipenv run python mail-send.py aidenjblanchard@protonmail.com #runs script
