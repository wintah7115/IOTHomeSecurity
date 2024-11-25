#!../tmp/.venv/bin/virtualenv python
import net_exportscanreport
import os
import smtplib
import sys
import traceback
from datetime import datetime
from email.message import EmailMessage 
from time import sleep
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
PASS = os.getenv("EMAIL_PASS")
REPORT = os.getenv("NET_REPORT_NAME")

msg = EmailMessage()
msg['Subject'] = 'IOT HOME SECURITY NOTIFICATION - NETWORK SCAN' 
msg['From'] = EMAIL_ADDRESS
msg['To'] = sys.argv[1]
msg.set_content('test')
print("Getting report")
try:
	net_exportscanreport.main()
except Exception as e:
	print("Error occurred during execution at " + str(datetime.now().date()) + " {}".format(datetime.now().time()))
	print(traceback.format_exc())
	print(e)
print("Sending Message")
with open(f'../Scans/{REPORT}', 'r', encoding='utf-8') as f:
	file_data = f.read()
	file_name = REPORT
msg.add_alternative(file_data, subtype='html')
with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
	smtp.login(EMAIL_ADDRESS, PASS)

	smtp.send_message(msg)

