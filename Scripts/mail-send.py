
import os
import smtplib
import sys
#import imghdr
from email.message import EmailMessage 

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
PASS = os.getenv("EMAIL_PASS")
REPORT = os.getenv("REPORT_NAME")

msg = EmailMessage()
msg['Subject'] = 'IOT HOME SECURITY NOTIFICATION' 
msg['From'] = EMAIL_ADDRESS
msg['To'] = sys.argv[1]
msg.set_content('test')


with open(f'../Scans/{REPORT}', 'r', encoding='utf-8') as f:
	file_data = f.read()
	file_name = REPORT
msg.add_alternative(file_data, subtype='html')
with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
	smtp.login(EMAIL_ADDRESS, PASS)

	smtp.send_message(msg)

