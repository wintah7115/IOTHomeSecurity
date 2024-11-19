import os
import smtplib
import sys
import imghdr
from email.message import EmailMessage 

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
PASS = os.getenv("EMAIL_PASS")
REPORT = os.getenv("REPORT_NAME")
#print(EMAIL_ADDRESS)
#print(PASS)

msg = EmailMessage()
msg['Subject'] = 'IOT HOME SECURITY NOTIFICATION' 
msg['From'] = EMAIL_ADDRESS
msg['To'] = sys.argv[1]
msg.set_content('test')

with open(f'../Scans/{REPORT}', 'rb') as f:
	file_data = f.read()
	file_type = imghdr.what(f.name)
	file_name = REPORT
msg.add_attachment(file_data, maintype='application', subtype='octet-stream', filename=file_name)

with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
	smtp.login(EMAIL_ADDRESS, PASS)

	smtp.send_message(msg)
