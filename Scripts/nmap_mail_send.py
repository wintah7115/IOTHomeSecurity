#!../tmp/.venv/bin/virtualenv python
import nmap_scanner
import os
import smtplib
import sys
import traceback
from datetime import datetime
from email.message import EmailMessage 
from time import sleep

# Environment variables
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
PASS = os.getenv("EMAIL_PASS")
REPORT = os.getenv("NMAP_REPORT", "nmap_report.html")

def send_nmap_report(recipient_email):
    msg = EmailMessage()
    msg['Subject'] = 'IOT HOME SECURITY NOTIFICATION - NMAP NETWORK SCAN' 
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg.set_content('NMAP Network Scan Report Attached')

    print("Running NMAP scan and generating report...")
    try:
        nmap_scanner.main()
    except Exception as e:
        error_time = datetime.now()
        error_message = (
            f"Error occurred during execution at {error_time.date()} {error_time.time()}\n"
            f"Traceback:\n{traceback.format_exc()}\n"
            f"Error: {str(e)}"
        )
        print(error_message)
        # Send error notification
        msg.set_content(f"Error in NMAP scan:\n\n{error_message}")
        
    else:
        print("Scan completed. Sending report...")
        try:
            with open(f'../Scans/{REPORT}', 'r', encoding='utf-8') as f:
                file_data = f.read()
            msg.add_alternative(file_data, subtype='html')
            
        except FileNotFoundError:
            msg.set_content("Error: Scan report file not found.")
            print(f"Report file '../Scans/{REPORT}' not found")
            return

    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, PASS)
            smtp.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap_mail_send.py recipient@email.com")
        sys.exit(1)
    
    recipient_email = sys.argv[1]
    send_nmap_report(recipient_email)