#!../tmp/.venv/bin/virtualenv python

# Import required modules
import nmap_scanner  # Custom module for running NMAP scans
import os
import smtplib
import sys
import traceback
from datetime import datetime
from email.message import EmailMessage 
from time import sleep

# Load email configuration from environment variables
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")  # Sender's email address
PASS = os.getenv("EMAIL_PASS")              # Email account password or app-specific password
REPORT = os.getenv("NMAP_REPORT", "nmap_report.html")  # Path to NMAP report file, with default value

def send_nmap_report(recipient_email):
    """
    Send NMAP scan report via email to specified recipient.
    
    This function:
    1. Creates and configures email message
    2. Runs NMAP scan
    3. Attaches scan results
    4. Sends email using Gmail SMTP
    
    Args:
        recipient_email (str): Email address of the recipient
    """
    # Create and configure email message
    msg = EmailMessage()
    msg['Subject'] = 'IOT HOME SECURITY NOTIFICATION - NMAP NETWORK SCAN' 
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg.set_content('NMAP Network Scan Report Attached')  # Default plain text content

    print("Running NMAP scan and generating report...")
    try:
        # Run NMAP scan using imported scanner module
        nmap_scanner.main()
    except Exception as e:
        # Handle any errors during scan execution
        error_time = datetime.now()
        error_message = (
            f"Error occurred during execution at {error_time.date()} {error_time.time()}\n"
            f"Traceback:\n{traceback.format_exc()}\n"
            f"Error: {str(e)}"
        )
        print(error_message)
        # Update email content to include error details
        msg.set_content(f"Error in NMAP scan:\n\n{error_message}")
        
    else:
        # If scan successful, attach the report
        print("Scan completed. Sending report...")
        try:
            # Read and attach the HTML report
            with open(f'../Scans/{REPORT}', 'r', encoding='utf-8') as f:
                file_data = f.read()
            msg.add_alternative(file_data, subtype='html')
            
        except FileNotFoundError:
            # Handle case where report file is missing
            msg.set_content("Error: Scan report file not found.")
            print(f"Report file '../Scans/{REPORT}' not found")
            return

    # Send the email using Gmail's SMTP server
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            # Login to Gmail account
            smtp.login(EMAIL_ADDRESS, PASS)
            # Send the message
            smtp.send_message(msg)
        print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {str(e)}")

if __name__ == "__main__":
    # Verify correct command line usage
    if len(sys.argv) != 2:
        print("Usage: python nmap_mail_send.py recipient@email.com")
        sys.exit(1)
    
    # Get recipient email from command line argument
    recipient_email = sys.argv[1]
    send_nmap_report(recipient_email)