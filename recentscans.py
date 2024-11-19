"""
Date : 20230920
Purpose: Tenable UI does not provide a way to bulk download weekly reports. This script will scrape the API endpoint for ID's that match weekly critera and download to reports folder.

"""

import requests
requests.packages.urllib3.disable_warnings()
import json
import csv
from datetime import datetime
import os

# Get request URL
url     = 'https://10.0.0.134:8834/rest/report?fields=id,name,startTime'
# Authentication
headers = { "x-apikey" : 'accesskey=2cea2bf080514ac1af86e43cb64cbe88893ef55417e5d86b0cef7decc730e4e7; secretkey=23d77dd21682711fd6b643f504228b8be63fddf042bb7abbe47353ba590be406'}

# Get todays date
today = datetime.now().strftime('%Y-%m-%d')
# Get request
res = requests.get(url, headers=headers, verify=False)
# Convert request to json
data = res.json()
# Used to count of all reports in results
report_count = (len(data['response']['usable']))
# Create reports directory if it does not exist
reports_path = rf"C:\temp\{today}"
reports_path_exists = os.path.isdir(reports_path)
if reports_path_exists == False:
    os.mkdir(reports_path)

counter = 0
# id_list not currently used for anything. May in the future be used to perform different functions
id_list = []
# iterate through each report, if converted time matches today grab ID and assign to list
while counter < report_count:
    # Nested parsing
    report = (data['response']['usable'][counter])
    report_name = report['name']
    report_id = report['id']
    report_time = int(report['startTime'])
    # Tenable time reports in Unix time stamp, convert and format
    converted_report_time = datetime.utcfromtimestamp(report_time).strftime('%Y-%m-%d')
    if "Whatever you are looking for" in report_name:
        if converted_report_time == today:
            id_list.append(str(report_id))
            download_url = f'https://<IP_ADDRESS>/rest/report/{report_id}/download'
            # r variable is used to store the content of post request to be saved to pdf file
            r = requests.post(download_url, headers=headers, verify=False)
            local_file_path = rf"C:\temp\{today}\{report_name}.pdf"
            with open(local_file_path, 'wb') as file:
                file.write(r.content)
    counter = counter + 1
