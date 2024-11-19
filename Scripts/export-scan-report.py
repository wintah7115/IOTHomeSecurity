import os
from time import sleep
from http import HTTPStatus

import requests
import urllib3

urllib3.disable_warnings()


# Nessus API configuration
NESSUS_URL = os.getenv("NESSUS_URL")
ACCESS_KEY = os.getenv("ACCESS_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
NESSUS_USER = os.getenv("NESSUS_USERNAME")
NESSUS_PASS = os.getenv("NESSUS_PASSWORD")
SCAN_NAME = os.getenv("SCAN_NAME", "test")
USER = os.getenv("USER")
# get Nessus API token
def get_nessus_token():
    url = f"{NESSUS_URL}/session"
    data = {"username": NESSUS_USER, "password": NESSUS_PASS}
    response = requests.post(url, json=data, verify=False)
#    print(NESSUS_USER)
 #   print(NESSUS_PASS)
  #  print(response.json())
    token = response.json()["token"]
    return token

# get scan ID by name
def get_scan_id_by_name(token, scan_name):
    url = f"{NESSUS_URL}/scans/"
    headers = {"X-Cookie": f"token={token}"}
    response = requests.get(url, headers=headers, verify=False)
    scans = response.json()["scans"]

    for scan in scans:
        if scan["name"] == scan_name:
            return scan["id"]

    return None

# export scan report
def export_scan_report(token, scan_id, format):
    url = f"{NESSUS_URL}/scans/{scan_id}/export?limit=2500"
    headers = {"X-Cookie": f"token={token}"}
   # print(format)
    data = {"format": format, "template_id": 36}
    response = requests.post(url, headers=headers, json=data, verify=False)
   # print("export_scan_report",response.json())
    return response.json()

# Check the file status of an exported scan
def is_exported_file_ready(token, scan_id, file_id):
    url = f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status"
    headers = {"X-Cookie": f"token={token}"}
    response = requests.get(url, headers=headers, verify=False)
   # print(response.json())
   # print("scan_id=", scan_id)
   # print("file_id=", file_id)
    if response.status_code == HTTPStatus.OK and response.json()["status"] == "ready":
        return True

# download the exported report
def download_report(token, scan_id, file_id, file_name):
    url = f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download"
    headers = {"X-Cookie": f"token={token}"}
    response = requests.get(url, headers=headers, verify=False)
    
    with open(f"/home/{USER}/Desktop/{file_name}", "wb") as f:
        f.write(response.content)

# Main script
def main():
    # Get Nessus API token
    token = get_nessus_token()

    if token:
        # Get scan ID by name
        scan_id = get_scan_id_by_name(token, SCAN_NAME)
    #    print("scan_id", scan_id)

        if scan_id:
            # Export scan report in PDF format
            export_result = export_scan_report(token, scan_id, format="html")

            if "file" in export_result:
                file_id = export_result["file"]
     #           print(export_result["file"])
                #sleep(10)
                #check if the file is ready, if not wait
                while True:
      #              print(is_exported_file_ready(token, scan_id, file_id))
                    if is_exported_file_ready(token, scan_id, file_id): 
                       break
                    sleep(3)

       #         print("file_id", file_id)
                file_name = f"{SCAN_NAME}_report.html"
                # Download the exported report
                download_report(token, scan_id, file_id, file_name)
                print(f"Report downloaded successfully: {file_name}")
            else:
                print("Failed to export scan report.")
        else:
            print(f"Scan with name '{SCAN_NAME}' not found.")
    else:
        print("Failed to obtain Nessus API token.")

if __name__ == "__main__":
    main()
