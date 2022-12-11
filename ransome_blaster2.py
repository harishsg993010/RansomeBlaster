import os
import time
import win32con
import win32api
import win32security
import win32com.client
import json
import argparse
import requests
import sys
import win32file
import win32evtlogutil
import win32security
import win32evtlog
import win32process
import threading
import slack
import urllib3

# Set the path to the JSON file with the list of IPs to block
JSON_FILE_PATH = 'ips.json'

root_dir = 'C:\\'
# Set the names of the programs to block
PROGRAMS_TO_BLOCK = ['reg.exe', 'cmd.exe', 'powershell.exe', 'certutil.exe', 'schtasks.exe',
                     'mshta.exe', 'InstallUtil.exe', 'AppInstaller.exe', 'bash.exe', 'wsl.exe',
                     'certoc.exe', 'bitsadmin.exe', 'certreq.exe', 'Cmstp.exe', 'Csc.exe',
                     'Cscript.exe', 'CustomShellHost.exe', 'Dnscmd.exe', 'finger.exe',
                     'msdt.exe', 'regsvr32.exe', 'wsl.exe']

# Set the directories to scan for recently downloaded files
DIRECTORIES_TO_SCAN = [os.getcwd(), os.path.join(os.environ['HOMEPATH'], 'Downloads')]

# Set the flag that indicates a recently downloaded file
RECENTLY_DOWNLOADED_FLAG = 'MOTW'

# Set the extensions of the files to delete
FILE_EXTENSIONS_TO_DELETE = ['.dll', '.exe','.js','.py','.cpp','.lnk','.app']

# Set the path to the lsass.exe process
LSASS_PROCESS_PATH = 'C:\\Windows\\System32\\lsass.exe'

# Set the path to the Windows notification service
NOTIFICATION_SERVICE_PATH = 'Windows.UI.Notifications.Management'

JSON_FILE_URL = 'https://raw.githubusercontent.com/harishsg993010/Malicious_Ips/main/ips.json'

# Set the interval for checking for updates (in seconds)
CHECK_INTERVAL = 60

# Set the list of blocked IPs
blocked_ips = []

SCAN_INTERVAL = 60 

def send_slack_message(message):
    # Check if the slack_enabled environmental variable is set to True
    if os.environ.get('slack_enabled') == 'True':
        # Get the Slack API key from the slack_api_key environmental variable
        slack_api_key = os.environ.get('slack_api_key')

        # Connect to the Slack API
        client = slack.WebClient(token=slack_api_key)

        # Send the message to Slack
        client.chat_postMessage(channel="#general", text=message)

def send_teams_message(message):
    # Check if the MSTeams_enabled environmental variable is set to True
    if os.environ.get('MSTeams_enabled') == 'True':
        # Get the Teams API key, channel, and channel ID from the environmental variables
        teams_api_key = os.environ.get('team_api_key')
        teams_channel = os.environ.get('team_channel')
        teams_channel_id = os.environ.get('team_channel_id')

        # Set the request headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {teams_api_key}"
        }

        # Set the request payload
        payload = {
            "body": {
                "contentType": "html",
                "content": message
            },
            "to": teams_channel_id
        }

        # Send the message to Microsoft Teams
        requests.post(f"https://outlook.office.com/webhook/{teams_channel}", headers=headers, json=payload)


def check_for_updates():
    """Continuously check for updates to the list of IPs on GitHub"""
    while True:
        # Download the JSON file
        with urllib3.request.urlopen(JSON_FILE_URL) as response:
            ips = json.loads(response.read())

        # Check if any new IPs have been added to the list
        new_ips = [ip for ip in ips if ip not in blocked_ips]

        # Block the new IPs
        for ip in new_ips:
            os.system(f'netsh advfirewall firewall add rule name="Block IP {ip}" dir=in remoteip={ip} action=block')
            print(f'Blocked IP: {ip}')
            blocked_ips.remove(ip)

def delete_recently_downloaded_files():
    """Continuously scan for DLL and executable files that were recently downloaded and delete them"""
    while True:
        # Scan each directory for recently downloaded files
        for directory in DIRECTORIES_TO_SCAN:
            # Get a list of files in the directory
            files = os.listdir(directory)

            # Delete each file with the correct extension and flag
            for file in files:
                if file.endswith(FILE_EXTENSIONS_TO_DELETE) and win32api.GetFileAttributes(file) & win32con.FILE_ATTRIBUTE_HIDDEN:
                    os.remove(file)
                    print(f'Deleted file: {file}')

                    # Notify the user via the Windows notification service
                    toast = win32com.client.Dispatch("ToastNotificationManager")
                    toast.CreateToastNotifier("File Deletion").Show(win32com.client.Dispatch("ToastNotification",
                                                                                            title="File Deletion",
                                                                                            text=f"Deleted file: {file}"))
                    send_slack_message(f"Deleted file: {file}")

        time.sleep(SCAN_INTERVAL)

def delete_recently_downloaded_files(root_dir):
    while True:
    # Get the value of the "whitelistfiles" environmental variable
        whitelist_files_env_var_value = os.environ.get('WHITELIST_FILES_ENV_VAR')
    # Split the environmental variable value by ";" to get the individual
    # filenames that should not be deleted
        whitelist_filenames = whitelist_files_env_var_value.split(";")

    # Walk the directory tree rooted at "root_dir"
        for root, dirs, files in os.walk(root_dir):
        # Iterate over all files in the current directory
            for filename in files:
            # Check if the file has one of the specified extensions
            # and if it is not in the whitelist
                if (filename.endswith(".exe") or filename.endswith(".dll") or
                filename.endswith(".pdf") or filename.endswith(".doc") or
                filename.endswith(".docx") or filename.endswith(".xls") or
                filename.endswith(".xlsx")) and filename not in whitelist_filenames:
                # Build the full path to the file
                    file_path = os.path.join(root, filename)
                # Check if the file has the "MOTW" flag
                    if has_motw_flag(file_path):
                    # Delete the file
                        os.remove(file_path)

                    send_slack_message(f"Deleted file: {file_path}")
                    toast = win32com.client.Dispatch("ToastNotificationManager")
                    toast.CreateToastNotifier("File Deletion").Show(win32com.client.Dispatch("ToastNotification",
                                                                                            title="File Deletion",
                                                                                            text=f"Deleted file: {file_path}"))
        time.sleep(SCAN_INTERVAL)

def has_motw_flag(file_path):
    # Get the security descriptor of the file
    sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
    # Get the discretionary access control list (DACL) from the security descriptor
    dacl = sd.GetSecurityDescriptorDacl()
    # Iterate over the access control entries (ACEs) in the DACL
    for i in range(dacl.GetAceCount()):
        # Get the ACE at the current index
        ace = dacl.GetAce(i)
        # Check if the ACE has the "MOTW" flag
        if ace[2] & win32con.PROTECTED_DACL_SECURITY_INFORMATION:
            return True
    return False

def block_programs():
    # Get the current process token
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    # Get the current user's privileges
    privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
    # Check if the current user has the SE_SECURITY_NAME privilege
    has_security_privilege = False
    for privilege in privileges:
        if privilege[0] == win32security.LookupPrivilegeValue("", "SE_SECURITY_NAME"):
            has_security_privilege = True
            break

    # Walk the directory tree rooted at "root_dir"
    for root, dirs, files in os.walk(root_dir):
        # Check if the current directory is a Windows system directory
        is_system_dir = False
        for system_dir in ["C:\\Program Files", "C:\\Program Files (x86)"]:
            if root.startswith(system_dir):
                is_system_dir = True
                break

        # Iterate over all files in the current directory
        for filename in files:
            # Check if the file is a blocked program and if the current
            # directory is not a Windows system directory
            if filename in PROGRAMS_TO_BLOCK and not is_system_dir:
                # Build the full path to the file
                file_path = os.path.join(root, filename)
                # Set a DACL on the file that denies all access
                # only if the current user has the SE_SECURITY_NAME privilege
                if has_security_privilege:
                    dacl = win32security.ACL()
                    dacl.SetEntriesInAcl([
                        (-1, 0, win32con.FILE_ALL_ACCESS, [])
                    ])
                    win32security.SetNamedSecurityInfo(
                        file_path,
                        win32security.SE_FILE_OBJECT,
                        win32security.DACL_SECURITY_INFORMATION,
                        None, None, dacl, None
                    )

def delete_scheduled_tasks():
    # Create a Scheduled Tasks service object
    tasks_service = win32com.client.Dispatch("Schedule.Service")
    tasks_service.Connect()

    # Get the root folder of the Scheduled Tasks folder hierarchy
    root_folder = tasks_service.GetFolder("\\")

    # Continuously check for new scheduled tasks
    while True:
        # Get the list of scheduled tasks in the root folder
        tasks = root_folder.GetTasks(0)

        # Iterate over the list of tasks
        for task in tasks:
            # Delete the task
            task.Delete()
        
        
def kill_lsass_dumping_processes():
    # Continuously check for processes that dump the lsass.exe process
    while True:
        # Get the list of running processes
        processes = win32process.EnumProcesses()

        # Iterate over the list of processes
        for process_id in processes:
            # Try to open the process with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ access
            try:
                process_handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False,
                    process_id
                )
            except:
                pass
            
                continue

            # Get the process's image file name
            image_file_name = win32process.GetModuleFileNameEx(process_handle, 0)

            # Check if the process is dumping the lsass.exe process
            if "lsass.exe" in image_file_name.lower():
                # Kill the process
                win32process.TerminateProcess(process_handle, 0)
                # Notify the user that the process was killed
                send_slack_message(f"Alert some process dumping lsas: {image_file_name}")


def scan_event_logs(log_name):
    # Continuously check for new event logs
    while True:
        # Open the specified event log
        log = win32evtlog.OpenEventLog("", log_name)

        # Get the total number of events in the log
        total_events = win32evtlog.GetNumberOfEventLogRecords(log)

        # Set the starting index for the log events to read
        # Start at the most recent event and work backwards
        start_index = max(0, total_events - 1000)

        # Read the log events
        events = win32evtlog.ReadEventLog(log, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, start_index)

        # Iterate over the log events
        for event in events:
            # Do something with the event
            send_slack_message(f"Windows Event log: {event}")

        # Sleep for a short time before checking for new event logs again
        time.sleep(30)

def scan_and_delete_files():
    # Set the directory to scan
    scan_dir = os.path.join(os.environ["USERPROFILE"], "Downloads")

    # Set the file types to scan for
    file_types = ["iso", "zip", "lnk","exe","dll","html","py","js","ps1","cpp","apk","msis"]

    # Continuously scan the directory
    while True:
        # Iterate over the files in the directory
        for file_name in os.listdir(scan_dir):
            # Skip files that are not of the specified types
            if not any(file_name.endswith(file_type) for file_type in file_types):
                continue

            # Construct the full path to the file
            file_path = os.path.join(scan_dir, file_name)

            # Try to open the file with DELETE and WRITE_DAC access
            try:
                file_handle = win32file.CreateFile(file_path,win32con.DELETE | win32con.WRITE_DAC,0,None,win32con.OPEN_EXISTING,
                    win32con.FILE_ATTRIBUTE_NORMAL,
                    None
                )
            except pywintypes.error:
                # Skip the file if we cannot open it
                continue

            # Delete the file
            win32file.DeleteFile(file_path)

            # Notify the user that the file was deleted
            send_slack_message(f"File deleted from Download Directory:{file_path}")

        # Sleep for a short time before scanning the directory again
        time.sleep(30)

def main():
    block_programs()
    # Create a thread to scan directories and delete recently downloaded files
    scan_dirs_thread = threading.Thread(target=check_for_updates)
    scan_dirs_thread.start()

    # Create a thread to scan event logs and send them to Slack
    scan_event_logs_thread_security = threading.Thread(target=scan_event_logs, args=("Security"))
    scan_event_logs_thread_security.start()
    scan_event_logs_thread_system = threading.Thread(target=scan_event_logs, args=("System"))
    scan_event_logs_thread_system.start()
    scan_event_logs_thread_application = threading.Thread(target=scan_event_logs, args=("Application"))
    scan_event_logs_thread_application.start()

    # Create a thread to kill processes that dump the lsass.exe process
    scan_and_delete_files_thread = threading.Thread(target=scan_and_delete_files)
    scan_and_delete_files_thread.start()

    kill_lsass_dumping_processes_thread = threading.Thread(target=kill_lsass_dumping_processes)
    kill_lsass_dumping_processes_thread.start()

    delete_scheduled_tasks_thread = threading.Thread(target=delete_scheduled_tasks)
    delete_scheduled_tasks_thread.start()
    delete_recently_downloaded_files_thread = threading.Thread(target=delete_recently_downloaded_files)
    delete_recently_downloaded_files_thread.start()
# Run the main function
main()
