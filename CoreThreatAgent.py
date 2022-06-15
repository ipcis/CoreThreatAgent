# CoreThreat Agent
#
#


import win32evtlog, win32event, win32con
import time, json, xmltodict, socket
import logging, logging.handlers

from urllib import request
import zipfile
import argparse
import shutil
import subprocess
import os


sPROTO = "TCP"
sHOST = ""
sPORT = 514
hostNAME = socket.gethostname()



# RFC syslog facility types:
FACILITY = {
    'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
    'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
    'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
    'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
    'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

# RFC log levels for syslog:
LEVEL = {
    'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
    'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}


def ask_question(question):
    print(question + " [Yes/y/no/n]?")
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}

    while True:
        choice = input().lower()

        if choice in yes:
            return True
        elif choice in no:
            return False
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'")
	
	
	
	
def action_change_audit():

    policies_list = [("Account Management - Security Group Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management",  '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Detailed Tracking - DPAPI Activity", '/set /subcategory:{0CCE922D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable' ),
                         ("Logon/Logoff - Account Lockout", '/set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Logon", '/set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Logon/Logoff - Other Logon/Logoff Events", '/set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Account Management - User Account Management", '/set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Packet Drop", '/set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Filtering Platform Connection", '/set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Detailed File Share", '/set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - File Share", '/set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ("Object Access - Other Object Access Events", '/set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable'),
                         ]

    print("For following policies:")
    for policy_name, policy_cmd in policies_list:
        print("* {} : to audit success and failures".format(policy_name))

    change_policies = ask_question("Do you agree to change audit for them?")
    if change_policies:
        for policy_name, policy_cmd in policies_list:
            print("-> Changing: {}".format(policy_name))
            args = ["auditpol.exe"]
            args += policy_cmd.split(" ")
            subprocess.run(args, shell=True)
            print("")
	

def action_psaudit():
    print("You need Powershell 5 at least to enhance audit.")
    print("Your current version of PowerShell won't be checked. Assuming you had PowerShell 5.")
    print("")
    import_ps = ask_question("For Powershell 5 do you want to enable:\n* ModuleLogging\n* ScriptBlockLogging\n* Transcription to C:\\pslog")

    if import_ps:
        print("Import registry file with new settings ...")
        subprocess.run(["reg.exe", "import", POWERSHELL_ENHANCED_AUDIT_REG_FILE])
        print("=> Done")
    else:
        print("=> Skip")

#pathes etc.
INSTALLER_DIRECTORY = os.path.dirname(os.path.abspath(__file__)).replace("/", "\\")
EXTRA_FILES = INSTALLER_DIRECTORY + "\\"

#SYSMON_
SYSMON_BASE_DIR = EXTRA_FILES + "\\"
SYSMON_ZIP_URL = "https://download.sysinternals.com/files/Sysmon.zip"
SYSMON_EXTRACTED_DIR = SYSMON_BASE_DIR + "\\"
SYSMON_ZIP_DOWNLOADED = SYSMON_EXTRACTED_DIR + "Sysmon.zip"
SYSMON_64 = SYSMON_EXTRACTED_DIR + "Sysmon64.exe"
SYSMON_32 = SYSMON_EXTRACTED_DIR + "Sysmon.exe"
SYSMON_FAKE_NAME = SYSMON_EXTRACTED_DIR + "sysM0N.exe"
SYSMON_DRIVER = "sysM0N"
SYSMON_CONFIG = "sysmonconfig.xml"


#powershell
POWERSHELL_ENHANCED_AUDIT_REG_FILE = "powershell_audit.reg"


def action_sysmon():
    install_sysmon = ask_question("Do you want to install/download pre-configured Sysmon?")

    if install_sysmon:
        # SYSMON NEEDS TO BE DOWNLOADED
        if not os.path.isfile(SYSMON_ZIP_DOWNLOADED):

            try:
                print("Downloading Sysmon ...")
                sysmon_zip_content = request.urlopen(SYSMON_ZIP_URL)
                if not sysmon_zip_content.getcode() == 200:
                    raise AssertionError
                with open(SYSMON_ZIP_DOWNLOADED, "wb") as smon:
                    print("Saving Sysmon.zip")
                    smon.write(sysmon_zip_content.read())

            except Exception as e:
                print(e)
                print("Cannot download Sysmon from URL: {}".format(SYSMON_ZIP_URL))
                print("Download Sysmon.zip manually and put in: {}".format(SYSMON_EXTRACTED_DIR))
                print("Then re-run installer.")

        if os.path.isfile(SYSMON_ZIP_DOWNLOADED):
            # EXTRACT ZIP
            if not os.path.exists(SYSMON_32) or os.path.exists(SYSMON_64):
                print("Extracting Sysmon.zip ...")
                zip_ref = zipfile.ZipFile(SYSMON_ZIP_DOWNLOADED, 'r')
                zip_ref.extractall(SYSMON_EXTRACTED_DIR)
                zip_ref.close()

            # ALREADY EXTRACTED
            if os.path.exists(SYSMON_32) and os.path.exists(SYSMON_64):
                SYSMON_TAKEN = ""

                if is_os_64_bit():
                    SYSMON_TAKEN = SYSMON_64
                else:
                    SYSMON_TAKEN = SYSMON_32



                args = [SYSMON_TAKEN, ]
                args += "-accepteula -n -d {} -i".format(SYSMON_DRIVER).split(" ")
                args.append(SYSMON_CONFIG)

                print("Installing Sysmon (Service: {} | Driver: {})".format(os.path.basename(SYSMON_64), SYSMON_DRIVER))
                subprocess.run(args)

            else:
                print("Sysmon.zip extraction error. Extract manually")
        else:
            print("Sysmon.zip not present")


def is_os_64_bit():
    return os.path.exists("C:\\Program Files (x86)")



def initiateSyslogConnection(host, port, proto):
    
    if proto == "TCP":
        # Open a TCP socket to the remote syslog host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.connect((host, port))
    except:
        print("[!] Connection failed!")
              
    if proto == "UDP":
        # Open a UDP socket to the remote syslog host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    return s
    
	
def closeSyslogConnection(s):
    # Be sure to close the socket!
    s.close()


def syslog(s, win_evt, level=LEVEL['debug'], facility=FACILITY['syslog']):
    data = '<%d>%s %s %s %s %s' % (level + facility * 8, '1', ' ' + str(hostNAME), '0', '0', win_evt)
    print(data)
    
    if sPROTO == "TCP":
        s.send(data.encode())  # encode the tuple as bytes for TCP packet
    if sPROTO == "UDP":
        s.sendto(data.encode(), (sHOST, sPORT))  # encode the tuple as bytes for UDP packet




def action_run(eventSub, syslog_host, syslog_port, syslog_proto):
	h=win32event.CreateEvent(None, 0, 0, None)
	s=win32evtlog.EvtSubscribe(eventSub, win32evtlog.EvtSubscribeStartAtOldestRecord, SignalEvent=h, Query=None)

	print("")
	print("SYSLOG PROTO: " + syslog_proto)
	print("")
	syslog_socket = initiateSyslogConnection(syslog_host, syslog_port, syslog_proto)
	syslog(syslog_socket,"HELLO SYSLOG FROM CoreThreat", level=LEVEL['debug'], facility=FACILITY['syslog'])

	while 1:
		while 1:
			events=win32evtlog.EvtNext(s, 10)
			if len(events)==0:
				break
			for event in events:
				print (win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
				try:
				    syslog(syslog_socket,
				       json.dumps(xmltodict.parse(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))),
				       level=LEVEL['debug'], facility=FACILITY['syslog'])
				except:
				    print("[!] Connection problem! Wait 5 secs and try to reconnect...")
				    time.sleep(5)
				    syslog_socket = initiateSyslogConnection(syslog_host, syslog_port, syslog_proto)
			print ('retrieved %s events' %len(events))
		while 1:
			print ('waiting...')
			w=win32event.WaitForSingleObjectEx(h, 2000, True)
			if w==win32con.WAIT_OBJECT_0:
				break
			
			
			
def help():
    print("CoreThreat Agent")
    print("Usage: CoreThreatAgent.exe <action>")
    print("")
    print("Possible actions:")
    print("  sysmon - Install (and download) Sysmon with predefined configuration file")
    print("  auditpol - Enable more events of Windows Audit (Evtx) with auditpol.exe")
    print("  psaudit - (Require PowerShell 5) Enhance audit by enabling: ModuleLogging, ScriptBlockLogging and Transcription")
    print("  runagent:<ip>:<port>:<proto> - start receiving events and sending over syslogs TCP or UDP")
    print("  ")
    print("  Run agent: CoreThreatAgent.exe runagent:192.168.1.28:514:TCP")
    print("  Press strg+c to break")

def main():
    parser = argparse.ArgumentParser(description='Installer')
    parser.add_argument('action', nargs='*', help="")
    args = parser.parse_args()
    actions_list = args.action

    #Default action install
    if len(actions_list) == 0:
        help()
    else:
        action = actions_list[0]
        if action == "sysmon":
            action_sysmon()
        elif action == "auditpol":
            action_change_audit()
        elif action == "psaudit":
            action_psaudit()
        elif "runagent" in action:
            arguments = action.split(":")
            syslogIP = arguments[1]
            syslogPORT = arguments[2]
            syslogPROTO = arguments[3]
            #to subscribe more than one eventlog maybe usage of threading
            global sPROTO
            global sHOST
            global sPORT
            sPROTO = syslogPROTO
            sHOST = syslogIP
            sPORT = int(syslogPORT)
            action_run('Microsoft-Windows-Sysmon/Operational', str(syslogIP), int(syslogPORT), str(syslogPROTO))
        else:
            parser.error("Unknown action: {}".format(action))


if __name__ == "__main__":
   main()
