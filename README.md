# CoreThreat Agent
<img src="https://corethreat.net/assets/img/logo.png" height="300px"> 

## What is CoreThreat Agent?
CoreThreat Agent collects security logs and send them over syslog.

Easy to deploy security related logs.
Automatically installs Sysmon, sets the necessary registry-keys and policies.

Gets the Windows-Events from Sysmon and sends them over syslog to the destination of your choice.

## Features
+ installs Sysmon
+ activates windows logging
+ collects sysmon-events
+ sends sysmon-events to syslog server

## How to use?
# CoreThreat.exe sysmon
# CoreThreat.exe auditpol
# CoreThreat.exe psaudit
# CoreThreat.exe runagent:(ip or hostname):(port)

## Working on the following features
- hide cmd dialog
- run as admin
- run as service
- other kinds of events: powershell, etc.
- threading
- udp
- filelog
