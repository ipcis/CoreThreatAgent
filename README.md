# CoreThreat Agent
<img src="https://corethreat.net/assets/img/logo.png" height="300px"> 

## What is CoreThreat Agent?
Core|Threat Agent collects security logs and send them over syslog.
Easy to deploy security related logs.
Automatically installs Sysmon, sets the necessary registry-keys and policies.
Gets the Windows-Events from Sysmon and sends them over syslog to the destination of your choice.

## Features
+ installs Sysmon
+ activates windows logging
+ collects sysmon-events
+ sends sysmon-events to syslog server

## How to use?
<code>CoreThreat.exe sysmon</code>

<code>CoreThreat.exe auditpol</code>

<code>CoreThreat.exe psaudit</code>

<code>CoreThreat.exe runagent:(ip or hostname):(port)</code>

  
## Working on the following features
- hide cmd dialog
- run as admin
- run as service
- other kinds of events: powershell, etc.
- threading
- udp
- filelog
