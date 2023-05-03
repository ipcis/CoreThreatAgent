# Core|Threat Agent
<img src="https://corethreat.net/ct_logo_big.png" height="300px"> 

## What is Core|Threat Agent?
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
<code>CoreThreatAgent.exe sysmon</code>

<code>CoreThreatAgent.exe auditpol</code>

<code>CoreThreatAgent.exe psaudit</code>

<code>CoreThreatAgent.exe runagent:(ip or hostname):(port):(proto)</code>

Sample: <code>CoreThreatAgent.exe runagent:10.10.10.1:5555:UDP</code>

## Releases
https://github.com/ipcis/CoreThreatAgent/releases
  
## Working on the following features
- hide cmd dialog (background mode)
- run as admin / service
- other kinds of events: powershell, etc.
- threading
- filelog

## Install on Windows - no exe
python -m pip install pywin32
python -m pip install xmltodict
