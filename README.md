# CoreThreatAgent
Collect security logs and send them over syslog.

Easy to deploy security related logs.
Automatically installs Sysmon, sets the necessary registry-keys and policies.

Gets the Windows-Events from Sysmon and sends them over syslog to the destination of your choice.



Future features:
- run as admin
- run as service
- other kinds of events: powershell, etc.
- threading
- udp
- filelog
