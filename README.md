<img width="1600" height="900" alt="Tor_Browser" src="https://github.com/user-attachments/assets/9a555290-cce0-41b1-bbe1-d254050042b2" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/NoahPageIT/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machine: Microsoft Azure
- EDR Platform: Microsoft Defender for Endpoint
- Query Language: Kusto Query Language
- Application Investigated: Tor Browser

##  Scenario

Management suspects that some employees may be using Tor Browser to bypass network security controls. Recent network logs showed unusual encrypted traffic patterns and connections to possible Tor-related infrastructure. There were also anonymous reports of employees discussing methods to access restricted sites during work hours.
The objective of this investigation was to identify whether Tor Browser was downloaded, installed, executed, or used to establish outbound network connections from the monitored endpoint. If Tor usage was confirmed, the findings would be documented and escalated to management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the *DeviceFileEvents* Table

A search was performed in the DeviceFileEvents table for files containing the string tor on the device lab-gk.
The results showed that the user karan downloaded and executed a Tor Browser installer from the Downloads folder. The file was later deleted from:C:\Users\karan\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe

Additional file activity showed that Tor Browser-related files were created under the Desktop path:
C:\Users\karan\Desktop\Tor Browser\Browser\TorBrowser\...

The evidence indicates that Tor Browser was extracted or installed onto the user’s Desktop and created multiple supporting files and shortcuts.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "lab-gk"
| where InitiatingProcessAccountName == “karan”
| where FileName contains "tor"
|  order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1447" height="323" alt="1" src="https://github.com/user-attachments/assets/94dd5ae2-bee6-49ce-89f7-7dbefb6ebc63" />

---

### 2. Searched the *DeviceProcessEvents* Table

A search was performed in the DeviceProcessEvents table for process command lines containing tor-browser.
The logs showed that the user karan executed the Tor Browser portable installer: tor-browser-windows-x86_64-portable-15.0.15.exe

This confirms that the Tor Browser installer was executed on the endpoint.

**Query used to locate event:**
```kql
DeviceProcessEvents
| where DeviceName == "lab-gk"
| where ProcessCommandLine contains "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine          
```
<img width="1315" height="65" alt="2" src="https://github.com/user-attachments/assets/93a35ea0-9096-4175-92ec-2f629121a131" />

---

### 3. Searched the *DeviceProcessEvents* Table for TOR Browser Execution

A follow-up search was performed to identify execution of Tor-related processes.

The results showed that tor.exe was executed from the Tor Browser directory located on the user’s Desktop:
C:\Users\karan\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
The logs also showed multiple instances of firefox.exe, which is expected because Tor Browser uses a modified Firefox-based browser process.
Several firefox.exe child/content processes were observed shortly after Tor execution, including command-line arguments such as: -contentproc -isForBrowser

This confirms that Tor Browser was not only installed, but actively launched and used.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "lab-gk"
| where FileName has_any ("tor.exe", "torbrowser.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc           
```
<img width="1467" height="653" alt="3" src="https://github.com/user-attachments/assets/2d6ebb12-a170-4e1e-86a5-f6e5eb0cabd7" />

---

### 4. Searched the *DeviceNetworkEvents* Table for TOR Network Connections

A search was performed in the DeviceNetworkEvents table for outbound network connections initiated by tor.exe or firefox.exe.
The logs showed several successful network connections initiated by Tor-related processes.
Notable observed activity included:
- tor.exe successfully connected to remote IP 57.129.17.163 over port 9001
- tor.exe successfully connected to remote IP 89.58.54.129 over port 443
- tor.exe attempted and failed a connection to remote IP 2.58.52.163 over port 9002
- firefox.exe established local connections to 127.0.0.1 over ports 9150 and 9151

The local loopback connections to 127.0.0.1 on ports 9150 and 9151 are consistent with Tor Browser’s local SOCKS/control communication behavior. The outbound connections over ports 9001, 9002, and 443 further support active Tor usage.


**Query used to locate events:**
```kql
DeviceNetworkEvents
| where DeviceName == "lab-gk"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9002", "9030", "9031", "9040", "9050", "9051", "9150", "9151", "9999", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc  
```
<img width="1512" height="259" alt="4" src="https://github.com/user-attachments/assets/47c9e630-c326-4da3-af01-e24f1ad79eae" />

---

## Chronological Event Timeline 

- On 7 Jun 2026, Tor Browser activity was identified on device lab-gk under the user account karan.

- At 17:54:33, the Tor Browser installer file, tor-browser-windows-x86_64-portable-15.0.15.exe, appeared in the user’s Downloads folder. This was the first indication that Tor Browser had been downloaded onto the endpoint.

- At 17:54:54, user karan executed the Tor Browser installer from the Downloads folder. Around the same time, the installer file was deleted from C:\Users\karan\Downloads\, which suggests the installer may have been removed after the application was installed.

- At 17:55:10, multiple Tor Browser support and license files were created under the Desktop Tor Browser directory. These included files such as tor.txt, Torbutton.txt, and Tor-Launcher.txt. This activity indicates that Tor Browser files were being iinstalled onto the system.

- At 17:55:11, the file tor.exe was created in the path C:\Users\karan\Desktop\Tor Browser\Browser\TorBrowser\Tor\. This is significant because tor.exe is the main executable used by Tor Browser to connect to the Tor network.

- At 17:55:16, a Tor Browser shortcut was created on the Desktop. At 17:55:34, another Tor Browser shortcut was created in the Start Menu. These shortcut creations indicate that Tor Browser was installed or prepared for normal user access.

- At 17:55:43 and 17:55:46, Tor Browser profile database files, including storage.sqlite and storage-sync-v2.sqlite, were created in the Tor Browser profile directory. This shows that the browser profile was initialized.

- At 17:55:34, Tor Browser’s bundled firefox.exe process was launched. Tor Browser is based on Firefox, so this process activity indicates that the browser was opened by the user. Between 17:55:44 and 17:59:27, multiple firefox.exe child processes were created, which is consistent with normal Tor Browser activity while the browser is running.

- At 17:55:48, tor.exe was launched from the Desktop Tor Browser directory. This confirms that the Tor service process started.

- At 17:55:49, firefox.exe successfully connected to 127.0.0.1 on port 9151. At 17:56:17, firefox.exe attempted to connect to 127.0.0.1 on port 9150, but the connection failed. At 17:57:20, firefox.exe successfully connected to 127.0.0.1 on port 9150. These localhost connections are consistent with Tor Browser communicating with its local Tor proxy service.

- At 17:56:46, tor.exe successfully connected to remote IP address 57.129.17.163 on port 9001. At 17:57:20 and 17:57:23, tor.exe successfully connected to remote IP address 89.58.54.129 on port 443.

- At 17:57:41, tor.exe attempted to connect to remote IP address 2.58.52.163 on port 9002, but the connection failed. These outbound connections indicate Tor-related network activity from the endpoint.

Overall, the activity followed a clear sequence: Tor Browser was downloaded, executed, installed, launched, and then used to initiate local and outbound Tor-related network connections. This confirms Tor Browser usage on device lab-gk by user karan.

---

## Summary
On June 7, 2026, user karan on device lab-gk conducted activity consistent with unauthorized Tor Browser use.
At approximately 5:54 PM, the user executed the Tor Browser installer from the Downloads folder. Within minutes, Tor Browser files were created on the Desktop, including tor.exe, browser profile files, and shortcuts. The browser was then launched through its bundled firefox.exe process, followed by execution of tor.exe.
Network logs confirmed Tor-related activity, including local connections to 127.0.0.1 on ports 9150 and 9151, and outbound connections by tor.exe to external IP addresses over ports 9001, 9002, and 443.
The sequence from installation to network activity occurred in less than five minutes, indicating intentional use rather than accidental activity. This confirms unauthorized Tor Browser usage and The device  was isolated and the user's direct manager was notified.
