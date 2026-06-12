# Sample Threat Report: Excel Malware Using mshta Persistence

A recent malware campaign delivers a fake invoice as an Excel attachment. When the victim opens the workbook and enables content, Excel spawns `mshta.exe` to retrieve a remote HTML application payload from an attacker-controlled domain.

After the payload runs, the malware creates a Registry Run Key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so it can restart after reboot. The infected host later makes HTTPS connections to newly registered domains for command and control.

Observed behaviors:
- `excel.exe` launches `mshta.exe`.
- `mshta.exe` downloads a payload from an unknown domain.
- A new Registry Run Key is created.
- The same host connects to a newly registered or uncategorized domain over HTTPS.
