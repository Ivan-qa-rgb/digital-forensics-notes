# Fileless PowerShell Attack on Win7: RAM Dump Analysis

## Goal
Analyze the `incident.mem` memory dump and identify the attack chain, malicious process, and signs of anti-forensics.

## Environment
- OS: Windows 7 SP1 x86
- Memory dump: `incident.mem`
- Tool: Volatility 2.6
- Attack time: 2019-03-10 12:30:35 UTC

## Findings
- Profile confirmed: `Win7SP1x86_23418`.
- Process chain: `explorer.exe (3484) -> cmd.exe (3008) -> powershell.exe (3672)`.
- `powershell.exe (PID 3672)` is the main indicator of compromise.
- Anti-forensics observed: `conhost.exe (1540)`, `cmd.exe`, and `powershell.exe` were wiped from memory artifacts.
- `CommandCount: 0` suggests command history cleanup.
- `powershell.exe` had 5 RWX regions.
- `NetScan` for PID `3672` showed suspicious UDP flows.

## Attack Chain
```text
explorer.exe(3484)
└─ cmd.exe(3008, PPID=3692)
   └─ powershell.exe(3672)
```

## Evidence
- Suspicious PID: `3672`
- Malicious process: `powershell.exe`
- RWX shellcode regions detected
- Network activity linked to the suspicious process

## Screenshots
![Process chain](./images/process-chain.png)
![RWX regions](./images/rwx-regions.png)
![NetScan result](./images/netscan-result.png)

## MITRE ATT&CK
- T1059.001 — PowerShell
- TA0002 — Execution
- Process Injection

## Conclusion
The incident was a fileless PowerShell attack launched via `Win+R -> cmd -> powershell`, with process injection, anti-forensics, and suspicious network activity.
