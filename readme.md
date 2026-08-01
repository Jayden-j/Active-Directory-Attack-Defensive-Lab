# Active Directory Attack & Defense Lab

A four-VM Active Directory lab I built to run a full attack chain end to end, from a single phished user account all the way to a complete domain compromise, then catch each step using Windows event logs and a custom Wazuh rule.

**Techniques:** Kerberoasting, Pass-the-Hash, DCSync
**Stack:** Windows Server 2022, Windows 11, Kali Linux, Wazuh SIEM, Sysmon
**Mapped to:** MITRE ATT&CK (T1558.003, T1550.002, T1003.006)

---

## Overview

I wanted a lab where I could actually carry out a domain compromise the way an attacker would, and then figure out how a SOC analyst would catch it. So I built the whole thing from scratch in VMware, ran every attack by hand from Kali, and then went back and confirmed each technique showed up somewhere I could detect it, both in raw Windows logs and in a SIEM.

The part I'm most happy with is the detection at the end. Wazuh's default rules don't flag DCSync, so I wrote my own rule to catch it.

---

## Lab Architecture

| Host | Role | OS | IP |
|------|------|-----|-----|
| **DC01** | Domain Controller (`LABBOX.local`) | Windows Server 2022 | `192.168.1.10` |
| **WS01** | Domain-joined workstation | Windows 11 | `192.168.1.20` |
| **Kali** | Attacker | Kali Linux | `192.168.1.250` |
| **Wazuh** | SIEM / log analysis | Ubuntu Server | `192.168.1.15` |

Every VM has two network adapters. One is host-only on `192.168.1.0/24` for the isolated lab network, and the other is NAT for internet access when I need to install tooling. That way the attack traffic stays contained but I can still pull packages down.

<!-- SCREENSHOT: network / VM topology diagram (optional) -->

---

## The Attack Chain

```
j.rivera (phished employee, low privilege)
   └─▶ Recon with BloodHound
        └─▶ Kerberoast svc-sql → crack weak password offline
             └─▶ Pass-the-Hash into WS01 as SYSTEM
                  └─▶ DCSync → dump every credential in the domain
```

---

### 1 · Reconnaissance with BloodHound

Starting from the phished `j.rivera` account, I pulled the full domain graph with `bloodhound-python` and loaded it into BloodHound CE to look for a path to Domain Admin.

```bash
bloodhound-python -u j.rivera -p 'Summer2025!' -d labbox.local -ns 192.168.1.10 -c All --zip
```

This came back with 2 computers, 7 users, 52 groups, and 3 OUs.

<!-- SCREENSHOT: BloodHound graph / shortest path to Domain Admins -->

---

### 2 · Kerberoasting (T1558.003)

Any authenticated domain user can request a service ticket for an account that has an SPN, and that ticket is encrypted with the service account's password hash. That means I can grab it and crack it offline. I went after `svc-sql`.

```bash
impacket-GetUserSPNs labbox.local/j.rivera:'Summer2025!' \
  -dc-ip 192.168.1.10 -request -outputfile kerberoast.hash
```

<!-- SCREENSHOT: GetUserSPNs output showing svc-sql SPN and captured ticket -->

The hash fell in under a second against `rockyou.txt`, since the service account was set up with a weak password (`Welcome1`).

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hash
```

<!-- SCREENSHOT: John the Ripper cracking svc-sql → Welcome1 -->

---

### 3 · Pass-the-Hash (T1550.002)

Now that `svc-sql` was cracked, and since it had local admin on WS01 (which happens a lot in real environments), I used the NT hash to log straight into WS01. I never typed the password once.

```bash
impacket-psexec -hashes :<NT_HASH> LABBOX/svc-sql@192.168.1.20
```

That gave me a SYSTEM shell on WS01. Worth noting: Windows Defender and Tamper Protection blocked the payload on the first few tries, which was a good reminder that built-in AV does catch this, and I had to work around it to get the shell.

<!-- SCREENSHOT: psexec SYSTEM shell on WS01 + whoami output -->

---

### 4 · DCSync (T1003.006)

`svc-sql` had been given Replicating Directory Changes rights, which is what an over-delegated service account looks like in the wild. With that, I could pretend to be a domain controller and replicate every credential hash out of the domain, including the `krbtgt` hash that would let you forge Golden Tickets.

```bash
impacket-secretsdump -hashes :<NT_HASH> LABBOX/svc-sql@192.168.1.10
```

At this point the whole domain is compromised. Every user, service, and machine account hash is dumped.

<!-- SCREENSHOT: secretsdump NTDS.DIT dump (hashes redacted) -->

---

## Detection & Defense

Running the attacks is only part of it. I went back through each technique and confirmed it showed up in Windows telemetry and in Wazuh.

### Native Windows event signatures

| Attack | Event ID | What gives it away |
|--------|----------|--------------------|
| Kerberoasting | **4769** | Ticket encryption type `0x17` (RC4) on a service account |
| Pass-the-Hash | **4624** | Logon Type 3 with NTLM as the auth package |
| DCSync | **4662** | Object access using a replication-rights GUID `{1131f6aa-...}` |

<!-- SCREENSHOT: Event Viewer showing 4662 Directory Service Access from svc-sql -->

---

### Custom Wazuh rule for DCSync

Out of the box, Wazuh won't alert on Event 4662. That's actually reasonable, because 4662 fires all the time during normal AD activity, and alerting on all of it would drown an analyst in noise. The trick is to only fire when the 4662 event carries one of the two replication-rights GUIDs that DCSync actually uses, so I wrote a rule to do exactly that.

```xml
<group name="windows,dcsync,attack,">
  <rule id="100010" level="12">
    <if_group>windows_security</if_group>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties">1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
    <description>Possible DCSync attack: AD replication rights used by $(win.eventdata.subjectUserName)</description>
    <mitre>
      <id>T1003.006</id>
    </mitre>
    <group>dcsync,active_directory,mitre_credential_access,</group>
  </rule>
</group>
```

When I ran the DCSync attack, the rule fired a burst of level-12 alerts, all inside a roughly 3-second window, which lines up with how fast `secretsdump` hammers out its replication requests. It named `svc-sql` as the account responsible and tagged the alert with MITRE T1003.006.

<!-- SCREENSHOT: Wazuh alerts for rule.id 100010 — burst histogram + alert detail -->

<!-- SCREENSHOT: Wazuh dashboard overview -->

---

## Incident Response Summary

| Stage | Technique | MITRE ID | How you'd catch it |
|-------|-----------|----------|--------------------|
| Recon | LDAP/SAMR enumeration | T1087, T1069 | BloodHound collection traffic |
| Credential Access | Kerberoasting | T1558.003 | Event 4769 (RC4 ticket) |
| Credential Access | Offline cracking | T1110.002 | Not visible (happens offline) |
| Lateral Movement | Pass-the-Hash | T1550.002 | Event 4624 (NTLM, Type 3) |
| Credential Access | DCSync | T1003.006 | Event 4662 + custom Wazuh rule 100010 |

### What I'd fix in a real environment
- Put strong, unique passwords on service accounts, or move them to gMSAs with automatic rotation. That one change kills the Kerberoasting path on its own.
- Go through delegation and pull back anything excessive. No service account should be sitting on Replicating Directory Changes rights.
- Keep service accounts out of the local admin group on workstations so they can't be used to move laterally.
- Actually alert on the giveaways: RC4 service tickets, NTLM network logons from accounts that shouldn't be doing that, and replication requests coming from anything that isn't a domain controller.

---

## What I ran into

Getting this working meant fixing a bunch of real problems along the way, not just typing commands. Kerberos kept throwing clock skew errors until I lined up the attacker and DC times, WS01's domain trust broke and had to be repaired, Defender's Tamper Protection kept quietly turning itself back on, and at one point my DCSync events weren't reaching Wazuh at all because the manager had crashed mid-attack from a full disk. The best thing to come out of it was realizing Wazuh doesn't catch DCSync by default, and then writing the rule to fix that myself.

---

Built by [Jayden Johnson](https://github.com/Jayden-j) · Information Systems (Cybersecurity), Mercer County Community College
