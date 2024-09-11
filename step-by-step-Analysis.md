### **Incident Response Documentation: Investigating a Compromised Employee VM**


#### **Project Overview**

This incident response project involved an investigation into a potentially compromised virtual machine (VM) used by an IT employee for penetration testing practice. The machine was suspected of being compromised after downloading a vulnerable VM from a Capture the Flag (CTF) website, which had been infiltrated by threat actors. The investigation required analyzing network traffic and memory dump data to identify malicious activity and processes.

---

#### **Objectives**

1. **Analyze network traffic** from the compromised VM to determine whether a breach occurred and identify communication with threat actors.
2. **Investigate memory dumps** to discover malicious processes running on the compromised machine.
3. **Identify and analyze malware** associated with the attack.
4. **Determine if the attacker achieved system-level privileges** on the compromised machine.
5. **Provide recommendations** for remediation and mitigation.

---

#### **Tools Used**

- **Wireshark**: Used to analyze the `.pcap` file containing network traffic data.
- **Volatility**: Utilized for memory dump analysis to find malicious processes and evidence of privilege escalation.
- **VirusTotal**: Used to analyze extracted malware files for signatures.
- **Zeek**: Optional network traffic analyzer for broader packet analysis.

---

### **Step-by-Step Analysis**

#### **1. Network Traffic Analysis with Wireshark**

- **Objective**: Analyze traffic between the compromised machine (192.168.248.100) and known malicious IPs (192.168.248.217 and 192.168.248.200).
  
- **Steps Taken**:
    - Filtered traffic in Wireshark using IP addresses to detect communication between the victim and threat actors.
    - Identified first connection between the victim’s VM and the malicious server (packet 30197).
    - Discovered suspicious traffic on ports 8080 and 4444 indicating a possible backdoor or reverse shell.

#### **2. Memory Analysis with Volatility**

- **Objective**: Identify malicious processes and network connections using the provided memory dump.

- **Steps Taken**:
    - Used `pslist` to list active processes, identifying suspicious executables: `ghost.exe`, `mXvtj.exe`, `HgTg.exe`.
    - Ran `netscan` to find active network connections, revealing malicious traffic on ports 7777, 4444, and 9999.
    - Used `procdump` to export malicious files for further analysis.

#### **3. Malware Analysis**

- **Objective**: Analyze extracted malware files using VirusTotal to confirm their malicious nature.
  
- **Steps Taken**:
    - Submitted files (`ghost.exe`, `eDqYEC.exe`, etc.) to VirusTotal, which identified them as malicious.
    - Verified that these files were linked to known Metasploit payloads and privilege escalation techniques.

#### **4. Privilege Escalation**

- **Objective**: Determine if the attacker achieved system-level privileges.

- **Steps Taken**:
    - Ran `getsids` in Volatility to check process privileges, confirming that the attacker had system-level access (`S-1-5-18`), indicating full control over the machine.

---

### **Conclusion and Recommendations**

- **Attacker’s IP**: 192.168.248.200
- **Compromised VM IP**: 192.168.248.217
- **Victim’s machine IP**: 192.168.248.100
- **Malicious processes**: `ghost.exe`, `mXvtj.exe`, `HgTg.exe`
- **Privilege Level**: System-level access confirmed.

---

#### **Recommendations**:

1. **Isolate the compromised machine**: Take the affected machine offline immediately to prevent further malicious activity.
2. **Patch vulnerabilities**: Ensure any exploited vulnerabilities are patched, including potential XSS vulnerabilities in web applications.
3. **Rebuild the system**: Wipe and rebuild the compromised VM to remove any malicious files or backdoors.
4. **User training**: Educate users on the risks of downloading files from unverified sources.
5. **Conduct a full forensic audit**: Ensure no further compromise has occurred within the network.

