from __future__ import annotations

from packages.core.models import NormalizedEvent
from packages.detection.engine import Rule


class SuspiciousPowerShellRule(Rule):
    id = "R001"
    name = "Suspicious PowerShell"
    severity = "high"
    tags = ["execution", "powershell"]

    def match(self, event: NormalizedEvent) -> bool:
        cmd = event.process_command_line.lower()
        return "powershell" in event.process_name.lower() and (
            "-encodedcommand" in cmd
            or "iex(" in cmd
            or "downloadstring" in cmd
            or "invoke-webrequest" in cmd
        )


class CredentialDumpingRule(Rule):
    id = "R002"
    name = "Credential Dumping Indicator"
    severity = "critical"
    tags = ["credential_access", "lsass"]

    def match(self, event: NormalizedEvent) -> bool:
        cmd = event.process_command_line.lower()
        return "lsass" in cmd or "procdump" in cmd or "sekurlsa" in cmd


class LocalAdminAddedRule(Rule):
    id = "R003"
    name = "New Local Admin/User Added"
    severity = "high"
    tags = ["persistence", "privilege_escalation"]

    def match(self, event: NormalizedEvent) -> bool:
        cmd = event.process_command_line.lower()
        return "net user" in cmd and ("/add" in cmd or "administrators" in cmd)


class RareOutboundConnectionRule(Rule):
    id = "R004"
    name = "Unusual Outbound Connection"
    severity = "medium"
    tags = ["command_and_control", "network"]

    rare_domains = {"pastebin.ru", "example-bad-domain.biz", "c2.invalid"}

    def match(self, event: NormalizedEvent) -> bool:
        if event.dest_domain and event.dest_domain.lower() in self.rare_domains:
            return True
        if event.dest_ip and event.dest_ip.startswith("185.227."):
            return True
        return False


class OfficeSpawnShellRule(Rule):
    id = "R005"
    name = "Office Spawning Shell"
    severity = "high"
    tags = ["execution", "initial_access"]

    def match(self, event: NormalizedEvent) -> bool:
        parent = event.parent_process_name.lower()
        child = event.process_name.lower()
        office = ("winword", "excel", "powerpnt", "outlook")
        shells = ("cmd.exe", "powershell", "pwsh")
        return any(proc in parent for proc in office) and any(sh in child for sh in shells)


class WebshellPatternRule(Rule):
    id = "R006"
    name = "Webshell-like Hosting Process Pattern"
    severity = "high"
    tags = ["persistence", "webshell"]

    def match(self, event: NormalizedEvent) -> bool:
        process = event.process_name.lower()
        cmd = event.process_command_line.lower()
        return (
            "php-cgi" in process or "php-fpm" in process or "cron" in process
        ) and ("/tmp/" in cmd or "base64_decode" in cmd or "wget" in cmd)


def load_default_rules() -> list[Rule]:
    return [
        SuspiciousPowerShellRule(),
        CredentialDumpingRule(),
        LocalAdminAddedRule(),
        RareOutboundConnectionRule(),
        OfficeSpawnShellRule(),
        WebshellPatternRule(),
    ]
