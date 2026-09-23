"""Network scanner: Nmap service/version detection + NSE vuln scripts."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from app.models import Finding, Severity, TargetType, ToolRunResult

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

STATE_TO_SEVERITY = {
    "VULNERABLE": Severity.HIGH,
    "LIKELY VULNERABLE": Severity.MEDIUM,
}


def scan(target: str, timeout: int = 900) -> tuple[list[Finding], ToolRunResult]:
    from app.scanners.base import run_command

    args = [
        "nmap",
        "-sV",
        "-O",
        "--script", "vuln",
        "-T4",
        "--host-timeout", "10m",
        "-oX", "-",
        target,
    ]
    result, stdout = run_command("nmap", args, timeout=timeout)
    findings: list[Finding] = []
    if not result.ok or not stdout.strip():
        return findings, result

    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return findings, result

    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else target

        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                findings.append(Finding(
                    category=TargetType.NETWORK,
                    source_tool="nmap",
                    severity=Severity.INFO,
                    title=f"OS fingerprint: {osmatch.get('name')}",
                    description="Nmap OS detection identified the likely operating system, "
                                 "which narrows the attack surface an attacker needs to research.",
                    affected=host_ip,
                    remediation="No action required unless this exposes an unsupported/EOL OS version.",
                ))

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol")
            service = port.find("service")
            svc_name = service.get("name") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            svc_desc = " ".join(filter(None, [product, version])) or svc_name

            findings.append(Finding(
                category=TargetType.NETWORK,
                source_tool="nmap",
                severity=Severity.INFO,
                title=f"Open port {portid}/{proto} ({svc_name})",
                description=f"Service detected: {svc_desc}.",
                affected=f"{host_ip}:{portid}",
                remediation="Confirm this service is intended to be reachable; "
                             "close or firewall ports that don't need to be exposed.",
            ))

            for script in port.findall("script"):
                findings.extend(_parse_vuln_script(script, host_ip, portid))

    return findings, result


def _parse_vuln_script(script_el, host_ip: str, portid: str) -> list[Finding]:
    findings: list[Finding] = []
    script_id = script_el.get("id", "unknown-script")
    output = script_el.get("output", "") or ""

    severity = Severity.INFO
    for marker, sev in STATE_TO_SEVERITY.items():
        if marker in output:
            severity = sev
            break

    if severity == Severity.INFO and "State: NOT VULNERABLE" in output:
        return findings  # don't report negative results as findings

    if severity == Severity.INFO and script_id in ("vulners",):
        # vulners nests one table per CVE; regex over the rendered output
        # is simpler and equally reliable than walking the table/elem tree.
        for cve in set(CVE_RE.findall(output)):
            findings.append(Finding(
                category=TargetType.NETWORK,
                source_tool=f"nmap:{script_id}",
                severity=Severity.HIGH,
                title=f"Possible known vulnerability: {cve}",
                description=f"nmap NSE script '{script_id}' flagged {cve} against the service "
                             f"on port {portid}. Verify applicability to the exact installed version.",
                affected=f"{host_ip}:{portid}",
                reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                remediation="Patch the affected service to a version that resolves this CVE.",
            ))
        return findings

    if severity != Severity.INFO or script_id not in ("vulners",):
        cves = sorted(set(CVE_RE.findall(output)))
        findings.append(Finding(
            category=TargetType.NETWORK,
            source_tool=f"nmap:{script_id}",
            severity=severity,
            title=f"NSE finding: {script_id}",
            description=output.strip()[:1500],
            affected=f"{host_ip}:{portid}",
            reference=", ".join(cves) if cves else None,
            remediation="Review the script output; patch or reconfigure the affected service.",
        ))

    return findings
