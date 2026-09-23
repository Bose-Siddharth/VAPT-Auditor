"""Mobile (Android APK) scanner: static analysis only.

This is a static-analysis tier, not a full mobile pentest: it inspects the
manifest, permissions, and decompiled strings for common misconfigurations.
It does NOT perform dynamic/runtime testing (instrumentation, traffic
interception, etc.) -- that requires a device/emulator and is out of scope
for this tool today.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from app.models import Finding, Severity, TargetType, ToolRunResult

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "Reads SMS messages, often abused to intercept OTP codes.",
    "android.permission.SEND_SMS": "Can send SMS silently, e.g. for premium-rate fraud.",
    "android.permission.RECORD_AUDIO": "Can record audio from the microphone.",
    "android.permission.CAMERA": "Can access the camera.",
    "android.permission.ACCESS_FINE_LOCATION": "Can access precise GPS location.",
    "android.permission.READ_CONTACTS": "Can read the user's contact list.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Can draw over other apps (overlay/clickjacking risk).",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Can write to shared storage.",
    "android.permission.READ_CALL_LOG": "Can read call history.",
}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key", re.compile(r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][a-z0-9]{16,45}[\"']")),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]


def scan(apk_path: str, timeout: int = 300) -> tuple[list[Finding], ToolRunResult]:
    started = datetime.now(timezone.utc)
    findings: list[Finding] = []

    try:
        from androguard.core.apk import APK
    except ImportError:
        finished = datetime.now(timezone.utc)
        return findings, ToolRunResult(
            tool="androguard",
            command=f"androguard static analysis on {apk_path}",
            started_at=started,
            finished_at=finished,
            ok=False,
            error="androguard is not installed",
        )

    try:
        apk = APK(apk_path)
    except Exception as exc:
        finished = datetime.now(timezone.utc)
        return findings, ToolRunResult(
            tool="androguard",
            command=f"androguard static analysis on {apk_path}",
            started_at=started,
            finished_at=finished,
            ok=False,
            error=f"failed to parse APK: {exc}",
        )

    package = apk.get_package() or apk_path

    if apk.get_effective_target_sdk_version() and int(apk.get_effective_target_sdk_version()) < 29:
        findings.append(Finding(
            category=TargetType.MOBILE_APK,
            source_tool="androguard",
            severity=Severity.MEDIUM,
            title="Low targetSdkVersion",
            description=f"targetSdkVersion is {apk.get_effective_target_sdk_version()}, "
                         "which misses newer Android platform security defaults/hardening.",
            affected=package,
            remediation="Raise targetSdkVersion to a current, supported API level.",
        ))

    if apk.is_debuggable():
        findings.append(Finding(
            category=TargetType.MOBILE_APK,
            source_tool="androguard",
            severity=Severity.HIGH,
            title="App is debuggable in production build",
            description="android:debuggable=\"true\" allows attaching a debugger to the running "
                         "app, exposing memory, logic, and stored data.",
            affected=package,
            remediation="Ensure android:debuggable is false (default) in release builds.",
        ))

    if apk.get_attribute_value("application", "allowBackup") in (None, "true"):
        findings.append(Finding(
            category=TargetType.MOBILE_APK,
            source_tool="androguard",
            severity=Severity.LOW,
            title="Backup not explicitly disabled",
            description="android:allowBackup is missing or true, so app data may be extracted "
                         "via adb backup on rooted/debug-enabled devices.",
            affected=package,
            remediation="Set android:allowBackup=\"false\" unless backups are required and vetted.",
        ))

    uses_cleartext = apk.get_attribute_value("application", "usesCleartextTraffic")
    if uses_cleartext == "true":
        findings.append(Finding(
            category=TargetType.MOBILE_APK,
            source_tool="androguard",
            severity=Severity.HIGH,
            title="Cleartext (HTTP) network traffic allowed",
            description="usesCleartextTraffic=\"true\" permits unencrypted HTTP traffic, "
                         "which can be intercepted/tampered with on-path.",
            affected=package,
            remediation="Set usesCleartextTraffic=\"false\" and use a Network Security Config allowlist.",
        ))

    granted_perms = set(apk.get_permissions())
    for perm, desc in DANGEROUS_PERMISSIONS.items():
        if perm in granted_perms:
            findings.append(Finding(
                category=TargetType.MOBILE_APK,
                source_tool="androguard",
                severity=Severity.LOW,
                title=f"Sensitive permission requested: {perm.split('.')[-1]}",
                description=desc,
                affected=package,
                remediation="Remove the permission if unused, or justify/minimize its scope.",
            ))

    for component_getter, kind in (
        (apk.get_activities, "activity"),
        (apk.get_services, "service"),
        (apk.get_receivers, "receiver"),
        (apk.get_providers, "provider"),
    ):
        for name in component_getter():
            exported = apk.get_attribute_value(kind, "exported", name=name)
            if exported == "true":
                findings.append(Finding(
                    category=TargetType.MOBILE_APK,
                    source_tool="androguard",
                    severity=Severity.MEDIUM,
                    title=f"Exported {kind}: {name.split('.')[-1]}",
                    description=f"{kind} '{name}' is exported and reachable by other apps on the device.",
                    affected=package,
                    remediation="Set android:exported=\"false\" unless this component must be "
                                 "callable by other apps, and validate all inputs if it must.",
                ))

    findings.extend(_scan_strings_for_secrets(apk, package))

    finished = datetime.now(timezone.utc)
    return findings, ToolRunResult(
        tool="androguard",
        command=f"androguard static analysis on {apk_path}",
        started_at=started,
        finished_at=finished,
        ok=True,
    )


def _scan_strings_for_secrets(apk, package: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        raw_files = apk.get_files()
    except Exception:
        return findings

    seen = set()
    for name in raw_files:
        if not name.endswith((".xml", ".txt", ".json", ".properties")):
            continue
        try:
            content = apk.get_file(name).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.findall(content):
                key = (label, name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    category=TargetType.MOBILE_APK,
                    source_tool="androguard",
                    severity=Severity.CRITICAL,
                    title=f"Possible hardcoded secret: {label}",
                    description=f"A string matching the pattern for {label} was found embedded in "
                                 f"the app package.",
                    affected=f"{package} :: {name}",
                    remediation="Remove hardcoded secrets; use a secrets manager or fetch at runtime "
                                 "over an authenticated channel, and rotate the exposed credential.",
                ))
    return findings
