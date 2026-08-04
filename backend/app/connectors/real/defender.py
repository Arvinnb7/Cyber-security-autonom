"""Live Microsoft Defender XDR connector (endpoint + email telemetry).

Sign-in and file activity from Microsoft 365 tells you what identities did; it
says nothing about what *ran* on a laptop or what landed in a mailbox. Without
that, malware, ransomware, phishing and lateral movement can never be detected on
real data no matter how good the correlation logic is. This connector supplies
that telemetry from the Defender stack the customer already owns — same Azure AD
app registration as the Microsoft 365 connector, just extra permissions.

Two sources, each degrading independently if its permission is missing:

* ``/security/alerts_v2`` — Defender's own verdicts (malware/ransomware names).
* ``/security/runHuntingQuery`` — raw Advanced Hunting telemetry (KQL).

Every mapping below targets the exact action name and ``raw`` flag that
``app/detection/detectors.py`` reads. Emitting a *nearly* right name is the same
as emitting nothing, so the tests assert the contract rather than the shape.

**Validation status:** mapped and unit-tested against recorded payload shapes;
must be confirmed against a live tenant during a pilot.
"""
from __future__ import annotations

import logging

from app.connectors.base import ActionResult, RawEvent
from app.connectors.real.base import ConnectorError
from app.connectors.real.graph import AzureGraphConnector, parse_ts

logger = logging.getLogger("sentinel.connectors.defender")

# Keep every hunting query bounded — an unbounded result set would be pulled into
# memory each cycle.
HUNT_LIMIT = 500
LOOKBACK = "ago(1h)"

# Subject words typical of credential-harvesting lures (DET-003 cred_keywords).
_CRED_WORDS = ("password", "verify", "account", "sign in", "signin", "login",
               "credential", "expire", "suspend", "urgent", "invoice", "mfa")
# Command-line markers of obfuscated PowerShell (DET-004 powershell_suspicious).
_PS_MARKERS = ("-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
               "bypass", "downloadstring", "iex ", "invoke-expression", "frombase64string")
# Tools typically used to execute code on another host (DET-009 remote_exec).
_REMOTE_EXEC_TOOLS = ("psexec.exe", "paexec.exe", "wmic.exe", "winrs.exe", "wmiprvse.exe")
_ELEVATED = ("system", "administrator", "admin")


def _lower(value) -> str:
    return str(value or "").lower()


class MicrosoftDefenderConnector(AzureGraphConnector):
    provider = "microsoft_defender"
    supported_actions = ("isolate_host",)
    required_permission = "SecurityAlert.Read.All and ThreatHunting.Read.All"

    # --- collection -------------------------------------------------------

    def fetch_events(self, cursor: str | None = None) -> list[RawEvent]:
        token = self._token()
        events: list[RawEvent] = []
        # Each source is optional: a tenant may license Defender for Endpoint but
        # not Defender for Office 365, or withhold a permission. Losing one must
        # not cost us the others.
        for name, collect in (("alerts", self._alerts),
                              ("hunting", self._hunting)):
            try:
                events.extend(collect(token))
            except ConnectorError as exc:
                logger.info("defender %s unavailable: %s", name, exc)
        return events

    def _alerts(self, token: str) -> list[RawEvent]:
        """Defender's own detections — the highest-confidence signal available."""
        out: list[RawEvent] = []
        query = f"security/alerts_v2?$top={HUNT_LIMIT}&$orderby=createdDateTime desc"
        for alert in self._get(token, query):
            title = alert.get("title") or ""
            evidence = alert.get("evidence") or []
            device = next((e.get("deviceDnsName") for e in evidence if e.get("deviceDnsName")), None)
            user = next((e.get("userAccount", {}).get("userPrincipalName")
                         for e in evidence if e.get("userAccount")), None)
            file_hashes = [e.get("sha256") for e in evidence if e.get("sha256")]
            out.append(RawEvent(
                source=self.provider,
                timestamp=parse_ts(alert.get("createdDateTime")),
                category="alert",
                # DET-004 malicious_hash_match / DET-005 known_ransomware_tool both
                # key off this action; the signature string carries the verdict.
                action="malware_detected",
                actor_username=user,
                target_asset=device or alert.get("assignedTo") or "endpoint",
                severity=self._severity(alert.get("severity")),
                raw={
                    "signature": title,
                    "hash_match": bool(file_hashes),
                    "hash": file_hashes[0] if file_hashes else None,
                    "category": alert.get("category"),
                    "determination": alert.get("determination"),
                    "alert_id": alert.get("id"),
                },
            ))
        return out

    @staticmethod
    def _severity(value: str | None) -> int:
        return {"informational": 1, "low": 2, "medium": 3, "high": 4}.get(_lower(value), 3)

    def _hunt(self, token: str, query: str) -> list[dict]:
        body = self._post(token, "security/runHuntingQuery", {"Query": query})
        return body.get("results", []) or []

    def _hunting(self, token: str) -> list[RawEvent]:
        """Raw Advanced Hunting telemetry, one small query per detector need."""
        out: list[RawEvent] = []
        for label, query, mapper in (
            ("email", self._q_email(), self._map_email),
            ("process", self._q_process(), self._map_process),
            ("device_events", self._q_device_events(), self._map_device_event),
            ("file", self._q_files(), self._map_file),
            ("logon", self._q_logons(), self._map_logon),
        ):
            try:
                rows = self._hunt(token, query)
            except ConnectorError as exc:
                logger.info("defender hunting/%s unavailable: %s", label, exc)
                continue
            for row in rows:
                event = mapper(row)
                if event:
                    out.append(event)
        return out

    # --- queries ----------------------------------------------------------
    # Projected to just the columns the mappers use, and capped.

    def _q_email(self) -> str:
        return (f"EmailEvents | where Timestamp > {LOOKBACK} "
                "| project Timestamp, SenderFromDomain, SenderFromAddress, RecipientEmailAddress, "
                "Subject, ThreatTypes, DetectionMethods, AttachmentCount, UrlCount, "
                "AuthenticationDetails, SenderIPv4 "
                f"| take {HUNT_LIMIT}")

    def _q_process(self) -> str:
        return (f"DeviceProcessEvents | where Timestamp > {LOOKBACK} "
                "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, "
                "SHA256, InitiatingProcessFileName "
                f"| take {HUNT_LIMIT}")

    def _q_device_events(self) -> str:
        return (f"DeviceEvents | where Timestamp > {LOOKBACK} "
                "| where ActionType has_any ('ShadowCopyDeleted', 'AntivirusDisabled', "
                "'TamperProtectionDisabled', 'SecurityControlDisabled') "
                "| project Timestamp, DeviceName, AccountName, ActionType "
                f"| take {HUNT_LIMIT}")

    def _q_files(self) -> str:
        return (f"DeviceFileEvents | where Timestamp > {LOOKBACK} "
                "| where ActionType has_any ('FileRenamed', 'FileModified') "
                "| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath "
                f"| take {HUNT_LIMIT}")

    def _q_logons(self) -> str:
        return (f"DeviceLogonEvents | where Timestamp > {LOOKBACK} "
                "| where LogonType in ('RemoteInteractive', 'Network') "
                "| project Timestamp, DeviceName, AccountName, LogonType, RemoteDeviceName, RemoteIP "
                f"| take {HUNT_LIMIT}")

    # --- mappers ----------------------------------------------------------

    def _map_email(self, r: dict) -> RawEvent | None:
        """DET-003: phishing is judged per sender domain over these flags."""
        threats = _lower(r.get("ThreatTypes"))
        methods = _lower(r.get("DetectionMethods"))
        auth = _lower(r.get("AuthenticationDetails"))
        subject = _lower(r.get("Subject"))
        return RawEvent(
            source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="email",
            action="email_received",
            actor_username=r.get("RecipientEmailAddress"),
            src_ip=r.get("SenderIPv4"), target_asset="exchange-online", severity=3,
            raw={
                "sender_domain": r.get("SenderFromDomain") or "unknown",
                "sender": r.get("SenderFromAddress"),
                "malicious_url": ("phish" in threats or "malware" in threats)
                                 and int(r.get("UrlCount") or 0) > 0,
                "attachment": int(r.get("AttachmentCount") or 0) > 0
                              and ("malware" in threats or "phish" in threats),
                "lookalike_domain": "spoof" in threats or "spoof" in methods
                                    or "impersonation" in methods,
                "auth_fail": "fail" in auth,
                "cred_keywords": any(w in subject for w in _CRED_WORDS),
                "subject": r.get("Subject"),
                "threat_types": r.get("ThreatTypes"),
            },
        )

    def _map_process(self, r: dict) -> RawEvent | None:
        """DET-004 (malware) and DET-009 (remote execution tooling)."""
        name = _lower(r.get("FileName"))
        cmdline = _lower(r.get("ProcessCommandLine"))
        account = _lower(r.get("AccountName"))
        device = r.get("DeviceName")
        # Tools whose whole purpose is running code on another machine.
        if name in _REMOTE_EXEC_TOOLS:
            return RawEvent(
                source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="process",
                action="remote_exec", actor_username=r.get("AccountName"),
                target_asset=device, severity=4,
                raw={"process": r.get("FileName"), "cmdline": r.get("ProcessCommandLine")},
            )
        return RawEvent(
            source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="process",
            action="process_start", actor_username=r.get("AccountName"),
            target_asset=device, severity=3,
            raw={
                "process": r.get("FileName"),
                "hash": r.get("SHA256"),
                # Unsigned/unknown binaries surface as a missing hash in hunting data.
                "unknown_hash": not r.get("SHA256"),
                "powershell_suspicious": name in ("powershell.exe", "pwsh.exe")
                                         and any(m in cmdline for m in _PS_MARKERS),
                "privileged": account in _ELEVATED,
                "cmdline": r.get("ProcessCommandLine"),
            },
        )

    def _map_device_event(self, r: dict) -> RawEvent | None:
        """DET-005 shadow-copy deletion, DET-007 security-control tampering."""
        action_type = _lower(r.get("ActionType"))
        if "shadowcopy" in action_type:
            action = "shadow_copy_delete"
        else:
            action = "security_control_disabled"
        return RawEvent(
            source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="process",
            action=action, actor_username=r.get("AccountName"),
            target_asset=r.get("DeviceName"), severity=4,
            raw={"action_type": r.get("ActionType")},
        )

    def _map_file(self, r: dict) -> RawEvent | None:
        """DET-005: a burst of renames on one device is the encryption signature."""
        folder = str(r.get("FolderPath") or "")
        return RawEvent(
            source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="file",
            action="file_rename", actor_username=r.get("AccountName"),
            target_asset=r.get("DeviceName"), severity=3,
            raw={
                "file": r.get("FileName"),
                "folder": folder,
                # UNC path => the encryption is reaching across the network.
                "network_share": folder.startswith("\\\\"),
                "action_type": r.get("ActionType"),
            },
        )

    def _map_logon(self, r: dict) -> RawEvent | None:
        """DET-009: interactive logons onto other hosts."""
        logon_type = _lower(r.get("LogonType"))
        return RawEvent(
            source=self.provider, timestamp=parse_ts(r.get("Timestamp")), category="authentication",
            action="remote_login", actor_username=r.get("AccountName"),
            src_ip=r.get("RemoteIP"), target_asset=r.get("DeviceName"), severity=3,
            raw={
                "logon_type": r.get("LogonType"),
                # RDP is the protocol attackers pivot with once they hold creds.
                "admin_protocol": logon_type == "remoteinteractive",
                "remote_device": r.get("RemoteDeviceName"),
            },
        )

    # --- response ---------------------------------------------------------

    def execute_action(self, action_type: str, target: str) -> ActionResult:
        """Isolate a compromised host — the containment step for ransomware."""
        if action_type not in self.supported_actions:
            return ActionResult(success=False, detail=f"microsoft_defender cannot perform '{action_type}'")
        if not target:
            return ActionResult(success=False, detail="no target device specified")
        token = self._token()
        code, text = self._write(
            token, "POST", f"security/machines/{target}/isolate",
            {"comment": "Isolated by Sentinel after manager approval", "isolationType": "full"})
        if code in (200, 201, 202, 204):
            return ActionResult(success=True, detail=f"isolated device {target} from the network")
        if code == 403:
            return ActionResult(
                success=False,
                detail="access denied — grant application permission 'Machine.Isolate' and admin-consent it")
        return ActionResult(success=False, detail=f"Defender error ({code}): {text[:200]}")
