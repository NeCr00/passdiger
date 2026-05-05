#!/usr/bin/env python3
"""
passdiger - Active Directory Credential Exposure Auditor

Audits Active Directory object attributes for inadvertently exposed
credentials, secrets, tokens, API keys, and connection strings.

Inspects both well-known credential-prone fields (description, comment,
info, etc.) and every custom (schema-extended) attribute in the directory.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import math
import re
import ssl
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

def _require_ldap3() -> Any:
    """Import ldap3 lazily so --help and the detector work without it installed."""
    try:
        import ldap3  # type: ignore
        from ldap3.core.exceptions import LDAPException  # type: ignore
    except ImportError:
        sys.stderr.write(
            "ERROR: the 'ldap3' package is required.\n"
            "       Install it with:  pip install ldap3\n"
        )
        sys.exit(2)
    return ldap3, LDAPException


# ---------------------------------------------------------------------------
# Constants and tuning
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

SEV_LOW = "LOW"
SEV_MEDIUM = "MEDIUM"
SEV_HIGH = "HIGH"
SEV_CRITICAL = "CRITICAL"

SEVERITY_RANK = {SEV_LOW: 1, SEV_MEDIUM: 2, SEV_HIGH: 3, SEV_CRITICAL: 4}

# Bit flag in attributeSchema.systemFlags marking schema base objects.
# An attribute that has this flag set ships with AD; one that does not
# was added later, almost always by a schema extension or a customer.
FLAG_SCHEMA_BASE_OBJECT = 0x10

# The "credential-prone" attributes that AD admins routinely (and often
# accidentally) use to store passwords, recovery keys, vendor secrets, etc.
COMMON_INSPECTION_ATTRS = {
    "description",
    "comment",
    "info",
    "displayname",
    "notes",
    "title",
    "department",
    "company",
    "physicaldeliveryofficename",
    "wwwhomepage",
    "url",
    "useraccountcontrol",
    "userpassword",
    "unixuserpassword",
    "ms-mcs-admpwd",
    "ms-laps-password",
    "ms-laps-encryptedpassword",
    "ms-laps-encryptedpasswordhistory",
    "scriptpath",
    "homedirectory",
    "profilepath",
    "employeenumber",
    "employeeid",
    "personaltitle",
    "carlicense",
    "homephone",
    "mobile",
    "pager",
    "telephonenumber",
    "facsimiletelephonenumber",
    "ipphone",
    "otherhomephone",
    "othertelephone",
    "othermobile",
    "otherpager",
    "otheripphone",
    "otherfacsimiletelephonenumber",
    "streetaddress",
    "postaladdress",
    "postofficebox",
    "userprincipalname",
    "samaccountname",
}
COMMON_INSPECTION_ATTRS.update({f"extensionattribute{i}" for i in range(1, 16)})

# Attributes that are large, binary, or that contain operational data we
# never want to scan or print. Matching is case-insensitive.
SKIP_ATTRS = {
    "objectsid",
    "objectguid",
    "thumbnailphoto",
    "jpegphoto",
    "userpkcs12",
    "usercertificate",
    "cacertificate",
    "msexchmailboxsecuritydescriptor",
    "ntsecuritydescriptor",
    "msds-allowedtoactonbehalfofotheridentity",
    "msds-keycredentiallink",
    "logonhours",
    "dnscord",
    "dnsrecord",
    "dnsproperty",
    "registeredaddress",
    "auditingpolicy",
    "tokengroups",
    "tokengroupsglobalanduniversal",
    "tokengroupsnogcacceptable",
    # Hashes & blobs we cannot meaningfully inspect or that are hashes.
    "ntpwdhistory",
    "lmpwdhistory",
    "unicodepwd",
    "supplementalcredentials",
    "dbcsfwd",
    "msds-revealedusers",
    "msds-revealedlist",
    "schemaidguid",
    "attributesecurityguid",
}

# Default object filter focuses on directory principals where credentials
# are most commonly leaked. Override with --filter for full scope.
DEFAULT_OBJECT_FILTER = (
    "(|"
    "(objectClass=user)"
    "(objectClass=computer)"
    "(objectClass=group)"
    "(objectClass=contact)"
    "(objectClass=msDS-ManagedServiceAccount)"
    "(objectClass=msDS-GroupManagedServiceAccount)"
    "(objectClass=organizationalUnit)"
    "(objectClass=foreignSecurityPrincipal)"
    "(objectClass=inetOrgPerson)"
    ")"
)


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Each pattern carries: regex, label, base confidence, severity.
# Confidence is a 0-100 integer expressing how strongly a match implies a
# real secret. Severity expresses the impact if it really is a secret.
PATTERNS: List[Tuple[str, "re.Pattern[str]", int, str]] = [
    (
        "password_keyvalue",
        re.compile(
            r"(?ix)\b(password|passwd|pwd|pass|secret|passphrase)\s*[:=]\s*"
            r"(?P<val>(?:\"[^\"\n]{2,200}\"|'[^'\n]{2,200}'|[^\s,;'\"<>]{3,200}))"
        ),
        92,
        SEV_CRITICAL,
    ),
    (
        "default_password_phrase",
        re.compile(
            r"(?i)\b(default|temp(orary)?|initial|new|admin|service|root)\s+"
            r"(password|passwd|pwd|pass)\b[^a-zA-Z0-9]{1,4}"
            r"(?P<val>[^\s,;'\"<>]{3,80})"
        ),
        88,
        SEV_CRITICAL,
    ),
    (
        "credential_keyvalue",
        re.compile(
            r"(?ix)\b(api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token"
            r"|bearer|token|client[_-]?secret)\s*[:=]\s*"
            r"(?P<val>(?:\"[^\"\n]{4,200}\"|'[^'\n]{4,200}'|[^\s,;'\"<>]{6,200}))"
        ),
        90,
        SEV_HIGH,
    ),
    (
        "sql_connection_string",
        re.compile(
            r"(?ix)(server|data\s*source|host|address|addr)\s*=\s*[^;]{3,200};"
            r"[^=]{0,400}?(password|pwd)\s*=\s*(?P<val>[^;]+)"
        ),
        96,
        SEV_CRITICAL,
    ),
    (
        "url_with_credentials",
        re.compile(
            r"(?i)\b([a-z][a-z0-9+\-.]{1,15}://)"
            r"(?P<user>[^:/?\s@]{1,100}):"
            r"(?P<val>[^@/?\s]{2,200})@"
        ),
        96,
        SEV_CRITICAL,
    ),
    (
        "private_key_pem",
        re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        99,
        SEV_CRITICAL,
    ),
    (
        "ssh_private_key_block",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        99,
        SEV_CRITICAL,
    ),
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        92,
        SEV_HIGH,
    ),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?ix)(aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*"
            r"['\"]?(?P<val>[A-Za-z0-9/+=]{40})['\"]?"
        ),
        94,
        SEV_CRITICAL,
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        98,
        SEV_CRITICAL,
    ),
    (
        "slack_token",
        re.compile(r"\bxox[bpoarsu]-[A-Za-z0-9-]{10,200}\b"),
        93,
        SEV_HIGH,
    ),
    (
        "stripe_secret",
        re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{20,128}\b"),
        97,
        SEV_CRITICAL,
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        92,
        SEV_HIGH,
    ),
    (
        "azure_storage_key",
        re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;.*?AccountKey="
            r"(?P<val>[A-Za-z0-9+/=]{40,})"
        ),
        97,
        SEV_CRITICAL,
    ),
    (
        "jwt_token",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
        85,
        SEV_HIGH,
    ),
    (
        "hash_md5",
        re.compile(r"\b[a-f0-9]{32}\b"),
        25,
        SEV_LOW,
    ),
    (
        "hash_sha1",
        re.compile(r"\b[a-f0-9]{40}\b"),
        30,
        SEV_LOW,
    ),
    (
        "hash_ntlm_pair",
        re.compile(r"\b[A-F0-9]{32}:[A-F0-9]{32}\b"),
        90,
        SEV_HIGH,
    ),
    (
        "bcrypt_hash",
        re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
        96,
        SEV_HIGH,
    ),
    (
        "shadow_hash",
        re.compile(r"\$[156]\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}"),
        95,
        SEV_HIGH,
    ),
]

# Keywords used for context-based detection inside otherwise opaque blobs.
CREDENTIAL_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "auth",
    "private_key",
    "private key",
    "access_key",
    "client_secret",
    "session",
)

# Placeholder values we should never flag (asterisks, x's, lorem ipsum, etc.)
PLACEHOLDER_VALUES = re.compile(
    r"^(?:"
    r"x+|X+|\*+|\.+|-+|<.*?>|\[.*?\]|"
    r"none|null|nil|n/?a|todo|tbd|pending|"
    r"changeme|placeholder|example|sample|test|demo|"
    r"redacted|hidden|removed|secret"
    r")$",
    re.IGNORECASE,
)

# Patterns we should never treat as a secret even if they look high-entropy.
NON_SECRET_PATTERNS = (
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
    re.compile(r"^S-1-(?:\d+-){1,15}\d+$"),  # SIDs
    re.compile(r"^\d+(?:\.\d+){2,}$"),  # version numbers
    re.compile(r"^\d{4}-\d{2}-\d{2}"),  # ISO dates
    re.compile(r"^[+\d][\d \-().]{6,}$"),  # phone numbers
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    object_dn: str
    object_class: str
    attribute_name: str
    attribute_classification: str  # 'built-in', 'custom', or 'unknown'
    detection_type: str
    severity: str
    confidence: int
    matched_value: str
    full_value: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CustomAttributeDump:
    object_dn: str
    object_class: str
    attribute_name: str
    value: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    started_at: str
    finished_at: str
    domain: str
    domain_controller: str
    base_dn: str
    bind: str
    objects_scanned: int
    attributes_scanned: int
    findings: List[Finding] = field(default_factory=list)
    custom_attribute_dump: List[CustomAttributeDump] = field(default_factory=list)
    builtin_attribute_count: int = 0
    custom_attribute_count: int = 0
    schema_resolved: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "domain": self.domain,
            "domain_controller": self.domain_controller,
            "base_dn": self.base_dn,
            "bind": self.bind,
            "objects_scanned": self.objects_scanned,
            "attributes_scanned": self.attributes_scanned,
            "schema_resolved": self.schema_resolved,
            "builtin_attribute_count": self.builtin_attribute_count,
            "custom_attribute_count": self.custom_attribute_count,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "custom_attribute_dump": [c.to_dict() for c in self.custom_attribute_dump],
        }

    def summary(self) -> Dict[str, int]:
        counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_LOW: 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        counts["TOTAL"] = len(self.findings)
        return counts


# ---------------------------------------------------------------------------
# Credential detection engine
# ---------------------------------------------------------------------------


class CredentialDetector:
    """Multi-stage detector with confidence scoring.

    Stage 1: regex pattern matching for well-known secret formats.
    Stage 2: encoding decoders (base64, hex) - re-scan decoded text.
    Stage 3: keyword-context entropy scoring for free-form notes.
    """

    def __init__(self, min_confidence: int = 50) -> None:
        self.min_confidence = min_confidence

    def detect(self, value: str) -> List[Tuple[str, str, int, str, str]]:
        """Return list of (detection_type, matched_value, confidence, severity, notes)."""
        results: List[Tuple[str, str, int, str, str]] = []
        if not value or not isinstance(value, str):
            return results

        stripped = value.strip()
        if len(stripped) < 4:
            return results
        if PLACEHOLDER_VALUES.fullmatch(stripped):
            return results
        if any(p.fullmatch(stripped) for p in NON_SECRET_PATTERNS):
            return results

        # Stage 1: pattern matching on raw value
        for label, pattern, base_conf, severity in PATTERNS:
            for match in pattern.finditer(value):
                matched_text = match.group("val") if "val" in match.groupdict() and match.group("val") else match.group(0)
                conf, note = self._adjust_confidence(label, matched_text, base_conf)
                if conf < self.min_confidence:
                    continue
                results.append((label, _truncate(matched_text, 200), conf, severity, note))

        # Stage 2: try to decode base64 / hex blobs and re-scan
        decoded = self._maybe_base64_decode(stripped)
        if decoded is not None:
            for label, pattern, base_conf, severity in PATTERNS:
                for match in pattern.finditer(decoded):
                    matched_text = match.group(0)
                    conf = max(60, base_conf - 15)
                    results.append(
                        (
                            f"base64_then_{label}",
                            _truncate(matched_text, 200),
                            conf,
                            severity,
                            "Decoded from base64 before matching",
                        )
                    )
            for kw in CREDENTIAL_KEYWORDS:
                if kw in decoded.lower():
                    results.append(
                        (
                            "base64_credential_keyword",
                            _truncate(decoded, 200),
                            72,
                            SEV_HIGH,
                            f"Base64 decoded text contains '{kw}'",
                        )
                    )
                    break

        decoded_hex = self._maybe_hex_decode(stripped)
        if decoded_hex is not None:
            for kw in CREDENTIAL_KEYWORDS:
                if kw in decoded_hex.lower():
                    results.append(
                        (
                            "hex_credential_keyword",
                            _truncate(decoded_hex, 200),
                            70,
                            SEV_HIGH,
                            f"Hex decoded text contains '{kw}'",
                        )
                    )
                    break

        # Stage 3: keyword-context entropy heuristic for free-form text
        ctx = self._keyword_context(value)
        if ctx is not None:
            label, snippet, conf, severity, note = ctx
            if conf >= self.min_confidence:
                results.append((label, _truncate(snippet, 200), conf, severity, note))

        return _dedupe_results(results)

    @staticmethod
    def _adjust_confidence(label: str, matched: str, base_conf: int) -> Tuple[int, str]:
        """Apply value-aware confidence tweaks and return a note if applicable."""
        notes: List[str] = []
        conf = base_conf
        if not matched:
            return 0, ""

        clean = matched.strip().strip("\"'")

        # Trim placeholder-y values aggressively.
        if PLACEHOLDER_VALUES.fullmatch(clean):
            return 0, ""

        # Hash-only patterns produce a lot of false positives in GUID-like fields;
        # require the value to look like a real hex hash and not part of a longer string.
        if label in {"hash_md5", "hash_sha1"}:
            if not re.fullmatch(r"[a-f0-9]+", clean):
                conf -= 10
            else:
                # We boost slightly if the hash sits in a value of comparable length.
                conf += 5
            notes.append("Hash-shaped value; verify it is not an internal ID")

        # AWS access keys are extremely specific - keep base.
        # Generic 40-char base64ish secrets need value scrutiny.
        if label == "aws_secret_access_key":
            entropy = _shannon_entropy(clean)
            if entropy < 4.0:
                conf -= 25
                notes.append(f"Low entropy ({entropy:.2f}) for AWS secret")

        # Connection-string passwords sometimes match placeholder text;
        # short or alphanumeric-only values get a small bump down.
        if label == "sql_connection_string" and len(clean) < 4:
            conf -= 30

        # password_keyvalue: avoid flagging "password reset link" prose.
        if label == "password_keyvalue":
            if clean.lower() in {"reset", "expired", "set", "change", "new", "required", "policy"}:
                return 0, ""
            if len(clean) < 4:
                conf -= 20

        return max(0, min(100, conf)), "; ".join(notes)

    @staticmethod
    def _maybe_base64_decode(value: str) -> Optional[str]:
        """Return decoded text if value plausibly encodes printable text."""
        token = value.strip().split()[-1] if value.strip() else value
        token = token.strip(",;\"'")
        if not (12 <= len(token) <= 4096):
            return None
        if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
            return None
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
        except Exception:
            return None
        try:
            decoded = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded = decoded_bytes.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
        if not decoded:
            return None
        printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
        if printable / len(decoded) < 0.85:
            return None
        return decoded

    @staticmethod
    def _maybe_hex_decode(value: str) -> Optional[str]:
        token = value.strip()
        if not (16 <= len(token) <= 4096):
            return None
        if len(token) % 2:
            return None
        if not re.fullmatch(r"[0-9a-fA-F]+", token):
            return None
        try:
            decoded_bytes = bytes.fromhex(token)
        except ValueError:
            return None
        try:
            decoded = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded = decoded_bytes.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
        printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
        if printable / len(decoded) < 0.85:
            return None
        return decoded

    @staticmethod
    def _keyword_context(value: str) -> Optional[Tuple[str, str, int, str, str]]:
        """Look for 'keyword <separator> token' where token has high entropy."""
        for kw in CREDENTIAL_KEYWORDS:
            pattern = re.compile(
                rf"(?i)\b{re.escape(kw)}\b\s*(?:is|:|=|->)\s*"
                rf"['\"`]?(?P<tok>[^\s,;'\"`<>]{{4,80}})['\"`]?"
            )
            match = pattern.search(value)
            if not match:
                continue
            token = match.group("tok")
            if PLACEHOLDER_VALUES.fullmatch(token):
                continue
            entropy = _shannon_entropy(token)
            if entropy < 2.5 and not any(c.isdigit() for c in token):
                continue
            confidence = 60
            if entropy >= 3.5:
                confidence = 75
            if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
                confidence += 5
            severity = SEV_HIGH if entropy >= 3.5 else SEV_MEDIUM
            return (
                "keyword_context_secret",
                f"{kw}: {token}",
                min(confidence, 90),
                severity,
                f"'{kw}' followed by entropy={entropy:.2f} token",
            )
        return None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def _dedupe_results(
    results: Sequence[Tuple[str, str, int, str, str]]
) -> List[Tuple[str, str, int, str, str]]:
    seen: Dict[Tuple[str, str], Tuple[str, str, int, str, str]] = {}
    for r in results:
        key = (r[0], r[1])
        if key not in seen or seen[key][2] < r[2]:
            seen[key] = r
    return list(seen.values())


# ---------------------------------------------------------------------------
# LDAP layer
# ---------------------------------------------------------------------------


def build_server(
    host: str,
    port: Optional[int],
    use_ssl: bool,
    verify_cert: bool,
    timeout: int,
) -> Any:
    """Configure an ldap3 Server with sane TLS defaults."""
    ldap3, _ = _require_ldap3()
    tls = None
    if use_ssl:
        if verify_cert:
            tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
        else:
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    return ldap3.Server(
        host=host,
        port=port,
        use_ssl=use_ssl,
        get_info=ldap3.ALL,
        connect_timeout=timeout,
        tls=tls,
    )


def open_connection(
    server: Any,
    username: Optional[str],
    password: Optional[str],
    domain: str,
    auth_mode: str,
    timeout: int,
) -> Any:
    """Open and bind an LDAP connection.

    auth_mode: 'auto' | 'simple' | 'ntlm' | 'anonymous'
    """
    ldap3, _ = _require_ldap3()
    auth_kwargs: Dict[str, Any] = {
        "auto_bind": True,
        "raise_exceptions": True,
        "receive_timeout": timeout,
    }

    mode = auth_mode.lower()
    if mode == "anonymous" or (mode == "auto" and not username):
        return ldap3.Connection(
            server,
            authentication=ldap3.ANONYMOUS,
            **auth_kwargs,
        )

    if not username:
        raise ValueError("Username is required for non-anonymous bind")

    pw = password or ""
    if mode == "ntlm" or (mode == "auto" and ("\\" in username or _looks_like_netbios(username))):
        ntlm_user = username if "\\" in username else f"{_netbios_from_domain(domain)}\\{username}"
        return ldap3.Connection(
            server,
            user=ntlm_user,
            password=pw,
            authentication=ldap3.NTLM,
            **auth_kwargs,
        )

    # Default: simple bind. Build a UPN if the user passed a bare sam name.
    bind_user = username
    if "@" not in bind_user and "," not in bind_user and "\\" not in bind_user:
        bind_user = f"{username}@{domain}" if domain else username
    return ldap3.Connection(
        server,
        user=bind_user,
        password=pw,
        authentication=ldap3.SIMPLE,
        **auth_kwargs,
    )


def _looks_like_netbios(user: str) -> bool:
    return "@" not in user and "," not in user and " " not in user


def _netbios_from_domain(domain: str) -> str:
    if not domain:
        return ""
    return domain.split(".")[0].upper()


def discover_root_info(server: Any) -> Dict[str, Any]:
    """Pull rootDSE information for fallback base DN and schema DN discovery."""
    info: Dict[str, Any] = {}
    if not server.info:
        return info
    try:
        info["default_naming_context"] = (
            server.info.other.get("defaultNamingContext", [None])[0]
        )
        info["schema_naming_context"] = (
            server.info.other.get("schemaNamingContext", [None])[0]
        )
        info["config_naming_context"] = (
            server.info.other.get("configurationNamingContext", [None])[0]
        )
    except Exception:
        pass
    return info


def classify_attributes(
    conn: Any, schema_dn: str
) -> Tuple[Set[str], Set[str]]:
    """Classify schema attributes into (built-in, custom) sets via systemFlags."""
    ldap3, _ = _require_ldap3()
    builtin: Set[str] = set()
    custom: Set[str] = set()
    if not schema_dn:
        return builtin, custom

    conn.search(
        search_base=schema_dn,
        search_filter="(objectClass=attributeSchema)",
        search_scope=ldap3.SUBTREE,
        attributes=["lDAPDisplayName", "systemFlags"],
        paged_size=500,
    )
    for entry in conn.entries:
        try:
            name = str(entry.lDAPDisplayName).lower()
        except Exception:
            continue
        try:
            raw = entry.systemFlags.value if "systemFlags" in entry else None
            flags = int(raw) if raw not in (None, "", []) else 0
        except (ValueError, TypeError):
            flags = 0
        if flags & FLAG_SCHEMA_BASE_OBJECT:
            builtin.add(name)
        else:
            custom.add(name)
    return builtin, custom


def paged_object_search(
    conn: Any,
    base_dn: str,
    ldap_filter: str,
    page_size: int = 500,
) -> Iterable[Dict[str, Any]]:
    """Paged search returning each entry as a dict-like view."""
    ldap3, _ = _require_ldap3()
    generator = conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=ldap_filter,
        search_scope=ldap3.SUBTREE,
        attributes=["*", "+"],
        paged_size=page_size,
        generator=True,
    )
    for entry in generator:
        # Skip referrals and other non-entry results.
        if entry.get("type") != "searchResEntry":
            continue
        yield entry


# ---------------------------------------------------------------------------
# Audit core
# ---------------------------------------------------------------------------


def coerce_value(raw: Any) -> Optional[str]:
    """Convert ldap3 attribute payloads to a printable string for inspection."""
    if raw is None:
        return None
    if isinstance(raw, list):
        # Collapse multi-valued attrs into newline-separated strings for scanning.
        parts = [coerce_value(v) for v in raw]
        parts = [p for p in parts if p]
        return "\n".join(parts) if parts else None
    if isinstance(raw, (bytes, bytearray)):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
    if isinstance(raw, (int, float, bool)):
        return str(raw)
    if isinstance(raw, datetime):
        return raw.isoformat()
    return str(raw)


def attribute_classification(
    name: str, builtin: Set[str], custom: Set[str]
) -> str:
    n = name.lower()
    if n in builtin:
        return "built-in"
    if n in custom:
        return "custom"
    if n in COMMON_INSPECTION_ATTRS:
        return "built-in"
    return "unknown"


def is_skippable_attribute(name: str) -> bool:
    return name.lower() in SKIP_ATTRS


def first_object_class(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        if not value:
            return ""
        # The leaf object class is the most specific; pick the last one.
        return str(value[-1])
    return str(value)


def audit_entry(
    entry: Dict[str, Any],
    detector: CredentialDetector,
    builtin_attrs: Set[str],
    custom_attrs: Set[str],
    show_all_custom: bool,
    inspect_only_common: bool,
) -> Tuple[List[Finding], List[CustomAttributeDump], int]:
    """Audit a single search entry, returning findings and the dump rows."""
    findings: List[Finding] = []
    dumps: List[CustomAttributeDump] = []

    dn = entry.get("dn") or entry.get("raw_dn") or "<unknown DN>"
    attrs = entry.get("attributes", {}) or {}
    obj_classes = attrs.get("objectClass", [])
    obj_class = first_object_class(obj_classes)

    attrs_scanned = 0
    for attr_name, raw_value in attrs.items():
        if is_skippable_attribute(attr_name):
            continue
        coerced = coerce_value(raw_value)
        if coerced is None or not coerced.strip():
            continue

        cls = attribute_classification(attr_name, builtin_attrs, custom_attrs)
        is_common = attr_name.lower() in COMMON_INSPECTION_ATTRS
        is_custom = cls == "custom"

        # Stage 1: always inspect common credential-prone attributes.
        # Stage 2: inspect every custom attribute.
        # If --only-common, skip custom unless they are also in COMMON list.
        should_scan = is_common or (is_custom and not inspect_only_common)
        if not should_scan and cls == "unknown":
            # 'unknown' (= attribute name not seen in schema) is rare; treat as custom-like
            should_scan = not inspect_only_common

        if should_scan:
            attrs_scanned += 1
            for label, matched, conf, sev, note in detector.detect(coerced):
                findings.append(
                    Finding(
                        object_dn=dn,
                        object_class=obj_class,
                        attribute_name=attr_name,
                        attribute_classification=cls,
                        detection_type=label,
                        severity=sev,
                        confidence=conf,
                        matched_value=matched,
                        full_value=_truncate(coerced, 500),
                        notes=note,
                    )
                )

        # Always-dump-custom for visibility.
        if show_all_custom and is_custom:
            dumps.append(
                CustomAttributeDump(
                    object_dn=dn,
                    object_class=obj_class,
                    attribute_name=attr_name,
                    value=_truncate(coerced, 500),
                )
            )

    return findings, dumps, attrs_scanned


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def format_table(report: AuditReport, mask: bool) -> str:
    findings = sorted(
        report.findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.object_dn),
    )
    out = io.StringIO()
    _write_header(out, report)

    if not findings:
        out.write("\nNo credential exposures detected.\n")
    else:
        out.write(f"\nFindings ({len(findings)}):\n")
        rows = [
            ["#", "SEV", "CONF", "CLASS", "ATTRIBUTE", "DETECTION", "OBJECT", "VALUE"]
        ]
        for i, f in enumerate(findings, 1):
            rows.append(
                [
                    str(i),
                    f.severity,
                    str(f.confidence),
                    f.attribute_classification,
                    f.attribute_name,
                    f.detection_type,
                    _shorten_dn(f.object_dn, 60),
                    _mask(f.matched_value, mask),
                ]
            )
        out.write(_render_table(rows))

    if report.custom_attribute_dump:
        out.write(
            f"\nCustom attribute dump ({len(report.custom_attribute_dump)} entries):\n"
        )
        rows = [["OBJECT", "CLASS", "ATTRIBUTE", "VALUE"]]
        for d in report.custom_attribute_dump:
            rows.append(
                [
                    _shorten_dn(d.object_dn, 60),
                    d.object_class,
                    d.attribute_name,
                    _mask(_truncate(d.value, 80), mask),
                ]
            )
        out.write(_render_table(rows))

    out.write("\n")
    out.write(_format_summary(report))
    return out.getvalue()


def format_json(report: AuditReport, mask: bool) -> str:
    payload = report.to_dict()
    if mask:
        for f in payload["findings"]:
            f["matched_value"] = _mask(f["matched_value"], True)
            f["full_value"] = _mask(f["full_value"], True)
        for c in payload["custom_attribute_dump"]:
            c["value"] = _mask(c["value"], True)
    return json.dumps(payload, indent=2, default=str)


def format_csv(report: AuditReport, mask: bool) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        [
            "object_dn",
            "object_class",
            "attribute_name",
            "attribute_classification",
            "detection_type",
            "severity",
            "confidence",
            "matched_value",
            "full_value",
            "notes",
        ]
    )
    for f in report.findings:
        writer.writerow(
            [
                f.object_dn,
                f.object_class,
                f.attribute_name,
                f.attribute_classification,
                f.detection_type,
                f.severity,
                f.confidence,
                _mask(f.matched_value, mask),
                _mask(f.full_value, mask),
                f.notes,
            ]
        )
    if report.custom_attribute_dump:
        writer.writerow([])
        writer.writerow(
            ["custom_dump_object_dn", "object_class", "attribute_name", "value"]
        )
        for d in report.custom_attribute_dump:
            writer.writerow(
                [d.object_dn, d.object_class, d.attribute_name, _mask(d.value, mask)]
            )
    return out.getvalue()


def _write_header(out: io.StringIO, report: AuditReport) -> None:
    out.write(f"passdiger v{VERSION} - Active Directory credential exposure audit\n")
    out.write(f"  Domain            : {report.domain}\n")
    out.write(f"  Domain controller : {report.domain_controller}\n")
    out.write(f"  Base DN           : {report.base_dn}\n")
    out.write(f"  Bind              : {report.bind}\n")
    out.write(f"  Schema resolved   : {report.schema_resolved}\n")
    out.write(f"  Built-in attrs    : {report.builtin_attribute_count}\n")
    out.write(f"  Custom attrs      : {report.custom_attribute_count}\n")
    out.write(f"  Objects scanned   : {report.objects_scanned}\n")
    out.write(f"  Attributes scanned: {report.attributes_scanned}\n")
    out.write(f"  Started           : {report.started_at}\n")
    out.write(f"  Finished          : {report.finished_at}\n")


def _format_summary(report: AuditReport) -> str:
    summary = report.summary()
    return (
        "Severity counts:\n"
        f"  CRITICAL: {summary[SEV_CRITICAL]}\n"
        f"  HIGH    : {summary[SEV_HIGH]}\n"
        f"  MEDIUM  : {summary[SEV_MEDIUM]}\n"
        f"  LOW     : {summary[SEV_LOW]}\n"
        f"  TOTAL   : {summary['TOTAL']}\n"
    )


def _render_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    widths = [
        max(len(str(row[col])) for row in rows) for col in range(len(rows[0]))
    ]
    widths = [min(w, 80) for w in widths]
    out = io.StringIO()
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out.write(sep + "\n")
    for i, row in enumerate(rows):
        cells = [
            f" {_truncate(str(row[c]), widths[c]).ljust(widths[c])} "
            for c in range(len(row))
        ]
        out.write("|" + "|".join(cells) + "|\n")
        if i == 0:
            out.write(sep + "\n")
    out.write(sep + "\n")
    return out.getvalue()


def _shorten_dn(dn: str, max_len: int) -> str:
    if len(dn) <= max_len:
        return dn
    parts = dn.split(",")
    if len(parts) <= 2:
        return _truncate(dn, max_len)
    return parts[0] + ",...," + parts[-1]


def _mask(s: str, mask: bool) -> str:
    if not mask or not s:
        return s
    if len(s) <= 6:
        return "*" * len(s)
    keep = 2
    return s[:keep] + ("*" * (len(s) - keep * 2)) + s[-keep:]


# ---------------------------------------------------------------------------
# CLI / Main
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="passdiger",
        description="Audit Active Directory attributes for exposed credentials, "
        "secrets, tokens, and connection strings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  passdiger -d corp.local -s 192.168.1.10\n"
            "  passdiger -d corp.local -s dc1.corp.local -u 'CORP\\auditor' -p 'P@ssw0rd' --use-ssl\n"
            "  passdiger -d corp.local -s 10.0.0.5 -u auditor@corp.local -p '...' "
            "--show-all-custom -o json -O report.json\n"
        ),
    )

    conn = parser.add_argument_group("Connection")
    conn.add_argument("-d", "--domain", required=True, help="Domain (FQDN), e.g. corp.local")
    conn.add_argument(
        "-s",
        "--dc",
        "--server",
        dest="server",
        required=True,
        help="Domain controller hostname or IP",
    )
    conn.add_argument("-u", "--user", help="Bind username (UPN, DN, or DOMAIN\\sam)")
    conn.add_argument("-p", "--password", help="Bind password (omit for anonymous)")
    conn.add_argument(
        "--auth",
        choices=["auto", "simple", "ntlm", "anonymous"],
        default="auto",
        help="Authentication mode (default: auto)",
    )
    conn.add_argument("--port", type=int, help="LDAP/LDAPS port override")
    conn.add_argument(
        "--use-ssl",
        action="store_true",
        help="Use LDAPS (TLS). Default port becomes 636.",
    )
    conn.add_argument(
        "--no-verify-cert",
        action="store_true",
        help="Skip TLS certificate validation (LDAPS only)",
    )
    conn.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Network timeout in seconds (default: 15)",
    )

    scope = parser.add_argument_group("Scope")
    scope.add_argument(
        "-b",
        "--base-dn",
        help="Base DN (default: rootDSE defaultNamingContext)",
    )
    scope.add_argument(
        "--filter",
        dest="ldap_filter",
        default=DEFAULT_OBJECT_FILTER,
        help="LDAP filter for objects to scan (default targets users/computers/groups/contacts/OUs)",
    )
    scope.add_argument(
        "--page-size",
        type=int,
        default=500,
        help="Paged search size (default: 500)",
    )
    scope.add_argument(
        "--max-objects",
        type=int,
        default=0,
        help="Stop after N objects (0 = no limit)",
    )

    detect = parser.add_argument_group("Detection")
    detect.add_argument(
        "--min-confidence",
        type=int,
        default=55,
        help="Minimum confidence score to report (0-100, default: 55)",
    )
    detect.add_argument(
        "--only-common",
        action="store_true",
        help="Inspect only well-known credential-prone attributes (skip custom attrs)",
    )
    detect.add_argument(
        "--show-all-custom",
        action="store_true",
        help="Print every custom attribute and value, even with no findings",
    )
    detect.add_argument(
        "--mask-values",
        action="store_true",
        help="Mask matched values in output (helpful when sharing reports)",
    )

    out = parser.add_argument_group("Output")
    out.add_argument(
        "-o",
        "--output-format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    out.add_argument(
        "-O",
        "--output-file",
        help="Write output to file (default: stdout)",
    )
    out.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress progress output to stderr",
    )
    out.add_argument(
        "--version",
        action="version",
        version=f"passdiger {VERSION}",
    )

    return parser.parse_args(argv)


def progress(quiet: bool, message: str) -> None:
    if not quiet:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()


def determine_port(args: argparse.Namespace) -> int:
    if args.port:
        return args.port
    return 636 if args.use_ssl else 389


def determine_bind_label(args: argparse.Namespace) -> str:
    if args.auth == "anonymous" or (args.auth == "auto" and not args.user):
        return "anonymous"
    return f"{args.user} ({args.auth})"


def run(args: argparse.Namespace) -> int:
    _, LDAPException = _require_ldap3()
    started = datetime.utcnow()
    port = determine_port(args)

    progress(
        args.quiet,
        f"[*] Connecting to {args.server}:{port} ({'LDAPS' if args.use_ssl else 'LDAP'})...",
    )
    server = build_server(
        host=args.server,
        port=port,
        use_ssl=args.use_ssl,
        verify_cert=not args.no_verify_cert,
        timeout=args.timeout,
    )

    try:
        conn = open_connection(
            server=server,
            username=args.user,
            password=args.password,
            domain=args.domain,
            auth_mode=args.auth,
            timeout=args.timeout,
        )
    except LDAPException as exc:
        sys.stderr.write(f"ERROR: LDAP bind failed: {exc}\n")
        return 3
    except ValueError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2

    try:
        root_info = discover_root_info(server)
        base_dn = args.base_dn or root_info.get("default_naming_context")
        if not base_dn:
            sys.stderr.write(
                "ERROR: could not determine base DN from rootDSE; pass --base-dn explicitly.\n"
            )
            return 4
        progress(args.quiet, f"[*] Bound as {determine_bind_label(args)}")
        progress(args.quiet, f"[*] Base DN: {base_dn}")

        builtin_attrs: Set[str] = set()
        custom_attrs: Set[str] = set()
        schema_dn = root_info.get("schema_naming_context")
        schema_resolved = False
        if schema_dn:
            try:
                progress(args.quiet, f"[*] Loading schema from {schema_dn}...")
                builtin_attrs, custom_attrs = classify_attributes(conn, schema_dn)
                schema_resolved = True
                progress(
                    args.quiet,
                    f"[*] Schema attributes: {len(builtin_attrs)} built-in, "
                    f"{len(custom_attrs)} custom",
                )
            except LDAPException as exc:
                progress(
                    args.quiet,
                    f"[!] Schema discovery failed ({exc}); falling back to heuristic.",
                )

        detector = CredentialDetector(min_confidence=args.min_confidence)

        report = AuditReport(
            started_at=started.isoformat() + "Z",
            finished_at="",
            domain=args.domain,
            domain_controller=f"{args.server}:{port}",
            base_dn=base_dn,
            bind=determine_bind_label(args),
            objects_scanned=0,
            attributes_scanned=0,
            builtin_attribute_count=len(builtin_attrs),
            custom_attribute_count=len(custom_attrs),
            schema_resolved=schema_resolved,
        )

        progress(
            args.quiet,
            f"[*] Enumerating objects with filter: {args.ldap_filter}",
        )

        try:
            for entry in paged_object_search(
                conn,
                base_dn=base_dn,
                ldap_filter=args.ldap_filter,
                page_size=args.page_size,
            ):
                report.objects_scanned += 1
                findings, dumps, attrs_scanned = audit_entry(
                    entry,
                    detector=detector,
                    builtin_attrs=builtin_attrs,
                    custom_attrs=custom_attrs,
                    show_all_custom=args.show_all_custom,
                    inspect_only_common=args.only_common,
                )
                report.findings.extend(findings)
                report.custom_attribute_dump.extend(dumps)
                report.attributes_scanned += attrs_scanned
                if args.max_objects and report.objects_scanned >= args.max_objects:
                    progress(
                        args.quiet,
                        f"[!] Reached --max-objects limit ({args.max_objects}); stopping.",
                    )
                    break
                if not args.quiet and report.objects_scanned % 500 == 0:
                    progress(
                        args.quiet,
                        f"[*] {report.objects_scanned} objects, "
                        f"{len(report.findings)} findings so far...",
                    )
        except LDAPException as exc:
            sys.stderr.write(f"ERROR: LDAP search failed: {exc}\n")
            return 5

        finished = datetime.utcnow()
        report.finished_at = finished.isoformat() + "Z"

        progress(
            args.quiet,
            f"[+] Scan complete: {report.objects_scanned} objects, "
            f"{report.attributes_scanned} attributes, "
            f"{len(report.findings)} findings.",
        )

    finally:
        try:
            conn.unbind()
        except Exception:
            pass

    if args.output_format == "json":
        rendered = format_json(report, mask=args.mask_values)
    elif args.output_format == "csv":
        rendered = format_csv(report, mask=args.mask_values)
    else:
        rendered = format_table(report, mask=args.mask_values)

    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
        progress(args.quiet, f"[+] Report written to {args.output_file}")
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    # Exit code reflects highest severity for CI integration.
    summary = report.summary()
    if summary[SEV_CRITICAL]:
        return 30
    if summary[SEV_HIGH]:
        return 20
    if summary[SEV_MEDIUM]:
        return 10
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2
    try:
        return run(args)
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        return 130
    except Exception as exc:
        # Catch ldap3 LDAPException and any other unhandled error here.
        sys.stderr.write(f"ERROR: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
