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
import html as _html
import io
import json
import math
import re
import ssl
import sys
from collections import Counter, OrderedDict
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

# Tight allowlist of built-in attributes the auditor checks for credentials.
# This is the *only* set of standard AD attrs we scan — everything else
# (samAccountName, objectSID, name, mail, telephoneNumber, …) is rejected
# from the audit because admins do not use those fields to store passwords.
# Custom attributes (schema extensions) are always inspected separately.
COMMON_INSPECTION_ATTRS = {
    "description",
    "info",
    "comment",
    "userpassword",
    "unixuserpassword",
    "unicodepwd",
    "mssfu30password",
    "ms-mcs-admpwd",
    "mslaps-password",
    "mslaps-encryptedpassword",
    "msds-managedpassword",
    "msds-keycredentiallink",
    "gecos",
    "displayname",
    "wwwhomepage",
}

# Attributes whose mere presence-with-a-value is itself a finding, regardless
# of what the value looks like. These are AD's known password / credential
# attributes — if the auditor read a value, that is the leak.
# Map: lower-cased attr name -> (severity, confidence, explanatory note).
CREDENTIAL_ATTRS: Dict[str, Tuple[str, int, str]] = {
    "userpassword":             (SEV_CRITICAL, 99, "Cleartext userPassword exposed"),
    "unixuserpassword":         (SEV_CRITICAL, 99, "Cleartext unixUserPassword exposed"),
    "unicodepwd":               (SEV_CRITICAL, 99, "unicodePwd readable (extremely unusual; AD normally hides this)"),
    "mssfu30password":          (SEV_CRITICAL, 99, "msSFU30Password (Unix services for AD) exposed"),
    "ms-mcs-admpwd":            (SEV_CRITICAL, 99, "LAPS cleartext local-admin password readable"),
    "mslaps-password":          (SEV_CRITICAL, 99, "LAPS v2 (Windows LAPS) cleartext password readable"),
    "mslaps-encryptedpassword": (SEV_HIGH,     90, "LAPS v2 encrypted password readable (DPAPI-NG decryptable by privileged accounts)"),
    "msds-managedpassword":     (SEV_CRITICAL, 99, "gMSA managed-password blob readable"),
    "msds-keycredentiallink":   (SEV_MEDIUM,   75, "msDS-KeyCredentialLink (WHfB key creds) readable"),
}

# Attributes we never scan or dump regardless of their classification:
# binary blobs, security descriptors, hash histories, large operational data.
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
    "logonhours",
    "dnscord",
    "dnsrecord",
    "dnsproperty",
    "registeredaddress",
    "auditingpolicy",
    "tokengroups",
    "tokengroupsglobalanduniversal",
    "tokengroupsnogcacceptable",
    "ntpwdhistory",
    "lmpwdhistory",
    "supplementalcredentials",
    "dbcsfwd",
    "msds-revealedusers",
    "msds-revealedlist",
    "schemaidguid",
    "attributesecurityguid",
}

# Comprehensive list of standard AD attribute names used as a *classification
# fallback* when the schema partition can't be read (e.g. anonymous bind on a
# locked-down DC). Without this, attrs like samAccountName/cn/memberOf would
# fall into the "unknown" bucket and get scanned/dumped, producing noise. We
# never scan attrs in this list — only attrs in COMMON_INSPECTION_ATTRS or
# real custom attrs.
KNOWN_AD_ATTRS = {
    # core identity
    "objectclass", "objectcategory", "objectguid", "objectsid",
    "samaccountname", "samaccounttype", "userprincipalname",
    "name", "cn", "distinguishedname", "givenname", "sn", "initials",
    "displayname", "displaynameprintable",
    "altsecurityidentities", "personaltitle", "carlicense",
    "employeeid", "employeenumber", "employeetype",
    # contact / address
    "mail", "proxyaddresses", "mailnickname",
    "telephonenumber", "mobile", "homephone", "pager",
    "facsimiletelephonenumber", "ipphone",
    "othertelephone", "othermobile", "otherhomephone", "otherpager",
    "otherfacsimiletelephonenumber", "otheripphone",
    "streetaddress", "postaladdress", "postofficebox", "postalcode",
    "homepostaladdress", "physicaldeliveryofficename",
    "l", "st", "co", "c", "countrycode",
    # org / manager
    "department", "company", "title", "manager", "directreports",
    # group / membership
    "memberof", "member", "primarygroupid", "grouptype", "groupterm",
    # account flags / pwd metadata
    "useraccountcontrol", "accountexpires", "badpwdcount", "badpasswordtime",
    "lastlogon", "lastlogontimestamp", "lastlogoff", "logoncount",
    "lockouttime", "pwdlastset", "lastpwdset",
    "userworkstations", "useworkstations",
    # paths / scripts / OS
    "homedirectory", "homedrive", "scriptpath", "profilepath",
    "url",  # often holds vendor URL but not a credential channel
    "dnshostname", "serviceprincipalname",
    "operatingsystem", "operatingsystemversion",
    "operatingsystemservicepack", "operatingsystemhotfix",
    # POSIX / SFU
    "uidnumber", "gidnumber", "loginshell", "uid",
    # change tracking / operational
    "instancetype", "whencreated", "whenchanged", "usnchanged", "usncreated",
    "createtimestamp", "modifytimestamp", "creatorsname", "modifiersname",
    "entrydn", "entryuuid", "subschemasubentry",
    # rid / replication metadata
    "ridtype", "rid", "ridmanagerreference", "ridmanager",
    "ridallocationpool", "ridsetreferences",
    # Exchange & misc operational
    "homemta", "ridallocationpool", "rolloversequence",
    "logontime", "iis6applicationpool",
    # extensionAttribute1..15 used by Exchange — admins do sometimes write
    # passwords here, but it's noisy by default; NOT included in COMMON
    # but also not in KNOWN_AD_ATTRS so they will be classified as
    # built-in via schema and ignored.
}

# Default object filter — by request, restricted to user accounts and groups
# only. Excludes computers (objectCategory=computer), contacts, OUs, GPOs,
# foreign-security-principals, etc. Override with --filter to broaden.
DEFAULT_OBJECT_FILTER = (
    "(|"
    "(&(objectCategory=person)(objectClass=user))"
    "(objectClass=group)"
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
            r"(?ix)\b(password|passwd|pwd|pass|secret|passphrase|passcode|creds?)\s*[:=]\s*"
            r"(?P<val>(?:\"[^\"\n]{2,200}\"|'[^'\n]{2,200}'|[^\s,;'\"<>]{3,200}))"
        ),
        92,
        SEV_CRITICAL,
    ),
    (
        "default_password_phrase",
        re.compile(
            r"(?ix)\b(default|temp(orary)?|initial|new|admin|service|root)\s+"
            r"(password|passwd|pwd|pass)\b"
            r"(?:\s*[:=]\s*|\s+is\s+|\s+)"
            r"['\"`]?(?P<val>[^\s,;'\"`<>]{4,80})['\"`]?"
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
        # XML / config-file shape: <password>VALUE</password>, also matches
        # <secret>, <token>, etc. with matching close tags.
        "xml_password_tag",
        re.compile(
            r"(?is)<\s*(?P<tag>password|passwd|pwd|secret|api[_-]?key|token|"
            r"client[_-]?secret|credentials?)\s*>"
            r"(?P<val>[^<]{3,400})"
            r"<\s*/\s*(?P=tag)\s*>"
        ),
        93,
        SEV_CRITICAL,
    ),
    (
        # CLI flag form: --password VALUE, --secret=VALUE, etc.
        "cli_password_flag",
        re.compile(
            r"(?ix)(?:^|\s|;)--?(password|passwd|pwd|secret|api[_-]?key|token"
            r"|client[_-]?secret|p)\b(?:\s*[=]\s*|\s+)"
            r"['\"`]?(?P<val>[^\s'\"`<>]{4,200})['\"`]?"
        ),
        85,
        SEV_HIGH,
    ),
    (
        # Imperative natural language: "set password to X", "use password X",
        # "change pwd as Y", "reset password = Z". The connector
        # (to|as|=|is|equals|->) is optional so "use password X" matches.
        "set_password_phrase",
        re.compile(
            r"(?ix)\b(?:set|use|change|update|reset|new)\s+(?:the\s+|a\s+|new\s+)*"
            r"(?:password|passwd|pwd|pass|secret|passphrase)\s+"
            r"(?:(?:to|as|=|is|equals?|of|->)\s+)?"
            r"['\"`]?(?P<val>[^\s,;'\"`<>]{4,200})['\"`]?"
        ),
        87,
        SEV_HIGH,
    ),
    (
        # Context-bracketed credential pair: a credential keyword nearby
        # plus a "user:pass" or "user/pass" pair.
        # Examples:
        #   "creds: admin:Welcome24"
        #   "Login: jdoe / S3cr3t"
        #   "Account john - W3lc0me!"
        "credential_pair_with_context",
        re.compile(
            r"(?ix)\b(credentials?|creds?|login|account|userpass|userpw|access)\b"
            r"[^a-zA-Z0-9\n]{1,30}"
            r"(?P<user>[a-zA-Z][a-zA-Z0-9._\-@]{1,30})"
            r"\s*[:/\\\-]\s*"
            r"(?P<val>[^\s,;'\"`<>]{4,80})"
        ),
        82,
        SEV_HIGH,
    ),
    (
        # Generic 'username:password' shape — risky by itself, so we apply
        # strict value-shape checks in _adjust_confidence (must look
        # password-like: have digit/special and decent entropy). Won't fire
        # for k:v noise like 'time:14', 'port:8080', 'version:1.2'.
        "username_password_pair",
        re.compile(
            r"(?ix)(?<!://)"
            r"\b(?P<user>[a-zA-Z][a-zA-Z0-9._\-]{2,29}):"
            r"(?P<val>[^\s:,;'\"`<>]{6,80})"
        ),
        70,
        SEV_HIGH,
    ),
    (
        "sql_connection_string",
        re.compile(
            r"(?ix)(server|data\s*source|host|address|addr)\s*=\s*[^;]{3,200};"
            r".{0,400}?(password|pwd)\s*=\s*(?P<val>[^;'\"<>]+)"
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
    (
        "argon2_hash",
        re.compile(
            r"\$argon2(?:i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$"
            r"[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+"
        ),
        97,
        SEV_CRITICAL,
    ),
    (
        "htpasswd_md5",
        re.compile(r"\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}"),
        96,
        SEV_CRITICAL,
    ),
    (
        "anthropic_api_key",
        re.compile(r"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_\-]{20,}\b"),
        98,
        SEV_CRITICAL,
    ),
    (
        "openai_project_key",
        re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
        92,
        SEV_HIGH,
    ),
    (
        "bearer_token",
        re.compile(
            r"(?i)\b(?:authorization\s*[:=]\s*)?bearer\s+"
            r"(?P<val>[A-Za-z0-9_\-\.+/=]{16,})"
        ),
        80,
        SEV_HIGH,
    ),
    (
        "basic_auth_b64",
        re.compile(
            r"(?i)\b(?:authorization\s*[:=]\s*)?basic\s+"
            r"(?P<val>[A-Za-z0-9+/=]{12,})"
        ),
        78,
        SEV_HIGH,
    ),
    (
        # Catch-all heuristic: the attribute value just *mentions* a
        # credential-related keyword. Confidence is intentionally low
        # (default min_confidence=55 hides it) so this pattern only
        # surfaces when the user explicitly lowers --min-confidence to
        # do an aggressive review pass. Useful for catching attributes
        # where someone wrote prose like "user has a password" or
        # "his secret is in the safe" without exposing the value
        # itself, but still worth a manual review.
        "credential_keyword_present",
        re.compile(
            r"(?i)\b(passwords?|passwd|pwd|pass(?:phrase|code|word)?|"
            r"secrets?|credentials?|creds?|"
            r"api[_-]?keys?|access[_-]?keys?|private[_-]?keys?|"
            r"client[_-]?secrets?|auth[_-]?tokens?|bearer|tokens?|keys?)\b"
        ),
        35,
        SEV_LOW,
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

# Placeholder values we should never flag (asterisks, x's, "REDACTED", etc.).
# The bracket alternatives are pinned to known placeholder words so we don't
# accidentally fullmatch real XML/JSON wrappers like <password>X</password>.
PLACEHOLDER_VALUES = re.compile(
    r"^(?:"
    r"x+|X+|\*+|\.+|-+|"
    r"<(?:empty|placeholder|none|null|todo|tbd|redacted|hidden|removed|insert[\w\s]*here|n/?a)>|"
    r"\[(?:empty|placeholder|none|null|todo|tbd|redacted|hidden|removed|insert[\w\s]*here|n/?a)\]|"
    r"none|null|nil|n/?a|todo|tbd|pending|"
    r"changeme|placeholder|"
    r"redacted|hidden|removed"
    r")$",
    re.IGNORECASE,
)

# Words that frequently appear *adjacent* to "password" in policy/prose
# (e.g. "password reset required", "password complexity rules"). Used by
# pattern-rejection logic to avoid flagging policy text as a credential.
PROSE_REJECT_WORDS = {
    "reset", "expired", "set", "change", "new", "required",
    "policy", "rules", "complexity", "history", "minimum",
    "maximum", "length", "age", "expires", "expiry", "expiration",
    "should", "must", "would", "will", "can", "may",
    "strong", "weak", "secure", "compliant",
    "true", "false", "none", "null", "empty", "default",
    "yes", "no", "valid", "invalid",
}

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
class CheckedAttribute:
    """One row of the per-object dump emitted with --dump-checked-attrs.

    Captures every attribute that the auditor *checked* for each object —
    credential-prone built-ins (description/info/comment/...) plus every
    custom attribute. Includes attributes where no finding fired, giving
    the user full visibility into what was inspected and why.
    """

    object_dn: str
    object_class: str
    attribute_name: str
    attribute_classification: str  # built-in / custom / unknown
    value: str
    has_finding: bool = False

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
    checked_attribute_dump: List[CheckedAttribute] = field(default_factory=list)
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
            "checked_attribute_dump": [c.to_dict() for c in self.checked_attribute_dump],
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

        # password_keyvalue / default_password_phrase / set_password_phrase /
        # cli_password_flag: avoid flagging prose like "password reset
        # required" or "password policy: ...".
        if label in {
            "password_keyvalue", "default_password_phrase",
            "set_password_phrase", "cli_password_flag",
        }:
            if clean.lower() in PROSE_REJECT_WORDS:
                return 0, ""
            if len(clean) < 4:
                conf -= 20

        # credential_pair_with_context: reject when the value is itself a
        # credential keyword (e.g. "Account john / Pass W3lc..." would
        # capture val="Pass" first).
        if label == "credential_pair_with_context":
            if clean.lower() in {
                "password", "passwd", "pwd", "pass", "secret", "passphrase",
                "credentials", "creds", "login", "user", "username",
            } or clean.lower() in PROSE_REJECT_WORDS:
                return 0, ""

        # username_password_pair: this is a generic K:V shape with high
        # FP risk. Require the value to look genuinely password-like:
        # have digits OR special chars AND length >= 6, and reject obvious
        # k:v noise (port:NUM, version:N.N.N, dates, true/false, etc.).
        if label == "username_password_pair":
            if clean.lower() in (PROSE_REJECT_WORDS | {
                "tcp", "udp", "http", "https", "smtp", "imap", "pop3",
                "localhost", "internal", "external", "public", "private",
            }):
                return 0, ""
            # Numeric-only value is a port/timestamp/ID, not a credential.
            if clean.isdigit():
                return 0, ""
            # IP-like: x.y.z.w
            if re.fullmatch(r"\d+(?:\.\d+){2,}\.?\d*", clean):
                return 0, ""
            # Date- or time-shaped values: 2024-01-15, 14:30:00, 12/31/24, etc.
            if re.fullmatch(r"\d{1,4}[-/.:]\d{1,4}([-/.:]\d{1,4})*Z?", clean):
                return 0, ""
            # Pure digits + separators (date/time/version-like).
            if re.fullmatch(r"[\d\-/.:]+", clean):
                return 0, ""
            has_digit = any(c.isdigit() for c in clean)
            has_special = any(c in "!@#$%^&*()_+-=[]{}|\\,.<>/?`~" for c in clean)
            has_upper = any(c.isupper() for c in clean)
            has_lower = any(c.islower() for c in clean)
            score = 0
            if has_digit:                score += 1
            if has_special:              score += 1
            if has_upper and has_lower:  score += 1
            if len(clean) >= 8:          score += 1
            if score < 2:
                return 0, ""
            # Higher score → boost confidence up to ~80
            conf = min(85, conf + (score - 2) * 5)
            notes.append(f"value-shape score={score} (digit={has_digit}, "
                         f"special={has_special}, mixed-case={has_upper and has_lower})")

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

    _KEYWORD_CONTEXT_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
        (
            kw,
            re.compile(
                rf"(?i)\b{re.escape(kw)}\b\s*"
                rf"(?:is|equals?|set\s+to|set\s+as|:|=|=>|->)\s+"
                rf"['\"`]?(?P<tok>[^\s,;'\"`<>]{{4,80}})['\"`]?"
            ),
        )
        for kw in CREDENTIAL_KEYWORDS
    ]

    @classmethod
    def _keyword_context(cls, value: str) -> Optional[Tuple[str, str, int, str, str]]:
        """Look for 'keyword <separator> token' where token has high entropy."""
        for kw, pattern in cls._KEYWORD_CONTEXT_PATTERNS:
            match = pattern.search(value)
            if not match:
                continue
            token = match.group("tok")
            if PLACEHOLDER_VALUES.fullmatch(token):
                continue
            # Reject prose words that aren't real credential values, e.g.
            # "password equals expired" / "secret is required" / etc.
            if token.lower() in PROSE_REJECT_WORDS:
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
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    if n <= 3:
        return "." * n
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
    # Important: use DSA (rootDSE only) — NOT ALL — for the bind-time
    # info fetch. AD allows anonymous reads of rootDSE but blocks the
    # schema partition (CN=Schema,CN=Configuration,...). With get_info=ALL
    # ldap3 would auto-query the schema during bind and the resulting
    # NO_OBJECT error escapes the Connection() constructor before our
    # explicit schema discovery (which has graceful fallback) ever runs.
    return ldap3.Server(
        host=host,
        port=port,
        use_ssl=use_ssl,
        get_info=ldap3.DSA,
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
    """Convert ldap3 attribute payloads to a printable string for inspection.

    Returns None for values that decode to mostly-unprintable junk, so the
    detector and dump paths never see binary garbage that just happens to
    decode under utf-16-le.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        parts = [coerce_value(v) for v in raw]
        parts = [p for p in parts if p]
        return "\n".join(parts) if parts else None
    if isinstance(raw, (bytes, bytearray)):
        decoded: Optional[str] = None
        try:
            candidate = raw.decode("utf-8")
            # AD frequently stores text as UTF-16-LE. Such bytes also decode
            # cleanly as UTF-8 (each byte < 0x80) but yield embedded nulls;
            # in that case re-decode as UTF-16-LE to recover the real text.
            if "\x00" in candidate:
                try:
                    decoded = raw.decode("utf-16-le")
                except UnicodeDecodeError:
                    decoded = candidate
            else:
                decoded = candidate
        except UnicodeDecodeError:
            try:
                decoded = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                return None
        if not decoded:
            return None
        printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
        if printable / len(decoded) < 0.85:
            return None
        return decoded
    if isinstance(raw, (int, float, bool)):
        return str(raw)
    if isinstance(raw, datetime):
        return raw.isoformat()
    return str(raw)


def attribute_classification(
    name: str, builtin: Set[str], custom: Set[str]
) -> str:
    """Classify an attribute name as 'built-in', 'custom', or 'unknown'.

    Order of resolution:
      1. The schema-derived ``builtin`` and ``custom`` sets (authoritative).
      2. Our hard-coded COMMON_INSPECTION_ATTRS list (always built-in).
      3. The KNOWN_AD_ATTRS fallback list (always built-in) — covers the
         common AD defaults (samAccountName, cn, memberOf, …) so that when
         the schema partition is unreadable we still classify them as
         built-in and exclude them from scanning / dumping.
      4. Otherwise 'unknown' — handled like a custom attr.
    """
    n = name.lower()
    if n in builtin:
        return "built-in"
    if n in custom:
        return "custom"
    if n in COMMON_INSPECTION_ATTRS:
        return "built-in"
    if n in KNOWN_AD_ATTRS:
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
    dump_checked_attrs: bool = False,
) -> Tuple[List[Finding], List[CustomAttributeDump], List[CheckedAttribute], int]:
    """Audit a single search entry.

    Returns a tuple of:
      (findings, custom_attr_dumps, checked_attr_dumps, attrs_scanned)

    The ``checked_attr_dumps`` list is only populated when ``dump_checked_attrs``
    is True and contains every credential-prone built-in attribute plus every
    custom attribute on the object — even when no finding fired, giving the
    user full visibility into what was inspected.
    """
    findings: List[Finding] = []
    dumps: List[CustomAttributeDump] = []
    checked: List[CheckedAttribute] = []

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

        attribute_findings: List[Finding] = []
        if should_scan:
            attrs_scanned += 1

            # Stage A: built-in credential attributes — the *presence* of
            # any value is itself a critical finding regardless of content.
            attr_lower = attr_name.lower()
            if attr_lower in CREDENTIAL_ATTRS:
                sev, conf, note = CREDENTIAL_ATTRS[attr_lower]
                attribute_findings.append(
                    Finding(
                        object_dn=dn,
                        object_class=obj_class,
                        attribute_name=attr_name,
                        attribute_classification=cls,
                        detection_type="sensitive_attribute_exposed",
                        severity=sev,
                        confidence=conf,
                        matched_value=_truncate(coerced, 200),
                        full_value=_truncate(coerced, 500),
                        notes=note,
                    )
                )

            # Stage B: pattern-based detection on the value itself. Runs
            # for every scanned attribute (including credential attrs above
            # — sometimes the value also matches an additional pattern
            # like a hash format or embedded URL).
            for label, matched, conf, sev, det_note in detector.detect(coerced):
                attribute_findings.append(
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
                        notes=det_note,
                    )
                )
        findings.extend(attribute_findings)

        # Always-dump-custom for visibility. In schema-fallback mode the
        # custom set is empty and unknown-classified attrs are effectively
        # custom from the user's perspective, so dump them too.
        should_dump_custom = is_custom or (cls == "unknown" and not is_common)
        if show_all_custom and should_dump_custom:
            dumps.append(
                CustomAttributeDump(
                    object_dn=dn,
                    object_class=obj_class,
                    attribute_name=attr_name,
                    value=_truncate(coerced, 500),
                )
            )

        # --dump-checked-attrs: emit every credential-prone built-in attr
        # AND every custom/unknown attr, with or without a finding. This
        # gives the user full visibility into what was inspected per object.
        if dump_checked_attrs and (is_common or should_dump_custom):
            checked.append(
                CheckedAttribute(
                    object_dn=dn,
                    object_class=obj_class,
                    attribute_name=attr_name,
                    attribute_classification=cls,
                    value=_truncate(coerced, 500),
                    has_finding=bool(attribute_findings),
                )
            )

    return findings, dumps, checked, attrs_scanned


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

    if report.checked_attribute_dump:
        out.write(
            f"\nChecked attribute dump ({len(report.checked_attribute_dump)} "
            "entries — every credential-prone built-in plus all custom attrs):\n"
        )
        rows = [["OBJECT", "ATTR", "CLASS", "FIND?", "VALUE"]]
        for c in report.checked_attribute_dump:
            rows.append(
                [
                    _shorten_dn(c.object_dn, 50),
                    c.attribute_name,
                    c.attribute_classification,
                    "yes" if c.has_finding else "no",
                    _mask(_truncate(c.value, 80), mask),
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
        for c in payload["checked_attribute_dump"]:
            c["value"] = _mask(c["value"], True)

    # When the user asks for a checked-attr dump, also expose a per-object
    # grouped view that's easier to consume than the flat list.
    if payload["checked_attribute_dump"]:
        grouped: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        for c in payload["checked_attribute_dump"]:
            obj = grouped.setdefault(
                c["object_dn"],
                {
                    "object_dn": c["object_dn"],
                    "object_class": c["object_class"],
                    "common_attributes": {},
                    "custom_attributes": {},
                },
            )
            target = (
                obj["custom_attributes"]
                if c["attribute_classification"] in ("custom", "unknown")
                else obj["common_attributes"]
            )
            target[c["attribute_name"]] = {
                "value": c["value"],
                "has_finding": c["has_finding"],
            }
        payload["checked_attribute_dump_by_object"] = list(grouped.values())

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
    if report.checked_attribute_dump:
        writer.writerow([])
        writer.writerow(
            [
                "checked_dump_object_dn",
                "object_class",
                "attribute_name",
                "attribute_classification",
                "has_finding",
                "value",
            ]
        )
        for c in report.checked_attribute_dump:
            writer.writerow(
                [
                    c.object_dn,
                    c.object_class,
                    c.attribute_name,
                    c.attribute_classification,
                    "yes" if c.has_finding else "no",
                    _mask(c.value, mask),
                ]
            )
    return out.getvalue()


def format_html(report: AuditReport, mask: bool) -> str:
    """Render the report as a self-contained HTML document with inline styles."""
    e = _html.escape
    findings = sorted(
        report.findings,
        key=lambda f: (-SEVERITY_RANK[f.severity], -f.confidence, f.object_dn),
    )
    summary = report.summary()

    grouped: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for c in report.checked_attribute_dump:
        obj = grouped.setdefault(
            c.object_dn,
            {
                "object_dn": c.object_dn,
                "object_class": c.object_class,
                "common": [],
                "custom": [],
            },
        )
        bucket = "custom" if c.attribute_classification in ("custom", "unknown") else "common"
        obj[bucket].append(c)

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head>')
    parts.append('<meta charset="utf-8">')
    parts.append(f"<title>passdiger report — {e(report.domain)}</title>")
    parts.append(_HTML_STYLE)
    parts.append("</head><body>")
    parts.append(f'<h1>passdiger report</h1>')
    parts.append('<section class="meta"><table>')
    for label, value in (
        ("Domain", report.domain),
        ("Domain controller", report.domain_controller),
        ("Base DN", report.base_dn),
        ("Bind", report.bind),
        ("Schema resolved", str(report.schema_resolved)),
        ("Built-in attrs (schema)", str(report.builtin_attribute_count)),
        ("Custom attrs (schema)", str(report.custom_attribute_count)),
        ("Objects scanned", str(report.objects_scanned)),
        ("Attributes scanned", str(report.attributes_scanned)),
        ("Started", report.started_at),
        ("Finished", report.finished_at),
    ):
        parts.append(f"<tr><th>{e(label)}</th><td>{e(value)}</td></tr>")
    parts.append("</table></section>")

    parts.append('<section class="summary"><h2>Severity counts</h2><div class="cards">')
    for sev, cls in (
        (SEV_CRITICAL, "crit"), (SEV_HIGH, "high"),
        (SEV_MEDIUM, "med"), (SEV_LOW, "low"),
    ):
        parts.append(
            f'<div class="card sev-{cls}">'
            f'<div class="count">{summary.get(sev, 0)}</div>'
            f'<div class="label">{e(sev)}</div></div>'
        )
    parts.append(
        f'<div class="card total">'
        f'<div class="count">{summary["TOTAL"]}</div>'
        f'<div class="label">TOTAL</div></div>'
    )
    parts.append("</div></section>")

    parts.append('<section><h2>Findings</h2>')
    if not findings:
        parts.append('<p class="empty">No credential exposures detected.</p>')
    else:
        parts.append('<table class="findings"><thead><tr>'
                     '<th>#</th><th>Severity</th><th>Conf</th><th>Class</th>'
                     '<th>Attribute</th><th>Detection</th><th>Object</th>'
                     '<th>Matched value</th><th>Notes</th>'
                     '</tr></thead><tbody>')
        for i, f in enumerate(findings, 1):
            sev_cls = {SEV_CRITICAL: "crit", SEV_HIGH: "high",
                       SEV_MEDIUM: "med", SEV_LOW: "low"}.get(f.severity, "low")
            parts.append(
                f'<tr class="sev-{sev_cls}">'
                f"<td>{i}</td>"
                f'<td><span class="badge sev-{sev_cls}">{e(f.severity)}</span></td>'
                f"<td>{f.confidence}</td>"
                f"<td>{e(f.attribute_classification)}</td>"
                f"<td><code>{e(f.attribute_name)}</code></td>"
                f"<td>{e(f.detection_type)}</td>"
                f'<td class="dn">{e(f.object_dn)}</td>'
                f'<td><code>{e(_mask(f.matched_value, mask))}</code></td>'
                f"<td>{e(f.notes or '')}</td>"
                f"</tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</section>")

    if report.custom_attribute_dump:
        parts.append('<section><h2>Custom attribute dump</h2>')
        parts.append('<table class="dump"><thead><tr>'
                     '<th>Object</th><th>Class</th><th>Attribute</th><th>Value</th>'
                     '</tr></thead><tbody>')
        for d in report.custom_attribute_dump:
            parts.append(
                f"<tr>"
                f'<td class="dn">{e(d.object_dn)}</td>'
                f"<td>{e(d.object_class)}</td>"
                f"<td><code>{e(d.attribute_name)}</code></td>"
                f"<td><code>{e(_mask(d.value, mask))}</code></td>"
                f"</tr>"
            )
        parts.append("</tbody></table></section>")

    if grouped:
        parts.append('<section><h2>Checked attributes per object</h2>')
        parts.append(
            '<p class="hint">Every credential-prone built-in attribute '
            '(<code>description</code>, <code>info</code>, <code>comment</code>, '
            'etc.) plus any custom attributes — '
            f'{len(grouped)} object(s).</p>'
        )
        for obj in grouped.values():
            parts.append('<article class="object-card">')
            parts.append(
                f'<header><span class="dn">{e(obj["object_dn"])}</span>'
                f' <span class="oc">{e(obj["object_class"] or "")}</span></header>'
            )
            for bucket_label, bucket_key in (
                ("Common (credential-prone) attributes", "common"),
                ("Custom attributes", "custom"),
            ):
                rows = obj[bucket_key]
                if not rows:
                    continue
                parts.append(f'<h3>{e(bucket_label)}</h3>')
                parts.append('<table class="attrs"><thead><tr>'
                             '<th>Attribute</th><th>Class</th>'
                             '<th>Finding?</th><th>Value</th>'
                             '</tr></thead><tbody>')
                for c in rows:
                    parts.append(
                        f'<tr class="{"hit" if c.has_finding else ""}">'
                        f"<td><code>{e(c.attribute_name)}</code></td>"
                        f"<td>{e(c.attribute_classification)}</td>"
                        f'<td>{"yes" if c.has_finding else "no"}</td>'
                        f'<td><code>{e(_mask(c.value, mask))}</code></td>'
                        f"</tr>"
                    )
                parts.append("</tbody></table>")
            parts.append("</article>")
        parts.append("</section>")

    parts.append(f'<footer>passdiger v{VERSION}</footer>')
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


_HTML_STYLE = """\
<style>
:root {
  color-scheme: light dark;
  --bg: #fafafa;
  --fg: #1a1a1a;
  --muted: #666;
  --border: #d8d8d8;
  --card: #fff;
  --crit: #c62828;
  --high: #ef6c00;
  --med:  #f9a825;
  --low:  #2e7d32;
  --hit-bg: #fff3e0;
}
@media (prefers-color-scheme: dark) {
  :root { --bg:#161616; --fg:#eee; --muted:#aaa; --border:#333; --card:#1e1e1e; --hit-bg:#3a2a10; }
}
* { box-sizing: border-box; }
body {
  font: 14px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background: var(--bg); color: var(--fg);
  margin: 0; padding: 32px; max-width: 1400px;
}
h1 { font-size: 24px; margin: 0 0 24px; font-weight: 600; }
h2 { font-size: 18px; margin: 32px 0 12px; font-weight: 600; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
h3 { font-size: 14px; margin: 16px 0 8px; font-weight: 600; color: var(--muted); }
section { margin-bottom: 24px; }
table { border-collapse: collapse; width: 100%; background: var(--card); }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-weight: 600; background: rgba(0,0,0,.03); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.meta table { width: auto; }
.meta th { background: transparent; text-transform: none; letter-spacing: 0; padding-right: 24px; color: var(--muted); }
code { font: 12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; word-break: break-all; }
.dn { font: 11px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; color: var(--muted); }
.hint { color: var(--muted); font-size: 13px; }
.empty { color: var(--muted); padding: 16px; background: var(--card); border-radius: 4px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; }
.card { padding: 12px 16px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; min-width: 96px; }
.card .count { font-size: 24px; font-weight: 600; }
.card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.card.sev-crit  { border-left: 4px solid var(--crit); }
.card.sev-high  { border-left: 4px solid var(--high); }
.card.sev-med   { border-left: 4px solid var(--med);  }
.card.sev-low   { border-left: 4px solid var(--low);  }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; color: #fff; }
.badge.sev-crit { background: var(--crit); }
.badge.sev-high { background: var(--high); }
.badge.sev-med  { background: var(--med);  color:#000; }
.badge.sev-low  { background: var(--low);  }
tr.hit { background: var(--hit-bg); }
.object-card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
.object-card header { margin-bottom: 8px; }
.object-card .oc { color: var(--muted); font-size: 12px; }
footer { margin-top: 48px; color: var(--muted); font-size: 12px; }
</style>"""


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
        default=20,
        help="Minimum confidence score to report (0-100, default: 20)",
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
        "--dump-checked-attrs",
        action="store_true",
        help=(
            "For each object, emit every credential-prone built-in attribute "
            "(description, info, comment, etc.) plus any custom attributes — "
            "even when no finding fired. Output respects -o/--output-format."
        ),
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
        choices=["table", "json", "csv", "html"],
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
        sys.stderr.write(f"ERROR: LDAP connection setup failed: {exc}\n")
        msg = str(exc).lower()
        if "noobject" in msg or "noSuchObject".lower() in msg or "insufficientaccess" in msg:
            sys.stderr.write(
                "  Hint: this looks like a permission error during the bind-time\n"
                "        rootDSE/schema fetch. If you are using anonymous bind on AD,\n"
                "        much of the directory is restricted by default — try -u/-p\n"
                "        with a domain account.\n"
            )
        elif "invalidcredentials" in msg or "strongerauthrequired" in msg:
            sys.stderr.write(
                "  Hint: the credentials were rejected. Verify the username format\n"
                "        (UPN like user@domain or NETBIOS\\sam) and the password.\n"
            )
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
                findings, dumps, checked, attrs_scanned = audit_entry(
                    entry,
                    detector=detector,
                    builtin_attrs=builtin_attrs,
                    custom_attrs=custom_attrs,
                    show_all_custom=args.show_all_custom,
                    inspect_only_common=args.only_common,
                    dump_checked_attrs=args.dump_checked_attrs,
                )
                report.findings.extend(findings)
                report.custom_attribute_dump.extend(dumps)
                report.checked_attribute_dump.extend(checked)
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
    elif args.output_format == "html":
        rendered = format_html(report, mask=args.mask_values)
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
