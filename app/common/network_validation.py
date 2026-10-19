"""
Validation helpers for network and security data: IP addresses, domains,
file hashes, CVE identifiers, and CVSS scores.

Used by the Assets, Threat Intelligence, and Vulnerability services.

Author: Anthony Feghali
"""
import ipaddress
import re

from app.common.errors import ApiError

DOMAIN_PATTERN = re.compile(
    r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$"
)
HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def require_ip(value, field_name="ip_address"):
    """Valid IPv4 or IPv6 address. Returns it in standard form (e.g. leading zeros removed)."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ApiError(f"'{field_name}' must be a valid IPv4 or IPv6 address, e.g. 192.168.1.10", 400)


def require_domain(value):
    """Valid domain name such as evil-site.com. Stored in lowercase."""
    domain = str(value).strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.match(domain):
        raise ApiError("Threat value must be a valid domain name, e.g. malicious-site.com", 400)
    return domain


def require_file_hash(value):
    """MD5 (32), SHA-1 (40), or SHA-256 (64) hexadecimal hash. Stored in lowercase."""
    file_hash = str(value).strip().lower()
    if len(file_hash) not in HASH_LENGTHS or not HEX_PATTERN.match(file_hash):
        raise ApiError(
            "Threat value must be a file hash: 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hexadecimal characters",
            400,
        )
    return file_hash


def hash_algorithm(file_hash):
    return HASH_LENGTHS.get(len(file_hash))


def require_cve(value):
    """CVE identifier such as CVE-2024-3094. Stored in uppercase."""
    cve_id = str(value).strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ApiError("'cve_id' must look like CVE-YYYY-NNNN, e.g. CVE-2024-3094", 400)
    return cve_id


def require_cvss(value):
    """CVSS score: a number from 0.0 to 10.0, rounded to one decimal place."""
    if isinstance(value, bool):
        raise ApiError("'cvss_score' must be a number from 0.0 to 10.0", 400)
    try:
        score = float(value)
    except (TypeError, ValueError):
        raise ApiError("'cvss_score' must be a number from 0.0 to 10.0", 400)
    if not 0.0 <= score <= 10.0:
        raise ApiError("'cvss_score' must be between 0.0 and 10.0", 400)
    return round(score, 1)


def severity_for_cvss(score):
    """Official CVSS v3 rating bands, used to check that severity matches the score."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
