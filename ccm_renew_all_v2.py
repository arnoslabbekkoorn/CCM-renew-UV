# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests",
#     "edgegrid-python",
#     "cryptography",
#     "acme",
#     "josepy",
#     "dnspython",
#     "python-dotenv",
# ]
# ///
"""
Akamai CCM certificate overview + Let's Encrypt auto-renewal (v2).

1. Lists ALL CCM lineages in the account with issuer, expiry date and days left.
2. Auto-renews a lineage only when ALL of these are true:
     - it is due: expired, or expires within RENEWAL_THRESHOLD_DAYS
     - it was created by a user in ONLY_CREATED_BY (empty = any user)
     - the certificate was issued by Let's Encrypt
     - it is a single-algorithm lineage (RSA or ECDSA, not both)
     - every SAN's DNS zone is hosted in Akamai Edge DNS
3. Due certificates that cannot be auto-renewed are reported with the reason
   (e.g. other CA or other DNS provider: script must be extended for those).

Run:  uv run ccm_renew_all_v2.py            (report + renew where allowed)
      uv run ccm_renew_all_v2.py --check    (report only, renew nothing)
"""

import os
import re
import sys
import time
import textwrap
import smtplib
import traceback
from datetime import datetime, timezone
from email.message import EmailMessage

import requests
import dns.resolver
from dotenv import load_dotenv
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization
from acme import client, messages, challenges
from josepy.jwk import JWKRSA

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

# ==========================================
# CONFIGURATION
# ==========================================
EDGERC_PATH = os.path.expanduser(os.getenv("EDGERC_PATH", "~/.edgerc"))
EDGERC_SECTION = os.getenv("EDGERC_SECTION", "default")
ACCOUNT_SWITCH_KEY = os.getenv("ACCOUNT_SWITCH_KEY")

# Only renew lineages created by these users (comma separated). Empty = all users.
ONLY_CREATED_BY = {u.strip().lower() for u in os.getenv("ONLY_CREATED_BY", "").split(",") if u.strip()}

# ACME account (currently Let's Encrypt only).
# Testing tip: use Let's Encrypt STAGING to avoid production rate limits (needs its own account):
#   https://acme-staging-v02.api.letsencrypt.org/directory
# Other ACME CAs use the same code with a different directory URL, e.g.:
#   ZeroSSL               https://acme.zerossl.com/v2/DV90                     (needs EAB)
#   Google Trust Services https://dv.acme-v02.api.pki.goog/directory           (needs EAB)
#   Sectigo / DigiCert    URL + EAB key ID/HMAC from the customer's CA portal  (needs EAB)
# EAB = External Account Binding: only needed once, when registering the ACME account.
ACCOUNT_KEY_PATH = os.getenv("ACCOUNT_KEY_PATH")
DIRECTORY_URL = os.getenv("DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory")
ACCOUNT_URI = os.getenv("ACCOUNT_URI")

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = SMTP_USER
EMAIL_TO = os.getenv("EMAIL_TO")

RENEWAL_THRESHOLD_DAYS = int(os.getenv("RENEWAL_THRESHOLD_DAYS", "8"))
DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", "480"))

# ==========================================
# AKAMAI SESSION
# ==========================================
edgerc = EdgeRc(EDGERC_PATH)
base_url = f"https://{edgerc.get(EDGERC_SECTION, 'host')}"
session = requests.Session()
session.auth = EdgeGridAuth.from_edgerc(edgerc, EDGERC_SECTION)
session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
if ACCOUNT_SWITCH_KEY:
    session.headers.update({"Account-Switch-Key": ACCOUNT_SWITCH_KEY})


def log(msg=""):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def api_ok(resp, what):
    if not resp.ok:
        log(f"API error ({what}) {resp.status_code}: {resp.text}")
    resp.raise_for_status()
    return resp


# ==========================================
# EMAIL
# ==========================================
def send_email(subject, body):
    if not (SMTP_SERVER and EMAIL_TO):
        log(f"(email not configured) {subject}")
        return
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        log(f"✅ Email sent: {subject}")
    except Exception as e:
        log(f"❌ Failed to send email: {e}")


# ==========================================
# CCM: INVENTORY
# ==========================================
def list_lineages():
    """All lineages in the account (follows the cursor-based 'next' links)."""
    lineages = []
    url = f"{base_url}/ccm/v2/lineages?pageSize=100"
    while url:
        data = api_ok(session.get(url), "list lineages").json()
        lineages += data.get("lineages", [])
        nxt = data.get("links", {}).get("next")
        url = f"{base_url}{nxt}" if nxt else None
    return lineages


def active_generation_id(lineage):
    return ((lineage.get("currentProduction") or {}).get("productionGenerationId")
            or (lineage.get("currentStaging") or {}).get("stagingGenerationId"))


def parse_date(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def issuer_org(issuer):
    """'CN=YE2,O=Let's Encrypt,C=US' -> "Let's Encrypt"."""
    m = re.search(r"(?:^|,)\s*O=([^,]+)", issuer or "")
    return m.group(1).strip() if m else (issuer or "-")


def is_lets_encrypt(issuer):
    # Let's Encrypt issuers look like "CN=E7,O=Let's Encrypt,C=US" (intermediates R10-R14, E5-E9, YE*, YR*).
    #
    # HOW TO ADD ANOTHER CA (see README "Supporting other Certificate Authorities"):
    #   - Another ACME CA (ZeroSSL, Google Trust Services, Sectigo/DigiCert ACME):
    #       replace this check with a mapping  issuer organisation -> {directory URL, account key,
    #       account URI, EAB credentials}  and let get_acme_client() pick the right account.
    #       Issuer organisation names: "ZeroSSL", "Google Trust Services", "Sectigo Limited", "DigiCert Inc".
    #   - A CA without ACME (DigiCert CertCentral API, Sectigo SCM, internal PKI):
    #       needs its own "submit CSR -> wait for approval -> download certificate" function.
    #   Until then these certificates are only reported ("script must be extended for this CA").
    return "let's encrypt" in (issuer or "").lower()


def inspect_lineage(lineage):
    """Collect everything needed for the report and the renewal decision."""
    lid = lineage["lineageId"]
    sans = lineage.get("sans") or []
    info = {
        "id": lid,
        "domain": (lineage.get("subject") or {}).get("commonName") or (sans[0] if sans else "-"),
        "sans": sans,
        "creator": lineage.get("lineageCreatedBy", "-"),
        "issuer": None,
        "key_types": [k.get("keyType") for k in lineage.get("keySpecs", [])],
        "not_after": None,
        "days_left": None,
    }
    gen_id = active_generation_id(lineage)
    if not gen_id:
        return info
    gen = api_ok(session.get(f"{base_url}/ccm/v2/lineages/{lid}/generations/{gen_id}"),
                 f"get generation {lid}/{gen_id}").json()
    algos = [a for a in gen.get("algorithms", []) if a.get("signedCertificateNotValidAfterDate")]
    if not algos:
        return info
    first = min(algos, key=lambda a: parse_date(a["signedCertificateNotValidAfterDate"]))
    info["not_after"] = parse_date(first["signedCertificateNotValidAfterDate"])
    info["days_left"] = (info["not_after"] - datetime.now(timezone.utc)).days
    info["issuer"] = first.get("signedCertificateIssuer")
    info["key_types"] = [a.get("keyType") for a in algos]
    return info


# ==========================================
# EDGE DNS
# ==========================================
_zones = None


def edge_dns_zones():
    global _zones
    if _zones is None:
        data = api_ok(session.get(f"{base_url}/config-dns/v2/zones", params={"showAll": "true"}),
                      "list Edge DNS zones").json()
        _zones = {z["zone"].lower().rstrip(".") for z in data.get("zones", [])}
    return _zones


def find_zone(name):
    """Longest Edge DNS zone that `name` falls under, or None (works for example.co.uk too)."""
    labels = name.lower().rstrip(".").removeprefix("*.").split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if candidate in edge_dns_zones():
            return candidate
    return None


def upsert_txt_record(record_name, values):
    """Create the TXT recordset; if it already exists (e.g. leftover from a failed run), replace it."""
    zone = find_zone(record_name)
    if not zone:
        raise ValueError(f"No Edge DNS zone found for {record_name}")
    rs = {"name": record_name, "type": "TXT", "ttl": 60, "rdata": list(values)}
    r = session.post(f"{base_url}/config-dns/v2/zones/{zone}/recordsets", json={"recordsets": [rs]})
    if r.status_code == 409:
        r = session.put(f"{base_url}/config-dns/v2/zones/{zone}/names/{record_name}/types/TXT", json=rs)
    api_ok(r, f"create TXT {record_name}")
    log(f"✅ TXT {record_name} set in zone {zone}")


def delete_txt_record(record_name):
    zone = find_zone(record_name)
    if not zone:
        return
    r = session.delete(f"{base_url}/config-dns/v2/zones/{zone}/names/{record_name}/types/TXT")
    if r.ok or r.status_code == 404:
        log(f"🧹 TXT {record_name} removed")
    else:
        log(f"Warning: could not delete {record_name}: {r.status_code} {r.text}")


def wait_for_dns(records, timeout=DNS_TIMEOUT):
    """records: {record_name: set(values)} — waits until every value is visible publicly."""
    log("⏳ Waiting for DNS propagation...")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    remaining = dict(records)
    start = time.time()
    while remaining:
        for name, wanted in list(remaining.items()):
            try:
                seen = {b"".join(r.strings).decode() for r in resolver.resolve(name, "TXT")}
                if wanted <= seen:
                    log(f"   👉 propagated: {name}")
                    del remaining[name]
            except Exception:
                pass
        if not remaining:
            return
        if time.time() - start > timeout:
            raise TimeoutError(f"DNS propagation timed out for: {', '.join(remaining)}")
        time.sleep(10)


# ==========================================
# DECISION
# ==========================================
def not_auto_renewable_reason(info):
    """None if the script may renew this lineage, otherwise the reason why not."""
    if ONLY_CREATED_BY and str(info["creator"]).lower() not in ONLY_CREATED_BY:
        return f"created by {info['creator']}, not in ONLY_CREATED_BY"
    if not is_lets_encrypt(info["issuer"]):
        return (f"issuer '{issuer_org(info['issuer'])}': script must be extended "
                f"for this CA")
    if len(info["key_types"]) != 1:
        return "RSA+ECDSA lineage: dual-algorithm renewal not supported yet"
    missing = [d for d in info["sans"] if not find_zone(d)]
    if missing:
        return (f"DNS for {', '.join(missing)} not in Akamai Edge DNS: script must be "
                f"extended for this DNS provider")
    return None


# ==========================================
# CCM: RENEWAL
# ==========================================
def request_new_csr(lineage_id):
    resp = api_ok(session.post(f"{base_url}/ccm/v2/lineages/{lineage_id}/generations"),
                  "create generation").json()
    head = resp.get("head", {})
    generation_id = head.get("headGenerationId")
    algo = head.get("algorithms", [])[0]

    body = (algo["csrPem"].replace("-----BEGIN CERTIFICATE REQUEST-----", "")
            .replace("-----END CERTIFICATE REQUEST-----", ""))
    body = "".join(body.split())
    csr_pem = ("-----BEGIN CERTIFICATE REQUEST-----\n"
               + "\n".join(textwrap.wrap(body, 64))
               + "\n-----END CERTIFICATE REQUEST-----\n")
    return generation_id, csr_pem, algo.get("keyType")


def get_domains_from_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return sorted(set(san.value.get_values_for_type(DNSName)))
    except x509.ExtensionNotFound:
        return []


def upload_certificate(lineage_id, generation_id, key_type, fullchain_pem):
    end = "-----END CERTIFICATE-----"
    certs = [(p + end).strip() for p in fullchain_pem.strip().split(end) if "-----BEGIN CERTIFICATE-----" in p]
    leaf, chain = certs[0], "\n".join(certs[1:])

    algo = str(key_type or "").strip().upper()
    if algo not in ("RSA", "ECDSA"):
        raise ValueError(f"Unknown key type '{key_type}' for generation {generation_id}")

    payload = {"algorithms": {algo: {"signedCertificatePem": leaf, "trustChainPem": chain}}}
    url = f"{base_url}/ccm/v2/lineages/{lineage_id}/generations/{generation_id}"
    api_ok(session.patch(url, json=payload), "upload certificate")
    log(f"✅ {algo} certificate uploaded to generation {generation_id}")


def promote_certificate(lineage_id, generation_id):
    url = f"{base_url}/ccm/v2/lineages/{lineage_id}/generations/{generation_id}"
    log("⏳ Waiting for generation to become READY_FOR_USE...")
    for attempt in range(15):
        r = session.get(url)
        if r.ok:
            status = r.json().get("generationStatus")
            log(f"   status {attempt + 1}/15: {status}")
            if status == "READY_FOR_USE":
                break
        time.sleep(4)
    else:
        log("⚠️ Generation not READY_FOR_USE in time, trying promotion anyway")

    payload = {"operationType": "PROMOTE", "generationId": int(generation_id),
               "networks": ["STAGING", "PRODUCTION"]}
    api_ok(session.post(f"{base_url}/ccm/v2/lineages/{lineage_id}/activations", json=payload), "promote")
    log("✅ Promoted to STAGING and PRODUCTION")


_acme = None


def get_acme_client():
    """Create the Let's Encrypt client once and reuse it for every lineage."""
    global _acme
    if _acme is None:
        with open(ACCOUNT_KEY_PATH, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        jwk = JWKRSA(key=key)
        net = client.ClientNetwork(jwk, user_agent="akamai-ccm-renewal/2.0")
        acme = client.ClientV2(client.ClientV2.get_directory(DIRECTORY_URL, net), net)
        regr = messages.RegistrationResource(uri=ACCOUNT_URI, body=messages.Registration(key=jwk.public_key()))
        acme.query_registration(regr)
        _acme = (acme, jwk)
    return _acme


def renew_lineage(lineage_id, current_key_type):
    acme, jwk = get_acme_client()

    log("Creating new CCM generation + CSR...")
    gen_id, csr_pem, csr_key_type = request_new_csr(lineage_id)
    log(f"New generation {gen_id}, domains: {get_domains_from_csr(csr_pem)}")

    order = acme.new_order(csr_pem.encode())

    records = {}       # record_name -> set of validation values
    to_answer = []
    for authz_res in order.authorizations:
        domain = authz_res.body.identifier.value      # wildcard comes without the "*."
        chal = next(c for c in authz_res.body.challenges if isinstance(c.chall, challenges.DNS01))
        records.setdefault(f"_acme-challenge.{domain}", set()).add(chal.validation(jwk))
        to_answer.append(chal)

    try:
        # example.com + *.example.com share one record name -> one recordset with 2 values
        for name, values in records.items():
            upsert_txt_record(name, values)
        wait_for_dns(records)

        log("Answering ACME challenges...")
        for chal in to_answer:
            acme.answer_challenge(chal, chal.response(jwk))

        finalized = acme.poll_and_finalize(order)
        log("✅ Certificate signed by Let's Encrypt")
    finally:
        for name in records:
            delete_txt_record(name)

    upload_certificate(lineage_id, gen_id, csr_key_type or current_key_type, finalized.fullchain_pem)
    promote_certificate(lineage_id, gen_id)
    return gen_id


# ==========================================
# REPORT
# ==========================================
def format_table(rows):
    headers = ["Lineage", "Domain", "Created by", "Issuer", "Key", "Expires", "Days", "Action"]
    data = [headers] + rows
    widths = [max(len(str(r[i])) for r in data) for i in range(len(headers))]
    lines = ["  ".join(str(v).ljust(w) for v, w in zip(r, widths)).rstrip() for r in data]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


# ==========================================
# MAIN
# ==========================================
def main():
    check_only = "--check" in sys.argv
    log(f"Akamai CCM overview - renewal threshold {RENEWAL_THRESHOLD_DAYS} days, "
        f"created by: {', '.join(sorted(ONLY_CREATED_BY)) or 'anyone'}"
        + (" [CHECK ONLY]" if check_only else ""))

    lineages = sorted(list_lineages(), key=lambda l: l["lineageId"])
    log(f"Found {len(lineages)} lineage(s)")

    rows, renewed, failed, attention = [], [], [], []

    for lineage in lineages:
        lid = lineage["lineageId"]
        try:
            info = inspect_lineage(lineage)
        except Exception as e:
            rows.append([lid, "-", lineage.get("lineageCreatedBy", "-"), "-", "-", "-", "-", f"ERROR: {e}"])
            failed.append(f"{lid}: could not read lineage: {e}")
            continue

        key = "+".join(k for k in info["key_types"] if k) or "-"
        if info["days_left"] is None:
            rows.append([lid, info["domain"], info["creator"], "-", key, "-", "-",
                         "SKIP: no signed certificate yet"])
            continue

        days = info["days_left"]
        due = days <= RENEWAL_THRESHOLD_DAYS
        reason = not_auto_renewable_reason(info)
        mine = not (ONLY_CREATED_BY and str(info["creator"]).lower() not in ONLY_CREATED_BY)
        row = [lid, info["domain"], info["creator"], issuer_org(info["issuer"]), key,
               f"{info['not_after']:%Y-%m-%d}", "EXPIRED" if days < 0 else days]

        if not due:
            rows.append(row + ["OK, not due" + (f" (manual: {reason})" if reason and mine else "")])
        elif reason:
            rows.append(row + [f"SKIP: {reason}"])
            if mine:  # only alert about your own certificates
                attention.append(f"{info['domain']} ({lid}) expires {info['not_after']:%Y-%m-%d}: {reason}")
        elif check_only:
            rows.append(row + ["WOULD RENEW"])
        else:
            rows.append(row + ["RENEWING..."])
            log("")
            log(f"===== Renewing {info['domain']} (lineage {lid}) =====")
            try:
                gen_id = renew_lineage(lid, info["key_types"][0])
                rows[-1][-1] = f"RENEWED (generation {gen_id})"
                renewed.append(f"{info['domain']} ({lid}): new generation {gen_id}")
            except Exception:
                err = traceback.format_exc()
                log(f"❌ Lineage {lid} failed:\n{err}")
                rows[-1][-1] = "FAILED (see log)"
                failed.append(f"{info['domain']} ({lid}):\n{err}")

    table = format_table(rows)
    log("")
    print(table, flush=True)
    log("")
    log(f"Done. renewed={len(renewed)} failed={len(failed)} needs attention={len(attention)}")

    if renewed or failed or attention:
        status = "FAILED" if failed else ("ATTENTION" if attention and not renewed else "SUCCESS")
        body = []
        if renewed:
            body += ["Renewed:"] + [f"  - {r}" for r in renewed] + [""]
        if failed:
            body += ["Failed:"] + [f"  - {f}" for f in failed] + [""]
        if attention:
            body += ["Due, but NOT auto-renewable (manual action or script update needed):"]
            body += [f"  - {a}" for a in attention] + [""]
        body += ["All certificates:", "", table]
        send_email(f"{status}: Akamai CCM certificate renewal "
                   f"({len(renewed)} renewed, {len(failed)} failed, {len(attention)} attention)",
                   "\n".join(body))

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
