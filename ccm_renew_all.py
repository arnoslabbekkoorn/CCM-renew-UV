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
Daily checker for Let's Encrypt certificates in Akamai Cloud Certificate Manager.

For every lineage in CCM_LINEAGE_IDS (comma separated, falls back to CCM_LINEAGE_ID):
  1. Read the expiry date of the active (production, else staging) generation.
  2. Expired, or expiring within RENEWAL_THRESHOLD_DAYS -> renew:
     new generation + CSR -> ACME DNS-01 via Akamai EdgeDNS -> upload -> promote.
  3. Otherwise -> skip.

A failure on one lineage does not stop the others. A summary email is sent only
when something was renewed or failed. Exit code is 1 if any lineage failed.

Run:  uv run ccm_renew_all.py            (normal run)
      uv run ccm_renew_all.py --check    (only report expiry, renew nothing)
"""

import os
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

_ids = os.getenv("CCM_LINEAGE_IDS") or os.getenv("CCM_LINEAGE_ID") or ""
CCM_LINEAGE_IDS = [i.strip() for i in _ids.split(",") if i.strip()]

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
# CCM
# ==========================================
def get_ccm_status(lineage_id):
    """Return (days_left, not_after, primary_domain, key_algorithm) of the active generation."""
    lineage = api_ok(session.get(f"{base_url}/ccm/v2/lineages/{lineage_id}"), "get lineage").json()
    primary_domain = lineage.get("subject", {}).get("commonName", str(lineage_id))

    gen_id = (lineage.get("currentProduction", {}).get("productionGenerationId")
              or lineage.get("currentStaging", {}).get("stagingGenerationId"))
    if not gen_id:
        raise ValueError(f"No active generation found for lineage {lineage_id}")

    gen = api_ok(session.get(f"{base_url}/ccm/v2/lineages/{lineage_id}/generations/{gen_id}"),
                 "get generation").json()
    algos = [a for a in gen.get("algorithms", []) if a.get("signedCertificateNotValidAfterDate")]
    if not algos:
        raise ValueError(f"Generation {gen_id} of lineage {lineage_id} has no signed certificate")

    # If several algorithms exist, the one that expires first decides.
    def not_after_of(a):
        return datetime.fromisoformat(a["signedCertificateNotValidAfterDate"].replace("Z", "+00:00"))

    first = min(algos, key=not_after_of)
    not_after = not_after_of(first)
    days_left = (not_after - datetime.now(timezone.utc)).days
    return days_left, not_after, primary_domain, first.get("keyAlgorithm", "ECDSA")


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
    return generation_id, csr_pem, algo.get("keyAlgorithm")


def get_domains_from_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return sorted(set(san.value.get_values_for_type(DNSName)))
    except x509.ExtensionNotFound:
        return []


def upload_certificate(lineage_id, generation_id, key_algorithm, fullchain_pem):
    end = "-----END CERTIFICATE-----"
    certs = [(p + end).strip() for p in fullchain_pem.strip().split(end) if "-----BEGIN CERTIFICATE-----" in p]
    leaf, chain = certs[0], "\n".join(certs[1:])

    algo = str(key_algorithm or "ECDSA").strip().upper()
    if algo not in ("RSA", "ECDSA"):
        log(f"Warning: unexpected algorithm '{algo}', using ECDSA")
        algo = "ECDSA"

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


# ==========================================
# EDGE DNS
# ==========================================
def zone_for(name):
    # Same assumption as the original script: the zone is the last two labels.
    return ".".join(name.rstrip(".").split(".")[-2:])


def upsert_txt_record(record_name, values):
    """Create the TXT recordset; if it already exists (e.g. leftover from a failed run), replace it."""
    zone = zone_for(record_name)
    rs = {"name": record_name, "type": "TXT", "ttl": 60, "rdata": list(values)}
    r = session.post(f"{base_url}/config-dns/v2/zones/{zone}/recordsets", json={"recordsets": [rs]})
    if r.status_code == 409:
        r = session.put(f"{base_url}/config-dns/v2/zones/{zone}/names/{record_name}/types/TXT", json=rs)
    api_ok(r, f"create TXT {record_name}")
    log(f"✅ TXT {record_name} set in zone {zone}")


def delete_txt_record(record_name):
    zone = zone_for(record_name)
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
# ACME
# ==========================================
_acme = None


def get_acme_client():
    """Create the Let's Encrypt client once and reuse it for every lineage."""
    global _acme
    if _acme is None:
        with open(ACCOUNT_KEY_PATH, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        jwk = JWKRSA(key=key)
        net = client.ClientNetwork(jwk, user_agent="akamai-ccm-renewal/1.0")
        acme = client.ClientV2(client.ClientV2.get_directory(DIRECTORY_URL, net), net)
        regr = messages.RegistrationResource(uri=ACCOUNT_URI, body=messages.Registration(key=jwk.public_key()))
        net.account = acme.query_registration(regr)
        _acme = (acme, jwk)
    return _acme


# ==========================================
# RENEW ONE LINEAGE
# ==========================================
def renew_lineage(lineage_id, current_algorithm):
    acme, jwk = get_acme_client()

    log("Creating new CCM generation + CSR...")
    gen_id, csr_pem, csr_algorithm = request_new_csr(lineage_id)
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

    upload_certificate(lineage_id, gen_id, csr_algorithm or current_algorithm, finalized.fullchain_pem)
    promote_certificate(lineage_id, gen_id)
    return gen_id


# ==========================================
# MAIN
# ==========================================
def main():
    check_only = "--check" in sys.argv
    if not CCM_LINEAGE_IDS:
        log("No lineages configured. Set CCM_LINEAGE_IDS in .env (e.g. CCM_LINEAGE_IDS=9137,9138).")
        sys.exit(2)

    log(f"Checking {len(CCM_LINEAGE_IDS)} lineage(s), renewal threshold {RENEWAL_THRESHOLD_DAYS} days"
        + (" [CHECK ONLY]" if check_only else ""))

    renewed, failed, ok = [], [], []

    for lineage_id in CCM_LINEAGE_IDS:
        log("")
        log(f"===== Lineage {lineage_id} =====")
        domain = lineage_id
        try:
            days_left, not_after, domain, algo = get_ccm_status(lineage_id)
            state = "EXPIRED" if days_left < 0 else f"{days_left} days left"
            log(f"{domain}: expires {not_after:%Y-%m-%d} ({state}), algorithm {algo}")

            if days_left > RENEWAL_THRESHOLD_DAYS:
                ok.append(f"{domain} ({lineage_id}): {days_left} days left")
                continue
            if check_only:
                ok.append(f"{domain} ({lineage_id}): {state} -> WOULD RENEW")
                continue

            log(f"Renewing {domain}...")
            gen_id = renew_lineage(lineage_id, algo)
            renewed.append(f"{domain} ({lineage_id}): was {state}, new generation {gen_id}")
        except Exception:
            err = traceback.format_exc()
            log(f"❌ Lineage {lineage_id} failed:\n{err}")
            failed.append(f"{domain} ({lineage_id}):\n{err}")

    log("")
    log(f"Done. renewed={len(renewed)} failed={len(failed)} unchanged={len(ok)}")
    for line in ok:
        log(f"  - {line}")

    if renewed or failed:
        status = "FAILED" if failed else "SUCCESS"
        body = []
        if renewed:
            body += ["Renewed:"] + [f"  - {r}" for r in renewed] + [""]
        if failed:
            body += ["Failed:"] + [f"  - {f}" for f in failed] + [""]
        if ok:
            body += ["Not due:"] + [f"  - {o}" for o in ok]
        send_email(f"{status}: Akamai CCM Let's Encrypt renewal "
                   f"({len(renewed)} renewed, {len(failed)} failed)", "\n".join(body))

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
