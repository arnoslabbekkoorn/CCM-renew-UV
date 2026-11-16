# Akamai Cloud Certificate Manager (CCM) – Let's Encrypt renewal

Automatic renewal of Let's Encrypt certificates in **Akamai Cloud Certificate Manager (CCM)**, using **Akamai Edge DNS** for ACME DNS-01 validation.

| Script | Purpose |
|---|---|
| `ccm_renew_all_v2.py` | **Recommended.** Shows an overview of *all* CCM lineages in the account and auto-renews only the certificates it can safely handle. Built to run daily from a scheduler. |
| `akamai_ccm_renewal.py` | Original script: renews one hard-coded lineage (`CCM_LINEAGE_ID`). |

---

## About this demo environment

This code is developed and tested on an **internal, shared Akamai account**. That account contains CCM lineages created by several colleagues, with certificates from different CAs (Let's Encrypt, a demo local CA, and lineages without a signed certificate yet).

To make sure the script never touches certificates that aren't mine, renewals are limited with:

```
ONLY_CREATED_BY="arno"
```

All lineages are still *shown* in the overview, but only lineages created by `arno` are renewed.

**In a customer account** all certificates normally belong to the same customer. Leave `ONLY_CREATED_BY` empty there to include every lineage, and use the other checks (issuer, DNS provider) to decide what can be automated.

---

## What `ccm_renew_all_v2.py` does

1. Lists **all** CCM lineages in the account (follows API paging).
2. Per lineage, reads the active generation (production, else staging): issuer, key type, expiry date, days left.
3. Prints an overview table:

```
Lineage  Domain                      Created by  Issuer         Key    Expires     Days  Action
-------  --------------------------  ----------  -------------  -----  ----------  ----  ------------------------------------------------
8348     lineage.akamai.******.net   ********    Let's Encrypt  RSA    2026-12-28  41    OK, not due
9137     slab***.nl                   arno       Let's Encrypt  ECDSA  2027-01-25  69    OK, not due
9489     ******.great-demo.com       ********    Demo Local CA  ECDSA  2027-04-24  159   OK, not due
10093    static.slab***.nl            arno        -             ECDSA  -           -     SKIP: no signed certificate yet
```

4. A lineage is **auto-renewed only when all of these are true**:
   - it is **due**: expired, or expires within `RENEWAL_THRESHOLD_DAYS`
   - it was **created by** a user in `ONLY_CREATED_BY` (empty = everyone)
   - the current certificate was issued by **Let's Encrypt**
   - it is a **single-algorithm** lineage (RSA *or* ECDSA, not both)
   - every domain (SAN) is in a zone hosted in **Akamai Edge DNS**
5. Due certificates that fail a check are **skipped with the reason**, for example:
   - `SKIP: issuer 'DigiCert Inc': script must be extended for this CA`
   - `SKIP: DNS for www.example.com not in Akamai Edge DNS: script must be extended for this DNS provider`
   - `SKIP: RSA+ECDSA lineage: dual-algorithm renewal not supported yet`
   - `SKIP: created by <user>, not in ONLY_CREATED_BY`
6. Renewal flow: new CCM generation + CSR → ACME order → `_acme-challenge` TXT records in Edge DNS → wait for propagation → validate → download certificate + chain → upload to CCM → promote to staging + production → remove TXT records.
7. Sends **one email** only when something was renewed, failed, or is one of your own certificates that is due but cannot be auto-renewed. The email includes the full overview table. Quiet days send no email.

A failure on one lineage never stops the others. Exit code is `1` when any lineage failed, otherwise `0`.

### Usage

```
uv run ccm_renew_all_v2.py           # overview + renew where allowed
uv run ccm_renew_all_v2.py --check   # overview only, never renews anything
```

Tip: test the renewal rules without renewing by temporarily raising the threshold:
```
RENEWAL_THRESHOLD_DAYS=200 uv run ccm_renew_all_v2.py --check
```

---

## Requirements

- Python 3.10+ and [uv](https://docs.astral.sh/uv/) (dependencies are declared inside the script)
- Akamai EdgeGrid credentials in `~/.edgerc` with **read-write** access to:
  - Cloud Certificate Manager (CCM)
  - Edge DNS (`config-dns`)
- An existing Let's Encrypt ACME account (account key + account URI)
- A `.env` file next to the script

### `.env` settings

| Variable | Example | Notes |
|---|---|---|
| `EDGERC_SECTION` | `default` | Section in `~/.edgerc` |
| `ACCOUNT_SWITCH_KEY` | | Only for Akamai internal / partner accounts |
| `ONLY_CREATED_BY` | `arno` | Comma separated. Empty = all users |
| `RENEWAL_THRESHOLD_DAYS` | `30` | Default `8`, see *Recommendations* |
| `DNS_TIMEOUT` | `480` | Seconds to wait for DNS propagation |
| `ACCOUNT_KEY_PATH` | `C:\...\acme\account.key` | Let's Encrypt account key |
| `DIRECTORY_URL` | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory |
| `ACCOUNT_URI` | `https://acme-v02.api.letsencrypt.org/acme/acct/<id>` | ACME account |
| `SMTP_SERVER`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `EMAIL_TO` | | Email reports (STARTTLS) |
| `CCM_LINEAGE_ID` | `9137` | Only used by `akamai_ccm_renewal.py` |

`.env`, `.edgerc` and `account.key` contain secrets and must **never** be committed (`.env` is in `.gitignore`).

---

## Daily schedule

**Windows (Task Scheduler)**, every day at 06:00, output appended to `renewal.log`:
```
schtasks /Create /TN "Akamai CCM Renewal" /SC DAILY /ST 06:00 /TR "cmd /c cd /d C:\path\to\CCM-renew-UV && uv run ccm_renew_all_v2.py >> renewal.log 2>&1"
```
Enable *"Run task as soon as possible after a scheduled start is missed"* for laptops, and *"Run whether user is logged on or not"* for servers.

**Linux (cron)**, `crontab -e`:
```
0 6 * * * cd /path/to/CCM-renew-UV && /usr/local/bin/uv run ccm_renew_all_v2.py >> renewal.log 2>&1
```
On Linux, use a Linux path for `ACCOUNT_KEY_PATH` and put `.edgerc` in the home folder of the user that runs cron.

---

## Supporting other Certificate Authorities

Customers often use several CAs. Many commercial CAs support **ACME** – the same protocol used for Let's Encrypt – so most of the code can be reused.

| CA type | Examples | Effort |
|---|---|---|
| Let's Encrypt | – | **Supported** |
| Other ACME CAs | ZeroSSL, Google Trust Services, Sectigo ACME, DigiCert ACME, GlobalSign Atlas, Entrust | **Easy.** Same ACME code with a different `DIRECTORY_URL`. Commercial CAs also need **EAB** credentials (External Account Binding: key ID + HMAC key from the CA portal) to register the ACME account once. |
| CAs without ACME | DigiCert CertCentral API, Sectigo Certificate Manager API, internal/enterprise PKI | **More work.** Each needs its own integration (submit CSR → approval → download certificate). Until then the script reports these certificates and alerts before they expire. |

How it would work: the script reads the issuer of each certificate (`signedCertificateIssuer` in CCM) and maps the issuer organisation (e.g. `ZeroSSL`, `Google Trust Services`, `Sectigo Limited`, `DigiCert Inc`) to a CA configuration (directory URL, account key, account URI, EAB). Certificates from CAs without a configuration are reported as *"script must be extended for this CA"*. See the comments at `is_lets_encrypt()` in the code.

Useful ACME directory URLs:

| CA | Directory URL | EAB |
|---|---|---|
| Let's Encrypt | `https://acme-v02.api.letsencrypt.org/directory` | No |
| Let's Encrypt (staging, for testing) | `https://acme-staging-v02.api.letsencrypt.org/directory` | No |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` | Yes |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` | Yes |
| Sectigo / DigiCert / GlobalSign | Provided per customer in the CA portal | Yes |

> Note: switching a certificate to a different CA is a business decision (OV/EV validation, contracts, warranty). The script deliberately renews with the **same** CA that issued the current certificate.

## Supporting other DNS providers

| DNS provider | Status |
|---|---|
| Akamai Edge DNS | **Supported** (zone found automatically from the Edge DNS zone list, so `example.co.uk` works too) |
| AWS Route 53, Azure DNS, Cloudflare, others | Not yet. Each needs a small module to create/delete the `_acme-challenge` TXT record via its API. Until then these certificates are reported as *"script must be extended for this DNS provider"*. |

Alternative without an API integration per DNS provider: **CNAME delegation**. The customer creates a one-time CNAME at their own DNS provider, e.g. `_acme-challenge.www.example.com CNAME www.example.com.acme.<zone-in-edge-dns>`. ACME validation follows the CNAME, so the TXT record can then be written in Edge DNS. This needs a small code change: look up the CNAME first and write the TXT record at the CNAME target. It's not implemented yet.

## Roadmap

1. ✅ Inventory and alerting for all certificates (v2)
2. Support any ACME CA with EAB (CA settings mapped by issuer)
3. Dual-algorithm (RSA + ECDSA) lineages: request and upload two certificates per generation
4. Additional DNS providers and non-ACME CAs, one at a time when needed

---

## Recommendations and good to know

- **Renew earlier than 8 days.** Let's Encrypt recommends renewing when about one third of the lifetime is left (≈ 30 days for 90-day certificates). With `RENEWAL_THRESHOLD_DAYS=30` a failed renewal gets about 30 daily retries instead of 8 before the certificate expires.
- **Certificate lifetimes are getting shorter.** The CA/Browser Forum is reducing the maximum certificate lifetime step by step (200 days from March 2026, 100 days from March 2027, 47 days from March 2029), and Let's Encrypt is moving towards 45-day certificates. Manual renewal won't scale; automation like this will become a requirement.
- **Let's Encrypt no longer sends expiry reminder emails** (stopped in 2025). The email report of this script covers that gap.
- **CAA records:** if a domain has a CAA record, it must allow `letsencrypt.org`, otherwise validation fails.
- **Rate limits:** Let's Encrypt limits duplicate certificates (5 per week for the same set of names) and failed validations. Use the staging directory for experiments.
- **Leftover generations:** if a run fails after CCM created a new generation, the next run may be refused until that generation is finished or deleted in CCM. The failure email shows the API error.
- **Least privilege:** give the EdgeGrid API client only the CCM and Edge DNS permissions it needs, and restrict it to the relevant groups where possible.
- **Logs:** each run is written to `renewal.log` (ignored by git). The exit code (`0` = OK, `1` = a lineage failed) can be used for monitoring.

## Original single-lineage script: `akamai_ccm_renewal.py`

Renews one lineage, set with `CCM_LINEAGE_ID` in `.env`. Workflow:

1. Fetch expiration of the lineage.
2. If expiration is below the threshold, generate a new CSR in CCM.
3. Send the CSR to Let's Encrypt and fetch the DNS-01 challenges.
4. Create temporary `_acme-challenge` TXT records in Edge DNS and validate them.
5. Download the signed certificate + trust chain and upload them to CCM.
6. Promote the certificate to staging and production.
7. Remove the `_acme-challenge` TXT records from Edge DNS.

Known limitation: it always assumes ECDSA (it reads a non-existent `keyAlgorithm` field) and derives the DNS zone from the last two labels of the domain. Both are fixed in `ccm_renew_all_v2.py`.
