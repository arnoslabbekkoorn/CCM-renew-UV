**Akamai Cloud certificate Manager (CCM) Version 3 Lets Encrypt certificate generation renewal.**

This Script renews a lets Encrypt certificate lineage generation based on expiration date.

**Requirements**
- Python 3.10
- Acme production URL & Account URI and Account key
            *ACCOUNT_KEY_PATH="C:\Users\username\Desktop\python\acme\account.key"*
            *DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory"*
            *ACCOUNT_URI="https://acme-v02.api.letsencrypt.org/acme/acct/***********"*
- Akamai EdgeGrid credentials,tokens for Cloud Certificate manager and EdgeDnS (in .EdgeRC  file)
- Akamai CCM Lineage_ID
- .env file with the variables

**WorkFlow**
1. Fetch Expiration.
2. If Expiration is below threshold f.e 7 days before expration 
3  generate new CSR
4. Send CSR to Lets Encrypt
5. Fetch DNS challenge(s) from Lets Encrypt (_Acme)
6. Create temporary Acme DNS records
7. Validate DNS challenges
8. Request Acme Order for signed certificate trust chain ( Leaf + intermediates and Root)
9. Fetch Signed certifiates and upload to CCM
10. Promote certificte to staging and production.
11. Remove _acme DNS TXT records from EdgeDNS
       
       

---

**Multiple certificates: `ccm_renew_all.py`**

Checks *all* configured CCM lineages and renews only the ones that are expired or expire within the threshold. Built to run once a day from a scheduler.

- Lineages are set in `.env`, comma separated (falls back to `CCM_LINEAGE_ID` if not set):
            *CCM_LINEAGE_IDS="9137,9140,9152"*
- Optional settings in `.env`:
            *RENEWAL_THRESHOLD_DAYS=8* (renew when this many days or fewer are left)
            *DNS_TIMEOUT=480* (seconds to wait for DNS propagation)
- A failure on one lineage does not stop the others.
- One summary email is sent only when something was renewed or failed. No email on days with nothing to do.
- Exit code `1` when any lineage failed, `0` otherwise.

Usage:
```
uv run ccm_renew_all.py           # check and renew where needed
uv run ccm_renew_all.py --check   # only show expiry dates, renew nothing
```

**Daily schedule**

Windows (Task Scheduler), every day at 06:00, output appended to `renewal.log`:
```
schtasks /Create /TN "Akamai CCM Renewal" /SC DAILY /ST 06:00 /TR "cmd /c cd /d C:\path\to\CCM-renew-UV && uv run ccm_renew_all.py >> renewal.log 2>&1"
```

Linux (cron), `crontab -e`:
```
0 6 * * * cd /path/to/CCM-renew-UV && uv run ccm_renew_all.py >> renewal.log 2>&1
```
On Linux, use a Linux path for `ACCOUNT_KEY_PATH` and place `.edgerc` in the home folder of the user running cron.
