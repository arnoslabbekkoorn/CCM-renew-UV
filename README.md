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
       
       
